"""
Flask extension instances, created uninitialized here and wired up via
`.init_app(app)` inside `create_app()` (see `glassbox/__init__.py`).
Kept in their own module so other modules (models, routes) can import them
without triggering circular imports with the app factory.
"""
import hashlib

import flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
# Alembic-backed migrations (infra track) - replaces the old "db.create_all()
# only, no migrations, add a new table instead of altering one" constraint.
# `flask db migrate`/`flask db upgrade` now own schema changes; db.create_all()
# in create_app() stays only as a first-run convenience for a brand-new empty
# DB (a fresh `flask db upgrade` accomplishes the same thing and is what a
# real deploy should run instead - see CLAUDE.md's Commands section).
migrate = Migrate()
# Deliberately constructed with no storage_uri: the backend is chosen
# entirely by RATELIMIT_STORAGE_URI in app.config at init_app() time (see
# config.py's declaration). Left unset, Flask-Limiter's own default applies
# (in-memory storage) - correct only for a single dev-server-process
# deploy, same caveat as SQLite's check_same_thread config. Set to a
# redis:// URL, it becomes a shared cross-worker counter store, which is
# what makes running behind gunicorn with >1 worker safe (HARD-01) - proved
# by tests/test_ratelimit_storage.py. This object is still a per-process
# singleton either way (one Limiter per worker process): that fact is why
# a shared *backend* is what closes the gap, not a shared Python object,
# and it's also why tests/conftest.py's TestConfig disables RATELIMIT_ENABLED
# by default (this singleton is reused across every create_app() call in
# one process, including every test app - see test_auth_flows.py's
# test_login_rate_limit_is_enforced for the one test that re-enables it).
limiter = Limiter(key_func=get_remote_address)

login_manager.login_view = "auth.login"


# The user_loader callback lives here (rather than models.py) so that
# extensions.py stays the single place that configures login_manager
# end-to-end. It imports User lazily (inside the function) to avoid a
# models.py <-> extensions.py circular import at module load time.
@login_manager.user_loader
def load_user(user_id):
    from glassbox.models import User

    return User.query.get(int(user_id))


# Phase 2 (API-01..05, D-01..D-04): a second, parallel authentication path -
# hash-only Bearer tokens - alongside the session-cookie auth above.
# request_loader is Flask-Login's own documented mechanism for this and is
# checked on every request that has no session-authenticated user, so it
# must never touch the DB unless an Authorization: Bearer header is actually
# present (Pitfall 2, 02-RESEARCH.md) - otherwise every anonymous page load
# pays an extra query. ApiToken is imported lazily, same reason load_user
# above imports User lazily: avoids a models.py <-> extensions.py circular
# import at module load time.
#
# CR-01 fix: request_loader has no notion of "which blueprint" - Flask-Login
# invokes it for *any* @login_required route with no session-authenticated
# user, not just /api/v1/*. Without this path scope, a leaked Bearer token
# would authenticate the token owner against every other @login_required
# route in the app (dashboard, assets, billing, org admin, HTML scan/report
# pages) - none of which carry the api blueprint's rate limits. Restricting
# this callback to /api/v1/* means a Bearer header is silently ignored
# everywhere else, so Flask-Login falls through to its normal
# session-cookie-only behavior (redirect to login) for every non-API route.
@login_manager.request_loader
def load_user_from_request(request):
    if not request.path.startswith("/api/v1/"):
        return None
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    raw_token = auth_header[len("Bearer "):].strip()
    if not raw_token:
        return None

    from datetime import datetime, timezone

    from glassbox.models import ApiToken

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    row = ApiToken.query.filter_by(token_hash=token_hash, revoked_at=None).first()
    if row is None:
        return None

    row.last_used_at = datetime.now(timezone.utc)
    db.session.commit()
    # Consumed by _ApiAwareSessionInterface.save_session below - a Bearer
    # token-authenticated request must never receive a Set-Cookie session
    # header back (Flask-Login's own documented "Disabling Session Cookie
    # for APIs" recommendation, CITED in 02-RESEARCH.md).
    flask.g.login_via_request = True
    return row.user


class _ApiAwareSessionInterface(flask.sessions.SecureCookieSessionInterface):
    """Skips writing a Set-Cookie session header for token-authenticated
    requests (flask.g.login_via_request), otherwise behaves exactly like
    Flask's default session interface. Wired in create_app() via
    `app.session_interface = _ApiAwareSessionInterface()`."""

    def save_session(self, app, session, response):
        if getattr(flask.g, "login_via_request", False):
            return
        return super().save_session(app, session, response)
