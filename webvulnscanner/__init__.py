"""
App factory for the webvulnscanner package.

`app.py` at the repo root is now the thin factory around this package
(Workstream 4's cutover): `from webvulnscanner import create_app; app =
create_app()`. All 5 blueprints (auth, org, billing, scan, public) are
registered here.
"""
import logging
import os
from urllib.parse import urlsplit, urlunsplit

import click
from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from flask_wtf.csrf import CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix

from webvulnscanner.config import Config
from webvulnscanner.email_stub import make_email_sender
from webvulnscanner.extensions import (
    _ApiAwareSessionInterface,
    csrf,
    db,
    limiter,
    login_manager,
    migrate,
)


def _maybe_start_scheduler(app):
    """Three-part guard (01-RESEARCH.md Pattern 1) so the in-process
    scheduler thread starts exactly once per real process and never during
    the test suite:
      (a) explicit config opt-out (SCHEDULER_ENABLED, e.g. ops maintenance)
      (b) TESTING - tests/conftest.py's `app` fixture creates a fresh Flask
          app (and disposable SQLite file) per test; without this check
          every test would leak an infinite background thread
      (c) the standard Werkzeug-reloader guard - `flask run --debug` forks a
          child process that re-imports/re-runs create_app(); only the
          reloader's actual child process (WERKZEUG_RUN_MAIN == "true")
          should start the thread. Production (gunicorn) never sets
          app.debug True, so `not app.debug` alone covers it there.
    """
    if not app.config.get("SCHEDULER_ENABLED", True):
        return
    if app.config.get("TESTING", False):
        return
    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return
    from webvulnscanner.scheduler import start_scheduler

    start_scheduler(app)


def _init_sentry(app):
    """Best-effort Sentry init - never raises, never required. sentry-sdk
    isn't a hard dependency (not in requirements.txt): if it's not
    installed, or SENTRY_DSN isn't set, this is a silent no-op with a log
    line, same degrade-gracefully convention as ai_summary.py's Groq call.
    Add `sentry-sdk[flask]` to requirements.txt and set SENTRY_DSN to
    actually activate it - see docs/env-vars.md."""
    dsn = app.config.get("SENTRY_DSN")
    if not dsn:
        return
    try:
        import sentry_sdk
        from sentry_sdk.integrations.flask import FlaskIntegration
    except ImportError:
        logging.warning(
            "SENTRY_DSN is set but sentry-sdk isn't installed - add "
            "sentry-sdk[flask] to requirements.txt to activate it."
        )
        return
    sentry_sdk.init(dsn=dsn, integrations=[FlaskIntegration()], traces_sample_rate=0.1)


def _safe_referrer():
    # Same-origin-only redirect target for the CSRFError handler below,
    # built from request.referrer - an attacker-controllable request
    # header, not trusted input, so it must never reach a redirect call
    # unvalidated, the same class of bug auth_routes.py's `next` param
    # guards against (SEC-07). Kept as its own named function (mirroring
    # _safe_next()'s pattern) rather than inlined, so
    # tests/test_auth_flows.py::test_only_safe_next_redirects_take_a_
    # request_derived_argument - which source-scans webvulnscanner/ for
    # every redirect call site and fails closed on anything that isn't
    # url_for(...) or a named, reviewed safe-redirect helper - has a
    # second, equally auditable pattern to recognize instead of a raw
    # inline referrer value reaching a redirect call unaudited.
    #
    # Falls back to the homepage when there's no referrer, or it isn't
    # same-origin (scheme+host match request.host) - a CSRF-token expiry
    # is common (idle timeout, a stale second tab) and deliberately never
    # reaches this codepath from a genuinely cross-site request in the
    # first place (that's what CSRFProtect just rejected), but the
    # referrer header itself is still not proof of that on its own.
    referrer = request.referrer
    if referrer:
        parsed = urlsplit(referrer)
        if (not parsed.scheme or parsed.scheme in ("http", "https")) and parsed.netloc == request.host:
            return urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    return url_for("public.index")


def create_app(config_class=Config):
    app = Flask(__name__, template_folder="../templates")
    app.config.from_object(config_class)

    # Trust exactly one reverse-proxy hop's X-Forwarded-* headers (Render's
    # edge proxy / Vercel's) - see config.py's TRUST_PROXY_HOPS docstring
    # for why this matters for both rate limiting and HTTPS-scheme
    # detection. A value of 0 (set TRUST_PROXY_HOPS=0) disables this for a
    # direct/unproxied deployment, where trusting forwarded headers from an
    # arbitrary client would let them spoof their own IP/scheme.
    hops = app.config.get("TRUST_PROXY_HOPS", 0)
    if hops > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops, x_host=hops)

    _init_sentry(app)

    db.init_app(app)
    login_manager.init_app(app)
    # A Bearer-token-authenticated request (Phase 2, login_manager.request_loader
    # in extensions.py) must never receive a Set-Cookie session header back -
    # Flask-Login's own documented recommendation. Set once, right after
    # login_manager.init_app(app), per 02-RESEARCH.md's Pattern 1 caveat.
    app.session_interface = _ApiAwareSessionInterface()
    csrf.init_app(app)
    limiter.init_app(app)
    # Operator-facing confirmation of which rate-limit storage backend this
    # worker actually attached to (HARD-01) - a misconfigured worker
    # otherwise fails silently by enforcing its own private in-memory
    # counters instead of the shared backend an operator thinks it's using.
    # Logs the URI scheme only, never the full RATELIMIT_STORAGE_URI value -
    # a redis:// URL routinely carries a password.
    _storage_uri = app.config.get("RATELIMIT_STORAGE_URI", "")
    if _storage_uri:
        _storage_scheme = _storage_uri.split("://", 1)[0]
        logging.info(
            "Rate limiting: using %s:// storage backend (shared across workers)",
            _storage_scheme,
        )
    else:
        logging.info(
            "Rate limiting: using in-memory storage (NOT shared across workers - "
            "single-process only; set RATELIMIT_STORAGE_URI for a multi-worker deploy)"
        )
    migrate.init_app(app, db)

    # Email sender is stashed on app.extensions (Flask's own convention for
    # extension-owned, app-scoped state) so route code can reach it via
    # current_app.extensions["email_sender"].
    app.extensions["email_sender"] = make_email_sender(
        app.config["EMAIL_MODE"], app.config["RESEND_API_KEY"], app.config["RESEND_FROM_EMAIL"],
    )

    from webvulnscanner.auth_routes import auth as auth_blueprint

    app.register_blueprint(auth_blueprint)

    from webvulnscanner.org_routes import org as org_blueprint

    app.register_blueprint(org_blueprint)

    from webvulnscanner.admin_routes import admin as admin_blueprint

    app.register_blueprint(admin_blueprint)

    from webvulnscanner.billing_routes import billing_bp as billing_blueprint

    app.register_blueprint(billing_blueprint)

    from webvulnscanner.scan_routes import scan as scan_blueprint

    app.register_blueprint(scan_blueprint)

    from webvulnscanner.asset_routes import asset as asset_blueprint

    app.register_blueprint(asset_blueprint)

    from webvulnscanner.public_routes import public as public_blueprint

    app.register_blueprint(public_blueprint)

    from webvulnscanner.api_tokens_routes import api_tokens as api_tokens_blueprint

    app.register_blueprint(api_tokens_blueprint)

    from webvulnscanner.api_routes import api as api_blueprint

    app.register_blueprint(api_blueprint)

    from webvulnscanner.assessment_routes import assessment as assessment_blueprint

    app.register_blueprint(assessment_blueprint)

    # Idle-session timeout: a session-cookie-authenticated user is signed
    # out server-side after IDLE_TIMEOUT_MINUTES with no request, regardless
    # of "Remember me" - logout_user() clears the remember cookie too, so a
    # stale remember cookie can't silently re-authenticate the next request.
    # Bearer-token (API) auth is explicitly exempt: those requests set
    # flask.g.login_via_request in extensions.py's request_loader and never
    # receive a session cookie back in the first place (see
    # _ApiAwareSessionInterface) - tokens have their own separate
    # revoke/expiry model in api_tokens_routes.py, not this one.
    @app.before_request
    def _enforce_idle_timeout():
        import flask
        from datetime import datetime, timedelta, timezone

        from flask import request, session
        from flask_login import current_user, logout_user

        if not current_user.is_authenticated:
            return
        if getattr(flask.g, "login_via_request", False):
            return

        now = datetime.now(timezone.utc)
        timeout = timedelta(minutes=app.config.get("IDLE_TIMEOUT_MINUTES", 5))
        last_seen_raw = session.get("_last_seen")
        if last_seen_raw:
            try:
                last_seen = datetime.fromisoformat(last_seen_raw)
            except ValueError:
                last_seen = None
            if last_seen is not None and now - last_seen > timeout:
                logout_user()
                session.clear()
                return
        # scan_progress.html's background status poll (2s) / SSE feed both
        # send the session cookie (credentials: same-origin) but are not
        # user activity - bumping _last_seen on every tick would keep an
        # AFK session alive indefinitely for the duration of any scan. Every
        # other request still refreshes it normally.
        if not (request.path.endswith("/status") or request.path.endswith("/events")):
            session["_last_seen"] = now.isoformat()

    from webvulnscanner.models import Role

    @app.context_processor
    def inject_role_enum():
        # base.html's nav checks current_user.role == Role.ORG_ADMIN;
        # base.html's footer and terms.html/privacy.html use current_year.
        from datetime import datetime, timezone

        return {
            "Role": Role,
            "current_year": datetime.now(timezone.utc).year,
            "idle_timeout_minutes": app.config.get("IDLE_TIMEOUT_MINUTES", 5),
        }

    # Custom error pages so 404/500 stay inside the app's own dark theme
    # (nav, back-to-dashboard link) instead of dropping a logged-in user
    # into Flask's raw unstyled default error page.
    @app.errorhandler(404)
    def _not_found(_e):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def _server_error(_e):
        db.session.rollback()
        return render_template("500.html"), 500

    @app.errorhandler(429)
    def _rate_limited(_e):
        return render_template("429.html"), 429

    # A CSRF token expires with the session that issued it (SESSION_COOKIE
    # ... / PERMANENT_SESSION_LIFETIME) - hitting an idle-timeout logout,
    # then submitting a form still open in another tab, is a completely
    # ordinary way to trip this, not an attack. Flask-WTF's CSRFProtect
    # raises this as a raw 400 with no handler registered, which used to
    # surface Flask's unstyled default error page (and its literal
    # "The CSRF token has expired." message) straight to the user - a
    # backend implementation detail leaking through, and confusing since
    # every other error in this app stays inside the themed error pages
    # above. Bounce back to the page that was submitted (its GET render
    # mints a fresh token via csrf_token()/hidden_tag()) with a plain-
    # English flash instead.
    @app.errorhandler(CSRFError)
    def _csrf_error(_e):
        # scan_new_advanced.html's Smart Setup fetch() call (the only
        # X-Requested-With: XMLHttpRequest sender in the app) expects a
        # JSON error body it can show inline, not an HTML redirect a fetch()
        # would just follow and then fail to JSON.parse - give it the same
        # shape its view already uses for its own validation errors.
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(error="Your session expired - please refresh and try again."), 400

        flash("Your session expired - please try again.", "error")
        return redirect(_safe_referrer())

    @app.cli.command("grant-platform-admin")
    @click.argument("email")
    def grant_platform_admin(email):
        """Grants User.is_platform_admin to an existing account by email.

        The only way to create a platform admin - no route or UI can set
        this flag (see User.is_platform_admin's docstring in models.py),
        so bootstrapping the first one is deliberately a server-access-only
        operation: `flask grant-platform-admin someone@example.com`.
        """
        from webvulnscanner.models import User

        user = User.query.filter_by(email=email.strip().lower()).first()
        if user is None:
            click.echo(f"No user found with email {email!r}.")
            return
        user.is_platform_admin = True
        db.session.commit()
        click.echo(f"Granted platform-admin to {user.email}.")

    @app.cli.command("revoke-platform-admin")
    @click.argument("email")
    def revoke_platform_admin(email):
        """Reverses grant-platform-admin."""
        from webvulnscanner.models import User

        user = User.query.filter_by(email=email.strip().lower()).first()
        if user is None:
            click.echo(f"No user found with email {email!r}.")
            return
        user.is_platform_admin = False
        db.session.commit()
        click.echo(f"Revoked platform-admin from {user.email}.")

    with app.app_context():
        # Import only, to register models with db.Model - schema creation is
        # now owned by Alembic (`flask db upgrade`, see migrations/ and
        # CLAUDE.md's Commands section), not an implicit db.create_all() here.
        # That unconditional call used to run on every app start, which is
        # also what silently masked adding a column to an existing table
        # never actually applying to a real, already-created DB - the exact
        # failure mode migrations exist to fix.
        from webvulnscanner import models  # noqa: F401

    _maybe_start_scheduler(app)

    return app
