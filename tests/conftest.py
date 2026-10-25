"""
Shared pytest fixtures for the glassbox test suite.

Env vars are set *before* anything under glassbox/ is imported, since
config.py reads them at module-import time (and raises RuntimeError if
SECRET_KEY is unset - see config.py's docstring). `os.environ.setdefault`
is used rather than a hard assignment so a developer's real .env (loaded
via python-dotenv inside config.py) still wins for values they've
deliberately set - but tests never *depend* on that; every value here has a
safe, deterministic test-only fallback so the suite also runs green in CI
with no .env file at all.
"""
import os

os.environ.setdefault("SECRET_KEY", "test-only-secret-never-used-outside-pytest")
os.environ.setdefault("SESSION_COOKIE_SECURE", "false")  # test client talks http, not https
os.environ.setdefault("EMAIL_MODE", "console")
os.environ.setdefault("GROQ_API_KEY", "")
# Blanked for the same reason as GROQ_API_KEY above: config.py's load_dotenv()
# call (override=False) won't clobber an env var already set by the time it
# runs, so this insulates the suite from whatever real Turnstile keys a
# developer's own .env has - a real key makes _turnstile_passes() actually
# hit Cloudflare's siteverify endpoint, which every signup test here isn't
# set up to satisfy (no real cf-turnstile-response token), and it fails
# closed by design (see auth_routes.py's _turnstile_passes docstring) - so
# an unblanked real key here would silently break every signup test.
os.environ.setdefault("TURNSTILE_SITE_KEY", "")
os.environ.setdefault("TURNSTILE_SECRET_KEY", "")

from datetime import UTC

import pytest
from werkzeug.security import generate_password_hash

from glassbox import create_app
from glassbox.config import Config
from glassbox.extensions import db as _db
from glassbox.models import ApiToken, Asset, Organization, Plan, Role, Scan, ScanStatus, User


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False  # form-posting tests don't need to juggle CSRF tokens
    RATELIMIT_ENABLED = False  # Limiter is a module-level singleton (extensions.py) shared
    # across every create_app() call in the same process - without this, rate-limit
    # counters from one test's requests would leak into the next test's app instance.
    SCHEDULER_ENABLED = False  # never start the in-process scheduler thread in the test
    # suite - the `app` fixture below creates a fresh Flask app (and disposable SQLite
    # file) per test, so an unconditionally-started scheduler thread would leak an
    # infinite background loop against a soon-to-be-deleted DB file for every test.


@pytest.fixture()
def app(tmp_path):
    """A fresh Flask app per test, backed by its own on-disk SQLite file
    under pytest's tmp_path (not ':memory:' - an in-memory DB is one
    connection only, and this app's SQLALCHEMY_ENGINE_OPTIONS
    (check_same_thread: False) plus Flask-SQLAlchemy's per-request
    connections need a real file to share state across them, same
    constraint documented in config.py for the background-scan-thread case).
    """
    db_path = tmp_path / "test.db"

    class _AppConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"

    application = create_app(_AppConfig)
    with application.app_context():
        # create_app() no longer calls db.create_all() itself (schema is now
        # Alembic's job - see migrations/ and glassbox/__init__.py) -
        # tests want instant fresh schema per-run, not a real migration
        # replay, so they create it directly here instead.
        _db.create_all()
    yield application
    with application.app_context():
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db(app):
    """The db extension, with an app context held open for the life of the
    test so direct ORM calls (Organization(...), db.session.add, etc.) work
    without every test needing its own `with app.app_context():` block."""
    with app.app_context():
        yield _db


# --------------------------------------------------------------------------
# Fixture-data factories. Plain functions (not fixtures themselves) so
# tests can call them multiple times with different args to build up
# multi-user/multi-org scenarios - request the `db` fixture first to get an
# active app context, then call these.
# --------------------------------------------------------------------------

def make_org(plan=Plan.FREE, name="Test Org"):
    org = Organization(name=name, plan=plan)
    _db.session.add(org)
    _db.session.flush()
    return org


def make_user(email, org=None, role=Role.MEMBER, password="password123", verified=True):
    from datetime import datetime

    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        org_id=org.id if org else None,
        role=role,
        email_verified_at=datetime.now(UTC) if verified else None,
    )
    _db.session.add(user)
    _db.session.flush()
    return user


def make_scan(user, org=None, target_url="https://example.com", scan_type="base",
              status=ScanStatus.QUEUED):
    scan = Scan(
        user_id=user.id,
        org_id=org.id if org else None,
        target_url=target_url,
        scan_type=scan_type,
        status=status,
    )
    _db.session.add(scan)
    _db.session.flush()
    return scan


def make_asset(org, user, name="Test Asset", target_url="https://example.com",
                cadence="daily", schedule_scan_type="base", next_run_at=None,
                is_paused=False, deleted_at=None):
    from datetime import datetime
    from urllib.parse import urlparse

    now = datetime.now(UTC)
    a = Asset(
        org_id=org.id if org else None,
        created_by_user_id=user.id,
        authorized_by_user_id=user.id,
        authorized_at=now,
        name=name,
        target_url=target_url,
        hostname=urlparse(target_url).hostname,
        cadence=cadence,
        schedule_scan_type=schedule_scan_type,
        next_run_at=next_run_at if next_run_at is not None else now,
        is_paused=is_paused,
        deleted_at=deleted_at,
    )
    _db.session.add(a)
    _db.session.flush()
    return a


def make_api_token(user, name="test", revoked=False):
    """Mirrors make_asset's shape: generates a raw token inline exactly like
    the real api_tokens_routes.create_token route does, hashes it, creates
    the ApiToken row, and returns BOTH the row and the raw token string so
    tests can authenticate as `Authorization: Bearer <raw_token>` without
    going through the HTML create-route first."""
    import hashlib
    import secrets
    from datetime import datetime

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    t = ApiToken(
        user_id=user.id,
        name=name,
        token_hash=token_hash,
        revoked_at=datetime.now(UTC) if revoked else None,
    )
    _db.session.add(t)
    _db.session.flush()
    return t, raw_token


def login(client, email, password="password123"):
    """Logs `client` in via the real /login route (not a session-cookie
    shortcut) so ownership/entitlement tests exercise the same auth path a
    real request would take."""
    return client.post(
        "/login", data={"email": email, "password": password}, follow_redirects=True,
    )
