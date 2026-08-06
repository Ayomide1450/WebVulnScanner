"""
Shared pytest fixtures for the webvulnscanner test suite.

Env vars are set *before* anything under webvulnscanner/ is imported, since
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

import pytest
from werkzeug.security import generate_password_hash

from webvulnscanner import create_app
from webvulnscanner.config import Config
from webvulnscanner.extensions import db as _db
from webvulnscanner.models import Organization, Plan, Role, Scan, ScanStatus, User


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False  # form-posting tests don't need to juggle CSRF tokens
    RATELIMIT_ENABLED = False  # Limiter is a module-level singleton (extensions.py) shared
    # across every create_app() call in the same process - without this, rate-limit
    # counters from one test's requests would leak into the next test's app instance.


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
    from datetime import datetime, timezone

    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        org_id=org.id if org else None,
        role=role,
        email_verified_at=datetime.now(timezone.utc) if verified else None,
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


def login(client, email, password="password123"):
    """Logs `client` in via the real /login route (not a session-cookie
    shortcut) so ownership/entitlement tests exercise the same auth path a
    real request would take."""
    return client.post(
        "/login", data={"email": email, "password": password}, follow_redirects=True,
    )
