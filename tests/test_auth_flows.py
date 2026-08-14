"""
Tests for webvulnscanner/auth_routes.py: signup, email verification, login,
logout, and the forgot-password/reset-password flow.

Fixture emails use .com/.org/.dev-style fake domains, never .test/.invalid/
.localhost - email_validator (backing WTForms' Email()) statically rejects
those reserved TLDs even with deliverability checking off (see CLAUDE.md's
Commands section / handoff.md for how this was found).
"""
from datetime import datetime, timedelta, timezone

import pytest
from werkzeug.security import check_password_hash, generate_password_hash

from webvulnscanner.email_stub import EmailSender
from webvulnscanner.models import Organization, PasswordReset, Plan, Role, User

from tests.conftest import login, make_org, make_user


class _SpyEmailSender(EmailSender):
    """Records every send() call instead of printing to the console, so
    tests can assert whether an email was (or, for the anti-enumeration
    case, was NOT) attempted, and pull the verify/reset URL out of the
    body without scraping HTML."""

    def __init__(self):
        self.sent = []

    def send(self, to, subject, body):
        self.sent.append({"to": to, "subject": subject, "body": body})


@pytest.fixture()
def spy_sender(app):
    sender = _SpyEmailSender()
    app.extensions["email_sender"] = sender
    return sender


# --------------------------------------------------------------------------
# Signup
# --------------------------------------------------------------------------

def test_signup_get_renders_form(client):
    resp = client.get("/signup")
    assert resp.status_code == 200


def test_signup_without_org_creates_solo_member(client, db, spy_sender):
    resp = client.post(
        "/signup",
        data={"email": "new@example.com", "password": "password123", "confirm_password": "password123"},
        follow_redirects=True,
    )
    assert resp.status_code == 200  # landed on /login after the redirect
    user = User.query.filter_by(email="new@example.com").first()
    assert user is not None
    assert user.org_id is None
    assert user.role == Role.MEMBER
    assert user.email_verified_at is None
    assert check_password_hash(user.password_hash, "password123")
    assert len(spy_sender.sent) == 1
    assert spy_sender.sent[0]["to"] == "new@example.com"


def test_signup_with_org_name_creates_org_and_makes_user_admin(client, db):
    resp = client.post(
        "/signup",
        data={
            "email": "founder@example.com", "password": "password123",
            "confirm_password": "password123", "org_name": "Acme Corp",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    user = User.query.filter_by(email="founder@example.com").first()
    assert user is not None
    assert user.role == Role.ORG_ADMIN
    assert user.org_id is not None
    org = Organization.query.get(user.org_id)
    assert org.name == "Acme Corp"
    assert org.plan == Plan.FREE  # new orgs always start FREE


def test_signup_duplicate_email_is_rejected(client, db):
    make_user("existing@example.com")
    resp = client.post(
        "/signup",
        data={"email": "existing@example.com", "password": "password123", "confirm_password": "password123"},
        follow_redirects=False,
    )
    assert resp.status_code == 200  # re-renders signup, no redirect
    assert User.query.filter_by(email="existing@example.com").count() == 1  # no duplicate created


def test_signup_email_is_case_insensitive_for_duplicate_check(client, db):
    make_user("existing@example.com")
    resp = client.post(
        "/signup",
        data={"email": "EXISTING@example.com", "password": "password123", "confirm_password": "password123"},
        follow_redirects=False,
    )
    assert User.query.count() == 1


def test_signup_rejects_short_password(client, db):
    resp = client.post(
        "/signup",
        data={"email": "weak@example.com", "password": "short", "confirm_password": "short"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert User.query.filter_by(email="weak@example.com").first() is None


def test_signup_rejects_mismatched_confirm_password(client, db):
    resp = client.post(
        "/signup",
        data={"email": "mismatch@example.com", "password": "password123", "confirm_password": "different123"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert User.query.filter_by(email="mismatch@example.com").first() is None


# --------------------------------------------------------------------------
# Turnstile bot-check (only active when TURNSTILE_SECRET_KEY is set - every
# test above signs up with no key configured, exercising the "unconfigured
# -> skip verification" degrade-open path implicitly).
# --------------------------------------------------------------------------

def test_signup_skips_turnstile_when_unconfigured(client, db):
    # No TURNSTILE_SECRET_KEY set (TestConfig doesn't set one) - signup
    # must succeed with no cf-turnstile-response field at all.
    resp = client.post(
        "/signup",
        data={"email": "nokey@example.com", "password": "password123", "confirm_password": "password123"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert User.query.filter_by(email="nokey@example.com").first() is not None


def test_signup_rejects_missing_turnstile_token_when_configured(client, db, app, monkeypatch):
    app.config["TURNSTILE_SECRET_KEY"] = "test-secret"
    resp = client.post(
        "/signup",
        data={"email": "notoken@example.com", "password": "password123", "confirm_password": "password123"},
        follow_redirects=False,
    )
    assert resp.status_code == 200  # re-rendered the form, not a redirect
    assert User.query.filter_by(email="notoken@example.com").first() is None
    app.config["TURNSTILE_SECRET_KEY"] = ""


def test_signup_rejects_failed_turnstile_verification(client, db, app, monkeypatch):
    from webvulnscanner import auth_routes

    app.config["TURNSTILE_SECRET_KEY"] = "test-secret"
    mock_resp = type("R", (), {"json": lambda self: {"success": False}})()
    monkeypatch.setattr(auth_routes.requests, "post", lambda *a, **k: mock_resp)

    resp = client.post(
        "/signup",
        data={
            "email": "badtoken@example.com", "password": "password123", "confirm_password": "password123",
            "cf-turnstile-response": "fake-token",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert User.query.filter_by(email="badtoken@example.com").first() is None
    app.config["TURNSTILE_SECRET_KEY"] = ""


def test_signup_succeeds_with_valid_turnstile_token(client, db, app, monkeypatch):
    from webvulnscanner import auth_routes

    app.config["TURNSTILE_SECRET_KEY"] = "test-secret"
    mock_resp = type("R", (), {"json": lambda self: {"success": True}})()
    monkeypatch.setattr(auth_routes.requests, "post", lambda *a, **k: mock_resp)

    resp = client.post(
        "/signup",
        data={
            "email": "goodtoken@example.com", "password": "password123", "confirm_password": "password123",
            "cf-turnstile-response": "real-token",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert User.query.filter_by(email="goodtoken@example.com").first() is not None
    app.config["TURNSTILE_SECRET_KEY"] = ""


def test_signup_turnstile_network_failure_fails_closed(client, db, app, monkeypatch):
    from webvulnscanner import auth_routes

    app.config["TURNSTILE_SECRET_KEY"] = "test-secret"

    def _boom(*a, **k):
        raise auth_routes.requests.RequestException("timeout")

    monkeypatch.setattr(auth_routes.requests, "post", _boom)

    resp = client.post(
        "/signup",
        data={
            "email": "netfail@example.com", "password": "password123", "confirm_password": "password123",
            "cf-turnstile-response": "some-token",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert User.query.filter_by(email="netfail@example.com").first() is None
    app.config["TURNSTILE_SECRET_KEY"] = ""


# --------------------------------------------------------------------------
# Email verification
# --------------------------------------------------------------------------

def test_verify_email_with_valid_token_marks_user_verified(client, db):
    client.post(
        "/signup",
        data={"email": "verifyme@example.com", "password": "password123", "confirm_password": "password123"},
    )
    user = User.query.filter_by(email="verifyme@example.com").first()
    token = user.verify_token
    assert token is not None

    resp = client.get(f"/verify-email/{token}")
    assert resp.status_code == 200

    db.session.refresh(user)
    assert user.email_verified_at is not None
    assert user.verify_token is None


def test_verify_email_with_unknown_token_shows_invalid(client, db):
    resp = client.get("/verify-email/not-a-real-token")
    assert resp.status_code == 200
    assert b"nvalid" in resp.data or b"expired" in resp.data.lower()


def test_verify_email_token_is_single_use(client, db):
    client.post(
        "/signup",
        data={"email": "onceonly@example.com", "password": "password123", "confirm_password": "password123"},
    )
    user = User.query.filter_by(email="onceonly@example.com").first()
    token = user.verify_token

    first = client.get(f"/verify-email/{token}")
    assert first.status_code == 200
    second = client.get(f"/verify-email/{token}")
    assert b"nvalid" in second.data or b"expired" in second.data.lower()


# --------------------------------------------------------------------------
# Login
# --------------------------------------------------------------------------

def test_login_with_valid_credentials_redirects_to_dashboard(client, db):
    make_user("owner@example.com")
    resp = client.post(
        "/login", data={"email": "owner@example.com", "password": "password123"}, follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/dashboard")


def test_login_with_wrong_password_is_rejected(client, db):
    make_user("owner@example.com")
    resp = client.post(
        "/login", data={"email": "owner@example.com", "password": "wrong-password"}, follow_redirects=False,
    )
    assert resp.status_code == 200
    assert b"Invalid email or password" in resp.data


def test_login_with_unknown_email_gives_identical_error_to_wrong_password(client, db):
    # Same flash message either way, guarding against user enumeration via
    # the login form itself.
    resp_unknown = client.post(
        "/login", data={"email": "nobody@example.com", "password": "password123"}, follow_redirects=False,
    )
    make_user("owner@example.com")
    resp_wrong_pw = client.post(
        "/login", data={"email": "owner@example.com", "password": "wrong-password"}, follow_redirects=False,
    )
    assert b"Invalid email or password" in resp_unknown.data
    assert b"Invalid email or password" in resp_wrong_pw.data


def test_login_remember_me_sets_remember_cookie(client, db):
    make_user("owner@example.com")
    resp = client.post(
        "/login",
        data={"email": "owner@example.com", "password": "password123", "remember": "y"},
        follow_redirects=False,
    )
    cookie_names = [c.split("=")[0] for c in resp.headers.get_all("Set-Cookie")]
    assert any(name == "remember_token" for name in cookie_names)


def test_login_ignores_absolute_url_next_param(client, db):
    # _safe_next() must reject a `next` that isn't a relative in-app path -
    # otherwise the post-login redirect becomes an open redirect.
    make_user("owner@example.com")
    resp = client.post(
        "/login?next=https://evil.example.com/phish",
        data={"email": "owner@example.com", "password": "password123"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/dashboard"


def test_login_ignores_protocol_relative_next_param(client, db):
    make_user("owner@example.com")
    resp = client.post(
        "/login?next=//evil.example.com",
        data={"email": "owner@example.com", "password": "password123"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/dashboard"


def test_login_honors_relative_next_param(client, db):
    make_user("owner@example.com")
    resp = client.post(
        "/login?next=/scan/new",
        data={"email": "owner@example.com", "password": "password123"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/scan/new"


# --------------------------------------------------------------------------
# Logout
# --------------------------------------------------------------------------

def test_logout_ends_the_session(client, db):
    make_user("owner@example.com")
    login(client, "owner@example.com")
    assert client.get("/dashboard").status_code == 200

    resp = client.get("/logout", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/login")

    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


# --------------------------------------------------------------------------
# Forgot password / reset password
# --------------------------------------------------------------------------

def test_forgot_password_for_existing_email_creates_reset_row(client, db, spy_sender):
    make_user("owner@example.com")
    resp = client.post("/forgot-password", data={"email": "owner@example.com"}, follow_redirects=True)
    assert resp.status_code == 200
    assert PasswordReset.query.count() == 1
    assert len(spy_sender.sent) == 1


def test_forgot_password_for_unknown_email_creates_no_row_but_looks_identical(client, db, spy_sender):
    # The anti-enumeration guarantee: response is indistinguishable, but
    # nothing was actually created or sent for a non-existent address.
    known_resp = client.post("/forgot-password", data={"email": "unknown-does-not-exist@example.com"},
                              follow_redirects=True)
    assert known_resp.status_code == 200
    assert b"a reset link has been sent" in known_resp.data.lower()
    assert PasswordReset.query.count() == 0
    assert len(spy_sender.sent) == 0


def test_reset_password_with_valid_token_updates_password_and_logs_in_with_new_one(client, db):
    user = make_user("owner@example.com", password="oldpassword1")
    token = "valid-token-abc"
    db.session.add(PasswordReset(
        user_id=user.id, token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
    ))
    db.session.flush()

    resp = client.post(
        f"/reset-password/{token}",
        data={"password": "newpassword1", "confirm_password": "newpassword1"},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    db.session.refresh(user)
    assert check_password_hash(user.password_hash, "newpassword1")
    assert not check_password_hash(user.password_hash, "oldpassword1")

    # Old password no longer works, new one does.
    assert client.post("/login", data={"email": "owner@example.com", "password": "oldpassword1"},
                        follow_redirects=False).status_code == 200  # re-renders with error
    assert client.post("/login", data={"email": "owner@example.com", "password": "newpassword1"},
                        follow_redirects=False).status_code == 302  # succeeds


def test_reset_password_token_is_single_use(client, db):
    user = make_user("owner@example.com", password="oldpassword1")
    token = "single-use-token"
    db.session.add(PasswordReset(
        user_id=user.id, token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
    ))
    db.session.flush()

    first = client.post(f"/reset-password/{token}",
                         data={"password": "firstnewpw1", "confirm_password": "firstnewpw1"},
                         follow_redirects=False)
    assert first.status_code == 302  # succeeded, redirected to login

    second = client.post(f"/reset-password/{token}",
                          data={"password": "secondnewpw1", "confirm_password": "secondnewpw1"},
                          follow_redirects=True)
    assert b"invalid or has expired" in second.data.lower()

    db.session.refresh(user)
    assert check_password_hash(user.password_hash, "firstnewpw1")  # second attempt didn't overwrite it


def test_reset_password_rejects_expired_token(client, db):
    user = make_user("owner@example.com", password="oldpassword1")
    token = "expired-token"
    db.session.add(PasswordReset(
        user_id=user.id, token=token,
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),  # already expired
    ))
    db.session.flush()

    resp = client.post(f"/reset-password/{token}",
                        data={"password": "newpassword1", "confirm_password": "newpassword1"},
                        follow_redirects=True)
    assert b"invalid or has expired" in resp.data.lower()

    db.session.refresh(user)
    assert check_password_hash(user.password_hash, "oldpassword1")  # unchanged


def test_reset_password_rejects_unknown_token(client, db):
    resp = client.get("/reset-password/does-not-exist", follow_redirects=True)
    assert b"invalid or has expired" in resp.data.lower()


def test_reset_password_rejects_mismatched_confirmation(client, db):
    user = make_user("owner@example.com", password="oldpassword1")
    token = "mismatch-token"
    db.session.add(PasswordReset(
        user_id=user.id, token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
    ))
    db.session.flush()

    resp = client.post(f"/reset-password/{token}",
                        data={"password": "newpassword1", "confirm_password": "different1"},
                        follow_redirects=False)
    assert resp.status_code == 200  # form re-rendered, no redirect

    db.session.refresh(user)
    assert check_password_hash(user.password_hash, "oldpassword1")  # unchanged


# --------------------------------------------------------------------------
# Rate limiting - disabled everywhere else in this suite (TestConfig sets
# RATELIMIT_ENABLED=False so unrelated tests aren't flaky against the
# Limiter's process-wide in-memory storage), so this is the one test that
# deliberately turns it back on to confirm the /login limit documented in
# CLAUDE.md ("10/min") is actually wired up.
# --------------------------------------------------------------------------

def test_login_rate_limit_is_enforced(tmp_path):
    from webvulnscanner import create_app
    from webvulnscanner.extensions import limiter as _limiter
    from tests.conftest import TestConfig

    class _RateLimitedConfig(TestConfig):
        RATELIMIT_ENABLED = True
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'ratelimit.db'}"

    rl_app = create_app(_RateLimitedConfig)
    with rl_app.app_context():
        from webvulnscanner.extensions import db as _db
        _db.create_all()
    _limiter.reset()
    try:
        rl_client = rl_app.test_client()
        statuses = []
        for _ in range(11):
            resp = rl_client.post(
                "/login", data={"email": "nobody@example.com", "password": "wrong"}, follow_redirects=False,
            )
            statuses.append(resp.status_code)
        assert 429 in statuses, f"expected a 429 within 11 requests against a 10/min limit, got {statuses}"
    finally:
        _limiter.reset()  # don't leak a tripped limit into whichever test runs next
