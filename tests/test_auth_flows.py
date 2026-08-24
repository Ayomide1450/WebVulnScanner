"""
Tests for webvulnscanner/auth_routes.py: signup, email verification, login,
logout, and the forgot-password/reset-password flow.

Fixture emails use .com/.org/.dev-style fake domains, never .test/.invalid/
.localhost - email_validator (backing WTForms' Email()) statically rejects
those reserved TLDs even with deliverability checking off (see CLAUDE.md's
Commands section / handoff.md for how this was found).
"""
import pathlib
import re
from datetime import datetime, timedelta, timezone

import pytest
from werkzeug.security import check_password_hash, generate_password_hash

from webvulnscanner.email_stub import EmailSender
from webvulnscanner.models import Organization, PasswordReset, Plan, Role, User

from tests.conftest import login, make_org, make_user

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WEBVULNSCANNER_DIR = REPO_ROOT / "webvulnscanner"


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


# --------------------------------------------------------------------------
# Email-verification gate on login (reversed from the old documented
# decision that unverified email does not block login)
# --------------------------------------------------------------------------

def test_unverified_user_cannot_log_in(client, db, spy_sender):
    user = make_user("pending@example.com", verified=False)
    resp = client.post(
        "/login", data={"email": "pending@example.com", "password": "password123"}, follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"verify your email address" in resp.data
    # No session was created - a protected page still bounces to login.
    resp2 = client.get("/dashboard", follow_redirects=False)
    assert resp2.status_code == 302
    assert "/login" in resp2.headers["Location"]
    assert user.email_verified_at is None


def test_verified_user_can_still_log_in(client, db):
    make_user("verified@example.com")  # make_user defaults to verified=True
    resp = client.post(
        "/login", data={"email": "verified@example.com", "password": "password123"}, follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/dashboard")


def test_blocked_login_offers_the_resend_option(client, db):
    make_user("pending@example.com", verified=False)
    resp = client.post(
        "/login", data={"email": "pending@example.com", "password": "password123"}, follow_redirects=True,
    )
    assert b"resend" in resp.data.lower()
    assert 'action="/resend-verification"' in resp.data.decode()


def test_resend_verification_re_sends_for_pending_account(client, db, spy_sender):
    make_user("pending@example.com", verified=False)
    client.get("/login")  # prime the CSRF cookie/token like a real visit
    resp = client.post(
        "/resend-verification",
        data={"email": "pending@example.com"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert len(spy_sender.sent) == 1
    assert spy_sender.sent[0]["to"] == "pending@example.com"
    assert "verify-email/" in spy_sender.sent[0]["body"]


def test_resend_verification_is_antienumeration_for_unknown_email(client, db, spy_sender):
    client.get("/login")
    resp = client.post(
        "/resend-verification",
        data={"email": "ghost@example.com"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert len(spy_sender.sent) == 0
    # The neutral flash is identical to the pending-account case.
    assert b"fresh verification link has been sent" in resp.data


def test_resend_verification_sends_nothing_for_already_verified_account(client, db, spy_sender):
    make_user("done@example.com")  # verified
    client.get("/login")
    resp = client.post(
        "/resend-verification",
        data={"email": "done@example.com"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert len(spy_sender.sent) == 0


def test_resend_verification_mints_token_for_tokenless_legacy_row(client, db, spy_sender):
    """A pre-gate unverified row with no stored verify_token (legacy shape)
    gets one minted by the resend endpoint so its link actually works."""
    legacy = make_user("legacy@example.com", verified=False)
    legacy.verify_token = None
    db.session.commit()
    client.get("/login")
    resp = client.post(
        "/resend-verification",
        data={"email": "legacy@example.com"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    db.session.expire(legacy)
    assert legacy.verify_token is not None
    assert "verify-email/" in spy_sender.sent[0]["body"]


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


import urllib.parse

# SEC-07 adversarial `next` shapes (08-06). Each probes the edges of
# _safe_next()'s two literal conditions ("starts with a slash", "does not
# start with two") - see auth_routes.py's own docstring for why the
# backslash and embedded-newline cases required a real fix (a live finding,
# not just a missing test - see 08-06-SUMMARY.md).
#
# Every payload is delivered via urllib.parse.urlencode(), which round-trips
# through Werkzeug's own query-string percent-decoding back to exactly the
# string written here by the time it reaches _safe_next() - so what's typed
# below is what the guard actually sees, regardless of how a real browser
# would have encoded the same value.
_ADVERSARIAL_NEXT_CASES = [
    pytest.param("http://evil.example.com/phish", id="absolute_http_url"),
    pytest.param("https://evil.example.com/phish", id="absolute_https_url"),
    pytest.param("//evil.example.com", id="protocol_relative_url"),
    pytest.param("/\\evil.example.com", id="backslash_prefixed_path"),
    pytest.param(" https://evil.example.com/phish", id="whitespace_prefixed_absolute_url"),
    pytest.param("/ok\nSet-Cookie: evil=1", id="embedded_newline"),
]


@pytest.mark.parametrize("payload", _ADVERSARIAL_NEXT_CASES)
def test_login_rejects_adversarial_next_params_and_falls_back_to_default(client, db, payload):
    # Every shape here must land on the in-app default - not merely "not
    # the payload". A guard that redirected somewhere else off-origin would
    # pass a weaker "!=" assertion; this is the strict one 08-06-PLAN.md
    # requires.
    make_user("owner@example.com")
    qs = urllib.parse.urlencode({"next": payload})
    resp = client.post(
        f"/login?{qs}",
        data={"email": "owner@example.com", "password": "password123"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/dashboard"


def test_login_rejects_double_percent_encoded_next_param(client, db):
    # A distinct shape from the family above: this one is built by hand,
    # not via urlencode(), specifically so the raw query string sent over
    # the wire is "%252F%252Fevil.example.com" - Werkzeug's single-pass
    # percent-decoding turns that into the literal string "%2F%2Fevil.example.com"
    # (one decode: %25 -> "%", "2F" stays as two literal characters) rather
    # than "//evil.example.com" - proving a second decode pass never
    # happens anywhere between the query string and _safe_next(), so
    # double-encoding buys an attacker nothing here.
    make_user("owner@example.com")
    resp = client.post(
        "/login?next=%252F%252Fevil.example.com",
        data={"email": "owner@example.com", "password": "password123"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/dashboard"


def test_login_honors_relative_next_param(client, db):
    # The positive control, immediately adjacent to the adversarial family
    # above - without this, every rejection above would also pass on a
    # _safe_next() that always returned the default no matter what.
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


def test_logout_ignores_a_next_param_supplied_on_the_logout_request(client, db):
    # logout() takes no `next` at all - it always redirects to
    # url_for("auth.login") with no user input reaching the redirect
    # target. SEC-07 names logout by name; this turns "it ignores input
    # entirely" into an assertion rather than a reading of the source.
    make_user("owner@example.com")
    login(client, "owner@example.com")

    resp = client.get(
        "/logout?next=https://evil.example.com/phish", follow_redirects=False,
    )

    assert resp.status_code == 302
    assert resp.headers["Location"] == "/login"


# --------------------------------------------------------------------------
# SEC-07 sole-surface source lock: every user-influenced redirect target
# anywhere in webvulnscanner/ must go through one of exactly two named,
# reviewed helpers - _safe_next() (the `next` query-param case) or
# _safe_referrer() (the CSRFError handler's `request.referrer` case, added
# Phase 10, 08-20/21) - never a bare, unaudited expression. Same
# comment-filtered, full-line-only source-scanning idiom as
# tests/test_csrf_enforcement.py's _find_csrf_exempt_call_sites and
# tests/test_injection_and_traversal.py's autoescape/Markup/execute-call-site
# locks (08-02/08-05).
# --------------------------------------------------------------------------

_REDIRECT_CALL_RE = re.compile(r"(?<![\w.])redirect\(")

# The exact, closed set of call sites allowed to build a redirect() target
# from _safe_next() - module name + line number. A fourth call site (a new
# route reusing _safe_next(), or the same three moving) fails this by name
# rather than by count.
_EXPECTED_SAFE_NEXT_CALL_SITES = {
    ("auth_routes.py", 165),
    ("auth_routes.py", 311),
    ("auth_routes.py", 354),
}

# Same closed-set treatment for _safe_referrer() (webvulnscanner/__init__.py's
# CSRFError handler) - currently exactly one call site. Line moved 303 -> 307
# when Phase 19 registered the webhooks blueprint above it, then 307 -> 311
# when Phase 21 registered the selftest blueprint, then 311 -> 315 when
# Phase 22 registered the api_docs blueprint.
_EXPECTED_SAFE_REFERRER_CALL_SITES = {
    ("__init__.py", 315),
}


def _find_redirect_call_sites():
    """Reads every .py file under webvulnscanner/, strips full-line '#'
    comments (a trailing inline comment on a real call site is still
    counted - only a comment-only line is skipped), and collects every
    `redirect(...)` call together with the text immediately following the
    opening paren, so each call's argument can be classified without
    needing to fully parse nested parens."""
    hits = []
    for path in sorted(WEBVULNSCANNER_DIR.rglob("*.py")):
        for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if raw_line.strip().startswith("#"):
                continue
            code_part = raw_line.split("#", 1)[0]
            for m in _REDIRECT_CALL_RE.finditer(code_part):
                argument = code_part[m.end():].strip()
                hits.append((path.relative_to(REPO_ROOT), path.name, lineno, argument, code_part.strip()))
    return hits


def test_only_safe_next_redirects_take_a_request_derived_argument():
    hits = _find_redirect_call_sites()
    assert hits, "no redirect() call sites found at all - the scan itself is broken"

    safe_next_sites = set()
    safe_referrer_sites = set()
    violations = []
    for rel_path, name, lineno, argument, line in hits:
        if argument.startswith("_safe_next("):
            safe_next_sites.add((name, lineno))
            continue
        if argument.startswith("_safe_referrer("):
            safe_referrer_sites.add((name, lineno))
            continue
        if argument.startswith("url_for("):
            continue
        violations.append(f"{rel_path}:{lineno} -> redirect({argument!r}) (full line: {line!r})")

    assert not violations, (
        "redirect() call site(s) with an argument that is neither url_for(...), "
        "_safe_next(), nor _safe_referrer() (SEC-07 regression) - a "
        f"request-derived redirect target outside those helpers may have been introduced: {violations}"
    )
    assert safe_next_sites == _EXPECTED_SAFE_NEXT_CALL_SITES, (
        f"the set of _safe_next()-based redirect() call sites changed - "
        f"expected exactly {sorted(_EXPECTED_SAFE_NEXT_CALL_SITES)}, "
        f"found {sorted(safe_next_sites)}"
    )
    assert safe_referrer_sites == _EXPECTED_SAFE_REFERRER_CALL_SITES, (
        f"the set of _safe_referrer()-based redirect() call sites changed - "
        f"expected exactly {sorted(_EXPECTED_SAFE_REFERRER_CALL_SITES)}, "
        f"found {sorted(safe_referrer_sites)}"
    )


# Negative control performed manually while writing this test (not itself a
# permanent test): a scratch route
#   @auth.route("/_neg_control_redirect")
#   def _neg_control_redirect():
#       return redirect(request.args.get("next"))
# was added directly below logout() in webvulnscanner/auth_routes.py, this
# test was run alone, and the route was reverted immediately after. Observed
# failure (recorded verbatim, mirroring 08-02's/08-05's own negative-control
# recording convention):
#
#   AssertionError: redirect() call site(s) with an argument that is neither
#   url_for(...) nor _safe_next() (SEC-07 regression) - a request-derived
#   redirect target outside _safe_next() may have been introduced:
#   ['webvulnscanner\\auth_routes.py:301 -> redirect(\'request.args.get("next"))\') '
#    "(full line: 'return redirect(request.args.get(\"next\"))')"]
#
# `git diff --stat webvulnscanner/auth_routes.py` confirmed empty afterward.


_NEXT_HELPER_DEF_RE = re.compile(r"^\s*def\s+(\w*next\w*)\s*\(", re.IGNORECASE)


def _find_next_parameter_helper_defs():
    """Same comment-filtered scan, looking for any function definition
    whose name contains 'next' (case-insensitive) - catches a second,
    divergent next-parameter guard being added anywhere in the app, not
    just a second call to the existing one."""
    hits = []
    for path in sorted(WEBVULNSCANNER_DIR.rglob("*.py")):
        for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if raw_line.strip().startswith("#"):
                continue
            code_part = raw_line.split("#", 1)[0]
            m = _NEXT_HELPER_DEF_RE.match(code_part)
            if m:
                hits.append((path.name, lineno, m.group(1)))
    return hits


def test_only_one_next_parameter_helper_is_defined():
    hits = _find_next_parameter_helper_defs()
    assert hits == [("auth_routes.py", 94, "_safe_next")], (
        f"expected exactly one next-parameter-style helper "
        f"(auth_routes.py's _safe_next, line 94), found {hits} - a second, "
        f"possibly divergent redirect-target guard may have been added"
    )


# Negative control performed manually while writing this test (not itself a
# permanent test): a second helper
#   def _get_safe_next_url(default="/dashboard"):
#       return default
# was added directly below logout() in webvulnscanner/auth_routes.py, this
# test was run alone, and the helper was reverted immediately after.
# Observed failure:
#
#   AssertionError: expected exactly one next-parameter-style helper
#   (auth_routes.py's _safe_next, line 90), found [('auth_routes.py', 90,
#   '_safe_next'), ('auth_routes.py', 299, '_get_safe_next_url')] - a
#   second, possibly divergent redirect-target guard may have been added
#
# `git diff --stat webvulnscanner/auth_routes.py` confirmed empty afterward.


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
