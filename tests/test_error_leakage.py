"""
Production-mode error-leakage coverage across all six status codes SEC-10
names (400/401/403/404/429/500).

Every other test in this repo's ~700-test suite runs under
`tests/conftest.py`'s `TestConfig`, which sets `TESTING = True` - this makes
Flask re-raise an unhandled exception straight into the test client instead
of routing it through the app's own `@app.errorhandler(500)`, so the actual
production error path (`TESTING = False`, `DEBUG = False`, the real Flask/
Werkzeug/Flask-WTF error-rendering machinery) has never been exercised once
in this repo's history before this module. This is the one place that flips
it, mirroring `tests/test_auth_flows.py::test_login_rate_limit_is_enforced`
and `tests/test_csrf_enforcement.py`'s own single-flag-flipped, independent-
second-app-instance pattern - here built directly off `Config` (not
`TestConfig`) so `TESTING`/`DEBUG` are both genuinely off, not merely
un-overridden.

`tests/conftest.py` is not modified anywhere in this module.
"""
import pathlib
import re

import pytest
from bs4 import BeautifulSoup

from webvulnscanner import create_app
from webvulnscanner.config import APP_DIR, Config
from webvulnscanner.extensions import db as _db
from webvulnscanner.extensions import limiter as _limiter
from webvulnscanner.models import Role

from tests.conftest import make_org, make_user

CONFIG_PY = pathlib.Path(__file__).resolve().parent.parent / "webvulnscanner" / "config.py"


def _derive_env_var_names_from_config():
    """Regex-extracts every `os.environ.get("NAME", ...)` literal name out
    of config.py, so the forbidden-substring list below tracks this app's
    real configuration surface instead of a hand-maintained list that would
    silently drift the next time a config value is added (08-06-PLAN.md's
    explicit instruction)."""
    text = CONFIG_PY.read_text(encoding="utf-8")
    names = sorted(set(re.findall(r'os\.environ\.get\(\s*["\']([A-Z_][A-Z0-9_]*)["\']', text)))
    return names


_ENV_VAR_NAMES = _derive_env_var_names_from_config()

# One shared definition of "leak", applied to every one of the six status
# codes below - a seventh forbidden pattern added here covers all six cases
# at once (08-06-PLAN.md's explicit data-driven requirement).
_FORBIDDEN_SUBSTRINGS = [
    "Traceback (most recent call last)",  # a raw Python traceback
    "Werkzeug Debugger",                  # the interactive debugger's own page title
    "The debugger caught an exception",   # the interactive debugger's own banner text
    str(APP_DIR),                         # an absolute filesystem path fragment matching the repo root
    "SELECT * FROM",                      # a SQL keyword sequence
] + _ENV_VAR_NAMES  # every env-var *name* this app reads, derived from config.py


def _assert_no_leak(resp, label):
    body = resp.get_data(as_text=True)
    hits = [s for s in _FORBIDDEN_SUBSTRINGS if s and s in body]
    assert not hits, f"{label} response leaked forbidden substring(s): {hits}"


# --------------------------------------------------------------------------
# App builder. SCHEDULER_ENABLED is forced off purely so this test app
# doesn't leak a real background poll thread - webvulnscanner/__init__.py's
# _maybe_start_scheduler only skips the scheduler on TESTING=True, and this
# app deliberately sets TESTING=False, so without this override every test
# below would start (and never stop) a real scheduler thread against a
# soon-to-be-deleted tmp_path SQLite file. RATELIMIT_ENABLED is explicitly
# on so the 429 case is a real trip, not a silent no-op.
# --------------------------------------------------------------------------


class _ProductionModeConfig(Config):
    """The first `TESTING = False` / `DEBUG = False` app config in this
    repo's test suite - see module docstring."""

    TESTING = False
    SCHEDULER_ENABLED = False
    RATELIMIT_ENABLED = True


@pytest.fixture()
def prod_app(tmp_path):
    db_path = tmp_path / "error_leakage.db"

    class _Config(_ProductionModeConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"

    app = create_app(_Config)
    with app.app_context():
        _db.create_all()
    _limiter.reset()
    yield app
    _limiter.reset()  # don't leak a tripped 429 into whichever test runs next
    with app.app_context():
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def prod_client(prod_app):
    return prod_app.test_client()


@pytest.fixture()
def prod_db(prod_app):
    with prod_app.app_context():
        yield _db


def _extract_csrf_token(html):
    """CSRF is genuinely enforced in this app (WTF_CSRF_ENABLED defaults
    True on the real Config, unlike TestConfig) - every POST below that
    is meant to succeed needs a real token pulled from a GET response
    first, same idiom tests/test_csrf_enforcement.py already established."""
    soup = BeautifulSoup(html, "html.parser")
    field = soup.find("input", {"name": "csrf_token"})
    assert field is not None, "no csrf_token input found in rendered HTML"
    return field["value"]


# --------------------------------------------------------------------------
# Sanity check first - with TESTING=False, a bug in this module's own setup
# surfaces as an opaque 500, not a stack trace (08-06-PLAN.md's own
# caution). Confirm the app is actually up before asserting anything about
# its error pages.
# --------------------------------------------------------------------------


def test_prod_app_serves_a_known_good_route(prod_client, prod_db):
    resp = prod_client.get("/")
    assert resp.status_code == 200


# --------------------------------------------------------------------------
# 404 - realistic path: a nonexistent URL. Handled (@app.errorhandler(404)),
# so it must render the app's own themed template.
# --------------------------------------------------------------------------


def test_404_renders_themed_template_and_leaks_nothing(prod_client, prod_db):
    resp = prod_client.get("/this-route-does-not-exist-xyz")
    assert resp.status_code == 404
    body = resp.get_data(as_text=True)
    assert "Page not found" in body, "404 did not render the app's own themed 404.html"
    _assert_no_leak(resp, "404")


# --------------------------------------------------------------------------
# 403 - realistic path: a role-gated route (org_admin_required) hit by an
# authenticated user who is a MEMBER, not an ORG_ADMIN. Unhandled
# (no @app.errorhandler(403) anywhere in the app), so it must fall through
# to Werkzeug's generic page - no repo branding.
# --------------------------------------------------------------------------


def test_403_renders_generic_page_and_leaks_nothing(prod_client, prod_db):
    org = make_org(name="Org")
    make_user("member@example.com", org=org, role=Role.MEMBER)
    prod_db.session.commit()

    get_resp = prod_client.get("/login")
    token = _extract_csrf_token(get_resp.get_data(as_text=True))
    prod_client.post(
        "/login",
        data={"email": "member@example.com", "password": "password123", "csrf_token": token},
        follow_redirects=True,
    )

    resp = prod_client.get("/org/admin")
    assert resp.status_code == 403
    body = resp.get_data(as_text=True)
    assert "Glassbox" not in body, "403 unexpectedly rendered the app's own themed page"
    _assert_no_leak(resp, "403")


# --------------------------------------------------------------------------
# 401 - realistic path: /api/v1/* with no Authorization header at all.
# api_login_required (api_routes.py) returns its own minimal JSON body
# directly - not Werkzeug's raw default page, since the api blueprint
# never lets a request reach that far unauthenticated. Still asserted
# against the same forbidden-substring list, and still confirmed to carry
# no repo-specific branding/markup.
# --------------------------------------------------------------------------


def test_401_returns_a_minimal_json_body_and_leaks_nothing(prod_client, prod_db):
    resp = prod_client.get("/api/v1/assets")
    assert resp.status_code == 401
    assert resp.content_type.startswith("application/json")
    body = resp.get_data(as_text=True)
    assert "Glassbox" not in body, "401 unexpectedly rendered the app's own themed page"
    _assert_no_leak(resp, "401")


# --------------------------------------------------------------------------
# 400 (CSRFError) - realistic path: a token-less POST to a state-changing
# route, same mechanism tests/test_csrf_enforcement.py already proves under
# TESTING=True. Phase 10 live-verification (08-20) found this used to fall
# straight through to Werkzeug's raw default 400 page, literally showing a
# real user "The CSRF token has expired." after an ordinary idle-timeout
# logout + stale-tab resubmit - a backend implementation detail leaking
# through, not an attack. @app.errorhandler(CSRFError) in __init__.py now
# redirects back to the referring page with a plain-English flash instead
# of ever rendering a raw error page for this case.
# --------------------------------------------------------------------------


def test_csrf_error_redirects_with_flash_instead_of_raw_400(prod_client, prod_db):
    resp = prod_client.post(
        "/forgot-password", data={"email": "someone@example.com"}, follow_redirects=False,
    )
    assert resp.status_code == 302, "a CSRFError should redirect, not render a raw error page"
    body = resp.get_data(as_text=True)
    assert "Glassbox" not in body, "the redirect response body unexpectedly carried the app's own theme"
    _assert_no_leak(resp, "CSRFError redirect")

    followed = prod_client.post(
        "/forgot-password", data={"email": "someone@example.com"}, follow_redirects=True,
    )
    assert followed.status_code == 200
    followed_body = followed.get_data(as_text=True)
    assert "session expired" in followed_body.lower(), (
        "expected the plain-English CSRF-expiry flash message on the page the redirect landed on"
    )
    _assert_no_leak(followed, "CSRFError redirect target")


def test_csrf_error_redirect_ignores_cross_origin_referrer(prod_client, prod_db):
    """request.referrer is an attacker-controllable header, not trusted
    input - the handler must not blindly redirect to it (same open-redirect
    class auth_routes.py's _safe_next() already guards for `next`)."""
    resp = prod_client.post(
        "/forgot-password",
        data={"email": "someone@example.com"},
        headers={"Referer": "https://evil.example.com/phish"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].startswith("/"), "must not redirect to a cross-origin referrer"
    assert "evil.example.com" not in resp.headers["Location"]


# --------------------------------------------------------------------------
# 429 - realistic path: trip /login's real 10/min limit, same technique as
# tests/test_auth_flows.py::test_login_rate_limit_is_enforced, extended to
# also carry a valid CSRF token per POST (CSRF's before_request hook runs
# before Flask-Limiter's, so a token-less POST would 400 before ever
# reaching the limiter). Handled (@app.errorhandler(429)), so it must
# render the app's own themed template.
# --------------------------------------------------------------------------


def test_429_renders_themed_template_and_leaks_nothing(prod_client, prod_db):
    make_user("owner@example.com")
    prod_db.session.commit()

    get_resp = prod_client.get("/login")
    token = _extract_csrf_token(get_resp.get_data(as_text=True))

    tripped = None
    for _ in range(11):
        resp = prod_client.post(
            "/login",
            data={"email": "owner@example.com", "password": "wrong-password", "csrf_token": token},
            follow_redirects=False,
        )
        if resp.status_code == 429:
            tripped = resp
            break
    assert tripped is not None, "expected a 429 within 11 requests against the 10/min /login limit"
    body = tripped.get_data(as_text=True)
    assert "Too many requests" in body, "429 did not render the app's own themed 429.html"
    _assert_no_leak(tripped, "429")


# --------------------------------------------------------------------------
# 500 - a scratch route registered directly on this test's own app
# instance (per-test fresh app via tmp_path, so this never touches the
# real app) that raises unconditionally - the only reliable way to force
# an unhandled exception without depending on a pre-existing bug
# elsewhere. Handled (@app.errorhandler(500)), so it must render the app's
# own themed template and must not echo the exception's own message.
# --------------------------------------------------------------------------


def test_500_renders_themed_template_and_does_not_echo_exception_message(prod_app, prod_db):
    @prod_app.route("/_test_raise_for_500")
    def _test_raise_for_500():
        raise RuntimeError("internal-secret-detail-should-not-appear-in-response")

    client = prod_app.test_client()
    resp = client.get("/_test_raise_for_500")
    assert resp.status_code == 500
    body = resp.get_data(as_text=True)
    assert "Something went wrong" in body, "500 did not render the app's own themed 500.html"
    assert "internal-secret-detail-should-not-appear-in-response" not in body, (
        "the 500 response echoed the raised exception's own message"
    )
    _assert_no_leak(resp, "500")
