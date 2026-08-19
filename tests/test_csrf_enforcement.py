"""
Tests for CSRF enforcement (SEC-02).

`tests/conftest.py`'s `TestConfig` sets `WTF_CSRF_ENABLED = False` for the
whole suite - a deliberate, documented choice so the other ~640 tests in
this repo don't have to juggle tokens on every form POST. The consequence
is that every CSRF-adjacent assertion elsewhere in the suite only checks
that a hidden `csrf_token` field is present in rendered markup; none of
them ever exercise Flask-WTF's actual server-side validation path
(`CSRFProtect`, wired app-wide in `extensions.py`/`__init__.py`).

This module is the one place that turns CSRF validation back on, mirroring
`tests/test_auth_flows.py::test_login_rate_limit_is_enforced`'s established
precedent for building a second, independently-configured app instance
with one `TestConfig` flag flipped - here `WTF_CSRF_ENABLED = True` instead
of `RATELIMIT_ENABLED = True`, against its own on-disk SQLite file so it
never shares state with the standard `app`/`client`/`db` fixtures.

Everything below proves *enforcement*, not markup presence: a token-less
POST to a state-changing, cookie-authenticated route must return 400 and
produce no database side effect; the same POST with a valid token must
still succeed; a wrong-but-well-formed token must be rejected too (proving
the value is validated, not merely required to be non-empty).

`tests/conftest.py` is not modified anywhere in this module.
"""
import pytest
from bs4 import BeautifulSoup

from webvulnscanner import create_app
from webvulnscanner.extensions import db as _db
from webvulnscanner.models import Invitation, Role

from tests.conftest import TestConfig, make_org, make_user


# --------------------------------------------------------------------------
# App-builder + token helpers. Kept local to this module rather than added
# to tests/conftest.py, exactly as test_login_rate_limit_is_enforced does
# for its own _RateLimitedConfig - conftest.py's shared fixtures stay
# CSRF-disabled for the other ~640 tests that depend on that default.
# --------------------------------------------------------------------------


class _CSRFEnabledConfig(TestConfig):
    """The one config in this suite that leaves CSRF validation on."""

    WTF_CSRF_ENABLED = True


def _extract_csrf_token(html):
    """Pulls the `csrf_token` hidden-input value out of rendered HTML,
    regardless of which of the app's two emission idioms produced it - an
    explicit `<input type="hidden" name="csrf_token" value="...">` and
    WTForms' `hidden_tag()` both render to the same input name/shape, so
    one BeautifulSoup lookup covers both."""
    soup = BeautifulSoup(html, "html.parser")
    field = soup.find("input", {"name": "csrf_token"})
    assert field is not None, "no csrf_token input found in rendered HTML"
    return field["value"]


def _mutate_token(token):
    """Returns a syntactically-plausible but wrong csrf token - same
    length/shape as a real one, just not the one the session actually
    signed. Proves the submitted value is validated, not merely required
    to be present.

    Flips the FIRST character rather than the last: the token is an
    itsdangerous URLSafeTimedSerializer payload
    (base64-payload.timestamp.base64-signature), and base64's final
    character in a run often only encodes padding bits that don't affect
    the decoded byte value - flipping it can silently decode to the exact
    same bytes and leave the token still valid, which was observed
    empirically while writing this test. Flipping the first character
    always changes the first decoded byte, corrupting the signed payload
    (and, transitively, the signature check) for real."""
    first = token[0]
    return ("0" if first != "0" else "1") + token[1:]


def _login(client, email, password="password123"):
    """Token-aware login helper. `tests.conftest.login()` posts to /login
    with no csrf_token, which under a CSRF-enabled app would itself 400 -
    this GETs /login first, extracts the real token, then POSTs with it.
    Deliberately local to this module rather than a change to the shared
    `login()` 646 other tests depend on."""
    get_resp = client.get("/login")
    token = _extract_csrf_token(get_resp.get_data(as_text=True))
    return client.post(
        "/login",
        data={"email": email, "password": password, "csrf_token": token},
        follow_redirects=True,
    )


@pytest.fixture()
def csrf_app(tmp_path):
    db_path = tmp_path / "csrf_enforcement.db"

    class _Config(_CSRFEnabledConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"

    app = create_app(_Config)
    with app.app_context():
        _db.create_all()
    yield app
    with app.app_context():
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def csrf_client(csrf_app):
    return csrf_app.test_client()


@pytest.fixture()
def csrf_db(csrf_app):
    """Mirrors conftest.py's own `db` fixture shape, bound to `csrf_app`
    instead of the standard `app` fixture / its own separate SQLite file -
    seeding through the shared `db` fixture would seed the wrong app/DB
    entirely."""
    with csrf_app.app_context():
        yield _db


# --------------------------------------------------------------------------
# Task 1: one end-to-end enforcement proof on /org/admin/invite - absent,
# wrong, and valid token.
# --------------------------------------------------------------------------


def test_invite_without_csrf_token_returns_400_and_creates_no_row(csrf_client, csrf_db):
    org = make_org(name="Org")
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    csrf_db.session.commit()

    _login(csrf_client, "admin@example.com")

    resp = csrf_client.post(
        "/org/admin/invite",
        data={"email": "invitee@example.com", "role": Role.MEMBER.value},
        follow_redirects=False,
    )

    assert resp.status_code == 400, f"expected 400 for a token-less invite POST, got {resp.status_code}"
    assert Invitation.query.count() == 0


def test_invite_with_wrong_csrf_token_returns_400_and_creates_no_row(csrf_client, csrf_db):
    org = make_org(name="Org")
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    csrf_db.session.commit()

    _login(csrf_client, "admin@example.com")

    admin_page = csrf_client.get("/org/admin")
    real_token = _extract_csrf_token(admin_page.get_data(as_text=True))
    wrong_token = _mutate_token(real_token)

    resp = csrf_client.post(
        "/org/admin/invite",
        data={"email": "invitee@example.com", "role": Role.MEMBER.value, "csrf_token": wrong_token},
        follow_redirects=False,
    )

    assert resp.status_code == 400, f"expected 400 for a wrong-token invite POST, got {resp.status_code}"
    assert Invitation.query.count() == 0


def test_invite_with_valid_csrf_token_returns_302_and_creates_one_row(csrf_client, csrf_db):
    org = make_org(name="Org")
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    csrf_db.session.commit()

    _login(csrf_client, "admin@example.com")

    admin_page = csrf_client.get("/org/admin")
    real_token = _extract_csrf_token(admin_page.get_data(as_text=True))

    resp = csrf_client.post(
        "/org/admin/invite",
        data={"email": "invitee@example.com", "role": Role.MEMBER.value, "csrf_token": real_token},
        follow_redirects=False,
    )

    assert resp.status_code == 302, f"expected 302 for a valid-token invite POST, got {resp.status_code}"
    assert Invitation.query.count() == 1
