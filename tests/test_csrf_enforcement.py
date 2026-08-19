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
the value is validated, not merely required to be non-empty). One
token-less-POST-returns-400 proof is repeated per cookie-authenticated
blueprint (auth/org/billing/asset/api_tokens/scan), since `CSRFProtect` is
wired app-wide and a single proof per blueprint is what confirms nothing
silently exempted a whole surface. Finally, the module locks
`csrf.exempt()`'s scope to exactly the Bearer-token `/api/v1` blueprint
(the one deliberate, documented exemption - token auth is not
cookie-based, so CSRF doesn't apply to it), proves that exemption doesn't
regress the API surface under enforcement, and proves every POST-form
template in `templates/` emits a token by one of this codebase's two known
idioms (an explicit hidden input rendering `csrf_token()`, or a WTForms
`hidden_tag()` call - the four auth templates use the second and would be
false-flagged by a single-pattern check).

`tests/conftest.py` is not modified anywhere in this module.
"""
import pathlib
import re
from datetime import datetime, timezone

import pytest
from bs4 import BeautifulSoup

from webvulnscanner import create_app
from webvulnscanner.extensions import db as _db
from webvulnscanner.models import (
    ApiToken,
    Asset,
    CryptoInvoice,
    DomainVerification,
    Invitation,
    PasswordReset,
    Plan,
    Role,
    Scan,
    VerifyMethod,
)

from tests.conftest import TestConfig, make_api_token, make_asset, make_org, make_user

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WEBVULNSCANNER_DIR = REPO_ROOT / "webvulnscanner"
TEMPLATES_DIR = REPO_ROOT / "templates"


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


# --------------------------------------------------------------------------
# Task 2: one token-less-POST-returns-400 proof per cookie-authenticated
# blueprint, each with a paired no-side-effect assertion. Org is already
# covered above via /org/admin/invite. Each case runs as a user who WOULD
# be authorized for that route (an ORG_ADMIN for billing, the asset's own
# org member for asset delete), so the only thing that can make the
# request fail is the missing/invalid CSRF token - not a 403 from a role
# decorator or a 429 from a rate limit (TestConfig keeps the limiter
# disabled) masquerading as a CSRF rejection.
# --------------------------------------------------------------------------


def test_auth_forgot_password_without_csrf_token_returns_400_no_reset_row(csrf_client, csrf_db):
    make_user("user@example.com")
    csrf_db.session.commit()

    resp = csrf_client.post(
        "/forgot-password",
        data={"email": "user@example.com"},
        follow_redirects=False,
    )

    assert resp.status_code == 400
    assert PasswordReset.query.count() == 0


def test_billing_create_invoice_without_csrf_token_returns_400_no_invoice_row(csrf_client, csrf_db):
    org = make_org(plan=Plan.FREE, name="Org")
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    csrf_db.session.commit()

    _login(csrf_client, "admin@example.com")

    resp = csrf_client.post(
        "/account/billing/invoice",
        data={"target_plan": Plan.PAID.value, "token_symbol": "USDT", "billing_cycle": "monthly"},
        follow_redirects=False,
    )

    assert resp.status_code == 400
    assert CryptoInvoice.query.count() == 0


def test_asset_delete_without_csrf_token_returns_400_not_deleted(csrf_client, csrf_db):
    org = make_org(name="Org")
    user = make_user("member@example.com", org=org, role=Role.MEMBER)
    csrf_db.session.commit()
    a = make_asset(org, user, name="Asset")
    csrf_db.session.commit()
    asset_id = a.id

    _login(csrf_client, "member@example.com")

    resp = csrf_client.post(f"/assets/{asset_id}/delete", follow_redirects=False)

    assert resp.status_code == 400
    refreshed = Asset.query.get(asset_id)
    assert refreshed.deleted_at is None


def test_api_tokens_create_without_csrf_token_returns_400_no_token_row(csrf_client, csrf_db):
    org = make_org(name="Org")
    make_user("member@example.com", org=org, role=Role.MEMBER)
    csrf_db.session.commit()

    _login(csrf_client, "member@example.com")

    resp = csrf_client.post(
        "/tokens/new",
        data={"name": "CI pipeline"},
        follow_redirects=False,
    )

    assert resp.status_code == 400
    assert ApiToken.query.count() == 0


def test_scan_new_base_without_csrf_token_returns_400_no_scan_row(csrf_client, csrf_db):
    org = make_org(name="Org")
    make_user("member@example.com", org=org, role=Role.MEMBER)
    csrf_db.session.commit()

    _login(csrf_client, "member@example.com")

    # A private literal IP - tests/test_ssrf_guard.py's own pattern for a
    # target that _unsafe_target_error would reject anyway. CSRFProtect's
    # before_request hook runs before new_scan_base's own body (including
    # its SSRF check), so a missing token alone must already 400 here - the
    # private-IP target is a defense-in-depth belt so this test is still
    # safe (no Scan row, no background thread) even if that ordering
    # assumption were ever wrong.
    resp = csrf_client.post(
        "/scan/new/base",
        data={"authorized": "on", "target": "10.0.0.5"},
        follow_redirects=False,
    )

    assert resp.status_code == 400
    assert Scan.query.count() == 0


def _seed_org_verified_member(csrf_db, domain="example.com"):
    """Advanced's own form only renders (csrf_token included) once
    `availability.unlocked` is true - Tier.ORG_VERIFIED *and* a verified
    DomainVerification row for the exact target - see
    scan_routes._scan_type_availability's Advanced branch. Seeds both so
    the Smart Setup pair below exercises the real, unlocked form rather
    than the locked upsell state."""
    org = make_org(plan=Plan.ORG_VERIFIED, name="Org")
    user = make_user("member@example.com", org=org, role=Role.MEMBER)
    csrf_db.session.add(DomainVerification(
        org_id=org.id, domain=domain, method=VerifyMethod.DNS_TXT,
        token="verify-token", verified_at=datetime.now(timezone.utc),
    ))
    csrf_db.session.commit()
    return org, user


def test_advanced_form_renders_a_csrf_token_input(csrf_client, csrf_db):
    _seed_org_verified_member(csrf_db)
    _login(csrf_client, "member@example.com")

    resp = csrf_client.get("/scan/new/advanced?target=https://example.com")
    soup = BeautifulSoup(resp.get_data(as_text=True), "html.parser")
    assert soup.find("input", {"name": "csrf_token"}) is not None, (
        "scan_new_advanced.html no longer renders a csrf_token input - Smart Setup's "
        "conditional fetch() would silently start omitting the token too"
    )


def test_advanced_detect_without_csrf_token_returns_400(csrf_client, csrf_db):
    _seed_org_verified_member(csrf_db)
    _login(csrf_client, "member@example.com")

    resp = csrf_client.post(
        "/scan/new/advanced/detect",
        data={"authorized_adv": "on", "target": "10.0.0.5"},
        follow_redirects=False,
    )

    assert resp.status_code == 400


# --------------------------------------------------------------------------
# Task 3a: csrf.exempt() scope lock - exactly one call site, in
# api_routes.py, applied to the `api` blueprint. Same source-parsing
# regression-lock shape as tests/test_scan_engine.py's
# test_no_orchestrator_carries_an_inline_scoring_block and
# tests/test_scheduler.py's test_fire_dispatches_only_on_base_media_api_no_advanced_branch.
# --------------------------------------------------------------------------


def _find_csrf_exempt_call_sites():
    """Reads every .py file under webvulnscanner/, strips full-line
    comments (a trailing inline comment on a real call site is still
    counted - only a comment-only line is skipped), and collects every
    line containing an exempt call. A future second exemption anywhere
    fails this with the offending file/line named, rather than an opaque
    count mismatch."""
    hits = []
    for path in sorted(WEBVULNSCANNER_DIR.rglob("*.py")):
        for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if raw_line.strip().startswith("#"):
                continue
            code_part = raw_line.split("#", 1)[0]
            if "csrf.exempt(" in code_part:
                hits.append((path, lineno, raw_line.strip()))
    return hits


def test_csrf_exempt_applied_to_exactly_one_blueprint():
    hits = _find_csrf_exempt_call_sites()
    assert len(hits) == 1, (
        f"expected exactly one csrf.exempt() call site (webvulnscanner/api_routes.py's "
        f"Bearer-token blueprint), found {len(hits)}: "
        f"{[(str(p.relative_to(REPO_ROOT)), n, line) for p, n, line in hits]}"
    )
    path, _lineno, line = hits[0]
    assert path.name == "api_routes.py", (
        f"the sole csrf.exempt() call site moved out of api_routes.py into {path.name} - "
        f"the Bearer-token API surface is no longer where CSRF exemption is scoped"
    )
    assert "csrf.exempt(api)" in line, (
        f"api_routes.py's exempt call no longer reads 'csrf.exempt(api)' - found: {line!r}"
    )


# Negative control performed manually while writing this test (not itself
# a permanent test - a second csrf.exempt(api) call was added directly
# below the real one in webvulnscanner/api_routes.py, this test was run
# alone, and reverted immediately after). Observed failure:
#
#   AssertionError: expected exactly one csrf.exempt() call site
#   (webvulnscanner/api_routes.py's Bearer-token blueprint), found 2:
#   [('webvulnscanner\\api_routes.py', 35, 'csrf.exempt(api)'),
#    ('webvulnscanner\\api_routes.py', 36, 'csrf.exempt(api)  # TEMP ...')]
#   assert 2 == 1
#
# `git diff --stat` confirmed api_routes.py was clean again afterward -
# recorded in 08-02-SUMMARY.md.


# --------------------------------------------------------------------------
# Task 3b: the Bearer-token API surface must still work under CSRF
# enforcement - a CSRF fix that broke it would be a regression, not
# hardening.
# --------------------------------------------------------------------------


def test_bearer_token_trigger_scan_not_blocked_by_csrf_enforcement(csrf_client, csrf_db, monkeypatch):
    spawned = []
    monkeypatch.setattr(
        "webvulnscanner.scheduler._spawn_scan_thread",
        lambda scan_id, scan_type, **kwargs: spawned.append((scan_id, scan_type, kwargs)),
    )

    org = make_org(plan=Plan.PAID, name="Org")
    user = make_user("owner@example.com", org=org)
    csrf_db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    a = make_asset(org, user, name="Asset", schedule_scan_type="base")
    csrf_db.session.commit()

    resp = csrf_client.post(
        f"/api/v1/assets/{a.id}/scans",
        headers={"Authorization": f"Bearer {raw_token}"},
    )

    assert resp.status_code != 400, (
        f"Bearer-token POST to the exempt API route was rejected by CSRF (status "
        f"{resp.status_code}) - the exemption is no longer working"
    )
    assert resp.status_code == 202
    assert len(spawned) == 1


# --------------------------------------------------------------------------
# Task 3c: every POST-form template emits a csrf token by one of the two
# known idioms. Not a single-pattern check - the four auth templates
# (login, signup, forgot_password, reset_password) use WTForms'
# hidden_tag() exclusively and would be false-flagged by a check that only
# looked for the explicit csrf_token() input.
# --------------------------------------------------------------------------

_POST_FORM_RE = re.compile(r'method\s*=\s*["\']post["\']', re.IGNORECASE)


def _post_form_templates():
    return sorted(p for p in TEMPLATES_DIR.glob("*.html") if _POST_FORM_RE.search(p.read_text(encoding="utf-8")))


def test_every_post_form_template_emits_a_known_csrf_idiom():
    explicit_idiom, wtforms_idiom, neither = [], [], []
    for path in _post_form_templates():
        text = path.read_text(encoding="utf-8")
        has_explicit = "csrf_token()" in text
        has_wtforms = "hidden_tag()" in text
        if has_explicit:
            explicit_idiom.append(path.name)
        if has_wtforms:
            wtforms_idiom.append(path.name)
        if not (has_explicit or has_wtforms):
            neither.append(path.name)

    assert not neither, (
        f"POST-form template(s) emit neither known CSRF idiom (explicit csrf_token() "
        f"input nor WTForms hidden_tag()): {neither}"
    )
    # explicit_idiom (10): api_tokens, asset_detail, asset_new, billing,
    #   org_admin (invite-resend/revoke buttons), platform_admin,
    #   scan_new_advanced, scan_new_api, scan_new_base, scan_new_media
    # wtforms_idiom (6): forgot_password, login, org_admin (invite form),
    #   org_verify_domain (add-domain form), reset_password, signup
    # (org_admin.html uses both idioms across different forms on the same
    #  page - recorded in 08-02-SUMMARY.md.)
