"""
Tests for the guided New Scan wizard (SCANUX-01..04): Step 1 (`/scan/new`,
Select Domain), Step 2 (`/scan/new/type`, Select Type), and Step 3 for the
Standard Scan (`/scan/new/base`, Confirm Authorization + Start Scan).

DNS is mocked via `_public_dns` (mirrors tests/test_ssrf_guard.py's
`_fake_getaddrinfo` pattern) for every test whose target must resolve as a
safe public address; loopback/link-local literals (127.0.0.1 etc.) resolve
for real with no mocking needed - same precedent test_ssrf_guard.py already
establishes for its own route-level integration tests.

Note on `/billing`: every existing "Upgrade" link in the codebase
(scan_new_advanced.html, scan_new_media.html, scan_new_api.html,
scan_report.html, org_admin.html, asset_detail.html) resolves the billing
link via `url_for('billing.view')`, which - per billing_routes.py's
`Blueprint("billing", __name__, url_prefix="/account/billing")` - is
`/account/billing`, not a bare `/billing`. This wizard follows that same
existing, working convention rather than hardcoding a URL that would 404;
tests below assert the real resolved path.
"""
import socket
from datetime import datetime, timezone

import pytest

from glassbox.extensions import db as _db
from glassbox.models import DomainVerification, Plan, Scan, VerifyMethod

from tests.conftest import login, make_org, make_user


@pytest.fixture()
def spawned(monkeypatch):
    """Monkeypatches _spawn_scan_thread to a no-op recorder - same
    convention tests/test_api_routes.py's `spawned` fixture and
    tests/test_scheduler.py already establish ("a real scan thread must
    never be triggered from a test": the daemon thread makes a real
    outbound HTTP request via `requests`, which must never happen from the
    test suite, and it also outlives the per-test app/DB teardown)."""
    calls = []

    def _fake_spawn(scan_id, scan_type, **kwargs):
        calls.append({"scan_id": scan_id, "scan_type": scan_type, "kwargs": kwargs})

    monkeypatch.setattr("glassbox.scan_routes._spawn_scan_thread", _fake_spawn)
    return calls


def _public_dns(monkeypatch):
    """Patches socket.getaddrinfo so any hostname resolves to a single
    ordinary public IPv4 address - for tests whose target must pass the
    SSRF safety check regardless of which (fake) domain string is used."""
    def _impl(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", _impl)


def _verify_domain(org, domain, verified=True):
    row = DomainVerification(
        org_id=org.id, domain=domain, method=VerifyMethod.DNS_TXT, token="tok",
        verified_at=datetime.now(timezone.utc) if verified else None,
    )
    _db.session.add(row)
    _db.session.flush()
    return row


# --------------------------------------------------------------------------
# Step 1 - GET /scan/new (Select Domain)
# --------------------------------------------------------------------------

def test_step1_requires_login(client, db):
    resp = client.get("/scan/new", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_step1_renders_stepper_labels(client, db):
    org = make_org()
    make_user("u1@example.com", org=org)
    login(client, "u1@example.com")
    resp = client.get("/scan/new")
    assert resp.status_code == 200
    body = resp.data.decode()
    for label in ("Select Domain", "Select Type", "Confirm Authorization", "Start Scan"):
        assert label in body
    assert 'name="verified_domain"' in body
    assert 'name="target"' in body


def test_step1_lists_only_org_scoped_verified_domains(client, db):
    org_a = make_org(name="Org A")
    org_b = make_org(name="Org B")
    make_user("a@example.com", org=org_a)
    make_user("b@example.com", org=org_b)
    _verify_domain(org_a, "a-owned.example.com")
    _verify_domain(org_a, "a-unverified.example.com", verified=False)
    _verify_domain(org_b, "b-owned.example.com")

    login(client, "a@example.com")
    resp = client.get("/scan/new")
    body = resp.data.decode()
    assert 'value="a-owned.example.com"' in body
    assert "a-unverified.example.com" not in body
    assert "b-owned.example.com" not in body


def test_step1_no_org_user_sees_empty_state_no_domain_options(client, db):
    make_user("solo@example.com")
    login(client, "solo@example.com")
    resp = client.get("/scan/new")
    body = resp.data.decode()
    assert "No verified domains yet" in body


def test_step1_empty_state_hint_and_target_input_present(client, db):
    org = make_org()
    make_user("u2@example.com", org=org)
    login(client, "u2@example.com")
    resp = client.get("/scan/new")
    body = resp.data.decode()
    assert "No verified domains yet" in body
    assert "Enter a target below, or verify a domain under" in body
    assert 'name="target"' in body


# --------------------------------------------------------------------------
# Step 2 - GET /scan/new/type (Select Type)
# --------------------------------------------------------------------------

def test_step2_requires_login(client, db):
    resp = client.get("/scan/new/type", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_step2_no_params_rerenders_step1_with_error(client, db):
    org = make_org()
    make_user("u3@example.com", org=org)
    login(client, "u3@example.com")
    resp = client.get("/scan/new/type")
    assert resp.status_code == 200
    assert "Select a verified domain or enter a target to continue." in resp.data.decode()


def test_step2_unparseable_target_rerenders_step1_with_error(client, db):
    org = make_org()
    make_user("u4@example.com", org=org)
    login(client, "u4@example.com")
    resp = client.get("/scan/new/type", query_string={"target": "not a domain at all"})
    assert resp.status_code == 200
    assert "Enter a valid domain or URL, e.g. example.com" in resp.data.decode()


def test_step2_unsafe_target_rerenders_step1_and_preserves_typed_value(client, db):
    org = make_org()
    make_user("u5@example.com", org=org)
    login(client, "u5@example.com")
    resp = client.get("/scan/new/type", query_string={"target": "127.0.0.1"})
    body = resp.data.decode()
    assert resp.status_code == 200
    assert "resolves to a private, internal, or unreachable address" in body
    assert "127.0.0.1" in body


def test_step2_verified_domain_wins_over_typed_target(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org()
    make_user("u6@example.com", org=org)
    login(client, "u6@example.com")
    resp = client.get("/scan/new/type", query_string={
        "verified_domain": "picked.example.com", "target": "typed.example.com",
    })
    body = resp.data.decode()
    assert "https://picked.example.com" in body
    assert "https://typed.example.com" not in body


def test_step2_typed_target_only(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org()
    make_user("u7@example.com", org=org)
    login(client, "u7@example.com")
    resp = client.get("/scan/new/type", query_string={"target": "typed.example.com"})
    body = resp.data.decode()
    assert "https://typed.example.com" in body


def test_step2_renders_standard_scan_not_old_base_card_title(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org()
    make_user("u8@example.com", org=org)
    login(client, "u8@example.com")
    resp = client.get("/scan/new/type", query_string={"target": "example.com"})
    body = resp.data.decode()
    assert "Standard Scan" in body
    assert "Base scan" not in body


def test_step2_free_tier_locks_media_api_advanced_behind_paid(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.FREE)
    make_user("u9@example.com", org=org)
    login(client, "u9@example.com")
    resp = client.get("/scan/new/type", query_string={"target": "example.com"})
    body = resp.data.decode()
    assert body.count("Requires Paid Plan") == 3  # advanced, media, api
    assert "Upgrade to Unlock" in body
    assert 'href="/account/billing"' in body


def test_step2_org_verified_no_verified_domain_advanced_locked_by_verification(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.ORG_VERIFIED)
    make_user("u10@example.com", org=org)
    login(client, "u10@example.com")
    resp = client.get("/scan/new/type", query_string={"target": "example.com"})
    body = resp.data.decode()
    assert "Requires Verified Domain" in body
    assert 'href="/org/verify-domain"' in body


def test_step2_org_verified_with_verified_domain_advanced_included(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.ORG_VERIFIED)
    make_user("u11@example.com", org=org)
    _verify_domain(org, "example.com")
    login(client, "u11@example.com")
    resp = client.get("/scan/new/type", query_string={"target": "example.com"})
    body = resp.data.decode()
    assert "/scan/new/advanced?target=" in body


def test_step2_unlocked_cta_hrefs_carry_target(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org()
    make_user("u12@example.com", org=org)
    login(client, "u12@example.com")
    resp = client.get("/scan/new/type", query_string={"target": "example.com"})
    body = resp.data.decode()
    assert "target=https" in body


def test_step2_target_is_html_escaped(client, db):
    org = make_org()
    make_user("u13@example.com", org=org)
    login(client, "u13@example.com")
    resp = client.get(
        "/scan/new/type",
        query_string={"target": '"><script>alert(1)</script>'},
    )
    assert b"<script>alert" not in resp.data


# --------------------------------------------------------------------------
# Step 3 - Standard Scan (/scan/new/base) - Task 2
# --------------------------------------------------------------------------

def test_step3_get_prefills_target_from_query(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org()
    make_user("u14@example.com", org=org)
    login(client, "u14@example.com")
    resp = client.get("/scan/new/base", query_string={"target": "https://example.com"})
    assert resp.status_code == 200
    assert "https://example.com" in resp.data.decode()


def test_step3_post_missing_authorized_preserves_typed_target(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org()
    make_user("u15@example.com", org=org)
    login(client, "u15@example.com")
    resp = client.post("/scan/new/base", data={"target": "typed.example.com"})
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "typed.example.com" in body


def test_step3_renders_standard_scan_and_included_pill(client, db):
    org = make_org()
    make_user("u16@example.com", org=org)
    login(client, "u16@example.com")
    resp = client.get("/scan/new/base")
    body = resp.data.decode()
    assert "Standard Scan" in body
    assert ">Included<" in body
    assert "Free tier included" not in body


def test_step3_renders_stepper_nodes_3_and_4_active(client, db):
    org = make_org()
    make_user("u17@example.com", org=org)
    login(client, "u17@example.com")
    resp = client.get("/scan/new/base")
    body = resp.data.decode()
    assert "Confirm Authorization" in body
    assert "Start Scan" in body
    assert body.count("wizard-step active") >= 2


def test_step3_post_creates_scan_and_redirects(client, db, monkeypatch, spawned):
    _public_dns(monkeypatch)
    org = make_org()
    make_user("u18@example.com", org=org)
    login(client, "u18@example.com")
    resp = client.post(
        "/scan/new/base", data={"target": "example.com", "authorized": "on"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert Scan.query.count() == 1


def test_step3_bulk_targets_creates_two_scans(client, db, monkeypatch, spawned):
    _public_dns(monkeypatch)
    org = make_org()
    make_user("u19@example.com", org=org)
    login(client, "u19@example.com")
    resp = client.post(
        "/scan/new/base",
        data={"target": "a.example.com\nb.example.com", "authorized": "on"},
        follow_redirects=False,
    )
    assert Scan.query.count() == 2


def test_step3_unsafe_target_creates_zero_scans(client, db):
    org = make_org()
    make_user("u20@example.com", org=org)
    login(client, "u20@example.com")
    resp = client.post(
        "/scan/new/base", data={"target": "127.0.0.1", "authorized": "on"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert Scan.query.count() == 0


# --------------------------------------------------------------------------
# Step 3 deviation - Advanced Smart Setup (URL-first intake + auto-detect)
# --------------------------------------------------------------------------

def test_advanced_get_renders_stepper_and_prefill(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.ORG_VERIFIED)
    make_user("adv1@example.com", org=org)
    _verify_domain(org, "example.com")
    login(client, "adv1@example.com")
    resp = client.get("/scan/new/advanced", query_string={"target": "https://example.com"})
    body = resp.data.decode()
    assert resp.status_code == 200
    for label in ("Select Domain", "Select Type", "Confirm Authorization", "Start Scan"):
        assert label in body
    assert "https://example.com" in body
    assert ">Included<" in body


def test_advanced_free_tier_locked_no_authorized_field(client, db):
    org = make_org(plan=Plan.FREE)
    make_user("adv2@example.com", org=org)
    login(client, "adv2@example.com")
    resp = client.get("/scan/new/advanced")
    body = resp.data.decode()
    assert "Upgrade to Unlock" in body
    assert 'name="authorized_adv"' not in body


def test_advanced_org_verified_no_verified_domain_shows_requires_verified_pill(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.ORG_VERIFIED)
    make_user("adv3@example.com", org=org)
    login(client, "adv3@example.com")
    resp = client.get("/scan/new/advanced", query_string={"target": "https://example.com"})
    body = resp.data.decode()
    assert "Requires Verified Domain" in body
    assert "Upgrade to Unlock" in body


def test_advanced_post_partial_fill_still_launches_backstop(client, db, monkeypatch, spawned):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.ORG_VERIFIED)
    make_user("adv4@example.com", org=org)
    _verify_domain(org, "example.com")
    login(client, "adv4@example.com")
    resp = client.post(
        "/scan/new/advanced",
        data={
            "target": "https://example.com",
            "authorized_adv": "on",
            "login_url": "https://example.com/login",
            "login_user_field": "username",
            "login_pass_field": "password",
            "login_fail_text": "Invalid",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert Scan.query.count() == 1
    assert Scan.query.first().scan_type == "advanced"


def test_advanced_post_no_group_filled_preserves_typed_value(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.ORG_VERIFIED)
    make_user("adv5@example.com", org=org)
    _verify_domain(org, "example.com")
    login(client, "adv5@example.com")
    resp = client.post(
        "/scan/new/advanced",
        data={
            "target": "https://example.com",
            "authorized_adv": "on",
            "login_url": "https://kept.example.com/login",
        },
        follow_redirects=False,
    )
    body = resp.data.decode()
    assert resp.status_code == 200
    assert "at least one advanced check group" in body
    assert "https://kept.example.com/login" in body
    assert Scan.query.count() == 0


def test_advanced_post_no_authorized_creates_zero_scans(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.ORG_VERIFIED)
    make_user("adv6@example.com", org=org)
    _verify_domain(org, "example.com")
    login(client, "adv6@example.com")
    resp = client.post(
        "/scan/new/advanced",
        data={"target": "https://example.com", "login_url": "https://example.com/login"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert Scan.query.count() == 0


def test_advanced_target_is_html_escaped(client, db, monkeypatch):
    org = make_org(plan=Plan.ORG_VERIFIED)
    make_user("adv7@example.com", org=org)
    login(client, "adv7@example.com")
    resp = client.get(
        "/scan/new/advanced",
        query_string={"target": '"><script>alert(1)</script>'},
    )
    assert b"<script>alert" not in resp.data


# --------------------------------------------------------------------------
# Smart Setup detect endpoint (/scan/new/advanced/detect) - UX aid only,
# never a gate: it must refuse to run before authorization is confirmed and
# must never create a Scan row or run any check itself.
# --------------------------------------------------------------------------

def test_detect_requires_login(client, db):
    resp = client.post("/scan/new/advanced/detect", data={"target": "https://example.com"})
    assert resp.status_code in (302, 401)


def test_detect_without_authorized_adv_refuses_and_never_crawls(client, db, monkeypatch):
    org = make_org(plan=Plan.ORG_VERIFIED)
    make_user("det1@example.com", org=org)
    login(client, "det1@example.com")

    called = []
    monkeypatch.setattr(
        "glassbox.scan_routes.detect_login_form",
        lambda *a, **kw: called.append((a, kw)) or None,
    )
    resp = client.post("/scan/new/advanced/detect", data={"target": "https://example.com"})
    assert resp.status_code == 400
    assert called == []  # the crawl must never fire before authorization is confirmed


def test_detect_unsafe_target_refuses_and_never_crawls(client, db, monkeypatch):
    org = make_org(plan=Plan.ORG_VERIFIED)
    make_user("det2@example.com", org=org)
    login(client, "det2@example.com")

    called = []
    monkeypatch.setattr(
        "glassbox.scan_routes.detect_login_form",
        lambda *a, **kw: called.append((a, kw)) or None,
    )
    resp = client.post(
        "/scan/new/advanced/detect",
        data={"target": "http://127.0.0.1", "authorized_adv": "on"},
    )
    assert resp.status_code == 400
    assert called == []


def test_detect_found_returns_login_fields_json(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.ORG_VERIFIED)
    make_user("det3@example.com", org=org)
    login(client, "det3@example.com")

    monkeypatch.setattr(
        "glassbox.scan_routes.detect_login_form",
        lambda *a, **kw: {
            "login_url": "https://example.com/session",
            "user_field": "email",
            "pass_field": "password",
        },
    )
    resp = client.post(
        "/scan/new/advanced/detect",
        data={"target": "https://example.com", "authorized_adv": "on"},
    )
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["found"] is True
    assert payload["login_url"] == "https://example.com/session"
    assert payload["user_field"] == "email"
    assert payload["pass_field"] == "password"


def test_detect_not_found_returns_found_false(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.ORG_VERIFIED)
    make_user("det4@example.com", org=org)
    login(client, "det4@example.com")

    monkeypatch.setattr("glassbox.scan_routes.detect_login_form", lambda *a, **kw: None)
    resp = client.post(
        "/scan/new/advanced/detect",
        data={"target": "https://example.com", "authorized_adv": "on"},
    )
    assert resp.status_code == 200
    assert resp.get_json() == {"found": False}


def test_detect_creates_zero_scan_rows(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.ORG_VERIFIED)
    make_user("det5@example.com", org=org)
    login(client, "det5@example.com")

    monkeypatch.setattr(
        "glassbox.scan_routes.detect_login_form",
        lambda *a, **kw: {"login_url": "https://example.com/login", "user_field": "u", "pass_field": "p"},
    )
    client.post(
        "/scan/new/advanced/detect",
        data={"target": "https://example.com", "authorized_adv": "on"},
    )
    assert Scan.query.count() == 0


# --------------------------------------------------------------------------
# Step 3 - Media and API scans (05-02 Task 1)
# --------------------------------------------------------------------------

def test_media_get_prefills_target_and_shows_included_pill(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.PAID)
    make_user("med1@example.com", org=org)
    login(client, "med1@example.com")
    resp = client.get("/scan/new/media", query_string={"target": "https://example.com"})
    body = resp.data.decode()
    assert resp.status_code == 200
    assert "https://example.com" in body
    assert ">Included<" in body
    for label in ("Select Domain", "Select Type", "Confirm Authorization", "Start Scan"):
        assert label in body


def test_api_get_prefills_target_and_shows_included_pill(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.PAID)
    make_user("api1@example.com", org=org)
    login(client, "api1@example.com")
    resp = client.get("/scan/new/api", query_string={"target": "https://example.com"})
    body = resp.data.decode()
    assert resp.status_code == 200
    assert "https://example.com" in body
    assert ">Included<" in body


def test_media_free_tier_locked_shows_upgrade(client, db):
    org = make_org(plan=Plan.FREE)
    make_user("med2@example.com", org=org)
    login(client, "med2@example.com")
    resp = client.get("/scan/new/media")
    body = resp.data.decode()
    assert "Requires Paid Plan" in body
    assert "Upgrade to Unlock" in body


def test_api_free_tier_locked_shows_upgrade(client, db):
    org = make_org(plan=Plan.FREE)
    make_user("api2@example.com", org=org)
    login(client, "api2@example.com")
    resp = client.get("/scan/new/api")
    body = resp.data.decode()
    assert "Requires Paid Plan" in body
    assert "Upgrade to Unlock" in body


def test_media_post_missing_authorized_preserves_typed_target(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.PAID)
    make_user("med3@example.com", org=org)
    login(client, "med3@example.com")
    resp = client.post("/scan/new/media", data={"media_target": "keepme.example.com"})
    body = resp.data.decode()
    assert resp.status_code == 200
    assert "keepme.example.com" in body
    assert Scan.query.count() == 0


def test_api_post_missing_authorized_preserves_typed_target(client, db, monkeypatch):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.PAID)
    make_user("api3@example.com", org=org)
    login(client, "api3@example.com")
    resp = client.post("/scan/new/api", data={"api_target": "keepme.example.com"})
    body = resp.data.decode()
    assert resp.status_code == 200
    assert "keepme.example.com" in body
    assert Scan.query.count() == 0


def test_media_free_tier_complete_post_creates_zero_scans(client, db, monkeypatch, spawned):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.FREE)
    make_user("med4@example.com", org=org)
    login(client, "med4@example.com")
    resp = client.post(
        "/scan/new/media",
        data={"media_target": "example.com", "authorized_media": "on"},
    )
    assert resp.status_code == 200
    assert Scan.query.count() == 0


def test_api_free_tier_complete_post_creates_zero_scans(client, db, monkeypatch, spawned):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.FREE)
    make_user("api4@example.com", org=org)
    login(client, "api4@example.com")
    resp = client.post(
        "/scan/new/api",
        data={"api_target": "example.com", "authorized_api": "on"},
    )
    assert resp.status_code == 200
    assert Scan.query.count() == 0


def test_media_paid_tier_complete_post_creates_scan_and_redirects(client, db, monkeypatch, spawned):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.PAID)
    make_user("med5@example.com", org=org)
    login(client, "med5@example.com")
    resp = client.post(
        "/scan/new/media",
        data={"media_target": "example.com", "authorized_media": "on"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert Scan.query.count() == 1
    assert Scan.query.first().scan_type == "media"


def test_api_paid_tier_complete_post_creates_scan_and_redirects(client, db, monkeypatch, spawned):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.PAID)
    make_user("api5@example.com", org=org)
    login(client, "api5@example.com")
    resp = client.post(
        "/scan/new/api",
        data={"api_target": "example.com", "authorized_api": "on"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert Scan.query.count() == 1
    assert Scan.query.first().scan_type == "api"


def test_media_target_is_html_escaped(client, db):
    org = make_org(plan=Plan.PAID)
    make_user("med6@example.com", org=org)
    login(client, "med6@example.com")
    resp = client.get(
        "/scan/new/media",
        query_string={"target": '"><script>alert(1)</script>'},
    )
    assert b"<script>alert" not in resp.data


def test_api_target_is_html_escaped(client, db):
    org = make_org(plan=Plan.PAID)
    make_user("api6@example.com", org=org)
    login(client, "api6@example.com")
    resp = client.get(
        "/scan/new/api",
        query_string={"target": '"><script>alert(1)</script>'},
    )
    assert b"<script>alert" not in resp.data


# --------------------------------------------------------------------------
# Step 3 - single Target box doubles as the seed URL when it has a query
# string, so the user doesn't need to fill in both the Target and the
# separate "seed URL" boxes for the common one-target case.
# --------------------------------------------------------------------------

def test_target_with_query_string_becomes_manual_test_url(client, db, monkeypatch, spawned):
    _public_dns(monkeypatch)
    org = make_org()
    make_user("seed1@example.com", org=org)
    login(client, "seed1@example.com")
    resp = client.post(
        "/scan/new/base",
        data={"target": "https://example.com/search?q=test", "authorized": "on"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert len(spawned) == 1
    assert spawned[0]["kwargs"]["manual_test_url"] == "https://example.com/search?q=test"
    # target_url on the Scan row is still just the bare domain -
    # normalize_target() strips the path/query for that field, same as
    # ever; only the seed URL passed to the orchestrator carries it.
    assert Scan.query.first().target_url == "https://example.com"


def test_explicit_test_url_wins_over_query_string_in_target(client, db, monkeypatch, spawned):
    _public_dns(monkeypatch)
    org = make_org()
    make_user("seed2@example.com", org=org)
    login(client, "seed2@example.com")
    resp = client.post(
        "/scan/new/base",
        data={
            "target": "https://example.com/search?q=test",
            "test_url": "https://example.com/other?id=1",
            "authorized": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert spawned[0]["kwargs"]["manual_test_url"] == "https://example.com/other?id=1"


def test_query_string_target_not_applied_across_bulk_targets(client, db, monkeypatch, spawned):
    _public_dns(monkeypatch)
    org = make_org()
    make_user("seed3@example.com", org=org)
    login(client, "seed3@example.com")
    resp = client.post(
        "/scan/new/base",
        data={
            "target": "https://a.example.com/search?q=test\nhttps://b.example.com",
            "authorized": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert len(spawned) == 2
    assert all(c["kwargs"]["manual_test_url"] is None for c in spawned)


def test_target_query_string_still_checked_for_ssrf_safety(client, db):
    org = make_org()
    make_user("seed4@example.com", org=org)
    login(client, "seed4@example.com")
    resp = client.post(
        "/scan/new/base",
        data={"target": "http://127.0.0.1/search?q=test", "authorized": "on"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert Scan.query.count() == 0
