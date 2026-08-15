"""
Tests for the guided New Scan wizard (SCANUX-01..04): Step 1 (`/scan/new`,
Select Domain) and Step 2 (`/scan/new/type`, Select Type).

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

from webvulnscanner.extensions import db as _db
from webvulnscanner.models import DomainVerification, Plan, VerifyMethod

from tests.conftest import login, make_org, make_user


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
