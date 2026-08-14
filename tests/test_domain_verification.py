"""
Tests for the domain-ownership verification flow (HARD-03's D-08 half):
`webvulnscanner/domain_verification.py`'s `generate_verification`/
`verify_domain`, and `org_routes.verify_domain_view`'s `action=add`/
`action=verify` POST branches. Both proof methods (DNS TXT, well-known
HTTP) already worked before this phase - D-08 scopes this module to
coverage only, not a behavior change.

Every DNS lookup and outbound HTTP request is mocked - `dns.resolver.resolve`
and `requests.get` are monkeypatched at the module path
`webvulnscanner/domain_verification.py` imports them through, following the
same never-touch-the-network convention `tests/test_ssrf_guard.py` already
established for this kind of check.

Split into a helper-level section (direct calls into domain_verification.py,
exercising the resolver-exception/HTTP-failure surface), a route-level
section (verify_domain_view's cross-org guard, a different failure surface
entirely - a wrong identifier rather than a network error), and a final
`domain_is_org_verified` section proving the two proof methods are
combined as an OR (from an independently-written pass covering the same
module - see that section's own header comment for why it's appended
here rather than a separate file).
"""
from datetime import datetime, timezone

import dns.resolver
import requests

from webvulnscanner.domain_verification import (
    generate_verification,
    txt_record_value,
    verify_domain,
    well_known_path_and_content,
)
from webvulnscanner.entitlements import domain_is_org_verified
from webvulnscanner.models import DomainVerification, Role, VerifyMethod

from tests.conftest import login, make_org, make_user


class _FakeTxtAnswer:
    """Mimics dns.resolver.resolve()'s per-record shape closely enough for
    _verify_dns_txt: a `.strings` list of byte-string chunks, joined and
    decoded exactly as the real dnspython answer would be."""

    def __init__(self, value):
        self.strings = [value.encode()]


class _FakeHttpResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


# --------------------------------------------------------------------------
# Helper-level: generate_verification
# --------------------------------------------------------------------------

def test_generate_verification_creates_new_row(db):
    org = make_org()
    db.session.commit()

    dv = generate_verification(org.id, "Example.com", VerifyMethod.DNS_TXT)

    assert dv.org_id == org.id
    assert dv.domain == "example.com"
    assert dv.method == VerifyMethod.DNS_TXT
    assert dv.token
    assert dv.verified_at is None
    assert DomainVerification.query.filter_by(org_id=org.id, domain="example.com").count() == 1


def test_generate_verification_resets_existing_row_in_place(db):
    org = make_org()
    db.session.commit()

    first = generate_verification(org.id, "example.com", VerifyMethod.DNS_TXT)
    first.verified_at = datetime.now(timezone.utc)
    db.session.commit()
    first_token = first.token
    first_id = first.id

    second = generate_verification(org.id, "example.com", VerifyMethod.WELL_KNOWN)

    assert second.id == first_id  # same row, not a new one
    assert second.token != first_token
    assert second.method == VerifyMethod.WELL_KNOWN
    assert second.verified_at is None
    assert DomainVerification.query.filter_by(org_id=org.id, domain="example.com").count() == 1


# --------------------------------------------------------------------------
# Helper-level: verify_domain (DNS TXT)
# --------------------------------------------------------------------------

def test_verify_domain_dns_txt_success(db, monkeypatch):
    org = make_org()
    db.session.commit()
    dv = generate_verification(org.id, "example.com", VerifyMethod.DNS_TXT)

    monkeypatch.setattr(
        dns.resolver, "resolve",
        lambda domain, rtype, lifetime=None: [_FakeTxtAnswer(txt_record_value(dv))],
    )

    assert verify_domain(dv) is True
    assert dv.verified_at is not None


def test_verify_domain_dns_txt_no_matching_record(db, monkeypatch):
    org = make_org()
    db.session.commit()
    dv = generate_verification(org.id, "example.com", VerifyMethod.DNS_TXT)

    monkeypatch.setattr(
        dns.resolver, "resolve",
        lambda domain, rtype, lifetime=None: [_FakeTxtAnswer("some-other-record")],
    )

    assert verify_domain(dv) is False
    assert dv.verified_at is None


def test_verify_domain_dns_txt_resolver_exception_does_not_raise(db, monkeypatch):
    org = make_org()
    db.session.commit()
    dv = generate_verification(org.id, "example.com", VerifyMethod.DNS_TXT)

    def _raise(domain, rtype, lifetime=None):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver, "resolve", _raise)

    assert verify_domain(dv) is False
    assert dv.verified_at is None


# --------------------------------------------------------------------------
# Helper-level: verify_domain (well-known)
# --------------------------------------------------------------------------

def test_verify_domain_well_known_https_success(db, monkeypatch):
    org = make_org()
    db.session.commit()
    dv = generate_verification(org.id, "example.com", VerifyMethod.WELL_KNOWN)
    _, token = well_known_path_and_content(dv)

    monkeypatch.setattr(requests, "get", lambda url, timeout=None: _FakeHttpResponse(200, token))

    assert verify_domain(dv) is True
    assert dv.verified_at is not None


def test_verify_domain_well_known_falls_back_to_http_when_https_raises(db, monkeypatch):
    org = make_org()
    db.session.commit()
    dv = generate_verification(org.id, "example.com", VerifyMethod.WELL_KNOWN)
    _, token = well_known_path_and_content(dv)

    def _get(url, timeout=None):
        if url.startswith("https://"):
            raise requests.RequestException("connection refused")
        return _FakeHttpResponse(200, token)

    monkeypatch.setattr(requests, "get", _get)

    assert verify_domain(dv) is True
    assert dv.verified_at is not None


def test_verify_domain_well_known_fails_when_both_schemes_fail(db, monkeypatch):
    org = make_org()
    db.session.commit()
    dv = generate_verification(org.id, "example.com", VerifyMethod.WELL_KNOWN)

    def _get(url, timeout=None):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(requests, "get", _get)

    assert verify_domain(dv) is False
    assert dv.verified_at is None


# --------------------------------------------------------------------------
# Route-level: verify_domain_view
# --------------------------------------------------------------------------

def test_verify_domain_view_add_creates_row_and_shows_proof(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()
    login(client, "admin@example.com")

    resp = client.post(
        "/org/verify-domain",
        data={"action": "add", "domain": "example.com", "method": VerifyMethod.DNS_TXT.value},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    dv = DomainVerification.query.filter_by(org_id=org.id, domain="example.com").first()
    assert dv is not None

    html = resp.get_data(as_text=True)
    assert txt_record_value(dv) in html


def test_verify_domain_view_verify_rejects_cross_org_row(client, db):
    org_a = make_org(name="Org A")
    org_b = make_org(name="Org B")
    make_user("admin_a@example.com", org=org_a, role=Role.ORG_ADMIN)
    make_user("admin_b@example.com", org=org_b, role=Role.ORG_ADMIN)
    db.session.commit()

    dv_b = generate_verification(org_b.id, "example.com", VerifyMethod.DNS_TXT)

    login(client, "admin_a@example.com")
    resp = client.post("/org/verify-domain", data={"action": "verify", "domain_id": dv_b.id})

    assert resp.status_code == 404
    refreshed = DomainVerification.query.get(dv_b.id)
    assert refreshed.verified_at is None


def test_verify_domain_view_get_requires_org_admin(client, db):
    org = make_org()
    make_user("member@example.com", org=org, role=Role.MEMBER)
    db.session.commit()
    login(client, "member@example.com")

    resp = client.get("/org/verify-domain")
    assert resp.status_code == 403


# --------------------------------------------------------------------------
# domain_is_org_verified() - proves the two proof methods (DNS TXT,
# well-known) are combined as an OR by entitlements.py's gate for intrusive
# checks (the actual gate scan_routes.py/entitlements.py check before an
# intrusive scan), not "the newer one replaces the older one". From an
# independently-written test pass over the same module.
# --------------------------------------------------------------------------

def test_domain_is_org_verified_true_after_dns_txt(db, monkeypatch):
    org = make_org()
    dv = generate_verification(org.id, "example.com", VerifyMethod.DNS_TXT)
    monkeypatch.setattr(dns.resolver, "resolve", lambda *a, **k: [_FakeTxtAnswer(txt_record_value(dv))])
    verify_domain(dv)
    assert domain_is_org_verified(org, "https://example.com") is True


def test_domain_is_org_verified_true_after_well_known(db, monkeypatch):
    import webvulnscanner.domain_verification as domver

    org = make_org()
    dv = generate_verification(org.id, "example.com", VerifyMethod.WELL_KNOWN)
    _path, token = well_known_path_and_content(dv)

    monkeypatch.setattr(domver.requests, "get", lambda url, timeout=None: _FakeHttpResponse(200, token))
    verify_domain(dv)
    assert domain_is_org_verified(org, "https://example.com") is True


def test_domain_is_org_verified_false_when_unverified(db):
    org = make_org()
    generate_verification(org.id, "example.com", VerifyMethod.DNS_TXT)  # never verified
    assert domain_is_org_verified(org, "https://example.com") is False
