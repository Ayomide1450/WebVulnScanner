"""
Tests for webvulnscanner/domain_verification.py - previously untested
despite already implementing *two* proof-of-ownership methods (DNS TXT and
well-known file), both wired end-to-end through generate_verification()/
verify_domain(). Written as part of the "strengthen ownership verification"
sign-off item after Step 0 found both methods already existed and worked;
these tests exist to actually prove that rather than take it on faith, and
to guard the "must keep working exactly as now" requirement against future
changes.

DNS/HTTP calls are mocked (monkeypatch dns.resolver.resolve / requests.get)
per the app's established test convention (see test_ssrf_guard.py's
module docstring) - no real network I/O.
"""
import requests

from webvulnscanner.domain_verification import (
    generate_verification,
    txt_record_value,
    verify_domain,
    well_known_path_and_content,
)
from webvulnscanner.entitlements import domain_is_org_verified
from webvulnscanner.models import VerifyMethod

from tests.conftest import make_org


class _FakeRdata:
    def __init__(self, text):
        self.strings = [text.encode()]


def test_generate_verification_creates_row_with_token(db):
    org = make_org()
    dv = generate_verification(org.id, "Example.COM", VerifyMethod.DNS_TXT)
    assert dv.domain == "example.com"  # lowercased
    assert dv.method == VerifyMethod.DNS_TXT
    assert dv.token
    assert dv.verified_at is None


def test_generate_verification_reuses_row_and_resets_verified_at(db):
    org = make_org()
    dv = generate_verification(org.id, "example.com", VerifyMethod.DNS_TXT)
    dv.verified_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    old_token = dv.token

    dv2 = generate_verification(org.id, "example.com", VerifyMethod.WELL_KNOWN)
    assert dv2.id == dv.id  # same row, not a duplicate
    assert dv2.token != old_token
    assert dv2.method == VerifyMethod.WELL_KNOWN
    assert dv2.verified_at is None  # reset, since it's no longer proven against the new token


# --------------------------------------------------------------------------
# DNS TXT method
# --------------------------------------------------------------------------

def test_dns_txt_verification_succeeds_on_matching_record(db, monkeypatch):
    import dns.resolver

    org = make_org()
    dv = generate_verification(org.id, "example.com", VerifyMethod.DNS_TXT)
    expected = txt_record_value(dv)

    monkeypatch.setattr(dns.resolver, "resolve", lambda *a, **k: [_FakeRdata(expected)])
    assert verify_domain(dv) is True
    assert dv.verified_at is not None


def test_dns_txt_verification_fails_on_mismatched_record(db, monkeypatch):
    import dns.resolver

    org = make_org()
    dv = generate_verification(org.id, "example.com", VerifyMethod.DNS_TXT)

    monkeypatch.setattr(dns.resolver, "resolve", lambda *a, **k: [_FakeRdata("webvulnscanner-verify=wrong-token")])
    assert verify_domain(dv) is False
    assert dv.verified_at is None


def test_dns_txt_verification_fails_gracefully_on_nxdomain(db, monkeypatch):
    import dns.resolver

    org = make_org()
    dv = generate_verification(org.id, "example.com", VerifyMethod.DNS_TXT)

    def _raise(*a, **k):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver, "resolve", _raise)
    assert verify_domain(dv) is False  # never raises past verify_domain


# --------------------------------------------------------------------------
# well-known file method
# --------------------------------------------------------------------------

def test_well_known_verification_succeeds_on_matching_content(db, monkeypatch):
    import webvulnscanner.domain_verification as domver

    org = make_org()
    dv = generate_verification(org.id, "example.com", VerifyMethod.WELL_KNOWN)
    path, token = well_known_path_and_content(dv)

    class _Resp:
        status_code = 200
        text = f"some prefix {token} some suffix"

    monkeypatch.setattr(domver.requests, "get", lambda url, timeout=None: _Resp())
    assert verify_domain(dv) is True
    assert dv.verified_at is not None


def test_well_known_verification_fails_on_wrong_content(db, monkeypatch):
    import webvulnscanner.domain_verification as domver

    org = make_org()
    dv = generate_verification(org.id, "example.com", VerifyMethod.WELL_KNOWN)

    class _Resp:
        status_code = 200
        text = "unrelated content"

    monkeypatch.setattr(domver.requests, "get", lambda url, timeout=None: _Resp())
    assert verify_domain(dv) is False


def test_well_known_verification_fails_gracefully_on_connection_error(db, monkeypatch):
    import webvulnscanner.domain_verification as domver

    org = make_org()
    dv = generate_verification(org.id, "example.com", VerifyMethod.WELL_KNOWN)

    def _raise(url, timeout=None):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr(domver.requests, "get", _raise)
    assert verify_domain(dv) is False  # never raises past verify_domain


# --------------------------------------------------------------------------
# Both methods are equally valid proof - domain_is_org_verified() (the
# actual gate entitlements.py/scan_routes.py check before an intrusive
# scan) only cares that *some* row for this org+domain has verified_at
# set, regardless of which method proved it. This is what makes the two
# methods "OR", not "the newer one replaces the older one".
# --------------------------------------------------------------------------

def test_domain_is_org_verified_true_after_dns_txt(db, monkeypatch):
    import dns.resolver

    org = make_org()
    dv = generate_verification(org.id, "example.com", VerifyMethod.DNS_TXT)
    monkeypatch.setattr(dns.resolver, "resolve", lambda *a, **k: [_FakeRdata(txt_record_value(dv))])
    verify_domain(dv)
    assert domain_is_org_verified(org, "https://example.com") is True


def test_domain_is_org_verified_true_after_well_known(db, monkeypatch):
    import webvulnscanner.domain_verification as domver

    org = make_org()
    dv = generate_verification(org.id, "example.com", VerifyMethod.WELL_KNOWN)
    _path, token = well_known_path_and_content(dv)

    class _Resp:
        status_code = 200
        text = token

    monkeypatch.setattr(domver.requests, "get", lambda url, timeout=None: _Resp())
    verify_domain(dv)
    assert domain_is_org_verified(org, "https://example.com") is True


def test_domain_is_org_verified_false_when_unverified(db):
    org = make_org()
    generate_verification(org.id, "example.com", VerifyMethod.DNS_TXT)  # never verified
    assert domain_is_org_verified(org, "https://example.com") is False
