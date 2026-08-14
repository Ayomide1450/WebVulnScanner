"""
Tests for the SSRF guard: `is_ssrf_safe_hostname()` in webvulnscanner/checks.py
and its caller `_unsafe_target_error()` in webvulnscanner/scan_routes.py,
which every `new_scan_*` route calls on each user-supplied absolute URL
before a `Scan` row is created (CLAUDE.md's hard rule: this function must
not be weakened).

`is_ssrf_safe_hostname` does a real `socket.getaddrinfo()` lookup - these
tests monkeypatch that call rather than depend on live DNS/network, per the
handoff note that real network calls inside test scripts are unreliable and
that a real scan thread must never be triggered from a test (it writes to
the app's DB from a second thread and can corrupt main-thread ORM state).
The two literal-IP integration tests below are the one exception: an IP
literal resolves locally with no network round-trip, so using one as the
scan target lets a route-level test exercise the guard for real without
either mocking or touching the network - and since the guard rejects them
before a Scan row is created, no background thread ever spawns.
"""
import socket

import pytest

from webvulnscanner.checks import is_ssrf_safe_hostname
from webvulnscanner.models import Plan, Scan

from tests.conftest import login, make_org, make_user


def _fake_getaddrinfo(*ips):
    """Builds a getaddrinfo() replacement returning one AF_INET/AF_INET6
    result per IP string, in the same shape socket.getaddrinfo returns:
    (family, type, proto, canonname, sockaddr), sockaddr[0] == the IP."""
    def _impl(host, port, *args, **kwargs):
        infos = []
        for ip in ips:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            sockaddr = (ip, 0, 0, 0) if family == socket.AF_INET6 else (ip, 0)
            infos.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
        return infos
    return _impl


@pytest.mark.parametrize("ip", [
    "93.184.216.34",  # ordinary public IPv4
    "8.8.8.8",
    "2606:2800:220:1:248:1893:25c8:1946",  # public IPv6
])
def test_public_address_is_safe(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(ip))
    assert is_ssrf_safe_hostname("example.com") is True


@pytest.mark.parametrize("ip,reason", [
    ("127.0.0.1", "loopback"),
    ("::1", "IPv6 loopback"),
    ("10.0.0.5", "RFC1918 private"),
    ("172.16.0.5", "RFC1918 private"),
    ("192.168.1.5", "RFC1918 private"),
    ("169.254.169.254", "link-local / cloud metadata endpoint"),
    ("224.0.0.1", "multicast"),
    ("0.0.0.0", "unspecified"),
    ("240.0.0.1", "reserved"),
])
def test_unsafe_address_classes_are_rejected(monkeypatch, ip, reason):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(ip))
    assert is_ssrf_safe_hostname("attacker-controlled.example") is False, reason


def test_rejects_if_any_resolved_address_is_unsafe(monkeypatch):
    # DNS can return multiple A/AAAA records - one public, one private is
    # enough to reject the whole hostname, not just skip the bad record.
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34", "127.0.0.1"))
    assert is_ssrf_safe_hostname("mixed-results.example") is False


def test_unresolvable_hostname_is_unsafe(monkeypatch):
    def _raise(*a, **k):
        raise socket.gaierror("name or service not known")
    monkeypatch.setattr(socket, "getaddrinfo", _raise)
    assert is_ssrf_safe_hostname("this-does-not-resolve.invalid") is False


def test_malformed_hostname_is_unsafe(monkeypatch):
    def _raise(*a, **k):
        raise UnicodeError("encoding error")
    monkeypatch.setattr(socket, "getaddrinfo", _raise)
    assert is_ssrf_safe_hostname("xn--bad") is False


def test_empty_resolution_result_is_unsafe(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])
    assert is_ssrf_safe_hostname("no-records.example") is False


def test_literal_loopback_ip_is_unsafe_without_mocking():
    # A literal IP resolves locally (no DNS round-trip), so this exercises
    # the real socket.getaddrinfo, matching how a scan submission of
    # "127.0.0.1" is actually handled.
    assert is_ssrf_safe_hostname("127.0.0.1") is False


def test_literal_cloud_metadata_ip_is_unsafe_without_mocking():
    assert is_ssrf_safe_hostname("169.254.169.254") is False


# --------------------------------------------------------------------------
# scan_routes._unsafe_target_error - the wrapper every new_scan_* route
# calls; pure function (urlparse + is_ssrf_safe_hostname only), so it's
# callable directly without an app/request context.
# --------------------------------------------------------------------------

def test_unsafe_target_error_none_for_public_host(app, monkeypatch):
    # Needs an app context now: a public/safe hostname also gets checked
    # against DomainVerification (is it a domain another org already
    # verified?), which is a real DB query - see _unsafe_target_error's
    # docstring for why. The private-host test below doesn't need this,
    # it short-circuits on the SSRF check before ever reaching the DB.
    from webvulnscanner.scan_routes import _unsafe_target_error

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    with app.app_context():
        assert _unsafe_target_error("https://example.com") is None


def test_unsafe_target_error_blocks_domain_verified_by_another_org(app, db, monkeypatch):
    from webvulnscanner.models import DomainVerification, VerifyMethod, _utcnow
    from webvulnscanner.scan_routes import _unsafe_target_error

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    owner_org = make_org(name="Owner Org")
    other_org = make_org(name="Other Org")
    dv = DomainVerification(
        org_id=owner_org.id, domain="example.com", method=VerifyMethod.DNS_TXT,
        token="tok", verified_at=_utcnow(),
    )
    db.session.add(dv)
    db.session.commit()

    with app.app_context():
        # The domain's own owning org: still allowed.
        assert _unsafe_target_error("https://example.com", org_id=owner_org.id) is None
        # Any other org (or no org at all): blocked.
        msg = _unsafe_target_error("https://example.com", org_id=other_org.id)
        assert msg is not None
        assert "another organization" in msg
        assert _unsafe_target_error("https://example.com", org_id=None) is not None


def test_unsafe_target_error_allows_unclaimed_domain_for_anyone(app, db, monkeypatch):
    from webvulnscanner.scan_routes import _unsafe_target_error

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    with app.app_context():
        assert _unsafe_target_error("https://example.com", org_id=None) is None


def test_unsafe_target_error_message_for_private_host():
    from webvulnscanner.scan_routes import _unsafe_target_error

    msg = _unsafe_target_error("https://127.0.0.1/admin")
    assert msg is not None
    assert "private" in msg.lower() or "internal" in msg.lower()


def test_unsafe_target_error_none_hostname_is_unsafe():
    from webvulnscanner.scan_routes import _unsafe_target_error

    # A URL urlparse can't extract a hostname from (e.g. no netloc) must
    # not slip through as "safe" just because is_ssrf_safe_hostname was
    # never even called.
    assert _unsafe_target_error("not a url") is not None


# --------------------------------------------------------------------------
# Route-level integration: a blocked target must not create a Scan row (and
# therefore never spawns the background-thread orchestrator that would
# make a real network request).
# --------------------------------------------------------------------------

@pytest.fixture()
def logged_in_client(db, client):
    org = make_org(plan=Plan.ORG_VERIFIED, name="Verified Org")  # tier is irrelevant to the SSRF guard, which runs before entitlement checks
    make_user("scanner@example.com", org=org)
    login(client, "scanner@example.com")
    return client


@pytest.mark.parametrize("target", [
    "127.0.0.1",
    "169.254.169.254",  # cloud metadata endpoint
    "192.168.1.1",
    "10.0.0.1",
])
def test_new_scan_base_rejects_private_targets_without_creating_a_scan(logged_in_client, db, target):
    resp = logged_in_client.post(
        "/scan/new/base",
        data={"authorized": "on", "target": target},
        follow_redirects=False,
    )
    assert resp.status_code == 200  # re-renders the form with an error, no redirect
    assert b"private" in resp.data.lower() or b"internal" in resp.data.lower()
    assert Scan.query.count() == 0


def test_new_scan_media_rejects_private_target(logged_in_client, db):
    resp = logged_in_client.post(
        "/scan/new/media",
        data={"authorized_media": "on", "media_target": "127.0.0.1"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert Scan.query.count() == 0


def test_new_scan_api_rejects_private_target(logged_in_client, db):
    resp = logged_in_client.post(
        "/scan/new/api",
        data={"authorized_api": "on", "api_target": "169.254.169.254"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert Scan.query.count() == 0


def test_new_scan_advanced_rejects_private_group_url(logged_in_client, db):
    resp = logged_in_client.post(
        "/scan/new/advanced",
        data={
            "authorized_adv": "on",
            "login_url": "http://127.0.0.1/login",
            "login_user_field": "user",
            "login_pass_field": "pass",
            "login_fail_text": "invalid",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert Scan.query.count() == 0


def test_new_scan_base_missing_authorized_checkbox_is_rejected_before_ssrf_check(logged_in_client, db):
    # The authorization checkbox is checked before target validation - a
    # private-IP target with no checkbox should get the authorization
    # error, not the SSRF one (both end in "no Scan row", but this pins the
    # documented ordering in new_scan_base).
    resp = logged_in_client.post(
        "/scan/new/base", data={"target": "127.0.0.1"}, follow_redirects=False,
    )
    assert resp.status_code == 200
    assert b"authorized" in resp.data.lower()
    assert Scan.query.count() == 0
