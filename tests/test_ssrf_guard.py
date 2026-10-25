"""
Tests for the SSRF guard: `is_ssrf_safe_hostname()` in glassbox/checks.py
and its caller `_unsafe_target_error()` in glassbox/scan_routes.py,
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
import hashlib
import http.server
import inspect
import socket
import socketserver
import threading

import pytest
import requests

from glassbox import checks
from glassbox.checks import UA, _mk_session, _SSRFSafeSession, is_ssrf_safe_hostname
from glassbox.models import Plan, Scan
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
    from glassbox.scan_routes import _unsafe_target_error

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    with app.app_context():
        assert _unsafe_target_error("https://example.com") is None


def test_unsafe_target_error_blocks_domain_verified_by_another_org(app, db, monkeypatch):
    from glassbox.models import DomainVerification, VerifyMethod, _utcnow
    from glassbox.scan_routes import _unsafe_target_error

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
    from glassbox.scan_routes import _unsafe_target_error

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    with app.app_context():
        assert _unsafe_target_error("https://example.com", org_id=None) is None


def test_unsafe_target_error_message_for_private_host():
    from glassbox.scan_routes import _unsafe_target_error

    msg = _unsafe_target_error("https://127.0.0.1/admin")
    assert msg is not None
    assert "private" in msg.lower() or "internal" in msg.lower()


def test_unsafe_target_error_none_hostname_is_unsafe():
    from glassbox.scan_routes import _unsafe_target_error

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


# --------------------------------------------------------------------------
# _SSRFSafeSession / _mk_session() - redirect-hop re-validation (SEC-03).
#
# checks._mk_session() is the single factory every check function's
# requests.Session comes from (see scan_engine.py's four `session =
# _mk_session()` lines). Before this section, that session was a plain
# `requests.Session()`: a target that resolves public at submission time
# and then 302s to a private/loopback/link-local/cloud-metadata address was
# followed with no re-check at all - the confirmed-open vulnerability this
# plan closes. `_SSRFSafeSession` re-validates every redirect hop's
# hostname through the same, unmodified `is_ssrf_safe_hostname()` used at
# submission time.
#
# These tests exercise real `_mk_session()`/`_SSRFSafeSession` objects
# against real local `http.server` instances in daemon threads for the
# cases where that's practical - not a mock of the override - because
# 08-RESEARCH.md's Assumption A3 (that overriding `resolve_redirects()` and
# filtering what it yields would suffice) was built and PROVEN WRONG by an
# earlier version of this test file: the "private" target's own request log
# showed it WAS fetched, because `resolve_redirects()`'s loop calls
# `self.send()` - the real network request - before it ever yields a
# response for the override to inspect. See `_SSRFSafeSession`'s docstring
# in checks.py for the full account, and 08-04-SUMMARY.md for the recorded
# finding. The actual fix overrides `get_redirect_target()` instead, which
# `resolve_redirects()` consults BEFORE sending each hop - proven below.
# --------------------------------------------------------------------------

_REAL_GETADDRINFO = socket.getaddrinfo


class _RoutedHandler(http.server.BaseHTTPRequestHandler):
    """Configured per-server via ROUTES/LOG class attributes - http.server
    instantiates one handler object per request itself, so there's no
    constructor hook to pass per-test config through; _start_server() below
    builds a fresh subclass per server instead."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.LOG.append(self.path)
        status, location, body = self.ROUTES.get(self.path, (404, None, b"not found"))
        self.send_response(status)
        if location is not None:
            self.send_header("Location", location)
        self.end_headers()
        if body:
            self.wfile.write(body)


def _start_server(routes):
    """Real local HTTP server, ephemeral loopback port, daemon thread.
    `routes`: request path -> (status, location_header_or_None, body_bytes).
    Returns (port, request_log) - request_log records every path asked for,
    which is what the blocked-hop tests below assert against directly,
    rather than trusting a response status/shape alone (a connection
    refusal can look superficially like a guard rejection; a server's own
    request log cannot be fooled that way)."""
    log = []
    handler_cls = type("_Handler", (_RoutedHandler,), {"ROUTES": routes, "LOG": log})
    server = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return port, log


def _fake_public_via_loopback(*public_hostnames):
    """socket.getaddrinfo replacement for this section's real-round-trip
    tests, used to make a hostname read as PUBLIC to is_ssrf_safe_hostname
    while a real local test server still receives the connection.

    is_ssrf_safe_hostname() always calls socket.getaddrinfo(host, None) -
    see its source above - while the real outbound TCP connection always
    calls it with the actual port number. This dispatches on that
    difference: for any hostname in `public_hostnames`, a lookup with
    port=None (is_ssrf_safe_hostname's own check) returns a genuine public
    IP, so the guard reads it as safe exactly like a real public hostname;
    a lookup with a real port (the actual connection) returns
    127.0.0.1-with-that-port, so the request actually reaches this test's
    local server. Any other hostname falls through to the real resolver
    unchanged. Without this, a test hostname that's actually reachable
    (i.e. resolves to loopback) would also always resolve to loopback for
    is_ssrf_safe_hostname's own check and be correctly - but unhelpfully -
    classified unsafe, since loopback is loopback regardless of who's
    asking."""
    def _impl(host, port, *args, **kwargs):
        if host in public_hostnames:
            if port is None:
                return _fake_getaddrinfo("93.184.216.34")(host, port)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        return _REAL_GETADDRINFO(host, port, *args, **kwargs)
    return _impl


def _redirect_hop_session():
    """Session for the round-trip redirect tests below: the real
    _SSRFSafeSession redirect-hop guard (get_redirect_target), but with a
    PLAIN adapter replacing _mk_session()'s connect-time peer-IP pinning.

    Those two guards are different layers. The redirect-hop guard lives on
    the Session and decides which Location to follow; the connect-pin
    adapter lives on the transport and validates the IP a socket actually
    reaches. These tests prove the first by physically round-tripping
    through a loopback test server - which the (correct) connect-pin guard
    would otherwise block, since loopback IS unsafe. Connect-pinning has
    its own coverage in test_ssrf_connect_pinning.py; here we isolate the
    redirect-hop layer by mounting a plain adapter."""
    session = _mk_session()
    plain = requests.adapters.HTTPAdapter()
    session.mount("http://", plain)
    session.mount("https://", plain)
    return session


def test_mk_session_returns_ssrf_safe_session_with_ua_header():
    session = _mk_session()
    assert isinstance(session, _SSRFSafeSession)
    assert session.headers["User-Agent"] == UA


def test_redirect_to_loopback_target_is_never_fetched():
    # Both "servers" here are real, bound to 127.0.0.1 - loopback is
    # naturally unsafe per is_ssrf_safe_hostname with no DNS mocking
    # needed, so this is the plan's required real-server-request-log proof:
    # if the guard failed, private_log would record the "/secret" request.
    private_port, private_log = _start_server({"/secret": (200, None, b"SECRET")})
    entry_port, entry_log = _start_server({
        "/": (302, f"http://127.0.0.1:{private_port}/secret", None),
    })

    session = _redirect_hop_session()
    resp = session.get(f"http://127.0.0.1:{entry_port}/", timeout=5)

    assert entry_log == ["/"]
    assert private_log == [], (
        "guard failed: the loopback target's own request log shows it was fetched"
    )
    assert resp.status_code == 302
    assert resp.url == f"http://127.0.0.1:{entry_port}/"


# RFC1918/link-local/cloud-metadata addresses can't be bound as a real local
# server in a sandboxed test environment (and 169.254.169.254 specifically
# must never be dialed for real in a test - on a real cloud VM that address
# is the live metadata service, so even attempting the connection would be
# the wrong kind of "proof"). Unlike the loopback case above, these three
# call the real, unmocked _SSRFSafeSession.get_redirect_target() directly
# against a manually-built Response - not a mock of the override, the
# actual method, exercised with a literal IP that needs no DNS mocking
# either (matching this file's existing
# test_literal_loopback_ip_is_unsafe_without_mocking pattern). This is the
# "equivalent assertion" for these three address classes: it proves the
# same blocking decision the loopback test proves by network observation,
# without ever letting a socket touch these addresses.
@pytest.mark.parametrize("target_url,reason", [
    ("http://10.0.0.5/internal", "RFC1918 private"),
    ("http://169.254.1.1/internal", "link-local"),
    ("http://169.254.169.254/latest/meta-data/", "cloud metadata endpoint"),
])
def test_redirect_to_unsafe_literal_ip_is_blocked_without_dialing_it(target_url, reason):
    session = _SSRFSafeSession()
    resp = requests.Response()
    resp.status_code = 302
    resp.url = "http://entry.example.test/"
    resp.headers["Location"] = target_url
    assert session.get_redirect_target(resp) is None, reason


def test_redirect_to_public_hostname_is_followed(monkeypatch):
    target_port, target_log = _start_server({"/": (200, None, b"final destination")})
    entry_port, entry_log = _start_server({
        "/": (302, f"http://public-target.example.test:{target_port}/", None),
    })
    monkeypatch.setattr(
        socket, "getaddrinfo",
        _fake_public_via_loopback("public-entry.example.test", "public-target.example.test"),
    )

    session = _redirect_hop_session()
    resp = session.get(f"http://public-entry.example.test:{entry_port}/", timeout=5)

    assert entry_log == ["/"]
    assert target_log == ["/"], "a legitimate public-to-public redirect must still be followed"
    assert resp.status_code == 200
    assert resp.url == f"http://public-target.example.test:{target_port}/"


def test_safe_safe_unsafe_chain_stops_at_last_safe_hop(monkeypatch):
    # hop3 is a real loopback server (naturally unsafe, no mocking needed) -
    # if the guard fails, its own request log proves it, exactly like
    # test_redirect_to_loopback_target_is_never_fetched above.
    hop3_port, hop3_log = _start_server({"/secret": (200, None, b"should never be reached")})
    hop2_port, hop2_log = _start_server({
        "/": (302, f"http://127.0.0.1:{hop3_port}/secret", None),
    })
    hop1_port, hop1_log = _start_server({
        "/": (302, f"http://hop2.example.test:{hop2_port}/", None),
    })
    monkeypatch.setattr(
        socket, "getaddrinfo",
        _fake_public_via_loopback("hop1.example.test", "hop2.example.test"),
    )

    session = _redirect_hop_session()
    resp = session.get(f"http://hop1.example.test:{hop1_port}/", timeout=5)

    assert hop1_log == ["/"]
    assert hop2_log == ["/"]
    assert hop3_log == [], "chain must stop before the unsafe third hop, not fetch it and stop after"
    assert resp.status_code == 302
    assert resp.url == f"http://hop2.example.test:{hop2_port}/"


@pytest.mark.parametrize("location", [
    "mailto:test@example.com",   # absolute URL, different scheme, no netloc
    "javascript:alert(1)",       # same shape, classic no-hostname payload
])
def test_redirect_with_unparseable_hostname_is_not_followed(location):
    entry_port, entry_log = _start_server({"/": (302, location, None)})

    session = _redirect_hop_session()
    resp = session.get(f"http://127.0.0.1:{entry_port}/", timeout=5)

    assert entry_log == ["/"]
    assert resp.status_code == 302
    assert resp.url == f"http://127.0.0.1:{entry_port}/"


# Every test in this section returns a plain Response from session.get()/
# get_redirect_target() and asserts on it directly - none wraps the call in
# try/except or pytest.raises. That absence is itself the proof for the
# "no exception escapes" acceptance criterion: a raised exception in any of
# them would fail the test outright, not silently pass.


# --------------------------------------------------------------------------
# Legitimate-redirect regression coverage (08-RESEARCH.md Pitfall 2: don't
# reject a hop merely because the hostname changed) + the frozen-surface and
# delegation locks (Pitfall 4: don't "finish" this by quietly weakening
# is_ssrf_safe_hostname or reinventing its logic inside the new class).
# --------------------------------------------------------------------------

class _PlainHTTPOverHTTPSAdapter(requests.adapters.HTTPAdapter):
    """Test-only adapter: rewrites an https:// request's URL to http://
    before sending it, so a real local plain-HTTP test server can stand in
    for a TLS endpoint. Exists purely to test a same-host scheme-upgrade
    redirect without this repo taking on a `cryptography` dependency
    (absent from requirements-dev.txt, and this plan's prohibitions say not
    to add one) just to mint a throwaway self-signed certificate for one
    test. Mounted only on a session built specifically for this test -
    never touches `_mk_session()`/production code."""

    def send(self, request, **kwargs):
        request.url = request.url.replace("https://", "http://", 1)
        return super().send(request, **kwargs)


def test_scheme_upgrade_redirect_same_host_is_followed(monkeypatch):
    routes = {}
    port, log = _start_server(routes)
    routes["/"] = (301, f"https://scheme-upgrade.example.test:{port}/next", None)
    routes["/next"] = (200, None, b"upgraded")
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_public_via_loopback("scheme-upgrade.example.test"),
    )

    session = _redirect_hop_session()
    session.mount("https://", _PlainHTTPOverHTTPSAdapter())
    resp = session.get(f"http://scheme-upgrade.example.test:{port}/", timeout=5)

    # resp.url reads http:// here (not https://) because the adapter above
    # rewrites the outbound request before requests records it - a
    # test-infrastructure artifact of avoiding a real TLS handshake, not a
    # scheme downgrade performed by the guard. The log proves what actually
    # matters: both hops were fetched, i.e. the same-host scheme-upgrade
    # redirect was followed, not rejected.
    assert log == ["/", "/next"]
    assert resp.status_code == 200


def test_apex_to_www_redirect_is_followed(monkeypatch):
    www_port, www_log = _start_server({"/": (200, None, b"www content")})
    apex_port, apex_log = _start_server({
        "/": (302, f"http://www.apex.example.test:{www_port}/", None),
    })
    monkeypatch.setattr(
        socket, "getaddrinfo",
        _fake_public_via_loopback("apex.example.test", "www.apex.example.test"),
    )

    session = _redirect_hop_session()
    resp = session.get(f"http://apex.example.test:{apex_port}/", timeout=5)

    assert apex_log == ["/"]
    assert www_log == ["/"]
    assert resp.status_code == 200
    assert resp.url == f"http://www.apex.example.test:{www_port}/"


def test_cross_domain_public_redirect_is_followed(monkeypatch):
    other_port, other_log = _start_server({"/": (200, None, b"other domain content")})
    origin_port, origin_log = _start_server({
        "/": (302, f"http://other-public.example.test:{other_port}/", None),
    })
    monkeypatch.setattr(
        socket, "getaddrinfo",
        _fake_public_via_loopback("origin-public.example.test", "other-public.example.test"),
    )

    session = _redirect_hop_session()
    resp = session.get(f"http://origin-public.example.test:{origin_port}/", timeout=5)

    assert origin_log == ["/"]
    assert other_log == ["/"], "hostname changing alone must not be treated as a rejection reason"
    assert resp.status_code == 200
    assert resp.url == f"http://other-public.example.test:{other_port}/"


def test_allow_redirects_false_returns_redirect_unfollowed():
    # Mirrors checks.py:536 and :1049's call pattern - this documents and
    # locks that those two call sites are unaffected by this change, since
    # allow_redirects=False never enters resolve_redirects()'s
    # self.send()-per-hop loop at all.
    entry_port, entry_log = _start_server({
        "/": (302, "http://127.0.0.1:1/unreachable", None),
    })

    session = _redirect_hop_session()
    resp = session.get(f"http://127.0.0.1:{entry_port}/", timeout=5, allow_redirects=False)

    assert entry_log == ["/"]
    assert resp.status_code == 302
    assert resp.headers["Location"] == "http://127.0.0.1:1/unreachable"


# This hash was computed from is_ssrf_safe_hostname()'s source at the point
# this plan started (08-04, SEC-03) - the function's pre-plan baseline.
_IS_SSRF_SAFE_HOSTNAME_SOURCE_SHA256 = (
    "546fc01009d3e9e737221df4fac42c6ac8d2041e7c63dd30421865bfe968c3dd"
)


def test_is_ssrf_safe_hostname_source_is_byte_identical_to_pre_plan_baseline():
    src = inspect.getsource(checks.is_ssrf_safe_hostname).replace("\r\n", "\n")
    actual_hash = hashlib.sha256(src.encode("utf-8")).hexdigest()
    assert actual_hash == _IS_SSRF_SAFE_HOSTNAME_SOURCE_SHA256, (
        "is_ssrf_safe_hostname()'s source has changed. This function is FROZEN per "
        "CLAUDE.md ('Do not weaken or remove ... checks.is_ssrf_safe_hostname()') - "
        "a change here needs a deliberate, explicit decision recorded in "
        "PROJECT.md/CLAUDE.md, not a quiet test-baseline update to make this pass."
    )


def test_ssrf_safe_session_delegates_to_is_ssrf_safe_hostname_not_its_own_classification():
    src = inspect.getsource(checks._SSRFSafeSession.get_redirect_target)
    # Filter out full-line comments so an explanatory comment mentioning the
    # forbidden term can't accidentally satisfy or break this assertion.
    code_only = "\n".join(
        line for line in src.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )
    assert "is_ssrf_safe_hostname(" in code_only, (
        "_SSRFSafeSession.get_redirect_target() must delegate to is_ssrf_safe_hostname() - "
        "no call to it found in the method body."
    )
    # Derived from checks.py's own `import ipaddress`, not retyped here.
    forbidden_module_name = checks.ipaddress.__name__
    assert forbidden_module_name not in code_only, (
        f"_SSRFSafeSession.get_redirect_target() references {forbidden_module_name!r} "
        "directly - it must not define its own address classification; "
        "is_ssrf_safe_hostname() is the single source of truth for what counts unsafe."
    )
