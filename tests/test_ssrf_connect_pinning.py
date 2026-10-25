"""Connect-time SSRF pinning - the DNS-rebinding half of the defense.

is_ssrf_safe_hostname (covered by test_ssrf_guard.py) resolves DNS at
submission time. A rebinding attacker can serve a public IP then and an
internal IP at connect time, slipping past that check. _mk_session()'s
_SSRFPinnedAdapter closes this by validating the IP the socket ACTUALLY
connected to, read off the live socket via getpeername(), before any
request byte is sent.

These tests exercise the real socket path against a real loopback HTTP
server rather than mocking getaddrinfo - mocking resolution would test the
submission-time check again, not this one. The key move: we connect the
pinned session straight to a 127.0.0.1 server (bypassing the
submission-time guard entirely, exactly as a successful rebind would) and
assert the connection is refused at the socket.
"""
import ipaddress
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

from glassbox.checks import (
    _assert_peer_ip_safe,
    _mk_session,
    _SSRFBlocked,
    is_unsafe_ip,
)


@pytest.fixture(autouse=True)
def _force_connect_pinning(monkeypatch):
    """This file is the one that proves the guard, so it overrides
    conftest.py's global disable and turns pinning back ON."""
    monkeypatch.setattr("glassbox.checks.PIN_CONNECTIONS", True)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"internal service reached")

    def log_message(self, *args):
        pass  # keep test output quiet


@pytest.fixture()
def loopback_server():
    """A real HTTP server bound to 127.0.0.1 - stands in for the internal
    host a rebind would land on."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address  # (host, port)
    finally:
        server.shutdown()
        server.server_close()


def test_pinned_session_refuses_a_loopback_peer(loopback_server):
    """The core proof: a session pointed directly at 127.0.0.1 - which is
    what a successful DNS rebind produces at connect time - is blocked at
    the socket, and the internal service's body is never returned."""
    host, port = loopback_server
    session = _mk_session()
    with pytest.raises(requests.exceptions.ConnectionError) as exc:
        session.get(f"http://{host}:{port}/", timeout=5)
    # It is specifically our guard, not a coincidental network error.
    assert isinstance(exc.value, _SSRFBlocked) or "blocked address" in str(exc.value)


def test_blocked_before_any_body_is_read(loopback_server):
    """Belt-and-braces: even catching broadly, we never see the server's
    response content - the block happens before request bytes are sent."""
    host, port = loopback_server
    session = _mk_session()
    try:
        resp = session.get(f"http://{host}:{port}/", timeout=5)
    except requests.exceptions.ConnectionError:
        return  # blocked as intended
    pytest.fail(f"loopback peer was NOT blocked; got {resp.status_code}: {resp.text!r}")


# --------------------------------------------------------------------------
# _assert_peer_ip_safe unit-level, with a fake socket (no network)
# --------------------------------------------------------------------------


class _FakeSock:
    def __init__(self, peer_ip):
        self._peer = peer_ip
        self.closed = False

    def getpeername(self):
        if self._peer is None:
            raise OSError("not connected")
        return (self._peer, 443)

    def close(self):
        self.closed = True


@pytest.mark.parametrize(
    "ip",
    ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "0.0.0.0"],
)
def test_assert_peer_ip_safe_rejects_and_closes_unsafe(ip):
    sock = _FakeSock(ip)
    with pytest.raises(_SSRFBlocked):
        _assert_peer_ip_safe(sock)
    assert sock.closed, "an unsafe socket must be closed, not leaked"


@pytest.mark.parametrize("ip", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])
def test_assert_peer_ip_safe_allows_public(ip):
    sock = _FakeSock(ip)
    _assert_peer_ip_safe(sock)  # no raise
    assert not sock.closed


def test_assert_peer_ip_safe_fails_closed_on_unknowable_peer():
    sock = _FakeSock(None)  # getpeername raises
    with pytest.raises(_SSRFBlocked):
        _assert_peer_ip_safe(sock)
    assert sock.closed


def test_is_unsafe_ip_matches_the_address_classes():
    for bad in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "224.0.0.1", "0.0.0.0"]:
        assert is_unsafe_ip(ipaddress.ip_address(bad)), bad
    for good in ["93.184.216.34", "8.8.8.8"]:
        assert not is_unsafe_ip(ipaddress.ip_address(good)), good
