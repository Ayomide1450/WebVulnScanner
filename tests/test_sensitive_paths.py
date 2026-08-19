"""Coverage for checks.check_sensitive_paths()'s evidence-based classification
(PASSED / INFORMATIONAL / NEEDS_REVIEW / CONFIRMED) - the rewrite that
replaced "200 = vulnerable, anything else = fine" with soft-404 baseline
comparison, 403 != exposure, and content-signature confirmation before a
result is ever reported as CONFIRMED.

Runs against a real local http.server (not a network mock) so the
soft-404 baseline comparison exercises actual response bytes/headers/
timing, matching how run_scan() calls this check in production.
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from webvulnscanner import checks
from webvulnscanner.checks import _mk_session, check_sensitive_paths


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence test output
        pass

    def do_GET(self):
        path = self.path.lstrip("/")

        # A real .env with recognizable KEY=value syntax -> CONFIRMED.
        if path == ".env":
            body = b"DB_PASSWORD=hunter2\nAPI_KEY=abc123\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)
            return

        # A real Git config -> CONFIRMED.
        if path == ".git/config":
            body = b"[core]\n\trepositoryformatversion = 0\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)
            return

        # Blocked by a WAF/access rule - must NOT be treated as confirmed.
        if path == ".aws/credentials":
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Forbidden")
            return

        # A real security.txt with a Contact field.
        if path == ".well-known/security.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Contact: mailto:security@example.com\n")
            return

        # Everything else, INCLUDING every other sensitive path AND the
        # randomly-generated soft-404 baseline probe, gets the exact same
        # "SPA shell" 200 response - simulates a site that never returns a
        # real 404. This is the scenario the soft-404 detector exists for.
        body = b"<html><title>My App</title><body>App shell</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def soft_404_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    thread.join(timeout=2)


def _row(data, path):
    return next(r for r in data["rows"] if r["path"] == path)


def test_confirmed_env_exposure(soft_404_server):
    data, findings = check_sensitive_paths(soft_404_server, _mk_session())
    row = _row(data, "/.env")
    assert row["classification"] == "confirmed"
    assert row["severity"] == "critical"
    assert row["confidence"] == "high"
    assert any("Confirmed exposure: /.env" in f.title for f in findings)


def test_confirmed_git_config_exposure(soft_404_server):
    data, _ = check_sensitive_paths(soft_404_server, _mk_session())
    row = _row(data, "/.git/config")
    assert row["classification"] == "confirmed"
    assert row["severity"] == "high"


def test_403_is_needs_review_not_confirmed(soft_404_server):
    data, findings = check_sensitive_paths(soft_404_server, _mk_session())
    row = _row(data, "/.aws/credentials")
    assert row["classification"] == "needs_review"
    assert row["confidence"] == "low"
    assert row["evidence"]["status"] == 403
    assert not any(f.severity == "critical" and "credentials" in f.title for f in findings)


def test_soft_404_paths_are_passed_not_confirmed(soft_404_server):
    """Every sensitive path this server doesn't special-case returns the
    same SPA-shell 200 as the random baseline probe - none of those should
    be reported as confirmed exposure just because the status was 200."""
    data, _ = check_sensitive_paths(soft_404_server, _mk_session())
    for row in data["rows"]:
        if row["path"] in ("/.env", "/.git/config", "/.aws/credentials",
                            "/.well-known/security.txt"):
            continue
        assert row["classification"] in ("passed", "informational"), (
            f"{row['path']} was classified {row['classification']!r}, expected a soft-404 "
            "match to keep it out of confirmed/needs_review"
        )


def test_security_txt_is_informational(soft_404_server):
    data, findings = check_sensitive_paths(soft_404_server, _mk_session())
    row = _row(data, "/.well-known/security.txt")
    assert row["classification"] == "informational"
    assert row["title"] == "Security contact policy found"
    # Presence of security.txt must never itself be reported as a Finding.
    assert not any("security.txt" in f.title and f.severity != "info" for f in findings)


def test_summary_counts_and_overall_status(soft_404_server):
    data, _ = check_sensitive_paths(soft_404_server, _mk_session())
    summary = data["summary"]
    assert summary["confirmed"] >= 2  # .env + .git/config
    assert summary["needs_review"] >= 1  # .aws/credentials (403)
    assert summary["total"] == len(data["rows"])
    assert summary["overall"] == "critical"  # a critical-severity confirmed exposure exists


def test_app_discovery_paths_never_produce_findings(soft_404_server):
    """api/health and the webpack chunk probe are Application Discovery,
    not Sensitive File Exposure - they must stay informational-only
    regardless of whether they respond, per the "don't report a missing
    /api/health as a vulnerability" requirement."""
    data, findings = check_sensitive_paths(soft_404_server, _mk_session())
    for path in ("/api/health", "/_next/static/chunks/webpack.js"):
        row = _row(data, path)
        assert row["classification"] == "informational"
    assert not any("api/health" in f.title or "webpack" in f.title for f in findings)


def test_secret_evidence_is_masked_by_default_with_raw_available(soft_404_server):
    """Confirmed findings must carry both a masked value (safe to show by
    default) and the raw matched fragment (reveal-gated in the UI, never in
    Finding.title/detail - see check_sensitive_paths' docstring)."""
    data, _ = check_sensitive_paths(soft_404_server, _mk_session())
    row = _row(data, "/.env")
    assert row["secret_evidence"] is not None
    assert row["secret_evidence"]["masked"] != row["secret_evidence"]["raw"]
    assert "…" in row["secret_evidence"]["masked"]  # the "…" redaction marker
    assert "DB_PASSWORD" in row["secret_evidence"]["raw"]
    # The raw value must never leak into a Finding (title/detail feed the
    # third-party AI-summary prompt - see ai_summary.py).
    _, findings = check_sensitive_paths(soft_404_server, _mk_session())
    env_findings = [f for f in findings if "/.env" in f.title]
    assert env_findings
    for f in env_findings:
        assert "hunter2" not in f.title
        assert "hunter2" not in f.detail


class _EdgeCaseHandler(BaseHTTPRequestHandler):
    """Covers the false-positive matrix from the task's testing checklist:
    redirects (301/302, including an auth-redirect-shaped one), rate
    limiting (429 + Retry-After), and upstream/server errors (502/503) -
    none of these may be classified CONFIRMED."""

    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.lstrip("/")

        if path == ".env":  # auth-redirect shape: 302 -> /login
            self._send(302, headers={"Location": "/login"})
            return
        if path == "login":
            self._send(200, b"<html><title>Login</title><body>Please sign in</body></html>")
            return

        if path == ".git/config":  # 301 -> an unrelated page
            self._send(301, headers={"Location": "/some-page"})
            return
        if path == "some-page":
            self._send(200, b"<html><title>Some Page</title><body>Nothing here</body></html>")
            return

        if path == "db.sql":  # rate limited
            self._send(429, b"Too Many Requests", headers={"Retry-After": "30"})
            return

        if path == "docker-compose.yml":  # upstream/gateway error
            self._send(502, b"Bad Gateway")
            return

        if path == "backup.zip":  # service unavailable
            self._send(503, b"Service Unavailable")
            return

        # Genuine 404 for everything else, including the random baseline probe.
        self._send(404, b"<html><title>Not Found</title></html>")


@pytest.fixture(scope="module")
def edge_case_server():
    server = HTTPServer(("127.0.0.1", 0), _EdgeCaseHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    thread.join(timeout=2)


def test_redirect_to_login_is_not_confirmed_exposure(edge_case_server, monkeypatch):
    """/.env -> 302 -> /login must NOT be classified as exposed, and the
    redirect chain must be recorded as evidence.

    Monkeypatches is_ssrf_safe_hostname() for the duration of this test:
    SEC-03's _mk_session() guard (08-04) re-validates every redirect hop's
    hostname, and this fixture's relative Location resolves to the same
    loopback host edge_case_server itself binds to - correctly classified
    unsafe outside tests, which would otherwise stop the chain before it's
    followed. This test is about redirect-chain evidence capture in
    check_sensitive_paths(), not SSRF classification (that's
    tests/test_ssrf_guard.py's job), so the guard is bypassed here rather
    than routed through a real public target."""
    monkeypatch.setattr(checks, "is_ssrf_safe_hostname", lambda hostname: True)
    data, _ = check_sensitive_paths(edge_case_server, _mk_session())
    row = _row(data, "/.env")
    assert row["classification"] != "confirmed"
    assert row["evidence"]["initial_status"] == 302
    assert row["evidence"]["redirect_chain"]
    assert row["evidence"]["status"] == 200  # final, post-redirect status


def test_redirect_to_unrelated_page_is_not_confirmed_exposure(edge_case_server, monkeypatch):
    """/.git/config -> 301 -> /some-page must NOT be automatically
    classified as exposed, and the redirect must be recorded as evidence.

    See test_redirect_to_login_is_not_confirmed_exposure's docstring above
    for why is_ssrf_safe_hostname() is monkeypatched here."""
    monkeypatch.setattr(checks, "is_ssrf_safe_hostname", lambda hostname: True)
    data, _ = check_sensitive_paths(edge_case_server, _mk_session())
    row = _row(data, "/.git/config")
    assert row["classification"] != "confirmed"
    assert row["evidence"]["initial_status"] == 301
    assert row["evidence"]["redirect_chain"]


def test_rate_limited_path_is_needs_review_not_passed_or_confirmed(edge_case_server):
    data, _ = check_sensitive_paths(edge_case_server, _mk_session())
    row = _row(data, "/db.sql")
    assert row["classification"] == "needs_review"
    assert row["classification"] != "confirmed"
    assert row["evidence"]["status"] == 429
    assert row["evidence"]["retry_after"] == "30"


def test_bad_gateway_is_needs_review_not_confirmed(edge_case_server):
    data, _ = check_sensitive_paths(edge_case_server, _mk_session())
    row = _row(data, "/docker-compose.yml")
    assert row["classification"] == "needs_review"
    assert row["evidence"]["status"] == 502


def test_service_unavailable_is_needs_review_not_confirmed(edge_case_server):
    data, _ = check_sensitive_paths(edge_case_server, _mk_session())
    row = _row(data, "/backup.zip")
    assert row["classification"] == "needs_review"
    assert row["evidence"]["status"] == 503


def test_genuine_404_is_passed_high_confidence(edge_case_server):
    data, _ = check_sensitive_paths(edge_case_server, _mk_session())
    row = _row(data, "/config.json")
    assert row["classification"] == "passed"
    assert row["confidence"] == "high"
    assert row["evidence"]["status"] == 404


class _SpaFallbackHandler(BaseHTTPRequestHandler):
    """Dedicated Next.js/SPA-fallback scenario: /.env returns HTTP 200 with
    the exact same application shell as a random nonexistent URL - the
    scanner must recognize this as a soft/fallback response, not treat the
    200 as evidence that .env exists."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"<html><title>My Next App</title><body><div id=\"__next\">App Shell</div></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def spa_fallback_server():
    server = HTTPServer(("127.0.0.1", 0), _SpaFallbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    thread.join(timeout=2)


def test_spa_fallback_env_is_not_confirmed_exposure(spa_fallback_server):
    data, findings = check_sensitive_paths(spa_fallback_server, _mk_session())
    row = _row(data, "/.env")
    assert row["classification"] == "passed"
    assert row["classification"] != "confirmed"
    assert not any("/.env" in f.title and f.severity == "critical" for f in findings)
