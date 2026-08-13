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
