"""Coverage for the read-only, scan-history-derived features added to the
sensitive-path report section: lifecycle status (NEW/ACTIVE/REOPENED) via
scan_routes._sensitive_path_lifecycle(), the "Compare with previous scan"
link via scan_routes._previous_completed_scan(), and the "Re-scan website"
link - plus a full render of /scan/<id>/report to confirm the masked-by-
default secret evidence and reveal control show up with no template errors.

Builds real Report rows/JSON files (same on-disk shape run_scan() produces)
against a tiny local http.server, matching the pattern already used in
tests/test_sensitive_paths.py, rather than hand-authoring a mock report
dict - a hand-rolled dict risks drifting from the real report shape and
missing template fields the real orchestrator always includes.
"""
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from glassbox.checks import REPORTS_DIR
from glassbox.entitlements import Tier
from glassbox.extensions import db as _db
from glassbox.models import Report, Scan, ScanStatus
from glassbox import scan_engine

from tests.conftest import login, make_org, make_scan, make_user


class _TargetHandler(BaseHTTPRequestHandler):
    """A .env-exposing target - every scan of it confirms the same finding,
    which is what lets consecutive scans exercise the NEW -> ACTIVE
    lifecycle transition."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        path = self.path.lstrip("/")
        if path == ".env":
            body = b"DB_PASSWORD=hunter2\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"<html><title>Target Site</title><body>home</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def target_server():
    server = HTTPServer(("127.0.0.1", 0), _TargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    thread.join(timeout=2)


def _stub_slow_checks(monkeypatch):
    """check_sensitive_paths (what these tests are actually exercising) and
    check_headers/check_cookies stay real; everything else in run_scan()'s
    jobs dict - plus check_open_ports, which does its own per-port socket
    connects - is stubbed to a fast no-op. Without this, each run_scan()
    call spends most of its time on check_tls_cert attempting a real TLS
    handshake against a plain-HTTP test server (an 8s timeout) and
    check_open_ports scanning ~20 ports, neither of which this test file
    cares about. Same technique as test_scan_events.py's _stub_all_checks."""
    for name in ("check_tls_cert", "check_https_redirect", "check_robots_sitemap",
                 "check_cors", "check_http_methods", "check_open_redirect",
                 "check_directory_listing", "check_mixed_content", "check_dns_email_security",
                 "check_vulnerable_js", "check_xss_sqli", "check_exposed_secrets", "check_sri"):
        monkeypatch.setattr(scan_engine, name, lambda *a, **k: ({}, []))
    monkeypatch.setattr(scan_engine, "check_open_ports", lambda *a, **k: ([], "127.0.0.1", []))


def _write_report_row(scan_row, base_url, monkeypatch):
    """Runs the real scan_engine.run_scan() (with slow/irrelevant checks
    stubbed - see _stub_slow_checks) against the live test target and
    persists it exactly like _run_scan_in_background does, so the resulting
    Report/JSON is the genuine shape scan_report.html expects. Returns the
    written filename for cleanup."""
    _stub_slow_checks(monkeypatch)
    report = scan_engine.run_scan(base_url, None, Tier.PAID, False)
    fname = scan_engine.save_report(report, "", f"test-history-{scan_row.id}")
    row = Report(scan_id=scan_row.id, json_path=fname)
    _db.session.add(row)
    _db.session.flush()
    return fname


@pytest.fixture()
def two_scans(db, target_server, monkeypatch):
    org = make_org(name="History Org")
    owner = make_user("owner@history.com", org=org)

    older = make_scan(owner, org=org, target_url=target_server, status=ScanStatus.COMPLETED)
    older.created_at = datetime.now(timezone.utc) - timedelta(days=3)
    newer = make_scan(owner, org=org, target_url=target_server, status=ScanStatus.COMPLETED)
    newer.created_at = datetime.now(timezone.utc)
    _db.session.flush()

    fname_older = _write_report_row(older, target_server, monkeypatch)
    fname_newer = _write_report_row(newer, target_server, monkeypatch)

    yield {"owner": owner, "older": older, "newer": newer}

    for fname in (fname_older, fname_newer):
        path = os.path.join(REPORTS_DIR, fname)
        if os.path.exists(path):
            os.remove(path)


def test_repeat_confirmed_finding_is_active_with_correct_first_detected(client, two_scans):
    login(client, "owner@history.com")
    resp = client.get(f"/scan/{two_scans['newer'].id}/report")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    assert "sp-lifecycle-active" in html
    assert "ACTIVE" in html
    assert "still unresolved" in html
    # first_detected should reflect the OLDER scan's date, not the newer one.
    expected_date = two_scans["older"].created_at.strftime("%b %d, %Y")
    assert expected_date in html


def test_first_ever_scan_confirmed_finding_is_new(client, two_scans):
    login(client, "owner@history.com")
    resp = client.get(f"/scan/{two_scans['older'].id}/report")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "sp-lifecycle-new" in html
    assert "NEW" in html


def test_compare_with_previous_scan_link_present_on_second_scan(client, two_scans):
    login(client, "owner@history.com")
    resp = client.get(f"/scan/{two_scans['newer'].id}/report")
    html = resp.get_data(as_text=True)
    assert f"/scan/{two_scans['older'].id}/compare/{two_scans['newer'].id}" in html
    assert "Compare with previous scan" in html


def test_compare_link_absent_on_first_scan(client, two_scans):
    login(client, "owner@history.com")
    resp = client.get(f"/scan/{two_scans['older'].id}/report")
    html = resp.get_data(as_text=True)
    assert "Compare with previous scan" not in html


def test_rescan_link_present_and_points_at_new_scan_base_with_target(client, two_scans):
    login(client, "owner@history.com")
    resp = client.get(f"/scan/{two_scans['newer'].id}/report")
    html = resp.get_data(as_text=True)
    assert "Re-scan website" in html
    assert "/scan/new/base?target=" in html


def test_confirmed_secret_is_masked_by_default_and_raw_present_for_reveal(client, two_scans):
    """The masked value renders visibly; the raw value is present in the
    page (so the existing page-level auth/ownership check is what gates
    it - see wvsToggleSecret()'s docstring) but marked `hidden` so it does
    not display by default."""
    login(client, "owner@history.com")
    resp = client.get(f"/scan/{two_scans['newer'].id}/report")
    html = resp.get_data(as_text=True)
    assert "sp-secret-masked" in html
    assert "sp-secret-raw" in html
    assert "wvsToggleSecret" in html
    assert 'hidden' in html  # the raw <code> starts hidden
    assert "hunter2" in html  # present for the authorized owner to reveal...
    assert "Reveal" in html   # ...but behind this control by default


def test_stranger_cannot_reach_the_report_at_all(client, two_scans):
    """Ownership gating is untouched: someone who isn't the owner (or their
    org admin) still gets a flat 404, same as before this feature - the
    secret value is only ever reachable through that same existing check."""
    make_org(name="Other Org")
    make_user("stranger@other.com", org=None)
    login(client, "stranger@other.com")
    resp = client.get(f"/scan/{two_scans['newer'].id}/report")
    assert resp.status_code == 404
