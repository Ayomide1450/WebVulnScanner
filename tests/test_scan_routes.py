"""Tests for webvulnscanner/scan_routes.py's dashboard() view."""
import json
import os

from webvulnscanner.checks import REPORTS_DIR
from webvulnscanner.extensions import db
from webvulnscanner.models import Report, ScanStatus
from tests.conftest import login, make_org, make_scan, make_user


def _attach_report(scan, findings, severity_counts):
    """Writes a real report JSON to REPORTS_DIR and links it via a Report
    row - same on-disk shape scan_engine.save_report() produces, so the
    dashboard's latest_report loading code path (scan_routes.dashboard())
    is exercised the same way it would be against a real completed scan."""
    filename = f"test-dashboard-{scan.id}.json"
    path = os.path.join(REPORTS_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"findings": findings, "severity_counts": severity_counts}, f)
    report = Report(scan_id=scan.id, json_path=filename)
    db.session.add(report)
    db.session.flush()
    return path


def test_dashboard_single_scored_scan_renders_flat_reference_line(client, db):
    """Regression test for the single-point sparkline bug: with exactly one
    scored scan, the SVG used to render one bare <circle> with no
    <polyline> at all (SVG polylines need >=2 points) - an unlabeled
    floating dot. It should now render a flat 2-point reference line plus a
    text label."""
    org = make_org()
    user = make_user("solo@example.com", org=org)
    scan = make_scan(user, org=org)
    scan.risk_score = 42
    db.session.commit()

    login(client, "solo@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    pad_l, pad_t, plot_w, plot_h = 34, 18, 540, 130
    y = round(pad_t + plot_h - (42 / 100 * plot_h), 1)
    assert f'<polyline points="{pad_l},{y} {pad_l + plot_w},{y}"' in body
    assert "only scan so far" in body


def test_dashboard_multiple_scored_scans_render_a_trend_polyline(client, db):
    org = make_org()
    user = make_user("trend@example.com", org=org)
    for score in (30, 70):
        s = make_scan(user, org=org)
        s.risk_score = score
    db.session.commit()

    login(client, "trend@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "only scan so far" not in body
    assert body.count("<circle cx=") >= 2


def test_dashboard_no_scored_scans_shows_not_enough_data_message(client, db):
    org = make_org()
    user = make_user("empty@example.com", org=org)
    make_scan(user, org=org)  # risk_score stays None (still queued)
    db.session.commit()

    login(client, "empty@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    assert "Not enough completed scans yet for a trend line." in resp.get_data(as_text=True)


def test_dashboard_scan_status_renders_as_a_pill(client, db):
    org = make_org()
    user = make_user("pill@example.com", org=org)
    make_scan(user, org=org)  # default status is ScanStatus.QUEUED
    db.session.commit()

    login(client, "pill@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    assert 'class="status-pill queued"' in resp.get_data(as_text=True)


def test_dashboard_renders_recent_findings_from_latest_report(client, db):
    org = make_org()
    user = make_user("findings@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    scan.risk_score = 97
    findings = [
        {"category": "headers", "title": "Missing Security Header",
         "severity": "low", "detail": "Security header is not configured correctly.",
         "recommendation": "Add the header.", "owasp_category": "A05"},
    ]
    path = _attach_report(scan, findings, {"critical": 0, "high": 0, "medium": 0, "low": 1})
    db.session.commit()
    try:
        login(client, "findings@example.com")
        resp = client.get("/dashboard")
        body = resp.get_data(as_text=True)

        assert resp.status_code == 200
        assert "Recent Findings" in body
        assert "Missing Security Header" in body
        assert "Security Score" in body
        assert "97" in body and "Grade A" in body
        assert "Low &mdash; 1" in body or "Low — 1" in body
    finally:
        os.remove(path)


def test_dashboard_recent_findings_empty_state_when_no_actionable_findings(client, db):
    org = make_org()
    user = make_user("clean@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    scan.risk_score = 100
    path = _attach_report(scan, [], {"critical": 0, "high": 0, "medium": 0, "low": 0})
    db.session.commit()
    try:
        login(client, "clean@example.com")
        resp = client.get("/dashboard")
        body = resp.get_data(as_text=True)

        assert resp.status_code == 200
        assert "No security issues found" in body
    finally:
        os.remove(path)
