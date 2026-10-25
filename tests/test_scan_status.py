"""
Tests for `GET /scan/<id>/status` (glassbox/scan_routes.py) - the
polling counterpart to `scan_events()`'s SSE feed for scan types that emit
no `ScanEvent` rows (advanced/media/api), plus the `scan_progress.html`
rendering assertions for the transport branch it feeds (SCANUX-05, D-04 -
see .planning/phases/05-new-scan-flow-redesign/05-CONTEXT.md).

Ownership scoping mirrors tests/test_scan_ownership.py's convention:
integration tests through the real routes/login flow, since `_check_ownership`
reads the context-local `flask_login.current_user` proxy.
"""
from datetime import datetime, timezone

import pytest

from glassbox.extensions import db as _db
from glassbox.models import Plan, Report, Role, ScanStatus

from tests.conftest import login, make_org, make_scan, make_user


def _add_report(scan):
    r = Report(scan_id=scan.id, json_path="reports/fake.json", data={"score": 90})
    _db.session.add(r)
    _db.session.flush()
    return r


# --------------------------------------------------------------------------
# Task 1 - GET /scan/<id>/status
# --------------------------------------------------------------------------

def test_status_queued_scan(client, db):
    org = make_org()
    user = make_user("s1@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.QUEUED)
    login(client, "s1@example.com")
    resp = client.get(f"/scan/{scan.id}/status")
    assert resp.status_code == 200
    assert resp.content_type.startswith("application/json")
    assert resp.get_json() == {"status": "queued", "report_url": None}


def test_status_running_scan(client, db):
    org = make_org()
    user = make_user("s2@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.RUNNING)
    login(client, "s2@example.com")
    resp = client.get(f"/scan/{scan.id}/status")
    assert resp.get_json() == {"status": "running", "report_url": None}


def test_status_failed_scan_no_report_url(client, db):
    org = make_org()
    user = make_user("s3@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.FAILED)
    login(client, "s3@example.com")
    resp = client.get(f"/scan/{scan.id}/status")
    assert resp.get_json() == {"status": "failed", "report_url": None}


def test_status_completed_with_report_row(client, db):
    org = make_org()
    user = make_user("s4@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    _add_report(scan)
    login(client, "s4@example.com")
    resp = client.get(f"/scan/{scan.id}/status")
    payload = resp.get_json()
    assert payload["status"] == "completed"
    assert payload["report_url"] == f"/scan/{scan.id}/report"


def test_status_completed_without_report_row(client, db):
    org = make_org()
    user = make_user("s5@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    login(client, "s5@example.com")
    resp = client.get(f"/scan/{scan.id}/status")
    assert resp.get_json() == {"status": "completed", "report_url": None}


def test_status_failed_scan_never_leaks_error_message(client, db):
    org = make_org()
    user = make_user("s6@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.FAILED)
    scan.error_message = "boom-secret-internal-detail"
    _db.session.flush()
    login(client, "s6@example.com")
    resp = client.get(f"/scan/{scan.id}/status")
    assert b"boom-secret-internal-detail" not in resp.data


def test_status_different_org_gets_404(client, db):
    org1 = make_org(name="Org One")
    org2 = make_org(name="Org Two")
    owner = make_user("owner@org1.com", org=org1)
    rival = make_user("rival@org2.com", org=org2)
    scan = make_scan(owner, org=org1, status=ScanStatus.RUNNING)
    login(client, "rival@org2.com")
    resp = client.get(f"/scan/{scan.id}/status")
    assert resp.status_code == 404


def test_status_same_org_member_gets_404(client, db):
    org = make_org()
    owner = make_user("owner2@example.com", org=org)
    colleague = make_user("colleague2@example.com", org=org, role=Role.MEMBER)
    scan = make_scan(owner, org=org, status=ScanStatus.RUNNING)
    login(client, "colleague2@example.com")
    resp = client.get(f"/scan/{scan.id}/status")
    assert resp.status_code == 404


def test_status_org_admin_gets_200(client, db):
    org = make_org()
    owner = make_user("owner3@example.com", org=org)
    admin = make_user("admin3@example.com", org=org, role=Role.ORG_ADMIN)
    scan = make_scan(owner, org=org, status=ScanStatus.RUNNING)
    login(client, "admin3@example.com")
    resp = client.get(f"/scan/{scan.id}/status")
    assert resp.status_code == 200


def test_status_anonymous_redirects_to_login(client, db):
    org = make_org()
    user = make_user("s7@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.RUNNING)
    resp = client.get(f"/scan/{scan.id}/status", follow_redirects=False)
    assert resp.status_code == 302


def test_status_nonexistent_scan_404(client, db):
    org = make_org()
    make_user("s8@example.com", org=org)
    login(client, "s8@example.com")
    resp = client.get("/scan/999999/status")
    assert resp.status_code == 404


# --------------------------------------------------------------------------
# Task 2 - View Report control and transport branch on scan_progress.html
# --------------------------------------------------------------------------

def test_progress_page_base_running_uses_sse(client, db):
    org = make_org()
    user = make_user("p1@example.com", org=org)
    scan = make_scan(user, org=org, scan_type="base", status=ScanStatus.RUNNING)
    login(client, "p1@example.com")
    resp = client.get(f"/scan/{scan.id}")
    body = resp.data.decode()
    assert resp.status_code == 200
    assert "new EventSource" in body
    assert '/events' in body
    assert 'id="viewReportBtn"' in body
    assert "Initializing investigation" in body


def test_progress_page_media_running_uses_polling_not_sse(client, db):
    org = make_org(plan=Plan.PAID)
    user = make_user("p2@example.com", org=org)
    scan = make_scan(user, org=org, scan_type="media", status=ScanStatus.RUNNING)
    login(client, "p2@example.com")
    resp = client.get(f"/scan/{scan.id}")
    body = resp.data.decode()
    assert resp.status_code == 200
    assert "/status" in body
    assert "new EventSource" not in body
    assert "This scan type reports status only" in body
    assert 'id="viewReportBtn"' in body


def test_progress_page_failed_media_shows_error_box(client, db):
    org = make_org()
    user = make_user("p3@example.com", org=org)
    scan = make_scan(user, org=org, scan_type="media", status=ScanStatus.FAILED)
    scan.error_message = "media scan blew up"
    _db.session.flush()
    login(client, "p3@example.com")
    resp = client.get(f"/scan/{scan.id}")
    body = resp.data.decode()
    assert "Scan failed:" in body
    assert "media scan blew up" in body


def test_progress_page_reveal_view_report_base_appears_twice(client, db):
    """Base's SSE branch renders `function revealViewReport()`'s definition
    plus its own call in the completion handler - the poll branch's call
    is Jinja-excluded from a base-type render entirely."""
    org = make_org()
    user = make_user("p4@example.com", org=org)
    scan = make_scan(user, org=org, scan_type="base", status=ScanStatus.RUNNING)
    login(client, "p4@example.com")
    resp = client.get(f"/scan/{scan.id}")
    body = resp.data.decode()
    assert body.count("revealViewReport") == 2


def test_progress_page_reveal_view_report_non_base_appears_twice(client, db):
    org = make_org()
    user = make_user("p4b@example.com", org=org)
    scan = make_scan(user, org=org, scan_type="api", status=ScanStatus.RUNNING)
    login(client, "p4b@example.com")
    resp = client.get(f"/scan/{scan.id}")
    body = resp.data.decode()
    assert body.count("revealViewReport") == 2


def test_progress_page_reveal_view_report_defined_and_called_in_both_transports(client, db):
    """Across the whole template source (not one render), revealViewReport
    appears exactly 3 times - the definition plus one call site per
    transport branch (SSE and poll) - matching the plan's acceptance
    criteria that neither branch was left un-wired."""
    with open("templates/scan_progress.html", encoding="utf-8") as f:
        source = f.read()
    assert source.count("revealViewReport") == 3


def test_progress_page_is_base_flag_present_multiple_times_in_source(client, db):
    with open("templates/scan_progress.html", encoding="utf-8") as f:
        source = f.read()
    assert source.count("isBase") >= 4
