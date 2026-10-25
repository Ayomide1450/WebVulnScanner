"""Tests for glassbox/scan_routes.py.

Originally covered only the dashboard() view (below), including its
"Recent Findings" section (a real report JSON on disk via _attach_report).
Now also owns HARD-02's Scan-row status-transition coverage for
_run_scan_in_background's media, api and advanced branches (04-04) - the
base branch's equivalent lives in tests/test_scan_events.py, where it was
written alongside the ScanEvent live-progress feed. The pure orchestrator
functions these branches call (run_media_scan/run_api_scan/
run_advanced_scan themselves) are covered at the function level in
tests/test_scan_engine.py (04-01); this module covers the DB-writing
wrapper around them instead: the Scan.status transitions, the per-scan-type
report-filename prefix, and the "never left stuck in RUNNING" failure
guarantee.
"""
import json
import os
from types import SimpleNamespace

from glassbox import scan_engine, scan_routes
from glassbox.checks import REPORTS_DIR
from glassbox.entitlements import Tier
from glassbox.extensions import db
from glassbox.models import Report, Scan, ScanStatus

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


# --------------------------------------------------------------------------
# HARD-02: _run_scan_in_background's Scan-row status transitions and
# failure handling for the media, api and advanced scan types (04-04).
#
# Deliberately does NOT use the shared `db` fixture (which holds one app
# context open for the whole test) - _run_scan_in_background pushes its own
# nested `with app.app_context():` internally, and calling it while an
# outer context/session is already held open causes its otherwise-
# successfully-committed writes to read back as stale/reverted through that
# same outer session afterward. See tests/test_scan_events.py's
# test_run_scan_in_background_persists_scan_events_and_progress for the
# full explanation of this hazard (04-RESEARCH.md Pitfall 3) - every test
# below follows that exact same short-lived-app-context shape instead.
#
# Every check function is stubbed on scan_engine's own module namespace
# (never on glassbox.checks - see test_scan_events.py's module
# docstring for why), and scan_routes.save_report is stubbed to a recorder
# so no JSON is ever written into the repository's report directory.
# --------------------------------------------------------------------------

def _stub_save_report(monkeypatch):
    """Replaces scan_routes.save_report with a recorder that returns a
    fixed filename - no file is ever written under REPORTS_DIR, and the
    per-scan-type filename prefix becomes an assertable value via the
    returned `calls` list."""
    calls = []

    def _fake_save_report(report, prefix, hostname):
        calls.append({"report": report, "prefix": prefix, "hostname": hostname})
        return "stubbed_report.json"

    monkeypatch.setattr(scan_routes, "save_report", _fake_save_report)
    return calls


def _stub_media_check(monkeypatch, findings=None):
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: SimpleNamespace())
    monkeypatch.setattr(
        scan_engine, "check_media",
        lambda session, base_url, download, max_files: ({"images": [], "videos": []}, findings or []),
    )


def _stub_api_checks(monkeypatch, wordlist_findings=None):
    fake_session = SimpleNamespace(get=lambda *a, **k: SimpleNamespace(text="<html></html>"))
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: fake_session)
    monkeypatch.setattr(scan_engine, "check_api_schema_exposure", lambda base_url, session: ({}, []))
    monkeypatch.setattr(
        scan_engine, "check_api_wordlist",
        lambda base_url, session: ({}, wordlist_findings or []),
    )
    monkeypatch.setattr(scan_engine, "check_api_js_discovery",
                         lambda session, base_url, home_html: ({}, []))


def _full_advanced_form():
    """Mirrors tests/test_scan_engine.py's _full_advanced_form - every
    field _parse_advanced_form (scan_routes.py) produces, all populated
    with obviously-fake example.com literals, so a run that's actually
    entitled exercises every one of the five check groups."""
    return {
        "login_url": "https://example.com/login",
        "user_field": "username",
        "pass_field": "password",
        "fail_text": "invalid credentials",
        "bruteforce_username": "testuser",
        "bruteforce_passwords": ["pw1", "pw2"],
        "sqli_union_url": "https://example.com/products?id=1",
        "sqli_union_param": "id",
        "stored_xss_submit_url": "https://example.com/comment",
        "stored_xss_field": "body",
        "stored_xss_view_url": "https://example.com/comments",
        "stored_xss_cookie": "session=fake-test-cookie-value",
        "idor_url_template": "https://example.com/orders/{id}",
        "idor_ids": ["1", "2"],
        "idor_cookie_a": "session=fake-account-a-cookie",
        "idor_cookie_b": "session=fake-account-b-cookie",
    }


def _stub_advanced_checks(monkeypatch):
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: SimpleNamespace())
    monkeypatch.setattr(scan_engine, "check_sqli_login", lambda *a, **k: ({}, []))
    monkeypatch.setattr(scan_engine, "check_bruteforce", lambda *a, **k: ({}, []))
    monkeypatch.setattr(scan_engine, "check_sqli_union", lambda *a, **k: ({}, []))
    monkeypatch.setattr(scan_engine, "check_xss_stored", lambda *a, **k: ({}, []))
    monkeypatch.setattr(scan_engine, "check_idor", lambda *a, **k: ({}, []))


# All three success-path tests below pass tier=Tier.FREE (below the Paid
# threshold that gates the AI-summary tail, scan_routes.py:174) so
# generate_remediation_summary is never reached and no Groq call is ever
# attempted - matching T-04-20's mitigation. tier has no effect on whether
# the (stubbed) checks run for media/api - route-level gating already
# happened before this wrapper is ever called in production, and neither
# orchestrator function takes a tier parameter at all.

def test_run_scan_in_background_media_completes_and_saves_report(app, monkeypatch):
    from glassbox.extensions import db as _db
    from glassbox.scan_routes import _run_scan_in_background

    _stub_media_check(monkeypatch)
    save_calls = _stub_save_report(monkeypatch)

    with app.app_context():
        user = make_user("media-owner@example.com")
        scan = make_scan(user, target_url="https://example.com", scan_type="media", status=ScanStatus.QUEUED)
        _db.session.commit()
        scan_id = scan.id

    _run_scan_in_background(
        app, scan_id, "media",
        base_url="https://example.com", download=False, max_files=20, tier=Tier.FREE,
    )

    with app.app_context():
        updated = Scan.query.get(scan_id)
        assert updated.status == ScanStatus.COMPLETED
        assert updated.completed_at is not None
        assert updated.risk_score == 100
        assert Report.query.filter_by(scan_id=scan_id).count() == 1

    assert len(save_calls) == 1
    assert save_calls[0]["prefix"] == "media_"


def test_run_scan_in_background_api_completes_and_saves_report(app, monkeypatch):
    from glassbox.extensions import db as _db
    from glassbox.scan_routes import _run_scan_in_background

    _stub_api_checks(monkeypatch)
    save_calls = _stub_save_report(monkeypatch)

    with app.app_context():
        user = make_user("api-owner@example.com")
        scan = make_scan(user, target_url="https://example.com", scan_type="api", status=ScanStatus.QUEUED)
        _db.session.commit()
        scan_id = scan.id

    _run_scan_in_background(app, scan_id, "api", base_url="https://example.com", tier=Tier.FREE)

    with app.app_context():
        updated = Scan.query.get(scan_id)
        assert updated.status == ScanStatus.COMPLETED
        assert updated.completed_at is not None
        assert updated.risk_score == 100
        assert Report.query.filter_by(scan_id=scan_id).count() == 1

    assert len(save_calls) == 1
    assert save_calls[0]["prefix"] == "api_"


def test_run_scan_in_background_advanced_completes_and_saves_report(app, monkeypatch):
    from glassbox.extensions import db as _db
    from glassbox.scan_routes import _run_scan_in_background

    _stub_advanced_checks(monkeypatch)
    save_calls = _stub_save_report(monkeypatch)

    with app.app_context():
        user = make_user("advanced-owner@example.com")
        scan = make_scan(user, target_url="https://example.com", scan_type="advanced", status=ScanStatus.QUEUED)
        _db.session.commit()
        scan_id = scan.id

    _run_scan_in_background(
        app, scan_id, "advanced",
        advanced=_full_advanced_form(), tier=Tier.FREE, org_verified=False,
    )

    with app.app_context():
        updated = Scan.query.get(scan_id)
        assert updated.status == ScanStatus.COMPLETED
        assert updated.completed_at is not None
        assert updated.risk_score is not None
        assert Report.query.filter_by(scan_id=scan_id).count() == 1

    assert len(save_calls) == 1
    assert save_calls[0]["prefix"] == "advanced_"


def test_run_scan_in_background_report_prefixes_all_differ():
    # The three prefixes asserted individually above must also all differ
    # from each other and from the base scan's empty prefix
    # (scan_routes.py:141/149/156/163) - a single assertion pinning that
    # relationship, rather than relying on the reader to notice it across
    # three separate tests.
    assert len({"", "advanced_", "media_", "api_"}) == 4


# --------------------------------------------------------------------------
# Failure handling: a stubbed check raising must leave the Scan row FAILED
# with the exception text in error_message, and create zero Report rows -
# the row must never be left stuck in RUNNING, which is the state
# scan_progress.html polls forever (scan_routes.py:186-190's broad except).
# --------------------------------------------------------------------------

def test_run_scan_in_background_media_failure_leaves_scan_failed(app, monkeypatch):
    from glassbox.extensions import db as _db
    from glassbox.scan_routes import _run_scan_in_background

    monkeypatch.setattr(scan_engine, "_mk_session", lambda: SimpleNamespace())

    def _boom(*a, **k):
        raise ValueError("simulated media check failure")

    monkeypatch.setattr(scan_engine, "check_media", _boom)
    _stub_save_report(monkeypatch)

    with app.app_context():
        user = make_user("media-fail@example.com")
        scan = make_scan(user, target_url="https://example.com", scan_type="media", status=ScanStatus.QUEUED)
        _db.session.commit()
        scan_id = scan.id

    _run_scan_in_background(
        app, scan_id, "media",
        base_url="https://example.com", download=False, max_files=20, tier=Tier.FREE,
    )

    with app.app_context():
        updated = Scan.query.get(scan_id)
        assert updated.status == ScanStatus.FAILED
        assert "simulated media check failure" in updated.error_message
        assert Report.query.filter_by(scan_id=scan_id).count() == 0


def test_run_scan_in_background_api_failure_leaves_scan_failed(app, monkeypatch):
    from glassbox.extensions import db as _db
    from glassbox.scan_routes import _run_scan_in_background

    fake_session = SimpleNamespace(get=lambda *a, **k: SimpleNamespace(text="<html></html>"))
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: fake_session)
    monkeypatch.setattr(scan_engine, "check_api_schema_exposure", lambda base_url, session: ({}, []))

    def _boom(*a, **k):
        raise ValueError("simulated api wordlist failure")

    monkeypatch.setattr(scan_engine, "check_api_wordlist", _boom)
    monkeypatch.setattr(scan_engine, "check_api_js_discovery", lambda session, base_url, home_html: ({}, []))
    _stub_save_report(monkeypatch)

    with app.app_context():
        user = make_user("api-fail@example.com")
        scan = make_scan(user, target_url="https://example.com", scan_type="api", status=ScanStatus.QUEUED)
        _db.session.commit()
        scan_id = scan.id

    _run_scan_in_background(app, scan_id, "api", base_url="https://example.com", tier=Tier.FREE)

    with app.app_context():
        updated = Scan.query.get(scan_id)
        assert updated.status == ScanStatus.FAILED
        assert "simulated api wordlist failure" in updated.error_message
        assert Report.query.filter_by(scan_id=scan_id).count() == 0


def test_run_scan_in_background_advanced_failure_leaves_scan_failed(app, monkeypatch):
    # Unlike the success-path advanced test above, this one must pass a tier
    # that actually clears the ORG_VERIFIED gate (with org_verified=True) so
    # the stubbed check group actually executes and can raise - a locked
    # group is never called at all, so a FREE-tier form here would silently
    # never reach the exception. This does NOT reach the AI-summary tail
    # despite tier >= Tier.PAID: run_advanced_scan raises before
    # _run_scan_in_background's try block ever gets to that line, so still
    # zero Groq calls (T-04-20).
    from glassbox.extensions import db as _db
    from glassbox.scan_routes import _run_scan_in_background

    monkeypatch.setattr(scan_engine, "_mk_session", lambda: SimpleNamespace())

    def _boom(*a, **k):
        raise ValueError("simulated sqli_login check failure")

    monkeypatch.setattr(scan_engine, "check_sqli_login", _boom)
    monkeypatch.setattr(scan_engine, "check_bruteforce", lambda *a, **k: ({}, []))
    monkeypatch.setattr(scan_engine, "check_sqli_union", lambda *a, **k: ({}, []))
    monkeypatch.setattr(scan_engine, "check_xss_stored", lambda *a, **k: ({}, []))
    monkeypatch.setattr(scan_engine, "check_idor", lambda *a, **k: ({}, []))
    _stub_save_report(monkeypatch)

    with app.app_context():
        user = make_user("advanced-fail@example.com")
        scan = make_scan(user, target_url="https://example.com", scan_type="advanced", status=ScanStatus.QUEUED)
        _db.session.commit()
        scan_id = scan.id

    _run_scan_in_background(
        app, scan_id, "advanced",
        advanced=_full_advanced_form(), tier=Tier.ORG_VERIFIED, org_verified=True,
    )

    with app.app_context():
        updated = Scan.query.get(scan_id)
        assert updated.status == ScanStatus.FAILED
        assert "simulated sqli_login check failure" in updated.error_message
        assert Report.query.filter_by(scan_id=scan_id).count() == 0


def test_run_scan_in_background_unknown_scan_type_lands_failed_not_raising(app):
    from glassbox.extensions import db as _db
    from glassbox.scan_routes import _run_scan_in_background

    with app.app_context():
        user = make_user("unknown-type@example.com")
        scan = make_scan(user, target_url="https://example.com", scan_type="not-a-scan-type",
                          status=ScanStatus.QUEUED)
        _db.session.commit()
        scan_id = scan.id

    # Must not raise out of the function - the broad except in
    # _run_scan_in_background catches the ValueError('unknown scan_type ...')
    # its own else-branch raises, same as any orchestrator exception.
    _run_scan_in_background(app, scan_id, "not-a-scan-type")

    with app.app_context():
        updated = Scan.query.get(scan_id)
        assert updated.status == ScanStatus.FAILED
        assert "unknown scan_type" in updated.error_message
        assert Report.query.filter_by(scan_id=scan_id).count() == 0


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
        assert "Recent Findings" in body or "Latest Scan" in body
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
        assert "No security issues found" in body or "No actionable vulnerabilities found" in body
    finally:
        os.remove(path)
