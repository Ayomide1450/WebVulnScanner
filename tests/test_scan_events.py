"""
Tests for the live scan-progress feed added in Phase 1 of the redesign:
webvulnscanner.models.ScanEvent, checks.CHECK_LABELS, run_scan()'s enriched
progress_cb contract, _run_scan_in_background's ScanEvent-writing closure,
and scan_routes._serialize_new_events().

Per the SSE-testing constraint already established in
tests/test_scan_ownership.py, the live generator body in scan_events() is
never consumed here either - only its pre-stream ownership guard, and the
data-layer functions it reads from.

Network calls are avoided by stubbing every check_* function scan_engine.py
imports (via monkeypatch on the scan_engine module's own namespace - each
is a `from webvulnscanner.checks import check_x` binding, so patching
scan_engine.check_x is what actually intercepts run_scan()'s calls) and by
stubbing _mk_session so the initial home-page fetch never hits the network
either - matching handoff.md's documented rule to mock network calls rather
than trigger a real scan in a test script.
"""
from types import SimpleNamespace

from webvulnscanner import scan_engine
from webvulnscanner.checks import CHECK_LABELS
from webvulnscanner.entitlements import Tier
from webvulnscanner.models import Role, Scan, ScanEvent, ScanEventPhase, ScanStatus

from tests.conftest import login, make_org, make_scan, make_user

FREE_TIER_JOBS = {
    "tls", "https_redirect", "sensitive_paths", "robots_sitemap",
    "mixed_content", "dns_email", "vulnerable_js", "secrets", "sri", "jwt",
    # v1.3 Phase 14 net-new checks - all FREE tier (passive/read-only)
    "file_upload", "privacy_exposure", "caching_sensitive",
}


# --------------------------------------------------------------------------
# ScanEvent model
# --------------------------------------------------------------------------

def test_scan_event_round_trips(db):
    from webvulnscanner.extensions import db as _db

    user = make_user("owner@example.com")
    scan = make_scan(user)
    ev = ScanEvent(scan_id=scan.id, check_name="tls", phase=ScanEventPhase.STARTED, detail="foo",
                    finding_count=2, top_severity="high")
    _db.session.add(ev)
    _db.session.flush()

    fetched = ScanEvent.query.get(ev.id)
    assert fetched.check_name == "tls"
    assert fetched.phase == ScanEventPhase.STARTED
    assert fetched.detail == "foo"
    assert fetched.finding_count == 2
    assert fetched.top_severity == "high"
    assert fetched.scan_id == scan.id
    assert fetched.scan.id == scan.id


# --------------------------------------------------------------------------
# CHECK_LABELS completeness - mirrors entitlements.py's own
# FEATURE_REQUIREMENTS-coverage regression test.
# --------------------------------------------------------------------------

def test_check_labels_covers_every_run_scan_job_name():
    import re
    from pathlib import Path

    src = Path(scan_engine.__file__).read_text(encoding="utf-8")
    start = src.index("jobs = {")
    end = src.index("\n    }", start)
    job_names = set(re.findall(r'"(\w+)":\s*lambda', src[start:end]))
    job_names |= {"headers", "cookies", "open_ports"}

    missing = job_names - set(CHECK_LABELS)
    assert not missing, f"CHECK_LABELS is missing entries for {missing} - live feed would title-case fallback"


def test_check_category_covers_every_check_label():
    # CHECK_CATEGORY drives the live feed's icon (see _serialize_new_events's
    # icon-key fallback to "shield") - keep it in sync with CHECK_LABELS's
    # key set the same way CHECK_LABELS itself is kept in sync with
    # run_scan()'s dispatchable check names above.
    from webvulnscanner.checks import CHECK_CATEGORY

    missing = set(CHECK_LABELS) - set(CHECK_CATEGORY)
    assert not missing, f"CHECK_CATEGORY is missing entries for {missing} - live feed would fall back to 'shield'"


# --------------------------------------------------------------------------
# run_scan()'s progress_cb call sequence
# --------------------------------------------------------------------------

def _stub_all_checks(monkeypatch):
    """Replaces every check_* function run_scan() can call with a fast,
    network-free stub, and replaces _mk_session so the initial home-page
    fetch doesn't hit the network either."""
    plain_stub_names = [
        "check_cookies", "check_tls_cert", "check_https_redirect",
        "check_sensitive_paths", "check_robots_sitemap", "check_cors", "check_http_methods",
        "check_open_redirect", "check_directory_listing", "check_mixed_content",
        "check_dns_email_security", "check_vulnerable_js", "check_xss_sqli",
        "check_exposed_secrets", "check_sri", "check_jwt_weakness",
        "check_file_upload", "check_privacy_exposure", "check_caching_sensitive_data",
        # Phase 20 (INTR-01..10)
        "check_ssti", "check_host_header", "check_cache_deception", "check_crlf_injection",
        "check_csrf_posture", "check_subdomain_takeover", "check_path_traversal",
        "check_rate_limit_posture", "check_jwt_active", "check_graphql_deep",
    ]
    for name in plain_stub_names:
        monkeypatch.setattr(scan_engine, name, lambda *a, **k: ({}, []))
    monkeypatch.setattr(scan_engine, "check_headers", lambda *a, **k: ({"grade": "A"}, []))
    monkeypatch.setattr(scan_engine, "check_open_ports", lambda *a, **k: ([], "1.2.3.4", []))

    fake_session = SimpleNamespace(get=lambda *a, **k: SimpleNamespace(text="<html></html>"))
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: fake_session)


def test_run_scan_progress_cb_sequence_free_tier(monkeypatch):
    _stub_all_checks(monkeypatch)
    calls = []

    def progress_cb(name, phase, done, total, detail=None, finding_count=None, top_severity=None):
        calls.append((name, phase, done, total, detail))

    scan_engine.run_scan("https://example.com", None, Tier.FREE, False, progress_cb=progress_cb)

    names_in_order = [c[0] for c in calls]
    # headers/cookies complete before any job's "started" call.
    assert names_in_order[0] == "headers"
    assert names_in_order[1] == "cookies"
    assert calls[0][1] == "completed"
    assert calls[0][4] == "grade A"
    assert calls[1][1] == "completed"

    # Every FREE-tier job gets exactly one "started" and one "completed".
    for job in FREE_TIER_JOBS:
        phases = [c[1] for c in calls if c[0] == job]
        assert phases.count("started") == 1, job
        assert phases.count("completed") == 1, job

    # A PAID/ORG_VERIFIED-tier job locked at FREE never gets an event at all.
    assert not any(c[0] == "cors" for c in calls)
    assert not any(c[0] == "xss_sqli" for c in calls)

    # open_ports is locked at FREE tier - phase=None (counter bump only, no
    # fabricated ScanEvent), not "completed".
    open_ports_calls = [c for c in calls if c[0] == "open_ports"]
    assert len(open_ports_calls) == 1
    assert open_ports_calls[0][1] is None

    # Final total == len(allowed jobs) + 3 (headers/cookies/open_ports), and
    # done reaches total by the last call.
    assert calls[-1][3] == len(FREE_TIER_JOBS) + 3
    assert calls[-1][2] == calls[-1][3]


def test_run_scan_progress_cb_open_ports_completed_when_allowed(monkeypatch):
    _stub_all_checks(monkeypatch)
    calls = []

    def progress_cb(name, phase, done, total, detail=None, finding_count=None, top_severity=None):
        calls.append((name, phase))

    scan_engine.run_scan("https://example.com", None, Tier.PAID, False, progress_cb=progress_cb)

    assert [c for c in calls if c[0] == "open_ports"] == [("open_ports", "completed")]


def test_run_scan_progress_cb_reports_failed_check(monkeypatch):
    _stub_all_checks(monkeypatch)

    def _boom(*a, **k):
        raise ValueError("simulated check failure")
    monkeypatch.setattr(scan_engine, "check_tls_cert", _boom)

    calls = []

    def progress_cb(name, phase, done, total, detail=None, finding_count=None, top_severity=None):
        calls.append((name, phase, detail))

    scan_engine.run_scan("https://example.com", None, Tier.FREE, False, progress_cb=progress_cb)

    tls_calls = [c for c in calls if c[0] == "tls"]
    assert ("tls", "started", None) in tls_calls
    failed = [c for c in tls_calls if c[1] == "failed"]
    assert len(failed) == 1
    assert "simulated check failure" in failed[0][2]


def test_run_scan_progress_cb_reports_finding_count_and_top_severity(monkeypatch):
    from webvulnscanner.checks import Finding

    _stub_all_checks(monkeypatch)
    # tls "completes" with two real findings (high + low) - top_severity
    # must be the more severe of the two, not just the first/last one.
    monkeypatch.setattr(scan_engine, "check_tls_cert", lambda *a, **k: ({}, [
        Finding("TLS", "Weak cipher suite", "low", "detail", "fix"),
        Finding("TLS", "Expired intermediate", "high", "detail", "fix"),
    ]))

    calls = []

    def progress_cb(name, phase, done, total, detail=None, finding_count=None, top_severity=None):
        calls.append((name, phase, finding_count, top_severity))

    scan_engine.run_scan("https://example.com", None, Tier.FREE, False, progress_cb=progress_cb)

    tls_completed = [c for c in calls if c[0] == "tls" and c[1] == "completed"]
    assert tls_completed == [("tls", "completed", 2, "high")]

    tls_started = [c for c in calls if c[0] == "tls" and c[1] == "started"]
    assert tls_started == [("tls", "started", None, None)]  # not known yet at start

    # A check that completes with zero findings reports finding_count=0,
    # top_severity=None (not "no data" - a real, meaningful zero).
    cookies_completed = [c for c in calls if c[0] == "cookies"]
    assert cookies_completed == [("cookies", "completed", 0, None)]


def test_run_scan_without_progress_cb_still_works(monkeypatch):
    # progress_cb is optional (default None) - unrelated call sites (or a
    # future scan type) must not break just because this signature grew.
    _stub_all_checks(monkeypatch)
    report = scan_engine.run_scan("https://example.com", None, Tier.FREE, False)
    assert report["score"] <= 100


# --------------------------------------------------------------------------
# _run_scan_in_background's progress_cb closure persists ScanEvent rows
# --------------------------------------------------------------------------

def test_run_scan_in_background_persists_scan_events_and_progress(app, monkeypatch):
    # Deliberately does NOT use the `db` fixture here (which holds one app
    # context open for the whole test) - _run_scan_in_background pushes its
    # own nested `with app.app_context():` internally, and calling it while
    # an outer context/session is already held open causes its otherwise-
    # successfully-committed writes (confirmed via traced commits during
    # investigation: status genuinely reaches COMPLETED in the DB) to read
    # back as stale/reverted through that same outer session afterward.
    # This is a broader instance of the concurrency caveat handoff.md
    # already documents for real background threads - it turns out to
    # apply to calling this exact codepath synchronously too, not just via
    # threading.Thread. Using `app` directly with short-lived, non-
    # overlapping `with app.app_context():` blocks (matching how a real
    # request thread and a real scan thread never share one Python-level
    # context either) avoids it entirely.
    from webvulnscanner.extensions import db as _db
    from webvulnscanner.scan_routes import _run_scan_in_background

    _stub_all_checks(monkeypatch)
    with app.app_context():
        user = make_user("owner@example.com")
        scan = make_scan(user, target_url="https://example.com", scan_type="base", status=ScanStatus.QUEUED)
        _db.session.commit()
        scan_id = scan.id

    _run_scan_in_background(
        app, scan_id, "base",
        base_url="https://example.com", manual_test_url=None,
        tier=Tier.FREE, org_verified=False,
    )

    with app.app_context():
        updated = Scan.query.get(scan_id)
        assert updated.status == ScanStatus.COMPLETED
        assert updated.progress_current == updated.progress_total
        assert updated.progress_total == len(FREE_TIER_JOBS) + 3

        events = ScanEvent.query.filter_by(scan_id=scan_id).all()
        # 2 synchronous (headers/cookies) + FREE-tier jobs * 2 (started+completed).
        # open_ports contributes zero rows at FREE tier (phase=None).
        assert len(events) == 2 + len(FREE_TIER_JOBS) * 2
        assert not any(e.check_name == "open_ports" for e in events)
        assert all(e.phase in (ScanEventPhase.STARTED, ScanEventPhase.COMPLETED) for e in events)


# --------------------------------------------------------------------------
# scan_events() - pre-stream ownership guard only, never the generator body
# --------------------------------------------------------------------------

def test_scan_events_ownership_guard_applies_regardless_of_after_param(client, db):
    org1 = make_org(name="Org One")
    org2 = make_org(name="Org Two")
    owner = make_user("owner@example.com", org=org1)
    stranger = make_user("stranger@example.com", org=org2, role=Role.ORG_ADMIN)
    scan = make_scan(owner, org=org1)

    login(client, "stranger@example.com")
    resp = client.get(f"/scan/{scan.id}/events?after=999")
    assert resp.status_code == 404


# --------------------------------------------------------------------------
# _serialize_new_events()
# --------------------------------------------------------------------------

def test_serialize_new_events_returns_only_events_after_cursor(db):
    from webvulnscanner.extensions import db as _db
    from webvulnscanner.scan_routes import _serialize_new_events

    user = make_user("owner@example.com")
    scan = make_scan(user)
    e1 = ScanEvent(scan_id=scan.id, check_name="headers", phase=ScanEventPhase.COMPLETED, detail="grade B",
                    finding_count=3, top_severity="high")
    e2 = ScanEvent(scan_id=scan.id, check_name="tls", phase=ScanEventPhase.STARTED)
    e3 = ScanEvent(scan_id=scan.id, check_name="totally_unknown_check", phase=ScanEventPhase.COMPLETED,
                    finding_count=0)
    _db.session.add_all([e1, e2, e3])
    _db.session.flush()

    all_events = _serialize_new_events(scan.id, 0)
    assert [e["check_name"] for e in all_events] == ["headers", "tls", "totally_unknown_check"]
    assert all_events[0]["label"] == "Security headers"
    assert all_events[0]["detail"] == "grade B"
    assert all_events[0]["finding_count"] == 3
    assert all_events[0]["top_severity"] == "high"
    assert all_events[1]["phase"] == "started"
    assert all_events[1]["finding_count"] is None  # not known yet at "started"
    # Fallback label for a check_name absent from CHECK_LABELS - same
    # title-case fallback templates/scan_report.html's locked_card() uses.
    assert all_events[2]["label"] == "Totally Unknown Check"
    assert all_events[2]["finding_count"] == 0  # a real, meaningful zero, not "no data"

    after_first = _serialize_new_events(scan.id, all_events[0]["id"])
    assert [e["check_name"] for e in after_first] == ["tls", "totally_unknown_check"]

    after_last = _serialize_new_events(scan.id, all_events[-1]["id"])
    assert after_last == []


def test_serialize_new_events_scopes_to_the_given_scan(db):
    from webvulnscanner.extensions import db as _db
    from webvulnscanner.scan_routes import _serialize_new_events

    user = make_user("owner@example.com")
    scan_a = make_scan(user, target_url="https://a.example.com")
    scan_b = make_scan(user, target_url="https://b.example.com")
    _db.session.add(ScanEvent(scan_id=scan_a.id, check_name="tls", phase=ScanEventPhase.COMPLETED))
    _db.session.add(ScanEvent(scan_id=scan_b.id, check_name="tls", phase=ScanEventPhase.COMPLETED))
    _db.session.flush()

    events_a = _serialize_new_events(scan_a.id, 0)
    assert len(events_a) == 1
