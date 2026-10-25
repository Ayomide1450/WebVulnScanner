"""Phase 21 (ST-01..06): the built-in detection self-test engine.

These tests run the REAL loopback lure server and the REAL check functions
inside pytest - no mocking of the layer under test. They lock both halves of
the matrix (five planted detections fire, five clean surfaces stay silent),
the listener's loopback-only binding and teardown, and the no-scan-row
contract.

2026-08-24 surface redesign (user direction): there is no standalone
/selftest route or page anymore - the engine feeds `run_scan()`'s report
directly (`report["detection_verified"]`, rendered by scan_report.html as an
"Engine verified" badge). The former route tests are gone with the route;
in their place this module locks the per-process cache semantics
(compute-once, error-not-cached), `verification_summary()`'s exact shape,
and - structurally, mirroring the `_score_report` source-parse precedent -
that `run_scan()` actually attaches the key."""

import socket
from pathlib import Path

import pytest

from glassbox.models import Scan
from glassbox.selftest import (
    EXPECTATIONS,
    detection_verification,
    reset_detection_verification_cache,
    run_selftest,
    start_lure_listener,
    verification_summary,
)


def test_expectations_matrix_covers_all_ten_intrusive_checks():
    names = {name for name, _, _ in EXPECTATIONS}
    assert len(EXPECTATIONS) == 10
    assert names == {
        "ssti", "path_traversal", "jwt_active", "graphql_deep", "csrf_posture",
        "host_header", "crlf", "rate_limit", "cache_deception",
        "subdomain_takeover"}


def test_full_matrix_every_expectation_matches():
    report = run_selftest()
    assert report["passed"], [
        (r["name"], r["matched"], r["error"], r["findings"])
        for r in report["results"] if not r["matched"]]
    assert len(report["results"]) == 10
    positives = [r for r in report["results"] if r["expect_finding"]]
    negatives = [r for r in report["results"] if not r["expect_finding"]]
    assert len(positives) == 5 and len(negatives) == 5
    for row in positives:
        assert row["findings"], f"{row['name']} detected nothing"


def test_selftest_is_deterministic_across_runs():
    first = run_selftest()
    second = run_selftest()
    assert first["passed"] and second["passed"]


def test_listener_binds_loopback_only():
    server, base_url = start_lure_listener()
    try:
        host, port = server.server_address
        assert host == "127.0.0.1"
        # The URL must be unreachable via any non-loopback name we can test:
        # the port is open ONLY on 127.0.0.1, so connecting to it through a
        # different local address must fail rather than reach the lure.
        probe = socket.socket()
        probe.settimeout(2)
        try:
            probe.connect(("localhost", port))
            reachable = True
        except OSError:
            reachable = False
        finally:
            probe.close()
        # 'localhost' may resolve to 127.0.0.1 on some setups (then it IS
        # reachable); what must NEVER happen is a 0.0.0.0-style wildcard bind.
        if reachable:
            import socket as s
            hostname_ip = s.gethostbyname(s.gethostname())
            if hostname_ip != "127.0.0.1":
                wildcard = socket.socket()
                wildcard.settimeout(2)
                with pytest.raises(OSError):
                    wildcard.connect((hostname_ip, port))
                wildcard.close()
    finally:
        server.shutdown()
        server.server_close()


def test_port_released_after_run():
    before = run_selftest()
    assert before["passed"]
    server, base_url = start_lure_listener()
    port = server.server_address[1]
    server.shutdown()
    server.server_close()
    probe = socket.socket()
    probe.settimeout(2)
    with pytest.raises(OSError):
        probe.connect(("127.0.0.1", port))
    probe.close()


def test_route_requires_login_removed_with_the_route():
    """2026-08-24 redesign regression lock: /selftest must NOT exist. The
    engine now feeds scan reports directly; a re-introduced route would
    resurrect the exact "another scanner - which domain does THIS one hit?"
    confusion the redesign exists to kill."""
    from glassbox import create_app
    app = create_app()
    client = app.test_client()
    resp = client.get("/selftest")
    assert resp.status_code == 404


def _matrix_stub(rows, passed=True, duration_ms=7):
    return {"passed": passed, "duration_ms": duration_ms,
            "results": [
                {"name": name, "ran": True, "expect_finding": expect,
                 "matched": matched,
                 "findings": [{"severity": "critical", "title": "t"}] if matched else [],
                 "error": None}
                for name, expect, matched in rows]}


def test_detection_verification_caches_per_process(monkeypatch):
    from glassbox import selftest as st
    reset_detection_verification_cache()
    calls = []

    def fake():
        calls.append(1)
        return _matrix_stub([("ssti", True, True)])

    monkeypatch.setattr(st, "run_selftest", fake)
    first = detection_verification()
    second = detection_verification()
    assert first is second
    assert len(calls) == 1, "second call must read the cache, not recompute"
    refreshed = detection_verification(force_refresh=True)
    assert len(calls) == 2 and refreshed is not None and refreshed is not first
    assert refreshed["passed"]


def test_verification_error_is_not_cached(monkeypatch):
    from glassbox import selftest as st
    reset_detection_verification_cache()
    attempts = []

    def flaky():
        attempts.append(1)
        if len(attempts) == 1:
            raise RuntimeError("listener port exhausted")
        return _matrix_stub([("ssti", True, True)])

    monkeypatch.setattr(st, "run_selftest", flaky)
    assert detection_verification() is None, \
        "a failed attempt returns None (badge omitted), never raises"
    recovered = detection_verification()
    assert recovered is not None and recovered["passed"], \
        "the failure was NOT cached - the next scan retried and succeeded"


def test_verification_summary_shape_and_failed_list(monkeypatch):
    from glassbox import selftest as st
    reset_detection_verification_cache()
    matrix = _matrix_stub(
        [("ssti", True, True), ("crlf", False, False)],
        passed=False, duration_ms=1234)
    # crlf is a NEGATIVE expectation that fired - specificity drift - so it
    # lands in `failed` even though it produced findings.
    matrix["results"][1]["matched"] = False
    monkeypatch.setattr(st, "run_selftest", lambda: matrix)

    summary = verification_summary()
    assert summary == {
        "passed": False,
        "confirmed": 1,
        "total": 2,
        "duration_ms": 1234,
        "failed": ["crlf"],
    }


def test_verification_summary_none_when_engine_unavailable(monkeypatch):
    from glassbox import selftest as st
    reset_detection_verification_cache()

    def boom():
        raise OSError("no loopback available")

    monkeypatch.setattr(st, "run_selftest", boom)
    assert verification_summary() is None


def test_run_scan_attaches_detection_verified():
    """Structural lock (the `_score_report` source-parse precedent): run_scan
    must call verification_summary() at the END of its pipeline (after
    scoring) and attach the result to the returned report only when present -
    an unavailable verification omits the key rather than failing the scan."""
    src = (Path(__file__).resolve().parent.parent / "glassbox" /
           "scan_engine.py").read_text(encoding="utf-8")
    scoring_at = src.index("_score_report(all_findings)")
    attach_at = src.index('report["detection_verified"] = detection_verified')
    summary_call_at = src.index("detection_verified = verification_summary()")
    assert scoring_at < summary_call_at < attach_at, (
        "verification must be gathered after scoring (end of pipeline, so the "
        "live progress feed isn't delayed on a worker's first scan)")
    assert src.count('"detection_verified"') == 1
    assert 'if detection_verified:' in src


def test_report_badge_template_tracks_the_key():
    html = (Path(__file__).resolve().parent.parent / "templates" /
            "scan_report.html").read_text(encoding="utf-8")
    assert "detection_verified" in html
    assert "Engine verified" in html
    # The badge must explain itself: the lure target is Glassbox's own
    # infrastructure, never the scanned site.
    assert "internal check target" in html
    # And it must degrade silently when the key is absent:
    assert "{% if r.get('detection_verified') %}" in html


def test_selftest_creates_no_scan_row_or_report_file(app):
    with app.app_context():
        assert Scan.query.count() == 0
        report = run_selftest()
        assert report["passed"]
        assert Scan.query.count() == 0
