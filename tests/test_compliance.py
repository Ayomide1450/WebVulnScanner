"""
Tests for the OWASP Top 10 / ASVS compliance-mapping layer added in Phase 3
(COMP-01/COMP-04): webvulnscanner.checks.CHECK_COMPLIANCE,
webvulnscanner.checks.SCAN_TYPE_CHECK_NAMES, Finding.check_name, the
check_name-tagging lines added to each of scan_engine.py's 4 orchestrators,
and the compliance pill/caption scan_report.html now renders per finding.

Lives in its own module rather than tests/test_entitlements.py, matching
this codebase's existing precedent that a per-check coverage-regression test
doesn't have to live beside the dict it tests (CHECK_LABELS's own coverage
test lives in tests/test_scan_events.py, not webvulnscanner/checks.py).

This module (Task 1) covers only run_scan()'s tagging plus the
report-page-rendering behaviors (mapped finding, legacy/unmapped finding,
HTML-escaping). Task 3 extends this module with the remaining 3
orchestrators' tagging tests and the full COMP-04 key-set coverage
regression tests.
"""
from types import SimpleNamespace

from webvulnscanner import scan_engine
from webvulnscanner.checks import CHECK_COMPLIANCE, Finding
from webvulnscanner.entitlements import Tier

from tests.conftest import login, make_scan, make_user
from tests.test_api_routes import _make_report


def _stub_all_checks_with_findings(monkeypatch):
    """Same network-free stubbing shape as
    tests/test_scan_events.py::_stub_all_checks, but check_headers/
    check_cookies/check_open_ports (run_scan()'s 3 synchronous/out-of-jobs-
    dict collection points) each return one real Finding, so the
    check_name-tagging added at every collection point can be asserted
    end to end against a real returned finding, not just an empty list."""
    plain_stub_names = [
        "check_cookies", "check_tls_cert", "check_https_redirect",
        "check_sensitive_paths", "check_robots_sitemap", "check_cors", "check_http_methods",
        "check_open_redirect", "check_directory_listing", "check_mixed_content",
        "check_dns_email_security", "check_vulnerable_js", "check_xss_sqli",
        "check_exposed_secrets", "check_sri",
    ]
    for name in plain_stub_names:
        monkeypatch.setattr(scan_engine, name, lambda *a, **k: ({}, []))

    # Override 3 of the above (headers/cookies aren't in plain_stub_names;
    # open_ports is dispatched separately below) to return one real Finding
    # each, so run_scan()'s three out-of-jobs-dict collection points
    # (headers/cookies synchronous pair, plus check_open_ports) are all
    # exercised with an actual finding to tag.
    monkeypatch.setattr(scan_engine, "check_headers", lambda *a, **k: (
        {"grade": "B"}, [Finding(category="Headers", title="Missing CSP", severity="medium", detail="d")],
    ))
    monkeypatch.setattr(scan_engine, "check_cookies", lambda *a, **k: (
        [], [Finding(category="Cookies", title="Missing Secure flag", severity="low", detail="d")],
    ))
    monkeypatch.setattr(scan_engine, "check_open_ports", lambda *a, **k: (
        [], "1.2.3.4", [Finding(category="Ports", title="Open port 22", severity="info", detail="d")],
    ))

    fake_session = SimpleNamespace(get=lambda *a, **k: SimpleNamespace(text="<html></html>"))
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: fake_session)


# --------------------------------------------------------------------------
# (a) run_scan() check_name tagging - COMP-01 tracer
# --------------------------------------------------------------------------

def test_run_scan_tags_every_finding_with_a_mapped_check_name(monkeypatch):
    _stub_all_checks_with_findings(monkeypatch)

    report = scan_engine.run_scan("https://example.com", None, Tier.ORG_VERIFIED, True)

    findings = report["findings"]
    assert findings, "stubs should have contributed at least one finding to tag"
    for f in findings:
        assert f["check_name"], f"finding missing check_name: {f}"
        assert f["check_name"] in CHECK_COMPLIANCE, (
            f"check_name {f['check_name']!r} is not a CHECK_COMPLIANCE key"
        )


# --------------------------------------------------------------------------
# (b)-(d) scan_report.html rendering
# --------------------------------------------------------------------------

def _minimal_report(findings, **overrides):
    report = {
        "target": "https://example.com",
        "hostname": "example.com",
        "scanned_at": "2026-01-01T00:00:00Z",
        "score": 82,
        "risk_grade": "B",
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "findings": findings,
        "locked_checks": [],
    }
    for f in findings:
        report["severity_counts"][f["severity"]] = report["severity_counts"].get(f["severity"], 0) + 1
    report.update(overrides)
    return report


def test_scan_report_shows_mapped_owasp_category_for_check_name(client, db):
    user = make_user("owner@example.com")
    db.session.commit()
    # scan_type deliberately not "base"/"advanced"/"media"/"api" - none of
    # this template's scan-type-specific "Detailed check output" blocks
    # apply, keeping this test's report dict scoped to exactly what the
    # shared findings-list section (where the compliance pill lives) reads.
    scan = make_scan(user, scan_type="other")
    report_dict = _minimal_report([
        {
            "category": "Headers",
            "title": "Missing CSP",
            "severity": "medium",
            "detail": "No Content-Security-Policy header present.",
            "recommendation": "",
            "check_name": "headers",
        },
    ])
    _make_report(db, scan, report_dict)

    login(client, "owner@example.com")
    resp = client.get(f"/scan/{scan.id}/report")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert CHECK_COMPLIANCE["headers"]["owasp"] in body


def test_scan_report_shows_uncategorized_for_legacy_finding_without_check_name(client, db):
    user = make_user("legacy@example.com")
    db.session.commit()
    scan = make_scan(user, scan_type="other")
    report_dict = _minimal_report([
        {
            "category": "Cookies",
            "title": "Missing Secure flag",
            "severity": "low",
            "detail": "d",
            "recommendation": "",
            # No "check_name" key at all - matches every report JSON written
            # to disk before this phase shipped.
        },
    ])
    _make_report(db, scan, report_dict)

    login(client, "legacy@example.com")
    resp = client.get(f"/scan/{scan.id}/report")

    assert resp.status_code == 200
    assert "Uncategorized" in resp.get_data(as_text=True)


def test_scan_report_escapes_finding_title_containing_script_tag(client, db):
    user = make_user("xss@example.com")
    db.session.commit()
    scan = make_scan(user, scan_type="other")
    raw_tag = "<script>alert(1)</script>"
    report_dict = _minimal_report([
        {
            "category": "Headers",
            "title": f"Reflected value: {raw_tag}",
            "severity": "high",
            "detail": "d",
            "recommendation": "",
            "check_name": "headers",
        },
    ])
    _make_report(db, scan, report_dict)

    login(client, "xss@example.com")
    resp = client.get(f"/scan/{scan.id}/report")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert raw_tag not in body
    assert "&lt;script&gt;" in body
