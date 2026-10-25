"""
Tests for the OWASP Top 10 / ASVS compliance-mapping layer added in Phase 3
(COMP-01/COMP-04): glassbox.checks.CHECK_COMPLIANCE,
glassbox.checks.SCAN_TYPE_CHECK_NAMES, Finding.check_name, the
check_name-tagging lines added to each of scan_engine.py's 4 orchestrators,
and the compliance pill/caption scan_report.html now renders per finding.

Lives in its own module rather than tests/test_entitlements.py, matching
this codebase's existing precedent that a per-check coverage-regression test
doesn't have to live beside the dict it tests (CHECK_LABELS's own coverage
test lives in tests/test_scan_events.py, not glassbox/checks.py).

Covers: run_scan()'s tagging plus the report-page-rendering behaviors
(mapped finding, legacy/unmapped finding, HTML-escaping) [Task 1]; the
remaining 3 orchestrators' (run_media_scan/run_api_scan/run_advanced_scan)
tagging tests, plus the full COMP-04 key-set coverage regression tests
that read scan_engine.py's live source rather than a hand-maintained list
[Task 3].
"""
import re
from pathlib import Path
from types import SimpleNamespace

from glassbox import scan_engine
from glassbox.checks import CHECK_COMPLIANCE, SCAN_TYPE_CHECK_NAMES, Finding
from glassbox.entitlements import Tier
from glassbox.scan_routes import GROUPING_MODES, group_findings_by_compliance
from tests.conftest import login, make_scan, make_user
from tests.test_api_routes import _make_report
from tests.test_entitlements import (
    ADVANCED_SCAN_CHECK_NAMES,
    OUT_OF_JOBS_DICT_NAMES,
    _run_scan_job_names,
)


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


# --------------------------------------------------------------------------
# (f) run_media_scan() / run_api_scan() / run_advanced_scan() check_name
# tagging - Task 3, the 3 orchestrators Task 1 didn't cover.
# --------------------------------------------------------------------------

def test_run_media_scan_tags_its_finding_with_check_name(monkeypatch):
    finding = Finding(category="Media", title="Publicly accessible backup image", severity="medium", detail="d")
    monkeypatch.setattr(scan_engine, "check_media", lambda *a, **k: ({"media_items": []}, [finding]))

    report = scan_engine.run_media_scan("https://example.com", False, 10)

    assert report["findings"], "stub should have contributed at least one finding to tag"
    for f in report["findings"]:
        assert f["check_name"] == "media"
        assert f["check_name"] in CHECK_COMPLIANCE


def test_run_api_scan_tags_each_of_its_three_findings_with_check_name(monkeypatch):
    monkeypatch.setattr(scan_engine, "check_api_schema_exposure", lambda *a, **k: (
        {}, [Finding(category="API", title="Swagger UI exposed", severity="medium", detail="d")],
    ))
    monkeypatch.setattr(scan_engine, "check_api_wordlist", lambda *a, **k: (
        {}, [Finding(category="API", title="Unauthenticated endpoint exposed", severity="high", detail="d")],
    ))
    monkeypatch.setattr(scan_engine, "check_api_js_discovery", lambda *a, **k: (
        {}, [Finding(category="API", title="JS-discovered endpoint exposed", severity="low", detail="d")],
    ))
    fake_session = SimpleNamespace(get=lambda *a, **k: SimpleNamespace(text="<html></html>"))
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: fake_session)

    report = scan_engine.run_api_scan("https://example.com")

    assert len(report["findings"]) == 3
    check_names = {f["check_name"] for f in report["findings"]}
    assert check_names == {"schema", "wordlist", "js_discovery"}
    for name in check_names:
        assert name in CHECK_COMPLIANCE


def test_run_advanced_scan_tags_each_group_finding_with_check_name(monkeypatch):
    monkeypatch.setattr(scan_engine, "check_sqli_login", lambda *a, **k: (
        {}, [Finding(category="Auth", title="Auth bypass via SQLi", severity="critical", detail="d")],
    ))
    monkeypatch.setattr(scan_engine, "check_bruteforce", lambda *a, **k: (
        {"cap": 5}, [Finding(category="Auth", title="Brute-force succeeded", severity="high", detail="d")],
    ))
    monkeypatch.setattr(scan_engine, "check_sqli_union", lambda *a, **k: (
        {}, [Finding(category="SQL Injection", title="UNION-based SQLi", severity="critical", detail="d")],
    ))
    monkeypatch.setattr(scan_engine, "check_xss_stored", lambda *a, **k: (
        {}, [Finding(category="XSS", title="Stored XSS confirmed", severity="high", detail="d")],
    ))
    monkeypatch.setattr(scan_engine, "check_idor", lambda *a, **k: (
        {}, [Finding(category="IDOR", title="Cross-account resource exposed", severity="high", detail="d")],
    ))

    # Every field-presence gate in run_advanced_scan() must see a truthy
    # value, and tier/org_verified_for_domain must both be satisfied, or
    # the corresponding check group is skipped/locked instead of run.
    advanced = {
        "login_url": "https://example.com/login", "user_field": "user", "pass_field": "pass",
        "fail_text": "invalid credentials",
        "bruteforce_username": "admin", "bruteforce_passwords": "pw1\npw2",
        "sqli_union_url": "https://example.com/items", "sqli_union_param": "id",
        "stored_xss_submit_url": "https://example.com/comment", "stored_xss_field": "body",
        "stored_xss_view_url": "https://example.com/view", "stored_xss_cookie": "session=abc",
        "idor_url_template": "https://example.com/orders/{id}", "idor_ids": "1,2,3",
        "idor_cookie_a": "session=a", "idor_cookie_b": "session=b",
    }

    report = scan_engine.run_advanced_scan(advanced, Tier.ORG_VERIFIED, True)

    assert len(report["findings"]) == 5, report["locked_checks"]
    check_names = {f["check_name"] for f in report["findings"]}
    assert check_names == {"sqli_login", "bruteforce", "sqli_union", "xss_stored", "idor"}
    for name in check_names:
        assert name in CHECK_COMPLIANCE


# --------------------------------------------------------------------------
# COMP-04 regression coverage - CHECK_COMPLIANCE's key set stays in sync
# with every check name dispatchable across all 4 orchestrators, read from
# scan_engine.py's live source (same source-parsing technique already
# proven in tests/test_entitlements.py) rather than a hand-maintained list
# that could silently drift.
# --------------------------------------------------------------------------

def test_scan_type_check_names_base_matches_run_scan_jobs_and_out_of_band():
    job_names = _run_scan_job_names()
    assert job_names, "extraction found no job names - regex or scan_engine.py's jobs dict shape changed"
    assert (job_names | OUT_OF_JOBS_DICT_NAMES) == SCAN_TYPE_CHECK_NAMES["base"]


def test_advanced_and_api_results_assignments_are_covered_by_scan_type_check_names():
    # Source-parses scan_engine.py for every literal `results["<name>"] =
    # data` assignment (run_advanced_scan's 5 + run_api_scan's 3) - catches
    # an advanced- or api-scan check added to an orchestrator without a
    # matching SCAN_TYPE_CHECK_NAMES entry. Deliberately does NOT match
    # run_scan()'s `results[name] = data` (a variable, not a literal string)
    # or `results["open_ports"] = ports` (assigns `ports`, not `data`).
    src = Path(scan_engine.__file__).read_text(encoding="utf-8")
    found = set(re.findall(r'results\["(\w+)"\]\s*=\s*data', src))
    assert found, "extraction found no results[...] = data assignments - scan_engine.py's shape changed"
    assert found == (ADVANCED_SCAN_CHECK_NAMES | SCAN_TYPE_CHECK_NAMES["api"])

    all_names = set().union(*SCAN_TYPE_CHECK_NAMES.values())
    missing = found - all_names
    assert not missing, (
        f"scan_engine.py assigns results[...] for {missing} but SCAN_TYPE_CHECK_NAMES has no "
        "matching entry for it"
    )


def test_check_compliance_covers_every_dispatchable_check_name():
    all_names = set().union(*SCAN_TYPE_CHECK_NAMES.values())
    missing = all_names - set(CHECK_COMPLIANCE)
    assert not missing, f"CHECK_COMPLIANCE is missing entries for {missing}"


def test_check_compliance_has_no_stale_keys():
    all_names = set().union(*SCAN_TYPE_CHECK_NAMES.values())
    stale = set(CHECK_COMPLIANCE) - all_names
    assert not stale, f"CHECK_COMPLIANCE has stale entries for check names no longer dispatched: {stale}"


def test_check_compliance_every_entry_has_owasp_and_valid_asvs():
    for name, entry in CHECK_COMPLIANCE.items():
        assert entry.get("owasp"), f"{name} has no owasp category (D-01: required on every mapped check)"
        asvs = entry.get("asvs")
        assert asvs is None or (isinstance(asvs, str) and asvs), (
            f"{name}'s asvs must be a non-empty string or None (never an empty string), got {asvs!r}"
        )


# --------------------------------------------------------------------------
# Plan 03-02: GROUPING_MODES allowlist + group_findings_by_compliance()
# --------------------------------------------------------------------------

_MAPPING = {
    "headers": {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V14.4"},
    "tls": {"owasp": "A02:2021-Cryptographic Failures", "asvs": "V9.1"},
    "cookies": {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
}


def test_grouping_modes_allowlist_is_severity_compliance_and_domain():
    # v1.3 SCORE-02 added "domain" as a third grouping mode alongside the
    # original severity/compliance pair.
    assert GROUPING_MODES == ("severity", "compliance", "domain")


def test_group_findings_by_compliance_empty_input_returns_empty_list():
    assert group_findings_by_compliance([], _MAPPING) == []


def test_group_findings_by_compliance_two_findings_share_a_category():
    findings = [
        {"check_name": "headers", "title": "a"},
        {"check_name": "cookies", "title": "b"},
    ]
    out = group_findings_by_compliance(findings, _MAPPING)
    assert out == [("A05:2021-Security Misconfiguration", findings)]


def test_group_findings_by_compliance_unmapped_check_name_is_uncategorized():
    findings = [{"check_name": "nope", "title": "c"}]
    out = group_findings_by_compliance(findings, _MAPPING)
    assert out == [("Uncategorized", findings)]


def test_group_findings_by_compliance_missing_check_name_key_is_uncategorized():
    findings = [{"title": "d"}]
    out = group_findings_by_compliance(findings, _MAPPING)
    assert out == [("Uncategorized", findings)]


def test_group_findings_by_compliance_uncategorized_group_is_always_last():
    mapped = {"check_name": "headers", "title": "a"}
    unmapped = {"title": "b"}
    tls_mapped = {"check_name": "tls", "title": "c"}
    out = group_findings_by_compliance([unmapped, mapped, tls_mapped], _MAPPING)
    labels = [category for category, _ in out]
    # Mapped categories sorted ascending by their OWASP string; Uncategorized last.
    assert labels == [
        "A02:2021-Cryptographic Failures",
        "A05:2021-Security Misconfiguration",
        "Uncategorized",
    ]
    assert out[-1][0] == "Uncategorized"
    assert out[-1][1] == [unmapped]
    # Arrival order preserved within a group.
    assert out[1][1] == [mapped]


# --------------------------------------------------------------------------
# scan_report() route: ?group= allowlisting/coercion
# --------------------------------------------------------------------------

def _report_with_two_categories():
    return _minimal_report([
        {
            "category": "Headers", "title": "Missing CSP", "severity": "medium",
            "detail": "d", "recommendation": "", "check_name": "headers",
        },
        {
            "category": "Cookies", "title": "Missing Secure flag", "severity": "low",
            "detail": "d", "recommendation": "", "check_name": "nope-not-mapped",
        },
    ])


def test_scan_report_group_param_matrix_returns_200(client, db):
    user = make_user("grouping@example.com")
    db.session.commit()
    scan = make_scan(user, scan_type="other")
    _make_report(db, scan, _report_with_two_categories())

    login(client, "grouping@example.com")
    for query in ("", "?group=severity", "?group=banana", "?group=compliance"):
        resp = client.get(f"/scan/{scan.id}/report{query}")
        assert resp.status_code == 200, query


def test_scan_report_unrecognized_group_value_matches_no_param_grouping_mode(client, db):
    user = make_user("grouping2@example.com")
    db.session.commit()
    scan = make_scan(user, scan_type="other")
    _make_report(db, scan, _report_with_two_categories())

    login(client, "grouping2@example.com")
    no_param = client.get(f"/scan/{scan.id}/report").get_data(as_text=True)
    garbage = client.get(f"/scan/{scan.id}/report?group=banana").get_data(as_text=True)

    # Both render in severity mode: the severity-view's per-category
    # <summary> headings ("Headers"/"Cookies") appear in both responses
    # identically - a compliance-mode response would show OWASP category
    # strings and "Uncategorized" as headings instead.
    assert ("<summary>Headers" in no_param) == ("<summary>Headers" in garbage)
    assert ("<summary>Cookies" in no_param) == ("<summary>Cookies" in garbage)


# --------------------------------------------------------------------------
# Plan 03-02 Task 2: report page grouping toggle + compliance-grouped
# accordion (finding_card() macro, both branches).
# --------------------------------------------------------------------------

def test_scan_report_compliance_mode_shows_owasp_heading_and_finding_title(client, db):
    user = make_user("toggle1@example.com")
    db.session.commit()
    scan = make_scan(user, scan_type="other")
    _make_report(db, scan, _report_with_two_categories())

    login(client, "toggle1@example.com")
    resp = client.get(f"/scan/{scan.id}/report?group=compliance")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert CHECK_COMPLIANCE["headers"]["owasp"] in body
    assert "Missing CSP" in body


def test_scan_report_compliance_mode_shows_uncategorized_heading_for_unmapped_finding(client, db):
    user = make_user("toggle2@example.com")
    db.session.commit()
    scan = make_scan(user, scan_type="other")
    _make_report(db, scan, _report_with_two_categories())

    login(client, "toggle2@example.com")
    resp = client.get(f"/scan/{scan.id}/report?group=compliance")

    assert resp.status_code == 200
    assert "Uncategorized" in resp.get_data(as_text=True)


def test_scan_report_compliance_mode_omits_uncategorized_heading_when_all_mapped(client, db):
    user = make_user("toggle3@example.com")
    db.session.commit()
    scan = make_scan(user, scan_type="other")
    report_dict = _minimal_report([
        {
            "category": "Headers", "title": "Missing CSP", "severity": "medium",
            "detail": "d", "recommendation": "", "check_name": "headers",
        },
    ])
    _make_report(db, scan, report_dict)

    login(client, "toggle3@example.com")
    resp = client.get(f"/scan/{scan.id}/report?group=compliance")

    assert resp.status_code == 200
    assert "Uncategorized" not in resp.get_data(as_text=True)


def test_scan_report_compliance_pill_appears_in_both_grouping_modes(client, db):
    user = make_user("toggle4@example.com")
    db.session.commit()
    scan = make_scan(user, scan_type="other")
    report_dict = _minimal_report([
        {
            "category": "Headers", "title": "Missing CSP", "severity": "medium",
            "detail": "d", "recommendation": "", "check_name": "headers",
        },
    ])
    _make_report(db, scan, report_dict)

    login(client, "toggle4@example.com")
    severity_body = client.get(f"/scan/{scan.id}/report").get_data(as_text=True)
    compliance_body = client.get(f"/scan/{scan.id}/report?group=compliance").get_data(as_text=True)

    assert CHECK_COMPLIANCE["headers"]["owasp"] in severity_body
    assert CHECK_COMPLIANCE["headers"]["owasp"] in compliance_body


def test_scan_report_zero_findings_shows_no_findings_and_no_toggle(client, db):
    user = make_user("toggle5@example.com")
    db.session.commit()
    scan = make_scan(user, scan_type="other")
    _make_report(db, scan, _minimal_report([]))

    login(client, "toggle5@example.com")
    resp = client.get(f"/scan/{scan.id}/report")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No findings." in body
    assert "Group by:" not in body


def test_scan_report_non_owner_gets_ownership_response_for_compliance_mode(client, db):
    owner = make_user("owner-toggle@example.com")
    make_user("other-toggle@example.com")
    db.session.commit()
    scan = make_scan(owner, scan_type="other")
    _make_report(db, scan, _report_with_two_categories())

    login(client, "other-toggle@example.com")
    resp = client.get(f"/scan/{scan.id}/report?group=compliance")

    assert resp.status_code != 200
