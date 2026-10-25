"""Phase 25 (INTG-01): NDJSON (newline-delimited JSON) export of scan findings.

Locks: the shared pure writer (format correctness, field coverage, determinism,
empty-findings degrade), the safe_filename allowlist reuse, then both export
surfaces: the session-web /scan/<id>/findings.ndjson route (ownership guard +
leak check mirroring CSV/SARIF/PDF) and the token-authed /api/v1 twin,
including the no-drift string-for-string lock between the two.

No WeasyPrint/GTK3 dependency — these tests always run on every platform.
"""

import json

import pytest

from glassbox.models import Plan, Report, Role, ScanStatus
from glassbox.ndjson_report import findings_ndjson
from glassbox.scan_routes import safe_filename

from tests.conftest import (
    login,
    make_api_token,
    make_asset,
    make_org,
    make_scan,
    make_user,
)


NDJSON_LEAK_MARKER = "MARKER-25-NDJSON-LEAK-CHECK-7b2e04"


def _fixture_report():
    return {
        "hostname": "example.com",
        "target": "https://example.com",
        "score": 64,
        "risk_grade": "D",
        "findings": [
            {
                "check_name": "sqli_union", "category": "SQL Injection",
                "title": "/items UNION probe reflected", "severity": "critical",
                "confidence": "Confirmed", "cwe": "CWE-89",
                "owasp_category": "A03:2021",
                "detail": "payload echoed in column 3",
                "recommendation": "parameterize queries",
            },
            {
                "check_name": "headers", "category": "headers",
                "title": "Content-Security-Policy missing", "severity": "medium",
                "confidence": "Potential", "detail": "no CSP header",
            },
            {
                "check_name": "headers", "category": "headers",
                "title": "Strict-Transport-Security missing", "severity": "high",
                "confidence": "Confirmed",
            },
            {
                "check_name": "tls", "title": "Certificate chain valid",
                "severity": "pass",
            },
        ],
    }


def _attach_ndjson_marker_report(scan):
    report_data = {
        "hostname": "example.com",
        "target": "https://example.com",
        "findings": [
            {
                "check_name": "xss_reflected", "category": "XSS",
                "title": "Reflected XSS", "severity": "high",
                "detail": NDJSON_LEAK_MARKER, "recommendation": "encode output",
            },
        ],
    }
    r = Report(scan_id=scan.id, json_path="unused-for-this-test.json",
               data=report_data)
    from glassbox.extensions import db as _db
    _db.session.add(r)
    _db.session.flush()
    return r


@pytest.fixture()
def scenario(db):
    org1 = make_org(name="Org One")
    org2 = make_org(name="Org Two")
    owner = make_user("ndjson-owner@org1.com", org=org1, role=Role.MEMBER)
    make_user("ndjson-rival@org2.com", org=org2, role=Role.ORG_ADMIN)
    scan = make_scan(owner, org=org1, target_url="https://example.com")
    return {"scan": scan}


# --------------------------------------------------------------------------
# Pure writer: findings_ndjson()
# --------------------------------------------------------------------------

class TestFindingsNdjson:
    def test_produces_one_json_object_per_line(self):
        text, _ = findings_ndjson(_fixture_report(), 1)
        lines = [l for l in text.strip().split("\n") if l]
        assert len(lines) == 4  # 4 findings

    def test_each_line_is_valid_json(self):
        text, _ = findings_ndjson(_fixture_report(), 1)
        for line in text.strip().split("\n"):
            obj = json.loads(line)
            assert isinstance(obj, dict)

    def test_expected_keys_present(self):
        text, _ = findings_ndjson(_fixture_report(), 1)
        first_line = text.strip().split("\n")[0]
        obj = json.loads(first_line)
        expected = {"category", "title", "severity", "confidence", "cwe",
                     "owasp_category", "detail", "recommendation"}
        assert expected == set(obj.keys())

    def test_unknown_keys_omitted(self):
        report = _fixture_report()
        report["findings"][0]["extra_secrets"] = ["AKIA..."]
        text, _ = findings_ndjson(report, 1)
        obj = json.loads(text.strip().split("\n")[0])
        assert "extra_secrets" not in obj
        assert "check_name" not in obj  # deliberately excluded

    def test_compact_separators_no_whitespace(self):
        text, _ = findings_ndjson(_fixture_report(), 1)
        first_line = text.strip().split("\n")[0]
        assert ", " not in first_line
        assert ": " not in first_line

    def test_deterministic_output(self):
        report = _fixture_report()
        a, name_a = findings_ndjson(report, 42)
        b, name_b = findings_ndjson(report, 42)
        assert a == b
        assert name_a == name_b

    def test_empty_findings_degrades(self):
        report = {"hostname": "empty.com", "findings": []}
        text, filename = findings_ndjson(report, 99)
        assert text == ""
        assert filename.endswith(".ndjson")

    def test_filename_sanitized(self):
        report = _fixture_report()
        report["hostname"] = "weird:host/name.com"
        _, filename = findings_ndjson(report, 5)
        assert "/" not in filename
        assert ":" not in filename

    def test_trailing_newline_present(self):
        text, _ = findings_ndjson(_fixture_report(), 1)
        assert text.endswith("\n")


# --------------------------------------------------------------------------
# safe_filename reuse (pure helper, no Flask context needed)
# --------------------------------------------------------------------------

class TestNdjsonSafeFilename:
    def test_clean_hostname_passes_through(self):
        assert safe_filename("example.com_scan42_findings.ndjson") == \
            "example.com_scan42_findings.ndjson"

    def test_leading_dots_collapsed(self):
        assert not safe_filename("...hidden").startswith(".")

    def test_empty_string_returns_scan(self):
        assert safe_filename("") == "scan"


# --------------------------------------------------------------------------
# Session-web route: /scan/<id>/findings.ndjson
# --------------------------------------------------------------------------

def test_scan_report_ndjson_owner_gets_valid_download(client, db):
    org = make_org()
    user = make_user("ndjson-owner@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()
    _attach_ndjson_marker_report(scan)
    db.session.commit()

    login(client, "ndjson-owner@example.com")
    resp = client.get(f"/scan/{scan.id}/findings.ndjson")
    assert resp.status_code == 200
    assert resp.content_type.startswith("application/x-ndjson")
    assert "attachment" in resp.headers["Content-Disposition"]
    assert "ndjson" in resp.headers["Content-Disposition"]
    # valid NDJSON: each line is valid JSON
    for line in resp.data.decode("utf-8").strip().split("\n"):
        obj = json.loads(line)
        assert "severity" in obj


def test_scan_report_ndjson_cross_org_is_404_and_leaks_no_finding_text(client, scenario, db):
    _attach_ndjson_marker_report(scenario["scan"])
    db.session.commit()

    login(client, "ndjson-rival@org2.com")
    resp = client.get(f"/scan/{scenario['scan'].id}/findings.ndjson")
    assert resp.status_code == 404
    assert NDJSON_LEAK_MARKER.encode() not in resp.data

    login(client, "ndjson-owner@org1.com")
    resp2 = client.get(f"/scan/{scenario['scan'].id}/findings.ndjson")
    assert resp2.status_code == 200
    assert NDJSON_LEAK_MARKER.encode() in resp2.data


def test_scan_report_ndjson_no_report_row_is_404(client, db):
    org = make_org()
    user = make_user("no-report-ndjson@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()

    login(client, "no-report-ndjson@example.com")
    resp = client.get(f"/scan/{scan.id}/findings.ndjson")
    assert resp.status_code == 404


def test_scan_report_ndjson_unauthenticated_is_redirect(client, db):
    org = make_org()
    user = make_user("ndjson-auth@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()
    _attach_ndjson_marker_report(scan)
    db.session.commit()

    resp = client.get(f"/scan/{scan.id}/findings.ndjson")
    assert resp.status_code == 302  # redirect to login


# --------------------------------------------------------------------------
# Token-authed API route: /api/v1/scans/<id>/findings.ndjson
# --------------------------------------------------------------------------

def test_api_report_ndjson_owner_gets_valid_download(client, db):
    org = make_org(plan=Plan.PAID)
    user = make_user("ndjson-api@example.com", org=org, role=Role.ORG_ADMIN)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()
    _attach_ndjson_marker_report(scan)
    db.session.commit()

    _, raw_token = make_api_token(user, name="tok")
    resp = client.get(
        f"/api/v1/scans/{scan.id}/findings.ndjson",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert resp.status_code == 200
    assert resp.content_type.startswith("application/x-ndjson")
    for line in resp.data.decode("utf-8").strip().split("\n"):
        obj = json.loads(line)
        assert "severity" in obj


def test_api_report_ndjson_matches_session_route_exactly(client, db):
    org = make_org(plan=Plan.PAID)
    user = make_user("ndjson-twin@example.com", org=org, role=Role.ORG_ADMIN)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()
    _attach_ndjson_marker_report(scan)
    db.session.commit()

    _, raw_token = make_api_token(user, name="tok")
    api_resp = client.get(
        f"/api/v1/scans/{scan.id}/findings.ndjson",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    login(client, "ndjson-twin@example.com")
    web_resp = client.get(f"/scan/{scan.id}/findings.ndjson")

    assert api_resp.status_code == 200 and web_resp.status_code == 200
    assert api_resp.data == web_resp.data


def test_report_ndjson_different_org_gets_404(client, db):
    org_a = make_org(plan=Plan.PAID, name="Org A")
    org_b = make_org(plan=Plan.PAID, name="Org B")
    user_a = make_user("a-ndjson@example.com", org=org_a)
    user_b = make_user("b-ndjson@example.com", org=org_b)
    db.session.commit()
    _, raw_token_b = make_api_token(user_b, name="b-tok")
    a = make_asset(org_a, user_a, name="Asset")
    scan = make_scan(user_a, org=org_a, status=ScanStatus.COMPLETED)
    scan.asset_id = a.id
    db.session.commit()
    _attach_ndjson_marker_report(scan)
    db.session.commit()

    resp = client.get(
        f"/api/v1/scans/{scan.id}/findings.ndjson",
        headers={"Authorization": f"Bearer {raw_token_b}"},
    )
    assert resp.status_code == 404
    assert NDJSON_LEAK_MARKER.encode() not in resp.data


def test_report_ndjson_soft_deleted_asset_gets_404(client, db):
    from datetime import datetime, timezone

    org = make_org(plan=Plan.PAID)
    user = make_user("del-asset-ndjson@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    a = make_asset(org, user, name="Doomed")
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    scan.asset_id = a.id
    db.session.commit()
    _attach_ndjson_marker_report(scan)
    a.deleted_at = datetime.now(timezone.utc)
    db.session.commit()

    resp = client.get(
        f"/api/v1/scans/{scan.id}/findings.ndjson",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert resp.status_code == 404


def test_api_report_ndjson_no_report_row_is_404(client, db):
    org = make_org(plan=Plan.PAID)
    user = make_user("no-report-api-ndjson@example.com", org=org, role=Role.ORG_ADMIN)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()

    _, raw_token = make_api_token(user, name="tok")
    resp = client.get(
        f"/api/v1/scans/{scan.id}/findings.ndjson",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert resp.status_code == 404
    assert resp.json["error"] == "report not available"
