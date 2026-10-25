"""Phase 29 (SARIF-01..02): SARIF 2.1.0 export of scan reports.

Locks, in order: the shared severity -> level mapping (one function, no
per-exporter copies), the shared writer's output against the VENDORED
official SARIF 2.1.0 JSON schema (fixture-based - not just "shape looks
right"), determinism, rule dedup/CWE tags, then both export surfaces:
the session-web /scan/<id>/report.sarif route (ownership guard + leak
check mirroring export.csv's) and the token-authed /api/v1 twin,
including the byte-for-byte no-drift lock between the two surfaces.
SARIF-03's live GitHub upload verification is a user-side step (needs a
scratch GitHub repo) and is documented in the phase ship record."""

import json
from datetime import UTC

import jsonschema
import pytest

from glassbox.checks import severity_to_sarif_level
from glassbox.models import Plan, Report, Role, ScanStatus
from glassbox.sarif import (
    SARIF_VERSION,
    _rule_id_for,
    build_sarif_report,
    sarif_text,
)
from tests.conftest import (
    login,
    make_api_token,
    make_asset,
    make_org,
    make_scan,
    make_user,
)

_SCHEMA_PATH = "tests/fixtures/sarif-2.1.0.json"


def _schema():
    # utf-8-sig: the schemastore copy ships with a BOM.
    with open(_SCHEMA_PATH, encoding="utf-8-sig") as f:
        return json.load(f)


def _fixture_report():
    return {
        "hostname": "example.com",
        "target": "https://example.com",
        "score": 64,
        "findings": [
            {
                "check_name": "sqli_union", "category": "SQL Injection",
                "title": "/items UNION probe reflected", "severity": "critical",
                "detail": "payload echoed in column 3", "recommendation": "parameterize",
                "confidence": "Confirmed", "cwe": "CWE-89",
            },
            {
                "check_name": "headers", "category": "headers",
                "title": "Content-Security-Policy missing", "severity": "medium",
                "confidence": "Potential",
            },
            {
                "check_name": "headers", "category": "headers",
                "title": "Strict-Transport-Security missing", "severity": "high",
                "confidence": "Confirmed",
            },
            # Legacy blob shape: no check_name -> category falls back to
            # being the rule id.
            {"category": "TLS", "title": "Weak cipher suite offered",
             "severity": "low"},
            # A passing check is not a problem -> level "none".
            {"check_name": "tls", "title": "Certificate chain valid",
             "severity": "pass"},
        ],
    }


# --------------------------------------------------------------------------
# SARIF-02: the shared mapping + the pure builder
# --------------------------------------------------------------------------

def test_severity_to_sarif_level_full_table():
    assert severity_to_sarif_level("critical") == "error"
    assert severity_to_sarif_level("high") == "error"
    assert severity_to_sarif_level("medium") == "warning"
    assert severity_to_sarif_level("low") == "note"
    assert severity_to_sarif_level("info") == "note"
    assert severity_to_sarif_level("pass") == "none"
    # Degrade-gracefully on junk, never raise.
    assert severity_to_sarif_level("CATASTROPHIC") == "note"
    assert severity_to_sarif_level(None) == "note"
    assert severity_to_sarif_level("") == "note"


def test_build_sarif_report_validates_against_official_21_schema():
    doc, _filename = build_sarif_report(_fixture_report(), 42)
    # Fixture-based validation against the vendored official OASIS/
    # schemastore SARIF 2.1.0 schema - not a hand-rolled structural check.
    jsonschema.validate(instance=doc, schema=_schema())
    assert doc["version"] == SARIF_VERSION


def test_rules_dedup_by_check_name_with_category_fallback():
    doc, _ = build_sarif_report(_fixture_report(), 42)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    # Two "headers" findings collapse to ONE rule; the legacy no-check_name
    # finding gets its category as the id.
    assert ids.count("headers") == 1
    assert ids == ["sqli_union", "headers", "TLS", "tls"]
    sqli_rule = rules[0]
    assert sqli_rule["properties"]["tags"] == ["security", "cwe:CWE-89"]
    # Non-CWE rules carry no properties block at all (nothing speculative).
    assert "properties" not in rules[1]


def test_results_carry_mapped_levels_and_rule_indexes():
    doc, _ = build_sarif_report(_fixture_report(), 42)
    run = doc["runs"][0]
    by_title = {r["properties"]["title"]: r for r in run["results"]}
    assert by_title["/items UNION probe reflected"]["level"] == "error"
    assert by_title["Strict-Transport-Security missing"]["level"] == "error"
    assert by_title["Content-Security-Policy missing"]["level"] == "warning"
    assert by_title["Weak cipher suite offered"]["level"] == "note"
    assert by_title["Certificate chain valid"]["level"] == "none"
    # ruleIndex points back into the driver's rules list correctly.
    for r in run["results"]:
        rid = r["ruleId"]
        assert run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == rid
    # Confidence round-trips for tooling that wants it.
    assert by_title["/items UNION probe reflected"]["properties"]["confidence"] == "Confirmed"


def test_message_text_and_location_shape():
    doc, _ = build_sarif_report(_fixture_report(), 42)
    first = doc["runs"][0]["results"][0]
    assert first["message"]["text"] == \
        "/items UNION probe reflected — payload echoed in column 3"
    loc = first["locations"][0]["physicalLocation"]["artifactLocation"]
    assert loc["uri"] == "https://example.com"


def test_no_target_omits_locations_instead_of_emitting_empty_uri():
    report = _fixture_report()
    del report["target"]
    doc, filename = build_sarif_report(report, 7)
    for r in doc["runs"][0]["results"]:
        assert "locations" not in r
    assert filename == "example.com_scan7.sarif"


def test_writer_is_deterministic_byte_for_byte():
    doc_a, name_a = build_sarif_report(_fixture_report(), 42)
    doc_b, name_b = build_sarif_report(_fixture_report(), 42)
    assert name_a == name_b
    assert sarif_text(doc_a) == sarif_text(doc_b)


def test_rule_id_helper_never_returns_empty():
    assert _rule_id_for({}) == "glassbox"
    assert _rule_id_for({"check_name": "", "category": ""}) == "glassbox"


# --------------------------------------------------------------------------
# SARIF-01: session-web route /scan/<id>/report.sarif
# --------------------------------------------------------------------------

SARIF_LEAK_MARKER = "MARKER-29-SARIF-LEAK-CHECK-b47e02"


@pytest.fixture()
def scenario(db):
    """Minimal two-org slice of test_scan_ownership.py's fixture: one scan
    owned by org1's plain member, plus org2's admin as the rival reader."""
    from glassbox.models import Role

    org1 = make_org(name="Org One")
    org2 = make_org(name="Org Two")
    owner = make_user("owner@org1.com", org=org1, role=Role.MEMBER)
    make_user("rival-admin@org2.com", org=org2, role=Role.ORG_ADMIN)
    scan = make_scan(owner, org=org1, target_url="https://example.com")
    return {"scan": scan}


def _attach_sarif_marker_report(scan):
    """Same direct-Report.data approach as the CSV leak test - no filesystem,
    no background thread; Report.data is the source of truth."""
    report_data = {
        "hostname": "example.com",
        "target": "https://example.com",
        "findings": [
            {
                "check_name": "xss_reflected", "category": "XSS",
                "title": "Reflected XSS", "severity": "high",
                "detail": SARIF_LEAK_MARKER, "recommendation": "encode output",
            },
        ],
    }
    r = Report(scan_id=scan.id, json_path="unused-for-this-test.json",
               data=report_data)
    from glassbox.extensions import db as _db

    _db.session.add(r)
    _db.session.flush()
    return r


def test_scan_report_sarif_owner_gets_ingestible_download(client, db):
    org = make_org()
    user = make_user("sarif-owner@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()
    _attach_sarif_marker_report(scan)
    db.session.commit()

    login(client, "sarif-owner@example.com")
    resp = client.get(f"/scan/{scan.id}/report.sarif")
    assert resp.status_code == 200
    assert resp.content_type.startswith("application/sarif+json")
    assert "attachment" in resp.headers["Content-Disposition"]
    assert 'filename="example.com_scan' in resp.headers["Content-Disposition"]
    doc = json.loads(resp.data.decode("utf-8"))
    jsonschema.validate(instance=doc, schema=_schema())
    assert doc["version"] == SARIF_VERSION
    assert doc["runs"][0]["automationDetails"]["id"] == f"glassbox/scan/{scan.id}"


def test_scan_report_sarif_cross_org_is_404_and_leaks_no_finding_text(client, scenario, db):
    _attach_sarif_marker_report(scenario["scan"])
    db.session.commit()

    # Negative: a different org's admin must not see the SARIF, or the marker.
    login(client, "rival-admin@org2.com")
    resp = client.get(f"/scan/{scenario['scan'].id}/report.sarif")
    assert resp.status_code == 404
    assert SARIF_LEAK_MARKER.encode() not in resp.data

    # Positive control: the owner gets real SARIF with the marker present -
    # proves the 404 came from the ownership guard, not a missing report.
    login(client, "owner@org1.com")
    resp2 = client.get(f"/scan/{scenario['scan'].id}/report.sarif")
    assert resp2.status_code == 200
    assert SARIF_LEAK_MARKER.encode() in resp2.data


def test_scan_report_sarif_no_report_row_is_404(client, db):
    org = make_org()
    user = make_user("no-report@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()

    login(client, "no-report@example.com")
    resp = client.get(f"/scan/{scan.id}/report.sarif")
    assert resp.status_code == 404


# --------------------------------------------------------------------------
# SARIF-01: token-authed /api/v1 twin
# --------------------------------------------------------------------------

def test_report_sarif_matches_session_route_bytes_exactly(client, db):
    """The no-drift lock: one scan, both surfaces, identical bodies - the
    whole point of the single shared writer."""
    org = make_org(plan=Plan.PAID)
    user = make_user("twin@example.com", org=org, role=Role.ORG_ADMIN)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()
    _attach_sarif_marker_report(scan)
    db.session.commit()

    _, raw_token = make_api_token(user, name="tok")
    api_resp = client.get(
        f"/api/v1/scans/{scan.id}/report.sarif",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    login(client, "twin@example.com")
    web_resp = client.get(f"/scan/{scan.id}/report.sarif")

    assert api_resp.status_code == 200 and web_resp.status_code == 200
    assert api_resp.data == web_resp.data


def test_report_sarif_different_org_gets_404(client, db):
    org_a = make_org(plan=Plan.PAID, name="Org A")
    org_b = make_org(plan=Plan.PAID, name="Org B")
    user_a = make_user("a-sarif@example.com", org=org_a)
    user_b = make_user("b-sarif@example.com", org=org_b)
    db.session.commit()
    _, raw_token_b = make_api_token(user_b, name="b-tok")
    a = make_asset(org_a, user_a, name="Asset")
    scan = make_scan(user_a, org=org_a, status=ScanStatus.COMPLETED)
    scan.asset_id = a.id
    db.session.commit()
    _attach_sarif_marker_report(scan)
    db.session.commit()

    resp = client.get(
        f"/api/v1/scans/{scan.id}/report.sarif",
        headers={"Authorization": f"Bearer {raw_token_b}"},
    )
    assert resp.status_code == 404
    assert SARIF_LEAK_MARKER.encode() not in resp.data


def test_report_sarif_soft_deleted_asset_gets_404(client, db):
    from datetime import datetime

    org = make_org(plan=Plan.PAID)
    user = make_user("deleted-asset@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    a = make_asset(org, user, name="Doomed")
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    scan.asset_id = a.id
    db.session.commit()
    _attach_sarif_marker_report(scan)
    a.deleted_at = datetime.now(UTC)
    db.session.commit()

    resp = client.get(
        f"/api/v1/scans/{scan.id}/report.sarif",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert resp.status_code == 404


def test_report_sarif_unauthenticated_gets_401_json(client, db):
    org = make_org(plan=Plan.PAID)
    user = make_user("unauth@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()

    resp = client.get(f"/api/v1/scans/{scan.id}/report.sarif")
    assert resp.status_code == 401
    assert resp.get_json()["error"]


@pytest.mark.parametrize("path", ["/api/v1/scans/999999/report.sarif"])
def test_report_sarif_missing_scan_gets_404(client, db, path):
    org = make_org(plan=Plan.PAID)
    user = make_user("missing@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")

    resp = client.get(path, headers={"Authorization": f"Bearer {raw_token}"})
    assert resp.status_code == 404
