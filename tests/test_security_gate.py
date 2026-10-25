"""Tests for the Security Gate - glassbox/security_gate.py's pure
evaluate_gate() and its single API exposure, GET /api/v1/scans/<id>/gate
(api_routes.py), which `glassbox gate` (cli/wvs.py) now consumes instead of
filtering findings client-side.

Two layers, mirroring test_readiness_verdict.py (pure-verdict unit tests)
and test_api_routes.py (token-auth/ownership conventions) respectively:
unit tests pin the blocking semantics; route tests pin that the endpoint
reuses fetch_report's exact ownership/error branches and never lets a gate
response be read more widely than the report it derives from.
"""
from datetime import UTC

import pytest

from glassbox.models import Plan, Report, Role, ScanStatus
from glassbox.security_gate import GATE_SEVERITIES, evaluate_gate
from tests.conftest import make_api_token, make_asset, make_org, make_scan, make_user


def _finding(severity, title="Finding"):
    return {"category": "Headers", "title": title, "severity": severity, "detail": "x"}


def _auth_headers(raw_token):
    return {"Authorization": f"Bearer {raw_token}"}


# --------------------------------------------------------------------------
# evaluate_gate() - pure blocking semantics.
# --------------------------------------------------------------------------

def test_empty_findings_passes():
    gate = evaluate_gate([])
    assert gate["passed"] is True
    assert gate["blocking_findings"] == []
    assert gate["blocking_count"] == 0


def test_default_fail_on_is_high():
    assert evaluate_gate([_finding("medium")])["passed"] is True
    assert evaluate_gate([_finding("high")])["passed"] is False
    assert evaluate_gate([_finding("critical")])["passed"] is False


def test_info_and_low_never_block_at_default():
    gate = evaluate_gate([_finding("info"), _finding("low")])
    assert gate["passed"] is True
    assert gate["fail_on"] == "high"


def test_medium_does_not_block_at_default_high():
    gate = evaluate_gate([_finding("medium"), _finding("medium")])
    assert gate["passed"] is True
    assert gate["blocking_count"] == 0


def test_blocking_findings_preserve_full_dicts_and_order():
    high = _finding("high", "The high one")
    critical = _finding("critical", "The critical one")
    gate = evaluate_gate([_finding("low"), high, critical])
    # Report order preserved; only at-or-above-threshold entries included;
    # full serialized finding dicts passed through untouched.
    assert gate["blocking_findings"] == [high, critical]
    assert gate["blocking_count"] == 2


def test_fail_on_critical_lets_high_through():
    gate = evaluate_gate([_finding("high"), _finding("medium")], fail_on="critical")
    assert gate["passed"] is True
    gate = evaluate_gate([_finding("critical")], fail_on="critical")
    assert gate["passed"] is False


def test_fail_on_low_is_inclusive():
    gate = evaluate_gate([_finding("low")], fail_on="low")
    assert gate["passed"] is False
    gate = evaluate_gate([_finding("info")], fail_on="low")
    assert gate["passed"] is True


def test_fail_on_info_blocks_everything_but_pass_severity():
    gate = evaluate_gate([_finding("info")], fail_on="info")
    assert gate["passed"] is False


def test_pass_severity_never_blocks_even_at_fail_on_info():
    # "pass" is the absence of a problem (checks.py SEVERITY_ORDER) and is
    # deliberately outside GATE_SEVERITIES - it must never block a deploy,
    # no matter how low the threshold is set.
    assert "pass" not in GATE_SEVERITIES
    gate = evaluate_gate([_finding("pass")], fail_on="info")
    assert gate["passed"] is True
    assert gate["blocking_count"] == 0


def test_malformed_or_missing_severity_ignored_not_fatal():
    # A report from an older engine version (or a hand-built fixture) must
    # not crash a CI pipeline - unrecognized severities are skipped.
    gate = evaluate_gate(
        [{"category": "X", "title": "no severity"}, {"severity": None},
         {"severity": "blocker-ish"}, "not-even-a-dict"],
    )
    assert gate["passed"] is True


def test_invalid_fail_on_raises_value_error():
    with pytest.raises(ValueError):
        evaluate_gate([], fail_on="PASS")
    with pytest.raises(ValueError):
        evaluate_gate([], fail_on="apocalyptic")


# --------------------------------------------------------------------------
# GET /api/v1/scans/<id>/gate - auth, ownership parity with fetch_report,
# error branches, payload shape.
# --------------------------------------------------------------------------

def _add_report(db, scan, data, json_path="unused.json"):
    """Creates the linking Report row with the JSON blob stored directly in
    Report.data (the column every read path prefers) - no on-disk file
    needed, since _load_report_json only falls back to the file when data
    is NULL."""
    r = Report(scan_id=scan.id, json_path=json_path, data=data)
    db.session.add(r)
    db.session.commit()
    return r


def _completed_scan_with_report(db, user, org=None, asset=None, findings=None):
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    if asset is not None:
        scan.asset_id = asset.id
    db.session.commit()
    _add_report(db, scan, {
        "score": 70,
        "risk_grade": "C",
        "severity_counts": {"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 1, "pass": 0},
        "findings": findings if findings is not None else [
            _finding("high", "SQL injection in search"),
            _finding("medium", "Missing CSP"),
            _finding("low", "Verbose server header"),
            _finding("info", "No CAA record"),
            _finding("pass", "HSTS present"),
        ],
    })
    return scan


def test_no_token_gets_401_json(client, db):
    resp = client.get("/api/v1/scans/1/gate")
    assert resp.status_code == 401
    assert resp.is_json


def test_nonexistent_scan_gets_404(client, db):
    org = make_org(name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")

    resp = client.get("/api/v1/scans/9999/gate", headers=_auth_headers(raw_token))

    assert resp.status_code == 404
    assert resp.is_json


def test_gate_passes_clean_report_payload_shape(client, db):
    org = make_org(plan=Plan.PAID, name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    scan = _completed_scan_with_report(db, user, org=org, findings=[_finding("medium")])

    resp = client.get(f"/api/v1/scans/{scan.id}/gate", headers=_auth_headers(raw_token))

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["passed"] is True
    assert body["fail_on"] == "high"  # default threshold when unspecified
    assert body["blocking_findings"] == []
    assert body["blocking_count"] == 0
    assert body["scan_id"] == scan.id
    assert body["scan_status"] == "completed"
    assert body["score"] == 70
    assert body["risk_grade"] == "C"
    assert body["target_url"] == scan.target_url


def test_gate_fails_on_high_finding_by_default(client, db):
    org = make_org(name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    scan = _completed_scan_with_report(db, user, org=org)

    resp = client.get(f"/api/v1/scans/{scan.id}/gate", headers=_auth_headers(raw_token))

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["passed"] is False
    assert body["blocking_count"] == 1
    assert [f["title"] for f in body["blocking_findings"]] == ["SQL injection in search"]
    assert body["severity_counts"]["high"] == 1


def test_fail_on_query_param_respected(client, db):
    org = make_org(name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    scan = _completed_scan_with_report(db, user, org=org)

    resp = client.get(
        f"/api/v1/scans/{scan.id}/gate?fail_on=critical", headers=_auth_headers(raw_token),
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["fail_on"] == "critical"
    assert body["passed"] is True  # only a high finding present


def test_invalid_fail_on_gets_400_json(client, db):
    org = make_org(name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    scan = _completed_scan_with_report(db, user, org=org)

    resp = client.get(
        f"/api/v1/scans/{scan.id}/gate?fail_on=nonsense", headers=_auth_headers(raw_token),
    )

    assert resp.status_code == 400
    assert resp.is_json
    assert "fail_on" in resp.get_json()["error"]


def test_running_scan_with_no_report_yet_gets_404(client, db):
    org = make_org(name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    scan = make_scan(user, org=org, status=ScanStatus.RUNNING)
    db.session.commit()

    resp = client.get(f"/api/v1/scans/{scan.id}/gate", headers=_auth_headers(raw_token))

    assert resp.status_code == 404
    assert resp.is_json
    assert resp.get_json()["error"] == "report not available"


def test_unreadable_report_blob_gets_500_json_not_html(client, db):
    # WR-02 parity: Report row exists but data is NULL and the json_path
    # points nowhere - must stay JSON for cli/wvs.py's error parser.
    org = make_org(name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()
    _add_report(db, scan, data=None, json_path="this-file-does-not-exist.json")

    resp = client.get(f"/api/v1/scans/{scan.id}/gate", headers=_auth_headers(raw_token))

    assert resp.status_code == 500
    assert resp.is_json
    assert resp.get_json()["error"]


def test_cross_org_asset_linked_scan_gets_404(client, db):
    org_a = make_org(name="Org A")
    org_b = make_org(name="Org B")
    user_a = make_user("a@example.com", org=org_a)
    user_b = make_user("b@example.com", org=org_b)
    db.session.commit()
    _, raw_token_b = make_api_token(user_b, name="b-tok")
    a = make_asset(org_a, user_a, name="Asset A")
    scan = _completed_scan_with_report(db, user_a, org=org_a, asset=a)

    resp = client.get(f"/api/v1/scans/{scan.id}/gate", headers=_auth_headers(raw_token_b))

    assert resp.status_code == 404


def test_manual_scan_non_owner_member_gets_404(client, db):
    # Same _check_ownership rule as fetch_report: a non-owner MEMBER of the
    # owning org cannot gate someone else's manual scan.
    org = make_org(name="Org")
    owner = make_user("owner@example.com", org=org, role=Role.MEMBER)
    member = make_user("member@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(member, name="tok")
    scan = _completed_scan_with_report(db, owner, org=org)  # manual: no asset_id

    resp = client.get(f"/api/v1/scans/{scan.id}/gate", headers=_auth_headers(raw_token))

    assert resp.status_code == 404


def test_manual_scan_org_admin_gets_200(client, db):
    # The ORG_ADMIN half of the same _check_ownership predicate. Kept as its
    # own test rather than a second request in one test body: the db fixture
    # holds a single app context open across requests and Flask-Login caches
    # the resolved user in `g` per app context - a second request in the
    # same context would silently inherit the FIRST caller's identity, so
    # per-request assertions here must stay one-request-per-test (a test-
    # harness constraint only; real requests each get their own context).
    org = make_org(name="Org")
    owner = make_user("owner@example.com", org=org, role=Role.MEMBER)
    admin = make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()
    _, raw_token = make_api_token(admin, name="tok")
    scan = _completed_scan_with_report(db, owner, org=org)  # manual: no asset_id

    resp = client.get(f"/api/v1/scans/{scan.id}/gate", headers=_auth_headers(raw_token))

    assert resp.status_code == 200


def test_asset_linked_org_member_can_gate_shared_asset_scan(client, db):
    from glassbox.models import Plan, Role

    org = make_org(plan=Plan.PAID, name="Org")
    creator = make_user("creator@example.com", org=org, role=Role.ORG_ADMIN)
    member = make_user("member@example.com", org=org, role=Role.MEMBER)
    db.session.commit()
    _, raw_token = make_api_token(member, name="member-tok")
    a = make_asset(org, creator, name="Shared asset")
    scan = _completed_scan_with_report(db, creator, org=org, asset=a)

    resp = client.get(f"/api/v1/scans/{scan.id}/gate", headers=_auth_headers(raw_token))

    assert resp.status_code == 200  # same _check_asset_access model as fetch_report


def test_soft_deleted_asset_gate_gets_404(client, db):
    from datetime import datetime

    from glassbox.models import Plan

    org = make_org(plan=Plan.PAID, name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    a = make_asset(org, user, name="Deleted asset",
                   deleted_at=datetime.now(UTC))
    scan = _completed_scan_with_report(db, user, org=org, asset=a)

    resp = client.get(f"/api/v1/scans/{scan.id}/gate", headers=_auth_headers(raw_token))

    assert resp.status_code == 404  # WR-01 parity: deleted Asset hides its scans
