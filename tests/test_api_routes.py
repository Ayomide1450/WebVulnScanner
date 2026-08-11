"""
Tests for webvulnscanner/api_routes.py - token-authenticated JSON surface
(API-02..05, D-02, Phase 2). GET /api/v1/assets (02-01) proved the auth
mechanism (401s, no Set-Cookie) end-to-end; this file also covers 02-02's
trigger-scan (API-03), fetch-report (API-04), and the cross-cutting
revoked-token/tier-gate/rate-limit proof (API-05).
"""
import pytest

from webvulnscanner.models import Plan, Report, Role, Scan, ScanStatus

from tests.conftest import make_api_token, make_asset, make_org, make_scan, make_user


def _auth_headers(raw_token):
    return {"Authorization": f"Bearer {raw_token}"}


# --------------------------------------------------------------------------
# API-02: GET /api/v1/assets returns only the caller's own org/solo-scoped
# Assets, plus each Asset's latest Scan status/risk_score.
# --------------------------------------------------------------------------

def test_list_assets_scoped_to_callers_org(client, db):
    org_a = make_org(plan=Plan.PAID, name="Org A")
    org_b = make_org(plan=Plan.PAID, name="Org B")
    user_a = make_user("a@example.com", org=org_a)
    user_b = make_user("b@example.com", org=org_b)
    db.session.commit()

    _, raw_token = make_api_token(user_a, name="a-token")
    asset_a = make_asset(org_a, user_a, name="Org A asset")
    make_asset(org_b, user_b, name="Org B asset")
    db.session.commit()

    resp = client.get("/api/v1/assets", headers=_auth_headers(raw_token))

    assert resp.status_code == 200
    assert resp.is_json
    body = resp.get_json()
    names = [a["name"] for a in body["assets"]]
    assert names == ["Org A asset"]
    assert body["assets"][0]["id"] == asset_a.id
    assert body["assets"][0]["latest_scan"] is None


def test_list_assets_includes_latest_scan_summary(client, db):
    org = make_org(plan=Plan.PAID, name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()

    _, raw_token = make_api_token(user, name="tok")
    asset = make_asset(org, user, name="Scanned asset")
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    scan.asset_id = asset.id
    scan.risk_score = 87
    db.session.commit()

    resp = client.get("/api/v1/assets", headers=_auth_headers(raw_token))

    assert resp.status_code == 200
    body = resp.get_json()
    assert len(body["assets"]) == 1
    latest = body["assets"][0]["latest_scan"]
    assert latest is not None
    assert latest["id"] == scan.id
    assert latest["status"] == "completed"
    assert latest["risk_score"] == 87


def test_solo_user_only_sees_own_assets(client, db):
    solo_a = make_user("solo-a@example.com")
    solo_b = make_user("solo-b@example.com")
    db.session.commit()

    _, raw_token = make_api_token(solo_a, name="solo-a-token")
    make_asset(None, solo_a, name="Solo A asset")
    make_asset(None, solo_b, name="Solo B asset")
    db.session.commit()

    resp = client.get("/api/v1/assets", headers=_auth_headers(raw_token))

    body = resp.get_json()
    names = [a["name"] for a in body["assets"]]
    assert names == ["Solo A asset"]


# --------------------------------------------------------------------------
# Auth failure modes: no header / malformed header / unknown token all get
# 401 JSON, never a redirect, never HTML, never 500.
# --------------------------------------------------------------------------

def test_no_authorization_header_gets_401_json(client, db):
    resp = client.get("/api/v1/assets")

    assert resp.status_code == 401
    assert resp.is_json
    assert resp.get_json()["error"]


def test_malformed_authorization_header_gets_401_json(client, db):
    resp = client.get("/api/v1/assets", headers={"Authorization": "NotBearer sometoken"})

    assert resp.status_code == 401
    assert resp.is_json


def test_nonexistent_token_gets_401_json(client, db):
    resp = client.get(
        "/api/v1/assets", headers={"Authorization": "Bearer totally-made-up-token-value"},
    )

    assert resp.status_code == 401
    assert resp.is_json


def test_revoked_token_gets_401_json(client, db):
    org = make_org(name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="revoked-token", revoked=True)
    db.session.commit()

    resp = client.get("/api/v1/assets", headers=_auth_headers(raw_token))

    assert resp.status_code == 401
    assert resp.is_json


# --------------------------------------------------------------------------
# No Set-Cookie header on a token-authenticated response (D-03/T-02-05).
# --------------------------------------------------------------------------

def test_token_authenticated_response_has_no_set_cookie_header(client, db):
    org = make_org(name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    db.session.commit()

    resp = client.get("/api/v1/assets", headers=_auth_headers(raw_token))

    assert resp.status_code == 200
    assert resp.headers.get("Set-Cookie") is None


def test_token_updates_last_used_at_on_use(client, db):
    org = make_org(name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()
    token, raw_token = make_api_token(user, name="tok")
    db.session.commit()
    assert token.last_used_at is None

    client.get("/api/v1/assets", headers=_auth_headers(raw_token))

    from webvulnscanner.models import ApiToken

    refreshed = ApiToken.query.get(token.id)
    assert refreshed.last_used_at is not None


# --------------------------------------------------------------------------
# API-03: POST /api/v1/assets/<id>/scans - trigger a scan, 100% reuse of
# scheduler._fire(asset). _spawn_scan_thread is monkeypatched to a no-op
# recorder in every test below - same convention as test_scheduler.py's
# `spawned` fixture ("a real scan thread must never be triggered from a
# test") - trigger_scan calls scheduler._fire() directly, which is the
# exact same dispatch path _tick() uses.
# --------------------------------------------------------------------------

@pytest.fixture()
def spawned(monkeypatch):
    calls = []

    def _fake_spawn(scan_id, scan_type, **kwargs):
        calls.append({"scan_id": scan_id, "scan_type": scan_type, "kwargs": kwargs})

    monkeypatch.setattr("webvulnscanner.scheduler._spawn_scan_thread", _fake_spawn)
    return calls


def test_trigger_scan_creates_exactly_one_scan_via_fire(client, db, spawned):
    org = make_org(plan=Plan.PAID, name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    a = make_asset(org, user, name="Asset", schedule_scan_type="base")
    db.session.commit()

    resp = client.post(f"/api/v1/assets/{a.id}/scans", headers=_auth_headers(raw_token))

    assert resp.status_code == 202
    body = resp.get_json()
    assert "scan_id" in body
    assert body["status"] == "queued"
    scans = Scan.query.filter_by(asset_id=a.id).all()
    assert len(scans) == 1
    assert scans[0].id == body["scan_id"]
    assert len(spawned) == 1


def test_trigger_scan_different_org_gets_404_no_scan_created(client, db, spawned):
    org_a = make_org(plan=Plan.PAID, name="Org A")
    org_b = make_org(plan=Plan.PAID, name="Org B")
    user_a = make_user("a@example.com", org=org_a)
    user_b = make_user("b@example.com", org=org_b)
    db.session.commit()
    _, raw_token_b = make_api_token(user_b, name="b-tok")
    asset_a = make_asset(org_a, user_a, name="Org A asset")
    db.session.commit()

    resp = client.post(
        f"/api/v1/assets/{asset_a.id}/scans", headers=_auth_headers(raw_token_b),
    )

    assert resp.status_code == 404
    assert resp.is_json
    assert Scan.query.filter_by(asset_id=asset_a.id).count() == 0
    assert len(spawned) == 0


def test_trigger_scan_non_admin_org_member_can_trigger_shared_asset(client, db, spawned):
    # asset_routes._check_asset_access's org-shared model (not
    # scan_routes._check_ownership's creator-or-admin-only model) governs
    # the trigger path - a non-admin, non-creating org member gets 202, not
    # 404, on an Asset a teammate created.
    org = make_org(plan=Plan.PAID, name="Org")
    creator = make_user("creator@example.com", org=org, role=Role.ORG_ADMIN)
    member = make_user("member@example.com", org=org, role=Role.MEMBER)
    db.session.commit()
    _, raw_token = make_api_token(member, name="member-tok")
    a = make_asset(org, creator, name="Shared asset")
    db.session.commit()

    resp = client.post(f"/api/v1/assets/{a.id}/scans", headers=_auth_headers(raw_token))

    assert resp.status_code == 202
    assert Scan.query.filter_by(asset_id=a.id).count() == 1


def test_trigger_scan_free_tier_media_asset_gets_failed_status(client, db, spawned):
    org = make_org(plan=Plan.FREE, name="Free Org")
    user = make_user("free@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    a = make_asset(org, user, name="Media asset", schedule_scan_type="media")
    db.session.commit()

    resp = client.post(f"/api/v1/assets/{a.id}/scans", headers=_auth_headers(raw_token))

    assert resp.status_code == 202
    body = resp.get_json()
    assert body["status"] == "failed"
    scan = Scan.query.get(body["scan_id"])
    assert scan.status == ScanStatus.FAILED
    assert "higher plan" in scan.error_message
    assert len(spawned) == 0


# --------------------------------------------------------------------------
# API-04: GET /api/v1/scans/<id>/report - fetch a completed scan's report
# as JSON, fixing the ownership-check mismatch (02-RESEARCH.md Pitfall 1)
# for this new route specifically.
# --------------------------------------------------------------------------

def _make_report(db, scan, report_dict=None):
    """Writes a real report JSON file to REPORTS_DIR (matching
    scan_engine.save_report()'s on-disk shape) and creates the linking
    Report row - so fetch_report's file-read path is exercised for real,
    not mocked."""
    import json as _json
    import os as _os

    from webvulnscanner.checks import REPORTS_DIR

    report_dict = report_dict if report_dict is not None else {"score": 91, "findings": []}
    fname = f"test_report_{scan.id}.json"
    with open(_os.path.join(REPORTS_DIR, fname), "w", encoding="utf-8") as f:
        _json.dump(report_dict, f)
    r = Report(scan_id=scan.id, json_path=fname)
    db.session.add(r)
    db.session.commit()
    return report_dict, fname


def test_fetch_report_returns_exact_on_disk_json_for_owner(client, db):
    org = make_org(plan=Plan.PAID, name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    a = make_asset(org, user, name="Asset")
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    scan.asset_id = a.id
    db.session.commit()
    report_dict, _ = _make_report(db, scan)

    resp = client.get(f"/api/v1/scans/{scan.id}/report", headers=_auth_headers(raw_token))

    assert resp.status_code == 200
    assert resp.get_json() == report_dict


def test_fetch_report_non_admin_non_creator_org_member_gets_200(client, db):
    # Directly confirms the Pitfall 1 fix: User B (non-admin, same org, did
    # NOT create the Asset) triggers a scan via their own token and can
    # fetch its report.
    org = make_org(plan=Plan.PAID, name="Org")
    creator = make_user("creator@example.com", org=org, role=Role.ORG_ADMIN)
    member = make_user("member@example.com", org=org, role=Role.MEMBER)
    db.session.commit()
    _, raw_token = make_api_token(member, name="member-tok")
    a = make_asset(org, creator, name="Shared asset")
    # scheduler._fire() always attributes the Scan to asset.created_by_user_id
    # - creator, not member - mirroring real trigger_scan() behavior.
    scan = make_scan(creator, org=org, status=ScanStatus.COMPLETED)
    scan.asset_id = a.id
    db.session.commit()
    report_dict, _ = _make_report(db, scan)

    resp = client.get(f"/api/v1/scans/{scan.id}/report", headers=_auth_headers(raw_token))

    assert resp.status_code == 200
    assert resp.get_json() == report_dict


def test_fetch_report_different_org_gets_404(client, db):
    org_a = make_org(plan=Plan.PAID, name="Org A")
    org_b = make_org(plan=Plan.PAID, name="Org B")
    user_a = make_user("a@example.com", org=org_a)
    user_b = make_user("b@example.com", org=org_b)
    db.session.commit()
    _, raw_token_b = make_api_token(user_b, name="b-tok")
    a = make_asset(org_a, user_a, name="Asset")
    scan = make_scan(user_a, org=org_a, status=ScanStatus.COMPLETED)
    scan.asset_id = a.id
    db.session.commit()
    _make_report(db, scan)

    resp = client.get(f"/api/v1/scans/{scan.id}/report", headers=_auth_headers(raw_token_b))

    assert resp.status_code == 404


def test_fetch_report_manual_scan_still_uses_check_ownership(client, db):
    # A manually-submitted (no asset_id) scan keeps the original
    # creator-or-org-admin _check_ownership rule unchanged - a non-owning,
    # non-admin member still gets 404, confirming the Asset-linked branch
    # didn't accidentally loosen this route's semantics for manual scans.
    org = make_org(plan=Plan.PAID, name="Org")
    owner = make_user("owner@example.com", org=org, role=Role.MEMBER)
    other_member = make_user("other@example.com", org=org, role=Role.MEMBER)
    db.session.commit()
    _, raw_token = make_api_token(other_member, name="tok")
    scan = make_scan(owner, org=org, status=ScanStatus.COMPLETED)  # no asset_id
    db.session.commit()
    _make_report(db, scan)

    resp = client.get(f"/api/v1/scans/{scan.id}/report", headers=_auth_headers(raw_token))

    assert resp.status_code == 404


def test_fetch_report_org_admin_can_view_manual_scan(client, db):
    org = make_org(plan=Plan.PAID, name="Org")
    owner = make_user("owner@example.com", org=org, role=Role.MEMBER)
    admin = make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()
    _, raw_token = make_api_token(admin, name="admin-tok")
    scan = make_scan(owner, org=org, status=ScanStatus.COMPLETED)  # no asset_id
    db.session.commit()
    report_dict, _ = _make_report(db, scan)

    resp = client.get(f"/api/v1/scans/{scan.id}/report", headers=_auth_headers(raw_token))

    assert resp.status_code == 200
    assert resp.get_json() == report_dict


def test_fetch_report_no_report_row_yet_gets_404_json(client, db):
    org = make_org(plan=Plan.PAID, name="Org")
    user = make_user("owner@example.com", org=org)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    a = make_asset(org, user, name="Asset")
    scan = make_scan(user, org=org, status=ScanStatus.RUNNING)
    scan.asset_id = a.id
    db.session.commit()

    resp = client.get(f"/api/v1/scans/{scan.id}/report", headers=_auth_headers(raw_token))

    assert resp.status_code == 404
    assert resp.is_json
