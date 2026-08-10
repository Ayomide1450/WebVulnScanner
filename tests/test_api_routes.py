"""
Tests for webvulnscanner/api_routes.py - token-authenticated JSON surface
(API-02, D-02, Phase 2 tracer plan 02-01). GET /api/v1/assets is the one
route this plan proves end-to-end; the auth mechanism itself (401s, no
Set-Cookie) is exercised here too since it's this route's job to prove it.
"""
from webvulnscanner.models import Plan, ScanStatus

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
