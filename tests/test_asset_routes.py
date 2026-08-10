"""
Tests for webvulnscanner/asset_routes.py - Asset registration + inventory
list routes (Phase 1, ASSET-01/02, tracer plan 01-01).
"""
import socket

import pytest

from webvulnscanner.models import Asset, Plan

from tests.conftest import login, make_asset, make_org, make_user


@pytest.fixture()
def logged_in_client(db, client):
    org = make_org(plan=Plan.PAID, name="Asset Org")
    make_user("registrant@example.com", org=org)
    login(client, "registrant@example.com")
    return client


def _fake_getaddrinfo_public(*a, **k):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]


def _fake_getaddrinfo_private(*a, **k):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]


# --------------------------------------------------------------------------
# ASSET-01: registration creates a row, distinct from a one-off Scan, and
# appears in the inventory list scoped to the registering user's org.
# --------------------------------------------------------------------------

def test_post_new_asset_valid_creates_asset_and_redirects(logged_in_client, db, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo_public)

    resp = logged_in_client.post(
        "/assets/new",
        data={
            "name": "Marketing site",
            "target": "example.com",
            "cadence": "daily",
            "schedule_scan_type": "base",
            "authorized": "on",
        },
        follow_redirects=False,
    )

    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/assets")
    assets = Asset.query.all()
    assert len(assets) == 1
    assert assets[0].name == "Marketing site"
    assert assets[0].cadence == "daily"
    assert assets[0].schedule_scan_type == "base"
    assert assets[0].next_run_at is not None


def test_registered_asset_appears_in_list(logged_in_client, db, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo_public)

    logged_in_client.post(
        "/assets/new",
        data={
            "name": "Marketing site",
            "target": "example.com",
            "cadence": "weekly",
            "schedule_scan_type": "base",
            "authorized": "on",
        },
        follow_redirects=False,
    )

    resp = logged_in_client.get("/assets")
    assert resp.status_code == 200
    assert b"Marketing site" in resp.data


# --------------------------------------------------------------------------
# ASSET-02: registration enforces the same authorized-checkbox +
# is_ssrf_safe_hostname gate as manual scan submission, with matching copy.
# --------------------------------------------------------------------------

def test_post_new_asset_missing_authorized_checkbox_is_rejected(logged_in_client, db, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo_public)

    resp = logged_in_client.post(
        "/assets/new",
        data={
            "name": "Marketing site", "target": "example.com",
            "cadence": "daily", "schedule_scan_type": "base",
        },
        follow_redirects=False,
    )

    assert resp.status_code == 200
    assert b"authorized" in resp.data.lower()
    assert Asset.query.count() == 0


def test_post_new_asset_unsafe_target_is_rejected(logged_in_client, db, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo_private)

    resp = logged_in_client.post(
        "/assets/new",
        data={
            "name": "Marketing site", "target": "127.0.0.1",
            "cadence": "daily", "schedule_scan_type": "base",
            "authorized": "on",
        },
        follow_redirects=False,
    )

    assert resp.status_code == 200
    assert b"private" in resp.data.lower() or b"internal" in resp.data.lower()
    assert Asset.query.count() == 0


def test_post_new_asset_invalid_cadence_is_rejected(logged_in_client, db, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo_public)

    resp = logged_in_client.post(
        "/assets/new",
        data={
            "name": "Marketing site", "target": "example.com",
            "cadence": "hourly", "schedule_scan_type": "base",
            "authorized": "on",
        },
        follow_redirects=False,
    )

    assert resp.status_code == 200
    assert Asset.query.count() == 0


def test_post_new_asset_invalid_scan_type_is_rejected(logged_in_client, db, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo_public)

    resp = logged_in_client.post(
        "/assets/new",
        data={
            "name": "Marketing site", "target": "example.com",
            "cadence": "daily", "schedule_scan_type": "advanced",
            "authorized": "on",
        },
        follow_redirects=False,
    )

    assert resp.status_code == 200
    assert Asset.query.count() == 0


# --------------------------------------------------------------------------
# Ownership/scoping: GET /assets lists only the current org's (or solo
# user's own) Assets.
# --------------------------------------------------------------------------

def test_list_assets_scoped_to_org_excludes_other_orgs_assets(db, client):
    org_a = make_org(plan=Plan.PAID, name="Org A")
    user_a = make_user("member-a@example.com", org=org_a)
    make_asset(org_a, user_a, name="Org A Asset")

    org_b = make_org(plan=Plan.PAID, name="Org B")
    user_b = make_user("member-b@example.com", org=org_b)
    make_asset(org_b, user_b, name="Org B Asset")
    db.session.commit()

    login(client, "member-a@example.com")
    resp = client.get("/assets")

    assert b"Org A Asset" in resp.data
    assert b"Org B Asset" not in resp.data


def test_two_solo_users_never_see_each_others_assets(db, client):
    solo_a = make_user("solo-a@example.com", org=None)
    make_asset(None, solo_a, name="Solo A Asset")

    solo_b = make_user("solo-b@example.com", org=None)
    make_asset(None, solo_b, name="Solo B Asset")
    db.session.commit()

    login(client, "solo-a@example.com")
    resp = client.get("/assets")

    assert b"Solo A Asset" in resp.data
    assert b"Solo B Asset" not in resp.data
