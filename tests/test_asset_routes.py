"""
Tests for webvulnscanner/asset_routes.py - Asset registration + inventory
list routes (Phase 1, ASSET-01/02, tracer plan 01-01) and Asset detail /
schedule-editing / pause / resume / delete routes (Phase 1,
ASSET-03/05/06, plan 01-02).
"""
import socket
from datetime import datetime, timedelta, timezone

import pytest

from webvulnscanner.models import Asset, Plan, Scan, ScanStatus

from tests.conftest import login, make_asset, make_org, make_user


def _as_aware(dt):
    """SQLite (unlike Postgres) doesn't preserve tzinfo on round-trip
    through a DateTime(timezone=True) column - a value read back after a
    commit comes back naive even though it was written tz-aware. Test-only
    normalization so assertions can safely compare against a fresh
    tz-aware datetime.now(timezone.utc). Same convention as
    tests/test_scheduler.py's _as_aware helper."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


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


# --------------------------------------------------------------------------
# ASSET-03/05: Asset detail page - schedule editing + scan history/trend
# (plan 01-02).
# --------------------------------------------------------------------------

def test_get_asset_detail_shows_schedule_and_empty_history(db, client):
    org = make_org(plan=Plan.PAID, name="Detail Org")
    user = make_user("detail-owner@example.com", org=org)
    make_asset(org, user, name="Empty History Asset", cadence="weekly", schedule_scan_type="base")
    db.session.commit()

    login(client, "detail-owner@example.com")
    a = Asset.query.filter_by(name="Empty History Asset").first()
    resp = client.get(f"/assets/{a.id}")

    assert resp.status_code == 200
    assert b"Empty History Asset" in resp.data
    assert b"hasn" in resp.data and b"scanned yet" in resp.data
    assert b"Weekly" in resp.data


def test_get_asset_detail_shows_populated_scan_history(db, client):
    org = make_org(plan=Plan.PAID, name="Detail Org 2")
    user = make_user("detail-owner2@example.com", org=org)
    a = make_asset(org, user, name="Populated Asset")
    s = Scan(
        asset_id=a.id, user_id=user.id, org_id=org.id,
        target_url=a.target_url, scan_type="base",
        status=ScanStatus.COMPLETED, risk_score=88,
    )
    db.session.add(s)
    db.session.commit()

    login(client, "detail-owner2@example.com")
    resp = client.get(f"/assets/{a.id}")

    assert resp.status_code == 200
    assert b"88" in resp.data
    assert b"completed" in resp.data.lower()


def test_get_asset_detail_for_other_org_is_404(db, client):
    org_a = make_org(plan=Plan.PAID, name="Owner Org")
    user_a = make_user("owner@example.com", org=org_a)
    a = make_asset(org_a, user_a, name="Owner Asset")

    org_b = make_org(plan=Plan.PAID, name="Other Org")
    make_user("other@example.com", org=org_b)
    db.session.commit()
    asset_id = a.id

    login(client, "other@example.com")
    resp = client.get(f"/assets/{asset_id}")

    assert resp.status_code == 404


def test_post_schedule_valid_update_persists_and_recomputes_next_run(db, client):
    org = make_org(plan=Plan.PAID, name="Schedule Org")
    user = make_user("schedule-owner@example.com", org=org)
    a = make_asset(
        org, user, cadence="daily", schedule_scan_type="base",
        next_run_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    db.session.commit()
    asset_id = a.id

    login(client, "schedule-owner@example.com")
    resp = client.post(
        f"/assets/{asset_id}/schedule",
        data={"cadence": "monthly", "schedule_scan_type": "media"},
        follow_redirects=False,
    )

    assert resp.status_code == 302
    updated = Asset.query.get(asset_id)
    assert updated.cadence == "monthly"
    assert updated.schedule_scan_type == "media"
    assert _as_aware(updated.next_run_at) > datetime.now(timezone.utc) + timedelta(days=20)


def test_post_schedule_invalid_value_rejected_and_row_unchanged(db, client):
    org = make_org(plan=Plan.PAID, name="Schedule Org 2")
    user = make_user("schedule-owner2@example.com", org=org)
    a = make_asset(org, user, cadence="daily", schedule_scan_type="base")
    db.session.commit()
    asset_id = a.id
    original_cadence = a.cadence
    original_scan_type = a.schedule_scan_type

    login(client, "schedule-owner2@example.com")
    resp = client.post(
        f"/assets/{asset_id}/schedule",
        data={"cadence": "hourly", "schedule_scan_type": "base"},
        follow_redirects=False,
    )

    assert resp.status_code == 200
    assert b"Choose a valid cadence and scan type." in resp.data
    unchanged = Asset.query.get(asset_id)
    assert unchanged.cadence == original_cadence
    assert unchanged.schedule_scan_type == original_scan_type


def test_schedule_tier_locked_hint_renders_when_over_org_tier(db, client):
    org = make_org(plan=Plan.FREE, name="Free Org")
    user = make_user("free-owner@example.com", org=org)
    a = make_asset(org, user, cadence="daily", schedule_scan_type="media")
    db.session.commit()

    login(client, "free-owner@example.com")
    resp = client.get(f"/assets/{a.id}")

    assert resp.status_code == 200
    assert b"requires a" in resp.data
    assert b"Paid" in resp.data


def test_schedule_tier_locked_hint_absent_when_within_org_tier(db, client):
    org = make_org(plan=Plan.PAID, name="Paid Org")
    user = make_user("paid-owner@example.com", org=org)
    a = make_asset(org, user, cadence="daily", schedule_scan_type="media")
    db.session.commit()

    login(client, "paid-owner@example.com")
    resp = client.get(f"/assets/{a.id}")

    assert resp.status_code == 200
    assert b"requires a" not in resp.data


def test_schedule_tier_locked_hint_absent_for_base_schedule_type(db, client):
    # "base" has no single FEATURE_REQUIREMENTS entry (individual checks
    # within a base scan are gated separately) - the hint must never raise
    # a KeyError or render for it, even on a FREE org.
    org = make_org(plan=Plan.FREE, name="Free Org Base")
    user = make_user("free-base-owner@example.com", org=org)
    a = make_asset(org, user, cadence="daily", schedule_scan_type="base")
    db.session.commit()

    login(client, "free-base-owner@example.com")
    resp = client.get(f"/assets/{a.id}")

    assert resp.status_code == 200
    assert b"requires a" not in resp.data


# --------------------------------------------------------------------------
# ASSET-06: pause / resume / delete controls (plan 01-02).
# --------------------------------------------------------------------------

def test_pause_resume_delete_pause_excludes_asset_from_due_query(db, client):
    org = make_org(plan=Plan.PAID, name="Pause Org")
    user = make_user("pause-owner@example.com", org=org)
    a = make_asset(org, user, next_run_at=datetime.now(timezone.utc) - timedelta(minutes=5))
    db.session.commit()
    asset_id = a.id

    login(client, "pause-owner@example.com")
    resp = client.post(f"/assets/{asset_id}/pause", follow_redirects=False)

    assert resp.status_code == 302
    updated = Asset.query.get(asset_id)
    assert updated.is_paused is True

    now = datetime.now(timezone.utc)
    due = Asset.query.filter(
        Asset.is_paused.is_(False), Asset.deleted_at.is_(None), Asset.next_run_at <= now,
    ).all()
    assert asset_id not in [x.id for x in due]


def test_pause_resume_delete_resume_reincludes_asset_in_due_query(db, client):
    org = make_org(plan=Plan.PAID, name="Resume Org")
    user = make_user("resume-owner@example.com", org=org)
    a = make_asset(
        org, user, is_paused=True,
        next_run_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    db.session.commit()
    asset_id = a.id

    login(client, "resume-owner@example.com")
    resp = client.post(f"/assets/{asset_id}/resume", follow_redirects=False)

    assert resp.status_code == 302
    updated = Asset.query.get(asset_id)
    assert updated.is_paused is False

    now = datetime.now(timezone.utc)
    due = Asset.query.filter(
        Asset.is_paused.is_(False), Asset.deleted_at.is_(None), Asset.next_run_at <= now,
    ).all()
    assert asset_id in [x.id for x in due]


def test_pause_resume_delete_delete_soft_deletes_and_keeps_scan_history(db, client):
    org = make_org(plan=Plan.PAID, name="Delete Org")
    user = make_user("delete-owner@example.com", org=org)
    a = make_asset(org, user, name="Doomed Asset")
    s = Scan(
        asset_id=a.id, user_id=user.id, org_id=org.id,
        target_url=a.target_url, scan_type="base",
        status=ScanStatus.COMPLETED, risk_score=70,
    )
    db.session.add(s)
    db.session.commit()
    asset_id = a.id
    scan_id = s.id

    login(client, "delete-owner@example.com")
    resp = client.post(f"/assets/{asset_id}/delete", follow_redirects=False)

    assert resp.status_code == 302
    updated = Asset.query.get(asset_id)
    assert updated.deleted_at is not None

    list_resp = client.get("/assets")
    assert b"Doomed Asset" not in list_resp.data

    kept_scan = Scan.query.filter_by(asset_id=asset_id).first()
    assert kept_scan is not None
    assert kept_scan.id == scan_id


def test_pause_resume_delete_all_three_404_for_non_owning_org(db, client):
    org_a = make_org(plan=Plan.PAID, name="Owner Org 2")
    user_a = make_user("owner2@example.com", org=org_a)
    a = make_asset(org_a, user_a, name="Protected Asset")

    org_b = make_org(plan=Plan.PAID, name="Intruder Org")
    make_user("intruder@example.com", org=org_b)
    db.session.commit()
    asset_id = a.id

    login(client, "intruder@example.com")

    assert client.post(f"/assets/{asset_id}/pause", follow_redirects=False).status_code == 404
    assert client.post(f"/assets/{asset_id}/resume", follow_redirects=False).status_code == 404
    assert client.post(f"/assets/{asset_id}/delete", follow_redirects=False).status_code == 404
