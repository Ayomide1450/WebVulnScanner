"""
Tests for glassbox/asset_routes.py - Asset registration + inventory
list routes (Phase 1, ASSET-01/02, tracer plan 01-01) and Asset detail /
schedule-editing / pause / resume / delete routes (Phase 1,
ASSET-03/05/06, plan 01-02).
"""
import json
import os
import socket
from datetime import datetime, timedelta, timezone

import pytest

from glassbox.asset_routes import compliance_coverage, summarize_compliance
from glassbox.checks import REPORTS_DIR
from glassbox.extensions import db as _db
from glassbox.models import Asset, Plan, Report, Scan, ScanStatus

from tests.conftest import login, make_asset, make_org, make_user


def _write_report(scan, report_dict):
    """Writes a real report JSON file to REPORTS_DIR and creates the linking
    Report row - mirrors tests/test_api_routes.py's _make_report helper, so
    compliance_coverage()'s file-read path is exercised for real, not
    mocked."""
    fname = f"test_asset_report_{scan.id}_{scan.scan_type}.json"
    with open(os.path.join(REPORTS_DIR, fname), "w", encoding="utf-8") as f:
        json.dump(report_dict, f)
    r = Report(scan_id=scan.id, json_path=fname)
    _db.session.add(r)
    _db.session.commit()
    return fname


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


def test_schedule_cross_org_is_404_and_does_not_mutate_cadence_or_scan_type(db, client):
    # SEC-01 (08-01, Task 3): asserting only the 404 would still pass if the
    # mutation happened before _check_asset_access ran - re-reading the row
    # is the only assertion that catches that ordering bug.
    org_a = make_org(plan=Plan.PAID, name="Owner Org 2")
    user_a = make_user("owner2@example.com", org=org_a)
    a = make_asset(org_a, user_a, name="Protected Asset", cadence="daily", schedule_scan_type="base")

    org_b = make_org(plan=Plan.PAID, name="Intruder Org")
    make_user("intruder@example.com", org=org_b)
    db.session.commit()
    asset_id = a.id

    login(client, "intruder@example.com")
    resp = client.post(
        f"/assets/{asset_id}/schedule",
        data={"cadence": "weekly", "schedule_scan_type": "media"},
        follow_redirects=False,
    )

    assert resp.status_code == 404
    refreshed = Asset.query.get(asset_id)
    assert refreshed.cadence == "daily"
    assert refreshed.schedule_scan_type == "base"


# --------------------------------------------------------------------------
# COMP-03: summarize_compliance() - the pure checked/failing/not-checked
# aggregation (plan 03-03, Task 1). No DB, no filesystem - hand-built report
# dicts, following this module's existing plain-function test style.
# --------------------------------------------------------------------------

A01 = "A01:2021-Broken Access Control"
A02 = "A02:2021-Cryptographic Failures"
A03 = "A03:2021-Injection"
A04 = "A04:2021-Insecure Design"
A05 = "A05:2021-Security Misconfiguration"
A06 = "A06:2021-Vulnerable and Outdated Components"
A07 = "A07:2021-Identification and Authentication Failures"

# All 9 base-scan check names CHECK_COMPLIANCE maps to A05 - locking every
# one of them is how these tests simulate "no other executed check maps to
# that category" for a single-category not_checked/locked assertion.
# caching_sensitive (v1.3 Phase 14) also maps to A05.
A05_BASE_CHECK_NAMES = [
    "headers", "cookies", "sensitive_paths", "open_ports",
    "cors", "http_methods", "directory_listing", "dns_email",
    "caching_sensitive",
    # v1.5 Phase 20: these three are also CHECK_COMPLIANCE-owasp A05, so a
    # "whole category locked" fixture has to lock them too or summarize_
    # compliance correctly reports A05 as partially covered.
    "host_header", "cache_deception", "subdomain_takeover",
    # Phase 33 (OWGAP-01..04): new A05-mapped checks
    "xxe", "csp_depth", "hsts_depth", "dnssec",
]


def test_summarize_compliance_empty_input_returns_empty_list():
    assert summarize_compliance({}) == []


def test_summarize_compliance_clean_base_report_all_categories_passing():
    rows = summarize_compliance({"base": {"findings": [], "locked_checks": []}})

    assert rows
    assert all(r["status"] == "passing" for r in rows)
    # robots_sitemap's own CHECK_COMPLIANCE entry is the literal owasp value
    # "Uncategorized" - a legitimate, always-checked candidate category, not
    # a missing-mapping fallback - so it appears here too, as passing.
    assert any(r["owasp"] == "Uncategorized" for r in rows)


def test_summarize_compliance_one_finding_yields_failing_row_others_stay_passing():
    rows = summarize_compliance({
        "base": {
            "findings": [{"check_name": "xss_sqli", "severity": "high", "title": "XSS"}],
            "locked_checks": [],
        },
    })
    by_owasp = {r["owasp"]: r for r in rows}

    assert by_owasp[A03]["status"] == "failing"
    assert by_owasp[A03]["finding_count"] == 1
    assert by_owasp[A03]["top_severity"] == "high"
    assert by_owasp[A05]["status"] == "passing"


def test_summarize_compliance_two_findings_same_category_count_and_worst_severity():
    rows = summarize_compliance({
        "base": {
            "findings": [
                {"check_name": "xss_sqli", "severity": "medium", "title": "a"},
                {"check_name": "xss_sqli", "severity": "critical", "title": "b"},
            ],
            "locked_checks": [],
        },
    })
    by_owasp = {r["owasp"]: r for r in rows}

    assert by_owasp[A03]["status"] == "failing"
    assert by_owasp[A03]["finding_count"] == 2
    assert by_owasp[A03]["top_severity"] == "critical"


def test_summarize_compliance_all_checks_for_a_category_locked_is_not_checked_and_locked():
    rows = summarize_compliance({
        "base": {"findings": [], "locked_checks": A05_BASE_CHECK_NAMES},
    })
    by_owasp = {r["owasp"]: r for r in rows}

    assert by_owasp[A05]["status"] == "not_checked"
    assert by_owasp[A05]["locked"] is True
    # tls (A02) wasn't locked, so it must not be dragged into not_checked too.
    assert by_owasp[A02]["status"] == "passing"


def test_summarize_compliance_untagged_finding_makes_whole_report_not_checked():
    rows = summarize_compliance({
        "base": {
            "findings": [{"check_name": "", "severity": "high", "title": "legacy"}],
            "locked_checks": [],
        },
    })

    assert rows
    assert not any(r["status"] == "passing" for r in rows)
    assert all(r["status"] == "not_checked" for r in rows)


def test_summarize_compliance_unmapped_check_name_lands_in_uncategorized_last():
    rows = summarize_compliance({
        "base": {
            "findings": [{"check_name": "nosuchcheck", "severity": "low", "title": "t"}],
            "locked_checks": [],
        },
    })

    assert rows[-1]["owasp"] == "Uncategorized"
    assert rows[-1]["status"] == "failing"
    assert rows[-1]["finding_count"] == 1
    # ascending order for every mapped category before the trailing Uncategorized row.
    mapped = [r["owasp"] for r in rows[:-1]]
    assert mapped == sorted(mapped)


def test_summarize_compliance_no_finding_maps_to_uncategorized_omits_the_row():
    rows = summarize_compliance({
        "advanced": {"ran": ["idor"], "locked_checks": [], "findings": []},
    })

    assert not any(r["owasp"] == "Uncategorized" for r in rows)


def test_summarize_compliance_only_present_scan_types_contribute_candidate_rows():
    rows = summarize_compliance({
        "advanced": {
            "ran": ["sqli_login", "bruteforce", "sqli_union", "xss_stored", "idor",
                     "auth_comparison", "mass_assignment"],
            "locked_checks": [], "findings": [],
        },
    })
    owasp_values = {r["owasp"] for r in rows}

    # sqli_login/sqli_union/xss_stored all map to A03, bruteforce to A07,
    # idor and auth_comparison to A01, mass_assignment to A04 — four
    # distinct categories, none of them base-only ones.
    assert owasp_values == {A01, A03, A04, A07}
    assert A05 not in owasp_values
    assert A06 not in owasp_values
    assert all(r["status"] == "passing" for r in rows)


# --------------------------------------------------------------------------
# COMP-03: compliance_coverage() - load the newest completed report per scan
# type behind the existing _check_asset_access guard (plan 03-03, Task 2).
# --------------------------------------------------------------------------

def test_compliance_coverage_loads_newest_completed_base_report(db):
    org = make_org(plan=Plan.PAID, name="Coverage Org")
    user = make_user("coverage-owner@example.com", org=org)
    a = make_asset(org, user, name="Coverage Asset")
    _db.session.commit()

    scan = Scan(
        asset_id=a.id, user_id=user.id, org_id=org.id,
        target_url=a.target_url, scan_type="base",
        status=ScanStatus.COMPLETED, risk_score=95,
    )
    _db.session.add(scan)
    _db.session.commit()
    _write_report(scan, {
        "findings": [{"check_name": "xss_sqli", "severity": "high", "title": "XSS"}],
        "locked_checks": [],
    })

    coverage = compliance_coverage(a)

    assert coverage["scan_types"] == ["base"]
    by_owasp = {r["owasp"]: r for r in coverage["rows"]}
    assert by_owasp["A03:2021-Injection"]["status"] == "failing"


def test_compliance_coverage_skips_scan_whose_report_file_is_missing(db):
    org = make_org(plan=Plan.PAID, name="Missing File Org")
    user = make_user("missing-owner@example.com", org=org)
    a = make_asset(org, user, name="Missing File Asset")
    _db.session.commit()

    scan = Scan(
        asset_id=a.id, user_id=user.id, org_id=org.id,
        target_url=a.target_url, scan_type="base",
        status=ScanStatus.COMPLETED, risk_score=95,
    )
    _db.session.add(scan)
    _db.session.commit()
    r = Report(scan_id=scan.id, json_path="does_not_exist_on_disk.json")
    _db.session.add(r)
    _db.session.commit()

    coverage = compliance_coverage(a)

    assert coverage["rows"] == []
    assert coverage["scan_types"] == []


def test_compliance_coverage_aggregates_base_and_api_scan_types(db):
    org = make_org(plan=Plan.PAID, name="Multi-type Org")
    user = make_user("multi-owner@example.com", org=org)
    a = make_asset(org, user, name="Multi-type Asset")
    _db.session.commit()

    base_scan = Scan(
        asset_id=a.id, user_id=user.id, org_id=org.id,
        target_url=a.target_url, scan_type="base",
        status=ScanStatus.COMPLETED, risk_score=95,
    )
    api_scan = Scan(
        asset_id=a.id, user_id=user.id, org_id=org.id,
        target_url=a.target_url, scan_type="api",
        status=ScanStatus.COMPLETED, risk_score=90,
    )
    _db.session.add_all([base_scan, api_scan])
    _db.session.commit()
    _write_report(base_scan, {"findings": [], "locked_checks": []})
    _write_report(api_scan, {
        "findings": [{"check_name": "wordlist", "severity": "medium", "title": "Exposed"}],
        "results": {"schema": {}, "wordlist": {}, "js_discovery": {}},
    })

    coverage = compliance_coverage(a)

    assert coverage["scan_types"] == ["api", "base"]
    by_owasp = {r["owasp"]: r for r in coverage["rows"]}
    assert by_owasp["A01:2021-Broken Access Control"]["status"] == "failing"


def test_get_asset_detail_route_200_with_completed_scan_and_report(db, client):
    org = make_org(plan=Plan.PAID, name="Route Coverage Org")
    user = make_user("route-owner@example.com", org=org)
    a = make_asset(org, user, name="Route Coverage Asset")
    db.session.commit()

    scan = Scan(
        asset_id=a.id, user_id=user.id, org_id=org.id,
        target_url=a.target_url, scan_type="base",
        status=ScanStatus.COMPLETED, risk_score=95,
    )
    db.session.add(scan)
    db.session.commit()
    _write_report(scan, {"findings": [], "locked_checks": []})

    login(client, "route-owner@example.com")
    resp = client.get(f"/assets/{a.id}")

    assert resp.status_code == 200


def test_get_asset_detail_compliance_coverage_cross_org_is_404_and_leaks_no_category(db, client):
    org_a = make_org(plan=Plan.PAID, name="Coverage Owner Org")
    user_a = make_user("coverage-owner-a@example.com", org=org_a)
    a = make_asset(org_a, user_a, name="Coverage Owner Asset")

    org_b = make_org(plan=Plan.PAID, name="Coverage Intruder Org")
    make_user("coverage-intruder@example.com", org=org_b)
    db.session.commit()

    scan = Scan(
        asset_id=a.id, user_id=user_a.id, org_id=org_a.id,
        target_url=a.target_url, scan_type="base",
        status=ScanStatus.COMPLETED, risk_score=40,
    )
    db.session.add(scan)
    db.session.commit()
    _write_report(scan, {
        "findings": [{"check_name": "xss_sqli", "severity": "critical", "title": "XSS"}],
        "locked_checks": [],
    })
    asset_id = a.id

    login(client, "coverage-intruder@example.com")
    resp = client.get(f"/assets/{asset_id}")

    assert resp.status_code == 404
    assert b"A03:2021-Injection" not in resp.data


# --------------------------------------------------------------------------
# COMP-03: "Compliance coverage" card on the asset detail page (plan 03-03,
# Task 3).
# --------------------------------------------------------------------------

def test_asset_detail_renders_compliance_coverage_heading_category_and_scope_hint(db, client):
    org = make_org(plan=Plan.PAID, name="Card Org")
    user = make_user("card-owner@example.com", org=org)
    a = make_asset(org, user, name="Card Asset")
    db.session.commit()

    scan = Scan(
        asset_id=a.id, user_id=user.id, org_id=org.id,
        target_url=a.target_url, scan_type="base",
        status=ScanStatus.COMPLETED, risk_score=90,
    )
    db.session.add(scan)
    db.session.commit()
    _write_report(scan, {
        "findings": [{"check_name": "xss_sqli", "severity": "high", "title": "XSS"}],
        "locked_checks": [],
    })

    login(client, "card-owner@example.com")
    resp = client.get(f"/assets/{a.id}")

    assert resp.status_code == 200
    assert b"Compliance coverage" in resp.data
    assert b"A03:2021-Injection" in resp.data
    assert b"most recent completed scan" in resp.data


def test_asset_detail_all_scans_queued_shows_not_enough_scans_hint_no_category(db, client):
    org = make_org(plan=Plan.PAID, name="Queued Org")
    user = make_user("queued-owner@example.com", org=org)
    a = make_asset(org, user, name="Queued Asset")
    db.session.commit()

    scan = Scan(
        asset_id=a.id, user_id=user.id, org_id=org.id,
        target_url=a.target_url, scan_type="base",
        status=ScanStatus.QUEUED,
    )
    db.session.add(scan)
    db.session.commit()

    login(client, "queued-owner@example.com")
    resp = client.get(f"/assets/{a.id}")

    assert resp.status_code == 200
    assert b"Not enough completed scans yet to show compliance coverage." in resp.data
    assert b"A03:2021-Injection" not in resp.data
    assert b"A05:2021-Security Misconfiguration" not in resp.data


def test_asset_detail_tier_locked_category_shows_not_checked_not_passing(db, client):
    org = make_org(plan=Plan.PAID, name="Locked Org")
    user = make_user("locked-owner@example.com", org=org)
    a = make_asset(org, user, name="Locked Asset")
    db.session.commit()

    scan = Scan(
        asset_id=a.id, user_id=user.id, org_id=org.id,
        target_url=a.target_url, scan_type="base",
        status=ScanStatus.COMPLETED, risk_score=90,
    )
    db.session.add(scan)
    db.session.commit()
    _write_report(scan, {"findings": [], "locked_checks": A05_BASE_CHECK_NAMES})

    login(client, "locked-owner@example.com")
    resp = client.get(f"/assets/{a.id}")

    assert resp.status_code == 200
    assert b"Not checked" in resp.data
    assert b"Upgrade to Paid" in resp.data
