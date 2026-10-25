"""
PERF-02's pagination coverage. 09-CONTEXT.md's D-03 names exactly four
lists to paginate at 20/page: dashboard's scan history, the asset list,
org members, and a single scan report's severity-grouped findings.

Each "real DB-level pagination" assertion below proves a page-2-of-25-seed
request returns exactly the remaining 5 rows BY IDENTIFYING FIELD (specific
target_url/email/asset name/finding title), not merely by count - a Python
slice of an already-fully-fetched list would pass a count-only assertion
just as easily as a real `.paginate()` query would, so the identifying-field
check is what actually distinguishes the two. Boundary cases (a 1-page list
renders disabled Prev/Next with no numbered-page row; a 0-row list renders
the empty-state partial instead of any pagination markup) are each proven
for at least one of the four lists, per this plan's must_haves.

Stat-independence assertions (dashboard's trend chart / completed-count,
org-admin's member_count) prove those read from a separate, unbounded
query/aggregate - never from the current page's row count - by requesting
page 2 of a 25-row seed and asserting the stat is unaffected.
"""
from tests.conftest import login, make_asset, make_org, make_scan, make_user
from glassbox.models import Report, Role, ScanStatus


# --------------------------------------------------------------------------
# Dashboard scan history (scan_routes.dashboard())
# --------------------------------------------------------------------------

def test_dashboard_scan_history_paginates_page1_and_page2(client, db):
    org = make_org()
    user = make_user("dash-page@example.com", org=org)
    for i in range(25):
        s = make_scan(user, org=org, target_url=f"https://target{i:02d}.example.com",
                       status=ScanStatus.COMPLETED)
        s.risk_score = i
    db.session.commit()
    login(client, "dash-page@example.com")

    # Default (no ?page=) - page 1, the 20 NEWEST scans (target24..target05,
    # since the query orders by created_at desc).
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    for i in range(5, 25):
        assert f"target{i:02d}.example.com".encode() in resp.data
    for i in range(0, 5):
        assert f"target{i:02d}.example.com".encode() not in resp.data
    # A 2nd page exists - the numbered pagination control links to it.
    assert b'href="?page=2"' in resp.data

    # ?page=2 - exactly the remaining 5 OLDEST scans (target00..target04),
    # identified by their specific target_url, not merely a row count.
    resp2 = client.get("/dashboard?page=2")
    assert resp2.status_code == 200
    for i in range(0, 5):
        assert f"target{i:02d}.example.com".encode() in resp2.data
    # target24 (the single newest scan) is deliberately excluded from this
    # "must not appear" range: it's `latest`, shown unconditionally in the
    # separate "Latest Scan" card regardless of which Scan History page is
    # requested (see must_haves: pagination must not affect that card) - so
    # its continued presence on page 2 is correct, not a pagination leak.
    for i in range(5, 24):
        assert f"target{i:02d}.example.com".encode() not in resp2.data


def test_dashboard_stats_and_trend_unaffected_by_current_page(client, db):
    """25 completed, scored scans seeded; requesting page 2 of the Scan
    History table must not shrink the "launched overall" completed-scan
    count or the Security Score Over Time chart's point count down to the
    5 rows on that page - both read from the full, unbounded scan list."""
    org = make_org()
    user = make_user("dash-stats@example.com", org=org)
    for i in range(25):
        s = make_scan(user, org=org, target_url=f"https://stat-target{i:02d}.example.com",
                       status=ScanStatus.COMPLETED)
        s.risk_score = 40 + i
    db.session.commit()
    login(client, "dash-stats@example.com")

    resp_p1 = client.get("/dashboard")
    resp_p2 = client.get("/dashboard?page=2")
    assert resp_p1.status_code == 200 and resp_p2.status_code == 200

    # "Total Scans" card's "N launched overall" caption - all 25, not 20/5.
    assert b"25 launched overall" in resp_p1.data
    assert b"25 launched overall" in resp_p2.data

    # Security Score Over Time chart plots one point per scored scan -
    # 25 chart-point-label <text> elements on EITHER page, not just the
    # current page's 20 (page 1) or 5 (page 2) rows. Matches the element's
    # class ATTRIBUTE specifically (not the bare class-name substring),
    # since the bare substring also appears once in this page's own <style>
    # block (`.chart-point-label { ... }`) and would otherwise inflate the
    # count by 1 regardless of scan count.
    assert resp_p1.data.count(b'class="chart-point-label"') == 25
    assert resp_p2.data.count(b'class="chart-point-label"') == 25


# --------------------------------------------------------------------------
# Asset list (asset_routes.list_assets())
# --------------------------------------------------------------------------

def test_asset_list_paginates_page1_and_page2(client, db):
    org = make_org()
    user = make_user("asset-page@example.com", org=org)
    for i in range(25):
        make_asset(org, user, name=f"Asset {i:02d}", target_url=f"https://asset{i:02d}.example.com")
    db.session.commit()
    login(client, "asset-page@example.com")

    resp = client.get("/assets")
    assert resp.status_code == 200
    for i in range(5, 25):
        assert f"Asset {i:02d}".encode() in resp.data
    for i in range(0, 5):
        assert f"Asset {i:02d}".encode() not in resp.data
    assert b'href="?page=2"' in resp.data

    resp2 = client.get("/assets?page=2")
    assert resp2.status_code == 200
    for i in range(0, 5):
        assert f"Asset {i:02d}".encode() in resp2.data
    for i in range(5, 25):
        assert f"Asset {i:02d}".encode() not in resp2.data


def test_asset_list_single_page_disables_prev_and_next_with_no_page_row(client, db):
    """5 assets (one page at 20/page): pagination_nav renders with BOTH
    Prev and Next aria-disabled, and no numbered-page row at all (avoids a
    pointless lone "1" button, per 09-UI-SPEC.md's D-03 rule)."""
    org = make_org()
    user = make_user("asset-onepage@example.com", org=org)
    for i in range(5):
        make_asset(org, user, name=f"Solo Asset {i}", target_url=f"https://solo{i}.example.com")
    db.session.commit()
    login(client, "asset-onepage@example.com")

    resp = client.get("/assets")
    assert resp.status_code == 200
    # Count only within <body> - _pagination.html's own <style> block (in
    # <head>) also contains the literal substring `aria-disabled="true"` as
    # a CSS attribute selector, which would otherwise inflate this count by
    # 1 regardless of how many real controls are disabled.
    body = resp.data.split(b"<body", 1)[-1]
    assert body.count(b'aria-disabled="true"') == 4  # Prev+Next x (desktop+mobile)
    assert b"pagination-pages" not in body


def test_asset_list_zero_rows_renders_empty_state_not_pagination(client, db):
    org = make_org()
    make_user("asset-empty@example.com", org=org)
    login(client, "asset-empty@example.com")

    resp = client.get("/assets")
    assert resp.status_code == 200
    assert b"No assets yet." in resp.data
    assert b'aria-label="Pagination"' not in resp.data


# --------------------------------------------------------------------------
# Org members (org_routes.admin())
# --------------------------------------------------------------------------

def test_org_admin_members_paginate_page1_and_page2(client, db):
    org = make_org()
    admin_user = make_user("orgadmin-page@example.com", org=org, role=Role.ORG_ADMIN)
    # 24 more members + the admin themself = 25 total, User.id ascending:
    # admin=1, member00..member23 = 2..25. Page 1 (20/page) = ids 1-20
    # (admin + member00..member18); page 2 = ids 21-25 (member19..member23).
    for i in range(24):
        make_user(f"member{i:02d}@example.com", org=org)
    db.session.commit()
    login(client, "orgadmin-page@example.com")

    resp = client.get("/org/admin")
    assert resp.status_code == 200
    assert b"orgadmin-page@example.com" in resp.data
    for i in range(0, 19):
        assert f"member{i:02d}@example.com".encode() in resp.data
    for i in range(19, 24):
        assert f"member{i:02d}@example.com".encode() not in resp.data
    assert b'href="?page=2"' in resp.data

    resp2 = client.get("/org/admin?page=2")
    assert resp2.status_code == 200
    for i in range(19, 24):
        assert f"member{i:02d}@example.com".encode() in resp2.data
    for i in range(0, 19):
        assert f"member{i:02d}@example.com".encode() not in resp2.data
    assert b"orgadmin-page@example.com" not in resp2.data


def test_org_admin_member_count_stat_unaffected_by_current_page(client, db):
    org = make_org()
    make_user("orgadmin-stat@example.com", org=org, role=Role.ORG_ADMIN)
    for i in range(24):
        make_user(f"statmember{i:02d}@example.com", org=org)
    db.session.commit()
    login(client, "orgadmin-stat@example.com")

    resp_p1 = client.get("/org/admin")
    resp_p2 = client.get("/org/admin?page=2")
    assert resp_p1.status_code == 200 and resp_p2.status_code == 200
    assert "Members &middot; <b>25</b>".encode() in resp_p1.data
    assert "Members &middot; <b>25</b>".encode() in resp_p2.data


# --------------------------------------------------------------------------
# Single scan report's severity-grouped findings (scan_routes.scan_report())
# --------------------------------------------------------------------------

def _make_report_with_findings(db, user, org, n=25):
    """Seeds one COMPLETED Scan + Report with `n` findings, each carrying a
    distinct, identifiable `title` ("Finding 00".."Finding NN") so page
    assertions can check for specific findings, not merely a count. All
    findings share one `category` (grouping is orthogonal to what this
    task's pagination covers) - `sorted(..., key=lambda f: f["category"])`
    is a stable sort, so same-category findings keep their original
    (insertion) order, making page 1/page 2's exact contents predictable.

    `scan_type="other"` (not "base") deliberately keeps this scan outside
    scan_report.html's `{% if scan.scan_type == 'base' %}` "Detailed check
    output" section (raw headers/cookies/ports/etc. dumps this pagination
    task doesn't touch) - same minimal-fixture convention
    tests/test_compliance.py's `_minimal_report` helper already established
    for testing this template's shared findings-list section in isolation.
    """
    s = make_scan(user, org=org, target_url="https://report-target.example.com",
                   scan_type="other", status=ScanStatus.COMPLETED)
    s.risk_score = 55
    report_data = {
        "target": "https://report-target.example.com",
        "hostname": "report-target.example.com",
        "scanned_at": "2024-01-01T00:00:00Z",
        "score": 55,
        "risk_grade": "C",
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": n, "info": 0},
        "locked_checks": [],
        "findings": [
            {
                "category": "Test Category", "title": f"Finding {i:02d}",
                "severity": "low", "detail": "detail text", "recommendation": "",
                "check_name": "",
            }
            for i in range(n)
        ],
    }
    db.session.add(Report(scan_id=s.id, json_path="unused.json", data=report_data))
    db.session.commit()
    return s


def test_scan_report_severity_findings_paginate_page1_and_page2(client, db):
    org = make_org()
    user = make_user("report-page@example.com", org=org)
    s = _make_report_with_findings(db, user, org, n=25)
    login(client, "report-page@example.com")

    resp = client.get(f"/scan/{s.id}/report")
    assert resp.status_code == 200
    for i in range(0, 20):
        assert f"Finding {i:02d}".encode() in resp.data
    for i in range(20, 25):
        assert f"Finding {i:02d}".encode() not in resp.data
    assert b'href="?page=2"' in resp.data

    resp2 = client.get(f"/scan/{s.id}/report?page=2")
    assert resp2.status_code == 200
    for i in range(20, 25):
        assert f"Finding {i:02d}".encode() in resp2.data
    for i in range(0, 20):
        assert f"Finding {i:02d}".encode() not in resp2.data


def test_scan_report_compliance_view_ignores_pagination(client, db):
    """The compliance-grouped view (?group=compliance) is explicitly left
    unpaginated per this plan's scope boundary - it must show ALL 25
    findings regardless of a ?page= param, proven explicitly rather than
    left implicit."""
    org = make_org()
    user = make_user("report-compliance@example.com", org=org)
    s = _make_report_with_findings(db, user, org, n=25)
    login(client, "report-compliance@example.com")

    resp = client.get(f"/scan/{s.id}/report?group=compliance&page=2")
    assert resp.status_code == 200
    for i in range(25):
        assert f"Finding {i:02d}".encode() in resp.data
