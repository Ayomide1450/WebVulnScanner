"""
Tests for `_check_ownership()` in glassbox/scan_routes.py - the IDOR
guard shared by every route that looks up a Scan by ID
(scan_detail/scan_events/scan_report/scan_compare). Per its own docstring:
a scan is viewable by the user who ran it, OR an ORG_ADMIN of the same org
that ran it; anything else is a 404 (not 403), matching org_routes.py's
convention of not confirming a resource's existence to someone who isn't
entitled to see it.

These are integration tests through the real routes/login flow rather than
calling `_check_ownership` directly, since it reads `flask_login.current_user`
(a context-local proxy) - exercising it via the actual request path is both
more representative and simpler than faking that context by hand.

`scan_detail` is used for most scenarios since it needs no Report row
(unlike scan_report/scan_compare, which 404 on a missing report regardless
of ownership - ownership is still checked first there, see
test_scan_report_and_scan_compare_enforce_ownership_too).
"""
import pytest

from glassbox.extensions import db as _db
from glassbox.models import Report, Role, ScanStatus
from tests.conftest import login, make_org, make_scan, make_user


@pytest.fixture()
def scenario(db):
    """Two orgs, several users, and one scan owned by org1's plain member.

    org1: owner (MEMBER, owns `scan`), colleague (MEMBER), admin (ORG_ADMIN)
    org2: rival_admin (ORG_ADMIN) - a different org entirely
    solo: a user with no org at all
    """
    org1 = make_org(name="Org One")
    org2 = make_org(name="Org Two")

    owner = make_user("owner@org1.com", org=org1, role=Role.MEMBER)
    colleague = make_user("colleague@org1.com", org=org1, role=Role.MEMBER)
    admin = make_user("admin@org1.com", org=org1, role=Role.ORG_ADMIN)
    rival_admin = make_user("admin@org2.com", org=org2, role=Role.ORG_ADMIN)
    solo = make_user("solo@nowhere.com", org=None, role=Role.MEMBER)

    scan = make_scan(owner, org=org1, target_url="https://example.com")

    return {
        "org1": org1, "org2": org2, "owner": owner, "colleague": colleague,
        "admin": admin, "rival_admin": rival_admin, "solo": solo, "scan": scan,
    }


def test_unauthenticated_request_redirects_to_login(client, scenario):
    resp = client.get(f"/scan/{scenario['scan'].id}")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_owner_can_view_own_scan(client, scenario):
    login(client, "owner@org1.com")
    resp = client.get(f"/scan/{scenario['scan'].id}")
    assert resp.status_code == 200


def test_plain_member_of_same_org_cannot_view_colleagues_scan(client, scenario):
    # Only ORG_ADMIN gets org-wide visibility (CLAUDE.md's "Dashboard
    # scoping decision") - a regular teammate must not see another
    # member's scan target just by being in the same org.
    login(client, "colleague@org1.com")
    resp = client.get(f"/scan/{scenario['scan'].id}")
    assert resp.status_code == 404


def test_org_admin_can_view_org_members_scan(client, scenario):
    login(client, "admin@org1.com")
    resp = client.get(f"/scan/{scenario['scan'].id}")
    assert resp.status_code == 200


def test_admin_of_a_different_org_cannot_view_scan(client, scenario):
    # The core IDOR case: incrementing a scan ID must not leak another
    # org's scan just because the requester also happens to be an admin.
    login(client, "admin@org2.com")
    resp = client.get(f"/scan/{scenario['scan'].id}")
    assert resp.status_code == 404


def test_unrelated_user_with_no_org_cannot_view_scan(client, scenario):
    login(client, "solo@nowhere.com")
    resp = client.get(f"/scan/{scenario['scan'].id}")
    assert resp.status_code == 404


def test_nonexistent_scan_id_is_404_even_when_authenticated(client, scenario):
    login(client, "owner@org1.com")
    resp = client.get("/scan/999999")
    assert resp.status_code == 404


def test_org_id_none_guard_blocks_none_equals_none_bypass(db, client):
    """Regression test for the `s.org_id is not None` guard in
    _check_ownership: without it, a scan with org_id=None (an individual,
    org-less user's scan) compared against a requester who also has
    org_id=None would satisfy `current_user.org_id == s.org_id` (None ==
    None) and, if that requester happened to hold the ORG_ADMIN role,
    would wrongly grant access. The guard must reject this regardless of
    role."""
    solo_owner = make_user("solo-owner@nowhere.com", org=None, role=Role.MEMBER)
    # Deliberately construct an org-less admin - shouldn't occur via normal
    # signup (ORG_ADMIN is only assigned alongside org creation), but the
    # ownership check must not rely on that invariant holding.
    make_user("solo-admin@nowhere.com", org=None, role=Role.ORG_ADMIN)
    scan = make_scan(solo_owner, org=None, target_url="https://example.com")

    login(client, "solo-admin@nowhere.com")
    resp = client.get(f"/scan/{scan.id}")
    assert resp.status_code == 404


def test_scan_report_and_scan_compare_enforce_ownership_too(client, scenario):
    # Ownership is checked before the report-existence check in both
    # scan_report and scan_compare (see scan_routes.py) - a stranger gets
    # 404 regardless of whether a report exists, same as scan_detail.
    login(client, "admin@org2.com")
    scan_id = scenario["scan"].id

    resp = client.get(f"/scan/{scan_id}/report")
    assert resp.status_code == 404

    second_scan = make_scan(scenario["owner"], org=scenario["org1"], target_url="https://example.org")
    resp = client.get(f"/scan/{scan_id}/compare/{second_scan.id}")
    assert resp.status_code == 404


def test_scan_compare_checks_both_scans_not_just_the_first(client, scenario):
    # A user who owns scan A but not scan B must still be denied - proves
    # _check_ownership(a) passing doesn't short-circuit the check on b.
    other_org_scan = make_scan(scenario["rival_admin"], org=scenario["org2"],
                                target_url="https://other.example.com")
    login(client, "owner@org1.com")  # owns scenario["scan"], not other_org_scan

    resp = client.get(f"/scan/{scenario['scan'].id}/compare/{other_org_scan.id}")
    assert resp.status_code == 404

    # And the reverse order (own scan passed as the second id) too.
    resp = client.get(f"/scan/{other_org_scan.id}/compare/{scenario['scan'].id}")
    assert resp.status_code == 404


def test_scan_events_denies_cross_org_access(client, scenario):
    # abort(404) fires before the SSE Response/generator is constructed, so
    # this is safe to check via status_code without touching the streaming
    # body (which would otherwise loop until scan completion).
    login(client, "admin@org2.com")
    resp = client.get(f"/scan/{scenario['scan'].id}/events")
    assert resp.status_code == 404


# --------------------------------------------------------------------------
# SEC-01 (08-01, Task 3): scan.scan_report_csv cross-org denial. Same
# ownership guard as scan_report (_check_ownership, checked before the
# report-existence check) - reused rather than reinvented, per
# scan_report_csv's own docstring. Report.data is populated directly (the
# source of truth per Report's docstring in models.py) so this test needs
# no filesystem state and no background scan thread.
# --------------------------------------------------------------------------

CSV_LEAK_MARKER = "MARKER-08-01-CSV-LEAK-CHECK-9f3c1a"


def _attach_report_with_marker(scan):
    report_data = {
        "hostname": "example.com",
        "target": "https://example.com",
        "findings": [
            {
                "category": "headers", "title": "Missing security header",
                "severity": "medium", "owasp_category": "A05:2021-Security Misconfiguration",
                "detail": CSV_LEAK_MARKER, "recommendation": "Add the header.",
            },
        ],
    }
    r = Report(scan_id=scan.id, json_path="unused-for-this-test.json", data=report_data)
    _db.session.add(r)
    _db.session.flush()
    return r


def test_scan_report_csv_cross_org_is_404_and_leaks_no_finding_text(client, scenario, db):
    _attach_report_with_marker(scenario["scan"])
    _db.session.commit()

    # Negative: a different org's admin must not see the CSV, or the marker.
    login(client, "admin@org2.com")
    resp = client.get(f"/scan/{scenario['scan'].id}/export.csv")
    assert resp.status_code == 404
    assert CSV_LEAK_MARKER.encode() not in resp.data

    # Positive control: the owner gets a real CSV with the marker present -
    # proves the 404 above came from the ownership guard, not a missing
    # report or a broken route.
    login(client, "owner@org1.com")
    resp2 = client.get(f"/scan/{scenario['scan'].id}/export.csv")
    assert resp2.status_code == 200
    assert resp2.content_type.startswith("text/csv")
    assert CSV_LEAK_MARKER.encode() in resp2.data


def test_scan_detail_redirects_to_report_when_completed(client, scenario, db):
    from glassbox.extensions import db as _db

    scenario["scan"].status = ScanStatus.COMPLETED
    _db.session.flush()

    login(client, "owner@org1.com")
    resp = client.get(f"/scan/{scenario['scan'].id}", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith(f"/scan/{scenario['scan'].id}/report")
