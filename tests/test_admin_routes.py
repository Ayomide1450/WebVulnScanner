"""Tests for webvulnscanner/admin_routes.py's /platform-admin dashboard -
the cross-org operator panel, gated by decorators.platform_admin_required
(User.is_platform_admin), independent of org role."""
from webvulnscanner.extensions import db as _db
from webvulnscanner.models import DomainVerification, Role, VerifyMethod
from tests.conftest import login, make_org, make_user


def test_platform_dashboard_requires_platform_admin(client, db):
    org = make_org()
    make_user("member@example.com", org=org, role=Role.MEMBER)
    db.session.commit()

    login(client, "member@example.com")
    resp = client.get("/platform-admin")

    assert resp.status_code == 403


def test_org_admin_alone_cannot_reach_platform_dashboard(client, db):
    # Being an ORG_ADMIN of some org is not the same privilege as being a
    # platform admin - the whole point of the separate is_platform_admin
    # flag.
    org = make_org()
    make_user("orgadmin@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()

    login(client, "orgadmin@example.com")
    resp = client.get("/platform-admin")

    assert resp.status_code == 403


def test_platform_dashboard_shows_counts_and_pending_deletions(client, db):
    org = make_org(name="Acme")
    admin = make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    staff = make_user("staff@example.com")
    staff.is_platform_admin = True
    dv = DomainVerification(org_id=org.id, domain="example.com", method=VerifyMethod.DNS_TXT, token="tok")
    _db.session.add(dv)
    _db.session.flush()
    db.session.commit()

    login(client, "admin@example.com")
    client.post(f"/org/admin/domain/{dv.id}/request-deletion", data={"reason": "no longer used"})

    login(client, "staff@example.com")
    resp = client.get("/platform-admin")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "example.com" in body
    assert "Acme" in body
    assert "admin@example.com" in body
    assert "no longer used" in body
