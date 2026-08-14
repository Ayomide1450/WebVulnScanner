"""Tests for org_routes.py's org_admin page: member/domain pill rendering,
the domain-deletion request/approve/reject workflow, and pending-invitation
resend/revoke."""
from webvulnscanner.extensions import db as _db
from webvulnscanner.models import DomainVerification, Invitation, InvitationStatus, OrgAuditEvent, Role, VerifyMethod
from tests.conftest import login, make_org, make_user


def _make_domain(org, domain="example.com", verified=True):
    dv = DomainVerification(
        org_id=org.id, domain=domain, method=VerifyMethod.DNS_TXT, token="tok",
    )
    if verified:
        from datetime import datetime, timezone
        dv.verified_at = datetime.now(timezone.utc)
    _db.session.add(dv)
    _db.session.flush()
    return dv


def test_org_admin_shows_member_verification_as_a_pill(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN, verified=True)
    db.session.commit()

    login(client, "admin@example.com")
    resp = client.get("/org/admin")

    assert resp.status_code == 200
    assert 'class="pill pass"' in resp.get_data(as_text=True)


def test_request_domain_deletion_sets_pending_and_does_not_delete(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    dv = _make_domain(org)
    db.session.commit()

    login(client, "admin@example.com")
    resp = client.post(f"/org/admin/domain/{dv.id}/request-deletion", data={"reason": "no longer used"}, follow_redirects=True)

    assert resp.status_code == 200
    assert "Deletion Pending" in resp.get_data(as_text=True)
    refreshed = DomainVerification.query.get(dv.id)
    assert refreshed is not None
    assert refreshed.deletion_pending
    assert refreshed.deletion_reason == "no longer used"
    events = OrgAuditEvent.query.filter_by(org_id=org.id, event_type="domain_deletion_requested").all()
    assert len(events) == 1


def test_request_domain_deletion_reason_is_optional(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    dv = _make_domain(org)
    db.session.commit()

    login(client, "admin@example.com")
    resp = client.post(f"/org/admin/domain/{dv.id}/request-deletion", data={}, follow_redirects=True)

    assert resp.status_code == 200
    refreshed = DomainVerification.query.get(dv.id)
    assert refreshed.deletion_pending
    assert refreshed.deletion_reason is None


def test_approve_domain_deletion_removes_domain_and_keeps_audit_record(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    dv = _make_domain(org)
    dv_id = dv.id
    db.session.commit()

    login(client, "admin@example.com")
    client.post(f"/org/admin/domain/{dv_id}/request-deletion", data={"reason": "stale"})
    resp = client.post(f"/org/admin/domain/{dv_id}/deletion/approve", follow_redirects=True)

    assert resp.status_code == 200
    assert DomainVerification.query.get(dv_id) is None
    approved_events = OrgAuditEvent.query.filter_by(org_id=org.id, event_type="domain_deletion_approved").all()
    assert len(approved_events) == 1
    assert "stale" in approved_events[0].detail


def test_reject_domain_deletion_keeps_domain_active(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    dv = _make_domain(org)
    dv_id = dv.id
    db.session.commit()

    login(client, "admin@example.com")
    client.post(f"/org/admin/domain/{dv_id}/request-deletion", data={"reason": "stale"})
    resp = client.post(f"/org/admin/domain/{dv_id}/deletion/reject", follow_redirects=True)

    assert resp.status_code == 200
    refreshed = DomainVerification.query.get(dv_id)
    assert refreshed is not None
    assert not refreshed.deletion_pending
    rejected_events = OrgAuditEvent.query.filter_by(org_id=org.id, event_type="domain_deletion_rejected").all()
    assert len(rejected_events) == 1


def test_domain_deletion_actions_are_org_scoped(client, db):
    org_a = make_org(name="Org A")
    org_b = make_org(name="Org B")
    make_user("admin_a@example.com", org=org_a, role=Role.ORG_ADMIN)
    make_user("admin_b@example.com", org=org_b, role=Role.ORG_ADMIN)
    dv = _make_domain(org_b)
    db.session.commit()

    login(client, "admin_a@example.com")
    resp = client.post(f"/org/admin/domain/{dv.id}/request-deletion", data={})

    assert resp.status_code == 404


def test_invite_creates_pending_invitation_and_shows_confirmation(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()

    login(client, "admin@example.com")
    resp = client.post(
        "/org/admin/invite",
        data={"email": "teammate@company.com", "role": Role.MEMBER.value},
        follow_redirects=True,
    )

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Invitation sent to teammate@company.com" in body
    assert "Pending Invitations" in body
    assert "teammate@company.com" in body
    invs = Invitation.query.filter_by(org_id=org.id).all()
    assert len(invs) == 1
    assert invs[0].status == InvitationStatus.PENDING


def test_revoke_invitation_removes_it_from_pending_list(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()

    login(client, "admin@example.com")
    client.post("/org/admin/invite", data={"email": "teammate@company.com", "role": Role.MEMBER.value})
    inv = Invitation.query.filter_by(org_id=org.id).first()

    resp = client.post(f"/org/admin/invite/{inv.id}/revoke", follow_redirects=True)

    assert resp.status_code == 200
    assert "No pending invitations." in resp.get_data(as_text=True)
    refreshed = Invitation.query.get(inv.id)
    assert refreshed.status == InvitationStatus.REVOKED


def test_resend_invitation_keeps_it_pending(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()

    login(client, "admin@example.com")
    client.post("/org/admin/invite", data={"email": "teammate@company.com", "role": Role.MEMBER.value})
    inv = Invitation.query.filter_by(org_id=org.id).first()

    resp = client.post(f"/org/admin/invite/{inv.id}/resend", follow_redirects=True)

    assert resp.status_code == 200
    assert "Invitation resent to teammate@company.com" in resp.get_data(as_text=True)
    refreshed = Invitation.query.get(inv.id)
    assert refreshed.status == InvitationStatus.PENDING
