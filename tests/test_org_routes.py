"""Tests for org_routes.py's org_admin page: member/domain pill rendering,
the domain-deletion request/approve/reject workflow, and pending-invitation
resend/revoke."""
from glassbox.extensions import db as _db
from glassbox.models import DomainVerification, Invitation, InvitationStatus, OrgAuditEvent, Role, VerifyMethod
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
    platform_admin = make_user("staff@example.com")
    platform_admin.is_platform_admin = True
    dv = _make_domain(org)
    dv_id = dv.id
    db.session.commit()

    login(client, "admin@example.com")
    client.post(f"/org/admin/domain/{dv_id}/request-deletion", data={"reason": "stale"})
    login(client, "staff@example.com")
    resp = client.post(f"/org/admin/domain/{dv_id}/deletion/approve", follow_redirects=True)

    assert resp.status_code == 200
    assert DomainVerification.query.get(dv_id) is None
    approved_events = OrgAuditEvent.query.filter_by(org_id=org.id, event_type="domain_deletion_approved").all()
    assert len(approved_events) == 1
    assert "stale" in approved_events[0].detail


def test_reject_domain_deletion_keeps_domain_active(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    platform_admin = make_user("staff@example.com")
    platform_admin.is_platform_admin = True
    dv = _make_domain(org)
    dv_id = dv.id
    db.session.commit()

    login(client, "admin@example.com")
    client.post(f"/org/admin/domain/{dv_id}/request-deletion", data={"reason": "stale"})
    login(client, "staff@example.com")
    resp = client.post(f"/org/admin/domain/{dv_id}/deletion/reject", follow_redirects=True)

    assert resp.status_code == 200
    refreshed = DomainVerification.query.get(dv_id)
    assert refreshed is not None
    assert not refreshed.deletion_pending
    rejected_events = OrgAuditEvent.query.filter_by(org_id=org.id, event_type="domain_deletion_rejected").all()
    assert len(rejected_events) == 1


def test_org_admin_cannot_approve_their_own_deletion_request(client, db):
    # The actual separation-of-duties fix: an org admin who requests a
    # deletion must not also be able to approve it - only a platform admin
    # (is_platform_admin) can. Regression test for a real gap: the original
    # implementation gated approve/reject with org_admin_required, the same
    # decorator as request, so any org admin could self-approve.
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    dv = _make_domain(org)
    dv_id = dv.id
    db.session.commit()

    login(client, "admin@example.com")
    client.post(f"/org/admin/domain/{dv_id}/request-deletion", data={"reason": "stale"})
    resp = client.post(f"/org/admin/domain/{dv_id}/deletion/approve")

    assert resp.status_code == 403
    assert DomainVerification.query.get(dv_id) is not None
    assert DomainVerification.query.get(dv_id).deletion_pending


def test_platform_admin_can_approve_deletion_for_an_org_they_dont_belong_to(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    # No org_id at all - a platform admin need not belong to any org.
    make_user("staff@example.com", org=None)
    from glassbox.models import User
    staff = User.query.filter_by(email="staff@example.com").first()
    staff.is_platform_admin = True
    dv = _make_domain(org)
    dv_id = dv.id
    db.session.commit()

    login(client, "admin@example.com")
    client.post(f"/org/admin/domain/{dv_id}/request-deletion", data={"reason": "stale"})
    login(client, "staff@example.com")
    resp = client.post(f"/org/admin/domain/{dv_id}/deletion/approve", follow_redirects=True)

    assert resp.status_code == 200
    assert DomainVerification.query.get(dv_id) is None
    approved = OrgAuditEvent.query.filter_by(org_id=org.id, event_type="domain_deletion_approved").first()
    assert approved is not None
    assert approved.actor_id == staff.id


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


# --------------------------------------------------------------------------
# SEC-01 (08-01, Task 1): cross-org IDOR proof for resend_invitation and
# revoke_invitation. org_routes.py:335/353 already carry the
# `inv.org_id != current_user.org_id: abort(404)` guard at both call sites -
# this section closes the proof gap (D-02), it does not fix a vulnerability.
# The positive control (the owning org's admin succeeding against the same
# invitation) exists so a broken fixture that accidentally 404s everything
# cannot be misread as a passing security test.
# --------------------------------------------------------------------------

def test_cross_org_resend_invitation_is_404_and_leaves_invitation_and_audit_log_untouched(client, db):
    org_a = make_org(name="Org A")
    org_b = make_org(name="Org B")
    make_user("admin_a@example.com", org=org_a, role=Role.ORG_ADMIN)
    make_user("admin_b@example.com", org=org_b, role=Role.ORG_ADMIN)
    db.session.commit()

    login(client, "admin_b@example.com")
    client.post("/org/admin/invite", data={"email": "teammate@orgb.com", "role": Role.MEMBER.value})
    inv = Invitation.query.filter_by(org_id=org_b.id).first()
    inv_id = inv.id

    login(client, "admin_a@example.com")
    resp = client.post(f"/org/admin/invite/{inv_id}/resend", follow_redirects=False)

    assert resp.status_code == 404
    refreshed = Invitation.query.get(inv_id)
    assert refreshed.status == InvitationStatus.PENDING
    resent_events = OrgAuditEvent.query.filter_by(org_id=org_b.id, event_type="invitation_resent").all()
    assert len(resent_events) == 0


def test_cross_org_revoke_invitation_is_404_and_leaves_invitation_and_audit_log_untouched(client, db):
    org_a = make_org(name="Org A")
    org_b = make_org(name="Org B")
    make_user("admin_a@example.com", org=org_a, role=Role.ORG_ADMIN)
    make_user("admin_b@example.com", org=org_b, role=Role.ORG_ADMIN)
    db.session.commit()

    login(client, "admin_b@example.com")
    client.post("/org/admin/invite", data={"email": "teammate@orgb.com", "role": Role.MEMBER.value})
    inv = Invitation.query.filter_by(org_id=org_b.id).first()
    inv_id = inv.id

    login(client, "admin_a@example.com")
    resp = client.post(f"/org/admin/invite/{inv_id}/revoke", follow_redirects=False)

    assert resp.status_code == 404
    refreshed = Invitation.query.get(inv_id)
    assert refreshed.status == InvitationStatus.PENDING
    assert refreshed.revoked_at is None
    revoked_events = OrgAuditEvent.query.filter_by(org_id=org_b.id, event_type="invitation_revoked").all()
    assert len(revoked_events) == 0


def test_owning_org_admin_can_still_resend_the_same_invitation(client, db):
    # Positive control for the cross-org resend test above: without this, a
    # fixture bug that made every resend 404 (e.g. a broken login()) would
    # read as "the cross-org guard works" when it actually proves nothing.
    org = make_org(name="Org A")
    make_user("admin_a@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()

    login(client, "admin_a@example.com")
    client.post("/org/admin/invite", data={"email": "teammate@orga.com", "role": Role.MEMBER.value})
    inv = Invitation.query.filter_by(org_id=org.id).first()
    inv_id = inv.id

    resend_resp = client.post(f"/org/admin/invite/{inv_id}/resend", follow_redirects=False)
    assert resend_resp.status_code == 302
    assert resend_resp.headers["Location"].endswith("/org/admin")
    assert Invitation.query.get(inv_id).status == InvitationStatus.PENDING


def test_owning_org_admin_can_still_revoke_the_same_invitation(client, db):
    # Positive control for the cross-org revoke test above - same rationale
    # as the resend positive control.
    org = make_org(name="Org A")
    make_user("admin_a@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()

    login(client, "admin_a@example.com")
    client.post("/org/admin/invite", data={"email": "teammate@orga.com", "role": Role.MEMBER.value})
    inv = Invitation.query.filter_by(org_id=org.id).first()
    inv_id = inv.id

    revoke_resp = client.post(f"/org/admin/invite/{inv_id}/revoke", follow_redirects=False)
    assert revoke_resp.status_code == 302
    assert revoke_resp.headers["Location"].endswith("/org/admin")
    assert Invitation.query.get(inv_id).status == InvitationStatus.REVOKED


def test_non_admin_member_cannot_resend_or_revoke_invitation(client, db):
    # org_admin_required aborts with 403 (not a redirect) for an
    # authenticated user who isn't an ORG_ADMIN - see decorators.py.
    org = make_org(name="Org A")
    make_user("admin_a@example.com", org=org, role=Role.ORG_ADMIN)
    make_user("member_a@example.com", org=org, role=Role.MEMBER)
    db.session.commit()

    login(client, "admin_a@example.com")
    client.post("/org/admin/invite", data={"email": "teammate@orga.com", "role": Role.MEMBER.value})
    inv = Invitation.query.filter_by(org_id=org.id).first()
    inv_id = inv.id

    login(client, "member_a@example.com")
    resend_resp = client.post(f"/org/admin/invite/{inv_id}/resend", follow_redirects=False)
    revoke_resp = client.post(f"/org/admin/invite/{inv_id}/revoke", follow_redirects=False)

    assert resend_resp.status_code == 403
    assert revoke_resp.status_code == 403
    assert Invitation.query.get(inv_id).status == InvitationStatus.PENDING
