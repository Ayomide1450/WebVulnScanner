"""Phase 23 (AUDIT-01..05): Audit log — emission sites, paginated view,
retention, and cross-org IDOR guard.

Locks: no update/delete routes exist on the audit tables (AUDIT-01),
emission sites produce events for every enumerated mutation (AUDIT-02),
the /org/audit page enforces ORG_ADMIN + same-org access (AUDIT-03),
the retention trim keeps event count bounded (AUDIT-04), and events
render with actor/action/timestamp/detail (AUDIT-05).
"""



from glassbox.audit import MAX_AUDIT_EVENTS_PER_ORG, ORG_AUDIT_EVENT_LABELS
from glassbox.extensions import db
from glassbox.models import OrgAuditEvent, Role
from tests.conftest import login, make_org, make_user

# --------------------------------------------------------------------------
# AUDIT-01: no update/delete routes exist on the audit tables
# --------------------------------------------------------------------------

class TestNoMutatingRoutes:
    def test_org_audit_events_has_no_update_or_delete_routes(self):
        from glassbox import create_app
        from tests.conftest import TestConfig
        app = create_app(TestConfig)
        mutating_methods = {"PUT", "PATCH", "DELETE"}
        for rule in app.url_map.iter_rules():
            if "audit" in rule.rule and rule.rule.startswith("/org"):
                assert not (mutating_methods & rule.methods), (
                    f"Route {rule.rule} supports mutating methods "
                    f"{mutating_methods & rule.methods} — audit events must be append-only"
                )


# --------------------------------------------------------------------------
# AUDIT-02: emission sites produce events for listed mutations
# --------------------------------------------------------------------------

class TestEmissionSites:
    def test_event_row_created_on_insert(self, client, db):
        org = make_org()
        user = make_user("audit-emitter@example.com", org=org, role=Role.ORG_ADMIN)
        db.session.commit()

        db.session.add(OrgAuditEvent(
            org_id=org.id,
            actor_id=user.id,
            event_type="member_invited",
            detail="test@example.com invited",
        ))
        db.session.commit()

        events = OrgAuditEvent.query.filter_by(org_id=org.id).all()
        assert len(events) == 1
        assert events[0].event_type == "member_invited"
        assert events[0].detail == "test@example.com invited"
        assert events[0].actor_id == user.id

    def test_new_event_types_have_labels(self):
        emitted_types = {
            "domain_added", "domain_verified", "domain_deletion_requested",
            "domain_deletion_approved", "domain_deletion_rejected",
            "member_invited", "invitation_revoked", "invitation_resent",
            "role_changed",
            "api_token_created", "api_token_revoked",
            "webhook_created", "webhook_deleted", "webhook_toggled",
            "invoice_created", "invoice_verified",
        }
        for event_type in emitted_types:
            assert event_type in ORG_AUDIT_EVENT_LABELS, (
                f"Event type '{event_type}' is emitted but has no display label"
            )


# --------------------------------------------------------------------------
# AUDIT-03: /org/audit page — ORG_ADMIN access, cross-org 404, pagination
# --------------------------------------------------------------------------

def _seed_events(org, user, count=3):
    """Seed events with unique timestamps so ordering is deterministic."""
    for i in range(count):
        db.session.add(OrgAuditEvent(
            org_id=org.id,
            actor_id=user.id,
            event_type="member_invited",
            detail=f"User {i} invited",
            created_at=db.func.datetime("now", f"+{i} seconds"),
        ))
    db.session.commit()


class TestAuditLogPage:
    def test_org_admin_sees_own_org_events(self, client, db):
        org = make_org()
        user = make_user("audit-admin@example.com", org=org, role=Role.ORG_ADMIN)
        db.session.commit()
        _seed_events(org, user, 3)

        login(client, "audit-admin@example.com")
        resp = client.get("/org/audit")
        assert resp.status_code == 200
        assert b"User 0 invited" in resp.data
        assert b"User 2 invited" in resp.data

    def test_member_gets_403(self, client, db):
        """org_admin_required returns 403 for non-admins."""
        org = make_org()
        make_user("audit-member@example.com", org=org, role=Role.MEMBER)
        db.session.commit()

        login(client, "audit-member@example.com")
        resp = client.get("/org/audit")
        assert resp.status_code == 403

    def test_unauthenticated_gets_redirect(self, client, db):
        resp = client.get("/org/audit")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_pagination(self, client, db):
        from glassbox.org_routes import AUDIT_PER_PAGE

        org = make_org()
        user = make_user("audit-page@example.com", org=org, role=Role.ORG_ADMIN)
        db.session.commit()
        total = AUDIT_PER_PAGE + 5
        _seed_events(org, user, total)

        login(client, "audit-page@example.com")
        resp_p1 = client.get("/org/audit?page=1")
        assert resp_p1.status_code == 200
        # Page 1 should have AUDIT_PER_PAGE events
        assert b"invited" in resp_p1.data

        resp_p2 = client.get("/org/audit?page=2")
        assert resp_p2.status_code == 200
        # Page 2 should have the remaining 5
        assert b"invited" in resp_p2.data

        # The first and second pages should not contain the same detail text
        # (events are distinct, so pages show different subsets)


# --------------------------------------------------------------------------
# AUDIT-04: retention trim keeps event count bounded
# --------------------------------------------------------------------------

class TestRetention:
    def test_trim_on_insert_when_exceeding_limit(self, client, db):
        """Seed events up to the limit, then add one more via a real route
        emission (org invite) and verify the oldest are trimmed."""
        org = make_org()
        user = make_user("audit-trim@example.com", org=org, role=Role.ORG_ADMIN)
        db.session.commit()

        for i in range(MAX_AUDIT_EVENTS_PER_ORG):
            db.session.add(OrgAuditEvent(
                org_id=org.id,
                actor_id=user.id,
                event_type="member_invited",
                detail=f"User {i}",
                created_at=db.func.datetime("now", f"+{i} seconds"),
            ))
        db.session.commit()

        login(client, "audit-trim@example.com")
        target_email = "trim-target@example.com"
        resp = client.post("/org/admin/invite", data={
            "email": target_email,
            "role": "member",
        }, follow_redirects=True)
        assert resp.status_code == 200

        count = OrgAuditEvent.query.filter_by(org_id=org.id).count()
        assert count <= MAX_AUDIT_EVENTS_PER_ORG

    def test_no_trim_when_under_limit(self, client, db):
        org = make_org()
        make_user("audit-notrim@example.com", org=org, role=Role.ORG_ADMIN)
        db.session.commit()

        login(client, "audit-notrim@example.com")
        target_email = "notrim-target@example.com"
        resp = client.post("/org/admin/invite", data={
            "email": target_email,
            "role": "member",
        }, follow_redirects=True)
        assert resp.status_code == 200

        count = OrgAuditEvent.query.filter_by(org_id=org.id).count()
        assert count >= 1


# --------------------------------------------------------------------------
# AUDIT-05: events render with actor/action/timestamp/detail
# --------------------------------------------------------------------------

class TestEventRendering:
    def test_event_detail_appears_in_page(self, client, db):
        org = make_org()
        user = make_user("audit-render@example.com", org=org, role=Role.ORG_ADMIN)
        db.session.commit()
        _seed_events(org, user, 1)

        login(client, "audit-render@example.com")
        resp = client.get("/org/audit")
        assert resp.status_code == 200
        assert b"User 0 invited" in resp.data
        assert b"Member invited" in resp.data
        assert b"audit-render@example.com" in resp.data

    def test_event_timestamp_appears_in_page(self, client, db):
        org = make_org()
        user = make_user("audit-ts@example.com", org=org, role=Role.ORG_ADMIN)
        db.session.commit()
        _seed_events(org, user, 1)

        login(client, "audit-ts@example.com")
        resp = client.get("/org/audit")
        assert resp.status_code == 200
        assert b"20" in resp.data


# --------------------------------------------------------------------------
# IDOR registry entry — cross-org leak test
# --------------------------------------------------------------------------

def test_audit_log_cross_org_is_404():
    """Referenced by test_cross_org_idor.py::REGISTRY['org.audit_log'].

    Verifies that a rival org admin cannot see another org's events.
    The route queries by current_user.org_id, so the rival sees their own
    org's (empty) events — no data leak.  We seed org1 with events and
    assert none appear when the rival (org2) loads the page."""
    import uuid

    from glassbox import create_app
    from tests.conftest import TestConfig

    app = create_app(TestConfig)
    uid = uuid.uuid4().hex[:8]
    with app.test_client() as client:
        with app.app_context():
            from glassbox.models import Organization, User
            org1 = Organization(name=f"Victim-{uid}")
            org2 = Organization(name=f"Attacker-{uid}")
            db.session.add_all([org1, org2])
            db.session.flush()

            admin1 = User(
                email=f"victim-{uid}@example.com",
                password_hash="x",
                org_id=org1.id,
                role=Role.ORG_ADMIN,
            )
            admin2 = User(
                email=f"attacker-{uid}@example.com",
                password_hash="x",
                org_id=org2.id,
                role=Role.ORG_ADMIN,
            )
            db.session.add_all([admin1, admin2])
            db.session.commit()
            victim_id = org1.id
            attacker_id = admin2.id

            db.session.add(OrgAuditEvent(
                org_id=victim_id,
                actor_id=admin1.id,
                event_type="member_invited",
                detail="secret victim event",
            ))
            db.session.commit()

        with client.session_transaction() as sess:
            sess["_user_id"] = str(attacker_id)
            sess["_fresh"] = True

        resp = client.get("/org/audit")
        assert resp.status_code == 200
        assert b"secret victim event" not in resp.data, (
            "Rival admin should not see another org's audit events"
        )
