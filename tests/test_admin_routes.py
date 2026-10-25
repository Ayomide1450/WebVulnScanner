"""Tests for glassbox/admin_routes.py's /platform-admin dashboard -
the cross-org operator panel, gated by decorators.platform_admin_required
(User.is_platform_admin), independent of org role."""
from glassbox.extensions import db as _db
from glassbox.models import DomainVerification, PlatformAuditEvent, Role, User, VerifyMethod
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


# --------------------------------------------------------------------------
# Phase 16: user/org detail views + suspend/unsuspend (ADMIN-01..04).
# --------------------------------------------------------------------------


def _make_platform_admin(email="staff@example.com"):
    staff = make_user(email)
    staff.is_platform_admin = True
    return staff


def test_user_detail_requires_platform_admin(client, db):
    org = make_org()
    member = make_user("member@example.com", org=org, role=Role.MEMBER)
    db.session.commit()

    login(client, "member@example.com")
    resp = client.get(f"/platform-admin/users/{member.id}")

    assert resp.status_code == 403


def test_user_detail_shows_org_role_and_status(client, db):
    org = make_org(name="Acme")
    member = make_user("member@example.com", org=org, role=Role.MEMBER)
    _make_platform_admin()
    db.session.commit()

    login(client, "staff@example.com")
    resp = client.get(f"/platform-admin/users/{member.id}")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "member@example.com" in body
    assert "Acme" in body
    assert "ACTIVE" in body


def test_suspend_user_confirm_page_requires_get_then_post_to_apply(client, db):
    org = make_org()
    member = make_user("member@example.com", org=org, role=Role.MEMBER)
    _make_platform_admin()
    db.session.commit()
    member_id = member.id

    login(client, "staff@example.com")

    confirm = client.get(f"/platform-admin/users/{member_id}/suspend")
    assert confirm.status_code == 200
    assert "Confirm suspension" in confirm.get_data(as_text=True)

    refreshed = User.query.get(member_id)
    assert refreshed.suspended_at is None, "GET must not itself apply the suspension"

    resp = client.post(f"/platform-admin/users/{member_id}/suspend", follow_redirects=True)
    assert resp.status_code == 200

    refreshed = User.query.get(member_id)
    assert refreshed.suspended_at is not None
    events = PlatformAuditEvent.query.filter_by(target_type="user", target_id=member_id).all()
    assert len(events) == 1
    assert events[0].event_type == "user_suspended"


def test_suspended_user_cannot_log_in(client, db):
    org = make_org()
    member = make_user("member@example.com", org=org, role=Role.MEMBER)
    _make_platform_admin()
    db.session.commit()

    login(client, "staff@example.com")
    client.post(f"/platform-admin/users/{member.id}/suspend")
    client.get("/logout")

    resp = client.post(
        "/login", data={"email": "member@example.com", "password": "password123"}, follow_redirects=True,
    )
    body = resp.get_data(as_text=True)
    assert "suspended" in body.lower()
    # Confirms the session was genuinely never established, not just that
    # the flash message appeared - a dashboard hit must bounce to login.
    dash = client.get("/dashboard")
    assert dash.status_code in (302, 401, 403)


def test_unsuspend_user_restores_login(client, db):
    org = make_org()
    member = make_user("member@example.com", org=org, role=Role.MEMBER)
    _make_platform_admin()
    db.session.commit()
    member_id = member.id

    login(client, "staff@example.com")
    client.post(f"/platform-admin/users/{member_id}/suspend")
    client.post(f"/platform-admin/users/{member_id}/unsuspend")
    client.get("/logout")

    resp = client.post(
        "/login", data={"email": "member@example.com", "password": "password123"}, follow_redirects=True,
    )
    body = resp.get_data(as_text=True)
    assert "dashboard" in resp.request.path.lower() or "Dashboard" in body

    events = PlatformAuditEvent.query.filter_by(target_type="user", target_id=member_id).order_by(
        PlatformAuditEvent.created_at.asc()
    ).all()
    assert [e.event_type for e in events] == ["user_suspended", "user_unsuspended"]


def test_cannot_suspend_self_or_another_platform_admin(client, db):
    staff = _make_platform_admin("staff@example.com")
    other_staff = _make_platform_admin("other-staff@example.com")
    db.session.commit()

    login(client, "staff@example.com")

    self_resp = client.get(f"/platform-admin/users/{staff.id}/suspend")
    assert self_resp.status_code == 403

    other_resp = client.get(f"/platform-admin/users/{other_staff.id}/suspend")
    assert other_resp.status_code == 403


def test_suspend_org_blocks_every_members_login(client, db):
    org = make_org(name="Acme")
    member_a = make_user("a@example.com", org=org, role=Role.MEMBER)
    member_b = make_user("b@example.com", org=org, role=Role.ORG_ADMIN)
    _make_platform_admin()
    db.session.commit()
    org_id = org.id

    login(client, "staff@example.com")
    client.post(f"/platform-admin/orgs/{org_id}/suspend")
    client.get("/logout")

    for email in ("a@example.com", "b@example.com"):
        resp = client.post("/login", data={"email": email, "password": "password123"}, follow_redirects=True)
        assert "suspended" in resp.get_data(as_text=True).lower(), f"{email} should be blocked by org suspension"

    events = PlatformAuditEvent.query.filter_by(target_type="organization", target_id=org_id).all()
    assert len(events) == 1
    assert events[0].event_type == "org_suspended"


def test_suspended_mid_session_is_logged_out_on_next_request(app, client, db):
    """Covers __init__.py's before_request enforcement, not just the
    login-time block - a user with an already-open session must lose
    access on their very next request once suspended.

    Uses a second, fully independent Flask app instance (same on-disk
    SQLite file, own client) for the member's session rather than
    `client.application.test_client()` - the `db` fixture holds one app
    context open for the whole test (see its own docstring), and Flask
    reuses that single active app context (and its `flask.g`) for every
    test-client call against the *same* app made within it, which means
    Flask-Login's per-request user cache on `g` doesn't actually reset
    between "separate" clients the way two real, independently-scoped
    HTTP requests would. A second `create_app()` call - the same
    technique tests/test_error_leakage.py uses for its own independent-
    app-instance cases - sidesteps that shared-context artifact entirely
    rather than fighting it with extra expire_all() calls."""
    from glassbox import create_app
    from glassbox.config import Config

    org = make_org()
    member = make_user("member@example.com", org=org, role=Role.MEMBER)
    _make_platform_admin()
    db.session.commit()
    member_id = member.id

    class _MemberConfig(Config):
        TESTING = True
        WTF_CSRF_ENABLED = False
        RATELIMIT_ENABLED = False
        SCHEDULER_ENABLED = False
        SQLALCHEMY_DATABASE_URI = app.config["SQLALCHEMY_DATABASE_URI"]

    member_app = create_app(_MemberConfig)
    member_client = member_app.test_client()
    login(member_client, "member@example.com")
    still_in = member_client.get("/dashboard")
    assert still_in.status_code == 200

    login(client, "staff@example.com")
    client.post(f"/platform-admin/users/{member_id}/suspend")

    resp = member_client.get("/dashboard", follow_redirects=False)
    assert resp.status_code in (302, 401, 403)


def test_all_six_user_org_detail_and_suspend_routes_require_platform_admin(client, db):
    """SEC-01/RoleGated coverage for admin_routes.py's Phase 16 <int:>-
    accepting endpoints (user_detail/org_detail/suspend_user/unsuspend_user/
    suspend_org/unsuspend_org) - see tests/test_cross_org_idor.py's REGISTRY
    entries for these six, which point here. All are deliberately cross-org
    (a platform admin reviews every org, not just their own), guarded by
    platform_admin_required alone, same shape as org.approve_domain_deletion/
    reject_domain_deletion already registered there - an org-scoping denial
    test would assert the wrong thing about these routes; this proves the
    role gate instead, for a caller who is a real ORG_ADMIN (so a 403 here
    can only be the missing is_platform_admin flag, not some other gate)."""
    org = make_org()
    other_org = make_org(name="Other Org")
    admin_of_org = make_user("orgadmin@example.com", org=org, role=Role.ORG_ADMIN)
    target_user = make_user("target@example.com", org=other_org, role=Role.MEMBER)
    db.session.commit()

    login(client, "orgadmin@example.com")

    routes = [
        ("GET", f"/platform-admin/users/{target_user.id}"),
        ("GET", f"/platform-admin/orgs/{other_org.id}"),
        ("GET", f"/platform-admin/users/{target_user.id}/suspend"),
        ("POST", f"/platform-admin/users/{target_user.id}/unsuspend"),
        ("GET", f"/platform-admin/orgs/{other_org.id}/suspend"),
        ("POST", f"/platform-admin/orgs/{other_org.id}/unsuspend"),
    ]
    for method, path in routes:
        resp = client.get(path) if method == "GET" else client.post(path)
        assert resp.status_code == 403, f"{method} {path}: expected 403 for a non-platform-admin ORG_ADMIN"


def test_list_users_search_filters_by_email(client, db):
    org = make_org()
    make_user("findme@example.com", org=org, role=Role.MEMBER)
    make_user("someoneelse@example.com", org=org, role=Role.MEMBER)
    _make_platform_admin()
    db.session.commit()

    login(client, "staff@example.com")
    resp = client.get("/platform-admin/users?q=findme")

    body = resp.get_data(as_text=True)
    assert "findme@example.com" in body
    assert "someoneelse@example.com" not in body
