"""Tests for templates/org_admin.html's member/domain pill rendering."""
from webvulnscanner.models import Role
from tests.conftest import login, make_org, make_user


def test_org_admin_shows_member_verification_as_a_pill(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN, verified=True)
    db.session.commit()

    login(client, "admin@example.com")
    resp = client.get("/org/admin")

    assert resp.status_code == 200
    assert 'class="pill pass"' in resp.get_data(as_text=True)
