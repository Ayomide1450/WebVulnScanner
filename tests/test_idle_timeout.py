"""
Tests for the idle-session timeout added to webvulnscanner/__init__.py's
`_enforce_idle_timeout` before_request hook: a session-cookie-authenticated
user is signed out server-side after `IDLE_TIMEOUT_MINUTES` (default 5) with
no request, independent of "Remember me". Bearer-token (API) auth is
exempt - see the hook's own docstring for why.
"""
from datetime import datetime, timedelta, timezone

from webvulnscanner.models import ApiToken, ScanStatus

from tests.conftest import login, make_api_token, make_org, make_scan, make_user


def _set_last_seen(client, when):
    with client.session_transaction() as sess:
        sess["_last_seen"] = when.isoformat()


def test_first_request_after_login_sets_last_seen(client, db):
    org = make_org()
    make_user("idle1@example.com", org=org)
    login(client, "idle1@example.com")
    with client.session_transaction() as sess:
        assert "_last_seen" in sess


def test_request_within_timeout_stays_logged_in(client, db):
    org = make_org()
    make_user("idle2@example.com", org=org)
    login(client, "idle2@example.com")
    _set_last_seen(client, datetime.now(timezone.utc) - timedelta(minutes=1))
    resp = client.get("/dashboard")
    assert resp.status_code == 200


def test_request_past_timeout_logs_out_and_redirects_to_login(client, db):
    org = make_org()
    make_user("idle3@example.com", org=org)
    login(client, "idle3@example.com")
    _set_last_seen(client, datetime.now(timezone.utc) - timedelta(minutes=6))
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_logged_out_session_is_actually_cleared(client, db):
    """Not just a redirect - the session itself must be cleared so a
    subsequent request doesn't silently re-authenticate via a stale
    remember cookie or leftover session state."""
    org = make_org()
    make_user("idle4@example.com", org=org)
    login(client, "idle4@example.com")
    _set_last_seen(client, datetime.now(timezone.utc) - timedelta(minutes=6))
    client.get("/dashboard", follow_redirects=False)
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_timeout_applies_even_with_remember_me(client, db):
    org = make_org()
    make_user("idle5@example.com", org=org)
    client.post(
        "/login",
        data={"email": "idle5@example.com", "password": "password123", "remember": "y"},
        follow_redirects=True,
    )
    _set_last_seen(client, datetime.now(timezone.utc) - timedelta(minutes=6))
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_bearer_token_requests_are_exempt_from_idle_timeout(client, db):
    org = make_org()
    user = make_user("idle6@example.com", org=org)
    token, raw = make_api_token(user)
    headers = {"Authorization": f"Bearer {raw}"}
    # Two requests far apart in wall-clock terms - the idle hook must never
    # even look at this path's session state since Bearer auth never
    # receives a session cookie back in the first place.
    resp1 = client.get("/api/v1/assets", headers=headers)
    resp2 = client.get("/api/v1/assets", headers=headers)
    assert resp1.status_code == 200
    assert resp2.status_code == 200


def test_scan_status_poll_does_not_refresh_last_seen(client, db):
    """The background /status poll on scan_progress.html must not count as
    activity - otherwise an AFK user watching a long scan would never time
    out. A request to /status must not bump _last_seen even though it does
    carry the session cookie."""
    org = make_org()
    user = make_user("idle7@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.RUNNING)
    login(client, "idle7@example.com")

    stale = datetime.now(timezone.utc) - timedelta(minutes=4)
    _set_last_seen(client, stale)
    client.get(f"/scan/{scan.id}/status")
    with client.session_transaction() as sess:
        assert sess["_last_seen"] == stale.isoformat()
