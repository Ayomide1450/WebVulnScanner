"""Tests for webvulnscanner/public_routes.py."""


def test_healthz_returns_ok_when_db_reachable(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_healthz_does_not_require_login(client):
    # Render's healthCheckPath / UptimeRobot can't authenticate - this must
    # never redirect to /login like an @login_required route would.
    resp = client.get("/healthz", follow_redirects=False)
    assert resp.status_code == 200
