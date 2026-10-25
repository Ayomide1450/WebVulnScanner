"""Tests for glassbox/public_routes.py."""


def test_healthz_returns_ok_when_db_reachable(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_healthz_does_not_require_login(client):
    # Render's healthCheckPath / UptimeRobot can't authenticate - this must
    # never redirect to /login like an @login_required route would.
    resp = client.get("/healthz", follow_redirects=False)
    assert resp.status_code == 200


def test_terms_page_returns_200_without_auth(client):
    resp = client.get("/terms")
    assert resp.status_code == 200
    assert b"Terms of Service" in resp.data


def test_privacy_page_returns_200_without_auth(client):
    resp = client.get("/privacy")
    assert resp.status_code == 200
    assert b"Privacy Policy" in resp.data


def test_footer_links_to_terms_and_privacy(client):
    resp = client.get("/")
    body = resp.get_data(as_text=True)
    assert 'href="/terms"' in body
    assert 'href="/privacy"' in body
