"""
Tests for glassbox/api_tokens_routes.py - self-service API token
generate/revoke (API-01, D-01..D-05, Phase 2 tracer plan 02-01).
"""
import pytest

from glassbox.models import ApiToken

from tests.conftest import login, make_api_token, make_org, make_user


@pytest.fixture()
def logged_in_client(db, client):
    org = make_org(name="Token Org")
    make_user("owner@example.com", org=org)
    login(client, "owner@example.com")
    return client


# --------------------------------------------------------------------------
# API-01: token creation shows the raw value exactly once, list never
# re-shows it (D-01).
# --------------------------------------------------------------------------

def test_create_token_shows_raw_value_exactly_once(logged_in_client, db):
    resp = logged_in_client.post(
        "/tokens/new", data={"name": "CI pipeline"}, follow_redirects=True,
    )

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # The raw token value must appear on this response...
    tokens = ApiToken.query.all()
    assert len(tokens) == 1
    assert tokens[0].name == "CI pipeline"
    assert tokens[0].token_hash is not None
    # ...and only a hash is ever persisted - no raw-token column exists at all.
    assert not hasattr(tokens[0], "raw_token")
    assert not hasattr(tokens[0], "value")

    # A subsequent GET /tokens must never re-show any raw token value -
    # only hash-derived metadata (name/created/last-used/status).
    list_resp = logged_in_client.get("/tokens")
    list_body = list_resp.get_data(as_text=True)
    assert "CI pipeline" in list_body
    # The create-response's raw secret shouldn't reappear anywhere in the
    # plain list view.
    import re

    raw_value_candidates = re.findall(r'value="([\w\-]{40,})"', body)
    assert raw_value_candidates, "expected the raw token value in the create response"
    raw_value = raw_value_candidates[0]
    assert raw_value not in list_body


def test_create_token_requires_a_name(logged_in_client, db):
    resp = logged_in_client.post("/tokens/new", data={"name": ""}, follow_redirects=True)

    assert resp.status_code == 200
    assert ApiToken.query.count() == 0
    body = resp.get_data(as_text=True)
    assert "Enter a name for this token" in body


def test_tokens_list_shows_only_hash_derived_metadata(logged_in_client, db):
    from glassbox.models import User

    user = User.query.filter_by(email="owner@example.com").first()
    _, raw_token = make_api_token(user, name="Personal script")

    resp = logged_in_client.get("/tokens")
    body = resp.get_data(as_text=True)

    assert "Personal script" in body
    assert raw_token not in body


# --------------------------------------------------------------------------
# API-01: revoking a token sets revoked_at and it immediately fails Bearer
# auth on the very next request (D-03).
# --------------------------------------------------------------------------

def test_revoke_sets_revoked_at_and_immediately_fails_api_auth(app, logged_in_client, db):
    from glassbox.models import User

    user = User.query.filter_by(email="owner@example.com").first()
    token, raw_token = make_api_token(user, name="Personal script")
    db.session.commit()

    resp = logged_in_client.post(
        f"/tokens/{token.id}/revoke", follow_redirects=False,
    )
    assert resp.status_code == 302

    refreshed = ApiToken.query.get(token.id)
    assert refreshed.revoked_at is not None

    # A fresh, session-less client (Flask-Login checks the session cookie
    # BEFORE falling back to request_loader, so re-using logged_in_client's
    # own session here would mask the revocation - this exercises the
    # Bearer-token-only path, matching how a real CLI/script would connect).
    # The explicit app.app_context() wrapper is required too: flask.g (and
    # Flask-Login's per-request user cache) is app-context-scoped, not
    # request-scoped, and the `db` fixture holds one app context open for
    # this whole test - without a fresh context here, this second request
    # would silently reuse the first request's cached (session) identity
    # instead of actually evaluating the Bearer header.
    api_client = app.test_client()
    with app.app_context():
        api_resp = api_client.get(
            "/api/v1/assets", headers={"Authorization": f"Bearer {raw_token}"},
        )
    assert api_resp.status_code == 401
    assert api_resp.is_json


def test_user_cannot_revoke_another_users_token(logged_in_client, db):
    other_user = make_user("someone-else@example.com")
    other_token, _ = make_api_token(other_user, name="Not yours")
    db.session.commit()

    resp = logged_in_client.post(f"/tokens/{other_token.id}/revoke")
    assert resp.status_code == 404

    refreshed = ApiToken.query.get(other_token.id)
    assert refreshed.revoked_at is None


# --------------------------------------------------------------------------
# D-04: multiple concurrently-active, independently-revocable named tokens.
# --------------------------------------------------------------------------

def test_creating_second_token_does_not_affect_first(logged_in_client, db):
    logged_in_client.post("/tokens/new", data={"name": "First token"})
    logged_in_client.post("/tokens/new", data={"name": "Second token"})

    tokens = ApiToken.query.order_by(ApiToken.created_at.asc()).all()
    assert len(tokens) == 2
    assert tokens[0].revoked_at is None
    assert tokens[1].revoked_at is None
    assert {t.name for t in tokens} == {"First token", "Second token"}
