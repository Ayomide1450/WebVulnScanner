"""
Tests for the org-invite flow (HARD-03's invite half): `generate_invite_token`/
`decode_invite_token` in `webvulnscanner/org_routes.py`, and the invite-mode
branch they feed into in `auth_routes.signup()`.

This module owns D-05/D-06/D-07: D-05 is the previously-undocumented gap this
plan closes (an invite link that was generated but never consumed);
D-06 finishes `/signup` to consume it while explicitly declining to add any
standalone member-role-change route (role assignment happens only at invite
time - there is nothing to test for a route that, by decision, doesn't
exist); D-07 is the email-binding security fix.

`decode_invite_token` had zero call sites anywhere in the repo before this
phase (confirmed via grep in 04-RESEARCH.md's Pitfall 6) - its
`BadSignature`/`SignatureExpired` handling and the new email-mismatch check
are being verified here for the first time, not re-verified, so the
tampered/expired/mismatch tests in this module are load-bearing, not
belt-and-suspenders.
"""
import pytest

from webvulnscanner.email_stub import EmailSender
from webvulnscanner.models import Role, User
from webvulnscanner.org_routes import decode_invite_token, generate_invite_token

from tests.conftest import login, make_org, make_user


class _SpyEmailSender(EmailSender):
    """Records every send() call instead of printing to the console (same
    pattern as tests/test_auth_flows.py's _SpyEmailSender) so a test can
    pull the real invite link - and the real token inside it - out of the
    message body, rather than parsing stdout or fabricating a token by
    hand."""

    def __init__(self):
        self.sent = []

    def send(self, to, subject, body):
        self.sent.append({"to": to, "subject": subject, "body": body})


@pytest.fixture()
def spy_sender(app):
    sender = _SpyEmailSender()
    app.extensions["email_sender"] = sender
    return sender


def _extract_token(body):
    """`body` is the full invite email text; the invite link is one line
    of it (`.../signup?invite=<token>`). The token is everything after the
    `invite=` query param up to the next whitespace - not to the end of
    the string, since the email body has more text after the link."""
    after = body.split("invite=", 1)[1]
    return after.split()[0]


# --------------------------------------------------------------------------
# Token unit tests
# --------------------------------------------------------------------------

def test_generate_and_decode_invite_token_round_trips_with_email(app):
    with app.app_context():
        token = generate_invite_token(org_id=5, role="member", email="Invitee@Example.com")
        decoded = decode_invite_token(token, expected_email="invitee@example.com")
    assert decoded == {"org_id": 5, "role": "member", "email": "invitee@example.com"}


def test_decode_invite_token_rejects_email_mismatch(app):
    with app.app_context():
        token = generate_invite_token(org_id=5, role="member", email="invitee@example.com")
        assert decode_invite_token(token, expected_email="attacker@example.com") is None


def test_decode_invite_token_without_expected_email_returns_payload(app):
    # The shape the GET render path uses to pre-fill the address - no
    # expected_email means "don't check, just decode".
    with app.app_context():
        token = generate_invite_token(org_id=5, role="member", email="invitee@example.com")
        decoded = decode_invite_token(token)
    assert decoded["email"] == "invitee@example.com"
    assert decoded["org_id"] == 5


# --------------------------------------------------------------------------
# invite() route
# --------------------------------------------------------------------------

def test_invite_route_produces_email_bound_token(client, db, spy_sender):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()
    login(client, "admin@example.com")

    resp = client.post(
        "/org/admin/invite",
        data={"email": "Newbie@Example.com", "role": Role.MEMBER.value},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert len(spy_sender.sent) == 1
    assert spy_sender.sent[0]["to"] == "newbie@example.com"

    token = _extract_token(spy_sender.sent[0]["body"])
    decoded = decode_invite_token(token, expected_email="newbie@example.com")
    assert decoded == {"org_id": org.id, "role": Role.MEMBER.value, "email": "newbie@example.com"}


# --------------------------------------------------------------------------
# signup() invite-mode branch
# --------------------------------------------------------------------------

def test_signup_get_with_valid_invite(client, db):
    org = make_org()
    db.session.commit()
    token = generate_invite_token(org.id, Role.MEMBER.value, "invitee@example.com")

    resp = client.get(f"/signup?invite={token}")
    html = resp.get_data(as_text=True)

    assert resp.status_code == 200
    assert "invitee@example.com" in html
    assert "readonly" in html
    assert "org_name" not in html
    # The form must post back with the invite param still attached, or the
    # POST handler never sees the token and silently downgrades to an
    # ordinary signup (04-RESEARCH.md Pitfall 8).
    assert f"invite={token}" in html


def test_signup_post_with_valid_invite_creates_member_in_org(client, db):
    org = make_org()
    db.session.commit()
    token = generate_invite_token(org.id, Role.MEMBER.value, "invitee@example.com")

    resp = client.post(
        f"/signup?invite={token}",
        data={
            "email": "invitee@example.com", "password": "password123",
            "confirm_password": "password123",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200

    user = User.query.filter_by(email="invitee@example.com").first()
    assert user is not None
    assert user.org_id == org.id
    assert user.role == Role.MEMBER


def test_signup_post_with_valid_invite_grants_admin_role_when_invited_as_admin(client, db):
    org = make_org()
    db.session.commit()
    token = generate_invite_token(org.id, Role.ORG_ADMIN.value, "secondadmin@example.com")

    client.post(
        f"/signup?invite={token}",
        data={
            "email": "secondadmin@example.com", "password": "password123",
            "confirm_password": "password123",
        },
        follow_redirects=True,
    )

    user = User.query.filter_by(email="secondadmin@example.com").first()
    assert user is not None
    assert user.role == Role.ORG_ADMIN
    assert user.org_id == org.id


def test_signup_post_with_mismatched_email_creates_no_user(client, db):
    org = make_org()
    db.session.commit()
    token = generate_invite_token(org.id, Role.MEMBER.value, "invitee@example.com")

    resp = client.post(
        f"/signup?invite={token}",
        data={
            "email": "someoneelse@example.com", "password": "password123",
            "confirm_password": "password123",
        },
    )
    assert resp.status_code == 200
    assert User.query.filter_by(email="someoneelse@example.com").first() is None
    assert "different email address" in resp.get_data(as_text=True)


def test_signup_without_invite_param_renders_ordinary_form(client):
    # The invite-mode template changes must not leak into the plain
    # signup path - org_name still offered, email still editable.
    resp = client.get("/signup")
    html = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "org_name" in html
    assert "readonly" not in html


# --------------------------------------------------------------------------
# Token failure paths - not optional. decode_invite_token had no callers
# (and therefore no coverage) before this phase, so its exception handling
# and org-binding are being proved for the first time here, not
# re-verified - the signup route now depends on this behavior being
# correct (04-RESEARCH.md Pitfall 6).
# --------------------------------------------------------------------------

def test_decode_invite_token_rejects_tampered_signature(app):
    with app.app_context():
        token = generate_invite_token(org_id=5, role="member", email="invitee@example.com")
        # Truncate one character off the end. A naive character FLIP here
        # turned out to be intermittently lossless: itsdangerous emits
        # UNPADDED urlsafe base64, so the final character can carry fewer
        # than six significant bits - flipping between characters that
        # differ only in the discarded low bits ('a'<->'b') yields a token
        # that decodes to the IDENTICAL signature and validates cleanly.
        # The flip failed this test only on runs whose signed timestamp
        # shifted the base64 group alignment. Truncation always changes the
        # signature, so the rejection being locked here is unconditional.
        tampered = token[:-1]
        assert decode_invite_token(tampered) is None
        assert decode_invite_token(tampered, expected_email="invitee@example.com") is None


def test_decode_invite_token_rejects_expired_token(app, monkeypatch):
    import webvulnscanner.org_routes as org_routes_module

    with app.app_context():
        token = generate_invite_token(org_id=5, role="member", email="invitee@example.com")
        # Force the expiry branch deterministically rather than assuming
        # it works because INVITE_MAX_AGE_SECONDS is generously set.
        monkeypatch.setattr(org_routes_module, "INVITE_MAX_AGE_SECONDS", -1)
        assert decode_invite_token(token) is None


def test_decode_invite_token_preserves_exact_org_id(app):
    # A token generated for one organization cannot be made to resolve to
    # another - the decoded org_id is exactly the one signed in.
    with app.app_context():
        token_a = generate_invite_token(org_id=7, role="member", email="invitee@example.com")
        token_b = generate_invite_token(org_id=42, role="member", email="invitee@example.com")
        assert decode_invite_token(token_a)["org_id"] == 7
        assert decode_invite_token(token_b)["org_id"] == 42


def test_decode_invite_token_normalizes_case_and_whitespace_on_both_sides(app):
    # Exercises Pitfall 7 exactly: an admin typing a mixed-case address at
    # invite time, and the invitee typing it lowercase (with incidental
    # whitespace) at signup, must still match.
    with app.app_context():
        token = generate_invite_token(org_id=5, role="member", email="  Invitee@Example.Com  ")
        decoded = decode_invite_token(token, expected_email=" invitee@example.com ")
    assert decoded is not None
    assert decoded["email"] == "invitee@example.com"


# --------------------------------------------------------------------------
# invite() route authorization/validation
# --------------------------------------------------------------------------

def test_invite_route_refuses_non_admin_member(client, db, spy_sender):
    org = make_org()
    make_user("member@example.com", org=org, role=Role.MEMBER)
    db.session.commit()
    login(client, "member@example.com")

    resp = client.post(
        "/org/admin/invite",
        data={"email": "newbie@example.com", "role": Role.MEMBER.value},
    )
    assert resp.status_code == 403
    assert spy_sender.sent == []


def test_invite_route_rejects_invalid_email_and_sends_nothing(client, db, spy_sender):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()
    login(client, "admin@example.com")

    resp = client.post(
        "/org/admin/invite",
        data={"email": "not-an-email", "role": Role.MEMBER.value},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert spy_sender.sent == []


def test_org_admin_page_no_longer_claims_signup_ignores_invites(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()
    login(client, "admin@example.com")

    resp = client.get("/org/admin")
    html = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "does not yet auto-apply" not in html
    assert "seven days" in html
