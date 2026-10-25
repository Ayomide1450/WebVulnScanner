"""Phase 26 (SSO-02): Route-level tests for the SSO blueprint.

Tests cover:
  - GET /login/saml: missing org, SSO disabled, SSRF-unsafe URL, valid redirect
  - POST /auth/saml/callback: missing session, SAML validation failure,
    domain mismatch, JIT provisioning (new user + existing user), login success
  - GET /auth/saml/logout: session cleared

The tests mock OneLogin_Saml2_Auth to avoid needing a real IdP — the
route logic (session state, error handling, JIT provisioning, domain
guard) is what's under test, not the SAML library's signature validation
(which the spike already proved).
"""
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from glassbox.extensions import db
from glassbox.models import (
    DomainVerification, Plan, Role, SSOConfiguration, User, VerifyMethod,
)
from tests.conftest import make_org, make_user


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_sso_config(org, enabled=True, idp_sso_url="https://idp.example.com/saml/sso"):
    """Create an SSOConfiguration for an org."""
    cert = SSOConfiguration.encrypt_secret("FAKE-IDP-CERT-PEM-CONTENT")
    cfg = SSOConfiguration(
        org_id=org.id,
        enabled=enabled,
        idp_entity_id="https://idp.example.com/metadata",
        idp_sso_url=idp_sso_url,
        idp_certificate=cert,
        sp_entity_id=f"https://glassbox.example.com/saml/metadata/{org.id}",
    )
    db.session.add(cfg)
    db.session.flush()
    return cfg


def _make_verified_domain(org, domain="example.com"):
    """Create a verified DomainVerification for an org."""
    dv = DomainVerification(
        org_id=org.id,
        domain=domain,
        method=VerifyMethod.DNS_TXT,
        token="fake-token",
        verified_at=datetime.now(timezone.utc),
    )
    db.session.add(dv)
    db.session.flush()
    return dv


# ---------------------------------------------------------------------------
# GET /login/saml
# ---------------------------------------------------------------------------

class TestLoginSaml:
    def test_missing_org_redirects_to_login(self, client):
        resp = client.get("/login/saml")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_nonexistent_org_redirects_to_login(self, client, db):
        resp = client.get("/login/saml?org=99999")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_sso_disabled_redirects_to_login(self, client, db):
        org = make_org()
        _make_sso_config(org, enabled=False)
        db.session.commit()
        resp = client.get(f"/login/saml?org={org.id}")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_sso_not_configured_redirects_to_login(self, client, db):
        org = make_org()
        db.session.commit()
        resp = client.get(f"/login/saml?org={org.id}")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_ssrf_unsafe_idp_url_redirects_to_login(self, client, db):
        org = make_org()
        _make_sso_config(org, idp_sso_url="http://169.254.169.254/latest/meta-data/")
        db.session.commit()
        resp = client.get(f"/login/saml?org={org.id}")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("glassbox.sso_routes._ssrf_safe_url", return_value=True)
    @patch("glassbox.sso_routes.OneLogin_Saml2_Auth")
    def test_valid_initiation_stores_session_and_redirects(self, mock_auth_cls, mock_ssrf, client, db):
        org = make_org()
        _make_sso_config(org)
        db.session.commit()

        mock_auth_instance = MagicMock()
        mock_auth_instance.redirect_to_idp.return_value = "redirect-to-idp"
        mock_auth_cls.return_value = mock_auth_instance

        resp = client.get(f"/login/saml?org={org.id}")
        # The route returns whatever redirect_to_idp() returns
        assert resp.status_code == 200  # mock returns a string, not a real redirect

        # Session should contain the org_id
        with client.session_transaction() as sess:
            assert sess["_saml_org_id"] == org.id


# ---------------------------------------------------------------------------
# POST /auth/saml/callback
# ---------------------------------------------------------------------------

class TestSamlCallback:
    def test_missing_session_org_redirects_to_login(self, client, db):
        db.session.commit()
        resp = client.post("/auth/saml/callback")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_sso_config_disabled_during_redirect_redirects(self, client, db):
        org = make_org()
        cfg = _make_sso_config(org, enabled=True)
        db.session.commit()

        # Simulate the session being set, then SSO getting disabled
        with client.session_transaction() as sess:
            sess["_saml_org_id"] = org.id

        # Disable the config
        cfg.enabled = False
        db.session.commit()

        resp = client.post("/auth/saml/callback")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("glassbox.sso_routes.OneLogin_Saml2_Auth")
    def test_saml_validation_error_redirects(self, mock_auth_cls, client, db):
        from onelogin.saml2.errors import OneLogin_Saml2_ValidationError

        org = make_org()
        _make_sso_config(org)
        db.session.commit()

        with client.session_transaction() as sess:
            sess["_saml_org_id"] = org.id

        mock_auth_instance = MagicMock()
        mock_auth_instance.process_response.side_effect = (
            OneLogin_Saml2_ValidationError("bad signature")
        )
        mock_auth_cls.return_value = mock_auth_instance

        resp = client.post("/auth/saml/callback")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("glassbox.sso_routes.OneLogin_Saml2_Auth")
    def test_saml_get_errors_redirects(self, mock_auth_cls, client, db):
        org = make_org()
        _make_sso_config(org)
        db.session.commit()

        with client.session_transaction() as sess:
            sess["_saml_org_id"] = org.id

        mock_auth_instance = MagicMock()
        mock_auth_instance.process_response.return_value = None
        mock_auth_instance.get_errors.return_value = ["invalid_signature"]
        mock_auth_cls.return_value = mock_auth_instance

        resp = client.post("/auth/saml/callback")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("glassbox.sso_routes.OneLogin_Saml2_Auth")
    def test_not_authenticated_redirects(self, mock_auth_cls, client, db):
        org = make_org()
        _make_sso_config(org)
        db.session.commit()

        with client.session_transaction() as sess:
            sess["_saml_org_id"] = org.id

        mock_auth_instance = MagicMock()
        mock_auth_instance.process_response.return_value = None
        mock_auth_instance.get_errors.return_value = []
        mock_auth_instance.is_authenticated.return_value = False
        mock_auth_cls.return_value = mock_auth_instance

        resp = client.post("/auth/saml/callback")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("glassbox.sso_routes.OneLogin_Saml2_Auth")
    def test_domain_mismatch_redirects(self, mock_auth_cls, client, db):
        org = make_org()
        _make_sso_config(org)
        _make_verified_domain(org, domain="example.com")
        db.session.commit()

        with client.session_transaction() as sess:
            sess["_saml_org_id"] = org.id

        mock_auth_instance = MagicMock()
        mock_auth_instance.process_response.return_value = None
        mock_auth_instance.get_errors.return_value = []
        mock_auth_instance.is_authenticated.return_value = True
        mock_auth_instance.get_nameid.return_value = "user@wrong-domain.com"
        mock_auth_cls.return_value = mock_auth_instance

        resp = client.post("/auth/saml/callback")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("glassbox.sso_routes.OneLogin_Saml2_Auth")
    def test_jit_provisions_new_user(self, mock_auth_cls, client, db):
        org = make_org()
        _make_sso_config(org)
        _make_verified_domain(org, domain="example.com")
        db.session.commit()

        with client.session_transaction() as sess:
            sess["_saml_org_id"] = org.id

        mock_auth_instance = MagicMock()
        mock_auth_instance.process_response.return_value = None
        mock_auth_instance.get_errors.return_value = []
        mock_auth_instance.is_authenticated.return_value = True
        mock_auth_instance.get_nameid.return_value = "newuser@example.com"
        mock_auth_cls.return_value = mock_auth_instance

        resp = client.post("/auth/saml/callback")
        assert resp.status_code == 302
        assert "/dashboard" in resp.headers["Location"]

        user = User.query.filter_by(email="newuser@example.com").first()
        assert user is not None
        assert user.org_id == org.id
        assert user.auth_method == "sso"
        assert user.password_hash is None
        assert user.email_verified_at is not None

    @patch("glassbox.sso_routes.OneLogin_Saml2_Auth")
    def test_jit_updates_existing_user(self, mock_auth_cls, client, db):
        org = make_org()
        _make_sso_config(org)
        _make_verified_domain(org, domain="example.com")
        existing = make_user("existing@example.com", org=org, verified=True)
        db.session.commit()

        with client.session_transaction() as sess:
            sess["_saml_org_id"] = org.id

        mock_auth_instance = MagicMock()
        mock_auth_instance.process_response.return_value = None
        mock_auth_instance.get_errors.return_value = []
        mock_auth_instance.is_authenticated.return_value = True
        mock_auth_instance.get_nameid.return_value = "existing@example.com"
        mock_auth_cls.return_value = mock_auth_instance

        resp = client.post("/auth/saml/callback")
        assert resp.status_code == 302
        assert "/dashboard" in resp.headers["Location"]

        user = User.query.filter_by(email="existing@example.com").first()
        assert user.auth_method == "sso"
        assert user.password_hash is None

    @patch("glassbox.sso_routes.OneLogin_Saml2_Auth")
    def test_jit_sets_org_for_orgless_user(self, mock_auth_cls, client, db):
        org = make_org()
        _make_sso_config(org)
        _make_verified_domain(org, domain="example.com")
        # Existing user with no org
        existing = make_user("orphan@example.com", org=None, verified=True)
        db.session.commit()

        with client.session_transaction() as sess:
            sess["_saml_org_id"] = org.id

        mock_auth_instance = MagicMock()
        mock_auth_instance.process_response.return_value = None
        mock_auth_instance.get_errors.return_value = []
        mock_auth_instance.is_authenticated.return_value = True
        mock_auth_instance.get_nameid.return_value = "orphan@example.com"
        mock_auth_cls.return_value = mock_auth_instance

        resp = client.post("/auth/saml/callback")
        assert resp.status_code == 302

        user = User.query.filter_by(email="orphan@example.com").first()
        assert user.org_id == org.id
        assert user.auth_method == "sso"

    @patch("glassbox.sso_routes.OneLogin_Saml2_Auth")
    def test_missing_nameid_redirects(self, mock_auth_cls, client, db):
        org = make_org()
        _make_sso_config(org)
        _make_verified_domain(org, domain="example.com")
        db.session.commit()

        with client.session_transaction() as sess:
            sess["_saml_org_id"] = org.id

        mock_auth_instance = MagicMock()
        mock_auth_instance.process_response.return_value = None
        mock_auth_instance.get_errors.return_value = []
        mock_auth_instance.is_authenticated.return_value = True
        mock_auth_instance.get_nameid.return_value = ""  # empty NameID
        mock_auth_cls.return_value = mock_auth_instance

        resp = client.post("/auth/saml/callback")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    @patch("glassbox.sso_routes.OneLogin_Saml2_Auth")
    def test_nameid_without_at_sign_redirects(self, mock_auth_cls, client, db):
        org = make_org()
        _make_sso_config(org)
        _make_verified_domain(org, domain="example.com")
        db.session.commit()

        with client.session_transaction() as sess:
            sess["_saml_org_id"] = org.id

        mock_auth_instance = MagicMock()
        mock_auth_instance.process_response.return_value = None
        mock_auth_instance.get_errors.return_value = []
        mock_auth_instance.is_authenticated.return_value = True
        mock_auth_instance.get_nameid.return_value = "not-an-email"
        mock_auth_cls.return_value = mock_auth_instance

        resp = client.post("/auth/saml/callback")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# GET /auth/saml/logout
# ---------------------------------------------------------------------------

class TestSamlLogout:
    def test_logout_redirects_to_login(self, client, db):
        db.session.commit()
        resp = client.get("/auth/saml/logout")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Org admin SSO config panel (SSO-03/04/05)
# ---------------------------------------------------------------------------

from tests.conftest import login as _login


def _make_admin_user(org):
    """Create an ORG_ADMIN user for the given org."""
    return make_user(
        f"admin-{org.id}@example.com",
        org=org,
        role=Role.ORG_ADMIN,
        verified=True,
    )


class TestAdminSSOConfig:
    def test_sso_config_page_renders_for_admin(self, client, db):
        org = make_org()
        admin = _make_admin_user(org)
        db.session.commit()
        _login(client, admin.email)
        resp = client.get("/org/admin/sso")
        assert resp.status_code == 200
        assert b"SSO Configuration" in resp.data

    def test_sso_config_page_shows_existing_config(self, client, db):
        org = make_org()
        admin = _make_admin_user(org)
        _make_sso_config(org)
        db.session.commit()
        _login(client, admin.email)
        resp = client.get("/org/admin/sso")
        assert resp.status_code == 200
        assert b"idp.example.com" in resp.data

    def test_non_admin_cannot_access_sso_config(self, client, db):
        org = make_org()
        member = make_user("member@example.com", org=org, role=Role.MEMBER, verified=True)
        db.session.commit()
        _login(client, member.email)
        resp = client.get("/org/admin/sso")
        assert resp.status_code in (302, 403)

    @patch("glassbox.org_routes._ssrf_safe_hostname", return_value=True)
    def test_save_sso_config_creates_new(self, mock_ssrf, client, db):
        org = make_org()
        admin = _make_admin_user(org)
        db.session.commit()
        _login(client, admin.email)
        resp = client.post("/org/admin/sso", data={
            "idp_entity_id": "https://idp.neworg.com/metadata",
            "idp_sso_url": "https://idp.neworg.com/saml/sso",
            "idp_certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            "allow_password_login": True,
        }, follow_redirects=True)
        assert resp.status_code == 200
        cfg = SSOConfiguration.query.filter_by(org_id=org.id).first()
        assert cfg is not None
        assert cfg.idp_entity_id == "https://idp.neworg.com/metadata"
        assert cfg.enabled is True

    @patch("glassbox.org_routes._ssrf_safe_hostname", return_value=True)
    def test_save_sso_config_updates_existing(self, mock_ssrf, client, db):
        org = make_org()
        admin = _make_admin_user(org)
        _make_sso_config(org)
        db.session.commit()
        _login(client, admin.email)
        resp = client.post("/org/admin/sso", data={
            "idp_entity_id": "https://new-idp.example.com/metadata",
            "idp_sso_url": "https://new-idp.example.com/saml/sso",
            "idp_certificate": "-----BEGIN CERTIFICATE-----\nUPDATED\n-----END CERTIFICATE-----",
        }, follow_redirects=True)
        assert resp.status_code == 200
        cfg = SSOConfiguration.query.filter_by(org_id=org.id).first()
        assert cfg.idp_entity_id == "https://new-idp.example.com/metadata"
        assert cfg.allow_password_login is False

    def test_ssrf_guard_blocks_private_idp_url(self, client, db):
        org = make_org()
        admin = _make_admin_user(org)
        db.session.commit()
        _login(client, admin.email)
        resp = client.post("/org/admin/sso", data={
            "idp_entity_id": "https://idp.evil.com/metadata",
            "idp_sso_url": "http://169.254.169.254/latest/meta-data/",
            "idp_certificate": "FAKE-CERT",
            "allow_password_login": True,
        }, follow_redirects=True)
        assert resp.status_code == 200
        cfg = SSOConfiguration.query.filter_by(org_id=org.id).first()
        assert cfg is None  # should not have been saved

    def test_ssrf_guard_blocks_private_metadata_url(self, client, db):
        org = make_org()
        admin = _make_admin_user(org)
        db.session.commit()
        _login(client, admin.email)
        resp = client.post("/org/admin/sso", data={
            "idp_entity_id": "https://idp.evil.com/metadata",
            "idp_sso_url": "https://idp.evil.com/saml/sso",
            "idp_certificate": "FAKE-CERT",
            "idp_metadata_url": "http://169.254.169.254/latest/meta-data/",
            "allow_password_login": True,
        }, follow_redirects=True)
        assert resp.status_code == 200
        cfg = SSOConfiguration.query.filter_by(org_id=org.id).first()
        assert cfg is None

    def test_toggle_sso_enable(self, client, db):
        org = make_org()
        admin = _make_admin_user(org)
        _make_sso_config(org, enabled=False)
        db.session.commit()
        _login(client, admin.email)
        resp = client.post("/org/admin/sso/toggle", follow_redirects=True)
        assert resp.status_code == 200
        cfg = SSOConfiguration.query.filter_by(org_id=org.id).first()
        assert cfg.enabled is True

    def test_toggle_sso_disable(self, client, db):
        org = make_org()
        admin = _make_admin_user(org)
        _make_sso_config(org, enabled=True)
        db.session.commit()
        _login(client, admin.email)
        resp = client.post("/org/admin/sso/toggle", follow_redirects=True)
        assert resp.status_code == 200
        cfg = SSOConfiguration.query.filter_by(org_id=org.id).first()
        assert cfg.enabled is False

    def test_toggle_without_config_redirects(self, client, db):
        org = make_org()
        admin = _make_admin_user(org)
        db.session.commit()
        _login(client, admin.email)
        resp = client.post("/org/admin/sso/toggle", follow_redirects=True)
        assert resp.status_code == 200
        # Should flash an error and redirect to admin
        assert SSOConfiguration.query.filter_by(org_id=org.id).first() is None

    def test_sso_config_appears_on_admin_page(self, client, db):
        org = make_org()
        admin = _make_admin_user(org)
        _make_sso_config(org, enabled=True)
        db.session.commit()
        _login(client, admin.email)
        resp = client.get("/org/admin")
        assert resp.status_code == 200
        assert b"SSO Enabled" in resp.data
        assert b"idp.example.com" in resp.data


# ---------------------------------------------------------------------------
# GET/POST /login/sso — email discovery
# ---------------------------------------------------------------------------

class TestSSODiscover:
    def test_get_renders_form(self, client, db):
        db.session.commit()
        resp = client.get("/login/sso")
        assert resp.status_code == 200
        assert b"Sign in with SSO" in resp.data
        assert b"sso-email" in resp.data

    def test_post_matching_domain_redirects_to_login_saml(self, client, db):
        org = make_org()
        _make_sso_config(org, enabled=True)
        _make_verified_domain(org, domain="acme.com")
        db.session.commit()
        resp = client.post("/login/sso", data={"email": "user@acme.com"})
        assert resp.status_code == 302
        assert f"/login/saml?org={org.id}" in resp.headers["Location"]

    def test_post_email_without_at_returns_400(self, client, db):
        db.session.commit()
        resp = client.post("/login/sso", data={"email": "not-an-email"})
        assert resp.status_code == 400
        assert b"valid email" in resp.data

    def test_post_empty_email_returns_400(self, client, db):
        db.session.commit()
        resp = client.post("/login/sso", data={"email": ""})
        assert resp.status_code == 400

    def test_post_unknown_domain_returns_400(self, client, db):
        org = make_org()
        _make_sso_config(org, enabled=True)
        _make_verified_domain(org, domain="acme.com")
        db.session.commit()
        resp = client.post("/login/sso", data={"email": "user@unknown.com"})
        assert resp.status_code == 400
        assert b"SSO" in resp.data  # still says SSO in the error

    def test_post_sso_disabled_org_returns_400(self, client, db):
        org = make_org()
        _make_sso_config(org, enabled=False)
        _make_verified_domain(org, domain="acme.com")
        db.session.commit()
        resp = client.post("/login/sso", data={"email": "user@acme.com"})
        assert resp.status_code == 400

    def test_post_unverified_domain_returns_400(self, client, db):
        org = make_org()
        _make_sso_config(org, enabled=True)
        # Domain exists but verified_at is None
        dv = DomainVerification(
            org_id=org.id, domain="acme.com",
            method=VerifyMethod.DNS_TXT, token="tok",
        )
        db.session.add(dv)
        db.session.commit()
        resp = client.post("/login/sso", data={"email": "user@acme.com"})
        assert resp.status_code == 400

    def test_login_page_has_sso_button(self, client, db):
        db.session.commit()
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"Sign in with SSO" in resp.data
        assert b"icon-sso" in resp.data
