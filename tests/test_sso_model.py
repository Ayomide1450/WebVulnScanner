"""Phase 26 (SSO-02): SSOConfiguration model + Fernet encryption tests.

Tests the model layer only — no routes, no template rendering.
Encryption round-trip, org uniqueness, nullable password_hash, and
auth_method column behavior.
"""
import pytest
from tests.conftest import make_org, make_user
from webvulnscanner.models import SSOConfiguration, Organization, Plan, Role


class TestSSOConfigurationModel:
    """SSOConfiguration CRUD + encryption round-trip."""

    def test_encrypt_decrypt_round_trip(self, db):
        plaintext = "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
        ciphertext = SSOConfiguration.encrypt_secret(plaintext)
        assert ciphertext != plaintext
        decrypted = SSOConfiguration.decrypt_secret(ciphertext)
        assert decrypted == plaintext

    def test_different_inputs_produce_different_ciphertext(self, db):
        ct1 = SSOConfiguration.encrypt_secret("secret-alpha")
        ct2 = SSOConfiguration.encrypt_secret("secret-beta")
        assert ct1 != ct2

    def test_create_sso_configuration(self, db):
        org = make_org()
        sso = SSOConfiguration(
            org_id=org.id,
            enabled=True,
            allow_password_login=True,
            idp_entity_id="https://idp.example.com/saml/metadata",
            idp_sso_url="https://idp.example.com/saml/sso",
            idp_certificate=SSOConfiguration.encrypt_secret("test-cert"),
            sp_entity_id="https://glassbox.example.com/saml/metadata",
        )
        db.session.add(sso)
        db.session.flush()
        assert sso.id is not None
        assert sso.enabled is True
        assert sso.allow_password_login is True

    def test_org_unique_constraint(self, db):
        org = make_org()
        sso1 = SSOConfiguration(
            org_id=org.id,
            enabled=False,
            allow_password_login=True,
            idp_entity_id="https://idp1.example.com",
            idp_sso_url="https://idp1.example.com/sso",
            idp_certificate=SSOConfiguration.encrypt_secret("cert1"),
            sp_entity_id="https://glassbox.example.com/saml/metadata",
        )
        db.session.add(sso1)
        db.session.flush()

        sso2 = SSOConfiguration(
            org_id=org.id,  # same org
            enabled=True,
            allow_password_login=True,
            idp_entity_id="https://idp2.example.com",
            idp_sso_url="https://idp2.example.com/sso",
            idp_certificate=SSOConfiguration.encrypt_secret("cert2"),
            sp_entity_id="https://glassbox.example.com/saml/metadata",
        )
        db.session.add(sso2)
        with pytest.raises(Exception):  # IntegrityError
            db.session.flush()

    def test_optional_metadata_fields(self, db):
        org = make_org()
        sso = SSOConfiguration(
            org_id=org.id,
            enabled=False,
            allow_password_login=True,
            idp_entity_id="https://idp.example.com",
            idp_sso_url="https://idp.example.com/sso",
            idp_certificate=SSOConfiguration.encrypt_secret("cert"),
            idp_metadata_url="https://idp.example.com/metadata.xml",
            idp_metadata_xml="<EntityDescriptor>...</EntityDescriptor>",
            sp_entity_id="https://glassbox.example.com/saml/metadata",
        )
        db.session.add(sso)
        db.session.flush()
        assert sso.idp_metadata_url is not None
        assert sso.idp_metadata_xml is not None

    def test_defaults(self, db):
        org = make_org()
        sso = SSOConfiguration(
            org_id=org.id,
            idp_entity_id="https://idp.example.com",
            idp_sso_url="https://idp.example.com/sso",
            idp_certificate=SSOConfiguration.encrypt_secret("cert"),
            sp_entity_id="https://glassbox.example.com/saml/metadata",
        )
        db.session.add(sso)
        db.session.flush()
        assert sso.enabled is False
        assert sso.allow_password_login is True

    def test_organization_relationship(self, db):
        org = make_org()
        sso = SSOConfiguration(
            org_id=org.id,
            enabled=True,
            allow_password_login=True,
            idp_entity_id="https://idp.example.com",
            idp_sso_url="https://idp.example.com/sso",
            idp_certificate=SSOConfiguration.encrypt_secret("cert"),
            sp_entity_id="https://glassbox.example.com/saml/metadata",
        )
        db.session.add(sso)
        db.session.flush()

        # Reload from relationship
        db.session.refresh(org)
        assert org.sso_configuration is not None
        assert org.sso_configuration.idp_entity_id == "https://idp.example.com"


class TestUserAuthMethod:
    """User.auth_method column + nullable password_hash."""

    def test_default_auth_method(self, db):
        user = make_user("default@example.com")
        assert user.auth_method == "password"

    def test_sso_user_nullable_password(self, db):
        user = make_user("sso@example.com")
        user.password_hash = None
        user.auth_method = "sso"
        db.session.flush()
        assert user.password_hash is None
        assert user.auth_method == "sso"

    def test_password_user_has_hash(self, db):
        user = make_user("pw@example.com")
        assert user.password_hash is not None
        assert user.auth_method == "password"
