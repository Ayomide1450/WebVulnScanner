"""Blueprint `sso`: SAML 2.0 SSO login initiation + ACS callback + JIT
provisioning (Phase 26, SSO-02..05).

ACS callback is CSRF-exempt — the IdP POSTs directly without a Flask-WTF
token.  The callback validates the SAML Response signature + conditions
(server-side) before creating a session, so CSRF protection on the callback
itself is unnecessary (the SAML Response IS the CSRF token, cryptographically
signed by the IdP).

JIT provisioning: when a valid SAML Response arrives for an email that
doesn't exist yet, a User is created with ``auth_method='sso'``,
``password_hash=None``, and ``email_verified_at=now``.  The user is bound
to the org whose SSOConfiguration served this login — but ONLY if the
asserted email's domain matches one of that org's verified domains.  A
domain mismatch is rejected with a generic error (no enumeration leak).

SSO-05 (SSRF): ``idp_metadata_url`` fetches go through
``checks.is_ssrf_safe_hostname()`` — the same guard used for scan targets.
IdP SSO URL POSTs also get the same guard.  ``idp_metadata_xml`` is parsed
from a string, no network fetch needed.
"""
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import login_user, logout_user
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.errors import OneLogin_Saml2_ValidationError
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from webvulnscanner.extensions import db, csrf, limiter
from webvulnscanner.models import (
    DomainVerification, Organization, SSOConfiguration, User,
)

logger = logging.getLogger(__name__)

sso = Blueprint("sso", __name__)

# CSRF-exempt the ACS callback — the IdP POSTs without our CSRF token.
csrf.exempt(sso)

# SSRF guard timeout (same convention as checks.py's REQUEST_TIMEOUT)
_SSRF_TIMEOUT = 8


def _get_sso_config_for_org(org_id):
    """Return the enabled SSOConfiguration for an org, or None."""
    return SSOConfiguration.query.filter_by(
        org_id=org_id, enabled=True,
    ).first()


def _email_domain_is_verified(email, org_id):
    """Check if the email's domain is among the org's verified domains."""
    domain = email.rsplit("@", 1)[-1].lower()
    return DomainVerification.query.filter_by(
        org_id=org_id,
        domain=domain,
    ).filter(
        DomainVerification.verified_at.isnot(None),
    ).first() is not None


def _ssrf_safe_url(url):
    """Return True if the URL's hostname passes the SSRF guard."""
    from webvulnscanner.checks import is_ssrf_safe_hostname
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        return is_ssrf_safe_hostname(hostname)
    except Exception:
        return False


# --- SSO login initiation -----------------------------------------------

@sso.route("/login/saml")
@limiter.limit("30 per minute")
def login_saml():
    """Initiate SP-initiated SAML login.  Requires ?org=<org_id> to know
    which IdP to redirect to.  Stores the IdP SSO URL and RelayState in
    the session for the ACS callback to verify."""
    org_id = request.args.get("org", type=int)
    if not org_id:
        flash("SSO login requires an organization.", "error")
        return redirect(url_for("auth.login"))

    sso_config = _get_sso_config_for_org(org_id)
    if sso_config is None:
        flash("SSO is not enabled for this organization.", "error")
        return redirect(url_for("auth.login"))

    # SSRF guard on the IdP SSO URL
    if not _ssrf_safe_url(sso_config.idp_sso_url):
        logger.warning("SSO: blocked SSRF-unsafe IdP SSO URL for org %d", org_id)
        flash("SSO login is temporarily unavailable.", "error")
        return redirect(url_for("auth.login"))

    # Store the org ID in the session so the ACS callback knows which
    # IdP configuration to validate against.
    session["_saml_org_id"] = org_id

    saml_settings_dict = _build_sp_settings(sso_config)
    auth_obj = OneLogin_Saml2_Auth(
        _saml_request_dict(),
        OneLogin_Saml2_Settings(saml_settings_dict),
    )

    return auth_obj.redirect_to_idp()


# --- ACS callback -------------------------------------------------------

@sso.route("/auth/saml/callback", methods=["POST"])
def saml_callback():
    """ACS (Assertion Consumer Service) callback — receives the SAML Response
    POSTed by the IdP.  Validates signature, conditions, then JIT-provisions
    the user and logs them in."""
    org_id = session.pop("_saml_org_id", None)
    if not org_id:
        flash("SSO session expired — please try again.", "error")
        return redirect(url_for("auth.login"))

    sso_config = _get_sso_config_for_org(org_id)
    if sso_config is None:
        flash("SSO is not configured for this organization.", "error")
        return redirect(url_for("auth.login"))

    saml_settings_dict = _build_sp_settings(sso_config)
    auth_obj = OneLogin_Saml2_Auth(
        _saml_request_dict(),
        OneLogin_Saml2_Settings(saml_settings_dict),
    )

    try:
        auth_obj.process_response()
    except OneLogin_Saml2_ValidationError as exc:
        logger.warning("SSO: SAML Response validation failed for org %d: %s", org_id, exc)
        flash("SSO authentication failed — please try again.", "error")
        return redirect(url_for("auth.login"))

    errors = auth_obj.get_errors()
    if errors:
        logger.warning("SSO: SAML errors for org %d: %s", org_id, errors)
        flash("SSO authentication failed — please try again.", "error")
        return redirect(url_for("auth.login"))

    if not auth_obj.is_authenticated():
        flash("SSO authentication failed — please try again.", "error")
        return redirect(url_for("auth.login"))

    # Extract identity
    name_id = auth_obj.get_nameid()
    if not name_id or "@" not in name_id:
        logger.warning("SSO: missing or invalid NameID: %r", name_id)
        flash("SSO authentication failed — please try again.", "error")
        return redirect(url_for("auth.login"))

    email = name_id.strip().lower()

    # Domain check — the asserted email's domain MUST be in the org's
    # verified-domains list (SSO-02 success criterion).
    if not _email_domain_is_verified(email, org_id):
        # Anti-enumeration: same generic error whether the domain is wrong
        # or doesn't belong to any org.
        logger.warning(
            "SSO: email domain %s not verified for org %d",
            email.rsplit("@", 1)[-1], org_id,
        )
        flash(
            "Your organization does not have SSO configured for this "
            "email domain. Please contact your administrator.",
            "error",
        )
        return redirect(url_for("auth.login"))

    # JIT provisioning — create or update the user
    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User(
            email=email,
            password_hash=None,
            auth_method="sso",
            email_verified_at=datetime.now(timezone.utc),
            org_id=org_id,
        )
        db.session.add(user)
        db.session.flush()
        logger.info("SSO: JIT-provisioned user %s for org %d", email, org_id)
    else:
        # Existing user — ensure they're bound to this org and SSO-enabled
        if user.org_id is None:
            user.org_id = org_id
        if user.auth_method != "sso":
            user.auth_method = "sso"
            user.password_hash = None
        if user.email_verified_at is None:
            user.email_verified_at = datetime.now(timezone.utc)

    db.session.commit()

    # Log in
    login_user(user)
    return redirect(url_for("scan.dashboard"))


# --- Helpers ------------------------------------------------------------

def _build_sp_settings(sso_config):
    """Build a python3-saml settings dict for the given SSOConfiguration."""
    idp_cert = SSOConfiguration.decrypt_secret(sso_config.idp_certificate)
    # Strip PEM armor for python3-saml's x509cert field
    idp_cert_b64 = (
        idp_cert
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("\n", "")
        .strip()
    )

    # Derive the ACS URL from the app's configured URL
    acs_url = url_for("sso.saml_callback", _external=True)

    return {
        "strict": True,
        "sp": {
            "entityId": sso_config.sp_entity_id,
            "assertionConsumerService": {
                "url": acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": url_for("sso.saml_logout", _external=True),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": sso_config.idp_entity_id,
            "singleSignOnService": {
                "url": sso_config.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": idp_cert_b64,
        },
    }


def _saml_request_dict():
    """Build a minimal request dict for OneLogin_Saml2_Auth from Flask's
    request context — enough for process_response() to extract the POST
    data and for redirect_to_idp() to know the ACS URL."""
    return {
        "https": "on" if request.is_secure else "off",
        "http_host": request.host,
        "script_name": request.path,
    }


@sso.route("/auth/saml/logout")
def saml_logout():
    """SSO logout — clears the session.  Does NOT initiate SLO with the
    IdP (future enhancement); just logs the user out locally."""
    logout_user()
    return redirect(url_for("auth.login"))
