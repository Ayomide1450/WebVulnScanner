"""
Blueprint `org`: /org/verify-domain, /org/admin (+ invite/resend/revoke,
domain deletion request/approve/reject).

Every route here requires both `@login_required` (must be authenticated)
and `@org_admin_required` (must be `Role.ORG_ADMIN`) - see
`glassbox/decorators.py`.

`/org/admin/invite` generates a signed, email-bound invite token and
"sends" (console-prints, via the same `EmailSender` pattern as
`auth_routes.py`) a link carrying it. `auth_routes.signup()` consumes that
token: following the link in invite mode joins the signer to the inviting
org at the invited role. The token is bound to the invited email address
(D-07) - `decode_invite_token`'s `expected_email` check rejects a token
redeemed under any other address, so a forwarded or leaked link cannot be
used by someone other than the invitee. Changing an existing member's role
after they've already joined is deliberately still not a route anywhere in
this file (D-06) - role assignment only happens at invite time.

An `Invitation` row is also persisted per send (separate from the signed
token itself) so org_admin.html's "Pending Invitations" table can list/
resend/revoke across requests. Revoking only removes it from the pending
list in the UI - it does not invalidate an already-issued link, since
nothing in `auth_routes.signup()`'s token-consumption path currently
checks `Invitation.status`. That gap is pre-existing (not introduced by
merging these two features) and worth closing in a follow-up.

Domain deletion is a two-step request/approve-or-reject workflow
(`request_domain_deletion` / `approve_domain_deletion` /
`reject_domain_deletion`) - a request only flags `DomainVerification` as
pending, never deletes it; every step is `_log_org_event()`-audited to
`OrgAuditEvent`, which deliberately outlives the `DomainVerification` row
it describes so deletion history survives approval.
"""
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.orm import joinedload
from wtforms import BooleanField, SelectField, StringField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Optional, URL

from glassbox.decorators import org_admin_required, platform_admin_required
from glassbox.domain_verification import (
    generate_verification,
    txt_record_value,
    verify_domain,
    well_known_path_and_content,
)
from glassbox.extensions import db
from glassbox.models import DomainVerification, Invitation, InvitationStatus, OrgAuditEvent, Role, Scan, SSOConfiguration, User, VerifyMethod, _utcnow

org = Blueprint("org", __name__, url_prefix="/org")

INVITE_SALT = "org-invite"
# Invite tokens are valid for 7 days - generous enough for someone to see an
# email and act on it, short enough that a leaked link doesn't stay valid
# forever.
INVITE_MAX_AGE_SECONDS = 7 * 24 * 60 * 60

# Display-only labels for org_admin.html - the underlying Role/Scan.scan_type
# DB values never change, this is purely UI wording (matches
# scan_routes.SCAN_TYPE_LABELS' convention for the same reason).
ROLE_LABELS = {
    Role.ORG_ADMIN.value: "Organization Admin",
    Role.MEMBER.value: "Member",
}
SCAN_TYPE_LABELS = {
    "base": "Standard Scan",
    "advanced": "Advanced Scan",
    "media": "Media Scan",
    "api": "API Scan",
}
from glassbox.audit import ORG_AUDIT_EVENT_LABELS, log_org_event as _log_org_event  # noqa: E402


class AddDomainForm(FlaskForm):
    domain = StringField("Domain", validators=[DataRequired()])
    method = SelectField(
        "Verification method",
        choices=[(m.value, m.value) for m in VerifyMethod],
        validators=[DataRequired()],
    )


class InviteForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    role = SelectField(
        "Role",
        choices=[(r.value, r.value) for r in Role],
        validators=[DataRequired()],
    )


class SSOConfigForm(FlaskForm):
    idp_entity_id = StringField("IdP Entity ID", validators=[DataRequired(), Length(max=2048)])
    idp_sso_url = StringField("IdP SSO URL", validators=[DataRequired(), URL(), Length(max=2048)])
    idp_certificate = TextAreaField(
        "IdP X.509 Certificate (PEM)",
        validators=[DataRequired(), Length(max=16384)],
    )
    idp_metadata_url = StringField(
        "IdP Metadata URL (optional)",
        validators=[Optional(), URL(), Length(max=2048)],
    )
    allow_password_login = BooleanField("Allow password login alongside SSO", default=True)


def _serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=INVITE_SALT)


def generate_invite_token(org_id, role, email):
    """Signs `{org_id, role, email}` into an itsdangerous token for the
    invite link.

    `email` is normalized (stripped and lowercased) inside this function,
    not by the caller, so every token's payload carries a single
    canonical form no matter how the caller received the address - the
    invite is bound to that normalized email (D-07): without this
    binding, a forwarded or leaked link would grant org membership at the
    granted role to whoever opens it, not just the intended invitee.

    Exposed as a module-level function (rather than inlined in the route)
    so it - and `decode_invite_token` below - can be exercised/verified
    directly without going through HTTP.
    """
    return _serializer().dumps({
        "org_id": org_id, "role": role, "email": email.strip().lower(),
    })


def decode_invite_token(token, expected_email=None):
    """Reverses `generate_invite_token`. Returns the decoded dict, or None
    if the token is invalid, expired, or (when `expected_email` is given)
    was issued for a different address.

    The email check lives here, beside the signature and expiry checks,
    so every validity condition for an invite token has one home rather
    than being split across call sites. Pass no `expected_email` to
    decode without that check (e.g. to pre-fill the invited address on a
    GET render before any address has been submitted).
    """
    try:
        payload = _serializer().loads(token, max_age=INVITE_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None

    if expected_email is not None and payload.get("email") != expected_email.strip().lower():
        return None

    return payload


@org.route("/verify-domain", methods=["GET", "POST"])
@login_required
@org_admin_required
def verify_domain_view():
    add_form = AddDomainForm()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "add":
            if add_form.validate_on_submit():
                domain_name = add_form.domain.data.strip().lower()
                generate_verification(
                    current_user.org_id,
                    add_form.domain.data,
                    VerifyMethod(add_form.method.data),
                )
                _log_org_event("domain_added", domain_name)
                db.session.commit()
                flash(
                    f"Verification record generated for {domain_name}. "
                    "Add the TXT record or well-known file below, then click Verify.",
                    "info",
                )
            return redirect(url_for("org.verify_domain_view"))

        if action == "verify":
            domain_id = request.form.get("domain_id", type=int)
            dv = DomainVerification.query.get(domain_id) if domain_id else None
            if dv is None or dv.org_id != current_user.org_id:
                abort(404)
            ok = verify_domain(dv)
            if ok:
                _log_org_event("domain_verified", dv.domain)
                db.session.commit()
                flash(f"{dv.domain} verified successfully.", "info")
            else:
                flash(f"Could not verify {dv.domain} yet - check the record/file and try again.", "error")
            return redirect(url_for("org.verify_domain_view"))

    domains = current_user.organization.domain_verifications if current_user.organization else []
    # Precompute the TXT value / well-known path+content per domain so the
    # template doesn't need to import domain_verification.py itself.
    instructions = {
        dv.id: {
            "txt_value": txt_record_value(dv),
            "well_known": well_known_path_and_content(dv),
        }
        for dv in domains
    }

    return render_template(
        "org_verify_domain.html",
        add_form=add_form,
        domains=domains,
        instructions=instructions,
    )


MEMBERS_PER_PAGE = 20


@org.route("/admin")
@login_required
@org_admin_required
def admin():
    org_obj = current_user.organization
    page = request.args.get("page", 1, type=int)
    # PERF-02: the Members table is DB-level paginated at 20/page via a
    # real .paginate() query on the underlying User query (org_obj.users is
    # an already-loaded relationship list, not a Query - the plan/D-03 needs
    # LIMIT/OFFSET issued at the DB layer, so this queries User directly,
    # matching the Scan.query.filter_by(org_id=...) pattern already used a
    # few lines below for the scans query). member_count stays a SEPARATE,
    # unbounded .count() so the "Members · N" stat is never affected by
    # which page of the table is currently being viewed.
    member_count = User.query.filter_by(org_id=org_obj.id).count() if org_obj else 0
    members_page = (
        User.query.filter_by(org_id=org_obj.id).order_by(User.id)
        .paginate(page=page, per_page=MEMBERS_PER_PAGE, error_out=False)
        if org_obj else None
    )
    domains = org_obj.domain_verifications if org_obj else []
    # Scan rows are written by scan_routes.py (a parallel workstream) - this
    # query is deliberately defensive and will just render an empty table
    # until that workstream lands and org-scoped scans start accumulating.
    # joinedload(Scan.user) + Scan.report - the audit-log table below shows
    # "who ran it" per row and links to the report where one exists, so
    # eager-loading both avoids an N+1 query per row.
    scans = (
        Scan.query.filter_by(org_id=current_user.org_id)
        .options(joinedload(Scan.user), joinedload(Scan.report))
        .order_by(Scan.created_at.desc())
        .limit(50)
        .all()
        if current_user.org_id
        else []
    )
    pending_invitations = (
        Invitation.query.filter_by(org_id=current_user.org_id, status=InvitationStatus.PENDING)
        .order_by(Invitation.created_at.desc())
        .all()
        if current_user.org_id
        else []
    )
    audit_events = (
        OrgAuditEvent.query.filter_by(org_id=current_user.org_id)
        .options(joinedload(OrgAuditEvent.actor))
        .order_by(OrgAuditEvent.created_at.desc())
        .limit(30)
        .all()
        if current_user.org_id
        else []
    )
    verified_domain_count = sum(1 for d in domains if d.verified_at)
    invite_form = InviteForm()
    sso_config = SSOConfiguration.query.filter_by(org_id=org_obj.id).first() if org_obj else None
    return render_template(
        "org_admin.html",
        org=org_obj,
        members_page=members_page,
        member_count=member_count,
        domains=domains,
        scans=scans,
        invite_form=invite_form,
        pending_invitations=pending_invitations,
        audit_events=audit_events,
        verified_domain_count=verified_domain_count,
        role_labels=ROLE_LABELS,
        scan_type_labels=SCAN_TYPE_LABELS,
        audit_event_labels=ORG_AUDIT_EVENT_LABELS,
        sso_config=sso_config,
    )


def _send_invite_email(email, role):
    token = generate_invite_token(current_user.org_id, role, email)
    invite_link = url_for("auth.signup", invite=token, _external=True)
    sender = current_app.extensions["email_sender"]
    sender.send(
        to=email,
        subject=f"You're invited to join {current_user.organization.name} on Glassbox",
        body=(
            f"You've been invited to join {current_user.organization.name} "
            f"as {role}.\n\nClick the link below to sign up:\n\n{invite_link}"
        ),
    )


@org.route("/admin/invite", methods=["POST"])
@login_required
@org_admin_required
def invite():
    form = InviteForm()
    if not form.validate_on_submit():
        for field_errors in form.errors.values():
            for err in field_errors:
                flash(err, "error")
        return redirect(url_for("org.admin"))

    role = form.role.data
    email = form.email.data.strip().lower()
    _send_invite_email(email, role)

    db.session.add(Invitation(
        org_id=current_user.org_id, email=email, role=role, invited_by_id=current_user.id,
    ))
    _log_org_event("member_invited", f"{email} as {ROLE_LABELS.get(role, role)}")
    db.session.commit()

    flash(f"Invitation sent to {email}", "info")
    return redirect(url_for("org.admin"))


@org.route("/admin/invite/<int:invitation_id>/resend", methods=["POST"])
@login_required
@org_admin_required
def resend_invitation(invitation_id):
    inv = Invitation.query.get_or_404(invitation_id)
    if inv.org_id != current_user.org_id:
        abort(404)
    if inv.status != InvitationStatus.PENDING:
        flash("That invitation is no longer pending.", "error")
        return redirect(url_for("org.admin"))

    _send_invite_email(inv.email, inv.role)
    _log_org_event("invitation_resent", inv.email)
    db.session.commit()
    flash(f"Invitation resent to {inv.email}", "info")
    return redirect(url_for("org.admin"))


@org.route("/admin/invite/<int:invitation_id>/revoke", methods=["POST"])
@login_required
@org_admin_required
def revoke_invitation(invitation_id):
    inv = Invitation.query.get_or_404(invitation_id)
    if inv.org_id != current_user.org_id:
        abort(404)

    inv.status = InvitationStatus.REVOKED
    inv.revoked_at = _utcnow()
    _log_org_event("invitation_revoked", inv.email)
    db.session.commit()
    flash(f"Invitation to {inv.email} revoked.", "info")
    return redirect(url_for("org.admin"))


# --------------------------------------------------------------------------
# Domain deletion request/approve/reject workflow. An org admin can
# request a deletion for their own org's domain, but never approve one -
# approve/reject require platform_admin_required instead (see
# glassbox/admin_routes.py for the cross-org review queue), a real
# separation-of-duties gate rather than the same actor being able to both
# request and approve their own request. A request never deletes the row
# itself, it just flips the domain into a "Deletion Pending" state until a
# platform admin's explicit approve/reject action resolves it.
# --------------------------------------------------------------------------

@org.route("/admin/domain/<int:domain_id>/request-deletion", methods=["POST"])
@login_required
@org_admin_required
def request_domain_deletion(domain_id):
    dv = DomainVerification.query.get_or_404(domain_id)
    if dv.org_id != current_user.org_id:
        abort(404)
    if dv.deletion_pending:
        flash(f"A deletion request for {dv.domain} is already pending.", "error")
        return redirect(url_for("org.admin"))

    reason = (request.form.get("reason") or "").strip()
    dv.deletion_requested_at = _utcnow()
    dv.deletion_requested_by_id = current_user.id
    dv.deletion_reason = reason or None
    _log_org_event("domain_deletion_requested", f"{dv.domain}" + (f" - {reason}" if reason else ""))
    db.session.commit()
    flash(f"Deletion requested for {dv.domain}. An admin must approve it before it's removed.", "info")
    return redirect(url_for("org.admin"))


@org.route("/admin/domain/<int:domain_id>/deletion/approve", methods=["POST"])
@login_required
@platform_admin_required
def approve_domain_deletion(domain_id):
    """Platform-admin-only (not org_admin_required) - this is the actual
    separation-of-duties gate: the org admin who requested a deletion
    cannot also be the one who approves it. No org-membership check on
    `dv` either, deliberately - a platform admin reviews requests across
    every org, not just their own."""
    dv = DomainVerification.query.get_or_404(domain_id)
    if not dv.deletion_pending:
        abort(404)

    domain_name = dv.domain
    requester = dv.deletion_requested_by.email if dv.deletion_requested_by else "unknown"
    reason = dv.deletion_reason or "(no reason given)"
    _log_org_event(
        "domain_deletion_approved",
        f"{domain_name} - requested by {requester} ({reason}) - approved by {current_user.email}",
        org_id=dv.org_id,
    )
    db.session.delete(dv)
    db.session.commit()
    flash(f"{domain_name} deleted.", "info")
    return redirect(url_for("admin.platform_dashboard"))


@org.route("/admin/domain/<int:domain_id>/deletion/reject", methods=["POST"])
@login_required
@platform_admin_required
def reject_domain_deletion(domain_id):
    """Platform-admin-only - see approve_domain_deletion's docstring."""
    dv = DomainVerification.query.get_or_404(domain_id)
    if not dv.deletion_pending:
        abort(404)

    requester = dv.deletion_requested_by.email if dv.deletion_requested_by else "unknown"
    reason = dv.deletion_reason or "(no reason given)"
    _log_org_event(
        "domain_deletion_rejected",
        f"{dv.domain} - requested by {requester} ({reason}) - rejected by {current_user.email}",
        org_id=dv.org_id,
    )
    dv.deletion_requested_at = None
    dv.deletion_requested_by_id = None
    dv.deletion_reason = None
    db.session.commit()
    flash(f"Deletion request for {dv.domain} rejected. The domain remains active.", "info")
    return redirect(url_for("admin.platform_dashboard"))


# --------------------------------------------------------------------------
# Audit log (Phase 23 / AUDIT-03)
# --------------------------------------------------------------------------

AUDIT_PER_PAGE = 20


@org.route("/audit")
@login_required
@org_admin_required
def audit_log():
    """Paginated view of the org's audit events (AUDIT-03).  ORG_ADMINs
    see their own org's events; platform admins see all orgs.  Everyone
    else gets 404 (the @org_admin_required decorator handles that).

    Events are rendered with actor email, event type label, detail, and
    timestamp — the dual-markup contract (AUDIT-05) reuses the same
    rendering pattern as org_admin.html's inline audit section but with
    full pagination and a link back from the org admin page."""
    from glassbox.audit import ORG_AUDIT_EVENT_LABELS
    from glassbox.models import Organization

    page = request.args.get("page", 1, type=int)

    if current_user.is_platform_admin:
        # Platform admins see all orgs' events, newest first
        query = (
            OrgAuditEvent.query
            .options(joinedload(OrgAuditEvent.actor), joinedload(OrgAuditEvent.organization))
            .order_by(OrgAuditEvent.created_at.desc())
        )
    else:
        org_id = current_user.org_id
        if not org_id:
            abort(404)
        query = (
            OrgAuditEvent.query.filter_by(org_id=org_id)
            .options(joinedload(OrgAuditEvent.actor))
            .order_by(OrgAuditEvent.created_at.desc())
        )

    pagination = query.paginate(page=page, per_page=AUDIT_PER_PAGE, error_out=False)

    return render_template(
        "audit_log.html",
        events=pagination.items,
        pagination=pagination,
        audit_event_labels=ORG_AUDIT_EVENT_LABELS,
        is_platform_admin=current_user.is_platform_admin,
    )


# --------------------------------------------------------------------------
# SSO Configuration (Phase 26, SSO-03/04/05)
# --------------------------------------------------------------------------

def _ssrf_safe_hostname(hostname):
    """SSRF guard for IdP metadata URL — blocks private/loopback/reserved."""
    from glassbox.checks import is_ssrf_safe_hostname
    try:
        return is_ssrf_safe_hostname(hostname)
    except Exception:
        return False


@org.route("/admin/sso", methods=["GET", "POST"])
@login_required
@org_admin_required
def admin_sso():
    """SSO configuration panel — view/edit the org's SAML IdP settings."""
    org_obj = current_user.organization
    if not org_obj:
        abort(404)

    existing = SSOConfiguration.query.filter_by(org_id=org_obj.id).first()
    form = SSOConfigForm(obj=existing)

    if request.method == "POST" and form.validate_on_submit():
        from urllib.parse import urlparse as _urlparse

        # SSO-05: SSRF guard on IdP SSO URL
        parsed_sso = _urlparse(form.idp_sso_url.data)
        if parsed_sso.hostname and not _ssrf_safe_hostname(parsed_sso.hostname):
            flash("The IdP SSO URL is not a valid public hostname.", "error")
            return redirect(url_for("org.admin_sso"))

        # SSO-05: SSRF guard on IdP metadata URL if provided
        if form.idp_metadata_url.data:
            parsed_meta = _urlparse(form.idp_metadata_url.data)
            if parsed_meta.hostname and not _ssrf_safe_hostname(parsed_meta.hostname):
                flash("The IdP metadata URL is not a valid public hostname.", "error")
                return redirect(url_for("org.admin_sso"))

        # Encrypt the certificate before storing
        encrypted_cert = SSOConfiguration.encrypt_secret(form.idp_certificate.data)
        sp_entity_id = f"https://glassbox.example.com/saml/metadata/{org_obj.id}"

        if existing:
            existing.idp_entity_id = form.idp_entity_id.data.strip()
            existing.idp_sso_url = form.idp_sso_url.data.strip()
            existing.idp_certificate = encrypted_cert
            existing.idp_metadata_url = (form.idp_metadata_url.data or "").strip() or None
            existing.allow_password_login = form.allow_password_login.data
            existing.updated_at = _utcnow()
        else:
            existing = SSOConfiguration(
                org_id=org_obj.id,
                enabled=True,
                idp_entity_id=form.idp_entity_id.data.strip(),
                idp_sso_url=form.idp_sso_url.data.strip(),
                idp_certificate=encrypted_cert,
                idp_metadata_url=(form.idp_metadata_url.data or "").strip() or None,
                allow_password_login=form.allow_password_login.data,
                sp_entity_id=sp_entity_id,
            )
            db.session.add(existing)

        _log_org_event("sso_config_saved", "SSO configuration updated")
        db.session.commit()
        flash("SSO configuration saved.", "info")
        return redirect(url_for("org.admin"))

    return render_template(
        "org_sso.html",
        org=org_obj,
        form=form,
        sso_config=existing,
    )


@org.route("/admin/sso/toggle", methods=["POST"])
@login_required
@org_admin_required
def admin_sso_toggle():
    """Enable or disable SSO for the org."""
    org_obj = current_user.organization
    if not org_obj:
        abort(404)

    existing = SSOConfiguration.query.filter_by(org_id=org_obj.id).first()
    if not existing:
        flash("SSO is not configured for this organization.", "error")
        return redirect(url_for("org.admin"))

    existing.enabled = not existing.enabled
    event = "sso_config_saved" if existing.enabled else "sso_config_disabled"
    _log_org_event(event, f"SSO {'enabled' if existing.enabled else 'disabled'}")
    db.session.commit()

    flash(f"SSO {'enabled' if existing.enabled else 'disabled'}.", "info")
    return redirect(url_for("org.admin"))
