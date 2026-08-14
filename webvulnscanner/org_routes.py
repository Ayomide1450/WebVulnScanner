"""
Blueprint `org`: /org/verify-domain, /org/admin (+ invite/resend/revoke,
domain deletion request/approve/reject).

Every route here requires both `@login_required` (must be authenticated)
and `@org_admin_required` (must be `Role.ORG_ADMIN`) - see
`webvulnscanner/decorators.py`.

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
from wtforms import SelectField, StringField
from wtforms.validators import DataRequired, Email

from webvulnscanner.decorators import org_admin_required
from webvulnscanner.domain_verification import (
    generate_verification,
    txt_record_value,
    verify_domain,
    well_known_path_and_content,
)
from webvulnscanner.extensions import db
from webvulnscanner.models import DomainVerification, Invitation, InvitationStatus, OrgAuditEvent, Role, Scan, VerifyMethod, _utcnow

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
ORG_AUDIT_EVENT_LABELS = {
    "domain_added": "Domain added",
    "domain_verified": "Domain verified",
    "domain_deletion_requested": "Domain deletion requested",
    "domain_deletion_approved": "Domain deletion approved",
    "domain_deletion_rejected": "Domain deletion rejected",
    "member_invited": "Member invited",
    "invitation_revoked": "Invitation revoked",
    "invitation_resent": "Invitation resent",
    "role_changed": "Role changed",
}


def _log_org_event(event_type, detail=None):
    """Records one row in the org-management audit log (separate from the
    Scan-history audit trail org_admin.html already shows). Best-effort:
    never raises past the caller, since a failed audit-log write must not
    block the action it's logging (same degrade-gracefully convention as
    every check_* function in checks.py) - but it does run in the same
    transaction as the action itself when possible, so a commit failure
    still rolls both back together."""
    db.session.add(OrgAuditEvent(
        org_id=current_user.org_id,
        actor_id=current_user.id,
        event_type=event_type,
        detail=detail,
    ))


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


@org.route("/admin")
@login_required
@org_admin_required
def admin():
    org_obj = current_user.organization
    members = org_obj.users if org_obj else []
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
    return render_template(
        "org_admin.html",
        org=org_obj,
        members=members,
        domains=domains,
        scans=scans,
        invite_form=invite_form,
        pending_invitations=pending_invitations,
        audit_events=audit_events,
        verified_domain_count=verified_domain_count,
        role_labels=ROLE_LABELS,
        scan_type_labels=SCAN_TYPE_LABELS,
        audit_event_labels=ORG_AUDIT_EVENT_LABELS,
    )


def _send_invite_email(email, role):
    token = generate_invite_token(current_user.org_id, role, email)
    invite_link = url_for("auth.signup", invite=token, _external=True)
    sender = current_app.extensions["email_sender"]
    sender.send(
        to=email,
        subject=f"You're invited to join {current_user.organization.name} on WebVulnScanner",
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
# Domain deletion request/approve/reject workflow. Any org admin can
# request a deletion (all of /org/admin is already org_admin_required -
# there's no separate "website admin" platform role in this codebase, so
# approval is gated the same way; a stricter separation-of-duties model
# would need a new platform-staff role, out of scope here) - the important
# behavior is that a request never deletes the row itself, it just flips
# the domain into a "Deletion Pending" state until a second, explicit
# approve/reject action resolves it.
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
@org_admin_required
def approve_domain_deletion(domain_id):
    dv = DomainVerification.query.get_or_404(domain_id)
    if dv.org_id != current_user.org_id:
        abort(404)
    if not dv.deletion_pending:
        abort(404)

    domain_name = dv.domain
    requester = dv.deletion_requested_by.email if dv.deletion_requested_by else "unknown"
    reason = dv.deletion_reason or "(no reason given)"
    _log_org_event(
        "domain_deletion_approved",
        f"{domain_name} - requested by {requester} ({reason}) - approved by {current_user.email}",
    )
    db.session.delete(dv)
    db.session.commit()
    flash(f"{domain_name} deleted.", "info")
    return redirect(url_for("org.admin"))


@org.route("/admin/domain/<int:domain_id>/deletion/reject", methods=["POST"])
@login_required
@org_admin_required
def reject_domain_deletion(domain_id):
    dv = DomainVerification.query.get_or_404(domain_id)
    if dv.org_id != current_user.org_id:
        abort(404)
    if not dv.deletion_pending:
        abort(404)

    requester = dv.deletion_requested_by.email if dv.deletion_requested_by else "unknown"
    reason = dv.deletion_reason or "(no reason given)"
    _log_org_event(
        "domain_deletion_rejected",
        f"{dv.domain} - requested by {requester} ({reason}) - rejected by {current_user.email}",
    )
    dv.deletion_requested_at = None
    dv.deletion_requested_by_id = None
    dv.deletion_reason = None
    db.session.commit()
    flash(f"Deletion request for {dv.domain} rejected. The domain remains active.", "info")
    return redirect(url_for("org.admin"))
