"""
Blueprint `org`: /org/verify-domain, /org/admin, /org/admin/invite.

Every route here requires both `@login_required` (must be authenticated)
and `@org_admin_required` (must be `Role.ORG_ADMIN`) - see
`webvulnscanner/decorators.py`.

Scope boundary (flagged per the plan): `/org/admin/invite` only generates
and "sends" (console-prints, via the same `EmailSender` pattern as
`auth_routes.py`) a signed invite link. It does NOT modify `/signup` to
accept an `invite` query param and consume the token - that's explicitly
called out in the plan as a follow-up needing more design discussion
(does an invited user set their own password vs. get a temp one?) and is
out of scope for this workstream.
"""
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from wtforms import SelectField, StringField
from wtforms.validators import DataRequired, Email

from webvulnscanner.decorators import org_admin_required
from webvulnscanner.domain_verification import (
    generate_verification,
    txt_record_value,
    verify_domain,
    well_known_path_and_content,
)
from webvulnscanner.models import DomainVerification, Role, Scan, VerifyMethod

org = Blueprint("org", __name__, url_prefix="/org")

INVITE_SALT = "org-invite"
# Invite tokens are valid for 7 days - generous enough for someone to see an
# email and act on it, short enough that a leaked link doesn't stay valid
# forever.
INVITE_MAX_AGE_SECONDS = 7 * 24 * 60 * 60


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


def generate_invite_token(org_id, role):
    """Signs `{org_id, role}` into an itsdangerous token for the invite link.

    Exposed as a module-level function (rather than inlined in the route)
    so it - and `decode_invite_token` below - can be exercised/verified
    directly without going through HTTP.
    """
    return _serializer().dumps({"org_id": org_id, "role": role})


def decode_invite_token(token):
    """Reverses `generate_invite_token`. Returns the decoded dict, or None
    if the token is invalid/expired."""
    try:
        return _serializer().loads(token, max_age=INVITE_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None


@org.route("/verify-domain", methods=["GET", "POST"])
@login_required
@org_admin_required
def verify_domain_view():
    add_form = AddDomainForm()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "add":
            if add_form.validate_on_submit():
                generate_verification(
                    current_user.org_id,
                    add_form.domain.data,
                    VerifyMethod(add_form.method.data),
                )
                flash(
                    f"Verification record generated for {add_form.domain.data.strip().lower()}. "
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
    scans = (
        Scan.query.filter_by(org_id=current_user.org_id)
        .order_by(Scan.created_at.desc())
        .limit(50)
        .all()
        if current_user.org_id
        else []
    )
    invite_form = InviteForm()
    return render_template(
        "org_admin.html",
        org=org_obj,
        members=members,
        domains=domains,
        scans=scans,
        invite_form=invite_form,
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
    token = generate_invite_token(current_user.org_id, role)
    invite_link = url_for("auth.signup", invite=token, _external=True)

    sender = current_app.extensions["email_sender"]
    sender.send(
        to=form.email.data.strip().lower(),
        subject=f"You're invited to join {current_user.organization.name} on WebVulnScanner",
        body=(
            f"You've been invited to join {current_user.organization.name} "
            f"as {role}.\n\nClick the link below to sign up:\n\n{invite_link}\n\n"
            "Note: this link is generated and printed to the console for now - "
            "signup does not yet consume the invite token automatically."
        ),
    )

    flash(f"Invite link generated and printed to the server console for {form.email.data}.", "info")
    return redirect(url_for("org.admin"))
