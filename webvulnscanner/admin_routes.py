"""
Blueprint `admin`: /platform-admin - the website's own operator panel, not
to be confused with `/org/admin` (an org's own ORG_ADMIN self-service page).

Every route here requires `platform_admin_required` (webvulnscanner/
decorators.py) - `User.is_platform_admin`, a flag no route can set, only
the `flask grant-platform-admin <email>` CLI command (webvulnscanner/cli.py).

Scope: a cross-org queue of pending domain-deletion requests (the actual
separation-of-duties fix - an org admin can request a deletion, only a
platform admin can approve/reject it, see org_routes.py's
approve_domain_deletion/reject_domain_deletion), the Phase 15 expert-
assessment-request queue, platform-wide counts, and (Phase 16) a user/org
detail view with suspend/unsuspend - still deliberately not a general CRUD
console (no rename/edit-arbitrary-field UI, no hard delete of a user or
org from here); suspension is the one moderation action this phase scopes
in, since it's reversible and doesn't destroy any data.
"""
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy.orm import joinedload

from webvulnscanner.decorators import platform_admin_required
from webvulnscanner.extensions import db
from webvulnscanner.models import (
    AssessmentRequest,
    DomainVerification,
    Organization,
    PlatformAuditEvent,
    Scan,
    User,
    _utcnow,
)

admin = Blueprint("admin", __name__, url_prefix="/platform-admin")


from webvulnscanner.audit import log_platform_event as _log_platform_event


@admin.route("")
@login_required
@platform_admin_required
def platform_dashboard():
    pending_deletions = (
        DomainVerification.query.filter(DomainVerification.deletion_requested_at.isnot(None))
        .options(joinedload(DomainVerification.organization), joinedload(DomainVerification.deletion_requested_by))
        .order_by(DomainVerification.deletion_requested_at.asc())
        .all()
    )
    assessment_requests = (
        AssessmentRequest.query
        .options(joinedload(AssessmentRequest.organization), joinedload(AssessmentRequest.requested_by))
        .order_by(AssessmentRequest.created_at.desc())
        .all()
    )
    counts = {
        "organizations": db.session.query(Organization).count(),
        "users": db.session.query(User).count(),
        "scans": db.session.query(Scan).count(),
        "pending_deletions": len(pending_deletions),
        "assessment_requests": len(assessment_requests),
    }
    return render_template(
        "platform_admin.html",
        pending_deletions=pending_deletions,
        assessment_requests=assessment_requests,
        counts=counts,
    )


@admin.route("/users")
@login_required
@platform_admin_required
def list_users():
    """Cross-org user directory (ADMIN-01) - a simple filterable list, not
    the detail view itself. `q` matches email case-insensitively (an
    exact-tier search is enough for an operator who already knows who
    they're looking for; this isn't meant to replace real log/analytics
    tooling)."""
    q = (request.args.get("q") or "").strip()
    query = User.query.options(joinedload(User.organization))
    if q:
        query = query.filter(User.email.ilike(f"%{q}%"))
    users = query.order_by(User.created_at.desc()).limit(200).all()
    return render_template("platform_admin_users.html", users=users, q=q)


@admin.route("/orgs")
@login_required
@platform_admin_required
def list_orgs():
    """Cross-org directory (ADMIN-01) - see list_users' docstring for the
    same search-scope caveat, matched against Organization.name here."""
    q = (request.args.get("q") or "").strip()
    query = Organization.query
    if q:
        query = query.filter(Organization.name.ilike(f"%{q}%"))
    orgs = query.order_by(Organization.created_at.desc()).limit(200).all()
    return render_template("platform_admin_orgs.html", orgs=orgs, q=q)


@admin.route("/users/<int:user_id>")
@login_required
@platform_admin_required
def user_detail(user_id):
    user = User.query.options(joinedload(User.organization)).get_or_404(user_id)
    scans = (
        Scan.query.filter_by(user_id=user.id)
        .order_by(Scan.created_at.desc())
        .limit(20)
        .all()
    )
    audit_events = (
        PlatformAuditEvent.query
        .filter_by(target_type="user", target_id=user.id)
        .order_by(PlatformAuditEvent.created_at.desc())
        .options(joinedload(PlatformAuditEvent.actor))
        .all()
    )
    return render_template("platform_admin_user_detail.html", user=user, scans=scans, audit_events=audit_events)


@admin.route("/orgs/<int:org_id>")
@login_required
@platform_admin_required
def org_detail(org_id):
    org = Organization.query.get_or_404(org_id)
    members = User.query.filter_by(org_id=org.id).order_by(User.created_at.asc()).all()
    domains = DomainVerification.query.filter_by(org_id=org.id).order_by(DomainVerification.domain.asc()).all()
    scans = (
        Scan.query.filter_by(org_id=org.id)
        .order_by(Scan.created_at.desc())
        .limit(20)
        .all()
    )
    audit_events = (
        PlatformAuditEvent.query
        .filter_by(target_type="organization", target_id=org.id)
        .order_by(PlatformAuditEvent.created_at.desc())
        .options(joinedload(PlatformAuditEvent.actor))
        .all()
    )
    return render_template(
        "platform_admin_org_detail.html", org=org, members=members, domains=domains, scans=scans,
        audit_events=audit_events,
    )


@admin.route("/users/<int:user_id>/suspend", methods=["GET", "POST"])
@login_required
@platform_admin_required
def suspend_user(user_id):
    """GET renders a confirmation page (ADMIN-02 - suspension is a real,
    user-visible consequence, not a one-click toggle like domain-deletion
    approve/reject); POST actually performs it. A platform admin cannot
    suspend their own account (would lock them out with no other admin
    necessarily available) or another platform admin's (a deliberate
    separation - demoting/suspending platform staff isn't in this phase's
    scope, see PROJECT.md if that's ever needed)."""
    user = User.query.get_or_404(user_id)
    if user.suspended_at is not None:
        flash(f"{user.email} is already suspended.", "info")
        return redirect(url_for("admin.user_detail", user_id=user.id))
    if user.id == current_user.id or user.is_platform_admin:
        abort(403)

    if request.method == "POST":
        user.suspended_at = _utcnow()
        _log_platform_event("user", user.id, "user_suspended", f"{user.email} suspended by {current_user.email}")
        db.session.commit()
        flash(f"{user.email} has been suspended.", "info")
        return redirect(url_for("admin.user_detail", user_id=user.id))

    return render_template("platform_admin_confirm.html", action="suspend", target_type="user", target=user)


@admin.route("/users/<int:user_id>/unsuspend", methods=["POST"])
@login_required
@platform_admin_required
def unsuspend_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.suspended_at is None:
        flash(f"{user.email} is not suspended.", "info")
        return redirect(url_for("admin.user_detail", user_id=user.id))

    user.suspended_at = None
    _log_platform_event("user", user.id, "user_unsuspended", f"{user.email} unsuspended by {current_user.email}")
    db.session.commit()
    flash(f"{user.email} has been unsuspended.", "info")
    return redirect(url_for("admin.user_detail", user_id=user.id))


@admin.route("/orgs/<int:org_id>/suspend", methods=["GET", "POST"])
@login_required
@platform_admin_required
def suspend_org(org_id):
    """See suspend_user's docstring - same GET-confirm/POST-perform shape.
    Suspending an org blocks every member's login (User.is_active checks
    the org's suspended_at) without touching each member row."""
    org = Organization.query.get_or_404(org_id)
    if org.suspended_at is not None:
        flash(f"{org.name} is already suspended.", "info")
        return redirect(url_for("admin.org_detail", org_id=org.id))

    if request.method == "POST":
        org.suspended_at = _utcnow()
        _log_platform_event("organization", org.id, "org_suspended", f"{org.name} suspended by {current_user.email}")
        db.session.commit()
        flash(f"{org.name} has been suspended - every member is now blocked from logging in.", "info")
        return redirect(url_for("admin.org_detail", org_id=org.id))

    return render_template("platform_admin_confirm.html", action="suspend", target_type="organization", target=org)


@admin.route("/orgs/<int:org_id>/unsuspend", methods=["POST"])
@login_required
@platform_admin_required
def unsuspend_org(org_id):
    org = Organization.query.get_or_404(org_id)
    if org.suspended_at is None:
        flash(f"{org.name} is not suspended.", "info")
        return redirect(url_for("admin.org_detail", org_id=org.id))

    org.suspended_at = None
    _log_platform_event("organization", org.id, "org_unsuspended", f"{org.name} unsuspended by {current_user.email}")
    db.session.commit()
    flash(f"{org.name} has been unsuspended.", "info")
    return redirect(url_for("admin.org_detail", org_id=org.id))
