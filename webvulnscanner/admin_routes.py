"""
Blueprint `admin`: /platform-admin - the website's own operator panel, not
to be confused with `/org/admin` (an org's own ORG_ADMIN self-service page).

Every route here requires `platform_admin_required` (webvulnscanner/
decorators.py) - `User.is_platform_admin`, a flag no route can set, only
the `flask grant-platform-admin <email>` CLI command (webvulnscanner/cli.py).

Scope, deliberately narrow for now: a cross-org queue of pending domain-
deletion requests (the actual separation-of-duties fix - an org admin can
request a deletion, only a platform admin can approve/reject it, see
org_routes.py's approve_domain_deletion/reject_domain_deletion) plus basic
platform-wide counts. Not a general org/user CRUD console - growing this
into one is a real, separate feature to scope deliberately later, not
something to bolt on here by default.
"""
from flask import Blueprint, render_template
from flask_login import login_required
from sqlalchemy.orm import joinedload

from webvulnscanner.decorators import platform_admin_required
from webvulnscanner.extensions import db
from webvulnscanner.models import AssessmentRequest, DomainVerification, Organization, Scan, User

admin = Blueprint("admin", __name__, url_prefix="/platform-admin")


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
