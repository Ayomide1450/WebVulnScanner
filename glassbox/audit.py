"""Shared audit-log helpers (Phase 23 / AUDIT-01..05).

Two append-only write paths:

- ``log_org_event`` writes to ``OrgAuditEvent`` (org-scoped mutations:
  invites, domain lifecycle, token/webhook CRUD, billing, role changes).
- ``log_platform_event`` writes to ``PlatformAuditEvent`` (platform-admin
  actions on users/orgs).

Both are best-effort: a failed audit-log write must not block the action
it's logging (same degrade-gracefully convention as every ``check_*``
function in ``checks.py``).  They run in the same transaction as the
action when possible, so a commit failure rolls both back together.

Retention (AUDIT-04): ``log_org_event`` trims the oldest events for the
org when the count exceeds ``MAX_AUDIT_EVENTS_PER_ORG`` — a per-org
trim-on-insert, not a background cleanup command.  The constant is
deliberately generous (10 000 events ≈ years of typical usage) so the
trim is a safety net, not something an org routinely hits.
"""

from flask import current_app
from flask_login import current_user

from glassbox.extensions import db
from glassbox.models import OrgAuditEvent, PlatformAuditEvent

# --- Retention (AUDIT-04) ------------------------------------------------

MAX_AUDIT_EVENTS_PER_ORG = 10_000

# --- Event-type labels (ORG) ---------------------------------------------

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
    # Phase 23 — new emission sites
    "api_token_created": "API token created",
    "api_token_revoked": "API token revoked",
    "webhook_created": "Webhook created",
    "webhook_deleted": "Webhook deleted",
    "webhook_toggled": "Webhook paused/resumed",
    "invoice_created": "Invoice created",
    "invoice_verified": "Payment verified — plan activated",
    # Phase 26 — SSO
    "sso_config_saved": "SSO configuration saved",
    "sso_config_disabled": "SSO configuration disabled",
    "sso_user_login": "SSO user login",
}

# --- Event-type labels (Platform) ----------------------------------------

PLATFORM_AUDIT_EVENT_LABELS = {
    "user_suspended": "User suspended",
    "user_unsuspended": "User unsuspended",
    "org_suspended": "Organization suspended",
    "org_unsuspended": "Organization unsuspended",
}


# --- Write paths ----------------------------------------------------------

def log_org_event(event_type, detail=None, org_id=None):
    """Record one row in the org-management audit log.

    ``org_id`` defaults to ``current_user.org_id`` — correct for every
    org-scoped action where the actor is necessarily a member of that org.
    Domain-deletion approve/reject are the one exception: the actor is a
    platform admin who may not belong to the org, so those call sites
    pass the domain's actual ``org_id`` explicitly.

    Solo users (org_id None) are silently skipped — there is no org
    audit log for a personal account.

    Retention: after the insert, if the org's event count exceeds
    ``MAX_AUDIT_EVENTS_PER_ORG``, the oldest events are trimmed so the
    total stays at the limit.  The trim is part of the same transaction.
    """
    effective_org_id = org_id if org_id is not None else current_user.org_id
    if effective_org_id is None:
        return  # solo user — no org audit log
    try:
        db.session.add(OrgAuditEvent(
            org_id=effective_org_id,
            actor_id=current_user.id,
            event_type=event_type,
            detail=detail,
        ))
        db.session.flush()

        count = OrgAuditEvent.query.filter_by(org_id=effective_org_id).count()
        if count > MAX_AUDIT_EVENTS_PER_ORG:
            excess = count - MAX_AUDIT_EVENTS_PER_ORG
            oldest = (
                OrgAuditEvent.query.filter_by(org_id=effective_org_id)
                .order_by(OrgAuditEvent.created_at.asc())
                .limit(excess)
                .all()
            )
            for ev in oldest:
                db.session.delete(ev)
    except Exception:
        current_app.logger.exception("Failed to write org audit event: %s", event_type)


def log_platform_event(target_type, target_id, event_type, detail=None):
    """Write one row to ``PlatformAuditEvent`` — the platform admin
    action trail.  Same best-effort convention as ``log_org_event``."""
    try:
        db.session.add(PlatformAuditEvent(
            actor_id=current_user.id,
            target_type=target_type,
            target_id=target_id,
            event_type=event_type,
            detail=detail,
        ))
    except Exception:
        current_app.logger.exception("Failed to write platform audit event: %s", event_type)
