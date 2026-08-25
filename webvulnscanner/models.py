"""
Data model for the webvulnscanner package.

Schema, FKs, and uniqueness constraints follow the plan's Workstream 1
"Data model" section exactly. Timestamps use `datetime.now(timezone.utc)`,
matching app.py's existing convention for `scanned_at` in the legacy JSON
reports.

The `@login_manager.user_loader` callback lives in `extensions.py`, not
here (see the comment there for why).
"""
import enum
from datetime import datetime, timezone

from flask_login import UserMixin

from webvulnscanner.extensions import db


def _utcnow():
    return datetime.now(timezone.utc)


class Role(enum.Enum):
    MEMBER = "member"
    ORG_ADMIN = "org_admin"


class Plan(enum.Enum):
    FREE = "free"
    PAID = "paid"
    ORG_VERIFIED = "org_verified"


class SubStatus(enum.Enum):
    NONE = "none"
    PENDING = "pending"
    ACTIVE = "active"
    EXPIRED = "expired"
    CANCELED = "canceled"


class ScanStatus(enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class VerifyMethod(enum.Enum):
    DNS_TXT = "dns_txt"
    WELL_KNOWN = "well_known"


class InvoiceStatus(enum.Enum):
    PENDING = "pending"
    PAID = "paid"
    EXPIRED = "expired"
    MISMATCHED = "mismatched"


class InvitationStatus(enum.Enum):
    PENDING = "pending"
    REVOKED = "revoked"


class Organization(db.Model):
    __tablename__ = "organizations"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    plan = db.Column(db.Enum(Plan), nullable=False, default=Plan.FREE)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)
    # Platform-admin suspension (Phase 16, ADMIN-03) - blocks login for
    # every member (User.is_active checks this), cascading without having
    # to touch each member row individually. Only ever set via
    # admin_routes.suspend_org/unsuspend_org.
    suspended_at = db.Column(db.DateTime(timezone=True), nullable=True)

    users = db.relationship("User", back_populates="organization")
    domain_verifications = db.relationship("DomainVerification", back_populates="organization")
    subscription = db.relationship("Subscription", back_populates="organization", uselist=False)
    crypto_invoices = db.relationship("CryptoInvoice", back_populates="organization")


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), nullable=True)
    role = db.Column(db.Enum(Role), nullable=False, default=Role.MEMBER)
    # Platform-staff privilege, orthogonal to `role` (which is org-scoped:
    # MEMBER/ORG_ADMIN only make sense within one org). Gates
    # decorators.platform_admin_required - the website's own operators
    # (not an org admin) reviewing cross-org actions like domain-deletion
    # approval. Nothing in the app can set this via a route - only the
    # `flask grant-platform-admin <email>` CLI command (webvulnscanner/cli.py)
    # can, so it can never be granted by a bug in ordinary request handling.
    is_platform_admin = db.Column(db.Boolean, nullable=False, default=False, server_default="false")
    email_verified_at = db.Column(db.DateTime(timezone=True), nullable=True)
    verify_token = db.Column(db.String(64), unique=True, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    organization = db.relationship("Organization", back_populates="users")
    scans = db.relationship("Scan", back_populates="user")

    def get_id(self):
        return str(self.id)

    # Platform-admin suspension (Phase 16, ADMIN-02) - distinct from
    # deletion: a suspended account still exists (its scans/reports/org
    # membership are untouched) but cannot log in or use an existing
    # session until unsuspended. Only ever set via
    # admin_routes.suspend_user/unsuspend_user - no self-service path.
    suspended_at = db.Column(db.DateTime(timezone=True), nullable=True)

    @property
    def is_active(self):
        # Unverified email does not block login (decision documented in
        # auth_routes.py / the plan's Workstream 1 section) - every created
        # user is "active" for Flask-Login purposes regardless of
        # email_verified_at. A suspended user, or a member of a suspended
        # org, is not - Flask-Login's login_user() refuses to authenticate
        # an inactive user, and __init__.py's before_request hook forces
        # out an already-open session the moment this flips false.
        if self.suspended_at is not None:
            return False
        if self.organization is not None and self.organization.suspended_at is not None:
            return False
        return True


class PasswordReset(db.Model):
    """One-time password-reset tokens, same pattern as User.verify_token
    but its own table rather than a column on User - added after the app
    already had a live database, and db.create_all() can only create new
    tables, never ALTER an existing one."""
    __tablename__ = "password_resets"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    user = db.relationship("User")


class DomainVerification(db.Model):
    __tablename__ = "domain_verifications"
    __table_args__ = (
        db.UniqueConstraint("org_id", "domain", name="uq_domain_verifications_org_domain"),
    )

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    method = db.Column(db.Enum(VerifyMethod), nullable=False)
    token = db.Column(db.String(64), nullable=False)
    verified_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    # Deletion-request workflow: requesting a deletion never deletes the row
    # directly - it just stamps these three columns so the domain shows as
    # "Deletion Pending" until an admin approves (row is deleted, the event
    # is recorded in OrgAuditEvent so history survives the row's removal)
    # or rejects (these three columns are cleared back to None, domain stays
    # active). See org_routes.py's request_domain_deletion/approve/reject.
    deletion_requested_at = db.Column(db.DateTime(timezone=True), nullable=True)
    deletion_requested_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    deletion_reason = db.Column(db.Text, nullable=True)

    organization = db.relationship("Organization", back_populates="domain_verifications")
    deletion_requested_by = db.relationship("User", foreign_keys=[deletion_requested_by_id])

    @property
    def deletion_pending(self):
        return self.deletion_requested_at is not None


class Asset(db.Model):
    """A persistent, recurring scan target (Phase 1, ASSET-01..08) - distinct
    from a one-off manual Scan. Registering an Asset arms a schedule
    (cadence + scan type); webvulnscanner.scheduler's tick loop claims due
    Assets and fires a Scan(asset_id=...) automatically, re-checking SSRF
    safety and tier entitlement at fire time (never cached from
    registration), see scheduler.py's module docstring.

    org_id is nullable to mirror Scan.org_id's existing convention for solo
    (no-org) users - see asset_routes._check_asset_access for the ownership
    check this requires (an org_id IS NULL comparison alone would leak one
    solo user's Assets to another).

    schedule_scan_type intentionally excludes "advanced" - that scan type
    needs a full credentialed form dict with no sane unattended-recurring
    representation short of persisting login credentials on this row (see
    01-01-PLAN.md's action text for the full rationale).
    """
    __tablename__ = "assets"
    __table_args__ = (
        db.Index("ix_assets_org_deleted", "org_id", "deleted_at"),
        db.Index("ix_assets_next_run_at", "next_run_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), nullable=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    authorized_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    authorized_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)
    name = db.Column(db.String(255), nullable=False)
    target_url = db.Column(db.String(2048), nullable=False)
    hostname = db.Column(db.String(255), nullable=False)
    cadence = db.Column(db.String(16), nullable=False)  # "daily" | "weekly" | "monthly"
    schedule_scan_type = db.Column(db.String(16), nullable=False)  # "base" | "media" | "api"
    next_run_at = db.Column(db.DateTime(timezone=True), nullable=False)
    # D-02's claim-guard lease - see scheduler._try_claim. Nullable: NULL
    # means unclaimed/lease expired.
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)
    is_paused = db.Column(db.Boolean, nullable=False, default=False)
    # NULL = active. Soft-delete only (Plan 01-02 sets this on delete) -
    # past Scan history for a deleted Asset is kept for the org's records.
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    organization = db.relationship("Organization")
    scans = db.relationship("Scan", back_populates="asset")


class ApiToken(db.Model):
    """A user-scoped, hash-only API token (Phase 2, API-01/D-01..D-04). Acts
    as the exact user who created it - no independent authorization model,
    see entitlements.py/asset_routes.py's existing checks, all reused
    unchanged for token-authenticated requests via
    login_manager.request_loader (extensions.py). Only token_hash is ever
    persisted - the raw token exists only as a local variable in
    api_tokens_routes.create_token, shown to the user exactly once (D-01)."""
    __tablename__ = "api_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String(255), nullable=False)  # D-04: user-facing label, e.g. "CI pipeline"
    token_hash = db.Column(db.String(64), unique=True, nullable=False)  # sha256 hexdigest, D-01
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)
    last_used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    # NULL = active. Soft-revoke only (D-03), mirrors Asset.deleted_at's convention exactly.
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    user = db.relationship("User")


class Scan(db.Model):
    __tablename__ = "scans"
    __table_args__ = (
        db.Index("ix_scans_user_created", "user_id", "created_at"),
        db.Index("ix_scans_org_created", "org_id", "created_at"),
        db.Index("ix_scans_asset_created", "asset_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), nullable=True)
    # Nullable so the existing manual-scan flow (no Asset involved) is
    # completely unaffected - only scans spawned by webvulnscanner.scheduler
    # ever set this.
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=True)
    target_url = db.Column(db.String(2048), nullable=False)
    scan_type = db.Column(db.String(16), nullable=False)  # "base" | "advanced" | "media" | "api"
    status = db.Column(db.Enum(ScanStatus), nullable=False, default=ScanStatus.QUEUED)
    risk_score = db.Column(db.Integer, nullable=True)
    progress_current = db.Column(db.Integer, nullable=False, default=0)
    progress_total = db.Column(db.Integer, nullable=False, default=0)
    error_message = db.Column(db.Text, nullable=True)
    started_at = db.Column(db.DateTime(timezone=True), nullable=True)
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    user = db.relationship("User", back_populates="scans")
    report = db.relationship("Report", back_populates="scan", uselist=False)
    asset = db.relationship("Asset", back_populates="scans")


class ScanEventPhase(enum.Enum):
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanEvent(db.Model):
    """Append-only, per-check timeline for a running scan - what drives the
    live "watching it think" feed on scan_progress.html. New table (not a
    column on Scan) for the same reason PasswordReset is its own table:
    db.create_all() only creates new tables, it never ALTERs an existing
    one, so a live DB can't gain a column on Scan without a manual migration.

    `id` doubles as the SSE delivery cursor for scan_routes.scan_events() -
    it's already a monotonic per-row PK, and the composite (scan_id, id)
    index below makes "events for this scan after cursor N" an index-range
    scan, so a separate per-scan sequence counter isn't needed.

    `check_name` stores the raw run_scan() jobs-dict key (e.g. "tls"), not
    a pre-rendered label - label resolution happens at read time via
    checks.CHECK_LABELS, so relabeling a check later is a code change, not
    a data backfill. `phase` is only ever STARTED for checks that actually
    run inside the ThreadPoolExecutor; synchronous checks (headers/cookies/
    open_ports) only ever get a single COMPLETED row - see run_scan()'s
    progress_cb call sites in scan_engine.py for the exact semantics,
    including why a tier-locked open_ports never gets a row here at all.

    `finding_count`/`top_severity` are only ever set on a COMPLETED/FAILED
    row (never STARTED, since a check's findings aren't known until it
    finishes) - they're what let the live feed on scan_progress.html show
    findings surfacing in real time ("2 findings, high") instead of only
    at the final report. `top_severity` is the most severe value present
    among that check's findings, per checks.SEVERITY_ORDER's ranking."""
    __tablename__ = "scan_events"
    __table_args__ = (
        db.Index("ix_scan_events_scan_id_id", "scan_id", "id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    check_name = db.Column(db.String(64), nullable=False)
    phase = db.Column(db.Enum(ScanEventPhase), nullable=False)
    detail = db.Column(db.String(255), nullable=True)
    finding_count = db.Column(db.Integer, nullable=True)
    top_severity = db.Column(db.String(16), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    scan = db.relationship("Scan")


class Report(db.Model):
    """`json_path` is legacy - local-disk reports/ writes only ever worked
    correctly on a single-machine deployment (multiple Fly.io/gunicorn
    workers each have their own disk, so a report written by one machine
    404s when a later request lands on another). `data` is the same JSON
    blob stored directly in Postgres instead - every read path
    (scan_report()/scan_report_csv()/dashboard's latest_report) now reads
    `data` first and only falls back to the on-disk file for old rows that
    predate this column. New scans still also write the local file (kept
    as a convenience for local dev / a human inspecting reports/ directly),
    but nothing in the app depends on it being readable anymore."""
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), unique=True, nullable=False)
    json_path = db.Column(db.String(1024), nullable=False)
    data = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    scan = db.relationship("Scan", back_populates="report")


class Subscription(db.Model):
    __tablename__ = "subscriptions"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), unique=True, nullable=False)
    plan = db.Column(db.Enum(Plan), nullable=False, default=Plan.FREE)
    status = db.Column(db.Enum(SubStatus), nullable=False, default=SubStatus.NONE)
    current_period_end = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

    organization = db.relationship("Organization", back_populates="subscription")


class CryptoInvoice(db.Model):
    __tablename__ = "crypto_invoices"
    __table_args__ = (
        # Defense in depth alongside create_invoice()'s offset-collision
        # retry: even if two invoices somehow ended up with the same
        # expected_amount, this stops the same on-chain transaction from
        # being credited to a second invoice after it already paid a
        # first. NULLs (unmatched/pending invoices) aren't constrained by
        # a unique index, so this only ever fires on an actual double-match.
        db.UniqueConstraint("matched_tx_hash", name="uq_crypto_invoices_matched_tx_hash"),
    )

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), nullable=False)
    target_plan = db.Column(db.Enum(Plan), nullable=False)
    # "monthly" | "annual" - which of billing.PLAN_PRICING's two prices this
    # invoice was priced at; drives _activate_subscription()'s
    # current_period_end length (30 vs 365 days). Server-default rather than
    # nullable=False so the existing table (pre-dating this column) doesn't
    # need a backfill migration - every pre-existing row is implicitly the
    # only cycle that existed before, monthly.
    billing_cycle = db.Column(db.String(16), nullable=False, server_default="monthly")
    token_symbol = db.Column(db.String(8), nullable=False)  # "USDT" | "USDC"
    chain = db.Column(db.String(32), nullable=False)
    receiving_address = db.Column(db.String(255), nullable=False)
    base_usd_amount = db.Column(db.Numeric(18, 6), nullable=False)
    unique_offset = db.Column(db.Numeric(18, 6), nullable=False)
    expected_amount = db.Column(db.Numeric(18, 6), nullable=False)
    status = db.Column(db.Enum(InvoiceStatus), nullable=False, default=InvoiceStatus.PENDING)
    matched_tx_hash = db.Column(db.String(128), nullable=True)
    matched_at = db.Column(db.DateTime(timezone=True), nullable=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    # Pre-existing gap: Organization.crypto_invoices declared
    # back_populates="organization" but this side never defined it - dormant
    # since SQLAlchemy only resolves back_populates when mapper
    # configuration is actually triggered, which nothing here happened to
    # do until Invitation/OrgAuditEvent below started referencing
    # Organization too. Filling it in (rather than leaving it latent)
    # is what actually surfaces the pairing correctly.
    organization = db.relationship("Organization", back_populates="crypto_invoices")


class Invitation(db.Model):
    """A sent-but-not-yet-consumed org invite, persisted so org_admin.html's
    "Pending Invitations" table can list/resend/revoke them across requests
    - the invite *link* itself is still a stateless signed token
    (org_routes.generate_invite_token), this row is purely bookkeeping for
    the admin UI. Note: this branch's /signup does not consume invite
    tokens (see org_routes.py's module docstring), so there is no way to
    detect "accepted" here yet - status is only ever PENDING or REVOKED."""
    __tablename__ = "invitations"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), nullable=False)
    status = db.Column(db.Enum(InvitationStatus), nullable=False, default=InvitationStatus.PENDING)
    invited_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    organization = db.relationship("Organization")
    invited_by = db.relationship("User")


class OrgAuditEvent(db.Model):
    """Append-only log of organization-management actions (as opposed to
    Scan rows, which already serve as the scan-history audit trail on
    org_admin.html). event_type is a short machine key
    (ORG_AUDIT_EVENT_LABELS in org_routes.py maps it to display text);
    detail is a short human-readable summary of what happened (domain name,
    reason, decision, etc.) rather than structured columns - this log's
    only job is "who did what, when," not driving app behavior. Deliberately
    outlives the row it describes (e.g. a domain deletion event has no FK to
    DomainVerification) so approving a deletion doesn't cascade-delete its
    own audit trail."""
    __tablename__ = "org_audit_events"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), nullable=False)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    event_type = db.Column(db.String(64), nullable=False)
    detail = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    organization = db.relationship("Organization")
    actor = db.relationship("User")


class AssessmentType(enum.Enum):
    EXTERNAL = "External Security Assessment"
    WEB_APP = "Web Application Assessment"
    API = "API Security Assessment"
    AUTHENTICATED = "Authenticated Assessment"
    FULL = "Full Security Assessment"
    CONTINUOUS = "Continuous Monitoring"


class AssessmentRequestStatus(enum.Enum):
    NEW = "new"
    CONTACTED = "contacted"
    CLOSED = "closed"


class AssessmentRequest(db.Model):
    """A "Request Expert Assessment" lead (Phase 15, CTA-01..04) - a human-
    fulfilled service inquiry, not something a check or scan can satisfy
    automatically. Submitted from a CTA on the dashboard/scan report, tied
    to the submitting user/org when the submitter is logged in (every
    current call site requires login), and surfaced to platform admins on
    `/platform-admin` for manual follow-up - mirrors the pending-domain-
    deletion queue's read/act pattern on that same page, but this queue is
    informational only (no approve/reject action; `status` is set by an
    operator via a separate maintenance path, not a route in this phase)."""
    __tablename__ = "assessment_requests"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), nullable=True)
    requested_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    company_name = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    contact_name = db.Column(db.String(255), nullable=False)
    contact_email = db.Column(db.String(255), nullable=False)
    contact_phone = db.Column(db.String(64), nullable=True)
    assessment_type = db.Column(db.Enum(AssessmentType), nullable=False)
    scope = db.Column(db.Text, nullable=True)
    auth_requirements = db.Column(db.Text, nullable=True)
    domain_count = db.Column(db.Integer, nullable=True)
    timeline = db.Column(db.String(255), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    status = db.Column(db.Enum(AssessmentRequestStatus), nullable=False, default=AssessmentRequestStatus.NEW)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    organization = db.relationship("Organization")
    requested_by = db.relationship("User")


class PlatformAuditEvent(db.Model):
    """Append-only who/what/when trail for platform-admin actions on a
    user or org (Phase 16, ADMIN-04) - a separate table from
    `OrgAuditEvent` rather than reusing it, because `OrgAuditEvent.org_id`
    is non-nullable (every existing event is inherently org-scoped) while
    a platform admin can act on a solo user who has no org at all
    (`User.org_id` is nullable - solo signup is a supported path per
    auth_routes.SignupForm's optional org_name). `target_type`/
    `target_id` instead of a nullable FK to each possible target table,
    matching `OrgAuditEvent.detail`'s "log the fact, not a live
    relationship" convention - deliberately outlives the row it
    describes."""
    __tablename__ = "platform_audit_events"

    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    target_type = db.Column(db.String(32), nullable=False)  # "user" | "organization"
    target_id = db.Column(db.Integer, nullable=False)
    event_type = db.Column(db.String(64), nullable=False)
    detail = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    actor = db.relationship("User")


class OutboundWebhook(db.Model):
    """Phase 19: a registered outbound-webhook endpoint that receives a JSON
    POST every time a scan in its scope completes - the delivery half of the
    platform's continuous-validation loop (the scheduler fires scans on a
    cadence; this is what announces the result to the places a team already
    watches, e.g. a Slack incoming webhook).

    Scope model deliberately mirrors `_scoped_asset_query()`'s dual rule
    (asset_routes.py): an org webhook (`org_id` set, managed by that org's
    ORG_ADMIN) receives every completed scan run by that org; a solo user's
    personal webhook (`org_id` None) only ever receives scans they ran
    themselves. Two different solo users both have `org_id = None`, so the
    solo branch must match on `created_by_user_id` explicitly, never on
    NULL-org equality.

    `url` is the receiver's HTTPS endpoint and is sensitive: Slack incoming-
    webhook URLs embed a token in their path. It is stored (needed to POST)
    but NEVER rendered back in full anywhere - templates show
    webhooks.redact_webhook_url()'s scheme://host/*** form only.

    `secret` is a per-webhook random value shown once at creation time;
    every delivery carries `X-Glassbox-Signature: sha256=HMAC(secret, body)`
    so a receiver can verify the request really came from Glassbox."""
    __tablename__ = "outbound_webhooks"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), nullable=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    label = db.Column(db.String(120), nullable=False)
    url = db.Column(db.String(2048), nullable=False)
    secret = db.Column(db.String(64), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    # Phase 25 (INTG-02): payload wrapping format for the POST body.
    # "default" = raw Glassbox JSON; "splunk_hec" = wraps in
    # {"event": <default_payload>, "sourcetype": "glassbox:scan"}.
    payload_format = db.Column(db.String(32), nullable=False, server_default="default")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    organization = db.relationship("Organization")
    creator = db.relationship("User")


class WebhookDelivery(db.Model):
    """One row per POST attempt an OutboundWebhook received, for the recent-
    deliveries table on /webhooks - without it a silently-failing endpoint
    (expired Slack URL, down receiver) would be indistinguishable from a
    healthy one. Append-only history like OrgAuditEvent: deliveries are
    facts about the past, not live relationships, so scan_id/webhook_id
    rows outliving either side is acceptable by design."""
    __tablename__ = "webhook_deliveries"
    __table_args__ = (
        db.Index("ix_webhook_deliveries_webhook_id_id", "webhook_id", "id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    webhook_id = db.Column(db.Integer, db.ForeignKey("outbound_webhooks.id"), nullable=False)
    # Nullable: a POST fired by the owner's "send test" button isn't about
    # any particular scan - only real scan-completed deliveries set this.
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=True)
    status = db.Column(db.String(16), nullable=False)  # "delivered" | "failed"
    response_code = db.Column(db.Integer, nullable=True)
    error_message = db.Column(db.Text(), nullable=True)
    # Phase 25 (INTG-03): which attempt of the bounded retry this row represents.
    # 1 on first attempt, up to MAX_DELIVERY_ATTEMPTS (3). Each attempt gets
    # its own WebhookDelivery row so the retry trail is visible in the UI.
    attempt_number = db.Column(db.Integer, nullable=False, server_default="1")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    webhook = db.relationship("OutboundWebhook")
    scan = db.relationship("Scan")
