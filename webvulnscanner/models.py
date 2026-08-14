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
    email_verified_at = db.Column(db.DateTime(timezone=True), nullable=True)
    verify_token = db.Column(db.String(64), unique=True, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    organization = db.relationship("Organization", back_populates="users")
    scans = db.relationship("Scan", back_populates="user")

    def get_id(self):
        return str(self.id)

    @property
    def is_active(self):
        # Unverified email does not block login (decision documented in
        # auth_routes.py / the plan's Workstream 1 section) - every created
        # user is "active" for Flask-Login purposes regardless of
        # email_verified_at.
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


class Scan(db.Model):
    __tablename__ = "scans"
    __table_args__ = (
        db.Index("ix_scans_user_created", "user_id", "created_at"),
        db.Index("ix_scans_org_created", "org_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), nullable=True)
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
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), unique=True, nullable=False)
    json_path = db.Column(db.String(1024), nullable=False)
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
