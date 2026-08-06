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

    organization = db.relationship("Organization", back_populates="domain_verifications")


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
    scan_type = db.Column(db.String(16), nullable=False)  # "base" | "advanced" | "media"
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

    organization = db.relationship("Organization", back_populates="crypto_invoices")
