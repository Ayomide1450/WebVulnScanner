"""
In-process daemon-thread scheduler for recurring Asset scans (Phase 1,
ASSET-03/04/08). Ticks on a fixed interval, claims due Assets via a
DB-level conditional UPDATE (D-02), and dispatches through the existing
scan_routes._spawn_scan_thread path unchanged (D-01). See
.planning/phases/01-asset-inventory-continuous-scanning/01-RESEARCH.md
for the design rationale and .planning/phases/01-asset-inventory-continuous-scanning/01-01-PLAN.md
for the exact behavior this module implements.

Bare-named module (no "_routes" suffix) per the project's
"supporting business-logic modules" convention - this holds no Flask routes.
"""
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, update

from webvulnscanner.checks import is_ssrf_safe_hostname
from webvulnscanner.entitlements import FEATURE_REQUIREMENTS, effective_tier_for_org, domain_is_org_verified
from webvulnscanner.extensions import db
from webvulnscanner.models import Asset, Scan, ScanStatus
from webvulnscanner.scan_routes import _spawn_scan_thread

# Fixed-interval cadence presets (D-03) - deliberately not a cron-expression
# parser; ASSET-03 only asks for daily/weekly/monthly presets.
CADENCE_INTERVALS = {
    "daily": timedelta(days=1),
    "weekly": timedelta(weeks=1),
    "monthly": timedelta(days=30),
}

# Comfortably longer than one tick interval (SCHEDULER_POLL_INTERVAL_SECONDS,
# default 60s) so a slow claim-to-dispatch step can't let the lease expire
# before dispatch completes.
LEASE_DURATION = timedelta(minutes=5)


def _try_claim(asset_id, now, next_run_at):
    """Conditional UPDATE claim guard (D-02, Pattern 3). Returns True iff
    this process won the claim for `asset_id` (rowcount == 1). Advances
    next_run_at in the same statement as taking the lease - next_run_at
    (not locked_until) is what determines "is this Asset still due", and
    rescheduling must not wait for the (async) scan to finish."""
    result = db.session.execute(
        update(Asset)
        .where(
            Asset.id == asset_id,
            Asset.is_paused.is_(False),
            Asset.deleted_at.is_(None),
            Asset.next_run_at <= now,
        )
        .where(or_(Asset.locked_until.is_(None), Asset.locked_until < now))
        .values(locked_until=now + LEASE_DURATION, next_run_at=next_run_at)
        # synchronize_session=False: this is a Core-style conditional UPDATE
        # whose rowcount is the only thing the caller needs - skip
        # SQLAlchemy's default in-Python "evaluate" sync strategy, which
        # would otherwise compare already-loaded Asset objects' (possibly
        # tz-naive, on SQLite) datetime attributes against `now`
        # (tz-aware) and raise. The caller re-fetches by primary key
        # afterward (see _tick), so no ORM-side attribute sync is needed
        # here.
        .execution_options(synchronize_session=False)
    )
    db.session.commit()
    return result.rowcount == 1


def _fire(asset):
    """Fires a claimed, due Asset. Re-derives every trust decision at fire
    time - never cached from registration/claim time (ASSET-07, RESEARCH
    Pitfall 1/5). Neither failure path below touches is_paused/next_run_at
    beyond what _try_claim already advanced (D-04: a failed scheduled scan
    keeps ticking at its normal cadence, it never pauses or otherwise
    changes the Asset's schedule state).

    Returns the created Scan row on every branch (success, SSRF-failure,
    tier-failure) - Phase 2 API-03's trigger_scan route (api_routes.py)
    relies on this return value to report scan_id/status back to the
    caller; _tick() (the only pre-existing caller) already ignores the
    return value, so this is a backward-compatible addition."""
    tier = effective_tier_for_org(asset.organization)
    org_verified = domain_is_org_verified(asset.organization, asset.target_url)

    if not is_ssrf_safe_hostname(asset.hostname):
        s = Scan(
            asset_id=asset.id, user_id=asset.created_by_user_id, org_id=asset.org_id,
            target_url=asset.target_url, scan_type=asset.schedule_scan_type,
            status=ScanStatus.FAILED,
            error_message="This target resolves to a private, internal, or unreachable "
                          "address and cannot be scanned.",
        )
        db.session.add(s)
        db.session.commit()
        return s

    if (asset.schedule_scan_type in ("media", "api")
            and FEATURE_REQUIREMENTS[asset.schedule_scan_type] > tier):
        s = Scan(
            asset_id=asset.id, user_id=asset.created_by_user_id, org_id=asset.org_id,
            target_url=asset.target_url, scan_type=asset.schedule_scan_type,
            status=ScanStatus.FAILED,
            error_message="This schedule requires a higher plan than your org's current "
                          "plan. Upgrade in Billing to resume this scan type.",
        )
        db.session.add(s)
        db.session.commit()
        return s

    s = Scan(
        asset_id=asset.id, user_id=asset.created_by_user_id, org_id=asset.org_id,
        target_url=asset.target_url, scan_type=asset.schedule_scan_type,
        status=ScanStatus.QUEUED,
    )
    db.session.add(s)
    db.session.commit()

    if asset.schedule_scan_type == "base":
        _spawn_scan_thread(
            s.id, "base",
            base_url=asset.target_url, manual_test_url=None, tier=tier, org_verified=org_verified,
        )
    elif asset.schedule_scan_type == "media":
        # download defaults False for unattended scheduled fires - the more
        # conservative default for a run nobody is watching.
        _spawn_scan_thread(
            s.id, "media",
            base_url=asset.target_url, download=False, max_files=20, tier=tier,
        )
    elif asset.schedule_scan_type == "api":
        _spawn_scan_thread(s.id, "api", base_url=asset.target_url, tier=tier)

    return s


def _tick(app):
    """One scheduler tick: finds candidate due Assets, attempts to claim
    each, and fires the ones this process wins the claim for."""
    now = datetime.now(timezone.utc)
    due_assets = Asset.query.filter(
        Asset.is_paused.is_(False),
        Asset.deleted_at.is_(None),
        Asset.next_run_at <= now,
    ).all()
    for asset in due_assets:
        next_run_at_candidate = now + CADENCE_INTERVALS[asset.cadence]
        if not _try_claim(asset.id, now, next_run_at_candidate):
            continue  # lost the race, or another tick already handled it
        # Re-fetch the row post-claim so _fire sees the just-committed state.
        claimed = Asset.query.get(asset.id)
        if claimed is None:
            continue
        _fire(claimed)


def _scheduler_loop(app):
    """Runs forever in a daemon thread. A fresh app context is pushed PER
    TICK (Pattern 2) - never one context held across the thread's whole
    lifetime, so Flask-SQLAlchemy's scoped session gets fresh/cleaned-up
    state each iteration instead of a stale identity map across hundreds of
    ticks. One bad tick is logged and never kills the loop."""
    poll_interval = app.config.get("SCHEDULER_POLL_INTERVAL_SECONDS", 60)
    while True:
        try:
            with app.app_context():
                _tick(app)
        except Exception:
            logging.exception("scheduler tick failed")
        time.sleep(poll_interval)


def start_scheduler(app):
    """Spawns the scheduler loop as a daemon thread. Callers must apply the
    three-part guard (SCHEDULER_ENABLED / TESTING / Werkzeug-reloader) before
    calling this - see webvulnscanner.__init__._maybe_start_scheduler."""
    thread = threading.Thread(target=_scheduler_loop, args=(app,), daemon=True)
    thread.start()
