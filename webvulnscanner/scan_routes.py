"""
Blueprint `scan`: /dashboard, /scan/new(/base|/advanced|/media|/api),
/scan/<id>, /scan/<id>/events, /scan/<id>/report, /scan/<id>/compare/<other_id>.

This is the cutover point where the old synchronous `/scan`, `/scan-advanced`,
`/scan-media` routes (formerly in the standalone `app.py`) become a single
async, tier-aware flow: submitting any of the four dedicated "new scan"
forms creates a `Scan(status=QUEUED)` row, spawns a daemon `threading.Thread`
running the appropriate orchestrator, and redirects to `/scan/<id>`, which
live-updates via SSE (`/scan/<id>/events`) until the scan finishes and
redirects to `/scan/<id>/report`.

**Per-type route decision**: `/scan/new` is a GET-only landing page (4 cards,
one per scan type) rather than a single POST-handling multiplexer keyed on a
hidden `scan_type` field. Each scan type gets its own GET+POST route
(`new_scan_base`/`new_scan_advanced`/`new_scan_media`/`new_scan_api`) and
template instead. Reasoning: a shared endpoint's validation-error repaint
can't keep the browser URL in sync with which of several stacked forms
actually failed; per-type routes make the URL always match the page content.
The `scan.new_scan` endpoint name/URL is deliberately kept stable so
existing links (`base.html`'s nav, `dashboard.html`'s CTA/empty-state links)
don't need to change - they just land on the chooser instead of a combined
form page.

**Ownership decision**: a scan is viewable by the user who ran it
(`scan.user_id == current_user.id`), OR by an ORG_ADMIN of the same org
(`scan.org_id == current_user.org_id and current_user.role == Role.ORG_ADMIN`).
Anything else is a 404 (not 403) - same convention already used in
`org_routes.py` for cross-org access, so a scan ID doesn't leak its
existence to someone who isn't entitled to see it either way.

**Dashboard scoping decision**: `/dashboard` shows only `current_user.id`'s
own scans, not the whole org's. Org-wide scan visibility already exists at
`/org/admin` (ORG_ADMIN only) - scoping the personal dashboard to the
individual avoids a non-admin org member seeing teammates' scan targets by
default.

**Diff placement decision**: `diff_reports()` lives in this module (not a
separate file) since it's only used by `scan_compare()` here and is small
enough not to warrant its own module.
"""
import csv
import io
import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from math import ceil
from urllib.parse import urlparse

from flask import Blueprint, Response, abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from webvulnscanner.ai_summary import generate_remediation_summary
from webvulnscanner.checks import (
    CHECK_CATEGORY,
    CHECK_COMPLIANCE,
    CHECK_LABELS,
    SECURITY_DOMAIN_MAP,
    detect_login_form,
    is_ssrf_safe_hostname,
    normalize_target,
)
from webvulnscanner.entitlements import FEATURE_REQUIREMENTS, Tier, domain_is_org_verified, effective_tier
from webvulnscanner.extensions import db
from webvulnscanner.models import Report, Role, Scan, ScanEvent, ScanEventPhase, ScanStatus
from webvulnscanner.scan_engine import (
    read_report_file,
    run_advanced_scan,
    run_api_scan,
    run_media_scan,
    run_scan,
    save_report,
)
from webvulnscanner.webhooks import fire_scan_webhooks, fire_regression_webhooks
from webvulnscanner.regressions import classify_regressions
from webvulnscanner.pdf_report import build_pdf_report, PDF_MIMETYPE
from webvulnscanner.sarif import build_sarif_report, sarif_text
from webvulnscanner.ndjson_report import findings_ndjson

scan = Blueprint("scan", __name__)

# Allowlist for the report page's `?group=` query parameter (COMP-02, and
# v1.3 SCORE-02's "domain" mode). Any value not in this tuple is coerced to
# "severity" in scan_report() before it ever reaches render_template() or
# the page - keeps an arbitrary/garbage query-string value from being
# echoed anywhere (T-03-21).
GROUPING_MODES = ("severity", "compliance", "domain")

# PERF-02: the severity-grouped (default) findings view is paginated at
# 20/page, same as the other three D-03 lists - a plain Python slice, not a
# .paginate() query, since `report` is already a fully-loaded in-memory dict
# (read from the on-disk/DB JSON blob), not a Query. The compliance-grouped
# view (?group=compliance) is DELIBERATELY left unpaginated - its different
# grouping semantics (by OWASP category, not a flat sorted list) are out of
# this plan's scope (09-03-PLAN.md's explicit prohibition), deferred to a
# future phase.
FINDINGS_PER_PAGE = 20


from webvulnscanner.utils import safe_filename  # noqa: E402 — after blueprint consts


# --------------------------------------------------------------------------
# Ownership
# --------------------------------------------------------------------------

def _owns_scan(user, s):
    """True if `user` owns `s` or is the ORG_ADMIN of the org that ran it -
    the actual predicate `_check_ownership` (session-auth callers) and
    api_routes.py (API-key callers) both gate on, so the two auth paths
    can never diverge in what counts as "yours to see"."""
    if s.user_id == user.id:
        return True
    if s.org_id is not None and user.org_id == s.org_id and user.role == Role.ORG_ADMIN:
        return True
    return False


def _check_ownership(s):
    """Aborts with 404 unless `current_user` owns `s` or is the ORG_ADMIN of
    the org that ran it. 404 (not 403) so a scan ID doesn't confirm its own
    existence to someone who isn't entitled to see it either way - matches
    the convention already used for cross-org access in org_routes.py."""
    if not _owns_scan(current_user, s):
        abort(404)


def _find_running_scan(user_id, target_url, scan_type):
    """Returns the most recent `QUEUED` or `RUNNING` `Scan` row matching
    `(user_id, target_url, scan_type)` exactly, or `None` if no such scan
    exists (STATE-03/D-06's duplicate-concurrent-scan guard).

    Deliberately scoped to include `scan_type`, not just `(user_id,
    target_url)`: a base scan and an api scan against the same target are
    two different checks running in parallel, not two copies of the same
    scan - the guard's purpose is refusing a redundant re-submission of a
    scan that is already in flight, not serializing all of a user's
    activity against one target. This is a narrower reading of D-06's
    literal wording ("a RUNNING scan already exists for the same
    target+user"), documented deliberately in 09-04-SUMMARY.md.

    Every new-scan call site (see `_launch_base_scan`, `new_scan_advanced`,
    `new_scan_media`, `new_scan_api`) calls this with the exact same
    `target_url` expression it's about to store on the `Scan` row it would
    otherwise create, so the guard's query and the stored data can never
    drift apart."""
    return (
        Scan.query.filter(
            Scan.user_id == user_id,
            Scan.target_url == target_url,
            Scan.scan_type == scan_type,
            Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]),
        )
        .order_by(Scan.created_at.desc())
        .first()
    )


# Exact Copywriting Contract text (09-UI-SPEC.md) for a duplicate-concurrent-
# scan redirect - shared by every new_scan_* route so the flashed message can
# never drift between call sites.
DUPLICATE_SCAN_MESSAGE = "A scan is already running for this target — showing its live progress."


# --------------------------------------------------------------------------
# Background-thread scan execution
# --------------------------------------------------------------------------

def _run_scan_in_background(app, scan_id, scan_type, **kwargs):
    """Runs the appropriate orchestrator inside a pushed app context, from a
    daemon thread (see scan_routes.new_scan). Writes Scan.status/progress/
    risk_score and a Report row as the scan proceeds and completes.

    Requires SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"check_same_thread":
    False}} (set in config.py) since this thread's writes go through the
    same SQLite connection pool as the request thread that spawned it.
    """
    with app.app_context():
        s = Scan.query.get(scan_id)
        s.status = ScanStatus.RUNNING
        s.started_at = datetime.now(timezone.utc)
        db.session.commit()
        try:
            if scan_type == "base":
                def progress_cb(name, phase, done, total, detail=None,
                                 finding_count=None, top_severity=None):
                    # progress_current/progress_total update unconditionally,
                    # same as before this closure carried a check name/phase
                    # at all - a tier-locked open_ports still bumps the
                    # counters (run_scan() calls this every time regardless
                    # of gating) but passes phase=None for it, since no
                    # check actually ran; only a real started/completed/
                    # failed phase gets a ScanEvent row, so the live feed on
                    # scan_progress.html never shows a fabricated "open
                    # ports: done" line for a check the caller's plan didn't
                    # unlock. finding_count/top_severity are only ever set
                    # on a completed/failed call (run_scan() never passes
                    # them for "started") - they're what let the feed show
                    # findings surfacing live as each check resolves.
                    row = Scan.query.get(scan_id)
                    row.progress_current = done
                    row.progress_total = total
                    if phase is not None:
                        db.session.add(ScanEvent(
                            scan_id=scan_id, check_name=name,
                            phase=ScanEventPhase(phase), detail=detail,
                            finding_count=finding_count, top_severity=top_severity,
                        ))
                    db.session.commit()

                report = run_scan(
                    kwargs["base_url"], kwargs["manual_test_url"],
                    kwargs["tier"], kwargs["org_verified"], progress_cb=progress_cb,
                )
                prefix, hostname = "", urlparse(kwargs["base_url"]).netloc
            elif scan_type == "advanced":
                # run_advanced_scan has no progress_cb param - its own locked-
                # check-group gating is the only per-check granularity it
                # exposes, so progress_current/progress_total stay 0/0 for
                # the whole run (scan_progress.html degrades to a status-only
                # display for this scan type, not a real percentage).
                report = run_advanced_scan(kwargs["advanced"], kwargs["tier"], kwargs["org_verified"])
                prefix, hostname = "advanced_", report["hostname"]
            elif scan_type == "media":
                # Same no-progress_cb note as above; also, tier gating for
                # media is enforced route-level in new_scan() before this
                # thread is ever spawned - run_media_scan's signature is
                # unchanged and does not re-check tier itself.
                report = run_media_scan(kwargs["base_url"], kwargs["download"], kwargs["max_files"])
                prefix, hostname = "media_", report["hostname"]
            elif scan_type == "api":
                # Same no-progress_cb note as above; tier gating for api is
                # enforced route-level in new_scan_api() before this thread
                # is ever spawned, mirroring media's pattern - run_api_scan's
                # signature does not re-check tier itself.
                report = run_api_scan(kwargs["base_url"])
                prefix, hostname = "api_", report["hostname"]
            else:
                raise ValueError(f"unknown scan_type {scan_type!r}")

            # AI-assisted remediation summary - Paid tier and above, all 4
            # scan types alike, one shared tail rather than 4 duplicated
            # call sites. `tier` is passed by every new_scan_* route
            # (see _spawn_scan_thread call sites) purely so this gate can
            # be evaluated here; generate_remediation_summary() never
            # raises (see its docstring), so a Groq outage degrades to no
            # summary, not a failed scan.
            if kwargs.get("tier") is not None and kwargs["tier"] >= Tier.PAID:
                report["ai_summary"] = generate_remediation_summary(
                    report, current_app.config["GROQ_API_KEY"], current_app.config["GROQ_MODEL"],
                )

            # Phase 27 (CONT-01): asset-linked scans (scheduler fires and
            # API-triggered asset scans - everything that arrives here with
            # asset_id set) diff their findings against that Asset's
            # previous completed scan of the same type, and the tags land IN
            # the stored report blob: each finding gains regression:
            # "new"|"recurring", and report["regression"] carries counts +
            # resolved-finding snapshots. Manual wizard scans have
            # asset_id=None and skip this entirely - their cross-scan story
            # stays the existing /compare view. Never raises past this
            # block: a diff failure degrades to an untagged report, never a
            # failed scan (same convention as every tail below).
            try:
                _attach_regression_tags(scan_id, report)
            except Exception:  # noqa: BLE001 - observability, not correctness
                logging.exception("regression tagging failed for scan %s", scan_id)

            fname = save_report(report, prefix, hostname)
            db.session.add(Report(scan_id=scan_id, json_path=fname, data=report))
            s = Scan.query.get(scan_id)
            # Race guard (T-09-12): if _timeout_watchdog() already marked
            # this scan FAILED-by-timeout while this orchestrator was still
            # finishing up, this late finish must not resurrect the row as
            # COMPLETED or erase the timeout's specific error_message - the
            # watchdog's write wins whichever side finishes second.
            if s.status == ScanStatus.FAILED:
                return
            s.status = ScanStatus.COMPLETED
            s.risk_score = report["score"]
            s.completed_at = datetime.now(timezone.utc)
            db.session.commit()
            # Phase 19: push a scan-completed notice to every matching
            # outbound webhook (org Slack channels / CI receivers). Called
            # AFTER the terminal commit so deliveries observe committed
            # state; fire_scan_webhooks() itself never raises (see its
            # docstring), and this whole block is belt-and-suspenders
            # guarded anyway - notifications must never un-complete a scan.
            try:
                fire_scan_webhooks(scan_id)
            except Exception:  # noqa: BLE001 - same degrade-gracefully contract
                pass
            # Phase 27 (CONT-03): a distinct `finding.regressed` event to the
            # SAME active org webhooks, reusing Phase 19's signed-delivery
            # machinery end to end - no second notification path. Self-guards:
            # reads the just-committed report and returns silently unless a
            # NEW High/Critical finding exists since the asset's previous scan.
            try:
                fire_regression_webhooks(scan_id)
            except Exception:  # noqa: BLE001 - notifications must never un-complete a scan
                pass
        except Exception as e:  # noqa: BLE001 - a failed scan must not leave the row stuck RUNNING
            s = Scan.query.get(scan_id)
            # Same race guard as the success path above: don't overwrite a
            # timeout's specific error_message with this generic exception
            # text if the watchdog already beat this except block to it.
            if s.status == ScanStatus.FAILED:
                return
            s.status = ScanStatus.FAILED
            s.error_message = str(e)
            db.session.commit()


def _timeout_watchdog(app_obj, scan_id):
    """Fires once, on its own `threading.Timer` thread, `SCAN_TIMEOUT_SECONDS`
    after `_spawn_scan_thread` starts a scan (STATE-03/D-06). Runs with no
    request context and no `current_user` - it operates purely on the
    `scan_id`/`app_obj` captured at spawn time, the same trust level
    `_run_scan_in_background`'s own thread already has.

    Re-reads the row's current status first: if the scan already reached a
    terminal state (COMPLETED or FAILED) on its own before this fired, it's
    a no-op - the scan simply finished within its deadline, nothing to do.
    Only a still-QUEUED-or-RUNNING row gets force-marked FAILED with the
    specific timeout message.

    This races with `_run_scan_in_background`'s own two terminal writes
    (success -> COMPLETED, exception -> FAILED); both sides guard on
    re-reading status immediately before writing (see their "race guard"
    comments) so whichever of {orchestrator finishes, watchdog fires}
    happens second cannot clobber whichever happened first (T-09-12)."""
    with app_obj.app_context():
        s = Scan.query.get(scan_id)
        if s is None:
            return
        if s.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
            s.status = ScanStatus.FAILED
            s.error_message = "This scan exceeded its time limit and was stopped."
            s.completed_at = datetime.now(timezone.utc)
            db.session.commit()


def _spawn_scan_thread(scan_id, scan_type, **kwargs):
    app_obj = current_app._get_current_object()
    thread = threading.Thread(
        target=_run_scan_in_background,
        args=(app_obj, scan_id, scan_type),
        kwargs=kwargs,
        daemon=True,
    )
    thread.start()

    # Second, independent background timer (STATE-03/D-06) - guarantees this
    # scan reaches a terminal state within SCAN_TIMEOUT_SECONDS even if the
    # scan thread above hangs indefinitely (a stalled network call with no
    # outer bound). Not stored/cancelled: letting it fire and no-op on an
    # already-terminal scan is the intended behavior, not a missed
    # cancellation - see _timeout_watchdog's docstring.
    watchdog_timer = threading.Timer(
        app_obj.config["SCAN_TIMEOUT_SECONDS"], _timeout_watchdog, args=(app_obj, scan_id),
    )
    watchdog_timer.daemon = True
    watchdog_timer.start()


# --------------------------------------------------------------------------
# Advanced-scan form parsing (same field set/convention as the old
# app.py:scan_advanced route)
# --------------------------------------------------------------------------

def _parse_advanced_form(f):
    return {
        "login_url": f.get("login_url", "").strip(),
        "user_field": f.get("login_user_field", "").strip(),
        "pass_field": f.get("login_pass_field", "").strip(),
        "fail_text": f.get("login_fail_text", "").strip(),
        "bruteforce_username": f.get("bruteforce_username", "").strip(),
        "bruteforce_passwords": [p.strip() for p in f.get("bruteforce_passwords", "").split(",") if p.strip()],
        "sqli_union_url": f.get("sqli_union_url", "").strip(),
        "sqli_union_param": f.get("sqli_union_param", "").strip(),
        "stored_xss_submit_url": f.get("stored_xss_submit_url", "").strip(),
        "stored_xss_field": f.get("stored_xss_field", "").strip(),
        "stored_xss_view_url": f.get("stored_xss_view_url", "").strip(),
        "stored_xss_cookie": f.get("stored_xss_cookie", "").strip(),
        "idor_url_template": f.get("idor_url_template", "").strip(),
        "idor_ids": [i.strip() for i in f.get("idor_ids", "").split(",") if i.strip()],
        "idor_cookie_a": f.get("idor_cookie_a", "").strip(),
        "idor_cookie_b": f.get("idor_cookie_b", "").strip(),
    }


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

def _per_target_trends(scans):
    """Groups `scans` (already newest-first, current_user's own) by
    hostname and returns {hostname: [scans oldest-to-newest]} for every
    target with 2+ completed, scored scans - a single scan has no trend to
    show, so those targets are dropped rather than rendered as a flat
    line. Powers the dashboard's per-target trend/portfolio section
    (roadmap item 8); deliberately independent of the existing all-scans
    sparkline above it, which mixes every target into one line."""
    by_host = {}
    for s in scans:
        if s.risk_score is None:
            continue
        host = urlparse(s.target_url).netloc or s.target_url
        by_host.setdefault(host, []).append(s)
    return {
        host: list(reversed(scored))  # scans is newest-first; trend reads oldest-first
        for host, scored in by_host.items()
        if len(scored) >= 2
    }


# User-facing labels for Scan.scan_type - the stored DB value ("base" etc.)
# never changes, this is a display-only mapping for the dashboard redesign.
SCAN_TYPE_LABELS = {
    "base": "Standard Security Scan",
    "advanced": "Advanced Security Scan",
    "media": "Media Security Scan",
    "api": "API Security Scan",
}


SCAN_HISTORY_PER_PAGE = 20


@scan.route("/dashboard")
@login_required
def dashboard():
    page = request.args.get("page", 1, type=int)

    # Full, unbounded history - PERF-02 must not shrink `latest`/
    # `target_trends`/`completed_count` to whichever page of the Scan
    # History table is currently being viewed (see this plan's
    # prohibitions); `scan_history` below is a SEPARATE, paginated query
    # feeding only the table itself.
    all_scans = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    latest = all_scans[0] if all_scans else None
    target_trends = _per_target_trends(all_scans)
    completed_count = sum(1 for s in all_scans if s.status == ScanStatus.COMPLETED)

    # Powers the "Recent Findings" section - only loaded when the latest
    # scan actually has a persisted report, same on-disk JSON every other
    # report view reads (scan_report()/scan_report_csv() above). A missing/
    # corrupt file degrades to None (empty state), never a 500 - same
    # convention as every check_* function in checks.py.
    latest_report = None
    if latest is not None and latest.status == ScanStatus.COMPLETED and latest.report is not None:
        latest_report = _load_report_json(latest)

    # PERF-02: the Scan History table itself is DB-level paginated at
    # 20/page (a real .paginate() query, not a Python slice of `all_scans`)
    # - error_out=False so an out-of-range ?page= value degrades to an
    # empty .items list rather than a 404, same "degrade rather than error
    # on bad input" convention as the rest of this app.
    scan_history = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .paginate(page=page, per_page=SCAN_HISTORY_PER_PAGE, error_out=False)
    )

    return render_template(
        "dashboard.html", scans=all_scans, scan_history=scan_history, latest=latest,
        target_trends=target_trends, completed_count=completed_count, latest_report=latest_report,
        scan_type_labels=SCAN_TYPE_LABELS,
    )


# Caps how many targets a single /scan/new/base submission can launch at
# once (see the bulk-scanning support in new_scan_base below). Kept small
# and hardcoded rather than a plan-based limit - this is about not letting
# one form submission spawn dozens of background scan threads at once, not
# an entitlement to gate by tier.
MAX_BULK_TARGETS = 10


# Verbatim SCANUX-03 availability labels for Step 2's ("Select Type") card
# grid - the only three states a scan-type card can be in.
AVAILABILITY_INCLUDED = "Included"
AVAILABILITY_VERIFIED = "Requires Verified Domain"
AVAILABILITY_PAID = "Requires Paid Plan"

# Step 2's grid is always exactly these four fixed cards (base, advanced,
# media, api) - 05-UI-SPEC.md's one "unresolved" UI consideration
# (zero-one-many for the scan-type grid) is planned as a fixed assumption
# for this phase, so no zero/one/many conditional copy is built here.
SCAN_TYPE_CARDS = (
    {
        "key": "base", "title": "Standard Scan", "endpoint": "scan.new_scan_base",
        "cta": "Run a Standard Scan",
        "blurb": ("A general health check: security headers, HTTPS setup, cookies, email/DNS "
                  "protection, and leaked secrets - the right starting point for any site."),
    },
    {
        "key": "advanced", "title": "Advanced Scan", "endpoint": "scan.new_scan_advanced",
        "cta": "Run an Advanced Scan",
        "blurb": ("Tests things only a logged-in attacker could try: bypassing your login, "
                  "guessing passwords, or one user seeing another user's private data."),
    },
    {
        "key": "media", "title": "Media Scan", "endpoint": "scan.new_scan_media",
        "cta": "Run a Media Scan",
        "blurb": ("Checks your images and videos for hidden location data (GPS in photo EXIF "
                  "data) and files you probably didn't mean to make public."),
    },
    {
        "key": "api", "title": "API Scan", "endpoint": "scan.new_scan_api",
        "cta": "Run an API Scan",
        "blurb": ("For sites with a developer API: finds API documentation, endpoints, and "
                  "data left exposed without a login."),
    },
)


def _tier_flags(tier):
    return {
        "tier": tier,
        "can_run_paid": Tier.PAID <= tier,
        "can_run_org_verified": Tier.ORG_VERIFIED <= tier,
        "can_run_media": FEATURE_REQUIREMENTS["media"] <= tier,
        "can_run_api": FEATURE_REQUIREMENTS["api"] <= tier,
        "max_bulk_targets": MAX_BULK_TARGETS,
    }


def _unsafe_target_error(url, org_id=None):
    """None if url's hostname resolves only to public addresses AND isn't a
    domain another org has already verified ownership of; an error string
    (safe to show the user) otherwise. Every route below calls this on each
    user-supplied absolute URL before a Scan row is created.

    The verified-domain check closes a real gap: base/passive scans never
    required domain verification at all (only the intrusive checks did),
    so any authenticated user could self-attest authorization via the
    checkbox and scan literally any public domain, including one someone
    else had already proven ownership of. Once a domain is verified by an
    org, every other org is blocked from scanning it - `org_id=None`
    (solo users with no org) is never treated as "no restriction", it's
    just never a match for any real verified org_id either. Unclaimed
    domains stay scannable via the existing checkbox self-attestation,
    since restricting recon/OSINT-style assessment of *any* public domain
    outright would defeat this tool's purpose as an autonomous security
    validation platform, not just this one site's protection.

    See is_ssrf_safe_hostname's docstring in checks.py for what the
    SSRF check does and doesn't protect against."""
    hostname = urlparse(url).hostname
    if not hostname or not is_ssrf_safe_hostname(hostname):
        return "This target resolves to a private, internal, or unreachable address and cannot be scanned."

    from webvulnscanner.models import DomainVerification

    claim = (
        DomainVerification.query.filter(
            DomainVerification.domain == hostname.lower(),
            DomainVerification.verified_at.isnot(None),
        ).first()
    )
    if claim is not None and claim.org_id != org_id:
        return (
            f"{hostname} is a verified domain belonging to another organization on this "
            "platform and cannot be scanned by you. If this is your domain, verify ownership "
            "of it yourself under Organization → Verify domain."
        )
    return None


def _verified_domain_choices(user):
    """Domain strings for Step 1's "Select Verified Domain" dropdown
    (SCANUX-02) - org-scoped `DomainVerification` rows with `verified_at`
    set, ordered by domain. Returns `[]` when `user.org_id` is None (a solo
    user with no org has no org-scoped verified domains to offer).

    Deliberately NOT `Asset` rows (D-01): registering an Asset only records
    a target a user *intends* to scan on a schedule - it is not proof of
    domain ownership. Only a `DomainVerification` row with `verified_at`
    set is. A row with a pending deletion request
    (`deletion_requested_at` set) is still included here: it remains a
    verified domain, shown with no special marker, until an admin actually
    approves the deletion (see `DomainVerification.deletion_pending` in
    models.py) - it would be misleading to hide it from the picker before
    that happens.
    """
    if user.org_id is None:
        return []

    from webvulnscanner.models import DomainVerification  # lazy import - see _unsafe_target_error above

    rows = (
        DomainVerification.query
        .filter(DomainVerification.org_id == user.org_id, DomainVerification.verified_at.isnot(None))
        .order_by(DomainVerification.domain)
        .all()
    )
    return [row.domain for row in rows]


def _prefill_target(field):
    """Value to repopulate a wizard form field with: `request.form`'s value
    on a POST (so a validation-error re-render never silently clears what
    the user typed - the exact regression class CLAUDE.md's bug history
    flags for this page family), or the `?target=` query parameter on a
    GET (the parameter `scan_report.html`'s existing re-scan link has
    always emitted but `new_scan_base` previously ignored)."""
    if request.method == "POST":
        return request.form.get(field, "")
    return request.args.get("target", "")


# normalize_target() (webvulnscanner/checks.py, frozen - never edited by
# this phase) only requires a non-empty netloc after prefixing "https://" -
# a string like "not a domain at all" or an HTML-injection payload still
# parses to a (garbage but non-empty) netloc and would otherwise sail past
# that check straight into _unsafe_target_error()'s real DNS lookup,
# surfacing the confusing "resolves to a private, internal, or
# unreachable address" message for input that was never a hostname to
# begin with. This regex is this wizard's own early sanity check on top of
# normalize_target() - it does not replace normalize_target() or
# is_ssrf_safe_hostname(), it only produces a clearer, correct error
# message for obviously-not-a-hostname input. A real hostname (or bare
# IPv4/IPv6/bracketed-IPv6 literal) only ever contains letters, digits,
# dots, hyphens, colons and square brackets.
_HOSTNAME_LOOKS_VALID_RE = re.compile(r"^[A-Za-z0-9.\-\[\]:]+$")


def _looks_like_hostname(hostname):
    return bool(hostname) and bool(_HOSTNAME_LOOKS_VALID_RE.match(hostname))


def _scan_type_availability(tier, org, target_url):
    """Returns `SCAN_TYPE_CARDS` (base/advanced/media/api, in that order)
    each enriched with `label`/`unlocked`/`upgrade_url` for Step 2's grid
    (SCANUX-03/04, D-03's context-aware CTA destination).

    Blocking-gate precedence: an insufficient plan tier is always reported
    before an unverified target domain, because upgrading the plan is the
    only thing that can move the user forward when the tier itself is the
    blocker - reporting "verify your domain" first would be a dead end for
    a user who can't reach Advanced's checks at all yet. Advanced therefore
    checks `Tier.ORG_VERIFIED <= tier` first and only falls through to the
    domain-verification check once that already passes.

    **Display-only - this is NOT a gate.** Every new_scan_* POST handler
    keeps its own FEATURE_REQUIREMENTS/authorized*/`_unsafe_target_error`
    checks, which remain the single source of truth - a hand-crafted POST
    to a card rendered here as locked is still refused server-side.
    """
    cards = []
    for card in SCAN_TYPE_CARDS:
        entry = dict(card)
        if card["key"] == "base":
            entry.update(label=AVAILABILITY_INCLUDED, unlocked=True, upgrade_url=None)
        elif card["key"] == "advanced":
            if not (Tier.ORG_VERIFIED <= tier):
                entry.update(label=AVAILABILITY_PAID, unlocked=False, upgrade_url=url_for("billing.view"))
            elif not target_url or not domain_is_org_verified(org, target_url):
                entry.update(label=AVAILABILITY_VERIFIED, unlocked=False,
                              upgrade_url=url_for("org.verify_domain_view"))
            else:
                entry.update(label=AVAILABILITY_INCLUDED, unlocked=True, upgrade_url=None)
        else:  # media, api
            if FEATURE_REQUIREMENTS[card["key"]] > tier:
                entry.update(label=AVAILABILITY_PAID, unlocked=False, upgrade_url=url_for("billing.view"))
            else:
                entry.update(label=AVAILABILITY_INCLUDED, unlocked=True, upgrade_url=None)
        cards.append(entry)
    return cards


def _availability_for(key, tier, org, target_url):
    """Returns the single `_scan_type_availability()` entry matching `key`
    ("advanced"/"media"/"api") - so a per-type Step 3 page's pill can never
    drift from what Step 2's card grid already showed for this exact
    target. Display-only, same as `_scan_type_availability` itself."""
    return next(c for c in _scan_type_availability(tier, org, target_url) if c["key"] == key)


def _render_step1(error=None):
    """Renders Step 1 (Select Domain) - shared by `new_scan()` (GET) and
    `new_scan_type()` (re-rendering Step 1 with a validation error, per
    the ?target= carrying its state forward)."""
    return render_template(
        "scan_new.html",
        verified_domains=_verified_domain_choices(current_user),
        prefill_target=_prefill_target("target"),
        selected_domain=request.args.get("verified_domain", ""),
        error=error,
    )


@scan.route("/scan/new")
@login_required
def new_scan():
    """Step 1 of the guided New Scan wizard (Select Domain -> Select Type
    -> Confirm Authorization -> Start Scan, SCANUX-01) - no longer the
    "choose a scan type" chooser (that's now Step 2, `new_scan_type`).
    Endpoint name/URL are kept stable so existing links (base.html's nav,
    dashboard.html's CTA and empty-state link) don't need to change."""
    return _render_step1()


@scan.route("/scan/new/type")
@login_required
def new_scan_type():
    """Step 2 of the guided wizard (Select Type). GET-only: Step 1's form
    submits here via `?verified_domain=`/`?target=`.

    Resolution order for the chosen target: `verified_domain` wins when
    non-empty (an explicit pick from a curated list of domains the org has
    already proven it owns), otherwise `target` (the free-text field).

    `_unsafe_target_error()` is run here as an **additional early check for
    the user's benefit only, never a replacement** - every new_scan_* POST
    handler still runs its own copy before a Scan row is ever created.
    """
    verified_domain = request.args.get("verified_domain", "").strip()
    target = request.args.get("target", "").strip()
    chosen = verified_domain or target
    if not chosen:
        return _render_step1(error="Select a verified domain or enter a target to continue.")

    base_url = normalize_target(chosen)
    if not base_url or not _looks_like_hostname(urlparse(base_url).hostname or ""):
        return _render_step1(error="Enter a valid domain or URL, e.g. example.com")

    unsafe = _unsafe_target_error(base_url, org_id=current_user.org_id)
    if unsafe:
        return _render_step1(error=unsafe)

    tier = effective_tier(current_user)
    return render_template(
        "scan_new_type.html", target=base_url,
        scan_types=_scan_type_availability(tier, current_user.organization, base_url),
    )


def _launch_base_scan(user, tier, raw_target, manual_test_url=None):
    """Validates+launches one base scan for `raw_target`, exactly the steps
    `new_scan_base`'s per-target loop already ran inline before this was
    extracted: normalize_target() -> _unsafe_target_error() (the SSRF gate
    every new_scan_* route calls before a Scan row is created) ->
    _find_running_scan() (STATE-03's duplicate-concurrent-scan guard) ->
    domain_is_org_verified() -> create the Scan row -> spawn the background
    thread. Returns `(scan, None, is_duplicate)` on success (a fresh launch
    or a reused already-running scan) or `(None, error_string, False)` on a
    validation/safety failure - never raises past its own SSRF/normalize
    checks.

    This is the single place both the UI's bulk-scan form (scan_routes.py)
    and the API's POST /api/v1/scans (api_routes.py) launch a scan, so an
    API-triggered scan is provably subject to the exact same
    ownership/SSRF gate as one launched from the form - not a
    reimplementation that could quietly drift from it. `user` is a plain
    parameter (not `current_user`) precisely so api_routes.py can pass the
    User the API key resolves to.

    `is_duplicate=True` means an existing QUEUED/RUNNING Scan for this
    exact (user, target, "base") triple was found and returned instead of
    creating a new row - the caller must not treat that as a fresh launch
    (no new thread was spawned)."""
    base_url = normalize_target(raw_target)
    if not base_url:
        return None, "not a valid domain/URL", False
    unsafe = _unsafe_target_error(base_url, org_id=user.org_id)
    if unsafe:
        return None, unsafe, False
    if manual_test_url:
        unsafe = _unsafe_target_error(manual_test_url, org_id=user.org_id)
        if unsafe:
            return None, unsafe, False

    existing = _find_running_scan(user.id, base_url, "base")
    if existing is not None:
        return existing, None, True

    org_verified = domain_is_org_verified(user.organization, base_url)
    s = Scan(user_id=user.id, org_id=user.org_id,
              target_url=base_url, scan_type="base", status=ScanStatus.QUEUED)
    db.session.add(s)
    db.session.commit()

    _spawn_scan_thread(
        s.id, "base",
        base_url=base_url, manual_test_url=manual_test_url,
        tier=tier, org_verified=org_verified,
    )
    return s, None, False


@scan.route("/scan/new/base", methods=["GET", "POST"])
@login_required
def new_scan_base():
    tier = effective_tier(current_user)

    if request.method == "GET":
        return render_template("scan_new_base.html", prefill_target=_prefill_target("target"), **_tier_flags(tier))

    if not request.form.get("authorized"):
        return render_template(
            "scan_new_base.html", error="You must confirm you own or are authorized to test this domain.",
            prefill_target=_prefill_target("target"), **_tier_flags(tier),
        )

    # Bulk-scanning support: the target field accepts one domain per line
    # (or comma-separated) so a user can launch several base scans from one
    # submission instead of repeating the form. Each raw entry still goes
    # through the exact same normalize_target()/is_ssrf_safe_hostname()
    # gate as a single-target submission - bulk is purely a UI convenience
    # for the launch step, not a relaxed validation path. Entries that
    # don't normalize or fail the SSRF check are skipped (reported back to
    # the user) rather than aborting the whole batch, so one typo doesn't
    # block the rest of a portfolio scan.
    raw_targets = [t.strip() for chunk in request.form.get("target", "").splitlines()
                   for t in chunk.split(",")]
    raw_targets = [t for t in raw_targets if t][:MAX_BULK_TARGETS]
    if not raw_targets:
        return render_template(
            "scan_new_base.html", error="Enter at least one valid domain or URL, e.g. example.com",
            prefill_target=_prefill_target("target"), **_tier_flags(tier),
        )

    manual_test_url = request.form.get("test_url", "").strip() or None
    # If the user pasted one full URL-with-query-string directly into the
    # Target box (e.g. https://www.example.com/search?q=test) instead of
    # using the separate "seed URL" field below, treat that same value as
    # the seed too - normalize_target() would otherwise silently discard
    # the path/query and only scan the bare domain, throwing away exactly
    # the query-string page the user was pointing at. Only applies to a
    # single target (same rule the explicit test_url field already
    # follows) and only when the user didn't also fill in test_url
    # explicitly - an explicit seed URL always wins.
    if not manual_test_url and len(raw_targets) == 1 and "?" in raw_targets[0]:
        manual_test_url = raw_targets[0]
    if manual_test_url:
        unsafe = _unsafe_target_error(manual_test_url, org_id=current_user.org_id)
        if unsafe:
            return render_template(
                "scan_new_base.html", error=unsafe,
                prefill_target=_prefill_target("target"), **_tier_flags(tier),
            )

    launched, skipped, duplicates = [], [], []
    for raw in raw_targets:
        # A seed test_url only makes sense against a single target -
        # applying it across a whole batch would test every target with
        # another site's query-string shape.
        s, err, is_duplicate = _launch_base_scan(
            current_user, tier, raw,
            manual_test_url=manual_test_url if len(raw_targets) == 1 else None,
        )
        if s is None:
            skipped.append((raw, err))
        elif is_duplicate:
            duplicates.append(s)
        else:
            launched.append(s)

    if not launched and not duplicates:
        return render_template(
            "scan_new_base.html",
            error="None of the entered targets could be scanned: " +
                  "; ".join(f"{t} ({why})" for t, why in skipped),
            prefill_target=_prefill_target("target"), **_tier_flags(tier),
        )

    if skipped:
        flash("Skipped: " + "; ".join(f"{t} ({why})" for t, why in skipped), "error")

    # A single-target submission that turned out to be a duplicate redirects
    # exactly like the other three scan types - straight to the existing
    # scan's progress page with the info-flash, no separate "launched"
    # branch to fall into.
    if not launched and len(duplicates) == 1:
        flash(DUPLICATE_SCAN_MESSAGE, "info")
        return redirect(url_for("scan.scan_detail", scan_id=duplicates[0].id))

    # Preserve the existing single-launched-target redirect exactly as it
    # was before this task: a submission that resulted in exactly one
    # freshly-launched scan goes straight to that scan's detail page,
    # regardless of whether any other targets in the same batch turned out
    # to be duplicates (those are reported via the separate info flash
    # below, not by changing this redirect's destination).
    if len(launched) == 1:
        if duplicates:
            flash(
                f"{len(duplicates)} target(s) already had a scan running - showing existing "
                "progress for those, not starting new ones.",
                "info",
            )
        return redirect(url_for("scan.scan_detail", scan_id=launched[0].id))

    if duplicates:
        flash(
            f"{len(duplicates)} target(s) already had a scan running - showing existing progress "
            "for those, not starting new ones.",
            "info",
        )

    if launched:
        flash(f"Started {len(launched)} base scans.", "info")

    return redirect(url_for("scan.dashboard"))


def _advanced_render_kwargs(tier):
    """Shared kwargs for every scan_new_advanced.html render site: the
    Smart Setup wizard's target prefill (POST branch reads request.form so
    a validation-error re-render never clears what the user typed, same
    _prefill_target convention 05-01 established for the other three scan
    types) plus the advanced card's own SCANUX-03 pill, sourced from the
    same _scan_type_availability() Step 2 uses so the label can never
    drift from what Step 2 already showed for this exact target."""
    prefill_target = _prefill_target("target")
    normalized = normalize_target(prefill_target) if prefill_target else ""
    availability = _availability_for("advanced", tier, current_user.organization, normalized or "")
    return {**_tier_flags(tier), "prefill_target": prefill_target, "availability": availability}


@scan.route("/scan/new/advanced", methods=["GET", "POST"])
@login_required
def new_scan_advanced():
    tier = effective_tier(current_user)

    if request.method == "GET":
        return render_template("scan_new_advanced.html", **_advanced_render_kwargs(tier))

    if not request.form.get("authorized_adv"):
        return render_template(
            "scan_new_advanced.html", error="You must confirm you own or are authorized to test this target.",
            **_advanced_render_kwargs(tier),
        )

    advanced = _parse_advanced_form(request.form)
    has_login_group = advanced["login_url"] and advanced["user_field"] and advanced["pass_field"] and advanced["fail_text"]
    has_union_group = advanced["sqli_union_url"] and advanced["sqli_union_param"]
    has_xss_group = (advanced["stored_xss_submit_url"] and advanced["stored_xss_field"]
                      and advanced["stored_xss_view_url"] and advanced["stored_xss_cookie"])
    has_idor_group = (advanced["idor_url_template"] and advanced["idor_ids"]
                       and advanced["idor_cookie_a"] and advanced["idor_cookie_b"])

    if not (has_login_group or has_union_group or has_xss_group or has_idor_group):
        return render_template(
            "scan_new_advanced.html",
            error="Fill in at least one advanced check group before running advanced checks.",
            **_advanced_render_kwargs(tier),
        )

    # Every group's URL field is user-typed free text, independent of
    # normalize_target - Org-verified + a verified domain only proves
    # ownership of *a* domain, not that these specific fields point at a
    # public address, so each one gets the same SSRF check as the other
    # scan types before anything is spawned.
    for group_url in (advanced["login_url"], advanced["sqli_union_url"],
                       advanced["stored_xss_submit_url"], advanced["stored_xss_view_url"],
                       advanced["idor_url_template"]):
        if not group_url:
            continue
        unsafe = _unsafe_target_error(group_url, org_id=current_user.org_id)
        if unsafe:
            return render_template("scan_new_advanced.html", error=unsafe, **_advanced_render_kwargs(tier))

    # run_advanced_scan takes a single org_verified_for_domain flag that
    # applies to every check group in the run. Advanced groups can target
    # different URLs (login_url vs sqli_union_url vs ...), so the domain
    # used for the verification check is the first non-empty group URL,
    # in the same precedence order run_advanced_scan itself checks groups
    # in - a judgment call, since there's no single canonical "the"
    # target when multiple groups are filled in at once.
    domain_probe_url = (advanced["login_url"] or advanced["sqli_union_url"]
                         or advanced["stored_xss_submit_url"] or advanced["idor_url_template"])
    org_verified = domain_is_org_verified(current_user.organization, domain_probe_url) if domain_probe_url else False

    existing = _find_running_scan(current_user.id, domain_probe_url or "advanced-scan", "advanced")
    if existing is not None:
        flash(DUPLICATE_SCAN_MESSAGE, "info")
        return redirect(url_for("scan.scan_detail", scan_id=existing.id))

    s = Scan(user_id=current_user.id, org_id=current_user.org_id,
              target_url=domain_probe_url or "advanced-scan",
              scan_type="advanced", status=ScanStatus.QUEUED)
    db.session.add(s)
    db.session.commit()

    _spawn_scan_thread(s.id, "advanced", advanced=advanced, tier=tier, org_verified=org_verified)
    return redirect(url_for("scan.scan_detail", scan_id=s.id))


@scan.route("/scan/new/advanced/detect", methods=["POST"])
@login_required
def new_scan_advanced_detect():
    """Smart Setup's auto-detect endpoint - the Advanced form's JS calls
    this once the user has typed a target AND ticked the authorization
    checkbox, never before (the checkbox is required in this endpoint's own
    request body, not just trusted from the page state, so a stray fetch()
    call can't sneak a scan of an unconfirmed target past this gate either).

    UX aid only - see checks.detect_login_form's docstring. This endpoint
    never creates a Scan row and never runs any check; it only suggests
    values for the login-bypass group's fields, which the user still
    reviews (and can edit or clear) before submitting the real form. All of
    Advanced's actual gates (authorized_adv, tier, domain verification,
    per-group SSRF checks) still run unchanged in new_scan_advanced above
    when that form is eventually submitted.
    """
    if not request.form.get("authorized_adv"):
        return jsonify(error="Tick the authorization checkbox first."), 400

    target = normalize_target(request.form.get("target", ""))
    if not target:
        return jsonify(error="Enter a valid domain or URL first."), 400

    unsafe = _unsafe_target_error(target, org_id=current_user.org_id)
    if unsafe:
        return jsonify(error=unsafe), 400

    found = detect_login_form(target)
    if not found:
        return jsonify(found=False)
    return jsonify(found=True, **found)


def _media_render_kwargs(tier):
    """Shared kwargs for every scan_new_media.html render site - mirrors
    `_advanced_render_kwargs`: `_prefill_target` for the wizard's
    cross-step target carrier (POST branch reads request.form so a
    validation-error re-render never clears what was typed) and the
    SCANUX-03 pill from the same `_availability_for` helper Step 2 uses."""
    prefill_target = _prefill_target("media_target")
    normalized = normalize_target(prefill_target) if prefill_target else ""
    availability = _availability_for("media", tier, current_user.organization, normalized or "")
    return {**_tier_flags(tier), "prefill_target": prefill_target, "availability": availability}


def _api_render_kwargs(tier):
    """Same shape as `_media_render_kwargs`, for scan_new_api.html."""
    prefill_target = _prefill_target("api_target")
    normalized = normalize_target(prefill_target) if prefill_target else ""
    availability = _availability_for("api", tier, current_user.organization, normalized or "")
    return {**_tier_flags(tier), "prefill_target": prefill_target, "availability": availability}


@scan.route("/scan/new/media", methods=["GET", "POST"])
@login_required
def new_scan_media():
    tier = effective_tier(current_user)

    if request.method == "GET":
        return render_template("scan_new_media.html", **_media_render_kwargs(tier))

    if not request.form.get("authorized_media"):
        return render_template(
            "scan_new_media.html", error="You must confirm you own or are authorized to test this domain.",
            **_media_render_kwargs(tier),
        )

    base_url = normalize_target(request.form.get("media_target", ""))
    if not base_url:
        return render_template(
            "scan_new_media.html", error="Enter a valid domain or URL for the media scan, e.g. example.com",
            **_media_render_kwargs(tier),
        )
    unsafe = _unsafe_target_error(base_url, org_id=current_user.org_id)
    if unsafe:
        return render_template("scan_new_media.html", error=unsafe, **_media_render_kwargs(tier))

    download = bool(request.form.get("media_download"))
    try:
        max_files = int(request.form.get("media_max_files", "20"))
    except ValueError:
        max_files = 20
    max_files = max(0, min(max_files, 50))

    # Media gating is route-level (run_media_scan's signature isn't
    # tier-aware) - if the tier doesn't qualify, don't create a Scan row
    # or spawn a thread at all; just re-render with an upgrade message.
    if FEATURE_REQUIREMENTS["media"] > tier:
        return render_template(
            "scan_new_media.html",
            error="Media scanning requires a Paid plan or higher. Upgrade on the Billing page to unlock it.",
            **_media_render_kwargs(tier),
        )

    existing = _find_running_scan(current_user.id, base_url, "media")
    if existing is not None:
        flash(DUPLICATE_SCAN_MESSAGE, "info")
        return redirect(url_for("scan.scan_detail", scan_id=existing.id))

    s = Scan(user_id=current_user.id, org_id=current_user.org_id,
              target_url=base_url, scan_type="media", status=ScanStatus.QUEUED)
    db.session.add(s)
    db.session.commit()

    _spawn_scan_thread(s.id, "media", base_url=base_url, download=download, max_files=max_files, tier=tier)
    return redirect(url_for("scan.scan_detail", scan_id=s.id))


@scan.route("/scan/new/api", methods=["GET", "POST"])
@login_required
def new_scan_api():
    """Same shape as new_scan_media: single target field, no sub-groups to
    partially unlock, so the tier is checked upfront and no Scan row/thread
    is created at all if it's insufficient (see run_api_scan's docstring in
    scan_engine.py for why this scan type isn't gated in the engine)."""
    tier = effective_tier(current_user)

    if request.method == "GET":
        return render_template("scan_new_api.html", **_api_render_kwargs(tier))

    if not request.form.get("authorized_api"):
        return render_template(
            "scan_new_api.html", error="You must confirm you own or are authorized to test this domain.",
            **_api_render_kwargs(tier),
        )

    base_url = normalize_target(request.form.get("api_target", ""))
    if not base_url:
        return render_template(
            "scan_new_api.html", error="Enter a valid domain or URL for the API scan, e.g. example.com",
            **_api_render_kwargs(tier),
        )
    unsafe = _unsafe_target_error(base_url, org_id=current_user.org_id)
    if unsafe:
        return render_template("scan_new_api.html", error=unsafe, **_api_render_kwargs(tier))

    if FEATURE_REQUIREMENTS["api"] > tier:
        return render_template(
            "scan_new_api.html",
            error="API exposure scanning requires a Paid plan or higher. Upgrade on the Billing page to unlock it.",
            **_api_render_kwargs(tier),
        )

    existing = _find_running_scan(current_user.id, base_url, "api")
    if existing is not None:
        flash(DUPLICATE_SCAN_MESSAGE, "info")
        return redirect(url_for("scan.scan_detail", scan_id=existing.id))

    s = Scan(user_id=current_user.id, org_id=current_user.org_id,
              target_url=base_url, scan_type="api", status=ScanStatus.QUEUED)
    db.session.add(s)
    db.session.commit()

    _spawn_scan_thread(s.id, "api", base_url=base_url, tier=tier)
    return redirect(url_for("scan.scan_detail", scan_id=s.id))


@scan.route("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    s = Scan.query.get_or_404(scan_id)
    _check_ownership(s)
    if s.status == ScanStatus.COMPLETED:
        return redirect(url_for("scan.scan_report", scan_id=scan_id))
    return render_template("scan_progress.html", scan=s)


def _serialize_new_events(scan_id, after_id):
    """Returns `[{"id", "check_name", "label", "phase", "detail",
    "finding_count", "top_severity"}, ...]` for every `ScanEvent` row
    belonging to `scan_id` with `id > after_id`, ordered oldest-first - the
    "only what's new since the last tick" query `scan_events()` streams, so
    the client never has to re-render its whole feed history every 0.5s.
    Standalone function (not inlined in `scan_events()`'s `generate()`
    closure) specifically so it's unit-testable without ever iterating the
    live SSE stream - see tests/test_scan_events.py, and the same
    constraint already documented for `_check_ownership` coverage in
    tests/test_scan_ownership.py."""
    rows = (
        ScanEvent.query.filter(ScanEvent.scan_id == scan_id, ScanEvent.id > after_id)
        .order_by(ScanEvent.id)
        .all()
    )
    return [
        {
            "id": row.id,
            "check_name": row.check_name,
            "label": CHECK_LABELS.get(row.check_name, row.check_name.replace("_", " ").title()),
            "icon": CHECK_CATEGORY.get(row.check_name, "shield"),
            "phase": row.phase.value,
            "detail": row.detail,
            "finding_count": row.finding_count,
            "top_severity": row.top_severity,
        }
        for row in rows
    ]


@scan.route("/scan/<int:scan_id>/events")
@login_required
def scan_events(scan_id):
    s = Scan.query.get_or_404(scan_id)
    _check_ownership(s)

    app_obj = current_app._get_current_object()

    def generate():
        # Runs after the view returns, while Flask streams the response body
        # - the request's app/application context is gone by then, so a
        # fresh one is pushed explicitly for the generator's lifetime (same
        # pattern as the background scan thread). `db.session.expire_all()`
        # each iteration forces a fresh row read instead of the scoped
        # session's cached copy from a previous iteration.
        #
        # `after_id` is a plain closure-local variable, not something the
        # client sends back - this SSE connection is one long-lived
        # response, not repeated short polls, so the cursor only needs to
        # survive across this loop's own iterations. A genuine client-side
        # reconnect (network drop, tab backgrounded) already falls back to
        # the page's existing stale/reconnect-then-reload recovery path,
        # which re-renders the whole page anyway.
        with app_obj.app_context():
            after_id = 0
            while True:
                db.session.expire_all()
                row = Scan.query.get(scan_id)
                if row is None:
                    break
                events = _serialize_new_events(scan_id, after_id)
                if events:
                    after_id = events[-1]["id"]
                payload = {
                    "progress_current": row.progress_current,
                    "progress_total": row.progress_total,
                    "status": row.status.value,
                    "events": events,
                }
                yield f"data: {json.dumps(payload)}\n\n"
                if row.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                    break
                time.sleep(0.5)

    return Response(generate(), mimetype="text/event-stream")


@scan.route("/scan/<int:scan_id>/status")
@login_required
def scan_status(scan_id):
    """Lightweight polling counterpart to `scan_events()`'s SSE feed, for
    the three scan types (advanced/media/api) whose orchestrators take no
    `progress_cb` and so never write a single `ScanEvent` row (D-04,
    05-CONTEXT.md). Those types have nothing to stream - holding a
    long-lived SSE connection open per running scan just to poll the same
    row `scan_events()` already re-reads every 0.5s buys nothing for them,
    so `scan_progress.html`'s script polls this instead on a 2s interval.
    Base scans are unaffected and keep using `scan_events()`.

    Reuses `_check_ownership` - the same owner-or-org-admin predicate
    `scan_detail`/`scan_events`/`scan_report`/`scan_report_csv` all gate on
    - so this can never become a weaker door onto the same data.

    Deliberately returns only `status` and `report_url`, never
    `error_message` or any exception text: the client only needs to know a
    scan became `failed` so it can reload into `scan_progress.html`'s
    existing server-rendered `.error-box` branch, which already renders
    `scan.error_message` itself. Putting the raw message into this JSON
    response would widen the disclosure surface for no benefit."""
    s = Scan.query.get_or_404(scan_id)
    _check_ownership(s)
    report_url = None
    if s.status == ScanStatus.COMPLETED and s.report is not None:
        report_url = url_for("scan.scan_report", scan_id=s.id)
    return jsonify(status=s.status.value, report_url=report_url)


# Bounds how many prior scans of the same target/type _sensitive_path_lifecycle
# will open and inspect - read-time-computed, so this is a latency/cost cap,
# not a data-retention limit. No schema change: lifecycle status is derived
# from the existing Scan/Report rows every time the report page renders,
# never persisted.
MAX_LIFECYCLE_SCANS = 20


def _ownership_scoped_history_query(s):
    """Same scans-I-can-see scoping _check_ownership() enforces per-row,
    expressed as a query filter: an individual's own scans, or (for an
    ORG_ADMIN) every scan run under their org - reused so the lifecycle/
    previous-scan lookups below can never surface another user's scan
    history through this side channel."""
    q = Scan.query.filter(Scan.target_url == s.target_url, Scan.scan_type == s.scan_type,
                           Scan.status == ScanStatus.COMPLETED)
    if s.org_id is not None and current_user.org_id == s.org_id and current_user.role == Role.ORG_ADMIN:
        return q.filter(Scan.org_id == s.org_id)
    return q.filter(Scan.user_id == s.user_id)


def _load_report_json(scan_row):
    """Reads a scan's report JSON: `Report.data` (Postgres) first, the
    on-disk file only as a fallback for rows saved before that column
    existed. `Report.data` is the source of truth going forward - a local
    disk write is per-machine and unreadable from a different worker/
    machine (real bug hit live on a 2-machine Fly deploy, see Report's
    docstring in models.py)."""
    if scan_row.report is None:
        return None
    if scan_row.report.data is not None:
        return scan_row.report.data
    return read_report_file(scan_row.report.json_path)


def _attach_regression_tags(scan_id, report):
    """Phase 27 (CONT-01): tags `report`'s findings new/recurring against
    the Asset's previous completed scan and stores resolved-finding
    snapshots under report["regression"]. Runs inside
    `_run_scan_in_background` BEFORE the Report row is inserted, so the
    stored blob itself carries the tags (CONT-01's "in the stored report").

    Scope: only scans linked to an Asset (asset_id set - scheduler fires and
    API-triggered asset scans) and only against the SAME ASSET's previous
    COMPLETED scan of the same scan_type, newest first. This is deliberately
    NOT _previous_completed_scan(): that helper is ownership-scoped via
    current_user, which doesn't exist on a background thread - here the
    asset_id linkage IS the authorization boundary, exactly as everywhere
    else asset-scoped queries run (compliance_coverage's precedent).

    No baseline (first fire for this asset/type, or the predecessor's report
    is missing/unreadable) leaves the report untouched - no fabricated "new"
    tags on a scan that had nothing to diff against."""
    s = Scan.query.get(scan_id)
    if s is None or s.asset_id is None:
        return
    prev = (Scan.query.filter(
                Scan.asset_id == s.asset_id,
                Scan.scan_type == s.scan_type,
                Scan.status == ScanStatus.COMPLETED,
                Scan.id != s.id,
                Scan.created_at < s.created_at)
            .order_by(Scan.created_at.desc())
            .first())
    if prev is None or prev.report is None:
        return
    prev_report = prev.report.data
    if prev_report is None:
        prev_report = read_report_file(prev.report.json_path)
    if prev_report is None:
        return

    tagged, summary = classify_regressions(prev_report, report)
    if summary is None:
        return
    report["findings"] = tagged
    report["regression"] = {
        "new": summary["new"],
        "recurring": summary["recurring"],
        "resolved": summary["resolved"],
    }


def _previous_completed_scan(s):
    """Most recent completed scan of the same target+type before `s`, within
    the caller's existing ownership scope - used for the report page's
    "Compare with previous scan" link (feeds the existing scan_compare()/
    diff_reports() below, not a new comparison mechanism)."""
    return (_ownership_scoped_history_query(s)
            .filter(Scan.id != s.id, Scan.created_at < s.created_at)
            .order_by(Scan.created_at.desc()).first())


def _sensitive_path_lifecycle(s, confirmed_paths):
    """For each path currently CONFIRMED-exposed in scan `s`'s report,
    returns {path: {"status": "new"|"active"|"reopened", "first_detected":
    datetime}} by walking up to MAX_LIFECYCLE_SCANS prior completed scans of
    the same target+type (read-only; nothing is persisted). A path with no
    prior occurrence is "new"; one confirmed in the immediately-preceding
    scan is "active"; one confirmed before but absent from the immediately-
    preceding scan is "reopened". Paths not currently confirmed (e.g.
    resolved since the last scan) aren't included - see the report page's
    "Compare with previous scan" link (reusing the existing diff_reports())
    for that side of the picture instead of duplicating it here."""
    if not confirmed_paths:
        return {}

    history = (_ownership_scoped_history_query(s)
               .filter(Scan.id != s.id, Scan.created_at < s.created_at)
               .order_by(Scan.created_at.asc())
               .limit(MAX_LIFECYCLE_SCANS).all())

    # presence[path] = [was_confirmed_in_history_scan_0, ...], chronological.
    presence = {path: [] for path in confirmed_paths}
    for hs in history:
        hreport = _load_report_json(hs)
        seen_here = set()
        if hreport:
            seen_here = {row["path"] for row in (hreport.get("sensitive_paths") or {}).get("rows", [])
                         if row.get("classification") == "confirmed"}
        for path in confirmed_paths:
            presence[path].append((hs.created_at, path in seen_here))

    lifecycle = {}
    for path, seq in presence.items():
        prior_occurrences = [d for d, present in seq if present]
        if not prior_occurrences:
            lifecycle[path] = {"status": "new", "first_detected": s.created_at}
        elif seq[-1][1]:  # present in the immediately-preceding scan too
            lifecycle[path] = {"status": "active", "first_detected": prior_occurrences[0]}
        else:
            lifecycle[path] = {"status": "reopened", "first_detected": prior_occurrences[0]}
    return lifecycle


@scan.route("/scan/<int:scan_id>/report")
@login_required
def scan_report(scan_id):
    s = Scan.query.get_or_404(scan_id)
    _check_ownership(s)
    if s.report is None:
        abort(404)

    report = _load_report_json(s)
    if report is None:
        abort(404)

    # Coerce the raw query-string value against the allowlist - never pass
    # request.args.get(...) itself into the template (T-03-21).
    group = request.args.get("group")
    if group not in GROUPING_MODES:
        group = "severity"

    compliance_groups = []
    domain_groups = []
    # findings_page/findings_page_num/findings_total_pages are only ever
    # meaningful for the severity (default) view - group == "compliance" or
    # "domain" leaves them at these defaults, and scan_report.html's
    # compliance/domain branches never read them (PERF-02's explicit scope
    # boundary: the compliance-grouped view stays unpaginated; domain
    # follows the same precedent rather than inventing a new pagination
    # rule for one grouping mode).
    findings_page, findings_page_num, findings_total_pages = [], 1, 1
    if group == "compliance":
        compliance_groups = group_findings_by_compliance(report.get("findings", []), CHECK_COMPLIANCE)
    elif group == "domain":
        domain_groups = group_findings_by_domain(report.get("findings", []), SECURITY_DOMAIN_MAP)
    else:
        sorted_findings = sorted(report.get("findings", []), key=lambda f: f.get("category", ""))
        findings_total_pages = max(1, ceil(len(sorted_findings) / FINDINGS_PER_PAGE))
        findings_page_num = max(1, request.args.get("page", 1, type=int))
        findings_page_num = min(findings_page_num, findings_total_pages)
        start = (findings_page_num - 1) * FINDINGS_PER_PAGE
        findings_page = sorted_findings[start:start + FINDINGS_PER_PAGE]

    lifecycle = {}
    sensitive_paths = report.get("sensitive_paths")
    if isinstance(sensitive_paths, dict):
        confirmed_paths = {row["path"] for row in sensitive_paths.get("rows", [])
                            if row.get("classification") == "confirmed"}
        lifecycle = _sensitive_path_lifecycle(s, confirmed_paths)

    previous_scan = _previous_completed_scan(s)

    return render_template(
        "scan_report.html", scan=s, r=report, locked=report.get("locked_checks", []),
        CHECK_COMPLIANCE=CHECK_COMPLIANCE, group=group, compliance_groups=compliance_groups,
        domain_groups=domain_groups,
        findings_page=findings_page, findings_page_num=findings_page_num,
        findings_total_pages=findings_total_pages,
        sensitive_path_lifecycle=lifecycle, previous_scan=previous_scan,
    )


def findings_csv_document(report, scan_id):
    """Shared CSV rendering of one report's findings - the single writer
    behind both export surfaces (the session-web /scan/<id>/export.csv
    route below and api_routes.py's token-authed GET /api/v1/scans/<id>/
    report.csv), so the two formats cannot drift. Pure function: no Flask
    objects in or out, returns (csv_text, filename)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["category", "title", "severity", "owasp_category", "detail", "recommendation"])
    for finding in report.get("findings", []):
        writer.writerow([
            finding.get("category", ""), finding.get("title", ""), finding.get("severity", ""),
            finding.get("owasp_category", ""), finding.get("detail", ""), finding.get("recommendation", ""),
        ])

    hostname = report.get("hostname") or urlparse(report.get("target", "")).netloc or "scan"
    filename = safe_filename(f"{hostname.replace(':', '_')}_scan{scan_id}_findings.csv")
    return buf.getvalue(), filename


@scan.route("/scan/<int:scan_id>/export.csv")
@login_required
def scan_report_csv(scan_id):
    """CSV export of a single report's findings. Same ownership guard as
    `scan_report` (404, not 403, for a scan the caller can't see) - export
    is just an alternate rendering of the same already-authorized report,
    not a new access path, so it reuses `_check_ownership` rather than
    inventing its own check. The CSV body itself comes from
    `findings_csv_document` above, shared verbatim with the /api/v1
    token-authed export."""
    s = Scan.query.get_or_404(scan_id)
    _check_ownership(s)
    if s.report is None:
        abort(404)

    report = _load_report_json(s)
    if report is None:
        abort(404)

    csv_text, filename = findings_csv_document(report, scan_id)
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@scan.route("/scan/<int:scan_id>/report.sarif")
@login_required
def scan_report_sarif(scan_id):
    """Phase 29 (SARIF-01): SARIF 2.1.0 export of a single report's
    findings, ingestible by GitHub's Security tab via
    github/codeql-action/upload-sarif. Same ownership guard as
    `scan_report`/`scan_report_csv` (404, not 403) - an alternate rendering
    of the same already-authorized report, not a new access path. The body
    comes from sarif.build_sarif_report + sarif.sarif_text, shared verbatim
    with the /api/v1 token-authed twin."""
    s = Scan.query.get_or_404(scan_id)
    _check_ownership(s)
    if s.report is None:
        abort(404)

    report = _load_report_json(s)
    if report is None:
        abort(404)

    doc, filename = build_sarif_report(report, scan_id)
    return Response(
        sarif_text(doc),
        mimetype="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@scan.route("/scan/<int:scan_id>/report.pdf")
@login_required
def scan_report_pdf(scan_id):
    """Phase 24 (PDFX-01): PDF export of a single report's findings.
    Same ownership guard as scan_report/scan_report_csv/scan_report_sarif
    (404, not 403) — an alternate rendering of the same already-authorized
    report, not a new access path. The PDF body comes from
    pdf_report.build_pdf_report's single shared writer, so the browser
    download and the /api/v1 token-authed twin can never drift."""
    s = Scan.query.get_or_404(scan_id)
    _check_ownership(s)
    if s.report is None:
        abort(404)

    report = _load_report_json(s)
    if report is None:
        abort(404)

    pdf_bytes, filename = build_pdf_report(report, scan_id)
    return Response(
        pdf_bytes,
        mimetype=PDF_MIMETYPE,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@scan.route("/scan/<int:scan_id>/findings.ndjson")
@login_required
def scan_report_ndjson(scan_id):
    """Phase 25 (INTG-01): NDJSON export — one JSON finding per line,
    ingestible by SIEMs, log aggregators, and CLI pipelines (jq, etc.).
    Same ownership guard as every other report rendering: 404-not-403 for
    a scan the caller can't see.  The NDJSON body comes from
    ndjson_report.findings_ndjson's single shared writer."""
    s = Scan.query.get_or_404(scan_id)
    _check_ownership(s)
    if s.report is None:
        abort(404)

    report = _load_report_json(s)
    if report is None:
        abort(404)

    ndjson_text, filename = findings_ndjson(report, scan_id)
    return Response(
        ndjson_text,
        mimetype="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def group_findings_by_compliance(findings, mapping):
    """Buckets a report's `findings` list (plain dicts) by their mapped
    OWASP Top 10 category, for the report page's Compliance grouping mode
    (COMP-02).

    Computed here rather than in the Jinja template because Jinja's
    `sort(attribute=...)` cannot sort on a computed key (the OWASP category
    is derived from `mapping[finding["check_name"]]["owasp"]`, not a field
    already on the finding dict) - and the existing severity-grouping
    template pattern only works on a list that's already sorted by the key
    being grouped on. `mapping` is accepted as a parameter (rather than this
    function importing CHECK_COMPLIANCE itself) so it stays a pure,
    Flask-free helper that's trivially unit-testable on plain dicts, the
    same shape as `diff_reports()`/`index_by_key()` above.

    Returns a list of `(owasp_category, [finding, ...])` pairs. Mapped
    categories are sorted ascending by their category string; findings whose
    check_name is missing, empty, or absent from `mapping` land in a single
    "Uncategorized" group that is always last (when non-empty). Findings
    keep their arrival order within each group.
    """
    groups = {}
    uncategorized = []
    for f in findings:
        check_name = f.get("check_name") or ""
        entry = mapping.get(check_name, {}) if check_name else {}
        category = entry.get("owasp") or ""
        if not category:
            uncategorized.append(f)
        else:
            groups.setdefault(category, []).append(f)

    result = [(category, groups[category]) for category in sorted(groups)]
    if uncategorized:
        result.append(("Uncategorized", uncategorized))
    return result


def group_findings_by_domain(findings, mapping):
    """v1.3 SCORE-02: buckets a report's `findings` list by their mapped
    security domain (SECURITY_DOMAIN_MAP), for the report page's new
    "Domain" grouping mode - the product-facing reorganization SCORE-02
    calls for, alongside the existing Severity/Compliance modes rather than
    replacing either.

    Same shape/contract as group_findings_by_compliance() above (plain
    dicts in, `(domain, [finding, ...])` pairs out, "Uncategorized" always
    last when non-empty) - the one difference is `mapping` here is a flat
    `{check_name: domain_string}` dict (SECURITY_DOMAIN_MAP), not
    CHECK_COMPLIANCE's `{check_name: {"owasp": ..., "asvs": ...}}` shape,
    so it reads the value directly rather than pulling a sub-key.
    """
    groups = {}
    uncategorized = []
    for f in findings:
        check_name = f.get("check_name") or ""
        domain = mapping.get(check_name, "") if check_name else ""
        if not domain:
            uncategorized.append(f)
        else:
            groups.setdefault(domain, []).append(f)

    result = [(domain, groups[domain]) for domain in sorted(groups)]
    if uncategorized:
        result.append(("Uncategorized", uncategorized))
    return result


def diff_reports(report_a, report_b):
    """Diffs two report dicts keyed on `(category, title)` - `detail`
    strings often contain run-specific data (timestamps/IPs), so comparing
    on full content would flag near-everything as "changed" between any two
    runs. Documented limitation: two distinct findings that happen to share
    (category, title) would collide.

    Returns {"added", "removed", "changed", "unchanged_count", "score_delta"}.
    """
    def index_by_key(report):
        idx = {}
        for f in report.get("findings", []):
            idx[(f["category"], f["title"])] = f
        return idx

    idx_a = index_by_key(report_a)
    idx_b = index_by_key(report_b)

    added = [f for key, f in idx_b.items() if key not in idx_a]
    removed = [f for key, f in idx_a.items() if key not in idx_b]
    changed = []
    unchanged_count = 0
    for key, fb in idx_b.items():
        if key in idx_a:
            fa = idx_a[key]
            if fa.get("severity") != fb.get("severity") or fa.get("detail") != fb.get("detail"):
                changed.append({"before": fa, "after": fb})
            else:
                unchanged_count += 1

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged_count": unchanged_count,
        "score_delta": report_b.get("score", 0) - report_a.get("score", 0),
    }


@scan.route("/scan/<int:scan_id>/compare/<int:other_id>")
@login_required
def scan_compare(scan_id, other_id):
    a = Scan.query.get_or_404(scan_id)
    b = Scan.query.get_or_404(other_id)
    _check_ownership(a)
    _check_ownership(b)
    if a.report is None or b.report is None:
        abort(404)

    report_a = _load_report_json(a)
    report_b = _load_report_json(b)
    if report_a is None or report_b is None:
        abort(404)

    diff = diff_reports(report_a, report_b)

    return render_template(
        "scan_compare.html", a=a, b=b, report_a=report_a, report_b=report_b, diff=diff,
    )
