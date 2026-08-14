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
import os
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from webvulnscanner.ai_summary import generate_remediation_summary
from webvulnscanner.checks import CHECK_CATEGORY, CHECK_LABELS, REPORTS_DIR, is_ssrf_safe_hostname, normalize_target
from webvulnscanner.entitlements import FEATURE_REQUIREMENTS, Tier, domain_is_org_verified, effective_tier
from webvulnscanner.extensions import db
from webvulnscanner.models import Report, Role, Scan, ScanEvent, ScanEventPhase, ScanStatus
from webvulnscanner.scan_engine import run_advanced_scan, run_api_scan, run_media_scan, run_scan, save_report

scan = Blueprint("scan", __name__)


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

            fname = save_report(report, prefix, hostname)
            db.session.add(Report(scan_id=scan_id, json_path=fname))
            s = Scan.query.get(scan_id)
            s.status = ScanStatus.COMPLETED
            s.risk_score = report["score"]
            s.completed_at = datetime.now(timezone.utc)
            db.session.commit()
        except Exception as e:  # noqa: BLE001 - a failed scan must not leave the row stuck RUNNING
            s = Scan.query.get(scan_id)
            s.status = ScanStatus.FAILED
            s.error_message = str(e)
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


@scan.route("/dashboard")
@login_required
def dashboard():
    scans = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    latest = scans[0] if scans else None
    target_trends = _per_target_trends(scans)
    completed_count = sum(1 for s in scans if s.status == ScanStatus.COMPLETED)

    # Powers the "Recent Findings" section - only loaded when the latest
    # scan actually has a persisted report, same on-disk JSON every other
    # report view reads (scan_report()/scan_report_csv() above). A missing/
    # corrupt file degrades to None (empty state), never a 500 - same
    # convention as every check_* function in checks.py.
    latest_report = None
    if latest is not None and latest.status == ScanStatus.COMPLETED and latest.report is not None:
        try:
            with open(os.path.join(REPORTS_DIR, latest.report.json_path), encoding="utf-8") as f:
                latest_report = json.load(f)
        except (OSError, ValueError):
            latest_report = None

    return render_template(
        "dashboard.html", scans=scans, latest=latest, target_trends=target_trends,
        completed_count=completed_count, latest_report=latest_report,
        scan_type_labels=SCAN_TYPE_LABELS,
    )


# Caps how many targets a single /scan/new/base submission can launch at
# once (see the bulk-scanning support in new_scan_base below). Kept small
# and hardcoded rather than a plan-based limit - this is about not letting
# one form submission spawn dozens of background scan threads at once, not
# an entitlement to gate by tier.
MAX_BULK_TARGETS = 10


def _tier_flags(tier):
    return {
        "tier": tier,
        "can_run_paid": Tier.PAID <= tier,
        "can_run_org_verified": Tier.ORG_VERIFIED <= tier,
        "can_run_media": FEATURE_REQUIREMENTS["media"] <= tier,
        "can_run_api": FEATURE_REQUIREMENTS["api"] <= tier,
        "max_bulk_targets": MAX_BULK_TARGETS,
    }


def _unsafe_target_error(url):
    """None if url's hostname resolves only to public addresses; an
    error string (safe to show the user) otherwise. Every route below
    calls this on each user-supplied absolute URL before a Scan row is
    created - see is_ssrf_safe_hostname's docstring in checks.py for
    what this does and doesn't protect against."""
    hostname = urlparse(url).hostname
    if not hostname or not is_ssrf_safe_hostname(hostname):
        return "This target resolves to a private, internal, or unreachable address and cannot be scanned."
    return None


@scan.route("/scan/new")
@login_required
def new_scan():
    """GET-only "choose a scan type" landing page. Each scan type has its
    own dedicated GET+POST route below (new_scan_base/advanced/media/api) -
    this endpoint/URL is kept stable so existing links (base.html's nav,
    dashboard.html's CTA and empty-state link) don't need to change."""
    tier = effective_tier(current_user)
    return render_template("scan_new.html", **_tier_flags(tier))


def _launch_base_scan(user, tier, raw_target, manual_test_url=None):
    """Validates+launches one base scan for `raw_target`, exactly the steps
    `new_scan_base`'s per-target loop already ran inline before this was
    extracted: normalize_target() -> _unsafe_target_error() (the SSRF gate
    every new_scan_* route calls before a Scan row is created) ->
    domain_is_org_verified() -> create the Scan row -> spawn the background
    thread. Returns (scan, None) on success or (None, error_string) on a
    validation/safety failure - never raises past its own SSRF/normalize
    checks.

    This is the single place both the UI's bulk-scan form (scan_routes.py)
    and the API's POST /api/v1/scans (api_routes.py) launch a scan, so an
    API-triggered scan is provably subject to the exact same
    ownership/SSRF gate as one launched from the form - not a
    reimplementation that could quietly drift from it. `user` is a plain
    parameter (not `current_user`) precisely so api_routes.py can pass the
    User the API key resolves to."""
    base_url = normalize_target(raw_target)
    if not base_url:
        return None, "not a valid domain/URL"
    unsafe = _unsafe_target_error(base_url)
    if unsafe:
        return None, unsafe
    if manual_test_url:
        unsafe = _unsafe_target_error(manual_test_url)
        if unsafe:
            return None, unsafe

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
    return s, None


@scan.route("/scan/new/base", methods=["GET", "POST"])
@login_required
def new_scan_base():
    tier = effective_tier(current_user)

    if request.method == "GET":
        return render_template("scan_new_base.html", **_tier_flags(tier))

    if not request.form.get("authorized"):
        return render_template(
            "scan_new_base.html", error="You must confirm you own or are authorized to test this domain.",
            **_tier_flags(tier),
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
            **_tier_flags(tier),
        )

    manual_test_url = request.form.get("test_url", "").strip() or None
    if manual_test_url:
        unsafe = _unsafe_target_error(manual_test_url)
        if unsafe:
            return render_template("scan_new_base.html", error=unsafe, **_tier_flags(tier))

    launched, skipped = [], []
    for raw in raw_targets:
        # A seed test_url only makes sense against a single target -
        # applying it across a whole batch would test every target with
        # another site's query-string shape.
        s, err = _launch_base_scan(
            current_user, tier, raw,
            manual_test_url=manual_test_url if len(raw_targets) == 1 else None,
        )
        if s is None:
            skipped.append((raw, err))
        else:
            launched.append(s)

    if not launched:
        return render_template(
            "scan_new_base.html",
            error="None of the entered targets could be scanned: " +
                  "; ".join(f"{t} ({why})" for t, why in skipped),
            **_tier_flags(tier),
        )

    if skipped:
        flash("Skipped: " + "; ".join(f"{t} ({why})" for t, why in skipped), "error")

    if len(launched) == 1:
        return redirect(url_for("scan.scan_detail", scan_id=launched[0].id))

    flash(f"Started {len(launched)} base scans.", "info")
    return redirect(url_for("scan.dashboard"))


@scan.route("/scan/new/advanced", methods=["GET", "POST"])
@login_required
def new_scan_advanced():
    tier = effective_tier(current_user)

    if request.method == "GET":
        return render_template("scan_new_advanced.html", **_tier_flags(tier))

    if not request.form.get("authorized_adv"):
        return render_template(
            "scan_new_advanced.html", error="You must confirm you own or are authorized to test this target.",
            **_tier_flags(tier),
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
            **_tier_flags(tier),
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
        unsafe = _unsafe_target_error(group_url)
        if unsafe:
            return render_template("scan_new_advanced.html", error=unsafe, **_tier_flags(tier))

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

    s = Scan(user_id=current_user.id, org_id=current_user.org_id,
              target_url=domain_probe_url or "advanced-scan",
              scan_type="advanced", status=ScanStatus.QUEUED)
    db.session.add(s)
    db.session.commit()

    _spawn_scan_thread(s.id, "advanced", advanced=advanced, tier=tier, org_verified=org_verified)
    return redirect(url_for("scan.scan_detail", scan_id=s.id))


@scan.route("/scan/new/media", methods=["GET", "POST"])
@login_required
def new_scan_media():
    tier = effective_tier(current_user)

    if request.method == "GET":
        return render_template("scan_new_media.html", **_tier_flags(tier))

    if not request.form.get("authorized_media"):
        return render_template(
            "scan_new_media.html", error="You must confirm you own or are authorized to test this domain.",
            **_tier_flags(tier),
        )

    base_url = normalize_target(request.form.get("media_target", ""))
    if not base_url:
        return render_template(
            "scan_new_media.html", error="Enter a valid domain or URL for the media scan, e.g. example.com",
            **_tier_flags(tier),
        )
    unsafe = _unsafe_target_error(base_url)
    if unsafe:
        return render_template("scan_new_media.html", error=unsafe, **_tier_flags(tier))

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
            **_tier_flags(tier),
        )

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
        return render_template("scan_new_api.html", **_tier_flags(tier))

    if not request.form.get("authorized_api"):
        return render_template(
            "scan_new_api.html", error="You must confirm you own or are authorized to test this domain.",
            **_tier_flags(tier),
        )

    base_url = normalize_target(request.form.get("api_target", ""))
    if not base_url:
        return render_template(
            "scan_new_api.html", error="Enter a valid domain or URL for the API scan, e.g. example.com",
            **_tier_flags(tier),
        )
    unsafe = _unsafe_target_error(base_url)
    if unsafe:
        return render_template("scan_new_api.html", error=unsafe, **_tier_flags(tier))

    if FEATURE_REQUIREMENTS["api"] > tier:
        return render_template(
            "scan_new_api.html",
            error="API exposure scanning requires a Paid plan or higher. Upgrade on the Billing page to unlock it.",
            **_tier_flags(tier),
        )

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
    if scan_row.report is None:
        return None
    try:
        with open(os.path.join(REPORTS_DIR, scan_row.report.json_path), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


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

    with open(os.path.join(REPORTS_DIR, s.report.json_path), encoding="utf-8") as f:
        report = json.load(f)

    lifecycle = {}
    sensitive_paths = report.get("sensitive_paths")
    if isinstance(sensitive_paths, dict):
        confirmed_paths = {row["path"] for row in sensitive_paths.get("rows", [])
                            if row.get("classification") == "confirmed"}
        lifecycle = _sensitive_path_lifecycle(s, confirmed_paths)

    previous_scan = _previous_completed_scan(s)

    return render_template(
        "scan_report.html", scan=s, r=report, locked=report.get("locked_checks", []),
        sensitive_path_lifecycle=lifecycle, previous_scan=previous_scan,
    )


@scan.route("/scan/<int:scan_id>/export.csv")
@login_required
def scan_report_csv(scan_id):
    """CSV export of a single report's findings. Same ownership guard as
    `scan_report` (404, not 403, for a scan the caller can't see) - export
    is just an alternate rendering of the same already-authorized report,
    not a new access path, so it reuses `_check_ownership` rather than
    inventing its own check."""
    s = Scan.query.get_or_404(scan_id)
    _check_ownership(s)
    if s.report is None:
        abort(404)

    with open(os.path.join(REPORTS_DIR, s.report.json_path), encoding="utf-8") as f:
        report = json.load(f)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["category", "title", "severity", "owasp_category", "detail", "recommendation"])
    for finding in report.get("findings", []):
        writer.writerow([
            finding.get("category", ""), finding.get("title", ""), finding.get("severity", ""),
            finding.get("owasp_category", ""), finding.get("detail", ""), finding.get("recommendation", ""),
        ])

    hostname = report.get("hostname") or urlparse(report.get("target", "")).netloc or "scan"
    filename = f"{hostname.replace(':', '_')}_scan{scan_id}_findings.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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

    with open(os.path.join(REPORTS_DIR, a.report.json_path), encoding="utf-8") as f:
        report_a = json.load(f)
    with open(os.path.join(REPORTS_DIR, b.report.json_path), encoding="utf-8") as f:
        report_b = json.load(f)

    diff = diff_reports(report_a, report_b)

    return render_template(
        "scan_compare.html", a=a, b=b, report_a=report_a, report_b=report_b, diff=diff,
    )
