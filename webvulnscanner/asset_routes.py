"""
Blueprint `asset`: /assets, /assets/new.

Asset registration + inventory-list routes (ASSET-01/02/03, tracer plan
01-01). An Asset is a persistent, recurring scan target - distinct from a
one-off manual Scan (see scan_routes.py's new_scan_* routes) - that
webvulnscanner.scheduler's tick loop fires automatically on a cadence.

**Ownership decision**: mirrors scan_routes._check_ownership's 404-not-403
convention, but org-scoped rather than owner-or-org-admin-scoped (every org
member sees the org's Assets, not just admins - Assets are shared
organizational inventory, unlike a personal dashboard of scans one person
ran). Solo (no-org) users are scoped by created_by_user_id, never by a raw
org_id equality - two different solo users both have org_id = None, so a
naive `a.org_id == current_user.org_id` comparison would match NULL == NULL
and leak one solo user's Assets to another.
"""
import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Blueprint, abort, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from webvulnscanner.checks import (
    CHECK_COMPLIANCE,
    CHECK_LABELS,
    REPORTS_DIR,
    SCAN_TYPE_CHECK_NAMES,
    SEVERITY_ORDER,
    is_ssrf_safe_hostname,
    normalize_target,
)
from webvulnscanner.entitlements import FEATURE_REQUIREMENTS, Tier, effective_tier_for_org
from webvulnscanner.extensions import db
from webvulnscanner.models import Asset, Scan, ScanStatus
from webvulnscanner.scheduler import CADENCE_INTERVALS

asset = Blueprint("asset", __name__, url_prefix="/assets")

CADENCE_CHOICES = ("daily", "weekly", "monthly")
SCHEDULE_SCAN_TYPE_CHOICES = ("base", "media", "api")
# Display names for the tier-locked schedule hint on asset_detail.html.
TIER_LABELS = {Tier.FREE: "Free", Tier.PAID: "Paid", Tier.ORG_VERIFIED: "Org-verified"}


def _check_asset_access(a):
    """Aborts with 404 unless `current_user` may access Asset `a`. 404 (not
    403) so an Asset ID doesn't confirm its own existence to someone who
    isn't entitled to see it either way - matches scan_routes._check_ownership's
    convention."""
    if current_user.org_id is not None:
        if a.org_id == current_user.org_id:
            return
        abort(404)
    # Solo (no-org) user: explicit branch required - a naive org_id equality
    # check would match NULL == NULL across two unrelated solo accounts.
    if a.org_id is None and a.created_by_user_id == current_user.id:
        return
    abort(404)


def _scoped_asset_query():
    if current_user.org_id is not None:
        return Asset.query.filter_by(org_id=current_user.org_id, deleted_at=None)
    return Asset.query.filter_by(
        org_id=None, created_by_user_id=current_user.id, deleted_at=None,
    )


@asset.route("")
@login_required
def list_assets():
    assets = _scoped_asset_query().order_by(Asset.created_at.desc()).all()
    return render_template("assets.html", assets=assets)


@asset.route("/new", methods=["GET", "POST"])
@login_required
def new_asset():
    if request.method == "GET":
        return render_template("asset_new.html")

    if not request.form.get("authorized"):
        return render_template(
            "asset_new.html",
            error="You must confirm you own or are authorized to test this domain.",
        )

    target_url = normalize_target(request.form.get("target", ""))
    if not target_url:
        return render_template(
            "asset_new.html", error="Enter a valid domain or URL, e.g. example.com",
        )

    hostname = urlparse(target_url).hostname
    if not hostname or not is_ssrf_safe_hostname(hostname):
        return render_template(
            "asset_new.html",
            error="This target resolves to a private, internal, or unreachable address "
                  "and cannot be scanned.",
        )

    cadence = request.form.get("cadence", "")
    schedule_scan_type = request.form.get("schedule_scan_type", "")
    if cadence not in CADENCE_CHOICES or schedule_scan_type not in SCHEDULE_SCAN_TYPE_CHOICES:
        return render_template(
            "asset_new.html", error="Choose a valid cadence and scan type.",
        )

    name = request.form.get("name", "").strip()
    if not name:
        return render_template(
            "asset_new.html", error="Enter a name for this Asset.",
        )

    now = datetime.now(timezone.utc)
    a = Asset(
        org_id=current_user.org_id,
        created_by_user_id=current_user.id,
        authorized_by_user_id=current_user.id,
        authorized_at=now,
        name=name,
        target_url=target_url,
        hostname=hostname,
        cadence=cadence,
        schedule_scan_type=schedule_scan_type,
        # Armed to fire on the very next scheduler tick (within
        # SCHEDULER_POLL_INTERVAL_SECONDS) rather than waiting a full cadence
        # interval - keeps exactly one dispatch code path (scheduler._tick/
        # _fire) for both the first scan and every recurring one after it.
        next_run_at=now,
    )
    db.session.add(a)
    db.session.commit()

    return redirect(url_for("asset.list_assets"))


def _category_for_check(check_name):
    """OWASP category string for `check_name`, per CHECK_COMPLIANCE, falling
    back to the literal "Uncategorized" for a check_name that isn't a
    CHECK_COMPLIANCE key at all - same graceful-degradation convention
    CHECK_COMPLIANCE's own module comment documents (checks.py). Note this
    is distinct from a check_name whose CHECK_COMPLIANCE entry's `owasp`
    value is itself the literal string "Uncategorized" (e.g. robots_sitemap)
    - both produce the same rendered text but the latter is a legitimate,
    always-present candidate category, not a missing-mapping fallback."""
    entry = CHECK_COMPLIANCE.get(check_name)
    return entry["owasp"] if entry else "Uncategorized"


def summarize_compliance(reports_by_scan_type):
    """Pure aggregation: turns `{scan_type: report_dict}` - each report being
    the most recent COMPLETED report of that scan_type an Asset has run -
    into an ordered list of compliance-coverage rows: `{owasp, status,
    finding_count, top_severity, locked}`, `status` one of
    "passing"/"failing"/"not_checked" (COMP-03).

    Deliberately DB-free and Flask-free (no query, no request, no
    current_user) - unit-testable directly against hand-built report dicts,
    same shape as scan_routes.diff_reports()/index_by_key(). This function
    performs no authorization; compliance_coverage() below is its only
    caller and is itself only ever reachable behind _check_asset_access.

    Coverage ("was this category checked") is derived from which check
    names actually EXECUTED in each report - never from findings alone - so
    a clean scan (zero findings) still reports full coverage rather than
    zero coverage (03-RESEARCH.md Pitfall 3). Each scan_type reports its
    executed-check set differently: base reports carry `locked_checks`
    (everything in CHECK_LABELS not in that list ran); advanced reports
    carry an explicit `ran` list; api reports carry a `results` dict whose
    keys are the executed check names; media reports carry neither - a
    completed media scan means its one check ("media") ran.

    A report whose findings contain ANY entry with no non-empty check_name
    is a report written before per-finding check_name tagging shipped
    (03-01) - its findings cannot be attributed to any check, so the whole
    report contributes no executed checks and no findings; its scan_type's
    categories still appear as "not_checked" candidate rows (never
    "passing", per this plan's prohibition: absence of findings is not
    evidence of passing when the report can't even say which checks ran).
    """
    tally = {}  # owasp category -> {"count": int, "severities": [str, ...]}
    executed_names = set()
    locked_names = set()
    candidate_names_by_category = {}

    for scan_type, report in reports_by_scan_type.items():
        for check_name in SCAN_TYPE_CHECK_NAMES.get(scan_type, ()):
            category = _category_for_check(check_name)
            candidate_names_by_category.setdefault(category, set()).add(check_name)

        findings = report.get("findings", [])
        if any(not f.get("check_name") for f in findings):
            continue  # untaggable legacy report - see docstring above

        if scan_type == "base":
            report_locked = set(report.get("locked_checks", []))
            report_executed = set(CHECK_LABELS) - report_locked
        elif scan_type == "advanced":
            report_locked = set(report.get("locked_checks", []))
            report_executed = set(report.get("ran", []))
        elif scan_type == "api":
            report_locked = set()
            report_executed = set(report.get("results", {}))
        elif scan_type == "media":
            report_locked = set()
            report_executed = {"media"}
        else:
            report_locked = set()
            report_executed = set()

        executed_names |= report_executed
        locked_names |= report_locked

        for f in findings:
            if f.get("severity") == "pass":
                continue
            category = _category_for_check(f.get("check_name", ""))
            entry = tally.setdefault(category, {"count": 0, "severities": []})
            entry["count"] += 1
            entry["severities"].append(f.get("severity"))

    checked_categories = {_category_for_check(name) for name in executed_names}
    all_categories = set(candidate_names_by_category) | set(tally)

    def _row(category):
        if category in tally:
            severities = tally[category]["severities"]
            top_severity = min(severities, key=SEVERITY_ORDER.index)
            return {
                "owasp": category, "status": "failing",
                "finding_count": tally[category]["count"],
                "top_severity": top_severity, "locked": False,
            }
        if category in checked_categories:
            return {
                "owasp": category, "status": "passing",
                "finding_count": 0, "top_severity": None, "locked": False,
            }
        names = candidate_names_by_category.get(category, set())
        return {
            "owasp": category, "status": "not_checked",
            "finding_count": 0, "top_severity": None,
            "locked": bool(names) and names <= locked_names,
        }

    mapped = sorted(c for c in all_categories if c != "Uncategorized")
    rows = [_row(c) for c in mapped]
    if "Uncategorized" in all_categories:
        rows.append(_row("Uncategorized"))
    return rows


def compliance_coverage(asset):
    """Aggregates `asset`'s most recent COMPLETED scan of each scan_type it
    has ever run into a per-OWASP-category coverage summary, via
    summarize_compliance() above.

    Performs NO authorization of its own - it takes the already-authorized
    `asset` object and queries strictly by `asset.id`; no scan id, asset id,
    or scan type is ever read from the request. Callers MUST call
    _check_asset_access(asset) first (see _render_asset_detail below) -
    without that guard this would be the phase's one real IDOR surface
    (03-RESEARCH.md Security Domain).

    Reads at most one report JSON file per scan_type present in `asset`'s
    completed-scan history (at most 4: base/advanced/media/api), newest
    scan of each type first. A scan whose report file is missing, unreadable,
    or not valid JSON is skipped - the remaining scan types still contribute
    - matching this codebase's "one check's failure never breaks the whole
    page" convention.
    """
    scans = (
        Scan.query.filter_by(asset_id=asset.id)
        .filter(Scan.status == ScanStatus.COMPLETED)
        .order_by(Scan.created_at.desc())
        .all()
    )
    scan_types_present = {s.scan_type for s in scans}

    kept = {}
    for s in scans:
        if len(kept) == len(scan_types_present):
            break
        if s.scan_type in kept or s.report is None:
            continue
        kept[s.scan_type] = s

    reports_by_scan_type = {}
    for scan_type, s in kept.items():
        try:
            with open(os.path.join(REPORTS_DIR, s.report.json_path), encoding="utf-8") as f:
                reports_by_scan_type[scan_type] = json.load(f)
        except (OSError, ValueError):
            continue

    return {
        "rows": summarize_compliance(reports_by_scan_type),
        "scan_types": sorted(reports_by_scan_type),
    }


def _render_asset_detail(a, **extra):
    scans = Scan.query.filter_by(asset_id=a.id).order_by(Scan.created_at.desc()).all()
    tier = effective_tier_for_org(a.organization)
    coverage = compliance_coverage(a)
    return render_template(
        "asset_detail.html", asset=a, scans=scans, tier=tier, coverage=coverage,
        FEATURE_REQUIREMENTS=FEATURE_REQUIREMENTS,
        TIER_LABELS=TIER_LABELS,
        CADENCE_CHOICES=CADENCE_CHOICES,
        SCHEDULE_SCAN_TYPE_CHOICES=SCHEDULE_SCAN_TYPE_CHOICES,
        **extra,
    )


@asset.route("/<int:asset_id>")
@login_required
def asset_detail(asset_id):
    a = Asset.query.get_or_404(asset_id)
    _check_asset_access(a)
    return _render_asset_detail(a)


@asset.route("/<int:asset_id>/schedule", methods=["POST"])
@login_required
def update_schedule(asset_id):
    a = Asset.query.get_or_404(asset_id)
    _check_asset_access(a)

    cadence = request.form.get("cadence", "")
    schedule_scan_type = request.form.get("schedule_scan_type", "")
    if cadence not in CADENCE_CHOICES or schedule_scan_type not in SCHEDULE_SCAN_TYPE_CHOICES:
        return _render_asset_detail(a, error="Choose a valid cadence and scan type.")

    # Single rule for every edit: unconditionally re-derive next_run_at from
    # "now" using the new cadence, rather than trying to preserve/adjust the
    # old cadence's remaining interval - avoids a stale next_run_at left over
    # from math done against a cadence that no longer applies.
    a.cadence = cadence
    a.schedule_scan_type = schedule_scan_type
    a.next_run_at = datetime.now(timezone.utc) + CADENCE_INTERVALS[cadence]
    db.session.commit()

    return redirect(url_for("asset.asset_detail", asset_id=a.id))


@asset.route("/<int:asset_id>/pause", methods=["POST"])
@login_required
def pause_asset(asset_id):
    a = Asset.query.get_or_404(asset_id)
    _check_asset_access(a)
    a.is_paused = True
    db.session.commit()
    return redirect(url_for("asset.asset_detail", asset_id=a.id))


@asset.route("/<int:asset_id>/resume", methods=["POST"])
@login_required
def resume_asset(asset_id):
    a = Asset.query.get_or_404(asset_id)
    _check_asset_access(a)
    # next_run_at is deliberately left untouched: a stale, already-past
    # next_run_at just means the Asset is due on the very next scheduler
    # tick after resuming - "catch up promptly" is the correct behavior
    # here, not a bug to special-case.
    a.is_paused = False
    db.session.commit()
    return redirect(url_for("asset.asset_detail", asset_id=a.id))


@asset.route("/<int:asset_id>/delete", methods=["POST"])
@login_required
def delete_asset(asset_id):
    a = Asset.query.get_or_404(asset_id)
    _check_asset_access(a)
    # Soft-delete only - deleted_at is what scheduler._tick's WHERE clause
    # and _scoped_asset_query() both already filter on, so past Scan
    # history for this Asset stays queryable/intact. is_paused=True too
    # (belt-and-suspenders): the row's own state stays self-explanatory
    # without needing to reason about two columns' interaction.
    a.deleted_at = datetime.now(timezone.utc)
    a.is_paused = True
    db.session.commit()
    return redirect(url_for("asset.list_assets"))
