"""
Blueprint `scan`: /dashboard, /scan/new, /scan/<id>, /scan/<id>/events,
/scan/<id>/report, /scan/<id>/compare/<other_id>.

This is the cutover point where the old synchronous `/scan`, `/scan-advanced`,
`/scan-media` routes (formerly in the standalone `app.py`) become a single
async, tier-aware flow: `POST /scan/new` creates a `Scan(status=QUEUED)` row,
spawns a daemon `threading.Thread` running the appropriate orchestrator, and
redirects to `/scan/<id>`, which live-updates via SSE (`/scan/<id>/events`)
until the scan finishes and redirects to `/scan/<id>/report`.

**Form/route multiplexing decision**: `/scan/new` handles all 3 scan types
(base/advanced/media) via a single route, dispatching on a hidden
`scan_type` form field (one per sub-form in `scan_new.html`) rather than
3 separate routes - this mirrors the old app.py's 3-separate-forms UI while
giving all 3 the same async/SSE handling with no duplicated route/thread
plumbing.

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
import json
import os
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Blueprint, Response, abort, current_app, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from webvulnscanner.checks import REPORTS_DIR, normalize_target
from webvulnscanner.entitlements import FEATURE_REQUIREMENTS, Tier, domain_is_org_verified, effective_tier
from webvulnscanner.extensions import db
from webvulnscanner.models import Report, Role, Scan, ScanStatus
from webvulnscanner.scan_engine import run_advanced_scan, run_media_scan, run_scan, save_report

scan = Blueprint("scan", __name__)


# --------------------------------------------------------------------------
# Ownership
# --------------------------------------------------------------------------

def _check_ownership(s):
    """Aborts with 404 unless `current_user` owns `s` or is the ORG_ADMIN of
    the org that ran it. 404 (not 403) so a scan ID doesn't confirm its own
    existence to someone who isn't entitled to see it either way - matches
    the convention already used for cross-org access in org_routes.py."""
    if s.user_id == current_user.id:
        return
    if s.org_id is not None and current_user.org_id == s.org_id and current_user.role == Role.ORG_ADMIN:
        return
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
                def progress_cb(done, total):
                    row = Scan.query.get(scan_id)
                    row.progress_current = done
                    row.progress_total = total
                    db.session.commit()

                report = run_scan(
                    kwargs["base_url"], kwargs["manual_test_url"],
                    kwargs["tier"], kwargs["org_verified"], progress_cb=progress_cb,
                )
                fname = save_report(report, "", urlparse(kwargs["base_url"]).netloc)
            elif scan_type == "advanced":
                # run_advanced_scan has no progress_cb param - its own locked-
                # check-group gating is the only per-check granularity it
                # exposes, so progress_current/progress_total stay 0/0 for
                # the whole run (scan_progress.html degrades to a status-only
                # display for this scan type, not a real percentage).
                report = run_advanced_scan(kwargs["advanced"], kwargs["tier"], kwargs["org_verified"])
                fname = save_report(report, "advanced_", report["hostname"])
            elif scan_type == "media":
                # Same no-progress_cb note as above; also, tier gating for
                # media is enforced route-level in new_scan() before this
                # thread is ever spawned - run_media_scan's signature is
                # unchanged and does not re-check tier itself.
                report = run_media_scan(kwargs["base_url"], kwargs["download"], kwargs["max_files"])
                fname = save_report(report, "media_", report["hostname"])
            else:
                raise ValueError(f"unknown scan_type {scan_type!r}")

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

@scan.route("/dashboard")
@login_required
def dashboard():
    scans = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    latest = scans[0] if scans else None
    return render_template("dashboard.html", scans=scans, latest=latest)


def _tier_flags(tier):
    return {
        "tier": tier,
        "can_run_paid": Tier.PAID <= tier,
        "can_run_org_verified": Tier.ORG_VERIFIED <= tier,
        "can_run_media": FEATURE_REQUIREMENTS["media"] <= tier,
    }


@scan.route("/scan/new", methods=["GET", "POST"])
@login_required
def new_scan():
    tier = effective_tier(current_user)

    if request.method == "GET":
        return render_template("scan_new.html", **_tier_flags(tier))

    scan_type = request.form.get("scan_type")

    if scan_type == "base":
        if not request.form.get("authorized"):
            return render_template(
                "scan_new.html", error="You must confirm you own or are authorized to test this domain.",
                **_tier_flags(tier),
            )

        base_url = normalize_target(request.form.get("target", ""))
        if not base_url:
            return render_template(
                "scan_new.html", error="Enter a valid domain or URL, e.g. example.com",
                **_tier_flags(tier),
            )

        manual_test_url = request.form.get("test_url", "").strip() or None
        org_verified = domain_is_org_verified(current_user.organization, base_url)

        s = Scan(user_id=current_user.id, org_id=current_user.org_id,
                  target_url=base_url, scan_type="base", status=ScanStatus.QUEUED)
        db.session.add(s)
        db.session.commit()

        _spawn_scan_thread(
            s.id, "base",
            base_url=base_url, manual_test_url=manual_test_url,
            tier=tier, org_verified=org_verified,
        )
        return redirect(url_for("scan.scan_detail", scan_id=s.id))

    if scan_type == "advanced":
        if not request.form.get("authorized_adv"):
            return render_template(
                "scan_new.html", error="You must confirm you own or are authorized to test this target.",
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
                "scan_new.html",
                error="Fill in at least one advanced check group before running advanced checks.",
                **_tier_flags(tier),
            )

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

    if scan_type == "media":
        if not request.form.get("authorized_media"):
            return render_template(
                "scan_new.html", error="You must confirm you own or are authorized to test this domain.",
                **_tier_flags(tier),
            )

        base_url = normalize_target(request.form.get("media_target", ""))
        if not base_url:
            return render_template(
                "scan_new.html", error="Enter a valid domain or URL for the media scan, e.g. example.com",
                **_tier_flags(tier),
            )

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
                "scan_new.html",
                error="Media scanning requires a Paid plan or higher. Upgrade on the Billing page to unlock it.",
                **_tier_flags(tier),
            )

        s = Scan(user_id=current_user.id, org_id=current_user.org_id,
                  target_url=base_url, scan_type="media", status=ScanStatus.QUEUED)
        db.session.add(s)
        db.session.commit()

        _spawn_scan_thread(s.id, "media", base_url=base_url, download=download, max_files=max_files)
        return redirect(url_for("scan.scan_detail", scan_id=s.id))

    return render_template("scan_new.html", error="Unknown scan type.", **_tier_flags(tier))


@scan.route("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    s = Scan.query.get_or_404(scan_id)
    _check_ownership(s)
    if s.status == ScanStatus.COMPLETED:
        return redirect(url_for("scan.scan_report", scan_id=scan_id))
    return render_template("scan_progress.html", scan=s)


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
        with app_obj.app_context():
            while True:
                db.session.expire_all()
                row = Scan.query.get(scan_id)
                if row is None:
                    break
                payload = {
                    "progress_current": row.progress_current,
                    "progress_total": row.progress_total,
                    "status": row.status.value,
                }
                yield f"data: {json.dumps(payload)}\n\n"
                if row.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                    break
                time.sleep(0.5)

    return Response(generate(), mimetype="text/event-stream")


@scan.route("/scan/<int:scan_id>/report")
@login_required
def scan_report(scan_id):
    s = Scan.query.get_or_404(scan_id)
    _check_ownership(s)
    if s.report is None:
        abort(404)

    with open(os.path.join(REPORTS_DIR, s.report.json_path), encoding="utf-8") as f:
        report = json.load(f)

    return render_template(
        "scan_report.html", scan=s, r=report, locked=report.get("locked_checks", []),
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
