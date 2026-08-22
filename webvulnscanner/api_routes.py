"""
Blueprint `api`: /api/v1.

Token-authenticated JSON surface (API-02..05, Phase 2). Every route here is
authenticated via login_manager.request_loader's Bearer-token lookup
(extensions.py), never via the session cookie's @login_required redirect
behavior - api_login_required (below) gives a JSON-appropriate 401 instead.

D-02: a token acts as the exact user who created it - every route below
reuses asset_routes._scoped_asset_query()/_check_asset_access() and
scan_routes._check_ownership() directly rather than re-implementing org/
solo scoping, so a token can never see more than its creating user's
session already could.
"""
from functools import wraps

from flask import Blueprint, abort, jsonify, request
from flask_login import current_user

from webvulnscanner.asset_routes import _check_asset_access, _scoped_asset_query
from webvulnscanner.entitlements import effective_tier
from webvulnscanner.extensions import csrf, limiter
from webvulnscanner.models import Asset, Scan
from webvulnscanner.scan_engine import read_report_file
from webvulnscanner.scan_routes import _check_ownership, _launch_base_scan, _load_report_json, diff_reports
from webvulnscanner.scheduler import _fire
from webvulnscanner.security_gate import DEFAULT_FAIL_ON, GATE_SEVERITIES, evaluate_gate

api = Blueprint("api", __name__, url_prefix="/api/v1")

# These routes are Bearer-token authenticated, not cookie/session-based -
# CSRF protection exists to protect cookie-authenticated state changes, and
# token auth is not cookie-based, so it doesn't apply here
# (02-RESEARCH.md's Standard Stack / Supporting table).
csrf.exempt(api)


def api_login_required(view_func):
    """Keeps @login_required's browser-redirect behavior untouched
    everywhere else in the app while giving /api/v1/* its own
    JSON-appropriate 401 - a CLI/script hitting an expired/missing token
    gets a parseable error, not a 302 to a login page (02-RESEARCH.md
    Pattern 2)."""

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify(error="missing or invalid API token"), 401
        return view_func(*args, **kwargs)

    return wrapped


@api.errorhandler(404)
def _api_not_found(_e):
    # Required, not optional: Asset.query.get_or_404(...) and every
    # ownership check reused from asset_routes.py/scan_routes.py call
    # abort(404) - without this blueprint-scoped handler those fall
    # through to the app's global @app.errorhandler(404)
    # (webvulnscanner/__init__.py), which renders the styled HTML
    # 404.html page - wrong content-type for a JSON API client.
    return jsonify(error="not found"), 404


def _api_rate_limit_key():
    """Matches Flask-Limiter's official per-user recipe, keyed by the
    token-populated current_user; falls back to the remote address before
    auth succeeds so an attacker can't dodge rate limiting entirely by
    omitting/mangling a token (02-RESEARCH.md Pattern 4)."""
    if current_user.is_authenticated:
        return f"user:{current_user.id}"
    from flask_limiter.util import get_remote_address

    return get_remote_address()


def _serialize_scan_summary(s):
    return {
        "id": s.id,
        "status": s.status.value,
        "risk_score": s.risk_score,
        "created_at": s.created_at.isoformat(),
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
    }


def _serialize_asset(a):
    latest = (
        Scan.query.filter_by(asset_id=a.id).order_by(Scan.created_at.desc()).first()
    )
    return {
        "id": a.id,
        "name": a.name,
        "target_url": a.target_url,
        "hostname": a.hostname,
        "cadence": a.cadence,
        "schedule_scan_type": a.schedule_scan_type,
        "is_paused": a.is_paused,
        "latest_scan": _serialize_scan_summary(latest) if latest else None,
    }


@api.route("/assets")
@api_login_required
@limiter.limit("60 per minute", key_func=_api_rate_limit_key)
def list_assets():
    assets = _scoped_asset_query().order_by(Asset.created_at.desc()).all()
    return jsonify(assets=[_serialize_asset(a) for a in assets])


@api.route("/assets/<int:asset_id>/scans", methods=["POST"])
@api_login_required
@limiter.limit("30 per minute", key_func=_api_rate_limit_key)
def trigger_scan(asset_id):
    """API-03: trigger a new scan against an existing Asset. 100% reuse of
    scheduler._fire(asset) - no parallel dispatch/SSRF/tier-check logic
    exists here (02-RESEARCH.md Pattern 3). _check_asset_access is the same
    org-shared, 404-not-403 ownership check the web UI's /assets/<id> route
    uses, so a non-admin org member can trigger a scan on a shared Asset
    they didn't create.

    Always returns 202 with the created Scan's id/status - even when
    _fire() internally produced a FAILED scan (SSRF-unsafe or
    tier-insufficient), since scan *creation* itself succeeded; the caller
    inspects the returned status field, exactly mirroring how the
    scheduler's own tick handles those same two failure branches.

    WR-01: excludes soft-deleted Assets (deleted_at is not None), matching
    _scoped_asset_query()'s own filter - a caller must not be able to keep
    firing scans against an Asset that was "deleted" through the web UI."""
    a = Asset.query.filter_by(id=asset_id, deleted_at=None).first_or_404()
    _check_asset_access(a)
    s = _fire(a)
    return jsonify(scan_id=s.id, status=s.status.value), 202


@api.route("/scans/<int:scan_id>")
@api_login_required
@limiter.limit("60 per minute", key_func=_api_rate_limit_key)
def scan_status(scan_id):
    """Lightweight status poll for a triggered scan - lets a CI/CLI caller
    check progress without pulling the full report. Ownership follows the
    exact same Asset-linked-vs-manual branch as fetch_report below (same
    Pitfall-1 fix, same WR-01 soft-delete guard) since both routes resolve
    a bare scan_id with no other scoping to lean on."""
    s = Scan.query.get_or_404(scan_id)
    if s.asset_id is not None:
        if s.asset.deleted_at is not None:
            abort(404)
        _check_asset_access(s.asset)
    else:
        _check_ownership(s)

    return jsonify(_serialize_scan_summary(s) | {
        "progress_current": s.progress_current,
        "progress_total": s.progress_total,
        "error_message": s.error_message,
    })


@api.route("/scans/<int:scan_id>/report")
@api_login_required
@limiter.limit("60 per minute", key_func=_api_rate_limit_key)
def fetch_report(scan_id):
    """API-04: fetch a completed scan's report as JSON - the exact on-disk
    JSON scan_engine.save_report() wrote, same file scan_routes.scan_report
    renders into HTML.

    Ownership branches on whether the scan is Asset-linked (the Pitfall 1
    fix, scoped to this new route only - see 02-CONTEXT.md's "Ownership-
    Check Mismatch" resolution, scan_routes.py's web-UI routes are
    unchanged): scheduler._fire()/trigger_scan() above always attribute the
    Scan to asset.created_by_user_id, not the actual triggering user, so an
    Asset-linked scan must be scoped the same org-shared way the Asset
    itself is (_check_asset_access), not by scan_routes._check_ownership's
    creator-or-org-admin-only rule. A manually-submitted (non-Asset) scan
    keeps that original rule unchanged.

    WR-01: an Asset-linked scan whose Asset has since been soft-deleted
    (deleted_at is not None) 404s here too, matching trigger_scan's own
    deleted_at=None filter - a caller must not be able to keep pulling
    reports for an Asset that was "deleted" through the web UI."""
    s = Scan.query.get_or_404(scan_id)
    if s.asset_id is not None:
        if s.asset.deleted_at is not None:
            abort(404)
        _check_asset_access(s.asset)
    else:
        _check_ownership(s)

    if s.report is None:
        return jsonify(error="report not available"), 404

    # WR-02: a missing/corrupt report (Report.data first, on-disk file only
    # as a fallback for rows saved before that column existed - see
    # Report's docstring in models.py) must still return JSON, not fall
    # through to the app's global @app.errorhandler(500) which renders an
    # HTML 500.html page - that would break cli/wvs.py's
    # _raise_for_error_response, which always expects a JSON body.
    if s.report.data is not None:
        report = s.report.data
    else:
        report = read_report_file(s.report.json_path)
        if report is None:
            return jsonify(error="report file is unavailable"), 500

    return jsonify(report), 200


@api.route("/scans", methods=["GET", "POST"])
@api_login_required
@limiter.limit("30 per minute", key_func=_api_rate_limit_key)
def scans_collection():
    """Phase 18 (glassbox CLI): a URL-first way into the same engine
    Assets already use, for a caller (CI pipeline, ad-hoc `glassbox
    assess <url>`) that doesn't want to create a persistent Asset first.

    POST launches a standard/base scan against `target_url` - the exact
    same `_launch_base_scan()` the web UI's bulk-scan form calls (see its
    own docstring), so this is provably subject to the identical SSRF/
    ownership/tier gate, not a parallel reimplementation that could drift.
    Only the base scan type is exposed here (Advanced/Media/API each need
    additional form fields - credentials, media-download flags - that
    don't have an ad-hoc-URL shape yet; use the existing Asset+
    `POST /assets/<id>/scans` path for those, or the web UI).

    `authorized: true` is REQUIRED in the JSON body, not inferred - the
    same explicit per-submission confirmation every other scan-launching
    surface in this app requires (the web forms' checkbox, the API-03
    Asset-trigger path's Asset.authorized_at set once at Asset-creation
    time). A CLI/CI caller with no browser and no checkbox to tick must
    still make this affirmative, can't-miss-it.

    GET lists the caller's own scans (optionally `?target_url=` filtered),
    newest first - lets a caller resolve "the most recent scan for this
    URL" (glassbox readiness/verify's default) without an Asset to key
    off, mirroring list_assets' own scoping (session or solo, never
    another user's/org's scans)."""
    if request.method == "GET":
        query = Scan.query.filter_by(user_id=current_user.id)
        target_url = request.args.get("target_url")
        if target_url:
            query = query.filter_by(target_url=target_url)
        limit = min(int(request.args.get("limit", 20) or 20), 100)
        scans = query.order_by(Scan.created_at.desc()).limit(limit).all()
        return jsonify(scans=[_serialize_scan_summary(s) | {"target_url": s.target_url, "scan_type": s.scan_type}
                               for s in scans])

    body = request.get_json(silent=True) or {}
    target_url = (body.get("target_url") or "").strip()
    if not target_url:
        return jsonify(error="target_url is required"), 400
    if not body.get("authorized"):
        return jsonify(error="authorized must be true - confirm you own or have explicit "
                              "permission to test this domain"), 400

    tier = effective_tier(current_user)
    s, err, is_duplicate = _launch_base_scan(current_user, tier, target_url)
    if s is None:
        return jsonify(error=err), 400

    return jsonify(scan_id=s.id, status=s.status.value, duplicate=is_duplicate), 202


@api.route("/scans/<int:scan_id>/compare/<int:other_id>")
@api_login_required
@limiter.limit("60 per minute", key_func=_api_rate_limit_key)
def scans_compare(scan_id, other_id):
    """Phase 18: `glassbox verify`/`glassbox compare`'s backing endpoint -
    100% reuse of scan_routes.diff_reports(), the exact same Added/Removed/
    Changed/Unchanged diff the web UI's /scan/<id>/compare/<id> page
    already renders, just as JSON instead of HTML. Ownership-checked
    against both scans independently (same as the web route) so a caller
    can't use one scan they own to pivot into reading a report on a scan
    they don't."""
    a = Scan.query.get_or_404(scan_id)
    b = Scan.query.get_or_404(other_id)
    _check_ownership(a)
    _check_ownership(b)
    if a.report is None or b.report is None:
        return jsonify(error="one or both scans have no report yet"), 404

    report_a = _load_report_json(a)
    report_b = _load_report_json(b)
    if report_a is None or report_b is None:
        return jsonify(error="one or both reports are unavailable"), 500

    diff = diff_reports(report_a, report_b)
    return jsonify(
        scan_a=_serialize_scan_summary(a), scan_b=_serialize_scan_summary(b), diff=diff,
    )


@api.route("/scans/<int:scan_id>/gate")
@api_login_required
@limiter.limit("60 per minute", key_func=_api_rate_limit_key)
def scans_gate(scan_id):
    """Security Gate: evaluate a completed scan's findings against a
    `?fail_on=` severity threshold and return a pass/fail verdict - the
    single server-side implementation `glassbox gate` (cli/wvs.py) and any
    direct HTTP CI consumer share, so the blocking rule is defined exactly
    once (webvulnscanner/security_gate.py's evaluate_gate).

    Read-only and derived on demand - nothing is persisted; the verdict is
    recomputed from the stored Report JSON on every call.

    Ownership branches exactly like fetch_report above (same Pitfall-1
    Asset-linked-vs-manual split, same WR-01 soft-delete guard) since a
    gate response embeds report-derived data (score/severity_counts), so it
    must be no easier to read than the report itself. The same two error
    branches apply too: no Report row yet -> 404 "report not available"
    (a still-running or failed scan has nothing to gate); Report row whose
    blob/file is unreadable -> 500 JSON (WR-02 - never the global HTML 500
    page, cli/wvs.py's _raise_for_error_response expects JSON)."""
    s = Scan.query.get_or_404(scan_id)
    if s.asset_id is not None:
        if s.asset.deleted_at is not None:
            abort(404)
        _check_asset_access(s.asset)
    else:
        _check_ownership(s)

    if s.report is None:
        return jsonify(error="report not available"), 404

    fail_on = request.args.get("fail_on", DEFAULT_FAIL_ON)
    if fail_on not in GATE_SEVERITIES:
        return jsonify(
            error=f"invalid fail_on {fail_on!r} - must be one of: {', '.join(GATE_SEVERITIES)}"
        ), 400

    report = _load_report_json(s)
    if report is None:
        return jsonify(error="report file is unavailable"), 500

    gate = evaluate_gate(report.get("findings") or [], fail_on=fail_on)
    return jsonify(gate | {
        "scan_id": s.id,
        "scan_status": s.status.value,
        "target_url": s.target_url,
        "score": report.get("score"),
        "risk_grade": report.get("risk_grade"),
        "severity_counts": report.get("severity_counts"),
    }), 200
