"""
Blueprint `api`: /api/v1.

Token-authenticated JSON surface (API-02..05, Phase 2). Every route here is
authenticated via login_manager.request_loader's Bearer-token lookup
(extensions.py), never via the session cookie's @login_required redirect
behavior - api_login_required (below) gives a JSON-appropriate 401 instead.

D-02: a token acts as the exact user who created it - every route below
reuses asset_routes._scoped_asset_query()/_check_asset_access() directly
rather than re-implementing org/solo scoping, so a token can never see more
than its creating user's session already could.
"""
from functools import wraps

from flask import Blueprint, jsonify
from flask_login import current_user

from webvulnscanner.asset_routes import _check_asset_access, _scoped_asset_query
from webvulnscanner.extensions import csrf, limiter
from webvulnscanner.models import Asset, Scan
from webvulnscanner.scheduler import _fire

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
    scheduler's own tick handles those same two failure branches."""
    a = Asset.query.get_or_404(asset_id)
    _check_asset_access(a)
    s = _fire(a)
    return jsonify(scan_id=s.id, status=s.status.value), 202
