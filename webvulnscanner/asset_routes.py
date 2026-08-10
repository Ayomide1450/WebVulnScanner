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
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Blueprint, abort, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from webvulnscanner.checks import is_ssrf_safe_hostname, normalize_target
from webvulnscanner.extensions import db
from webvulnscanner.models import Asset

asset = Blueprint("asset", __name__, url_prefix="/assets")

CADENCE_CHOICES = ("daily", "weekly", "monthly")
SCHEDULE_SCAN_TYPE_CHOICES = ("base", "media", "api")


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
