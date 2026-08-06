"""
Blueprint `public`: "/" marketing page. No auth required.

Not assigned to a specific plan workstream by name, but built alongside
scan_routes.py since this is the workstream where "/" stops being the old
single-file app's scan-trigger page (index.html) and becomes a real
marketing landing page with Sign up / Log in CTAs.
"""
from flask import Blueprint, jsonify, render_template

from webvulnscanner.extensions import db

public = Blueprint("public", __name__)


@public.route("/")
def index():
    return render_template("marketing.html")


@public.route("/healthz")
def healthz():
    """Liveness + DB-connectivity check for Render's healthCheckPath and
    UptimeRobot - unauthenticated on purpose (a load balancer/uptime monitor
    can't log in), returns only a boolean and no scan/user data."""
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify(status="ok"), 200
    except Exception as e:  # noqa: BLE001 - report the failure, don't crash the health check itself
        return jsonify(status="error", detail=str(e)), 503
