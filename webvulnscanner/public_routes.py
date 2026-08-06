"""
Blueprint `public`: "/" marketing page. No auth required.

Not assigned to a specific plan workstream by name, but built alongside
scan_routes.py since this is the workstream where "/" stops being the old
single-file app's scan-trigger page (index.html) and becomes a real
marketing landing page with Sign up / Log in CTAs.
"""
from flask import Blueprint, render_template

public = Blueprint("public", __name__)


@public.route("/")
def index():
    return render_template("marketing.html")
