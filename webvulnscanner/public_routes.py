"""
Blueprint `public`: "/" marketing page. No auth required.

Not assigned to a specific plan workstream by name, but built alongside
scan_routes.py since this is the workstream where "/" stops being the old
single-file app's scan-trigger page (index.html) and becomes a real
marketing landing page with Sign up / Log in CTAs.
"""
from flask import Blueprint, Response, current_app, jsonify, render_template, url_for

from webvulnscanner.extensions import db

public = Blueprint("public", __name__)


@public.route("/")
def index():
    return render_template("marketing.html")


@public.route("/terms")
def terms():
    return render_template("terms.html")


@public.route("/privacy")
def privacy():
    return render_template("privacy.html")


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


@public.route("/robots.txt")
def robots_txt():
    """Built from current_app.url_map at request time, never a static file
    or a hand-maintained list (SEO-02, D-01 in 09-CONTEXT.md) - a future
    authenticated route added to an existing blueprint (or a brand-new
    blueprint) is automatically Disallowed the moment it's registered,
    since the prefix is derived from the rule's own path rather than a
    second list someone has to remember to keep in sync.

    Only the `public` blueprint's routes (and Flask's built-in `static`
    endpoint) are ever allowed - every other blueprint's routes are
    Disallowed by their first path segment.
    """
    disallow_prefixes = set()
    for rule in current_app.url_map.iter_rules():
        blueprint = rule.endpoint.split(".", 1)[0]
        if blueprint in ("public", "static"):
            continue
        segment = rule.rule.strip("/").split("/")[0]
        if not segment:
            continue
        disallow_prefixes.add("/" + segment)

    lines = ["User-agent: *", "Allow: /"]
    for prefix in sorted(disallow_prefixes):
        lines.append(f"Disallow: {prefix}")
    lines.append(f"Sitemap: {url_for('public.sitemap_xml', _external=True)}")

    body = "\n".join(lines) + "\n"
    return Response(body, mimetype="text/plain")


@public.route("/sitemap.xml")
def sitemap_xml():
    """Built from current_app.url_map at request time - lists exactly the
    `public` blueprint's parameter-free GET routes, excluding /healthz and
    robots.txt/sitemap.xml themselves - none of those three are pages meant
    for a search-result listing (SEO-03). Never includes a
    dashboard/scan/report/org/billing/admin/account/asset/token URL, since
    only endpoints starting with "public." are ever considered."""
    non_page_endpoints = {"public.healthz", "public.robots_txt", "public.sitemap_xml"}
    locs = []
    for rule in current_app.url_map.iter_rules():
        if not rule.endpoint.startswith("public."):
            continue
        if rule.endpoint in non_page_endpoints:
            continue
        if "GET" not in (rule.methods or set()):
            continue
        if "<" in rule.rule:
            continue
        locs.append(url_for(rule.endpoint, _external=True))

    urls = "".join(f"<url><loc>{loc}</loc></url>" for loc in sorted(locs))
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"{urls}"
        "</urlset>"
    )
    return Response(body, mimetype="application/xml")
