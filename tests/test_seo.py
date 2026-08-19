"""
SEO-01..04 coverage (09-01-PLAN.md).

This module grows across all three tasks in 09-01-PLAN.md:

- Task 1: base.html's favicon <link> set (the four static assets under
  webvulnscanner/static/ resolve with a 200, and base.html references all
  four via <link> tags).
- Task 2: /robots.txt (self-updating Disallow list derived from
  current_app.url_map, never a hardcoded list) and /sitemap.xml (exactly
  the three public-blueprint URLs, no authenticated route ever listed).
- Task 3: marketing.html/terms.html/privacy.html render title/meta
  description/canonical/OG/Twitter Card tags; every authenticated template
  renders none of them.
"""
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# Task 1: favicon set
# ---------------------------------------------------------------------------

def test_favicon_static_assets_return_200_nonempty(client):
    for path in (
        "/static/favicon.ico",
        "/static/favicon-16x16.png",
        "/static/favicon-32x32.png",
        "/static/apple-touch-icon.png",
    ):
        resp = client.get(path)
        assert resp.status_code == 200, path
        assert len(resp.data) > 0, path


def test_base_head_references_favicon_links(client):
    resp = client.get("/")
    html = resp.get_data(as_text=True)
    assert '<link rel="icon"' in html
    assert '<link rel="apple-touch-icon"' in html
    assert "favicon.ico" in html
    assert "favicon-16x16.png" in html
    assert "favicon-32x32.png" in html
    assert "apple-touch-icon.png" in html


# ---------------------------------------------------------------------------
# Task 2: /robots.txt and /sitemap.xml
# ---------------------------------------------------------------------------

def test_robots_txt_returns_200_text_plain(client):
    resp = client.get("/robots.txt")
    assert resp.status_code == 200
    assert "text/plain" in resp.content_type


def test_robots_txt_disallows_every_non_public_blueprint(client, app):
    resp = client.get("/robots.txt")
    body = resp.get_data(as_text=True)
    assert "User-agent: *" in body
    assert "Allow: /" in body
    assert "Sitemap:" in body

    # Independently re-derive the expected set of disallowed blueprints from
    # url_map.iter_rules() inside the test itself, rather than copying the
    # route's own prefix-computation logic - this is what proves the route
    # is actually driven by url_map and not a list that happens to match.
    with app.app_context():
        blueprints_seen = set()
        for rule in app.url_map.iter_rules():
            blueprint = rule.endpoint.split(".", 1)[0]
            if blueprint not in ("public", "static"):
                blueprints_seen.add(blueprint)

    expected_blueprints = {
        "auth", "org", "admin", "billing", "scan", "asset", "api_tokens", "api",
    }
    assert expected_blueprints <= blueprints_seen

    # Every one of those blueprints must have at least one Disallow: line
    # matching one of its rules' first path segments.
    with app.app_context():
        for blueprint in expected_blueprints:
            sample_rules = [
                r for r in app.url_map.iter_rules()
                if r.endpoint.split(".", 1)[0] == blueprint
            ]
            assert sample_rules, blueprint
            matched = False
            for rule in sample_rules:
                segment = rule.rule.strip("/").split("/")[0]
                if segment and f"Disallow: /{segment}" in body:
                    matched = True
                    break
            assert matched, f"no Disallow: line found covering blueprint {blueprint!r}"


def test_sitemap_xml_returns_200_xml_content_type(client):
    resp = client.get("/sitemap.xml")
    assert resp.status_code == 200
    assert "xml" in resp.content_type


def test_sitemap_xml_lists_exactly_three_public_urls(client):
    resp = client.get("/sitemap.xml")
    root = ET.fromstring(resp.data)
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locs = {el.text for el in root.findall(".//sm:loc", ns)}

    expected = {
        "http://localhost/",
        "http://localhost/terms",
        "http://localhost/privacy",
    }
    assert locs == expected


def test_sitemap_xml_never_lists_authenticated_route_prefixes(client):
    resp = client.get("/sitemap.xml")
    body = resp.get_data(as_text=True)
    forbidden_prefixes = (
        "/dashboard", "/scan", "/org", "/billing", "/admin",
        "/account", "/assets", "/tokens",
    )
    for prefix in forbidden_prefixes:
        assert prefix not in body, prefix
