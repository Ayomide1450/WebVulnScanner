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

import pytest

from tests.conftest import login, make_org, make_user

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

    # Every SINGLE rule belonging to a non-public/non-static blueprint must
    # be covered by a Disallow: line that is a literal prefix of its path -
    # not merely "one sample rule per blueprint", since a blueprint with no
    # url_prefix (auth, scan) can have several distinct first-path-segments
    # of its own (e.g. auth's /login vs /signup vs /forgot-password each
    # produce their own Disallow line).
    with app.app_context():
        disallowed_rules = [
            r for r in app.url_map.iter_rules()
            if r.endpoint.split(".", 1)[0] not in ("public", "static")
        ]
    assert disallowed_rules
    for rule in disallowed_rules:
        segment = rule.rule.strip("/").split("/")[0]
        assert segment, rule.rule
        assert f"Disallow: /{segment}" in body, (
            f"{rule.endpoint} ({rule.rule}) has no matching Disallow: line"
        )


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


# ---------------------------------------------------------------------------
# Task 3: public-page meta tags (positive) + authenticated-page absence (negative)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/", "/terms", "/privacy"])
def test_public_pages_render_full_seo_tag_set(client, path):
    resp = client.get(path)
    html = resp.get_data(as_text=True)

    # meta description, 150-160 chars
    match_start = html.find('<meta name="description" content="')
    assert match_start != -1, path
    content_start = match_start + len('<meta name="description" content="')
    content_end = html.find('"', content_start)
    description = html[content_start:content_end]
    assert 150 <= len(description) <= 160, (path, len(description), description)

    assert '<link rel="canonical"' in html
    assert 'property="og:title"' in html
    assert 'property="og:description"' in html
    assert 'property="og:image"' in html
    assert 'property="og:url"' in html
    assert 'name="twitter:card"' in html
    assert 'name="twitter:title"' in html
    assert 'name="twitter:description"' in html
    assert 'name="twitter:image"' in html


def test_authenticated_pages_render_none_of_the_seo_tags(client, db):
    org = make_org()
    user = make_user("seo-negative-test@example.com", org=org)
    login(client, user.email)

    forbidden_markers = (
        '<meta name="description"',
        '<link rel="canonical"',
        'property="og:',
        'name="twitter:',
    )

    for path in ("/dashboard", "/scan/new/base", "/account/billing"):
        resp = client.get(path)
        html = resp.get_data(as_text=True)
        for marker in forbidden_markers:
            assert marker not in html, (path, marker)
