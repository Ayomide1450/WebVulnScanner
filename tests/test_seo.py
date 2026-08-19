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
