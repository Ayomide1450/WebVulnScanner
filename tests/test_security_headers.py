"""Glassbox's own security response headers.

`checks.py`'s SECURITY_HEADERS table grades every *scanned* site on six
headers and rates two of them "high" - and until 2026-10-25 Glassbox sent
none of them itself. A self-scan would have failed its own audit six times
over, and the app genuinely was framable with no browser-enforced
containment for an XSS.

These tests lock that fix in. The CSP assertions in particular are the
guardrail against the easy regression: someone hits a blocked inline
script and "fixes" it by adding 'unsafe-inline', which would make the
whole header decorative.
"""
import re

SECURITY_HEADER_PATHS = ["/", "/login", "/signup"]


def _csp(resp):
    return resp.headers.get("Content-Security-Policy", "")


# --------------------------------------------------------------------------
# Presence
# --------------------------------------------------------------------------


def test_core_security_headers_present_on_public_pages(client):
    for path in SECURITY_HEADER_PATHS:
        r = client.get(path)
        assert r.status_code == 200, path
        assert _csp(r), f"no CSP on {path}"
        assert r.headers.get("X-Frame-Options") == "DENY", path
        assert r.headers.get("X-Content-Type-Options") == "nosniff", path
        assert r.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin", path
        assert r.headers.get("Cross-Origin-Opener-Policy") == "same-origin", path
        assert r.headers.get("X-Permitted-Cross-Domain-Policies") == "none", path
        assert "geolocation=()" in r.headers.get("Permissions-Policy", ""), path


def test_security_headers_also_set_on_error_pages(client):
    """A 404 is still an attacker-reachable HTML response."""
    r = client.get("/this-route-does-not-exist")
    assert r.status_code == 404
    assert _csp(r)
    assert r.headers.get("X-Frame-Options") == "DENY"


# --------------------------------------------------------------------------
# CSP strength - the assertions that matter
# --------------------------------------------------------------------------


def test_csp_never_allows_unsafe_inline_or_eval_for_scripts(client):
    """script-src must stay nonce-based.

    style-src-attr deliberately keeps 'unsafe-inline' (151 inline style=
    attributes across the templates cannot carry a nonce), so this test
    checks the script directive specifically rather than the whole policy.
    """
    csp = _csp(client.get("/login"))
    script_src = next(
        (d for d in csp.split(";") if d.strip().startswith("script-src")), ""
    )
    assert script_src, "no script-src directive"
    assert "'unsafe-inline'" not in script_src
    assert "'unsafe-eval'" not in script_src
    assert "'nonce-" in script_src


def test_csp_locks_down_the_dangerous_directives(client):
    csp = _csp(client.get("/login"))
    for directive in [
        "default-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]:
        assert directive in csp, directive


def test_csp_nonce_is_fresh_per_request_and_matches_the_body(client):
    """A reused nonce is as good as 'unsafe-inline' to an attacker who can
    read one response."""
    first = client.get("/login")
    body = first.get_data(as_text=True)
    nonces = set(re.findall(r'nonce="([^"]+)"', body))
    assert nonces, "no nonce stamped into the rendered page"
    assert len(nonces) == 1, f"expected one nonce per page, got {nonces}"

    (nonce,) = nonces
    assert f"'nonce-{nonce}'" in _csp(first), "body nonce absent from the CSP header"
    assert len(nonce) >= 16, "nonce too short to be unguessable"

    second_nonces = set(
        re.findall(r'nonce="([^"]+)"', client.get("/login").get_data(as_text=True))
    )
    assert nonces.isdisjoint(second_nonces), "nonce reused across requests"


def test_every_inline_script_and_style_tag_carries_the_nonce(client):
    """An un-nonced inline tag is dead code under this policy - it renders
    but the browser refuses to run it, which is easy to miss by eye."""
    for path in SECURITY_HEADER_PATHS:
        body = client.get(path).get_data(as_text=True)
        # Strip comments first: base.html's own CSS comments mention the
        # words "script"/"style" and would otherwise match.
        stripped = re.sub(r"<!--.*?-->", "", body, flags=re.S)
        stripped = re.sub(r"/\*.*?\*/", "", stripped, flags=re.S)
        offenders = re.findall(
            r"<(?:script|style)(?![^>]*(?:nonce=|src=))[^>]*>", stripped
        )
        assert not offenders, f"{path}: inline tag(s) without a nonce: {offenders}"


def test_turnstile_is_the_only_allowlisted_third_party(client):
    """signup.html loads Cloudflare Turnstile's api.js and the widget runs
    in a Cloudflare-hosted iframe, so it needs script-src and frame-src.
    Everything else must stay 'self' - the fonts were self-hosted in the
    same release specifically to stop leaking visitor IPs to Google."""
    csp = _csp(client.get("/signup"))
    assert "https://challenges.cloudflare.com" in csp

    external = set(re.findall(r"https://[^\s;]+", csp))
    assert external == {"https://challenges.cloudflare.com"}, (
        f"unexpected third-party origin(s) in CSP: {external}"
    )
    assert "fonts.googleapis.com" not in csp
    assert "fonts.gstatic.com" not in csp


# --------------------------------------------------------------------------
# HSTS is conditional on actually being over TLS
# --------------------------------------------------------------------------


def test_hsts_absent_over_plain_http(client):
    """Sending HSTS over http is ignored by browsers, and sending it in
    local dev would pin localhost to https in the developer's browser -
    a genuinely painful footgun to undo."""
    assert "Strict-Transport-Security" not in client.get("/login").headers


def test_hsts_present_over_https(app, client):
    app.config["SESSION_COOKIE_SECURE"] = True
    r = client.get("/login", base_url="https://localhost")
    hsts = r.headers.get("Strict-Transport-Security", "")
    assert "max-age=31536000" in hsts
    assert "includeSubDomains" in hsts
