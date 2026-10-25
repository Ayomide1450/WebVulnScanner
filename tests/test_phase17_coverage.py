"""Phase 17 / DEPTH-01..03 coverage locks.

Three things are locked here, per the phase's success criteria:

1. DEPTH-01: the approved crawl posture - depth-2 harvesting exists, is
   hard-capped (MAX_CRAWL_PAGES), same-origin + robots-honored, and merges
   BEHIND the hop-1 list so the probe budget never grows. The decision
   record lives in .planning/PHASE17-DEPTH-DECISION.md.
2. DEPTH-02: reflected XSS gained variant breadth (REFLECTED_XSS_VARIANTS,
   marker-only, no alert()) and boolean-blind SQLi picks its true/false pair
   by param context; SQL_ERROR_SIGNATURES grew by two engines.
3. DEPTH-03: source-arithmetic regression locks - if anyone adds probe
   variants without revisiting MAX_PROBE_REQUESTS_PER_URL, or shrinks a
   variant registry, these tests fail.

Network-free throughout: every test drives checks.py / scan_engine.py with
in-memory fake sessions.
"""

import re
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from glassbox import checks, scan_engine
from glassbox.entitlements import Tier

# --------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------

class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class FakeSession:
    """Serves canned pages per exact URL; records every GET. Anything
    unrequested comes back as a 404 empty page, like a polite dead origin."""

    def __init__(self, pages=None):
        self.pages = dict(pages or {})
        self.get_calls = []

    def get(self, url, timeout=None, **kwargs):
        self.get_calls.append(url)
        return self.pages.get(url, FakeResp("", 404))


class EchoSession(FakeSession):
    """Reflects the injected value of param `p` back verbatim into the HTML
    body - simulates a badly-escaped template for reflection tests."""

    def __init__(self, p="q"):
        super().__init__()
        self.p = p

    def get(self, url, timeout=None, **kwargs):
        self.get_calls.append(url)
        vals = parse_qs(urlparse(url).query).get(self.p, [])
        return FakeResp(text=f"<html>{vals[0] if vals else ''}</html>")


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(checks.time, "sleep", lambda *_: None)


def _injected_values(session, base_url, p):
    """Distinct values injected into query param `p` across all recorded
    GETs. Matches on scheme/netloc/path because _inject_param re-encodes the
    whole query string, so raw-prefix comparison never matches."""
    base = urlparse(base_url)
    seen = []
    for called in session.get_calls:
        c = urlparse(called)
        if (c.scheme, c.netloc, c.path) != (base.scheme, base.netloc, base.path):
            continue
        vals = parse_qs(c.query).get(p, [])
        if vals and vals[0] not in seen:
            seen.append(vals[0])
    return seen


# --------------------------------------------------------------------------
# DEPTH-02 / DEPTH-03: payload registries and the budget lock
# --------------------------------------------------------------------------

def test_reflected_xss_variants_registry_minimum_breadth():
    assert len(checks.REFLECTED_XSS_VARIANTS) >= 4
    names = [name for name, _ in checks.REFLECTED_XSS_VARIANTS]
    assert len(names) == len(set(names)), "variant names must be unique"
    for _, template in checks.REFLECTED_XSS_VARIANTS:
        payload = template.format(m=checks.XSS_MARKER)
        assert checks.XSS_MARKER in payload
        # Marker-only discipline: no execution attempt, same style as
        # check_xss_stored's proof.
        assert "alert(" not in payload


def test_sql_error_signatures_minimum_and_regex_validity():
    assert len(checks.SQL_ERROR_SIGNATURES) >= 14
    for sig in checks.SQL_ERROR_SIGNATURES:
        re.compile(sig)  # must not raise


def test_probe_budget_arithmetic_lock():
    # Worst case per parameter: one request per XSS variant + 1 error probe
    # + 2 boolean-blind requests. Adding variants without raising the cap
    # fails HERE first.
    worst_case = len(checks.REFLECTED_XSS_VARIANTS) + 1 + 2
    assert worst_case <= checks.MAX_PROBE_REQUESTS_PER_URL
    assert checks.MAX_PROBE_REQUESTS_PER_URL == 12


def test_depth2_page_cap_constant_matches_decision_record():
    # .planning/PHASE17-DEPTH-DECISION.md binding cap #1.
    assert checks.MAX_CRAWL_PAGES == 15


def test_entitlements_registry_still_covers_the_probe_check():
    # No NEW check names were introduced in Phase 17, but lock the existing
    # mapping anyway - the variants ride inside xss_sqli's entitlement.
    assert "xss_sqli" in scan_engine.FEATURE_REQUIREMENTS


# --------------------------------------------------------------------------
# DEPTH-02: check_xss_sqli behavior
# --------------------------------------------------------------------------

STRING_URL = "http://t.test/page?q=abc"
NUMERIC_URL = "http://t.test/item?id=42"


def test_xss_sqli_sends_every_registered_variant_shape():
    session = EchoSession(p="q")
    tested, findings = checks.check_xss_sqli([STRING_URL], session)
    injected = _injected_values(session, STRING_URL, "q")
    for _, template in checks.REFLECTED_XSS_VARIANTS:
        expected = template.format(m=checks.XSS_MARKER)
        assert expected in injected, f"missing variant shape {expected!r}"
    # The echo server reflects every payload verbatim -> exactly one
    # confirmed XSS finding per registered variant, nothing else.
    assert len(findings) == len(checks.REFLECTED_XSS_VARIANTS)
    assert all(f.category == "XSS" and f.severity == "critical" for f in findings)
    assert tested[0]["xss"] == "fail"
    assert tested[0]["sqli"] == "pass"


def test_xss_sqli_request_budget_per_param_is_within_cap():
    session = EchoSession(p="q")
    checks.check_xss_sqli([STRING_URL], session)
    # Every request this check makes is a probe of the single param under
    # test, so the session total IS the per-param count.
    assert len(session.get_calls) <= checks.MAX_PROBE_REQUESTS_PER_URL
    # And exactly the documented arithmetic, no silent extras:
    assert len(session.get_calls) == len(checks.REFLECTED_XSS_VARIANTS) + 1 + 2


def test_xss_sqli_numeric_param_gets_unquoted_boolean_pair():
    session = EchoSession(p="id")
    checks.check_xss_sqli([NUMERIC_URL], session)
    injected = _injected_values(session, NUMERIC_URL, "id")
    assert "1 AND 1=1" in injected and "1 AND 1=2" in injected
    assert "1' AND '1'='1" not in "".join(injected)


def test_xss_sqli_string_param_keeps_quote_context_boolean_pair():
    session = EchoSession(p="q")
    checks.check_xss_sqli([STRING_URL], session)
    injected = _injected_values(session, STRING_URL, "q")
    assert "1' AND '1'='1" in injected and "1' AND '1'='2" in injected
    assert "1 AND 1=1" not in "".join(injected)


def test_xss_sqli_reflection_raises_finding_named_after_variant():
    session = EchoSession(p="q")
    tested, findings = checks.check_xss_sqli([STRING_URL], session)
    assert tested[0]["xss"] == "fail"
    titles = " | ".join(f.title for f in findings)
    for name, _ in checks.REFLECTED_XSS_VARIANTS:
        assert name in titles, f"{name} reflection produced no finding"


def test_xss_sqli_db_error_signature_still_wins_over_boolean_pair():
    class ErrorSigSession(FakeSession):
        def get(self, url, timeout=None, **kwargs):
            self.get_calls.append(url)
            return FakeResp(text="you have an error in your sql syntax near ''")

    session = ErrorSigSession()
    tested, findings = checks.check_xss_sqli([STRING_URL], session)
    assert tested[0]["sqli"] == "fail"
    assert any(f.category == "SQL Injection" for f in findings)
    # Boolean pair must NOT have been sent once the error signature matched.
    injected = _injected_values(session, STRING_URL, "q")
    assert "1' AND '1'='1" not in "".join(injected)
    assert "1 AND 1=1" not in "".join(injected)


# --------------------------------------------------------------------------
# DEPTH-01: crawl_depth2_param_urls caps and politeness
# --------------------------------------------------------------------------

T_BASE = "http://t.test"

ROBOTS = FakeResp("User-agent: *\nDisallow: /private\n", 200)


def _home(links):
    return f"<html>{''.join(f'<a href=\"{h}\">x</a>' for h in links)}</html>"


def test_depth2_harvests_param_urls_from_interior_pages():
    session = FakeSession({
        f"{T_BASE}/robots.txt": ROBOTS,
        f"{T_BASE}/about": FakeResp(
            '<html><a href="/products?item=7">p</a><a href="/contact">c</a></html>',
            headers={"Content-Type": "text/html"}),
    })
    found = checks.crawl_depth2_param_urls(
        session, T_BASE, _home(["/about", "/blog?page=2"]))
    assert found == [f"{T_BASE}/products?item=7"]
    # Only the /about seed was fetched (blog?page=2 already carries params,
    # so hop-1 owns it and hop-2 does not re-fetch it).
    assert session.get_calls == [f"{T_BASE}/robots.txt", f"{T_BASE}/about"]


def test_depth2_skips_cross_origin_robots_disallowed_and_asset_seeds():
    session = FakeSession({
        f"{T_BASE}/robots.txt": ROBOTS,
    })
    home = _home(["https://evil.test/x", "/private/panel", "/logo.png", "/ok"])
    found = checks.crawl_depth2_param_urls(session, T_BASE, home)
    assert found == []
    fetched_paths = [urlparse(c).path for c in session.get_calls]
    assert "/private/panel" not in fetched_paths, "robots Disallow ignored"
    assert all(not p.endswith(".png") for p in fetched_paths)
    # /ok WAS fetched (allowed interior seed) even though it yielded nothing.
    assert "/ok" in fetched_paths


def test_depth2_disallows_apply_to_harvested_links_too():
    session = FakeSession({
        f"{T_BASE}/robots.txt": ROBOTS,
        f"{T_BASE}/about": FakeResp(
            '<html><a href="/private/panel?token=1">x</a></html>',
            headers={"Content-Type": "text/html"}),
    })
    found = checks.crawl_depth2_param_urls(session, T_BASE, _home(["/about"]))
    assert found == [], "a robots-disallowed link must never be harvested"


def test_depth2_respects_max_pages_cap():
    links = [f"/p{i}" for i in range(10)]
    pages = {f"{T_BASE}/robots.txt": ROBOTS}
    for i in range(10):
        pages[f"{T_BASE}/p{i}"] = FakeResp(
            f'<html><a href="/found?i={i}">f</a></html>',
            headers={"Content-Type": "text/html"})
    session = FakeSession(pages)
    found = checks.crawl_depth2_param_urls(session, T_BASE, _home(links), max_pages=3)
    assert len(found) == 3
    fetched_seeds = [c for c in session.get_calls if "/p" in urlparse(c).path]
    assert len(fetched_seeds) == 3


def test_depth2_ignores_non_html_responses():
    session = FakeSession({
        f"{T_BASE}/robots.txt": ROBOTS,
        f"{T_BASE}/doc": FakeResp("<html><a href='/x?y=1'>l</a></html>",
                                  headers={"Content-Type": "application/pdf"}),
    })
    found = checks.crawl_depth2_param_urls(session, T_BASE, _home(["/doc"]))
    assert found == []


def test_depth2_never_posts_and_handles_dead_pages():
    session = FakeSession()  # everything 404s; no post attr exists at all
    found = checks.crawl_depth2_param_urls(session, T_BASE, _home(["/dead"]))
    assert found == []


def test_depth2_empty_home_html_is_noop():
    session = FakeSession()
    assert checks.crawl_depth2_param_urls(session, T_BASE, "") == []
    assert session.get_calls == []  # not even robots.txt


# --------------------------------------------------------------------------
# DEPTH-01: run_scan wiring - merge order, cap, and gating
# --------------------------------------------------------------------------

_STUB_CHECK_NAMES = [
    "check_cookies", "check_tls_cert", "check_https_redirect",
    "check_sensitive_paths", "check_robots_sitemap", "check_cors", "check_http_methods",
    "check_open_redirect", "check_directory_listing", "check_mixed_content",
    "check_dns_email_security", "check_vulnerable_js", "check_xss_sqli",
    "check_exposed_secrets", "check_sri", "check_jwt_weakness",
    "check_file_upload", "check_privacy_exposure", "check_caching_sensitive_data",
]


def _stub_run_scan_world(monkeypatch, hop1, depth2):
    fake_session = SimpleNamespace(get=lambda *a, **k: SimpleNamespace(text="<html></html>"))
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: fake_session)
    monkeypatch.setattr(scan_engine, "check_headers", lambda *a, **k: ({"grade": "A"}, []))
    monkeypatch.setattr(scan_engine, "check_open_ports", lambda *a, **k: ([], "1.2.3.4", []))
    captured = {}

    for name in _STUB_CHECK_NAMES:
        if name == "check_xss_sqli":
            monkeypatch.setattr(scan_engine, name,
                                lambda urls, session: captured.setdefault("urls", list(urls)) or ({}, []))
        else:
            monkeypatch.setattr(scan_engine, name, lambda *a, **k: ({}, []))

    monkeypatch.setattr(scan_engine, "crawl_same_origin", lambda *a, **k: (list(hop1), []))
    depth2_calls = []
    monkeypatch.setattr(scan_engine, "crawl_depth2_param_urls",
                        lambda *a, **k: depth2_calls.append(k) or list(depth2))
    return captured, depth2_calls


def test_run_scan_merges_depth2_behind_hop1_and_caps_at_ten(monkeypatch):
    hop1 = [f"http://t.test/a?x={i}" for i in range(8)]
    depth2 = [f"http://t.test/b?y={i}" for i in range(5)]  # 5 more, 13 total
    captured, _ = _stub_run_scan_world(monkeypatch, hop1, depth2)

    # ORG_VERIFIED tier + verified domain: the only combination where both
    # the hop-1 crawl and the depth-2 extension run.
    scan_engine.run_scan("http://t.test", None, Tier.ORG_VERIFIED, True)

    urls = captured["urls"]
    assert len(urls) == 10, "probe list cap must stay at 10"
    assert urls[:8] == hop1, "hop-1 links keep priority order"
    assert set(urls[8:]) <= set(depth2), "remaining slots filled from depth-2"


def test_run_scan_skips_depth2_without_domain_verification(monkeypatch):
    captured, depth2_calls = _stub_run_scan_world(
        monkeypatch, ["http://t.test/a?x=1"], ["http://t.test/b?y=1"])

    scan_engine.run_scan("http://t.test", None, Tier.ORG_VERIFIED, False)
    assert depth2_calls == [], "unverified domain: no depth-2 fetching"

    scan_engine.run_scan("http://t.test", None, Tier.FREE, True)
    assert depth2_calls == [], "FREE tier skips the whole crawl including depth-2"
