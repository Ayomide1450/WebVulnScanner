"""Phase 20 / INTR-01..10 coverage locks.

Ten new intrusive-but-non-destructive check families. This module locks:

1. The tier matrix (criterion 3): reflection probes = PAID, bursts/forgery
   probes = ORG_VERIFIED - exactly, not "at least".
2. Named cap constants (criterion 1) - the values themselves are load-
   bearing promises to targets.
3. Per-check behavior against in-memory fake sessions: confirmation rules
   (computed-result SSTI, passwd-signature traversal, OUR OWN CRLF header),
   stop-on-first-hit discipline, GET-only rate-limit burst, alg:none
   acceptance requiring baseline-match AND garbage-control mismatch,
   DNS-only takeover logic, read-only GraphQL probing.
4. check_csrf_posture performs ZERO network requests (pure data).

Network-free throughout.
"""

import base64
import json
from types import SimpleNamespace

import pytest
import requests

from glassbox import checks
from glassbox.entitlements import FEATURE_REQUIREMENTS, Tier

# --------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------

class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class FakeSession:
    def __init__(self):
        self.get_calls = []
        self.post_calls = []

    def get(self, url, timeout=None, **kwargs):
        self.get_calls.append((url, kwargs))
        return self._get(url, kwargs)

    def post(self, url, timeout=None, **kwargs):
        self.post_calls.append((url, kwargs))
        return self._post(url, kwargs)

    def _get(self, url, kwargs):
        return FakeResp("")

    def _post(self, url, kwargs):
        return FakeResp("")


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(checks.time, "sleep", lambda *_: None)


URL = "http://t.test/page?q=abc"


def _make_token():
    """A structurally real JWT (HS256 header, some claims, dummy sig)."""
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg({'sub': '1', 'exp': 9999999999})}.c2ln"


# --------------------------------------------------------------------------
# Tier matrix + caps (criteria 1 and 3)
# --------------------------------------------------------------------------

PHASE20_PAID = ["ssti", "host_header", "cache_deception", "crlf",
                "csrf_posture", "subdomain_takeover"]
PHASE20_ORG = ["path_traversal", "rate_limit", "jwt_active", "graphql_deep"]


def test_phase20_tier_matrix_exact():
    for name in PHASE20_PAID:
        assert name in FEATURE_REQUIREMENTS
        assert FEATURE_REQUIREMENTS[name] is Tier.PAID, name
    for name in PHASE20_ORG:
        assert name in FEATURE_REQUIREMENTS
        assert FEATURE_REQUIREMENTS[name] is Tier.ORG_VERIFIED, name


def test_labels_and_categories_cover_every_phase20_check():
    for name in PHASE20_PAID + PHASE20_ORG:
        assert name in checks.CHECK_LABELS, name
        assert name in checks.CHECK_CATEGORY, name


@pytest.mark.parametrize("const,value", [
    ("MAX_SSTI_PROBE_PARAMS", 8),
    ("RATE_LIMIT_BURST", 15),
    ("MAX_TRAVERSAL_URLS", 6),
    ("MAX_CRLF_PROBE_PARAMS", 6),
    ("MAX_TAKEOVER_SUBDOMAINS", 8),
])
def test_named_cap_constants_hold_the_promised_values(const, value):
    assert getattr(checks, const) == value


# --------------------------------------------------------------------------
# INTR-01 SSTI
# --------------------------------------------------------------------------

class SstiEchoSession(FakeSession):
    def _get(self, url, kwargs):
        return FakeResp(text=url)  # echoes the raw payload, never computes it


def test_ssti_confirms_only_on_computed_result():
    class ComputedSession(FakeSession):
        def _get(self, url, kwargs):
            # Only the arithmetic RESULT counts as proof - reflect it.
            return FakeResp(text="price is 6776 total")
    tested, findings = checks.check_ssti([URL], ComputedSession())
    assert any(f.category == "SSTI" and f.severity == "critical" for f in findings)


def test_ssti_payload_echo_without_computation_is_not_a_finding():
    tested, findings = checks.check_ssti([URL], SstiEchoSession())  # echoes raw payload
    assert findings == []
    assert tested[0]["result"] == "pass"


def test_ssti_stops_at_first_confirmation():
    calls = []

    class CountingSession(FakeSession):
        def _get(self, url, kwargs):
            calls.append(url)
            return FakeResp(text="6776")
    checks.check_ssti([URL], CountingSession())
    assert len(calls) == 1  # first jinja2 payload confirmed -> immediate stop


# --------------------------------------------------------------------------
# INTR-02 Host header
# --------------------------------------------------------------------------

def test_host_header_flags_body_reflection():
    class EchoHost(FakeSession):
        def _get(self, url, kwargs):
            sent = list(kwargs["headers"].values())[0]
            return FakeResp(text=f"hello {sent}")
    rows, findings = checks.check_host_header("http://t.test", EchoHost())
    assert any(f.severity == "high" for f in findings)
    assert all(r["reflected"] for r in rows)


def test_host_header_clean_site_has_no_finding():
    rows, findings = checks.check_host_header("http://t.test", FakeSession())
    assert findings == []


# --------------------------------------------------------------------------
# INTR-03 Cache deception surface
# --------------------------------------------------------------------------

def test_cache_deception_reports_only_with_hit_markers():
    class Cached(FakeSession):
        def _get(self, url, kwargs):
            if url.endswith(".css"):
                return FakeResp(status_code=200, headers={"Age": "120", "X-Cache": "HIT"})
            return FakeResp(text="home")
    rows, findings = checks.check_cache_deception("http://t.test", Cached())
    assert findings and findings[0].severity == "low"

    class Uncached(FakeSession):
        def _get(self, url, kwargs):
            return FakeResp(text="x")
    _, findings2 = checks.check_cache_deception("http://t.test", Uncached())
    assert findings2 == []


# --------------------------------------------------------------------------
# INTR-04 Path traversal
# --------------------------------------------------------------------------

def test_path_traversal_confirms_via_passwd_signature_and_stops():
    calls = []

    class Vuln(FakeSession):
        def _get(self, url, kwargs):
            calls.append(url)
            return FakeResp(text="daemon:x:1:1\nroot:x:0:0:root:/root:/bin/bash")
    urls = [f"http://t.test/d?file=a{i}" for i in range(4)]
    tested, findings = checks.check_path_traversal(urls, Vuln())
    assert any(f.category == "Path Traversal" for f in findings)
    assert len(calls) == 1, "must stop at first confirmed read"
    assert "file" in calls[0]  # probed the file-hinted param


def test_path_traversal_ignores_unhinted_params():
    tested, findings = checks.check_path_traversal(
        ["http://t.test/d?q=abc"], FakeSession())
    assert findings == []
    assert tested == []  # never even sent - param name lacks file hints


# --------------------------------------------------------------------------
# INTR-05 Rate limiting posture
# --------------------------------------------------------------------------

def test_rate_limit_burst_is_get_only_and_capped():
    session = FakeSession()  # everything 200s
    data, findings = checks.check_rate_limit_posture("http://t.test", session)
    assert len(data["statuses"]) == checks.RATE_LIMIT_BURST
    assert findings, "no throttle signal at all must be reported"
    assert session.post_calls == []  # GET-only burst - never submits anything


def test_rate_limit_stops_at_first_429_and_reports_nothing():
    class Throttles(FakeSession):
        def __init__(self):
            super().__init__()
            self.n = 0
        def _get(self, url, kwargs):
            self.n += 1
            return FakeResp(status_code=429 if self.n >= 3 else 200)
    data, findings = checks.check_rate_limit_posture("http://t.test", Throttles())
    assert data["throttled"] is True
    # The candidate-probe consumed one counter tick, so the burst itself saw
    # 200 then 429 - the point is it STOPPED well before the cap.
    assert len(data["statuses"]) < checks.RATE_LIMIT_BURST
    assert data["statuses"][-1] == 429
    assert findings == []


# --------------------------------------------------------------------------
# INTR-06 JWT active acceptance
# --------------------------------------------------------------------------

class JwtSession(FakeSession):
    """Jar-backed so check_jwt_active's evict/restore cycle runs against the
    same RequestsCookieJar API a live scan session exposes."""

    def __init__(self, responses):
        super().__init__()
        from requests.cookies import RequestsCookieJar

        self.responses = list(responses)
        self.cookies = RequestsCookieJar()
        self.cookies.set("auth_token", _make_token(), domain="t.test", path="/")

    def _get(self, url, kwargs):
        # Simulate sites that rotate their JWT cookie on every response -
        # the exact behavior that originally poisoned the scan session's
        # jar between replay variants (live-fire finding).
        self.cookies.set("auth_token", _make_token(), domain="t.test", path="/")
        return self.responses.pop(0)


def test_jwt_active_flags_none_alg_acceptance():
    ok = FakeResp(status_code=200, text="x" * 500)
    session = JwtSession([ok, FakeResp(status_code=200, text="y" * 505), FakeResp(status_code=401)])
    data, findings = checks.check_jwt_active(session, "http://t.test", "")
    assert data["tested"] is True
    assert any(f.category == "JWT Forgery" for f in findings)
    # Restore contract: the genuine token must be back in the jar afterwards.
    assert any(c.name == "auth_token" for c in session.cookies)


def test_jwt_active_sends_exactly_one_cookie_per_variant_over_the_wire():
    """Live-fire regression: with the genuine token sitting in the session
    jar AND a rotating site, replays must carry EXACTLY ONE auth_token
    cookie - the forged/garbage variant - never a duplicate pair where the
    jar's valid copy satisfies the server and silences the control."""
    import http.server
    import threading

    seen = []

    class Echo(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Cookie", ""))
            body = b"r" * 100
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        real = requests.Session()
        real.cookies.set("auth_token", _make_token(), domain="127.0.0.1", path="/")
        data, findings = checks.check_jwt_active(
            real, f"http://127.0.0.1:{port}", "")
    finally:
        server.shutdown()

    assert len(seen) == 3
    for wire in seen:
        assert wire.count("auth_token=") == 1, f"duplicate cookie sent: {wire!r}"
    assert seen[2].endswith("AAAAgarbageAAAA")


def test_jwt_active_requires_control_to_differ():
    # ALL three variants behave identically -> nothing provable, no finding.
    same = FakeResp(status_code=302, text="r" * 10)
    session = JwtSession([same, same, same])
    data, findings = checks.check_jwt_active(session, "http://t.test", "")
    assert findings == []


def test_jwt_active_skips_when_no_token_visible():
    data, findings = checks.check_jwt_active(FakeSession(), "http://t.test", "<html></html>")
    assert data["tested"] is False
    assert findings == []


# --------------------------------------------------------------------------
# INTR-07 CRLF injection
# --------------------------------------------------------------------------

def test_crlf_detects_own_canary_header_and_encodes_once():
    class Splitter(FakeSession):
        def __init__(self):
            super().__init__()
            self.urls = []
        def _get(self, url, kwargs):
            self.urls.append(url)
            return FakeResp(headers={"X-Glassbox-Crlf": "1"})
    s = Splitter()
    tested, findings = checks.check_crlf_injection([URL], s)
    assert any(f.category == "CRLF Injection" for f in findings)
    # Exactly-once encoding: %0d%0a present, double-encoded %250d absent.
    joined = " ".join(s.urls).lower()
    assert "%0d%0a" in joined
    assert "%250d" not in joined


def test_crlf_clean_response_is_pass():
    tested, findings = checks.check_crlf_injection([URL], FakeSession())
    assert findings == []
    assert tested[0]["result"] == "pass"


# --------------------------------------------------------------------------
# INTR-08 CSRF posture - zero network by contract
# --------------------------------------------------------------------------

def test_csrf_posture_makes_zero_requests_and_flags_tokenless_post_forms():
    forms = [
        {"action": "/login", "method": "POST", "inputs": ["email", "password"]},
        {"action": "/safe", "method": "POST", "inputs": ["x", "csrfmiddlewaretoken"]},
        {"action": "/search", "method": "GET", "inputs": ["q"]},  # GET ignored
    ]
    session = FakeSession()
    rows, findings = checks.check_csrf_posture(forms)
    assert session.get_calls == [] and session.post_calls == []
    assert len(rows) == 2  # only POST forms assessed
    assert len(findings) == 1 and findings[0].severity == "medium"


def test_csrf_posture_clean_forms_produce_no_finding():
    forms = [{"action": "/f", "method": "POST", "inputs": ["a", "_csrf"]}]
    _, findings = checks.check_csrf_posture(forms)
    assert findings == []


# --------------------------------------------------------------------------
# INTR-09 Subdomain takeover (DNS-only)
# --------------------------------------------------------------------------

class _Ans(list):
    pass


def test_takeover_flags_dangling_fingerprint(monkeypatch):
    import dns.resolver as dr

    def fake_resolve(name, rtype):
        if rtype == "CNAME":
            return _Ans([SimpleNamespace(target=name.replace(".t.test", "") +
                                        ".github.io." if name.startswith("www") else "elsewhere.example.")])
        raise dr.NXDOMAIN  # every A lookup fails

    monkeypatch.setattr(checks.dns.resolver, "resolve", fake_resolve)
    rows_data, findings = checks.check_subdomain_takeover("t.test")
    assert any(f.category == "Subdomain Takeover" and "GitHub Pages" in f.title for f in findings)


def test_takeover_live_target_is_not_flagged(monkeypatch):

    state = {"cname_done": False}

    def fake_resolve(name, rtype):
        if rtype == "CNAME":
            state["cname_done"] = True
            return _Ans([SimpleNamespace(target="live-site.github.io.")])
        return _Ans(["93.184.216.34"])  # A record resolves fine

    monkeypatch.setattr(checks.dns.resolver, "resolve", fake_resolve)
    rows_data, findings = checks.check_subdomain_takeover("t.test")
    assert findings == []


# --------------------------------------------------------------------------
# INTR-10 GraphQL deep probe
# --------------------------------------------------------------------------

def test_graphql_introspection_enabled_is_reported_readonly():
    class Gql(FakeSession):
        def _post(self, url, kwargs):
            body = kwargs["data"]
            if "__schema" in body:
                return FakeResp(text='{"data":{"__schema":{"queryType":{"name":"Query"}}}}')
            return FakeResp(text='{"errors":[{"message":"Cannot query field. Did you mean \\"user\\"?"}]}')
    s = Gql()
    rows, findings = checks.check_graphql_deep("http://t.test", s)
    assert any(f.severity == "medium" and "introspection" in f.title.lower() for f in findings)
    assert any(f.severity == "low" and "suggest" in f.title.lower() for f in findings)
    # Read-only contract: both bodies are queries, never mutations.
    for _url, kw in s.post_calls:
        assert "mutation" not in kw["data"].lower()


def test_graphql_introspection_off_still_checks_suggestions():
    class GqlOff(FakeSession):
        def _post(self, url, kwargs):
            body = kwargs["data"]
            if "__schema" in body:
                return FakeResp(text='{"errors":[{"message":"introspection is disabled"}]}')
            return FakeResp(text='{"errors":[{"message":"Did you mean \\"user?\\""}]}')
    rows, findings = checks.check_graphql_deep("http://t.test", GqlOff())
    assert not any("enabled" in f.title.lower() for f in findings)
    assert any("suggest" in f.title.lower() for f in findings)
