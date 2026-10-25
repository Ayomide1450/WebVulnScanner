"""Unit tests for check_http_methods' false-positive fix.

Before this fix, any status code outside a small rejection set was reported
as "Confirmed" - including a plain 200 from a method-agnostic router/edge
that answers every HTTP verb identically, which is a very common, entirely
safe pattern (SPA fallback routes, some CDNs). This is the exact class of
"false alarm" issue flagged in review: check_http_methods had zero
behavioral test coverage before this file, so the bug shipped undetected.

Three scenarios are locked:
1. A genuinely dangerous method (explicitly listed in OPTIONS' Allow header,
   or - for TRACE - actually reflected in the response body) stays
   confidence="Confirmed".
2. A method-agnostic router (same status code as a plain GET to the same
   path, not listed in Allow, no TRACE reflection) is downgraded to
   confidence="Potential"/severity="info" - still surfaced, never silently
   dropped, but no longer overclaimed.
3. A rejection status code (404/405/etc.) produces no finding at all,
   unchanged from before.
"""
from glassbox.checks import check_http_methods

BASE = "https://example.com"


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class _FakeSession:
    """Stand-in for requests.Session - no HTTP-mocking dependency, per this
    repo's existing convention (see test_check_net_new.py's _FakeSession).
    `responses` maps method name -> _FakeResponse; GET (baseline) and
    OPTIONS are both routed through the same dict."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def request(self, method, url, headers=None, timeout=None, **kwargs):
        self.calls.append((method, url, headers))
        return self.responses.get(method, _FakeResponse(status_code=404))

    def get(self, url, timeout=None, **kwargs):
        self.calls.append(("GET", url, None))
        return self.responses.get("GET", _FakeResponse(status_code=404))


def test_method_agnostic_router_is_downgraded_not_confirmed():
    """PUT/DELETE/CONNECT all answer 200, identical to GET, and OPTIONS
    doesn't list them - the classic false-positive case this fix targets."""
    session = _FakeSession({
        "GET": _FakeResponse(200),
        "OPTIONS": _FakeResponse(200, headers={"Allow": "GET, HEAD"}),
        "PUT": _FakeResponse(200),
        "DELETE": _FakeResponse(200),
        "TRACE": _FakeResponse(200),
        "CONNECT": _FakeResponse(200),
    })
    _, findings = check_http_methods(BASE, session)
    assert len(findings) == 4
    for f in findings:
        assert f.confidence == "Potential"
        assert f.severity == "info"
        assert "method-agnostic" in f.detail or "identical to a plain GET" in f.detail


def test_method_explicitly_allowed_in_options_stays_confirmed():
    session = _FakeSession({
        "GET": _FakeResponse(404),
        "OPTIONS": _FakeResponse(200, headers={"Allow": "GET, PUT, DELETE"}),
        "PUT": _FakeResponse(200),
        "DELETE": _FakeResponse(200),
        "TRACE": _FakeResponse(404),
        "CONNECT": _FakeResponse(404),
    })
    _, findings = check_http_methods(BASE, session)
    by_title = {f.title: f for f in findings}
    assert by_title["PUT method not rejected (200)"].confidence == "Confirmed"
    assert by_title["PUT method not rejected (200)"].severity == "medium"
    assert by_title["DELETE method not rejected (200)"].confidence == "Confirmed"


def test_trace_reflected_canary_stays_confirmed_high():
    """Real XST: the server actually echoes the probe's canary header back
    in the response body - this is the one case a bare 200 legitimately
    proves something."""
    # The real function generates a random canary, so use a session that
    # echoes back whatever header it actually receives on the TRACE request
    # rather than pre-scripting a fixed response text.
    class _EchoingSession(_FakeSession):
        def request(self, method, url, headers=None, timeout=None, **kwargs):
            self.calls.append((method, url, headers))
            if method == "TRACE" and headers:
                canary = headers.get("X-Wvscan-Trace-Canary", "")
                return _FakeResponse(200, text=f"TRACE / HTTP/1.1\nX-Wvscan-Trace-Canary: {canary}")
            return self.responses.get(method, _FakeResponse(status_code=404))

    session = _EchoingSession({
        "GET": _FakeResponse(200),
        "OPTIONS": _FakeResponse(200, headers={"Allow": "GET"}),
        "PUT": _FakeResponse(404),
        "DELETE": _FakeResponse(404),
        "CONNECT": _FakeResponse(404),
    })
    _, findings = check_http_methods(BASE, session)
    trace_findings = [f for f in findings if f.title.startswith("TRACE")]
    assert len(trace_findings) == 1
    assert trace_findings[0].confidence == "Confirmed"
    assert trace_findings[0].severity == "high"


def test_trace_unreflected_200_is_downgraded_not_reported_as_xst():
    """TRACE answers 200 but does NOT echo the canary, and matches the GET
    baseline - a method-agnostic router again, not real XST."""
    session = _FakeSession({
        "GET": _FakeResponse(200, text="homepage"),
        "OPTIONS": _FakeResponse(200, headers={"Allow": "GET"}),
        "PUT": _FakeResponse(404),
        "DELETE": _FakeResponse(404),
        "TRACE": _FakeResponse(200, text="homepage"),
        "CONNECT": _FakeResponse(404),
    })
    _, findings = check_http_methods(BASE, session)
    trace_findings = [f for f in findings if f.title.startswith("TRACE")]
    assert len(trace_findings) == 1
    assert trace_findings[0].confidence == "Potential"
    assert trace_findings[0].severity == "info"


def test_clean_rejection_codes_produce_no_findings():
    session = _FakeSession({
        "GET": _FakeResponse(200),
        "OPTIONS": _FakeResponse(200, headers={"Allow": "GET, HEAD"}),
        "PUT": _FakeResponse(405),
        "DELETE": _FakeResponse(404),
        "TRACE": _FakeResponse(501),
        "CONNECT": _FakeResponse(403),
    })
    _, findings = check_http_methods(BASE, session)
    assert findings == []


def test_never_sends_a_request_body():
    """Non-destructive design constraint - this check only ever probes
    with a bare method + timeout (+ a canary header for TRACE), never a
    body/payload, since PUT/DELETE could otherwise mutate the target."""
    session = _FakeSession({
        "GET": _FakeResponse(200),
        "OPTIONS": _FakeResponse(200),
        "PUT": _FakeResponse(404),
        "DELETE": _FakeResponse(404),
        "TRACE": _FakeResponse(404),
        "CONNECT": _FakeResponse(404),
    })
    check_http_methods(BASE, session)
    for method, url, headers in session.calls:
        assert url == BASE + "/"
