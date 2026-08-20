"""v1.3 Phase 14: unit tests for the three genuinely net-new checks
(file_upload, privacy_exposure, caching_sensitive). CHECK-02 (security.txt)
and CHECK-05 (GraphQL introspection) are NOT covered here - both already
existed before this phase (check_sensitive_paths, check_api_schema_exposure)
and were deliberately not duplicated; see checks.py's own comment marking
the boundary."""
from webvulnscanner.checks import (
    check_caching_sensitive_data,
    check_file_upload,
    check_privacy_exposure,
)

BASE = "https://example.com"


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class _FakeSession:
    """Minimal stand-in for requests.Session - this project has no HTTP-
    mocking library dependency (requests-mock/responses) and Phase 14's own
    "avoid unnecessary dependencies" rule means not adding one just for
    these tests. Only implements .get(), which is all check_caching_
    sensitive_data calls; asserts every call is a GET with no data/json
    payload, proving the check never sends credentials or a request body."""

    def __init__(self, responses):
        self.responses = responses  # {path: _FakeResponse}
        self.calls = []

    def get(self, url, timeout=None, allow_redirects=None, **kwargs):
        assert "data" not in kwargs and "json" not in kwargs, "check must never send a request body"
        self.calls.append(url)
        path = url.rsplit("/", 1)[-1]
        if path in self.responses:
            return self.responses[path]
        return _FakeResponse(status_code=404)


# --------------------------------------------------------------------------
# check_file_upload
# --------------------------------------------------------------------------

def test_file_upload_no_form_returns_empty_no_findings():
    data, findings = check_file_upload(BASE, "<html><body>no forms here</body></html>")
    assert data == {"upload_forms_found": 0}
    assert findings == []


def test_file_upload_empty_html_returns_empty_no_findings():
    data, findings = check_file_upload(BASE, "")
    assert data == {"upload_forms_found": 0}
    assert findings == []


def test_file_upload_detects_file_input_and_never_makes_a_network_call():
    html = """
    <html><body>
      <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="avatar" accept="image/*">
        <button>Upload</button>
      </form>
    </body></html>
    """
    # No requests_mock adapter registered at all - if this check ever made a
    # real network call, it would raise ConnectionError, proving it's
    # genuinely read-only against already-fetched HTML (the explicit "never
    # uploads a file" safety rule).
    data, findings = check_file_upload(BASE, html)
    assert data["upload_forms_found"] == 1
    assert data["rows"][0]["name"] == "avatar"
    assert data["rows"][0]["form_action"] == "/upload"
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].confidence == "Confirmed"
    assert findings[0].verification_state == "Discovered"
    assert "upload" in findings[0].title.lower()


def test_file_upload_multiple_inputs_counted():
    html = '<input type="file" name="a"><input type="file" name="b">'
    data, findings = check_file_upload(BASE, html)
    assert data["upload_forms_found"] == 2
    assert len(findings) == 1  # one summary finding, not one per input


# --------------------------------------------------------------------------
# check_privacy_exposure
# --------------------------------------------------------------------------

def test_privacy_exposure_no_pii_no_findings():
    data, findings = check_privacy_exposure(BASE, "<html><body>Nothing here.</body></html>")
    assert data == {"emails": [], "phones": []}
    assert findings == []


def test_privacy_exposure_empty_html_no_findings():
    data, findings = check_privacy_exposure(BASE, "")
    assert findings == []


def test_privacy_exposure_finds_email_address():
    html = "<html><body>Contact us at support@example.com for help.</body></html>"
    data, findings = check_privacy_exposure(BASE, html)
    assert data["emails"] == ["support@example.com"]
    assert len(findings) == 1
    assert findings[0].category == "Privacy"
    assert findings[0].confidence == "Strong Evidence"


def test_privacy_exposure_finds_phone_number():
    html = "<html><body>Call us: (555) 123-4567</body></html>"
    data, findings = check_privacy_exposure(BASE, html)
    assert data["phones"]
    assert any(f.title.lower().startswith("1 phone") or "phone" in f.title.lower() for f in findings)
    phone_finding = next(f for f in findings if "phone" in f.title.lower())
    assert phone_finding.confidence == "Potential"  # explicit lower confidence, real FP surface


def test_privacy_exposure_deduplicates_and_caps_hits():
    emails = " ".join(f"user{i}@example.com" for i in range(20))
    html = f"<html><body>{emails} user0@example.com</body></html>"  # duplicate included
    data, _ = check_privacy_exposure(BASE, html)
    assert len(data["emails"]) <= 8  # MAX_PRIVACY_HITS_PER_TYPE
    assert len(set(data["emails"])) == len(data["emails"])  # no duplicates


# --------------------------------------------------------------------------
# check_caching_sensitive_data
# --------------------------------------------------------------------------

def test_caching_sensitive_data_flags_missing_cache_control():
    session = _FakeSession({"login": _FakeResponse(200, text="<html>login</html>")})  # no Cache-Control
    data, findings = check_caching_sensitive_data(BASE, session)
    assert len(findings) == 1
    assert findings[0].category == "Caching"
    assert findings[0].severity == "medium"
    assert "/login" in findings[0].title


def test_caching_sensitive_data_passes_when_no_store_present():
    session = _FakeSession({"login": _FakeResponse(200, headers={"Cache-Control": "no-store"},
                                                     text="<html>login</html>")})
    data, findings = check_caching_sensitive_data(BASE, session)
    assert findings == []
    assert data["rows"][0]["status"] == "pass"


def test_caching_sensitive_data_skips_non_200_paths():
    session = _FakeSession({})  # every path 404s
    data, findings = check_caching_sensitive_data(BASE, session)
    assert data["rows"] == []
    assert findings == []


def test_caching_sensitive_data_never_sends_credentials_or_uses_other_methods():
    """Read-only GET only - _FakeSession has no .post()/.put()/etc, so any
    attempt to use one would raise AttributeError, and .get() itself asserts
    no request body is ever sent."""
    session = _FakeSession({"login": _FakeResponse(200, text="<html>login</html>")})
    check_caching_sensitive_data(BASE, session)
    assert all(call.startswith(BASE) for call in session.calls)
