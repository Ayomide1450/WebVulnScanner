"""Phase 34 (APIT-01..03): API Testing Enhancements.

Tests cover:
- check_graphql_depth: nested query depth probing
- check_auth_comparison: unauthenticated-exposure probe on auth-sounding paths
- check_mass_assignment: extra field injection detection
- All 3 registered in registries and wired into run_scan

check_auth_comparison and check_mass_assignment were rewritten after review
found both produced guaranteed/near-guaranteed false positives:
check_auth_comparison compared session.get() against an identical second
session.get() call (there is no authenticated leg in the pipeline it's
wired into) and check_mass_assignment scanned for "role" etc. as a raw
text substring, which matches ordinary role="..." ARIA markup on most
real pages. Tests below use explicit fake responses (not bare MagicMock,
whose auto-mocked magic methods like __contains__ silently return
truthy and would mask exactly this class of bug) so they exercise the
real corrected logic.
"""
from webvulnscanner.checks import (
    check_graphql_depth, check_auth_comparison, check_mass_assignment,
    CHECK_LABELS, CHECK_CATEGORY, CHECK_COMPLIANCE,
)
from webvulnscanner.entitlements import FEATURE_REQUIREMENTS


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, text="", json_data=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.content = text.encode()
        self._json_data = json_data

    def json(self):
        if self._json_data is None:
            raise ValueError("no JSON body")
        return self._json_data


class _FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, timeout=None, allow_redirects=None, **kwargs):
        self.calls.append(url)
        return self.response

    def post(self, url, json=None, headers=None, timeout=None, allow_redirects=None, **kwargs):
        self.calls.append((url, json))
        return self.response


class TestCheckGraphqlDepth:
    """APIT-01: GraphQL query depth limit testing."""

    def test_returns_tuple(self):
        session = _FakeSession(_FakeResponse(status_code=404))
        result = check_graphql_depth("http://example.com", session)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_no_graphql_endpoints(self):
        session = _FakeSession(_FakeResponse(status_code=404))
        data, findings = check_graphql_depth("http://example.com", session)
        assert data["endpoints_tested"] == 0

    def test_shallow_depth_no_finding(self):
        # Return errors for all depth queries -> max_depth_observed < 5 -> no finding
        session = _FakeSession(_FakeResponse(status_code=400, text='{"errors":[{"message":"Query too deep"}]}'))
        data, findings = check_graphql_depth("http://example.com", session)
        for f in findings:
            assert "No query depth limit" not in f.title


class TestCheckAuthComparison:
    """APIT-02: unauthenticated-exposure probe on auth-sounding paths (not a
    real auth-vs-unauth comparison - see module docstring for why)."""

    def test_returns_tuple(self):
        session = _FakeSession(_FakeResponse(status_code=404, text="not found"))
        result = check_auth_comparison("http://example.com", session)
        assert isinstance(result, tuple)

    def test_api_shaped_200_with_no_credentials_flags_potential_not_confirmed(self):
        session = _FakeSession(_FakeResponse(
            status_code=200, headers={"Content-Type": "application/json"}, text='{"users":[]}',
        ))
        data, findings = check_auth_comparison("http://example.com", session)
        assert data["endpoints_tested"] > 0
        assert len(findings) > 0
        for f in findings:
            # Never "Confirmed" - this check has no authenticated leg to
            # compare against, so it can only ever say "unconfirmed, needs
            # review", never claim a proven bypass.
            assert f.confidence == "Potential"
            assert f.severity == "medium"

    def test_404_no_finding(self):
        session = _FakeSession(_FakeResponse(status_code=404, text="not found"))
        data, findings = check_auth_comparison("http://example.com", session)
        assert len(findings) == 0

    def test_html_shell_200_is_not_flagged_spa_false_positive_guard(self):
        """A 200 that isn't API-shaped (an SPA's catch-all index.html, e.g.)
        must not be flagged - _looks_like_api_response guards this exactly
        like check_api_wordlist already relies on."""
        session = _FakeSession(_FakeResponse(
            status_code=200, headers={"Content-Type": "text/html"}, text="<html><body>App shell</body></html>",
        ))
        data, findings = check_auth_comparison("http://example.com", session)
        assert findings == []

    def test_never_makes_a_second_identical_request_per_path(self):
        """Regression lock for the original bug: exactly one GET per
        candidate path, never two (there is nothing to compare a second
        request against in this pipeline)."""
        session = _FakeSession(_FakeResponse(status_code=404, text="not found"))
        check_auth_comparison("http://example.com", session)
        assert len(session.calls) == len(set(session.calls)), "duplicate identical calls detected"


class TestCheckMassAssignment:
    """APIT-03: Mass assignment detection."""

    def test_returns_tuple(self):
        session = _FakeSession(_FakeResponse(status_code=404, text="not found"))
        result = check_mass_assignment("http://example.com", session)
        assert isinstance(result, tuple)

    def test_exact_json_field_echo_flags_confirmed(self):
        session = _FakeSession(_FakeResponse(
            status_code=201,
            json_data={"role": "admin", "is_admin": True, "username": "test_probe_user_31415"},
        ))
        data, findings = check_mass_assignment("http://example.com", session)
        assert data["endpoints_tested"] > 0
        assert len(findings) > 0
        assert findings[0].category == "Mass Assignment"
        assert findings[0].confidence == "Confirmed"

    def test_role_as_html_attribute_substring_is_not_a_false_positive(self):
        """The exact false-positive class fixed in review: role="button"-
        style ARIA markup used to trip this as "accepted field: role"
        purely because the substring "role" appeared anywhere in the
        response text. A non-JSON HTML response now yields no finding."""
        session = _FakeSession(_FakeResponse(
            status_code=200,
            text='<html><body><div role="button">Click</div></body></html>',
        ))
        data, findings = check_mass_assignment("http://example.com", session)
        assert findings == []

    def test_json_response_without_matching_values_is_not_flagged(self):
        """A JSON response that happens to contain the key "role" with a
        DIFFERENT value than what was submitted (e.g. the server stripped
        the privileged value and returned the default) must not be
        flagged - only an exact submitted-value echo counts."""
        session = _FakeSession(_FakeResponse(
            status_code=201,
            json_data={"role": "user", "username": "test_probe_user_31415"},
        ))
        data, findings = check_mass_assignment("http://example.com", session)
        assert findings == []

    def test_clean_response_no_finding(self):
        session = _FakeSession(_FakeResponse(status_code=400, json_data={"error": "invalid request"}))
        data, findings = check_mass_assignment("http://example.com", session)
        for f in findings:
            assert "role" not in f.title.lower()

    def test_never_probes_registration_endpoints(self):
        """Non-destructive design: a fabricated POST to a real /register
        route could create a real account on the live target - dropped
        entirely from the probe list, not just downgraded."""
        session = _FakeSession(_FakeResponse(status_code=404, text="not found"))
        check_mass_assignment("http://example.com", session)
        probed_paths = [url for url, _ in session.calls]
        assert not any("register" in p for p in probed_paths)


class TestRegistration:
    """All 3 checks registered in registries."""

    def test_check_labels(self):
        for key in ("graphql_depth", "auth_comparison", "mass_assignment"):
            assert key in CHECK_LABELS

    def test_check_category(self):
        for key in ("graphql_depth", "auth_comparison", "mass_assignment"):
            assert key in CHECK_CATEGORY

    def test_check_compliance(self):
        for key in ("graphql_depth", "auth_comparison", "mass_assignment"):
            assert key in CHECK_COMPLIANCE

    def test_feature_requirements(self):
        for key in ("graphql_depth", "auth_comparison", "mass_assignment"):
            assert key in FEATURE_REQUIREMENTS

    def test_wired_in_scan_engine(self):
        import pathlib
        source = pathlib.Path("webvulnscanner/scan_engine.py").read_text(encoding="utf-8")
        for key in ("graphql_depth", "auth_comparison", "mass_assignment"):
            assert f'"{key}":' in source
