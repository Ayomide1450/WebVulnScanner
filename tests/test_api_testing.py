"""Phase 34 (APIT-01..03): API Testing Enhancements.

Tests cover:
- check_graphql_depth: nested query depth probing
- check_auth_comparison: authenticated vs unauthenticated comparison
- check_mass_assignment: extra field injection detection
- All 3 registered in registries and wired into run_scan
"""
from unittest.mock import MagicMock
from webvulnscanner.checks import (
    check_graphql_depth, check_auth_comparison, check_mass_assignment,
    CHECK_LABELS, CHECK_CATEGORY, CHECK_COMPLIANCE,
)
from webvulnscanner.entitlements import FEATURE_REQUIREMENTS


class TestCheckGraphqlDepth:
    """APIT-01: GraphQL query depth limit testing."""

    def test_returns_tuple(self):
        session = MagicMock()
        session.post.return_value = MagicMock(status_code=404)
        result = check_graphql_depth("http://example.com", session)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_no_graphql_endpoints(self):
        session = MagicMock()
        session.post.return_value = MagicMock(status_code=404)
        data, findings = check_graphql_depth("http://example.com", session)
        assert data["endpoints_tested"] == 0

    def test_shallow_depth_no_finding(self):
        session = MagicMock()
        # Return errors for all depth queries → max_depth_observed < 5 → no finding
        error_resp = MagicMock(status_code=400, text='{"errors":[{"message":"Query too deep"}]}')
        session.post.return_value = error_resp
        data, findings = check_graphql_depth("http://example.com", session)
        for f in findings:
            assert "No query depth limit" not in f.title


class TestCheckAuthComparison:
    """APIT-02: Auth vs unauth comparison."""

    def test_returns_tuple(self):
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=404, content=b"")
        result = check_auth_comparison("http://example.com", session)
        assert isinstance(result, tuple)

    def test_200_without_auth_flags_finding(self):
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=200, content=b'{"users":[]}')
        data, findings = check_auth_comparison("http://example.com", session)
        assert data["endpoints_tested"] > 0
        # All endpoints return 200 → should flag findings
        assert len(findings) > 0

    def test_404_no_finding(self):
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=404, content=b"not found")
        data, findings = check_auth_comparison("http://example.com", session)
        assert len(findings) == 0


class TestCheckMassAssignment:
    """APIT-03: Mass assignment detection."""

    def test_returns_tuple(self):
        session = MagicMock()
        session.post.return_value = MagicMock(status_code=404, text="not found")
        result = check_mass_assignment("http://example.com", session)
        assert isinstance(result, tuple)

    def test_extra_fields_in_response(self):
        session = MagicMock()
        session.post.return_value = MagicMock(
            status_code=201,
            text='{"role":"admin","is_admin":true,"username":"test"}',
        )
        data, findings = check_mass_assignment("http://example.com", session)
        assert data["endpoints_tested"] > 0
        assert len(findings) > 0
        assert findings[0].category == "Mass Assignment"

    def test_clean_response_no_finding(self):
        session = MagicMock()
        session.post.return_value = MagicMock(
            status_code=400,
            text='{"error":"invalid request"}',
        )
        data, findings = check_mass_assignment("http://example.com", session)
        for f in findings:
            assert "role" not in f.title.lower()


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
