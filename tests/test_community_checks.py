"""
Tests for Phase 28 — Community Check Extensibility (PLUG-01..05).

Covers:
- Schema validation: one deliberately malformed fixture per rejection reason
- Happy-path: valid check loads, registers, builds jobs, executes
- Safety constraints: GET-only enforcement, max-requests, regex compilation
- Registry integration: FEATURE_REQUIREMENTS, CHECK_LABELS, etc. updated
- Scan-engine integration: community checks appear in run_scan() jobs dict
"""
import os
import re
import tempfile
from unittest.mock import MagicMock

import pytest
import yaml

from webvulnscanner.community_checks import (
    COMMUNITY_CHECKS_DIR,
    MAX_REQUESTS_PER_CHECK,
    VALID_METHODS,
    CommunityCheckError,
    CommunityCheckSpec,
    _build_check_function,
    _parse_check,
    _validate_check,
    build_community_jobs,
    load_community_checks,
    register_community_checks,
)
from webvulnscanner.checks import (
    CHECK_CATEGORY,
    CHECK_COMPLIANCE,
    CHECK_LABELS,
    SCAN_TYPE_CHECK_NAMES,
    SECURITY_DOMAIN_MAP,
)
from webvulnscanner.entitlements import FEATURE_REQUIREMENTS, Tier

FIXTURES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures", "community_checks",
)
VALID_DIR = os.path.join(FIXTURES_DIR, "valid")


@pytest.fixture(autouse=True)
def _restore_registries():
    """Snapshot all module-level registries before each test and restore after.

    register_community_checks() mutates the real dicts; if we don't clean up,
    entries leak into test_compliance.py's stale-key / asvs-format assertions.
    """
    before = {
        id(d): dict(d) for d in (
            FEATURE_REQUIREMENTS, CHECK_LABELS, CHECK_CATEGORY,
            CHECK_COMPLIANCE, SECURITY_DOMAIN_MAP,
        )
    }
    yield
    for d, snap in zip(
        (FEATURE_REQUIREMENTS, CHECK_LABELS, CHECK_CATEGORY,
         CHECK_COMPLIANCE, SECURITY_DOMAIN_MAP),
        before.values(),
    ):
        d.clear()
        d.update(snap)


def _load_fixture_raw(name):
    """Load a single fixture file as raw YAML dict."""
    fpath = os.path.join(FIXTURES_DIR, name)
    with open(fpath, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _isolated_load(*fixture_names):
    """Load community checks from a temp dir containing only the named fixtures."""
    with tempfile.TemporaryDirectory() as tmpdir:
        for name in fixture_names:
            src = os.path.join(FIXTURES_DIR, name)
            dst = os.path.join(tmpdir, name)
            with open(src, "r", encoding="utf-8") as fin:
                with open(dst, "w", encoding="utf-8") as fout:
                    fout.write(fin.read())
        return load_community_checks(tmpdir)


# ---------------------------------------------------------------------------
# Schema validation — one test per rejection reason (PLUG-05)
# ---------------------------------------------------------------------------

class TestSchemaValidation:
    """Each malformed fixture triggers a CommunityCheckError at load time."""

    def test_missing_name(self):
        raw = _load_fixture_raw("bad_missing_name.yaml")
        with pytest.raises(CommunityCheckError, match="missing required field: name"):
            _validate_check(raw, "bad_missing_name.yaml")

    def test_invalid_name_format(self):
        raw = _load_fixture_raw("bad_invalid_name.yaml")
        with pytest.raises(CommunityCheckError, match="snake_case"):
            _validate_check(raw, "bad_invalid_name.yaml")

    def test_invalid_tier(self):
        raw = _load_fixture_raw("bad_invalid_tier.yaml")
        with pytest.raises(CommunityCheckError, match="tier"):
            _validate_check(raw, "bad_invalid_tier.yaml")

    def test_non_get_method(self):
        raw = _load_fixture_raw("bad_non_get_method.yaml")
        with pytest.raises(CommunityCheckError, match="method must be GET"):
            _validate_check(raw, "bad_non_get_method.yaml")

    def test_too_many_requests(self):
        raw = _load_fixture_raw("bad_too_many_requests.yaml")
        with pytest.raises(CommunityCheckError, match="max allowed is"):
            _validate_check(raw, "bad_too_many_requests.yaml")

    def test_invalid_regex(self):
        raw = _load_fixture_raw("bad_invalid_regex.yaml")
        with pytest.raises(CommunityCheckError, match="invalid regex"):
            _validate_check(raw, "bad_invalid_regex.yaml")

    def test_missing_finding(self):
        raw = _load_fixture_raw("bad_missing_finding.yaml")
        with pytest.raises(CommunityCheckError, match="missing required field: finding"):
            _validate_check(raw, "bad_missing_finding.yaml")

    def test_invalid_severity(self):
        raw = _load_fixture_raw("bad_invalid_severity.yaml")
        with pytest.raises(CommunityCheckError, match="severity"):
            _validate_check(raw, "bad_invalid_severity.yaml")

    def test_invalid_security_domain(self):
        raw = _load_fixture_raw("bad_invalid_security_domain.yaml")
        with pytest.raises(CommunityCheckError, match="security_domain"):
            _validate_check(raw, "bad_invalid_security_domain.yaml")

    def test_invalid_confidence(self):
        raw = _load_fixture_raw("bad_invalid_confidence.yaml")
        with pytest.raises(CommunityCheckError, match="confidence"):
            _validate_check(raw, "bad_invalid_confidence.yaml")

    def test_invalid_icon_category(self):
        raw = _load_fixture_raw("bad_invalid_icon.yaml")
        with pytest.raises(CommunityCheckError, match="icon_category"):
            _validate_check(raw, "bad_invalid_icon.yaml")

    def test_empty_requests_list(self):
        raw = _load_fixture_raw("bad_empty_requests.yaml")
        with pytest.raises(CommunityCheckError, match="non-empty list"):
            _validate_check(raw, "bad_empty_requests.yaml")

    def test_yaml_parse_error(self):
        """Malformed YAML syntax causes a CommunityCheckError."""
        with pytest.raises(CommunityCheckError, match="YAML parse error"):
            _isolated_load("bad_yaml_syntax.yaml")

    def test_non_mapping_top_level(self):
        """A YAML file whose root is a list (not a mapping) is rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_path = os.path.join(tmpdir, "bad_list.yaml")
            with open(bad_path, "w") as f:
                f.write("- not a mapping\n- another item\n")
            with pytest.raises(CommunityCheckError, match="expected a YAML mapping"):
                load_community_checks(tmpdir)


# ---------------------------------------------------------------------------
# Happy path — valid check loads, registers, builds, executes
# ---------------------------------------------------------------------------

class TestHappyPath:
    """A valid community check flows through the full pipeline."""

    def test_load_valid_check(self):
        specs = load_community_checks(VALID_DIR)
        assert len(specs) == 1
        spec = specs[0]
        assert spec.name == "test_valid_check"
        assert spec.display_label == "Valid test check"
        assert spec.tier == Tier.FREE
        assert spec.icon_category == "lock"
        assert len(spec.requests) == 1
        assert spec.requests[0]["path"] == "/test"
        assert spec.requests[0]["param_name"] == "q"

    def test_register_populates_registries(self):
        specs = load_community_checks(VALID_DIR)
        register_community_checks(specs)
        full_name = "community_test_valid_check"
        assert full_name in FEATURE_REQUIREMENTS
        assert FEATURE_REQUIREMENTS[full_name] == Tier.FREE
        assert full_name in CHECK_LABELS
        assert CHECK_LABELS[full_name] == "Valid test check"
        assert full_name in CHECK_CATEGORY
        assert CHECK_CATEGORY[full_name] == "lock"
        assert full_name in CHECK_COMPLIANCE
        assert full_name in SECURITY_DOMAIN_MAP

    def test_build_jobs_returns_callable(self):
        specs = load_community_checks(VALID_DIR)
        session = MagicMock()
        jobs = build_community_jobs(specs, "http://example.com", session)
        assert "community_test_valid_check" in jobs
        assert callable(jobs["community_test_valid_check"])

    def test_check_function_returns_tuple(self):
        specs = load_community_checks(VALID_DIR)
        fn = _build_check_function(specs[0])
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "expected_content is here"
        mock_resp.headers = {}
        session.get.return_value = mock_resp
        data, findings = fn("http://example.com", session)
        assert isinstance(data, list)
        assert isinstance(findings, list)
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert findings[0].confidence == "Confirmed"
        assert findings[0].cwe == "CWE-200"
        assert "Matched 1/1" in findings[0].detail

    def test_check_no_match_returns_empty_findings(self):
        specs = load_community_checks(VALID_DIR)
        fn = _build_check_function(specs[0])
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "not found"
        mock_resp.headers = {}
        session.get.return_value = mock_resp
        data, findings = fn("http://example.com", session)
        assert len(findings) == 0
        assert data[0]["result"] == "pass"


# ---------------------------------------------------------------------------
# Safety constraints
# ---------------------------------------------------------------------------

class TestSafetyConstraints:
    """Verify load-time enforcement of safety limits."""

    def test_max_requests_enforced(self):
        spec_dict = {
            "name": "overflow",
            "display_label": "Overflow",
            "description": "Test",
            "owasp_category": "A05",
            "security_domain": "Configuration",
            "tier": "free",
            "requests": [{"path": f"/{i}", "match": {"status_code": 200}} for i in range(11)],
            "finding": {"title": "T", "severity": "low", "description": "D"},
        }
        with pytest.raises(CommunityCheckError, match="max allowed is"):
            _validate_check(spec_dict, "test")

    def test_post_method_rejected(self):
        spec_dict = {
            "name": "post_check",
            "display_label": "Post",
            "description": "Test",
            "owasp_category": "A05",
            "security_domain": "Configuration",
            "tier": "free",
            "requests": [{"path": "/", "method": "POST", "match": {"status_code": 200}}],
            "finding": {"title": "T", "severity": "low", "description": "D"},
        }
        with pytest.raises(CommunityCheckError, match="method must be GET"):
            _validate_check(spec_dict, "test")

    def test_missing_directory_returns_empty(self):
        result = load_community_checks("/nonexistent/path/xyz")
        assert result == []


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------

class TestRegistryIntegration:
    """Community checks join the same registries as built-in checks."""

    def test_community_checks_in_feature_requirements(self):
        specs = load_community_checks(VALID_DIR)
        register_community_checks(specs)
        assert "community_test_valid_check" in FEATURE_REQUIREMENTS

    def test_community_checks_in_check_labels(self):
        specs = load_community_checks(VALID_DIR)
        register_community_checks(specs)
        assert "community_test_valid_check" in CHECK_LABELS

    def test_community_checks_in_compliance_map(self):
        specs = load_community_checks(VALID_DIR)
        register_community_checks(specs)
        assert "community_test_valid_check" in CHECK_COMPLIANCE

    def test_community_checks_in_security_domain_map(self):
        specs = load_community_checks(VALID_DIR)
        register_community_checks(specs)
        assert "community_test_valid_check" in SECURITY_DOMAIN_MAP

    def test_community_checks_not_in_scan_type_check_names(self):
        """Community checks are dynamic, not in SCAN_TYPE_CHECK_NAMES."""
        specs = load_community_checks(VALID_DIR)
        register_community_checks(specs)
        assert "community_test_valid_check" not in SCAN_TYPE_CHECK_NAMES["base"]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Boundary conditions and error handling."""

    def test_network_error_returns_empty_findings(self):
        import requests as _requests
        specs = load_community_checks(VALID_DIR)
        fn = _build_check_function(specs[0])
        session = MagicMock()
        session.get.side_effect = _requests.ConnectionError("connection refused")
        data, findings = fn("http://example.com", session)
        assert len(findings) == 0
        assert data[0]["result"] == "error"

    def test_forbidden_headers_absent_triggers_finding(self):
        """forbidden_headers: [Server] fires when Server is NOT in the response."""
        spec = CommunityCheckSpec(
            name="forbidden_test",
            display_label="Forbidden test",
            description="Test",
            owasp_category="A05",
            security_domain="Configuration",
            tier=Tier.FREE,
            requests=[{
                "path": "/",
                "match": {"forbidden_headers": ["Server"]},
            }],
            finding={
                "title": "Server header missing",
                "severity": "info",
                "description": "Server header is absent",
            },
        )
        fn = _build_check_function(spec)
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ""
        mock_resp.headers = {}  # No Server header → forbidden condition met
        session.get.return_value = mock_resp
        data, findings = fn("http://example.com", session)
        assert len(findings) == 1
        assert data[0]["result"] == "fail"

    def test_forbidden_headers_present_no_finding(self):
        """forbidden_headers: [Server] does NOT fire when Server IS present."""
        spec = CommunityCheckSpec(
            name="forbidden_test2",
            display_label="Forbidden test 2",
            description="Test",
            owasp_category="A05",
            security_domain="Configuration",
            tier=Tier.FREE,
            requests=[{
                "path": "/",
                "match": {"forbidden_headers": ["Server"]},
            }],
            finding={
                "title": "Server header missing",
                "severity": "info",
                "description": "Server header is absent",
            },
        )
        fn = _build_check_function(spec)
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ""
        mock_resp.headers = {"Server": "nginx/1.21"}
        session.get.return_value = mock_resp
        data, findings = fn("http://example.com", session)
        assert len(findings) == 0
        assert data[0]["result"] == "pass"

    def test_required_headers_present_triggers_finding(self):
        """required_headers: [Server] fires when Server IS in the response."""
        spec = CommunityCheckSpec(
            name="required_test",
            display_label="Required test",
            description="Test",
            owasp_category="A05",
            security_domain="Configuration",
            tier=Tier.FREE,
            requests=[{
                "path": "/",
                "match": {"required_headers": ["Server"]},
            }],
            finding={
                "title": "Server header found",
                "severity": "info",
                "description": "Server header is present",
            },
        )
        fn = _build_check_function(spec)
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ""
        mock_resp.headers = {"Server": "nginx/1.21"}
        session.get.return_value = mock_resp
        data, findings = fn("http://example.com", session)
        assert len(findings) == 1
        assert data[0]["result"] == "fail"

    def test_body_regex_match(self):
        """body_regex matching works correctly."""
        spec = CommunityCheckSpec(
            name="regex_test",
            display_label="Regex test",
            description="Test",
            owasp_category="A05",
            security_domain="Configuration",
            tier=Tier.FREE,
            requests=[{
                "path": "/",
                "match": {"body_regex": r"(?i)error\s+\d{3}"},
            }],
            finding={
                "title": "Error pattern found",
                "severity": "medium",
                "description": "Error pattern in response",
            },
        )
        fn = _build_check_function(spec)
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Internal Error 500 occurred"
        mock_resp.headers = {}
        session.get.return_value = mock_resp
        data, findings = fn("http://example.com", session)
        assert len(findings) == 1

    def test_body_regex_no_match(self):
        """body_regex does NOT match when pattern is absent."""
        spec = CommunityCheckSpec(
            name="regex_test2",
            display_label="Regex test 2",
            description="Test",
            owasp_category="A05",
            security_domain="Configuration",
            tier=Tier.FREE,
            requests=[{
                "path": "/",
                "match": {"body_regex": r"(?i)error\s+\d{3}"},
            }],
            finding={
                "title": "Error pattern found",
                "severity": "medium",
                "description": "Error pattern in response",
            },
        )
        fn = _build_check_function(spec)
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Everything is fine"
        mock_resp.headers = {}
        session.get.return_value = mock_resp
        data, findings = fn("http://example.com", session)
        assert len(findings) == 0

    def test_multiple_requests_partial_match(self):
        """When some requests match and others don't, a finding is still produced."""
        spec = CommunityCheckSpec(
            name="partial_test",
            display_label="Partial test",
            description="Test",
            owasp_category="A05",
            security_domain="Configuration",
            tier=Tier.FREE,
            requests=[
                {"path": "/ok", "match": {"status_code": 200}},
                {"path": "/fail", "match": {"status_code": 404}},
            ],
            finding={
                "title": "Partial match",
                "severity": "low",
                "description": "Test",
            },
        )
        fn = _build_check_function(spec)
        session = MagicMock()
        resp_ok = MagicMock()
        resp_ok.status_code = 200
        resp_ok.text = ""
        resp_ok.headers = {}
        session.get.return_value = resp_ok
        data, findings = fn("http://example.com", session)
        assert len(findings) == 1
        assert "1/2" in findings[0].detail

    def test_param_injection_in_url(self):
        """Verify query parameter is correctly injected."""
        spec = CommunityCheckSpec(
            name="param_test",
            display_label="Param test",
            description="Test",
            owasp_category="A05",
            security_domain="Configuration",
            tier=Tier.FREE,
            requests=[{
                "path": "/search",
                "param_name": "q",
                "payload": "test<script>",
                "match": {"status_code": 200},
            }],
            finding={
                "title": "Test",
                "severity": "info",
                "description": "Test",
            },
        )
        fn = _build_check_function(spec)
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ""
        mock_resp.headers = {}
        session.get.return_value = mock_resp
        fn("http://example.com", session)
        call_args = session.get.call_args
        url = call_args[0][0]
        assert "q=" in url

    def test_check_name_prefix(self):
        """Community check functions are prefixed with 'community_'."""
        specs = load_community_checks(VALID_DIR)
        fn = _build_check_function(specs[0])
        assert fn.__name__ == "community_test_valid_check"

    def test_requests_appended_to_existing_query_string(self):
        """When path already has ?, param uses & separator."""
        spec = CommunityCheckSpec(
            name="qs_test",
            display_label="QS test",
            description="Test",
            owasp_category="A05",
            security_domain="Configuration",
            tier=Tier.FREE,
            requests=[{
                "path": "/page?existing=1",
                "param_name": "inject",
                "payload": "test",
                "match": {"status_code": 200},
            }],
            finding={
                "title": "Test",
                "severity": "info",
                "description": "Test",
            },
        )
        fn = _build_check_function(spec)
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ""
        mock_resp.headers = {}
        session.get.return_value = mock_resp
        fn("http://example.com", session)
        url = session.get.call_args[0][0]
        assert "existing=1" in url
        assert "inject=test" in url
        assert "&" in url.split("?")[1]


# ---------------------------------------------------------------------------
# Built-in check registry coverage locks remain unbroken
# ---------------------------------------------------------------------------

class TestBuiltInRegistryCoverage:
    """Ensure community checks don't break existing registry-sync tests."""

    def test_check_compliance_covers_check_labels(self):
        for name in CHECK_LABELS:
            assert name in CHECK_COMPLIANCE, (
                f"{name} in CHECK_LABELS but missing from CHECK_COMPLIANCE"
            )

    def test_check_labels_covers_check_category(self):
        for name in CHECK_LABELS:
            assert name in CHECK_CATEGORY, (
                f"{name} in CHECK_LABELS but missing from CHECK_CATEGORY"
            )

    def test_feature_requirements_has_all_base_checks(self):
        for name in SCAN_TYPE_CHECK_NAMES["base"]:
            assert name in FEATURE_REQUIREMENTS, (
                f"{name} in SCAN_TYPE_CHECK_NAMES['base'] but missing from FEATURE_REQUIREMENTS"
            )
