"""Phase 33 (OWGAP-01..05): OWASP Gap Audit checks.

Tests cover:
- check_xxe: marker-only payload, graceful error handling
- check_csp_depth: inline script detection
- check_hsts_depth: max-age, includeSubDomains, preload analysis
- check_dnssec: DNSKEY + AD flag checks (mocked dns.resolver)
- check_dependency_audit: known library detection, CVE matching
- All 5 registered in FEATURE_REQUIREMENTS, CHECK_LABELS, CHECK_CATEGORY
- All 5 wired into run_scan() jobs dict
"""
import pytest
from unittest.mock import patch, MagicMock
from webvulnscanner.checks import (
    Finding, check_xxe, check_csp_depth, check_hsts_depth,
    check_dnssec, check_dependency_audit,
    CHECK_LABELS, CHECK_CATEGORY,
)
from webvulnscanner.entitlements import FEATURE_REQUIREMENTS


class TestCheckXxe:
    """OWGAP-01: XXE injection probing."""

    def test_returns_tuple(self):
        session = MagicMock()
        session.post.return_value = MagicMock(status_code=200, text="normal page")
        result = check_xxe(["http://example.com/xml"], session)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_no_urls_returns_empty(self):
        session = MagicMock()
        data, findings = check_xxe([], session)
        assert data["urls_tested"] == 0
        assert findings == []

    def test_error_handling(self):
        session = MagicMock()
        session.post.side_effect = ConnectionError("fail")
        data, findings = check_xxe(["http://example.com/xml"], session)
        assert data["rows"][0]["status"] == "error"
        assert findings == []


class TestCheckCspDepth:
    """OWGAP-02: CSP depth analysis."""

    def test_no_inline_scripts(self):
        html = '<html><head><script src="app.js"></script></head></html>'
        data, findings = check_csp_depth(html)
        assert data["inline_scripts"] == 0
        assert findings == []

    def test_inline_scripts_detected(self):
        html = '<html><head><script>var x = 1;</script></head></html>'
        data, findings = check_csp_depth(html)
        assert data["inline_scripts"] >= 1
        assert len(findings) >= 1
        assert findings[0].category == "CSP"

    def test_empty_html(self):
        data, findings = check_csp_depth("")
        assert data["inline_scripts"] == 0


class TestCheckHstsDepth:
    """OWGAP-03: HSTS depth analysis."""

    def test_no_hsts(self):
        data, findings = check_hsts_depth({"content-type": "text/html"})
        assert data["present"] is False
        assert findings == []

    def test_short_max_age(self):
        data, findings = check_hsts_depth({"strict-transport-security": "max-age=100"})
        assert data["max_age"] == 100
        assert any("too short" in f.title.lower() for f in findings)

    def test_adequate_max_age(self):
        data, findings = check_hsts_depth({"strict-transport-security": "max-age=31536000"})
        assert data["max_age"] == 31536000
        assert data["include_subdomains"] is False
        assert any("includeSubDomains" in f.title for f in findings)

    def test_full_hsts(self):
        data, findings = check_hsts_depth({
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
        })
        assert data["include_subdomains"] is True
        assert data["preload"] is True
        assert not any(f.severity in ("high", "critical") for f in findings)


class TestCheckDnssec:
    """OWGAP-04: DNSSEC verification."""

    def test_returns_tuple(self):
        data, findings = check_dnssec("example.com")
        assert isinstance(data, dict)
        assert "hostname" in data

    @patch("webvulnscanner.checks.dns.resolver")
    def test_no_dnssec(self, mock_resolver):
        mock_flags = MagicMock()
        mock_flags.__and__ = lambda self, other: 0
        mock_resolver.flags = mock_flags

        mock_answer = MagicMock()
        mock_answer.__len__ = lambda self: 0
        mock_resolver.resolve.side_effect = [
            mock_answer,  # DNSKEY - no records
            MagicMock(response=MagicMock(flags=mock_flags)),  # SOA - no AD
        ]

        data, findings = check_dnssec("example.com")
        # Should have rows from both queries
        assert len(data["rows"]) >= 1

    def test_import_error_handling(self):
        with patch.dict("sys.modules", {"dns.resolver": None}):
            data, findings = check_dnssec("example.com")
            # Should handle ImportError gracefully
            assert isinstance(data, dict)


class TestCheckDependencyAudit:
    """OWGAP-05: Dependency version audit."""

    def test_no_scripts(self):
        data, findings = check_dependency_audit("<html><body>hello</body></html>")
        assert data["scripts_found"] == 0
        assert findings == []

    def test_known_library_detected(self):
        html = '<html><head><script src="https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js"></script></head></html>'
        data, findings = check_dependency_audit(html)
        assert data["scripts_found"] == 1
        assert len(findings) >= 1
        assert "lodash" in findings[0].title.lower()

    def test_unknown_library_no_finding(self):
        html = '<html><head><script src="https://cdn.example.com/custom.js"></script></head></html>'
        data, findings = check_dependency_audit(html)
        assert data["scripts_found"] == 1
        assert findings == []

    def test_empty_html(self):
        data, findings = check_dependency_audit("")
        assert data["scripts_found"] == 0


class TestRegistration:
    """All 5 checks registered in registries and wired into run_scan()."""

    def test_check_labels_coverage(self):
        for key in ("xxe", "csp_depth", "hsts_depth", "dnssec", "dep_audit"):
            assert key in CHECK_LABELS, f"{key} missing from CHECK_LABELS"

    def test_check_category_coverage(self):
        for key in ("xxe", "csp_depth", "hsts_depth", "dnssec", "dep_audit"):
            assert key in CHECK_CATEGORY, f"{key} missing from CHECK_CATEGORY"

    def test_feature_requirements_coverage(self):
        for key in ("xxe", "csp_depth", "hsts_depth", "dnssec", "dep_audit"):
            assert key in FEATURE_REQUIREMENTS, f"{key} missing from FEATURE_REQUIREMENTS"

    def test_wired_in_scan_engine(self):
        import pathlib
        source = pathlib.Path("webvulnscanner/scan_engine.py").read_text(encoding="utf-8")
        for key in ("xxe", "csp_depth", "hsts_depth", "dnssec", "dep_audit"):
            assert f'"{key}":' in source, f"{key} not wired into scan_engine.py jobs dict"

    def test_imports_in_scan_engine(self):
        import pathlib
        source = pathlib.Path("webvulnscanner/scan_engine.py").read_text(encoding="utf-8")
        for fn in ("check_xxe", "check_csp_depth", "check_hsts_depth", "check_dnssec", "check_dependency_audit"):
            assert fn in source, f"{fn} not imported in scan_engine.py"
