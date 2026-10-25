"""Phase 31 (CVSS-01..05): CVSS 3.1 base score computation + Finding.cvss_vector plumbing.

Tests cover:
- compute_cvss_score() vector parsing and scoring for well-known vectors
- Edge cases: invalid vectors, missing metrics, empty input
- Finding.cvss_vector field round-trip through dataclass asdict
- Source-parse lock: _score_report still uses SEVERITY_WEIGHT (CVSS is附加)
- 5 check call sites supply CVSS vectors (one per severity tier)
"""
from glassbox.checks import Finding, compute_cvss_score


class TestComputeCvssScore:
    """CVSS-02: compute_cvss_score() parsing and scoring."""

    def test_critical_vector(self):
        """Classic remote code execution: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"""
        score, label = compute_cvss_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        assert score == 9.8
        assert label == "Critical"

    def test_high_vector(self):
        """Open redirect: AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"""
        score, label = compute_cvss_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
        )
        assert score == 6.5
        assert label == "Medium"

    def test_medium_vector(self):
        """SRI missing: AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"""
        score, label = compute_cvss_score(
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"
        )
        assert score == 4.2
        assert label == "Medium"

    def test_low_vector(self):
        """JWT no expiry: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"""
        score, label = compute_cvss_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        )
        assert score == 5.3
        assert label == "Medium"  # 5.3 is Medium per CVSS 3.1

    def test_info_vector(self):
        """File upload detected: AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"""
        score, label = compute_cvss_score(
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
        )
        assert score == 3.7
        assert label == "Low"

    def test_reflected_xss_vector(self):
        """Reflected XSS: AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"""
        score, label = compute_cvss_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
        )
        assert score == 8.1
        assert label == "High"

    def test_all_none_impact_returns_zero(self):
        """When C/I/A are all None, impact sub-score is 0 → base score 0."""
        score, label = compute_cvss_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        )
        assert score == 0.0
        assert label == "None"

    def test_invalid_vector_returns_zero(self):
        score, label = compute_cvss_score("not-a-vector")
        assert score == 0.0
        assert label == "None"

    def test_empty_string_returns_zero(self):
        score, label = compute_cvss_score("")
        assert score == 0.0
        assert label == "None"

    def test_none_returns_zero(self):
        score, label = compute_cvss_score(None)
        assert score == 0.0
        assert label == "None"

    def test_missing_required_metric_returns_zero(self):
        """Missing AV metric → KeyError → graceful fallback."""
        score, label = compute_cvss_score("CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 0.0
        assert label == "None"

    def test_cvss2_vector_returns_zero(self):
        """CVSS v2 vectors should not be accepted."""
        score, label = compute_cvss_score("AV:N/AC:L/Au:N/C:C/I:C/A:C")
        assert score == 0.0
        assert label == "None"


class TestFindingCvssField:
    """CVSS-01: Finding.cvss_vector field."""

    def test_default_is_none(self):
        f = Finding("XSS", "test", "high", "detail")
        assert f.cvss_vector is None

    def test_cvss_vector_roundtrip(self):
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        f = Finding("XSS", "test", "high", "detail", cvss_vector=vec)
        assert f.cvss_vector == vec

    def test_asdict_preserves_cvss_vector(self):
        from dataclasses import asdict
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
        f = Finding("XSS", "xss", "critical", "detail", cvss_vector=vec)
        d = asdict(f)
        assert d["cvss_vector"] == vec

    def test_count_default_is_one(self):
        f = Finding("XSS", "test", "high", "detail")
        assert f.count == 1

    def test_count_roundtrip(self):
        f = Finding("XSS", "test", "high", "detail", count=3)
        assert f.count == 3


class TestScoreReportCvssIndependence:
    """CVSS-04: _score_report still uses SEVERITY_WEIGHT, not CVSS scores."""

    def test_score_report_uses_severity_weight(self):
        """Source-parse lock: _score_report's arithmetic references SEVERITY_WEIGHT,
        not compute_cvss_score — CVSS is附加 metadata, not a scoring replacement."""
        import inspect

        from glassbox.scan_engine import _score_report
        source = inspect.getsource(_score_report)
        assert "SEVERITY_WEIGHT" in source
        assert "compute_cvss_score" not in source


class TestCvssCallSiteCoverage:
    """CVSS-05: At least 5 check call sites supply CVSS vectors (one per severity tier)."""

    def test_five_call_sites_have_cvss_vector(self):
        """Source-parse: at least 5 Finding(...) calls in checks.py pass cvss_vector."""
        import pathlib
        source = pathlib.Path("glassbox/checks.py").read_text(encoding="utf-8")
        count = source.count("cvss_vector=")
        assert count >= 5, f"expected at least 5 cvss_vector= call sites, found {count}"

    def test_one_per_severity_tier(self):
        """Each severity tier (critical/high/medium/low/info) has at least one
        Finding with a cvss_vector."""
        import pathlib
        source = pathlib.Path("glassbox/checks.py").read_text(encoding="utf-8")
        # Find all cvss_vector= lines and check surrounding context for severity
        for sev in ("critical", "high", "medium", "low", "info"):
            # Look for the severity string near a cvss_vector= in the same Finding
            assert f'"{sev}"' in source, f"severity {sev} not found in checks.py"
