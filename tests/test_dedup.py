"""Phase 32 (DEDUP-01..04): Finding deduplication.

Tests cover:
- deduplicate_findings() collapses identical findings, preserves first occurrence
- Count field incremented correctly
- Highest severity kept across duplicates (no silent downgrade)
- Deterministic: same input → same output
- Empty list, single finding, all unique, all duplicate scenarios
- CVSS vector preserved from first occurrence
- _score_report regression lock (still uses SEVERITY_WEIGHT, not dedup count)
- Source-parse: all 4 orchestrators call deduplicate_findings before _score_report
"""
from glassbox.checks import Finding, deduplicate_findings


def _mk_finding(category, title, severity="medium", **kw):
    f = Finding(category, title, severity, "detail", **kw)
    return f


class TestDeduplicateFindings:
    """DEDUP-01 + DEDUP-04: core dedup logic."""

    def test_empty_list(self):
        assert deduplicate_findings([]) == []

    def test_single_finding_unchanged(self):
        f = _mk_finding("XSS", "Reflected XSS in param")
        result = deduplicate_findings([f])
        assert len(result) == 1
        assert result[0].count == 1

    def test_all_unique(self):
        findings = [
            _mk_finding("XSS", "XSS in A"),
            _mk_finding("XSS", "XSS in B"),
            _mk_finding("SQLi", "SQLi in C"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 3
        for f in result:
            assert f.count == 1

    def test_all_duplicates(self):
        findings = [
            _mk_finding("XSS", "Reflected XSS in q"),
            _mk_finding("XSS", "Reflected XSS in q"),
            _mk_finding("XSS", "Reflected XSS in q"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0].count == 3

    def test_mixed_duplicates_and_unique(self):
        findings = [
            _mk_finding("XSS", "XSS in A"),
            _mk_finding("XSS", "XSS in A"),
            _mk_finding("XSS", "XSS in B"),
            _mk_finding("SQLi", "SQLi in C"),
            _mk_finding("SQLi", "SQLi in C"),
            _mk_finding("SQLi", "SQLi in C"),
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 3
        counts = {f.title: f.count for f in result}
        assert counts["XSS in A"] == 2
        assert counts["XSS in B"] == 1
        assert counts["SQLi in C"] == 3

    def test_severity_keeps_highest(self):
        """Same finding with different severities → highest severity wins."""
        f_low = _mk_finding("XSS", "XSS in q", severity="low")
        f_high = _mk_finding("XSS", "XSS in q", severity="high")
        f_medium = _mk_finding("XSS", "XSS in q", severity="medium")
        result = deduplicate_findings([f_low, f_high, f_medium])
        assert len(result) == 1
        assert result[0].severity == "high"
        assert result[0].count == 3

    def test_severity_keeps_highest_reversed_order(self):
        """Same test but highest severity comes first."""
        f_high = _mk_finding("XSS", "XSS in q", severity="high")
        f_low = _mk_finding("XSS", "XSS in q", severity="low")
        result = deduplicate_findings([f_high, f_low])
        assert len(result) == 1
        assert result[0].severity == "high"

    def test_different_title_not_deduped(self):
        """Same category but different title → two separate findings."""
        f1 = _mk_finding("XSS", "XSS in /page1")
        f2 = _mk_finding("XSS", "XSS in /page2")
        result = deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_different_category_not_deduped(self):
        """Same title but different category → two separate findings."""
        f1 = _mk_finding("Headers", "Missing HSTS")
        f2 = _mk_finding("CSP", "Missing HSTS")
        result = deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_deterministic_output(self):
        """Same input always produces same output order and counts."""
        findings = [
            _mk_finding("XSS", "XSS in A", severity="medium"),
            _mk_finding("XSS", "XSS in A", severity="high"),
            _mk_finding("SQLi", "SQLi in B"),
        ]
        r1 = deduplicate_findings(findings)
        r2 = deduplicate_findings(findings)
        assert [(f.title, f.severity, f.count) for f in r1] == [
            (f.title, f.severity, f.count) for f in r2
        ]

    def test_cvss_vector_preserved_from_first(self):
        """When first occurrence has a CVSS vector, it's preserved."""
        f1 = _mk_finding("XSS", "XSS in q", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N")
        f2 = _mk_finding("XSS", "XSS in q")  # no CVSS
        result = deduplicate_findings([f1, f2])
        assert result[0].cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"

    def test_cvss_vector_upgraded_on_higher_severity(self):
        """When a higher-severity duplicate has CVSS, the CVSS is upgraded."""
        f1 = _mk_finding("XSS", "XSS in q", severity="low",
                          cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N")
        f2 = _mk_finding("XSS", "XSS in q", severity="critical",
                          cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N")
        result = deduplicate_findings([f1, f2])
        assert result[0].severity == "critical"
        assert result[0].cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"

    def test_first_occurrence_is_kept(self):
        """The first occurrence's non-title fields (detail, recommendation) are kept."""
        f1 = _mk_finding("XSS", "XSS in q")
        f1.detail = "first detail"
        f1.recommendation = "first fix"
        f2 = _mk_finding("XSS", "XSS in q")
        f2.detail = "second detail"
        f2.recommendation = "second fix"
        result = deduplicate_findings([f1, f2])
        assert result[0].detail == "first detail"
        assert result[0].recommendation == "first fix"

    def test_case_insensitive_dedup(self):
        """Same title in different cases should dedup."""
        f1 = _mk_finding("XSS", "XSS in Query")
        f2 = _mk_finding("XSS", "xss in query")
        result = deduplicate_findings([f1, f2])
        assert len(result) == 1
        assert result[0].count == 2


class TestScoreReportDedupIndependence:
    """DEDUP-04 (regression lock): _score_report still uses SEVERITY_WEIGHT."""

    def test_score_report_uses_severity_weight(self):
        import inspect

        from glassbox.scan_engine import _score_report
        source = inspect.getsource(_score_report)
        assert "SEVERITY_WEIGHT" in source
        assert "deduplicate_findings" not in source


class TestDedupWiring:
    """Source-parse: all 4 orchestrators call deduplicate_findings before _score_report."""

    def test_all_four_orchestrators_wired(self):
        import pathlib
        source = pathlib.Path("glassbox/scan_engine.py").read_text(encoding="utf-8")
        lines = source.splitlines()
        # All 4 _score_report calls (excluding def line and docstring refs) should be preceded by deduplicate_findings
        score_lines = [i for i, line in enumerate(lines)
                       if "_score_report(" in line and "def " not in line
                       and '"""' not in line]
        dedup_lines = [i for i, line in enumerate(lines)
                       if "deduplicate_findings(" in line and "import" not in line
                       and '"""' not in line]
        assert len(score_lines) == 4, f"expected 4 _score_report calls, found {len(score_lines)}"
        assert len(dedup_lines) == 4, f"expected 4 deduplicate_findings calls, found {len(dedup_lines)}"
        # Each dedup call should come before a score call
        for si in score_lines:
            assert any(di < si for di in dedup_lines), (
                f"_score_report at line {si} has no preceding deduplicate_findings"
            )

    def test_dedup_import_in_scan_engine(self):
        import pathlib
        source = pathlib.Path("glassbox/scan_engine.py").read_text(encoding="utf-8")
        assert "deduplicate_findings" in source
