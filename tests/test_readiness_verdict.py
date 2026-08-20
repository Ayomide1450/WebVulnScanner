"""v1.3 Phase 13 (SCORE-04): unit tests for scan_engine._compute_readiness -
the production-readiness verdict companion to _score_report. Deliberately
kept as its own test module mirroring test_scan_engine.py's own _score_report
section, since _compute_readiness is a new, separate function (not a change
to _score_report's existing, test-locked arithmetic)."""
from webvulnscanner import scan_engine
from webvulnscanner.checks import Finding


def _finding(severity, confidence="Confirmed"):
    return Finding("Cat", "Title", severity, "detail", "", confidence=confidence)


def test_no_findings_and_full_coverage_is_ready():
    verdict, reasons, coverage = scan_engine._compute_readiness([])
    assert verdict == "READY"
    assert coverage is None
    assert reasons


def test_credible_critical_is_not_ready():
    verdict, reasons, _ = scan_engine._compute_readiness([_finding("critical", "Confirmed")])
    assert verdict == "NOT READY"
    assert any("critical" in r for r in reasons)


def test_credible_high_is_ready_with_warnings_not_not_ready():
    verdict, _, _ = scan_engine._compute_readiness([_finding("high", "Strong Evidence")])
    assert verdict == "READY WITH WARNINGS"


def test_low_confidence_critical_does_not_alone_trigger_not_ready():
    """A critical finding whose own check flagged it as merely 'Potential'
    must not gate readiness the same way a credible one does - explicit
    'do not base this only on vulnerability count' requirement."""
    verdict, reasons, _ = scan_engine._compute_readiness([_finding("critical", "Potential")])
    assert verdict == "READY WITH WARNINGS"
    assert verdict != "NOT READY"
    assert any("not yet confidently confirmed" in r for r in reasons)


def test_informational_findings_never_affect_verdict():
    verdict, _, _ = scan_engine._compute_readiness([_finding("info", "Informational")] * 5)
    assert verdict == "READY"


def test_incomplete_coverage_caps_ready_at_warnings_even_with_zero_findings():
    verdict, reasons, coverage = scan_engine._compute_readiness(
        [], locked_count=3, total_check_count=15,
    )
    assert verdict == "READY WITH WARNINGS"
    assert coverage == 80
    assert any("80%" in r for r in reasons)


def test_full_coverage_with_zero_locked_reports_100_percent():
    _, _, coverage = scan_engine._compute_readiness([], locked_count=0, total_check_count=15)
    assert coverage == 100


def test_no_total_check_count_means_coverage_is_none_not_a_fabricated_value():
    """media/api scans have no locked-check concept - coverage_pct must
    stay None, not silently default to 100."""
    _, _, coverage = scan_engine._compute_readiness([_finding("low")])
    assert coverage is None


def test_not_ready_outranks_coverage_and_uncertain_findings():
    """A credible critical must win NOT READY even alongside incomplete
    coverage and uncertain findings - the worst credible signal governs."""
    findings = [_finding("critical", "Confirmed"), _finding("high", "Potential")]
    verdict, reasons, coverage = scan_engine._compute_readiness(
        findings, locked_count=2, total_check_count=10,
    )
    assert verdict == "NOT READY"
    assert len(reasons) >= 2  # critical reason + coverage reason, both surfaced
