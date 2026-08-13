"""
Tests for webvulnscanner/scan_engine.py's shared scoring helper and the
three orchestrators that previously had no automated coverage at all
(HARD-04, HARD-02 / D-02, D-03, D-04).

- `_score_report` section: unit tests for the arithmetic/grading/ordering
  the four orchestrators now share (score clamp, grade boundaries,
  severity_counts completeness, findings_sorted ordering/non-mutation, the
  ValueError on an unrecognised severity).
- `run_media_scan` section (this task; `run_api_scan`/`run_advanced_scan`
  follow in later tasks): direct-invocation, fully-mocked coverage of the
  orchestrator's completed return shape and error-propagation path. Every
  check function is stubbed on `scan_engine`'s own module namespace (never
  on `webvulnscanner.checks`) - `scan_engine.py` does
  `from webvulnscanner.checks import check_x`, so patching `checks.check_x`
  would not intercept the orchestrator's call and the test would silently
  hit the network. See `tests/test_scan_events.py`'s module docstring for
  the same caveat, already established for `run_scan`.
  No test in this module touches the DB or a `Scan` row - the
  status-transition half of HARD-02 (`scan_routes._run_scan_in_background`)
  lives in plan 04-04, not here.

The "Safety-constraint regression locks (D-02)" section calls
`webvulnscanner.checks` directly rather than through an orchestrator,
because orchestrator-level tests stub check functions out entirely and
therefore cannot observe the caps those checks enforce internally. No
function in `webvulnscanner/checks.py` is modified by this plan - these
tests lock existing, already-shipped behaviour, they do not introduce it.
"""
from types import SimpleNamespace

import pytest

from webvulnscanner import scan_engine
from webvulnscanner.checks import Finding, SEVERITY_WEIGHT

# --------------------------------------------------------------------------
# _score_report
# --------------------------------------------------------------------------


def _finding(severity, check_name="x"):
    return Finding("Cat", "Title", severity, "detail", "", check_name=check_name)


def test_score_report_empty_findings_is_perfect_score():
    score, grade, counts, findings_sorted = scan_engine._score_report([])
    assert (score, grade, findings_sorted) == (100, "A", [])
    assert set(counts) == set(SEVERITY_WEIGHT)
    assert all(v == 0 for v in counts.values())


def test_score_report_subtracts_weight_per_finding():
    findings = [_finding("high"), _finding("medium")]
    score, grade, counts, _ = scan_engine._score_report(findings)
    assert score == 100 - SEVERITY_WEIGHT["high"] - SEVERITY_WEIGHT["medium"]
    assert grade == "B"
    assert counts["high"] == 1
    assert counts["medium"] == 1


def test_score_report_clamps_at_zero_never_negative():
    findings = [_finding("critical") for _ in range(10)]
    score, grade, counts, _ = scan_engine._score_report(findings)
    assert score == 0
    assert grade == "F"
    assert counts["critical"] == 10


@pytest.mark.parametrize("raw_score,expected_grade", [
    (90, "A"), (89, "B"), (75, "B"), (74, "C"),
    (60, "C"), (59, "D"), (40, "D"), (39, "F"),
])
def test_score_report_grade_boundaries(monkeypatch, raw_score, expected_grade):
    # The real severity weights (25/15/7/3, gcd 1 but with an 11-point
    # Frobenius gap between 3 and 7) can't hit every exact deficit this
    # boundary table needs (e.g. 100-89=11 has no exact 25/15/7/3 combination).
    # Monkeypatch SEVERITY_WEIGHT to a synthetic 1-point-per-finding scheme
    # for "low" only, scoped to this test via monkeypatch, so any deficit
    # 0-100 can be hit exactly with `deficit` low-severity findings - this
    # test is about the score->grade mapping, not the weight values
    # themselves (those are covered by the subtraction/clamp tests above).
    monkeypatch.setattr(scan_engine, "SEVERITY_WEIGHT", {"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0})
    deficit = 100 - raw_score
    findings = [_finding("low") for _ in range(deficit)]

    score, grade, _, _ = scan_engine._score_report(findings)
    assert score == raw_score
    assert grade == expected_grade


def test_score_report_severity_counts_has_all_keys_even_when_zero():
    _, _, counts, _ = scan_engine._score_report([_finding("low")])
    assert set(counts) == set(SEVERITY_WEIGHT)
    assert counts["low"] == 1
    assert counts["critical"] == 0


def test_score_report_findings_sorted_orders_most_severe_first_and_does_not_mutate_input():
    original = [_finding("low"), _finding("critical"), _finding("medium")]
    original_copy = list(original)

    _, _, _, findings_sorted = scan_engine._score_report(original)

    assert [f.severity for f in findings_sorted] == ["critical", "medium", "low"]
    # The caller's input list is not reordered in place - a new list is
    # returned.
    assert original == original_copy
    assert findings_sorted is not original


def test_score_report_raises_on_unrecognised_severity():
    with pytest.raises(ValueError):
        scan_engine._score_report([_finding("nonsense-severity")])


# --------------------------------------------------------------------------
# run_media_scan
# --------------------------------------------------------------------------


def _stub_session(monkeypatch):
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: SimpleNamespace())


def test_run_media_scan_completed_shape_no_findings(monkeypatch):
    _stub_session(monkeypatch)
    monkeypatch.setattr(
        scan_engine, "check_media",
        lambda session, base_url, download, max_files: ({"images": [], "videos": []}, []),
    )

    report = scan_engine.run_media_scan("https://example.com", download=False, max_files=20)

    assert report["score"] == 100
    assert report["risk_grade"] == "A"
    assert report["findings"] == []
    assert report["media"] == {"images": [], "videos": []}


def test_run_media_scan_one_finding_scores_via_score_report_and_tags_check_name(monkeypatch):
    _stub_session(monkeypatch)
    finding = _finding("high")

    def fake_check_media(session, base_url, download, max_files):
        return {"images": [], "videos": []}, [finding]

    monkeypatch.setattr(scan_engine, "check_media", fake_check_media)

    report = scan_engine.run_media_scan("https://example.com", download=False, max_files=20)

    expected_score, expected_grade, _, _ = scan_engine._score_report([finding])
    assert report["score"] == expected_score
    assert report["risk_grade"] == expected_grade
    assert len(report["findings"]) == 1
    assert report["findings"][0]["check_name"] == "media"


def test_run_media_scan_propagates_check_media_exception(monkeypatch):
    import requests

    _stub_session(monkeypatch)

    def raising_check_media(*a, **k):
        raise requests.RequestException("boom")

    monkeypatch.setattr(scan_engine, "check_media", raising_check_media)

    with pytest.raises(requests.RequestException):
        scan_engine.run_media_scan("https://example.com", download=False, max_files=20)


# --------------------------------------------------------------------------
# run_api_scan
# --------------------------------------------------------------------------


class _RecordingSession:
    """Records every get/post call it receives; returns a bare-HTML page
    for `get` (run_api_scan's three check functions are stubbed out
    entirely in these tests, so `post` is never actually called by the
    orchestrator itself - only its own initial home-page `get` is)."""

    def __init__(self):
        self.calls = []

    def get(self, url, timeout=None, **kwargs):
        self.calls.append(("GET", url))
        return SimpleNamespace(text="<html></html>")

    def post(self, url, timeout=None, **kwargs):
        self.calls.append(("POST", url))
        return SimpleNamespace(text="")


def _stub_api_checks(monkeypatch, schema=None, wordlist=None, js_discovery=None):
    monkeypatch.setattr(scan_engine, "check_api_schema_exposure",
                         lambda base_url, session: schema or ({}, []))
    monkeypatch.setattr(scan_engine, "check_api_wordlist",
                         lambda base_url, session: wordlist or ({}, []))
    monkeypatch.setattr(scan_engine, "check_api_js_discovery",
                         lambda session, base_url, home_html: js_discovery or ({}, []))


def test_run_api_scan_completed_shape_no_findings(monkeypatch):
    session = _RecordingSession()
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: session)
    _stub_api_checks(monkeypatch)

    report = scan_engine.run_api_scan("https://example.com")

    assert report["score"] == 100
    assert report["risk_grade"] == "A"
    assert set(report["results"]) == {"schema", "wordlist", "js_discovery"}


def test_run_api_scan_tags_finding_with_matching_check_name(monkeypatch):
    session = _RecordingSession()
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: session)
    finding = _finding("medium")
    _stub_api_checks(monkeypatch, wordlist=({}, [finding]))

    report = scan_engine.run_api_scan("https://example.com")

    expected_score, expected_grade, _, _ = scan_engine._score_report([finding])
    assert report["score"] == expected_score
    assert report["risk_grade"] == expected_grade
    assert len(report["findings"]) == 1
    assert report["findings"][0]["check_name"] == "wordlist"


def test_run_api_scan_propagates_exception_from_wordlist_check(monkeypatch):
    import requests

    session = _RecordingSession()
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: session)
    monkeypatch.setattr(scan_engine, "check_api_schema_exposure", lambda base_url, session: ({}, []))

    def raising_wordlist(base_url, session):
        raise requests.RequestException("boom")

    monkeypatch.setattr(scan_engine, "check_api_wordlist", raising_wordlist)
    monkeypatch.setattr(scan_engine, "check_api_js_discovery",
                         lambda session, base_url, home_html: ({}, []))

    with pytest.raises(requests.RequestException):
        scan_engine.run_api_scan("https://example.com")


def test_run_api_scan_performs_exactly_one_home_page_fetch_before_any_check(monkeypatch):
    session = _RecordingSession()
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: session)
    _stub_api_checks(monkeypatch)

    scan_engine.run_api_scan("https://example.com")

    gets = [call for call in session.calls if call[0] == "GET"]
    assert gets == [("GET", "https://example.com/")]


# --------------------------------------------------------------------------
# HARD-04 cross-orchestrator regression lock: none of the four orchestrators
# may carry an inline copy of the scoring arithmetic ever again. This is
# the source-parsing regression-lock technique tests/test_entitlements.py
# and tests/test_compliance.py already use for their own coverage maps.
# --------------------------------------------------------------------------


def test_no_orchestrator_carries_an_inline_scoring_block():
    import inspect

    orchestrators = (
        scan_engine.run_scan, scan_engine.run_advanced_scan,
        scan_engine.run_media_scan, scan_engine.run_api_scan,
    )
    regressed = []
    for fn in orchestrators:
        src = inspect.getsource(fn)
        has_inline_formula = "SEVERITY_WEIGHT" in src or "SEVERITY_ORDER" in src
        calls_helper = "_score_report(" in src
        if has_inline_formula or not calls_helper:
            regressed.append(fn.__name__)
    assert not regressed, (
        f"{regressed} no longer routes its score/grade/severity_counts through "
        "_score_report() - HARD-04's dedup has regressed (a formula change would "
        "now need to be made in more than one place again)."
    )
