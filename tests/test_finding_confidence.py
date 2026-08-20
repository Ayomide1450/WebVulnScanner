"""v1.3 Phase 12 (FSCH-01..05): coverage lock proving every real `Finding(...)`
construction site in checks.py passes an explicit `confidence=` keyword drawn
from `CONFIDENCE_LEVELS`, and that the dataclass itself carries the new
confidence/cwe/verification_state fields with the expected shape.

Static, AST-based - not a runtime default check. FSCH-04's requirement is
that no call site is left on a silent/implicit default; the class-level
default on `Finding.confidence` exists only for ad-hoc construction outside
this file (see checks.py's own comment on the field), so a runtime check
of the default wouldn't prove anything about the real call sites. Walking
the actual source with `ast` is the same "coverage lock over hand-authored
code" pattern this repo already uses for CHECK_COMPLIANCE/CHECK_LABELS/
FEATURE_REQUIREMENTS.
"""
import ast
import pathlib

from webvulnscanner.checks import CONFIDENCE_LEVELS, Finding

CHECKS_PY = pathlib.Path(__file__).resolve().parent.parent / "webvulnscanner" / "checks.py"


def _find_finding_calls(tree):
    """Every ast.Call node whose function is the bare name `Finding`."""
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Finding":
            calls.append(node)
    return calls


def _confidence_kwarg(call):
    for kw in call.keywords:
        if kw.arg == "confidence":
            return kw
    return None


def test_every_finding_call_site_passes_an_explicit_confidence_kwarg():
    tree = ast.parse(CHECKS_PY.read_text(encoding="utf-8"))
    calls = _find_finding_calls(tree)
    assert len(calls) >= 50, (
        f"expected ~50+ Finding(...) call sites in checks.py, found {len(calls)} - "
        "this test's own discovery logic may be broken, not just the coverage"
    )

    missing = []
    for call in calls:
        kw = _confidence_kwarg(call)
        if kw is None:
            missing.append(call.lineno)

    assert not missing, (
        f"Finding(...) call site(s) at line(s) {missing} in checks.py have no explicit "
        "confidence= kwarg - every real finding must state how certain the check is, "
        "not rely on the class-level default"
    )


def test_every_finding_call_site_confidence_value_is_a_known_literal_in_confidence_levels():
    tree = ast.parse(CHECKS_PY.read_text(encoding="utf-8"))
    calls = _find_finding_calls(tree)

    bad = []
    for call in calls:
        kw = _confidence_kwarg(call)
        if kw is None:
            continue  # already caught by the sibling test
        if not (isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str)):
            bad.append((call.lineno, "non-string-literal confidence value"))
            continue
        if kw.value.value not in CONFIDENCE_LEVELS:
            bad.append((call.lineno, kw.value.value))

    assert not bad, f"Finding(...) call site(s) using a confidence value outside CONFIDENCE_LEVELS: {bad}"


def test_finding_dataclass_has_the_new_v1_3_fields_with_safe_defaults():
    f = Finding(category="Test", title="t", severity="info", detail="d")
    assert f.confidence in CONFIDENCE_LEVELS
    assert f.cwe is None
    assert f.verification_state is None

    f2 = Finding(
        category="Test", title="t", severity="critical", detail="d",
        confidence="Confirmed", cwe="CWE-79", verification_state="Confirmed Finding",
    )
    assert f2.confidence == "Confirmed"
    assert f2.cwe == "CWE-79"
    assert f2.verification_state == "Confirmed Finding"


def test_confidence_levels_never_includes_a_severity_word():
    """Guards the FSCH-01 separation-of-concerns rule at the constant level:
    confidence and severity are different axes, so the confidence vocabulary
    must never reuse a severity word (critical/high/medium/low/info/pass) -
    that would make it trivially easy to conflate "how bad" with "how sure"
    in a future call site."""
    severity_words = {"critical", "high", "medium", "low", "info", "pass"}
    for level in CONFIDENCE_LEVELS:
        assert level.lower() not in severity_words, f"{level!r} collides with a severity word"
