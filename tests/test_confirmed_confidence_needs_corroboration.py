"""Regression lock for the check_http_methods false-positive class (fixed in
f2dc05a): a `Finding(..., confidence="Confirmed")` gated by nothing but a
bare HTTP status-code comparison overclaims certainty - a method-agnostic
router, CDN, or SPA fallback can produce any status code without the
condition actually being true. "Confirmed" must be corroborated by
something more than "the status code wasn't in my rejection list" -
a content/body match, a baseline diff, a reflected canary, an explicit
header value, etc.

Static, AST-based, same "coverage lock over hand-authored code" pattern as
test_finding_confidence.py/CHECK_COMPLIANCE/CHECK_LABELS - walks the real
source rather than exercising runtime behavior, so it catches a *new*
check making this exact mistake before it ships, not just this one.

What counts as "bare": the nearest enclosing `if`/`elif` test is a single
`Compare` (optionally negated) whose left-hand side is a `.status_code`
attribute access, with no `and`/`or` combining it with any other
condition. `if r.status_code == 200 and re.search(...)` is fine (compound
condition - the `and` clause is dropped in the current per-check
allowlist below only when it's genuinely a bare code-only gate).
"""
import ast
import pathlib

CHECKS_PY = pathlib.Path(__file__).resolve().parent.parent / "webvulnscanner" / "checks.py"

# Call sites that intentionally gate "Confirmed" on nothing but a bare
# status-code comparison, with the corroboration living in a DIFFERENT
# statement earlier in the same function (so it isn't visible in the same
# `if` test AST-locally) - each entry names the real evidence and why a
# same-line `and` isn't how it's expressed. Add here only with a one-line
# justification; do not add an entry just to silence a genuine miss.
ALLOWLISTED_LINES = {
    # check_open_ports: severity/confidence live entirely outside this
    # module's Finding(...) call shape (constructed in scan_engine.py from
    # already-corroborated port-scan data, not a raw response-status gate).
}


def _iter_functions(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            yield node


def _is_status_code_attr(node):
    return isinstance(node, ast.Attribute) and node.attr == "status_code"


def _is_bare_status_code_test(test):
    """True iff `test` is only a status_code comparison - no and/or with
    anything else. Handles both `x == y` and `x != y` / `x in (...)` /
    `x not in (...)` shapes, and a leading `not (...)` wrapper."""
    node = test
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        node = node.operand
    if not isinstance(node, ast.Compare):
        return False
    return _is_status_code_attr(node.left)


def _confidence_kwarg_value(call):
    for kw in call.keywords:
        if kw.arg == "confidence" and isinstance(kw.value, ast.Constant):
            return kw.value.value
    return None


def _find_enclosing_if_test(fn_node, target_call):
    """Walks fn_node looking for the innermost If/elif whose body contains
    target_call (by identity via line range), returns its test node or
    None if the call isn't inside any If."""
    best = None
    for node in ast.walk(fn_node):
        if isinstance(node, ast.If):
            # A call "belongs" to this If if it falls within the If node's
            # own line span and the If has no further-nested If also
            # containing it (approximated by taking the narrowest span).
            if node.lineno <= target_call.lineno <= (node.end_lineno or node.lineno):
                if best is None or (node.end_lineno - node.lineno) < (best.end_lineno - best.lineno):
                    best = node
    return best.test if best else None


def test_confirmed_findings_are_not_gated_by_a_bare_status_code_check():
    tree = ast.parse(CHECKS_PY.read_text(encoding="utf-8"))
    violations = []

    for fn in _iter_functions(tree):
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Finding"):
                continue
            if _confidence_kwarg_value(node) != "Confirmed":
                continue
            if node.lineno in ALLOWLISTED_LINES:
                continue
            test_expr = _find_enclosing_if_test(fn, node)
            if test_expr is not None and _is_bare_status_code_test(test_expr):
                violations.append((fn.name, node.lineno))

    assert not violations, (
        "Finding(..., confidence='Confirmed') gated by nothing but a bare "
        "status-code comparison - the exact check_http_methods false-positive "
        "class fixed in f2dc05a (a method-agnostic router/CDN/SPA fallback can "
        "produce any status code without the claimed condition being true). "
        "Either corroborate with a content/body match, baseline diff, "
        "reflected canary, or explicit header - or downgrade to "
        "confidence='Potential' if that corroboration genuinely isn't "
        f"available. Violations (function, line): {violations}"
    )
