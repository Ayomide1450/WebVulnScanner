"""Security Gate evaluation for Glassbox.

The CI/CD-shaped pass/fail verdict over an already-completed scan's
findings: "did this assessment surface anything at or above severity X?"
This is the server-side, single implementation of that decision - the
`glassbox gate` CLI command (cli/wvs.py) calls the /api/v1/scans/<id>/gate
endpoint (api_routes.py), which delegates here, so a non-CLI HTTP consumer
(CI pipeline hitting the API directly) and the CLI can never drift apart in
what counts as "blocking".

Deliberately NOT persistence-backed (no GateVerdict table): the verdict is
a pure function of the stored Report JSON and can be recomputed on demand
forever - persisting it would just create a second copy that can drift from
its own input. This mirrors how _score_report()/_compute_readiness()
(scan_engine.py) are derived, recomputable signals rather than stored ones.

Like those two functions this module is pure: no Flask, no DB, no models
import. It operates on *serialized* findings (the list of dicts a report's
"findings" key holds - see scan_engine._serialize_findings), not Finding
dataclasses, because every caller reads it out of an already-serialized
report blob.
"""
import logging

# The severities a --fail-on threshold may name, most-to-least severe -
# checks.SEVERITY_ORDER minus "pass", since "pass" findings are the absence
# of a problem and can never block a deploy. Kept as its own constant rather
# than imported-and-sliced so the gate's contract is explicit and stable
# even if SEVERITY_ORDER ever grows another non-blocking state.
GATE_SEVERITIES = ["critical", "high", "medium", "low", "info"]

DEFAULT_FAIL_ON = "high"


def evaluate_gate(findings, fail_on=DEFAULT_FAIL_ON):
    """Evaluates `findings` (a report's serialized findings list) against a
    `fail_on` threshold and returns the gate result dict.

    A finding blocks when its severity is at or above `fail_on`
    (critical=most severe -> info=least). Returns::

        {
            "passed": bool,            # True iff nothing blocked
            "fail_on": fail_on,
            "blocking_findings": [...],  # full serialized finding dicts, report order
            "blocking_count": int,
        }

    Semantics kept byte-compatible with the CLI's original client-side
    filter this module replaces:
      - Findings whose severity is missing, unknown, or "pass" never block
        (a malformed severity must not crash a CI pipeline, and "pass"
        findings are not problems).
      - Confidence is deliberately NOT consulted - every finding at or
        above the threshold blocks, matching the documented behavior of the
        command this replaces (`glassbox gate --fail-on high`). Confidence-
        aware gating already exists as a separate signal (_compute_readiness'
        READINESS_GATING_CONFIDENCE); folding it in here silently would
        change the gate's meaning for every existing caller.

    Raises ValueError on a fail_on outside GATE_SEVERITIES - the API route
    validates user input before calling; anything reaching here with a bad
    threshold is a programming error worth surfacing, not absorbing.
    """
    if fail_on not in GATE_SEVERITIES:
        raise ValueError(
            f"invalid fail_on {fail_on!r} - must be one of: {', '.join(GATE_SEVERITIES)}"
        )

    threshold_idx = GATE_SEVERITIES.index(fail_on)
    blocking = []
    for f in findings or []:
        severity = (f.get("severity") or "").lower() if isinstance(f, dict) else None
        if severity not in GATE_SEVERITIES:
            if severity:
                logging.warning("security_gate: ignoring finding with unrecognized severity %r", severity)
            continue
        if GATE_SEVERITIES.index(severity) <= threshold_idx:
            blocking.append(f)

    return {
        "passed": not blocking,
        "fail_on": fail_on,
        "blocking_findings": blocking,
        "blocking_count": len(blocking),
    }
