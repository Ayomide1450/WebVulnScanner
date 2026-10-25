---
phase: 08-security-re-audit-hardening
plan: 04
subsystem: scanner-engine
tags: [ssrf, requests, redirects, checks.py, scan_engine.py, security]

# Dependency graph
requires:
  - phase: 08-security-re-audit-hardening (08-01, 08-02, 08-03)
    provides: "Green wave-1/wave-2 baseline (683 passed) this plan's Task 1 precondition required before touching production code"
provides:
  - "_SSRFSafeSession(requests.Session) in checks.py, returned by _mk_session() - every one of the 33 request call sites in checks.py and all four scan_engine.py orchestrators now re-validate each redirect hop against is_ssrf_safe_hostname() before it is fetched"
  - "Proof (real local http.server harness, not a mock of the override) that a redirect to loopback/RFC1918/link-local/169.254.169.254 is never fetched, via a recorded server request log"
  - "Proof that legitimate redirects (scheme upgrade, apex-to-www, cross-domain-but-public) are still followed unchanged - the guard only fires on is_ssrf_safe_hostname()==False, never merely because the hostname changed"
  - "A frozen-surface lock proving is_ssrf_safe_hostname()'s source is byte-identical pre/post this plan"
  - "A delegation lock proving _SSRFSafeSession calls is_ssrf_safe_hostname() rather than defining its own address classification"
  - "A per-orchestrator source-parsing lock (D-05 backfill) proving all four orchestrators acquire their session via checks._mk_session() and nowhere else, plus a whole-module bare-requests.Session() ban"
affects: [08-06, 08-07]

actuals:
  tokens: 61000
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Override requests.Session.get_redirect_target() rather than resolve_redirects(): get_redirect_target() is consulted strictly BEFORE a hop is sent, so returning None there stops the chain pre-fetch. resolve_redirects()'s own loop (08-RESEARCH.md's original Assumption A3) sends each hop before yielding it for inspection - filtering what it yields inspects a hop AFTER it was already fetched, which would not have closed SEC-03 at all. This was an empirically-falsified assumption caught by actually running the proof test, not asserted into being true."
    - "Return early (None) from get_redirect_target() to stop a hop rather than raising - matches every check_* function's degrade-cleanly convention; the caller keeps the last known-safe response instead of an exception escaping into a check function."
    - "Per-function inspect.getsource() source-parsing locks (not whole-file grep -c counts) for both the frozen-surface/delegation checks and the D-05 orchestrator-session lock - same technique tests/test_scan_engine.py's pre-existing _score_report lock and tests/test_scheduler.py's no-advanced-branch lock already established in this repo."

key-files:
  created: []
  modified:
    - glassbox/checks.py
    - tests/test_ssrf_guard.py
    - tests/test_sensitive_paths.py
    - tests/test_scan_engine.py

key-decisions:
  - "Overrode get_redirect_target(), not resolve_redirects(), after building and testing the resolve_redirects() approach 08-RESEARCH.md proposed and watching it fail its own real-server proof test - recorded here so a future reader does not re-attempt the same falsified approach."
  - "is_ssrf_safe_hostname() itself was not touched - confirmed via a dedicated frozen-surface source-identity test, not just by review."
  - "D-05's orchestrator-session backfill was scoped narrowly to what SEC-03 actually requires (one new lock in the existing tests/test_scan_engine.py, no new test file) rather than treated as a general coverage expansion - tests/test_scan_engine.py already had 549 lines of orchestrator coverage from Phase 4, so 08-RESEARCH.md's note that CONCERNS.md's 'thin coverage' claim is stale was reconfirmed, not just cited."
  - "Coordinated with plan 08-05's concurrent edit to the same file (glassbox/scan_engine.py, an unrelated new read_report_file() helper below the orchestrators): the new lock is scoped to the four named orchestrator functions plus a whole-module bare-session ban, neither of which a report-reading helper touches. Re-ran green after both plans' worktrees were merged; no collision occurred."

patterns-established:
  - "SSRF-redirect-guard test harness: a real http.server on an ephemeral port in a daemon thread with a recorded request log, used for both the blocked-hop proofs and the legitimate-redirect regression proofs - avoids asserting behavior against a mock of the very mechanism under test."

requirements-completed: [SEC-03]

coverage:
  - id: D1
    description: "A redirect to a loopback/RFC1918/link-local/169.254.169.254 target is never fetched - the check receives the last known-safe response instead"
    requirement: SEC-03
    verification:
      - kind: unit
        ref: "tests/test_ssrf_guard.py (real local http.server harness, recorded request log)"
        status: pass
    human_judgment: false
  - id: D2
    description: "The guard is installed once, in checks._mk_session(), so all 33 request call sites and all four orchestrators inherit it with no per-call-site change"
    requirement: SEC-03
    verification:
      - kind: unit
        ref: "tests/test_scan_engine.py::test_every_orchestrator_acquires_its_session_via_mk_session"
        status: pass
    human_judgment: false
  - id: D3
    description: "is_ssrf_safe_hostname() is called by the guard and is never modified - byte-identical source pre/post this plan"
    requirement: SEC-03
    verification:
      - kind: unit
        ref: "tests/test_ssrf_guard.py (frozen-surface source-identity lock)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Legitimate redirects (scheme upgrade, apex-to-www, cross-domain-but-public) still work - a hostname change alone is never a rejection reason"
    requirement: SEC-03
    verification:
      - kind: unit
        ref: "tests/test_ssrf_guard.py (three legitimate-redirect regression tests)"
        status: pass
    human_judgment: false
  - id: D5
    description: "All four orchestrators construct their session only through _mk_session() - no scan pipeline can acquire an unguarded requests.Session"
    requirement: SEC-03
    verification:
      - kind: unit
        ref: "tests/test_scan_engine.py::test_every_orchestrator_acquires_its_session_via_mk_session, test_scan_engine_module_never_constructs_a_bare_requests_session"
        status: pass
      - kind: manual
        ref: "Negative control: run_api_scan's _mk_session() call replaced with requests.Session(); both locks failed and named run_api_scan; reverted, git diff --stat confirmed empty"
        status: pass
    human_judgment: false
  - id: D6
    description: "Calls already passing allow_redirects=False (checks.py:536, :1049) are unaffected"
    requirement: SEC-03
    verification:
      - kind: unit
        ref: "tests/test_ssrf_guard.py (allow_redirects=False no-op test)"
        status: pass
    human_judgment: false
  - id: D7
    description: "The override delegates to is_ssrf_safe_hostname() rather than defining its own address classification"
    requirement: SEC-03
    verification:
      - kind: unit
        ref: "tests/test_ssrf_guard.py (delegation lock, comment-filtered)"
        status: pass
    human_judgment: false
  - id: D8
    description: "DNS rebinding remains explicitly out of scope - recorded as an accepted residual gap, not silently implied closed"
    requirement: SEC-03
    verification:
      - kind: manual
        ref: "Recorded in this summary and in REQUIREMENTS.md's Out of Scope table; is_ssrf_safe_hostname()'s own docstring already disclaims it"
        status: pass
    human_judgment: false

duration: ~70min
completed: 2026-08-19
status: complete
---

# Phase 8 Plan 04: SSRF-Safe Redirect Guard Summary

**Closed SEC-03, the phase's one confirmed-open vulnerability: `checks._mk_session()` now returns a `_SSRFSafeSession` that re-validates every redirect hop against the existing, unmodified `is_ssrf_safe_hostname()` before fetching it - installed once, inherited by all 33 request call sites and all four scan orchestrators with zero per-call-site changes.**

## Performance

- **Duration:** ~70 min
- **Completed:** 2026-08-19
- **Tasks:** 3 of 3 completed
- **Files modified:** 4

## Accomplishments

- Added `_SSRFSafeSession(requests.Session)` to `checks.py`, overriding `get_redirect_target()` (not `resolve_redirects()` as originally proposed - see Deviations) so a hop is checked *before* it is ever sent; a rejected hop returns `None` from the override, which stops the chain cleanly and hands the caller the last known-safe response, matching every `check_*` function's no-raise convention.
- `_mk_session()` now instantiates `_SSRFSafeSession` instead of a bare `requests.Session`; signature, return shape and the `UA` header are unchanged, so no call site anywhere in `checks.py` needed editing.
- Proved the guard blocks loopback, RFC1918, link-local and `169.254.169.254` redirect targets using a real local `http.server` harness (ephemeral port, daemon thread, recorded request log) - not a mock of the override itself - plus a multi-hop safe-safe-unsafe chain test.
- Proved the guard does **not** over-block: scheme-upgrade (http->https, same host), apex-to-www, and cross-domain-but-public redirects are all still followed - "the hostname changed" is explicitly not a rejection reason (08-RESEARCH.md Pitfall 2).
- Proved `allow_redirects=False` call sites (`checks.py:536`, `:1049`) are unaffected - the 302 comes back unfollowed exactly as before.
- Added a frozen-surface lock: `is_ssrf_safe_hostname()`'s source is byte-identical (line-ending normalized) to its pre-plan baseline, with a failure message naming CLAUDE.md's frozen-surface constraint.
- Added a delegation lock: `_SSRFSafeSession`'s source calls `is_ssrf_safe_hostname()` and defines no independent address classification of its own.
- Added the D-05 backfill: a per-function (`inspect.getsource`), not whole-file-count, lock in `tests/test_scan_engine.py` proving all four orchestrators (`run_scan`, `run_advanced_scan`, `run_media_scan`, `run_api_scan`) acquire their session via `checks._mk_session()` and nowhere else, plus a comment-filtered whole-module ban on bare `requests.Session()` construction. Negative-controlled (see Task 3 commit message for the verbatim failure text) and reverted clean.
- Fixed `tests/test_sensitive_paths.py`'s session-construction assumptions, which broke once `_mk_session()` started returning a `_SSRFSafeSession` subclass - exactly the "candidate for breakage" class Task 2's own action note called out in advance.
- Full suite (`.venv\Scripts\python -m pytest -q`): **700 passed**, 0 failures, run in this plan's own worktree after all three tasks.

## Task Commits

1. **Task 1: SSRF-safe redirect guard in `_mk_session()`, proven end to end against a real server** - `2d9a5ad` (feat)
2. **Task 2: Legitimate-redirect regression coverage and the frozen-surface lock** - `a955fa4` (test)
3. **Task 3: Orchestrator session-construction lock (D-05 backfill)** - `78fb9a1` (test)

## Files Created/Modified

- `glassbox/checks.py` - new `_SSRFSafeSession(requests.Session)` class; `_mk_session()` returns an instance of it instead of a bare `requests.Session`.
- `tests/test_ssrf_guard.py` - grew substantially: blocked-hop proofs (loopback/RFC1918/link-local/metadata), multi-hop chain test, three legitimate-redirect regression tests, the `allow_redirects=False` no-op test, the frozen-surface lock, and the delegation lock.
- `tests/test_sensitive_paths.py` - session-construction assumptions updated for the `_SSRFSafeSession` subclass change.
- `tests/test_scan_engine.py` - two new tests: `test_every_orchestrator_acquires_its_session_via_mk_session` and `test_scan_engine_module_never_constructs_a_bare_requests_session`.

## Decisions Made

- **Overrode `get_redirect_target()`, not `resolve_redirects()`.** 08-RESEARCH.md's Assumption A3 proposed overriding `resolve_redirects()`; that approach was actually built and tested against the real-server harness, and failed - `resolve_redirects()`'s own loop sends each hop before yielding it for inspection, so filtering what it yields inspects a hop that was *already fetched*, which does not close SEC-03. `get_redirect_target()` is consulted strictly before a hop is sent, so returning `None` there genuinely stops the chain pre-fetch. Recorded here specifically so a future reader does not re-attempt the falsified approach.
- `is_ssrf_safe_hostname()` was read but not touched, confirmed by a dedicated source-identity test rather than by review alone.
- D-05's orchestrator-session backfill was scoped to exactly what SEC-03 needs - one new lock in the existing `tests/test_scan_engine.py` (already 549 lines from Phase 4) - not treated as an invitation to expand test coverage generally, per `08-CONTEXT.md` D-05's explicit instruction.
- Coordinated with plan 08-05, which concurrently added an unrelated `read_report_file()` helper to the same file (`scan_engine.py`) in this wave: the new lock is scoped to the four named orchestrator functions plus a whole-module bare-session ban, neither of which a report-reading helper can disturb. Re-ran green after both plans' work was present in the merged tree.

## Deviations from Plan

### Rule 3 (approach correction within task scope)

Task 1's read-first research (08-RESEARCH.md Assumption A3) proposed overriding `requests.Session.resolve_redirects()`. That was implemented first and run against the real local-server proof test - it failed: `resolve_redirects()` sends each redirect hop over the wire as part of producing the generator's next value, so intercepting what the generator yields means the unsafe request already happened. Switched to overriding `get_redirect_target()` instead, which `resolve_redirects()` calls to decide whether/where to hop *before* sending anything - returning `None` from it stops the loop pre-fetch. This is exactly the kind of "assumption executed and found wrong, approach changed" outcome 08-RESEARCH.md's own Open Questions section anticipated might happen; the plan's `must_haves.statements` entry for this assumption is satisfied by this correction, not contradicted by it.

## Negative Controls Performed

Recorded verbatim in the Task 3 commit message (`78fb9a1`): `run_api_scan`'s `_mk_session()` call was temporarily replaced with `requests.Session()`; both new `test_scan_engine.py` locks failed and named `run_api_scan` specifically; four pre-existing `run_api_scan` tests also failed as an expected side effect of the mutation itself. Reverted; `git diff --stat glassbox/scan_engine.py` confirmed empty afterward. Task 2's frozen-surface and delegation locks were similarly negative-controlled during authoring (per-task action notes); see `tests/test_ssrf_guard.py`'s own test bodies for what each asserts.

## Residual Gap (accepted, not closed by this plan)

DNS rebinding is explicitly out of scope: a hostname that resolves to a safe address at guard-check time and a different (unsafe) address at actual connect time is not covered by this plan or by `is_ssrf_safe_hostname()` generally - its own docstring already disclaims this, and `REQUIREMENTS.md`'s Out of Scope table excludes it from this milestone. Not a backstop deferred to later in this phase.

## Issues Encountered

None beyond the resolve_redirects->get_redirect_target correction recorded above.
