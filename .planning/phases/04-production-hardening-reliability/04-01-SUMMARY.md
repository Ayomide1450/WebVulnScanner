---
phase: 04-production-hardening-reliability
plan: 01
subsystem: testing
tags: [pytest, scan_engine, scoring, orchestrators, regression-lock]

requires:
  - phase: 03-compliance-framework-reporting
    provides: stable four-orchestrator scan_engine.py (run_scan/run_advanced_scan/run_media_scan/run_api_scan) with no test coverage gaps addressed yet
provides:
  - "scan_engine._score_report(findings) - the single scoring implementation (score/risk_grade/severity_counts/findings_sorted) shared by all four orchestrators"
  - "tests/test_scan_engine.py - direct-invocation, network-free coverage for run_media_scan/run_api_scan/run_advanced_scan (previously zero automated coverage) plus safety-constraint regression locks on check_bruteforce's cap and check_xss_stored's marker-only proof"
  - "Source-parsing regression lock proving no orchestrator can silently re-inline the scoring formula"
affects: [04-04-orchestrator-scheduler-testing, 04-05-documentation-and-visual-consistency]

actuals:
  tokens: 7343
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Direct-invocation orchestrator testing: monkeypatch every check_* function on scan_engine's own module namespace (never checks.check_x), matching tests/test_scan_events.py's documented binding-location caveat"
    - "Safety-constraint regression locks live beside the orchestrator they protect (tests/test_scan_engine.py), calling webvulnscanner.checks directly since orchestrator-level tests stub every check out entirely"
    - "Source-parsing regression lock (inspect.getsource + string search) to guard against silent re-inlining of shared logic, mirroring tests/test_entitlements.py's / tests/test_compliance.py's coverage-map technique"

key-files:
  created:
    - tests/test_scan_engine.py
  modified:
    - webvulnscanner/scan_engine.py

key-decisions:
  - "_score_report returns a 4-tuple (score, risk_grade, severity_counts, findings_sorted), folding in findings_sorted rather than CONCERNS.md's suggested 3-tuple, since that sort line was also duplicated identically at all four call sites (04-RESEARCH.md A1)"
  - "run_advanced_scan tested via direct invocation only (D-04) - scheduler._fire() has no \"advanced\" branch and Asset stores no credentials for an unattended run; a one-line comment above the function documents this by design"
  - "Grade-boundary parametrized test monkeypatches SEVERITY_WEIGHT to a synthetic 1-point-per-finding scheme rather than using the real 25/15/7/3 weights, because deficit=11 (raw_score=89) has no exact combination of the real weights (Frobenius gap between 3 and 7) - the test is about the score-to-grade mapping, not the weight values, which are already covered by the subtraction/clamp tests"
  - "CLAUDE.md's Scoring section (\"duplicated four times... needs updating in all four places\") is now stale after this plan - left for 04-05's documentation-reconciliation task per this plan's action item 4, which owns CLAUDE.md end-to-end in wave 2"

patterns-established:
  - "Mutation-proof discipline for regression locks: before finalizing a safety-constraint or dedup lock, temporarily weaken the production code, confirm the new test fails, then revert and confirm the test passes and the file is byte-identical to its pre-mutation state (verified via git diff --stat showing no change)"

requirements-completed: [HARD-04, HARD-02]

coverage:
  - id: D1
    description: "scan_engine._score_report() extracted as the single scoring implementation; all four orchestrators (run_scan/run_advanced_scan/run_media_scan/run_api_scan) call it and none retains an inline copy of the score/grade/severity_counts/findings_sorted arithmetic"
    requirement: "HARD-04"
    verification:
      - kind: unit
        ref: "tests/test_scan_engine.py::test_score_report_empty_findings_is_perfect_score"
        status: pass
      - kind: unit
        ref: "tests/test_scan_engine.py::test_no_orchestrator_carries_an_inline_scoring_block"
        status: pass
    human_judgment: false
  - id: D2
    description: "run_media_scan/run_api_scan/run_advanced_scan each get automated, fully-mocked test coverage of their completed return shape and error-propagation path (matching what run_scan already had)"
    requirement: "HARD-02"
    verification:
      - kind: unit
        ref: "tests/test_scan_engine.py::test_run_media_scan_completed_shape_no_findings"
        status: pass
      - kind: unit
        ref: "tests/test_scan_engine.py::test_run_api_scan_completed_shape_no_findings"
        status: pass
      - kind: unit
        ref: "tests/test_scan_engine.py::test_run_advanced_scan_all_allowed_runs_every_group_and_locks_nothing"
        status: pass
    human_judgment: false
  - id: D3
    description: "Safety-constraint regression locks: check_bruteforce never exceeds MAX_BRUTEFORCE_ATTEMPTS and stops on first success without leaking the password; check_xss_stored contacts only the submit/view hosts and never sends the supplied cookie elsewhere"
    requirement: "HARD-02"
    verification:
      - kind: unit
        ref: "tests/test_scan_engine.py::test_check_bruteforce_never_exceeds_max_attempts"
        status: pass
      - kind: unit
        ref: "tests/test_scan_engine.py::test_check_bruteforce_stops_on_first_success_and_withholds_password_in_detail"
        status: pass
      - kind: unit
        ref: "tests/test_scan_engine.py::test_check_xss_stored_contacts_only_submit_and_view_hosts_no_cookie_exfiltration"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-08-13
status: complete
---

# Phase 4 Plan 1: Shared Scoring Helper + Orchestrator Test Coverage Summary

**Deduplicated the four-times-copy-pasted scoring arithmetic into `scan_engine._score_report()` and closed the automated-test gap on `run_advanced_scan`/`run_media_scan`/`run_api_scan`, including regression locks on the brute-force attempt cap and the stored-XSS marker-only proof.**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-08-13T16:10Z (context read)
- **Completed:** 2026-08-13T17:09Z (last commit)
- **Tasks:** 3/3 completed
- **Files modified:** 2 (`webvulnscanner/scan_engine.py`, `tests/test_scan_engine.py` new)

## Accomplishments

- Extracted `_score_report(findings)` as the single scoring implementation (score/risk_grade/severity_counts/findings_sorted); all four orchestrators route through it and none retains an inline copy — a source-parsing regression test fails loudly if that ever changes.
- `run_media_scan`, `run_api_scan`, and `run_advanced_scan` each gained direct-invocation, fully-mocked test coverage of their completed return shape, per-check finding tagging, and error-propagation path — closing HARD-02's orchestrator-level gap for the three scan types that previously had zero automated coverage.
- `run_advanced_scan`'s five-group lock/run matrix is covered at, below, and beside the required tier, plus the empty-form "silently skipped, not locked" edge case (04-RESEARCH.md Pitfall 5).
- Locked the app's most sensitive safety constraints with dedicated regression tests calling `webvulnscanner.checks` directly: `check_bruteforce`'s `MAX_BRUTEFORCE_ATTEMPTS` cap and stop-on-first-success behavior, and `check_xss_stored`'s marker-only proof with no cookie exfiltration to any other host.
- Two independent mutation proofs (temporarily re-inlining the scoring formula; temporarily widening the brute-force cap) confirmed the new regression tests actually fail when the underlying guarantee is weakened, then confirmed a clean revert restores a byte-identical file and a passing suite.

## Task Commits

Each task was committed atomically:

1. **Task 1: End-to-end "one shared scoring helper, proven through a real orchestrator"** - `c32bc4f` (feat) — `_score_report` added, `run_media_scan` rewritten to use it, `tests/test_scan_engine.py` created with `_score_report` arithmetic tests and `run_media_scan` coverage (17 tests)
2. **Task 2: Route the remaining three orchestrators through the helper and cover run_api_scan** - `c5db2c8` (feat) — `run_api_scan`/`run_advanced_scan`/`run_scan` rewritten to use `_score_report`; `run_api_scan` coverage and the cross-orchestrator source-parsing regression lock added (22 tests)
3. **Task 3: run_advanced_scan coverage plus the safety-constraint regression locks** - `a824847` (test) — `run_advanced_scan`'s full lock/run matrix, D-04 scheduler-dispatch comment, and the three D-02 safety-constraint regression locks (32 tests)

**Plan metadata:** (this commit, following)

## Files Created/Modified

- `webvulnscanner/scan_engine.py` — added `_score_report(findings)`; all four orchestrators (`run_scan`, `run_advanced_scan`, `run_media_scan`, `run_api_scan`) now call it instead of carrying an inline copy of the score/grade/severity_counts/findings_sorted arithmetic; added a one-line comment above `run_advanced_scan` documenting its scheduler-dispatch-free design (D-04)
- `tests/test_scan_engine.py` (new, 549 lines, 32 tests) — `_score_report` unit tests; `run_media_scan`/`run_api_scan`/`run_advanced_scan` direct-invocation tests; the HARD-04 cross-orchestrator regression lock; the D-02 safety-constraint regression locks against `checks.check_bruteforce` and `checks.check_xss_stored`

## Decisions Made

- `_score_report`'s 4-tuple return (folding in `findings_sorted`) over CONCERNS.md's suggested 3-tuple — see key-decisions above.
- `run_advanced_scan` tested via direct invocation only, by design (D-04) — no scheduler-fired test exists or is expected for it.
- Grade-boundary test monkeypatches `SEVERITY_WEIGHT` to a synthetic weight scheme rather than trying to hit every boundary with the real 25/15/7/3 weights (see key-decisions above for why 11 is unreachable with the real weights).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `_RecordingAuthSession` initially stubbed `.post()`, but `check_bruteforce` calls `_timed_request`, which always goes through `session.request(...)`**
- **Found during:** Task 3, running the brute-force cap regression tests
- **Issue:** The fake session's `post` method was never invoked — `checks._timed_request(session, "POST", url, ...)` calls `session.request(method, url, ...)` internally, not `session.post` directly, so the test's recording list stayed empty and raised `AttributeError: '_RecordingAuthSession' object has no attribute 'request'`.
- **Fix:** Renamed the fake session's method from `post` to `request` (matching `_timed_request`'s actual call signature: `session.request(method, url, timeout=..., **kwargs)`), added a comment noting why.
- **Files modified:** `tests/test_scan_engine.py`
- **Verification:** `test_check_bruteforce_never_exceeds_max_attempts` and `test_check_bruteforce_stops_on_first_success_and_withholds_password_in_detail` both pass; mutation proof (widening the cap) confirmed the cap test actually fails when the guarantee is weakened.
- **Committed in:** `a824847` (part of Task 3's commit — caught and fixed before that commit, not a follow-up)

**2. [Rule 1 - Bug] Grade-boundary parametrized test's initial construction (greedy 25/15/7/3 weight decomposition) failed to reach an exact deficit of 11**
- **Found during:** Task 1, writing the `_score_report` grade-boundary tests
- **Issue:** `100 - 89 = 11` has no non-negative integer combination of the real severity weights `{25, 15, 7, 3}` (the Frobenius/coin-problem gap between coprime 3 and 7 is 11) — a greedy construction silently left a nonzero remainder, which the test's own assertion (`assert remaining == 0`) would have caught at test-collection time, not silently passed with a wrong score.
- **Fix:** Monkeypatched `scan_engine.SEVERITY_WEIGHT` (scoped to the test via `monkeypatch`) to a synthetic 1-point-per-finding scheme for `"low"` severity only, so any deficit 0-100 is trivially exact — the test is about the score-to-grade mapping, which doesn't depend on the specific weight values (those are covered separately by the subtraction/clamp tests).
- **Files modified:** `tests/test_scan_engine.py`
- **Verification:** All 8 grade-boundary parametrized cases pass.
- **Committed in:** `c32bc4f` (part of Task 1's commit)

---

**Total deviations:** 2 auto-fixed (both Rule 1 — bugs in the new test code itself, caught before committing, not in production code)
**Impact on plan:** No scope creep; both fixes were necessary to make the new tests correct and were resolved before each task's commit landed.

## Issues Encountered

None beyond the two auto-fixed test-authoring bugs documented above.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- HARD-04 is fully satisfied: one shared `_score_report()` helper, used by all four orchestrators, with a regression test that fails if the formula is ever re-inlined.
- HARD-02's orchestrator-level half is satisfied: `run_advanced_scan`/`run_media_scan`/`run_api_scan` now have direct-invocation, fully-mocked coverage of their completed/error paths, matching what `run_scan` already had. Plan 04-04 (per this phase's artifact-ownership table) still owns the scheduler-fired `media`/`api` tests and the `_run_scan_in_background` status-transition tests — those are a distinct, complementary slice of HARD-02, not duplicated here.
- Plan 04-05's documentation-reconciliation task needs to update `CLAUDE.md`'s "Scoring" section, which currently states the block is "duplicated four times... needs updating in all four places" — that statement is now stale.
- No blockers for 04-02/04-03/04-04/04-05 — this plan touched only `webvulnscanner/scan_engine.py` and added a new, self-contained test file; `checks.py`, `entitlements.py`, and `scan_routes.py` are unmodified (confirmed via `git diff --name-only` across the whole plan).
- Full test suite: 292/292 passing (260 baseline + 32 new), confirmed after each task and again at plan completion.

## Self-Check: PASSED

- FOUND: `webvulnscanner/scan_engine.py`
- FOUND: `tests/test_scan_engine.py`
- FOUND commit: `c32bc4f`
- FOUND commit: `c5db2c8`
- FOUND commit: `a824847`

---
*Phase: 04-production-hardening-reliability*
*Completed: 2026-08-13*
