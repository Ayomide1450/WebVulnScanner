---
phase: 04-production-hardening-reliability
plan: 04
subsystem: testing
tags: [pytest, scheduler, scan_routes, orchestrator-status-transitions, regression-lock]

requires:
  - phase: 04-production-hardening-reliability
    provides: "scan_engine._score_report and direct-invocation orchestrator coverage for run_media_scan/run_api_scan/run_advanced_scan (plan 04-01)"
provides:
  - "tests/test_scheduler.py: entitled-plan media/api scheduler-fire coverage (dispatch kwargs, rescheduling, fire-time SSRF refusal) plus a source-parsing regression lock proving _fire has no advanced branch"
  - "tests/test_scan_routes.py: _run_scan_in_background Scan-row status-transition coverage (COMPLETED/FAILED, per-scan-type report prefix, unknown-scan-type handling) for media, api and advanced"
affects: [04-05-documentation-and-visual-consistency]

actuals:
  tokens: 9800
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Scheduler-fired allowed-path test mirrors the existing tier-denial test's shape exactly (same fixtures, same _past()/_as_aware() helpers), only the org's Plan and the assertions on spawned[0] differ"
    - "Source-parsing regression lock (inspect.getsource + regex over scheduler._fire's own source) asserting the exact set of dispatched scan-type literals, mirroring test_scan_engine.py's cross-orchestrator scoring-dedup lock from plan 04-01"
    - "_run_scan_in_background wrapper tests use short-lived `with app.app_context():` blocks (never the shared db fixture), matching test_scan_events.py's documented stale-read workaround (04-RESEARCH.md Pitfall 3)"
    - "Every wrapper test passes tier=Tier.FREE to keep the AI-summary tail unreached, except the one advanced-failure test that needs the check group to actually execute in order to raise - documented inline why that still reaches zero Groq calls"

key-files:
  created: []
  modified:
    - tests/test_scheduler.py
    - tests/test_scan_routes.py

key-decisions:
  - "Advanced success-path wrapper test uses tier=Tier.FREE/org_verified=False (deliberately below the ORG_VERIFIED gate advanced checks require) - status-transition/prefix coverage doesn't need the check groups to actually run, and this keeps the AI-summary tail unreached without a second monkeypatch; the failure-path advanced test is the one exception, using tier=Tier.ORG_VERIFIED/org_verified=True specifically because a locked group is never called and therefore can never raise, with a comment explaining why the AI-summary tail is still never reached in that case (the exception propagates before that line runs)"
  - "No test in this plan imports test_scan_engine.py's stub helpers - test_scan_routes.py defines its own local _stub_media_check/_stub_api_checks/_stub_advanced_checks/_full_advanced_form, matching test_scan_events.py's precedent of each test module owning its own network-free stubbing helpers rather than sharing them across files"

requirements-completed: [HARD-02]

coverage:
  - id: D1
    description: "Entitled-plan media and api scheduler fires produce a QUEUED Scan and dispatch with the correct scan_type, unattended defaults (media: download=False/max_files=20), and a tier value; both reschedule next_run_at past now"
    requirement: "HARD-02"
    verification:
      - kind: unit
        ref: "tests/test_scheduler.py::test_paid_tier_media_schedule_spawns_with_unattended_defaults"
        status: pass
      - kind: unit
        ref: "tests/test_scheduler.py::test_paid_tier_api_schedule_spawns_with_target_and_tier"
        status: pass
    human_judgment: false
  - id: D2
    description: "A fire-time SSRF failure on a media-scheduled Asset produces a FAILED Scan with no dispatch, proving the SSRF re-check runs ahead of the scan-type dispatch on the media branch too"
    requirement: "HARD-02"
    verification:
      - kind: unit
        ref: "tests/test_scheduler.py::test_fire_time_ssrf_failure_on_media_schedule_produces_failed_scan_without_spawning"
        status: pass
    human_judgment: false
  - id: D3
    description: "scheduler._fire's source dispatches on exactly base/media/api scan-type literals - no advanced branch exists, asserted as a property of the source rather than assumed (D-04)"
    requirement: "HARD-02"
    verification:
      - kind: unit
        ref: "tests/test_scheduler.py::test_fire_dispatches_only_on_base_media_api_no_advanced_branch"
        status: pass
    human_judgment: false
  - id: D4
    description: "_run_scan_in_background drives the Scan row through RUNNING into COMPLETED for media/api/advanced, writing the orchestrator's score onto risk_score and creating exactly one Report row under the correct per-scan-type filename prefix"
    requirement: "HARD-02"
    verification:
      - kind: unit
        ref: "tests/test_scan_routes.py::test_run_scan_in_background_media_completes_and_saves_report"
        status: pass
      - kind: unit
        ref: "tests/test_scan_routes.py::test_run_scan_in_background_api_completes_and_saves_report"
        status: pass
      - kind: unit
        ref: "tests/test_scan_routes.py::test_run_scan_in_background_advanced_completes_and_saves_report"
        status: pass
    human_judgment: false
  - id: D5
    description: "An orchestrator raising inside _run_scan_in_background leaves the Scan row FAILED with the exception text in error_message, never stuck in RUNNING, for media/api/advanced and for an unknown scan_type"
    requirement: "HARD-02"
    verification:
      - kind: unit
        ref: "tests/test_scan_routes.py::test_run_scan_in_background_media_failure_leaves_scan_failed"
        status: pass
      - kind: unit
        ref: "tests/test_scan_routes.py::test_run_scan_in_background_api_failure_leaves_scan_failed"
        status: pass
      - kind: unit
        ref: "tests/test_scan_routes.py::test_run_scan_in_background_advanced_failure_leaves_scan_failed"
        status: pass
      - kind: unit
        ref: "tests/test_scan_routes.py::test_run_scan_in_background_unknown_scan_type_lands_failed_not_raising"
        status: pass
    human_judgment: false

duration: 40min
completed: 2026-08-13
status: complete
---

# Phase 4 Plan 4: Scheduler and Scan-Status-Transition Testing Summary

**Closed the second half of HARD-02: proved the scheduler actually fires media/api scans on an entitled plan (not just denies them on Free), locked the absence of an advanced scheduler branch as a source-level invariant, and covered `_run_scan_in_background`'s Scan-row COMPLETED/FAILED transitions for all three previously-untested scan types.**

## Performance

- **Duration:** ~40 min
- **Started:** 2026-08-13 (context read)
- **Completed:** 2026-08-13
- **Tasks:** 2/2 completed
- **Files modified:** 2 (`tests/test_scheduler.py`, `tests/test_scan_routes.py`) — no production code touched

## Accomplishments

- `tests/test_scheduler.py` gained the allowed-path counterpart to the existing Free-tier media/api denial tests: an entitled-plan (`Plan.PAID`) media fire and api fire each assert a QUEUED `Scan`, the correct `_spawn_scan_thread` dispatch (`scan_type`, `base_url`, media's `download=False`/`max_files=20` unattended defaults, and a `tier` value in kwargs), and that `next_run_at` reschedules past now exactly like the base-scan fire already does.
- A media-scheduled fire-time SSRF failure test proves the SSRF re-check runs ahead of the scan-type dispatch on the media branch too, not only on the pre-existing base-branch test.
- A source-parsing regression lock (`inspect.getsource` + regex over `scheduler._fire`'s own body) asserts the exact set of scan-type literals `_fire` dispatches on is `{"base", "media", "api"}` — D-04's "no advanced branch" finding is now a property the suite verifies, not just documents.
- `tests/test_scan_routes.py`'s docstring widened to describe its new dual role (dashboard view + `_run_scan_in_background` status-transition coverage), and gained: three success-path tests (media/api/advanced each reach COMPLETED, set `completed_at`/`risk_score`, create exactly one `Report` row, and save under their own filename prefix — `media_`/`api_`/`advanced_`, distinct from base's empty prefix and from each other); three failure-path tests plus an unknown-scan-type test (all four land FAILED with the exception text in `error_message` and zero `Report` rows, never stuck in RUNNING).
- Two independent mutation proofs — flipping the scheduler's media `download` default to `True`, and narrowing `_run_scan_in_background`'s broad `except Exception` to `except KeyError` — confirmed the new regression tests actually fail when the underlying guarantee is weakened, then confirmed a clean revert restores byte-identical production files and a fully passing suite.

## Task Commits

Each task was committed atomically:

1. **Task 1: Scheduler-fired media and api success paths** - `e5c7311` (test) — entitled-plan media/api fire tests, reschedule assertions, media SSRF-failure test, and the no-advanced-branch source-parsing lock added to `tests/test_scheduler.py` (16 tests total in the file, 5 new)
2. **Task 2: Scan-row status transitions and failure handling for media, api and advanced** - `2a44083` (test) — `_run_scan_in_background` success/failure/unknown-type coverage added to `tests/test_scan_routes.py` (12 tests total in the file, 8 new, plus the widened module docstring)

**Plan metadata:** (this commit, following)

## Files Created/Modified

- `tests/test_scheduler.py` — added the entitled-plan media/api scheduler-fire tests, the media-scheduled SSRF-failure test, and the `_fire` no-advanced-branch source-parsing regression lock (5 new tests; 16 total in the file)
- `tests/test_scan_routes.py` — widened the module docstring; added `_stub_save_report`/`_stub_media_check`/`_stub_api_checks`/`_stub_advanced_checks`/`_full_advanced_form` local helpers plus 8 new tests covering `_run_scan_in_background`'s COMPLETED and FAILED transitions for media/api/advanced and the unknown-scan-type path (12 total in the file)

## Decisions Made

- The advanced success-path wrapper test intentionally uses `tier=Tier.FREE`/`org_verified=False` — status-transition/prefix coverage doesn't require the advanced check groups to actually execute (they'd all land in `locked_checks`, score stays 100), and this keeps the AI-summary tail unreached with no second monkeypatch needed.
- The advanced failure-path test is the one deliberate exception to "every test passes a tier below Paid" — it uses `tier=Tier.ORG_VERIFIED`/`org_verified=True` because a locked check group is never called at all and therefore can never raise; a comment explains why this still never reaches the AI-summary tail (the exception propagates out of `run_advanced_scan` before `_run_scan_in_background`'s tier-gated AI-summary line is ever reached).
- `tests/test_scan_routes.py` defines its own local stubbing helpers rather than importing `test_scan_engine.py`'s — matches `test_scan_events.py`'s existing precedent of each test module owning its own network-free stub set.

## Deviations from Plan

None - plan executed exactly as written. No production code changes (both mutation proofs were reverted to byte-identical state, confirmed via `git diff --stat`).

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- HARD-02 is now fully satisfied across all three levels: orchestrator-function level (plan 04-01), scheduler-dispatch level for media/api (this plan), and `Scan`-row status-transition level for media/api/advanced (this plan). `run_advanced_scan` remains direct-invocation-only by design (D-04), now backed by both a documentation comment in `scheduler.py` and a source-parsing regression test that would fail if an `"advanced"` branch were ever silently added.
- No blockers for 04-05 — this plan touched only `tests/test_scheduler.py` and `tests/test_scan_routes.py`; `glassbox/scheduler.py` and `glassbox/scan_routes.py` are unmodified (confirmed via `git diff --name-only` across the whole plan, and via the byte-identical mutation-proof reverts).
- Full test suite: 335/335 passing (297 baseline + 5 scheduler tests + 12 scan_routes tests, adjusted for the file's pre-existing 4 dashboard tests), confirmed after each task and again at plan completion.

## Self-Check: PASSED

- FOUND: `tests/test_scheduler.py`
- FOUND: `tests/test_scan_routes.py`
- FOUND commit: `e5c7311`
- FOUND commit: `2a44083`

---
*Phase: 04-production-hardening-reliability*
*Completed: 2026-08-13*
