---
phase: 05-new-scan-flow-redesign
plan: 03

subsystem: ui
tags: [flask, jinja, scan-routes, scan-progress, polling, sse]

# Dependency graph
requires:
  - phase: 05-new-scan-flow-redesign
    plan: 02
    provides: media/API wizard Step 3 pages and the Advanced Smart Setup page (both launch into the same scan_progress.html this plan extends)
provides:
  - "GET /scan/<id>/status - ownership-guarded, error-text-free status endpoint for scan types with no ScanEvent stream"
  - "View Report primary button on scan_progress.html, revealed on the first completed tick for all four scan types"
  - "Jinja-level transport split in scan_progress.html: base keeps SSE, advanced/media/api poll /status every 2s"
affects: []

# Actuals
actuals:
  tasks: 2 (of 3 - Task 3 is a human-verify checkpoint, not run in this session)
  commits: pending

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Jinja-level ({% if scan.scan_type == 'base' %}) transport split, not just a JS runtime branch - keeps the SSE-only code path (new EventSource(...)) out of the rendered source entirely for non-base scan types, verified by a direct string-absence assertion rather than trusting the JS guard alone"
    - "revealViewReport() called before window.location.href is set in both transport branches, so the View Report control exists in the DOM even if navigation is suppressed (backgrounded tab, blocked assignment)"

key-files:
  created:
    - tests/test_scan_status.py
  modified:
    - webvulnscanner/scan_routes.py
    - templates/scan_progress.html

key-decisions:
  - "D-04 implemented via a dedicated GET /scan/<id>/status endpoint rather than reusing /scan/<id>/events - advanced/media/api orchestrators take no progress_cb and write zero ScanEvent rows, so a long-lived SSE connection per running scan would hold a worker open for nothing; a 2s poll of one indexed row is both cheaper and simpler to test."
  - "scan_status() returns exactly {status, report_url} - no error_message or exception text. The client only needs to know a scan became failed to reload into scan_progress.html's existing server-rendered .error-box branch, which already renders the message itself server-side."

patterns-established:
  - "scan_status() reuses _check_ownership() unchanged - the same owner-or-org-admin predicate scan_detail/scan_events/scan_report/scan_report_csv already gate on, so this is not a second, potentially-divergent auth path."

requirements-completed: [SCANUX-05]

coverage:
  - id: D1
    description: "GET /scan/<id>/status returns {status, report_url} JSON for queued/running/failed/completed states, 404s for a caller who is neither owner nor org-admin, and never leaks error_message"
    requirement: "SCANUX-05"
    verification:
      - kind: unit
        ref: "tests/test_scan_status.py (11 status-endpoint tests: all four status values, report-row presence, cross-org/same-org-member/org-admin/anonymous/nonexistent-id cases, error-message-never-leaked)"
        status: pass
    human_judgment: false
  - id: D2
    description: "scan_progress.html reveals a View Report primary button and lands the user on the report automatically for all four scan types, with base keeping its unmodified SSE feed and advanced/media/api polling /status every 2s"
    requirement: "SCANUX-05"
    verification:
      - kind: unit
        ref: "tests/test_scan_status.py (7 rendering tests: viewReportBtn present, base uses new EventSource + /events and not /status-only copy, non-base uses /status and omits new EventSource entirely from rendered source, feed-empty copy correction, failed-scan error box, revealViewReport/isBase occurrence counts in template source)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Live browser walk: media/API/base scans complete and auto-navigate to the report, View Report button appears, base scan's per-check feed/progress bar/severity tally are unregressed, a forced failure reloads into the error box, and a cross-org direct status-URL visit 404s"
    verification:
      - kind: manual_procedural
        ref: "Task 3 checkpoint:human-verify - not yet run"
        status: pending
    human_judgment: true
    rationale: "Visual/interaction verification (button reveal timing, auto-navigation, feed/bar non-regression, network-tab poll cadence) requires a human eyeball on a running scan against a real target, not just HTTP-response assertions. Not run in this session - the automated coverage above (18 new tests, plus the existing scan_events/scan_routes/scan_ownership suites re-run clean) covers every behavior the checkpoint's script re-verifies except live timing/visual confirmation."

duration: ~25min (this session)
completed: 2026-08-17
status: executed (Task 3 human-verify checkpoint outstanding)
---

# Phase 5 Plan 3: Scan Status Polling / View Report Reachability Summary

**Closed SCANUX-05 for advanced/media/API scans: a new ownership-guarded `GET /scan/<id>/status` endpoint plus a Jinja-level transport split in `scan_progress.html` (SSE for base, 2s status polling for the other three) reveals a `View Report` button and auto-navigates to the report on completion for every scan type, with base scans' existing SSE behavior fully unregressed.**

## Accomplishments
- `scan_status(scan_id)` added directly after `scan_events()` in `scan_routes.py`: `get_or_404` + `_check_ownership` (the same predicate every other scan route uses), returns `{status, report_url}` with `report_url` set only when `COMPLETED` and a `Report` row exists - no `error_message`, no exception text, ever.
- `scan_progress.html`: a `View Report` `.btn.primary` (hidden by default, since `scan_detail()` already redirects a `COMPLETED` scan away from this page before it ever renders) is revealed by `revealViewReport()` in both the SSE completion handler and the poll completion handler, called before the navigation assignment so the control exists in the DOM even if navigation itself is suppressed.
- The transport split is enforced at the **Jinja** level (`{% if scan.scan_type == 'base' %} ... {% else %} ... {% endif %}`), not just a JS `if (isBase)` runtime guard - a non-base render's HTML source never contains the literal `new EventSource` call at all, verified directly by a test that asserts its absence from the response body (not just that a JS branch wouldn't execute it).
- The `feed-empty` placeholder row's copy is corrected per scan type: base keeps "Initializing investigation…" (it will fill in live); the other three now read "This scan type reports status only - no per-check feed." instead of a claim they can never fulfill.
- The `watchdog`'s "still waiting for an update" interval is base-only (`isBase ? setInterval(...) : null`) - it would be guaranteed-wrong copy for scan types that never emit an SSE message in the first place. `staleLine` stays in the DOM for the poll branch's own 3-failures-in-a-row "Connection lost - still trying" message.
- 18 new tests in `tests/test_scan_status.py`: 11 on the status endpoint (all four `ScanStatus` values, report-row presence/absence, cross-org/same-org-member/org-admin/anonymous/nonexistent-id ownership matrix, error-message-never-leaked), 7 on the rendered progress page (button presence, transport-branch source-content assertions, failed-scan error box, template-source occurrence counts for `revealViewReport`/`isBase`).

## Files Created/Modified
- `webvulnscanner/scan_routes.py` - added `scan_status()` route (one new function, `jsonify` already imported from an earlier session change this same session); no existing function body touched.
- `templates/scan_progress.html` - `viewReportBtn` anchor in `.soc-header`; conditional `feed-empty` copy; `isBase` flag, `revealViewReport()`, base-only `watchdog`; the SSE construction/handlers wrapped in a Jinja `{% if scan.scan_type == 'base' %}` block, the poll `pollStatus()`/`setInterval` in the paired `{% else %}` block. Zero changes inside the `<style>` block (confirmed by diffing the block directly, not just the blunt open-brace grep the original plan's acceptance criteria used, which also counts JS braces).
- `tests/test_scan_status.py` - new module, 18 tests.

## Decisions Made
- D-04 (05-CONTEXT.md) implemented via the dedicated-endpoint branch it left open, for the reasons already recorded in the plan's `<objective>`: no query-logic duplication (a `get_or_404` + the same `_check_ownership`), and strictly less server load than the SSE alternative would have been for these three types (a long-lived worker connection replaced by one row-read every 2s, bounded to stop on the first completed/failed tick).
- Kept the plan's JS `isBase` variable and its runtime guards (`if (isBase)` / `if (!isBase)`) even though the Jinja split alone already guarantees exclusivity - both together is what makes the "no `new EventSource` in a non-base render" property hold structurally rather than by convention, and it's what the acceptance criteria's `isBase`-occurrence-count check was written against.

## Deviations from Plan
- The plan's literal action text said to wrap the SSE/poll code in a JS-only `if (isBase) { ... } else { ... }`. Acceptance criteria in the same plan required a non-base render's body to not contain `new EventSource` at all - a JS-only runtime branch can't satisfy that (the string is always present in the rendered source regardless of which branch executes). Resolved by splitting at the Jinja template level instead, with the JS `isBase` guards nested inside each branch for the additional invariant. This is a plan self-consistency fix, not a scope change - the acceptance criteria's letter was followed.

## Issues Encountered
- First test-writing pass asserted the wrong `revealViewReport`/`isBase` occurrence counts against *rendered per-scan-type output* rather than the *template source file* the plan's acceptance criteria actually greps - corrected by splitting into source-level assertions (matching the plan literally) plus separate rendered-output assertions for the behavior that does vary by scan type (2 occurrences of `revealViewReport` per single-type render, one per active branch).

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Task 3 (human-verify checkpoint: live browser walk of a completing media/API/base scan, a forced failure, and a cross-org 404 check) has not been run this session - flagged as `pending` in the coverage block above. All automated coverage the checkpoint's script re-verifies is in place; the checkpoint adds the visual/timing confirmation a real browser session provides.
- No blockers for any later phase. `entitlements.py`, `checks.py`, `scan_engine.py` are untouched by this plan.

---
*Phase: 05-new-scan-flow-redesign*
*Completed: 2026-08-17*
