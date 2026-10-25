---
phase: 02-api-cli-access
plan: 02
subsystem: api
tags: [flask, sqlalchemy, flask-limiter, bearer-token, rest]

requires:
  - phase: 02-api-cli-access
    provides: "02-01's ApiToken model, login_manager.request_loader Bearer-token auth, api_login_required decorator, _api_rate_limit_key, GET /api/v1/assets"
  - phase: 01-asset-inventory-continuous-scanning
    provides: "scheduler._fire(asset) fire-time SSRF/tier re-check, asset_routes._check_asset_access org-shared ownership, scan_routes._check_ownership creator-or-admin ownership"
provides:
  - "scheduler._fire(asset) returns the created Scan row on every branch (success, SSRF-failure, tier-failure) - backward-compatible, _tick() still ignores the return value"
  - "POST /api/v1/assets/<id>/scans (API-03) - trigger a scan via API, 100% reuse of scheduler._fire, zero new dispatch/SSRF/tier logic"
  - "GET /api/v1/scans/<id>/report (API-04) - fetch a completed scan's report as JSON, fixes the _check_ownership/_check_asset_access mismatch (RESEARCH.md Pitfall 1) for this route"
  - "Proof (not just code) that a revoked token, an insufficient tier, and a rate-limit breach all fail correctly (401/failed-scan/429), never silently or with a 500 (API-05)"
affects: [02-03-cli, cli/wvs.py]

actuals:
  tokens: 5120
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Scoped ownership-check branch: _check_asset_access(scan.asset) for Asset-linked Scans (org-shared), _check_ownership(scan) for manually-submitted Scans (creator-or-admin) - fixes a pre-existing Phase 1 gap for exactly one new route, without touching scan_routes.py's web-UI routes"
    - "Mutating-action routes get a tighter rate limit (30/min) than read-only routes (60/min) on the same /api/v1 blueprint"
    - "Route always returns a success HTTP status (202) even when the underlying operation's business logic failed (SSRF-unsafe/tier-insufficient) - the caller inspects the response body's status field, exactly mirroring how scheduler._tick handles the same two failure branches"

key-files:
  created: []
  modified:
    - glassbox/scheduler.py
    - glassbox/api_routes.py
    - tests/test_api_routes.py
    - .planning/REQUIREMENTS.md

key-decisions:
  - "scheduler._fire(asset) return-value change applied identically to all three branches (SSRF-failure, tier-failure, success) rather than only the success path, so trigger_scan never has to special-case which branch produced the Scan it needs to serialize"
  - "fetch_report's ownership check branches on scan.asset_id (Asset-linked vs manual) rather than adding a new column or model - reuses _check_asset_access/_check_ownership verbatim per CONTEXT.md's scoped-fix guidance, no app-wide _check_ownership refactor"

patterns-established:
  - "Cross-cutting proof tasks (API-05-style): a task with no new production code, whose sole job is exercising already-wired gating (rate limits, tier checks, revocation) under real HTTP requests rather than code review - keeps the 'is it actually wired' question answered by a test, not an assertion in a docstring"

requirements-completed: [API-03, API-04, API-05]

coverage:
  - id: D1
    description: "POST /api/v1/assets/<id>/scans creates exactly one new Scan row via scheduler._fire(asset) unchanged, returns 202 with {scan_id, status}"
    requirement: "API-03"
    verification:
      - kind: unit
        ref: "tests/test_api_routes.py#test_trigger_scan_creates_exactly_one_scan_via_fire"
        status: pass
    human_judgment: false
  - id: D2
    description: "Triggering a scan on an Asset belonging to a different org returns 404 JSON and creates no Scan row"
    requirement: "API-03"
    verification:
      - kind: unit
        ref: "tests/test_api_routes.py#test_trigger_scan_different_org_gets_404_no_scan_created"
        status: pass
    human_judgment: false
  - id: D3
    description: "A non-admin org member (not the Asset's creator) can trigger a scan on a same-org, org-shared Asset via their own token - _check_asset_access's org-shared model, not _check_ownership's creator-or-admin-only model, governs the trigger path"
    requirement: "API-03"
    verification:
      - kind: unit
        ref: "tests/test_api_routes.py#test_trigger_scan_non_admin_org_member_can_trigger_shared_asset"
        status: pass
    human_judgment: false
  - id: D4
    description: "A Free-tier org's token triggering a scan on a media/api-scheduled Asset gets 202 with status=\"failed\" and the same upgrade-prompt error_message scheduler._fire already produces on its own ticks - not a 500, not a silent no-op"
    requirement: "API-03"
    verification:
      - kind: unit
        ref: "tests/test_api_routes.py#test_trigger_scan_free_tier_media_asset_gets_failed_status"
        status: pass
    human_judgment: false
  - id: D5
    description: "GET /api/v1/scans/<id>/report returns the exact JSON scan_engine.save_report() wrote to disk for a completed, owned scan"
    requirement: "API-04"
    verification:
      - kind: unit
        ref: "tests/test_api_routes.py#test_fetch_report_returns_exact_on_disk_json_for_owner"
        status: pass
    human_judgment: false
  - id: D6
    description: "A non-admin, non-creating org member fetches an org-shared Asset's scan report via their own token and gets 200, not 404 - the Pitfall 1 fix, directly confirming the 'User B triggers a scan, can't fetch its report' warning sign from 02-RESEARCH.md no longer reproduces"
    requirement: "API-04"
    verification:
      - kind: unit
        ref: "tests/test_api_routes.py#test_fetch_report_non_admin_non_creator_org_member_gets_200"
        status: pass
    human_judgment: false
  - id: D7
    description: "A token holder from a different org gets 404 fetching another org's scan report"
    requirement: "API-04"
    verification:
      - kind: unit
        ref: "tests/test_api_routes.py#test_fetch_report_different_org_gets_404"
        status: pass
    human_judgment: false
  - id: D8
    description: "A manually-submitted (non-Asset) scan's report still only visible to its creator or an org admin - confirms the Asset-linked branch didn't accidentally loosen existing web-UI-equivalent semantics for manual scans"
    requirement: "API-04"
    verification:
      - kind: unit
        ref: "tests/test_api_routes.py#test_fetch_report_manual_scan_still_uses_check_ownership"
        status: pass
      - kind: unit
        ref: "tests/test_api_routes.py#test_fetch_report_org_admin_can_view_manual_scan"
        status: pass
    human_judgment: false
  - id: D9
    description: "A completed scan with no Report row yet returns 404 JSON, never 500"
    requirement: "API-04"
    verification:
      - kind: unit
        ref: "tests/test_api_routes.py#test_fetch_report_no_report_row_yet_gets_404_json"
        status: pass
    human_judgment: false
  - id: D10
    description: "A revoked or invalid Bearer token gets 401 JSON on every /api/v1/* route (list, trigger, report), never a 500 and never an HTML page"
    requirement: "API-05"
    verification:
      - kind: unit
        ref: "tests/test_api_routes.py#test_revoked_token_gets_401_on_all_three_routes"
        status: pass
    human_judgment: false
  - id: D11
    description: "GET /api/v1/assets exceeding its configured 60/minute rate limit returns 429, proving the limiter+key_func wiring actually trips (not just registered)"
    requirement: "API-05"
    verification:
      - kind: unit
        ref: "tests/test_api_routes.py#test_rate_limit_trips_429_on_list_assets"
        status: pass
    human_judgment: false

duration: 30min
completed: 2026-08-11
status: complete
---

# Phase 2 Plan 2: Trigger Scan + Fetch Report via API Summary

**POST /api/v1/assets/<id>/scans and GET /api/v1/scans/<id>/report, both 100% reusing Phase 1's scheduler._fire/asset_routes._check_asset_access/scan_routes._check_ownership - zero new dispatch, SSRF, tier, or ownership logic**

## Performance

- **Duration:** ~30 min
- **Started:** 2026-08-11T09:1x (prior commit 5c1ee94 at 08:48 was the orchestrator's pre-session backfill, not this plan's work)
- **Completed:** 2026-08-11T09:31:25+01:00
- **Tasks:** 3
- **Files modified:** 3 (`glassbox/scheduler.py`, `glassbox/api_routes.py`, `tests/test_api_routes.py`)

## Accomplishments
- `scheduler._fire(asset)` now returns the created `Scan` on every branch (success, SSRF-failure, tier-failure) - a minimal, backward-compatible change confirmed not to regress any of the 12 pre-existing scheduler tests
- `POST /api/v1/assets/<id>/scans` (API-03): trigger a scan against an existing Asset via `_check_asset_access` + `_fire(a)` directly - no parallel SSRF/tier/dispatch code path, always 202, caller inspects the returned `status` field for the actual outcome
- `GET /api/v1/scans/<id>/report` (API-04): fetch a completed scan's report as the exact on-disk JSON `scan_engine.save_report()` wrote, branching ownership on `scan.asset_id` to fix the pre-existing `_check_ownership`/`_check_asset_access` mismatch (RESEARCH.md Pitfall 1) for this specific new route
- API-05 cross-cutting proof: a revoked token gets 401 JSON on all three `/api/v1/*` routes; a dedicated rate-limit-enabled test proves `GET /api/v1/assets` actually returns 429 past its 60/minute limit (mirroring `test_auth_flows.py`'s `/login` rate-limit test)
- 12 new tests across the three tasks (4 + 6 + 2); full suite 199/199 passing

## Task Commits

Each task was committed atomically:

1. **Task 1: Trigger scan via API (API-03) - reuse scheduler._fire unchanged** - `8265bc6` (feat)
2. **Task 2: Fetch scan report via API (API-04) - fix the ownership-check mismatch for this route** - `a4bddda` (feat)
3. **Task 3: API-05 cross-cutting proof - revoked token, tier-gate failure mode, rate-limit 429** - `4f760a1` (test)

**Plan metadata:** this SUMMARY.md (committed separately per execute-plan.md's final-commit step)

## Files Created/Modified
- `glassbox/scheduler.py` - `_fire()` returns the created `Scan` row on every branch
- `glassbox/api_routes.py` - `POST /assets/<id>/scans` (`trigger_scan`), `GET /scans/<id>/report` (`fetch_report`)
- `tests/test_api_routes.py` - 12 new tests: 4 trigger-scan, 6 fetch-report, 2 revoked-token/rate-limit
- `.planning/REQUIREMENTS.md` - API-03/API-04/API-05 marked complete (checkbox + traceability table)

## Decisions Made
No new decisions beyond what CONTEXT.md/RESEARCH.md already locked - the plan's own action text was followed exactly:
- `_fire()`'s return-value change applied to all three branches (not just success) so `trigger_scan` never special-cases which branch produced the `Scan`.
- `fetch_report`'s ownership check branches on `scan.asset_id is not None` (Asset-linked → `_check_asset_access`, manual → `_check_ownership`) per CONTEXT.md's explicitly scoped-to-this-route fix - `scan_routes.py`'s existing web-UI routes were left untouched, confirmed by `test_fetch_report_manual_scan_still_uses_check_ownership` and `test_fetch_report_org_admin_can_view_manual_scan`.

## Deviations from Plan

None - plan executed exactly as written. The only judgment call was test-infrastructure, not scope: `trigger_scan`'s test suite needed `_spawn_scan_thread` monkeypatched to a no-op recorder (mirroring `test_scheduler.py`'s existing `spawned` fixture) so triggering a "base" scan via the API route in a test doesn't spawn a real daemon thread making a real outbound HTTP request against `example.com` - this is test hygiene matching an established project convention, not a change to production code or scope.

## Issues Encountered
None. All three tasks' `<verify>` commands passed on first implementation; the full suite (`pytest`) was green (199/199) after Task 3 with no regressions to the 12 pre-existing scheduler tests or the 19 pre-existing api-route tests.

## User Setup Required
None - no external service configuration required (no new env vars, config keys, or dependencies).

## Next Phase Readiness
API-03/04/05 are fully satisfied and tested on top of 02-01's proven token-auth mechanism. `scheduler._fire`'s new return value, `trigger_scan`, and `fetch_report` are all available for 02-03's CLI (`cli/wvs.py`) to wrap as `scan start`/`report get` commands - no further backend changes anticipated for that plan beyond the CLI itself and its own tests (`tests/test_cli.py`).

---
*Phase: 02-api-cli-access*
*Completed: 2026-08-11*

## Self-Check: PASSED

All created/modified files (`glassbox/scheduler.py`, `glassbox/api_routes.py`,
`tests/test_api_routes.py`, this SUMMARY.md) exist on disk. All three task commits
(`8265bc6`, `a4bddda`, `4f760a1`) are present in `git log`.
