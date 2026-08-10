---
phase: 01-asset-inventory-continuous-scanning
plan: 02
subsystem: web
tags: [flask, jinja2, sqlalchemy, entitlements]

requires:
  - phase: 01-asset-inventory-continuous-scanning (plan 01-01)
    provides: "Asset model, scheduler.py tick/claim/fire engine, asset_routes.py's /assets + /assets/new + _check_asset_access ownership guard"
provides:
  - "GET /assets/<id> (asset_detail): schedule + scan history/trend page"
  - "POST /assets/<id>/schedule (update_schedule): cadence/scan-type editing, recomputes next_run_at"
  - "POST /assets/<id>/pause, /resume, /delete: schedule lifecycle controls, delete is soft (deleted_at)"
  - "templates/asset_detail.html reusing dashboard.html's score-card/sparkline/table conventions"
  - "4 new icon-clock/pause/play/trash symbols in base.html's shared sprite"
affects: []

actuals:
  tokens: 7400
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Icon-only row-action buttons (44px min touch target + required aria-label), native confirm()-gated destructive form submit - no new modal/dialog component"
    - "FEATURE_REQUIREMENTS.get(key, 0) default-to-FREE lookup for a schedule-type that may not have a whole-type tier entry (e.g. 'base'), mirroring entitlements.allowed_checks()'s existing missing-key convention"

key-files:
  created:
    - templates/asset_detail.html
  modified:
    - webvulnscanner/asset_routes.py
    - templates/assets.html
    - templates/base.html
    - tests/test_asset_routes.py

key-decisions:
  - "Split the plan's two tasks into two atomic commits despite both touching the same asset_detail.html/asset_routes.py files, by temporarily reducing each file to its Task-1-only scope, running that task's verify command + full suite, committing, then restoring the Task-2 additions - preserves per-task commit atomicity without leaving an intermediate broken state in either commit."
  - "assets.html (inventory list): wired the Name column and previously-stubbed Actions column ('-' placeholder from 01-01) to link to the new asset_detail page - not in the plan's files_modified list, but the detail page this plan builds would otherwise be unreachable from normal navigation (Rule 2)."
  - "Tier-locked hint uses FEATURE_REQUIREMENTS.get(asset.schedule_scan_type, 0) rather than a direct index - schedule_scan_type can be 'base', which has no whole-type entry in FEATURE_REQUIREMENTS (only its individual checks do); a direct [] index would KeyError. Mirrors entitlements.allowed_checks()'s existing default-to-Tier.FREE-on-missing-key convention (Rule 1)."

requirements-completed: [ASSET-03, ASSET-05, ASSET-06]

coverage:
  - id: D1
    description: "An Asset's detail page shows its current schedule (cadence + scan type), scan history ordered newest-first, and a risk-score trend, scoped to the owning org/solo user (404 for anyone else)"
    requirement: "ASSET-03"
    verification:
      - kind: integration
        ref: "tests/test_asset_routes.py#test_get_asset_detail_shows_schedule_and_empty_history"
        status: pass
      - kind: integration
        ref: "tests/test_asset_routes.py#test_get_asset_detail_shows_populated_scan_history"
        status: pass
      - kind: integration
        ref: "tests/test_asset_routes.py#test_get_asset_detail_for_other_org_is_404"
        status: pass
    human_judgment: false
  - id: D2
    description: "Editing an Asset's schedule persists valid cadence+scan_type edits and recomputes next_run_at; rejects invalid values and leaves the row unchanged"
    requirement: "ASSET-03"
    verification:
      - kind: integration
        ref: "tests/test_asset_routes.py#test_post_schedule_valid_update_persists_and_recomputes_next_run"
        status: pass
      - kind: integration
        ref: "tests/test_asset_routes.py#test_post_schedule_invalid_value_rejected_and_row_unchanged"
        status: pass
    human_judgment: false
  - id: D3
    description: "The schedule-config form shows an inline tier-locked upgrade hint exactly when the Asset's current schedule_scan_type exceeds the org's effective tier, and never for a schedule type with no whole-type tier entry (e.g. base)"
    requirement: "ASSET-03"
    verification:
      - kind: integration
        ref: "tests/test_asset_routes.py#test_schedule_tier_locked_hint_renders_when_over_org_tier"
        status: pass
      - kind: integration
        ref: "tests/test_asset_routes.py#test_schedule_tier_locked_hint_absent_when_within_org_tier"
        status: pass
      - kind: integration
        ref: "tests/test_asset_routes.py#test_schedule_tier_locked_hint_absent_for_base_schedule_type"
        status: pass
    human_judgment: false
  - id: D4
    description: "Pausing an Asset excludes it from the scheduler's due-Asset query; resuming re-includes it"
    requirement: "ASSET-06"
    verification:
      - kind: integration
        ref: "tests/test_asset_routes.py#test_pause_resume_delete_pause_excludes_asset_from_due_query"
        status: pass
      - kind: integration
        ref: "tests/test_asset_routes.py#test_pause_resume_delete_resume_reincludes_asset_in_due_query"
        status: pass
    human_judgment: false
  - id: D5
    description: "Deleting an Asset soft-deletes it (excluded from the inventory list and future scheduler ticks) while its prior Scan history remains queryable and intact"
    requirement: "ASSET-06"
    verification:
      - kind: integration
        ref: "tests/test_asset_routes.py#test_pause_resume_delete_delete_soft_deletes_and_keeps_scan_history"
        status: pass
    human_judgment: false
  - id: D6
    description: "Pause/resume/delete all enforce the same _check_asset_access ownership guard 01-01 established (404 for a non-owning org)"
    requirement: "ASSET-06"
    verification:
      - kind: integration
        ref: "tests/test_asset_routes.py#test_pause_resume_delete_all_three_404_for_non_owning_org"
        status: pass
    human_judgment: false
  - id: D7
    description: "Pause/resume/delete row controls are icon-only, 44px minimum touch target, with a required aria-label, and delete requires a confirm() step before it takes effect"
    verification: []
    human_judgment: true
    rationale: "Touch-target sizing and screen-reader label wiring are visually/assistively verified conventions (01-UI-SPEC.md's Spacing Scale exception) - no automated test asserts computed CSS box size or drives a native confirm() dialog; code inspection confirms .icon-btn's min-width/min-height:44px and each button's aria-label are present in templates/asset_detail.html."

duration: 40min
completed: 2026-08-10
status: complete
---

# Phase 1 Plan 2: Asset Detail — Schedule Editing, History/Trend, Pause/Resume/Delete Summary

**Asset detail page (schedule editing, scan history/trend, tier-locked hint) and pause/resume/delete row controls, both built directly on 01-01's Asset model, scheduler engine, and `_check_asset_access` ownership guard with zero changes to any of them.**

## Performance

- **Duration:** ~40 min
- **Tasks:** 2
- **Files modified:** 5 (1 created, 4 modified)
- **Commits:** 2 task commits (`761dc0e`, `8414c91`)

## Accomplishments
- `GET /assets/<id>` (`asset_detail`) renders the Asset's current schedule, its scan history newest-first, and a risk-score sparkline trend, reusing `dashboard.html`'s exact score-card/sparkline/table conventions scoped to one Asset (Target column dropped as redundant), with the plan's adapted near-immediate-first-fire empty-state copy.
- `POST /assets/<id>/schedule` (`update_schedule`) validates cadence/scan-type against the same fixed allow-lists registration uses, and on success unconditionally recomputes `next_run_at` from "now" plus the new cadence's interval - a single rule for every edit, avoiding a stale value left over from the old cadence's math.
- A tier-locked inline hint (`.warn-box` + `icon-lock`) appears on the schedule-config form exactly when `FEATURE_REQUIREMENTS.get(asset.schedule_scan_type, 0) > effective_tier_for_org(asset.organization)` - using `.get()` with a default rather than a direct index, since `schedule_scan_type == "base"` has no whole-type entry in `FEATURE_REQUIREMENTS`.
- `POST /assets/<id>/pause`, `/resume`, `/delete` - all three reuse `_check_asset_access`; delete soft-deletes (`deleted_at` + `is_paused=True`, belt-and-suspenders) so scheduler ticks and the inventory list both already exclude it via 01-01's existing filters, while prior `Scan` rows stay queryable by `asset_id`.
- 4 new icon symbols (`icon-clock`, `icon-pause`, `icon-play`, `icon-trash`) added to `base.html`'s shared sprite, matching the existing stroke convention exactly.
- Icon-only pause/resume/delete row controls: 44px minimum touch target, required `aria-label` per control, pause/resume styled `.btn.secondary` (never accent - a schedule toggle isn't a conversion action), delete styled with `.error-box`'s destructive rgba treatment plus a native `confirm()`-gated form submit (message built via Jinja `tojson`, no new modal component). All three forms disable their submit button while in flight via the existing `button:disabled` pattern.
- `templates/assets.html`'s previously-stubbed Actions column (`-` placeholder from 01-01) and Name column now link to the new detail page - otherwise the page this plan builds would have been unreachable from normal navigation.
- 12 new tests in `tests/test_asset_routes.py`: detail-page history/schedule/tier-hint coverage (8) and pause/resume/delete lifecycle + ownership coverage (4).

## Task Commits

1. **Task 1: Asset detail page - schedule editing + scan history/trend** - `761dc0e` (feat)
2. **Task 2: Pause / resume / delete controls + destructive confirmation** - `8414c91` (feat)

**Plan metadata:** this SUMMARY.md + STATE.md/ROADMAP.md/REQUIREMENTS.md update (separate docs commit, see below)

## Files Created/Modified
- `webvulnscanner/asset_routes.py` - `asset_detail`, `update_schedule`, `pause_asset`, `resume_asset`, `delete_asset` routes; `_render_asset_detail` helper; `TIER_LABELS` display-name map
- `templates/asset_detail.html` (new) - schedule config + history/trend + pause/resume/delete UI
- `templates/assets.html` - Name/Actions columns now link to the detail page
- `templates/base.html` - `icon-clock`/`icon-pause`/`icon-play`/`icon-trash` sprite symbols
- `tests/test_asset_routes.py` - 12 new tests across detail/schedule/tier-hint and pause/resume/delete

## Decisions Made
- Split the plan's two tasks into two atomic commits by temporarily reducing each file to its Task-1-only scope (verify + full suite green at that snapshot), committing, then restoring the Task-2 additions - preserves per-task commit atomicity even though both tasks touch the same `asset_detail.html`/`asset_routes.py`.
- `templates/assets.html`'s Actions/Name columns wired to the detail page (Rule 2 - not in the plan's `files_modified` list, but necessary for the page to be reachable at all).
- Tier-locked hint uses `FEATURE_REQUIREMENTS.get(asset.schedule_scan_type, 0)` rather than a direct index, to safely handle `schedule_scan_type == "base"` (Rule 1 - the plan's literal behavior spec text would KeyError for base-scheduled Assets).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `FEATURE_REQUIREMENTS[asset.schedule_scan_type]` would KeyError for `schedule_scan_type == "base"`**
- **Found during:** Task 1, while implementing the tier-locked hint per the plan's `<behavior>` spec
- **Issue:** The plan's behavior text directly indexes `FEATURE_REQUIREMENTS[asset.schedule_scan_type]`. `FEATURE_REQUIREMENTS` (in `entitlements.py`) has entries for `"media"` and `"api"` but no whole-type `"base"` key (only base scan's individual checks are gated separately) - `scheduler.py::_fire` avoids this by scoping its own tier check to `schedule_scan_type in ("media", "api")` only, but the plan's hint text has no such guard.
- **Fix:** Used `FEATURE_REQUIREMENTS.get(asset.schedule_scan_type, 0)` instead of a direct index, mirroring `entitlements.allowed_checks()`'s existing convention of defaulting a missing key to `Tier.FREE` (0). A base-scheduled Asset never renders the hint, matching the fact that base scheduling as a whole is never tier-gated.
- **Files modified:** `webvulnscanner/asset_routes.py` (route passes `FEATURE_REQUIREMENTS` through), `templates/asset_detail.html` (uses `.get(..., 0)`)
- **Verification:** `tests/test_asset_routes.py::test_schedule_tier_locked_hint_absent_for_base_schedule_type` (FREE-tier org, base-scheduled Asset, hint absent, no 500)
- **Committed in:** `761dc0e` (Task 1 commit)

**2. [Rule 2 - Missing functionality] Asset inventory list had no way to reach the new detail page**
- **Found during:** Task 1, after building `asset_detail.html`
- **Issue:** `templates/assets.html` (built in 01-01) rendered the Actions column as a literal `-` placeholder and the Name column as plain text - with no link anywhere to `GET /assets/<id>`, the page this plan builds would be unreachable through normal navigation.
- **Fix:** Linked both the Name and Actions columns to `url_for('asset.asset_detail', asset_id=a.id)`, matching the existing `a.row-link`/"View →" convention `dashboard.html`'s scan table already uses.
- **Files modified:** `templates/assets.html`
- **Verification:** Exercised indirectly by every `test_asset_routes.py` test that navigates via `client.get("/assets")` then `client.get(f"/assets/{id}")`; full suite green.
- **Committed in:** `761dc0e` (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 missing functionality). Both necessary for correctness/usability; no scope creep beyond what the plan's own objective already committed to ("give the user ongoing control over that schedule and visibility into its history").

## Issues Encountered

**No local venv in this worktree.** `.venv/` does not exist inside the git worktree checkout; `pytest`/`flask` are not resolvable from a bare `python -m pytest` in this directory. Ran tests via the main repo's existing `.venv` (`C:\Users\Arktech_Designs\Documents\WebVulnScanner\.venv\Scripts\python.exe -m pytest`) against this worktree's `tests/` - same interpreter/dependency set 01-01 used, no code path difference, just an invocation-path note for the next executor in this worktree.

No `flask` CLI commands were run in this plan (no model/migration changes), so the `.env` cross-repo-leak risk flagged in 01-01's SUMMARY did not resurface here.

## User Setup Required

None - no external service configuration required. No new environment variables, no schema changes.

## Next Phase Readiness

- ASSET-03 (schedule editable after creation), ASSET-05 (history/trend), and ASSET-06 (pause/resume/delete) are all fully implemented and tested, completing Phase 1's Asset-inventory feature set alongside 01-01's ASSET-01/02/04/07/08.
- Full test suite (172 tests, up from 160 after 01-01) green; no model or migration changes in this plan.
- `webvulnscanner/asset_routes.py` now exposes the complete `asset` blueprint surface (`/assets`, `/assets/new`, `/assets/<id>`, `/assets/<id>/schedule`, `/assets/<id>/pause`, `/assets/<id>/resume`, `/assets/<id>/delete`) for any future phase that needs to link into or extend Asset management.

---
*Phase: 01-asset-inventory-continuous-scanning*
*Completed: 2026-08-10*

## Self-Check: PASSED

All created/modified files verified present on disk; commits `761dc0e` and `8414c91` verified present in `git log --oneline --all`.
