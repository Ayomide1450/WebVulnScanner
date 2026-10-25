---
phase: 01-asset-inventory-continuous-scanning
verified: 2026-08-10T00:00:00Z
status: passed
score: 5/5 must-haves verified
behavior_unverified: 0
overrides_applied: 0
---

# Phase 1: Asset Inventory & Continuous Scanning Verification Report

**Phase Goal:** Users can register a domain they own once as a persistent Asset and have
Glassbox scan it automatically on a recurring schedule, building a history over time —
instead of manually resubmitting the same target for every scan.
**Verified:** 2026-08-10
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | User can add a domain as a persistent Asset (separate from a one-off scan) that appears in an Asset inventory list | ✓ VERIFIED | `Asset` model (`glassbox/models.py:137-182`, `__tablename__ = "assets"`), `POST /assets/new` (`asset_routes.py:69-128`) creates a row and redirects to `GET /assets` (`list_assets`, `asset_routes.py:62-66`) which renders `templates/assets.html`. `Scan.asset_id` is nullable (`models.py:199`) so the existing one-off `new_scan_*` flow is untouched — Assets are a genuinely separate entity. Confirmed with a live SQLite DB: `assets` table exists with all expected columns (verified via direct `sqlite3` introspection), migration `672a304d4921` applied. Tests: `test_post_new_asset_valid_creates_asset_and_redirects`, `test_registered_asset_appears_in_list` — both pass. |
| 2 | Adding an Asset requires the same authorization checkbox and SSRF-safe-hostname check as submitting a manual scan — no weaker gate | ✓ VERIFIED | `asset_routes.py:75-93`: `new_asset()` checks `request.form.get("authorized")` (reusing the exact error copy `"You must confirm you own or are authorized to test this domain."` from `scan_routes.py`'s `new_scan_base`) then calls `is_ssrf_safe_hostname(hostname)` from `glassbox/checks.py` (reusing the exact SSRF error copy) before any `Asset` row is created. `templates/asset_new.html` has a `required` checkbox (`id="authorized"`). Tests: `test_post_new_asset_missing_authorized_checkbox_is_rejected`, `test_post_new_asset_unsafe_target_is_rejected` — both pass, and assert no Asset row is created on rejection. |
| 3 | User can set a recurring scan schedule on an Asset (cadence + scan type), and a scan runs automatically at that cadence without the user manually starting it | ✓ VERIFIED | Cadence (`daily`/`weekly`/`monthly`) and `schedule_scan_type` (`base`/`media`/`api`) are set at registration and editable via `POST /assets/<id>/schedule` (`update_schedule`, `asset_routes.py:152-172`). `glassbox/scheduler.py`'s in-process daemon thread (`start_scheduler`→`_scheduler_loop`→`_tick`→`_try_claim`→`_fire`) independently finds due Assets and dispatches through the existing, unmodified `_spawn_scan_thread` (imported from `scan_routes.py`) — no user action required. Wired into the app factory via `_maybe_start_scheduler(app)` in `glassbox/__init__.py:20-43`, called at the end of `create_app()`, guarded against double-start (SCHEDULER_ENABLED / TESTING / Werkzeug reloader). Tests: `test_tick_fires_due_asset_and_creates_one_scan`, `test_tick_advances_next_run_at_by_cadence` — both pass. |
| 4 | User can view an Asset's scan history/trend across multiple scheduled runs, not just the latest single scan | ✓ VERIFIED | `GET /assets/<id>` (`asset_detail`, `asset_routes.py:144-149`) queries `Scan.query.filter_by(asset_id=a.id).order_by(Scan.created_at.desc())` and renders `templates/asset_detail.html`, which shows a risk-score sparkline trend (SVG polyline over all scored scans, oldest-to-newest) and a full scan-history table, not just the latest scan. Tests: `test_get_asset_detail_shows_populated_scan_history` passes. |
| 5 | User can pause, resume, or delete an Asset's schedule; a Free-tier Asset's scheduled scan never silently runs Paid/Org-verified-only checks | ✓ VERIFIED | `POST /assets/<id>/pause`, `/resume`, `/delete` (`asset_routes.py:175-212`) all present, all guarded by `_check_asset_access`. `pause_asset` sets `is_paused=True`; `resume_asset` clears it; `delete_asset` soft-deletes (`deleted_at`) and also pauses (belt-and-suspenders) — `scheduler._tick`'s due-Asset query filters `Asset.is_paused.is_(False), Asset.deleted_at.is_(None)` (`scheduler.py:131-135`), so paused/deleted Assets are excluded from firing. Tier gating: `scheduler.py::_fire` (lines 91-101) recomputes `effective_tier_for_org(asset.organization)` **at fire time** (never cached from registration) and checks `FEATURE_REQUIREMENTS[asset.schedule_scan_type] > tier` for `media`/`api`, writing a `FAILED` Scan and returning **without spawning a thread** if the org's tier is insufficient. Tests: `test_free_tier_media_schedule_fails_without_spawning`, `test_free_tier_api_schedule_fails_without_spawning`, `test_tier_upgrade_is_respected_at_next_fire_not_retroactively`, `test_pause_resume_delete_pause_excludes_asset_from_due_query`, `test_pause_resume_delete_resume_reincludes_asset_in_due_query`, `test_pause_resume_delete_delete_soft_deletes_and_keeps_scan_history` — all pass. |

**Score:** 5/5 truths verified (0 present-but-behavior-unverified)

### Cross-Tenant IDOR Fix (Solo Users, org_id = NULL) — Explicitly Re-Verified

This was flagged as a specific risk area (`_check_asset_access` in `asset_routes.py:38-51`): a naive
`a.org_id == current_user.org_id` comparison would match `NULL == NULL` for two unrelated solo
(no-org) users, leaking one solo user's Assets to another. The code has an explicit branch:

```python
if current_user.org_id is not None:
    if a.org_id == current_user.org_id:
        return
    abort(404)
if a.org_id is None and a.created_by_user_id == current_user.id:
    return
abort(404)
```

**Independently verified (not just code-read):**
- Ran the project's own tests: `test_two_solo_users_never_see_each_others_assets` (list-view scoping) and `test_list_assets_scoped_to_org_excludes_other_orgs_assets` — both pass.
- The existing suite covers cross-org **direct-URL** access (`test_get_asset_detail_for_other_org_is_404` — passes) but had no test for cross-**solo-user** direct-URL access. I wrote and ran an ad-hoc test (added to `tests/`, executed, then removed — no residual changes, confirmed via `git status`) exercising exactly that gap:
  - `GET /assets/<id>` for solo user B against solo user A's Asset → **404** (confirmed)
  - `POST /assets/<id>/pause` for solo user B against solo user A's Asset → **404** (confirmed)

The fix is real, implemented, and functions correctly for both the list view and every direct-URL/mutation route (`asset_detail`, `update_schedule`, `pause_asset`, `resume_asset`, `delete_asset` all share the same `_check_asset_access` guard).

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `glassbox/models.py` | `Asset` model + `Scan.asset_id` FK | ✓ VERIFIED | `class Asset(db.Model)` present with all documented columns; `Scan.asset_id` nullable FK + `Scan.asset` relationship + `ix_scans_asset_created` index present |
| `migrations/versions/672a304d4921_*.py` | assets table + scans.asset_id migration | ✓ VERIFIED | Hand-reviewed migration present; applied to local dev SQLite DB (confirmed via direct introspection — `alembic_version` = `672a304d4921`, `assets` table exists with all 15 expected columns, `scans.asset_id` column present) |
| `glassbox/scheduler.py` | tick/claim-guard/fire scheduling engine | ✓ VERIFIED | `start_scheduler`, `_scheduler_loop`, `_tick`, `_try_claim`, `_fire` all present and match the plan's design exactly (conditional `UPDATE ... WHERE locked_until IS NULL OR locked_until < now`, fire-time re-derivation of tier/SSRF, dispatch via unmodified `_spawn_scan_thread`) |
| `glassbox/asset_routes.py` | Asset registration + inventory + detail + lifecycle routes | ✓ VERIFIED | `list_assets`, `new_asset`, `asset_detail`, `update_schedule`, `pause_asset`, `resume_asset`, `delete_asset` all present; blueprint registered in `__init__.py` |
| `glassbox/entitlements.py` | org-shaped tier helper | ✓ VERIFIED | `effective_tier_for_org(org)` present; `effective_tier(user)` delegates to it; single `Plan -> Tier` mapping |
| `templates/asset_new.html`, `templates/assets.html`, `templates/asset_detail.html` | registration form, inventory list, detail page | ✓ VERIFIED | All three present, reuse existing design system (`.card`, `.table-scroll`, `.status-pill`, `.warn-box`, `.error-box`), no stub content |
| `tests/test_scheduler.py`, `tests/test_asset_routes.py` | coverage for scheduler + routes | ✓ VERIFIED | 172 tests in full suite pass (up from ~148 pre-phase); both files present with substantive, non-trivial test bodies (verified by reading several test bodies, not just counting) |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `glassbox/__init__.py` | `glassbox/scheduler.py` | `_maybe_start_scheduler(app)` → `start_scheduler(app)` | ✓ WIRED | Called at end of `create_app()` (`__init__.py:156`), three-part guard confirmed present |
| `glassbox/scheduler.py` | `glassbox/scan_routes.py` | `_fire()` calls `_spawn_scan_thread` | ✓ WIRED | Imported unchanged at module top (`scheduler.py:24`), invoked in `_fire()` for all three schedule types with correct per-type kwargs |
| `glassbox/scheduler.py` | `glassbox/entitlements.py` | `_fire()` calls `effective_tier_for_org()` at fire time | ✓ WIRED | `scheduler.py:77`, called fresh inside `_fire`, never cached |
| `glassbox/asset_routes.py` | `glassbox/checks.py` | `new_asset()` calls `is_ssrf_safe_hostname()` | ✓ WIRED | `asset_routes.py:88`, before Asset creation |
| `templates/asset_detail.html` | `glassbox/asset_routes.py` | POST forms for schedule/pause/resume/delete | ✓ WIRED | All four forms use `url_for('asset.*', asset_id=asset.id)` with CSRF tokens |
| `glassbox/asset_routes.py::delete_asset` | `glassbox/scheduler.py::_tick` | `deleted_at` set on delete, excluded from due-Asset query | ✓ WIRED | `_tick`'s query filters `Asset.deleted_at.is_(None)` |
| `templates/assets.html` | `glassbox/asset_routes.py::asset_detail` | Name/Actions columns link to detail page | ✓ WIRED | Fixed in 01-02 (flagged in SUMMARY as a Rule-2 deviation — the inventory list would otherwise have been a dead end) |

### Behavioral Spot-Checks / Test Execution

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full project test suite | `pytest` (via main-repo `.venv`) | **172 passed, 0 failed, 0 errors** in 107.41s | ✓ PASS |
| DB migration state matches models | direct `sqlite3` introspection of `glassbox.db` | `alembic_version` = `672a304d4921`; `assets` table has all 15 model-declared columns; `scans.asset_id` present | ✓ PASS |
| Cross-tenant IDOR (solo users, direct URL, `GET /assets/<id>`) | ad-hoc pytest (added, run, removed) | 404 confirmed | ✓ PASS |
| Cross-tenant IDOR (solo users, direct URL, `POST /assets/<id>/pause`) | ad-hoc pytest (added, run, removed) | 404 confirmed | ✓ PASS |
| Claim-guard race (two concurrent `_try_claim` calls) | `test_try_claim_second_call_loses_the_race` | second call returns `False` (rowcount 0) | ✓ PASS |
| Fire-time SSRF re-check | `test_fire_time_ssrf_failure_produces_failed_scan_without_spawning` | `Scan(FAILED)`, no thread spawned | ✓ PASS |
| Tier upgrade respected at next fire, not retroactively | `test_tier_upgrade_is_respected_at_next_fire_not_retroactively` | first fire fails (Free), second fire (post-upgrade) succeeds | ✓ PASS |

**Note on test suite independence:** I did not trust the executors' self-reported "172 tests, all green" claim from the SUMMARY files. I ran `pytest` myself directly against this worktree (via the main repo's `.venv`, since this worktree has no local venv — same interpreter/dependency set the executors used) and independently confirmed **172 passed, 0 failed**. I additionally wrote and ran my own ad-hoc test (not part of the shipped suite) specifically targeting the solo-user cross-tenant IDOR gap that the existing suite did not directly cover for detail-page/mutation routes, and confirmed it holds.

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| ASSET-01 | 01-01 | Persistent Asset registration, distinct from one-off scan | ✓ SATISFIED | `Asset` model, `new_asset` route, `list_assets` |
| ASSET-02 | 01-01 | Same authorization + SSRF gate as manual scan | ✓ SATISFIED | `new_asset` reuses exact checkbox check + `is_ssrf_safe_hostname` + exact error copy |
| ASSET-03 | 01-01 (initial) + 01-02 (editing) | Configurable recurring schedule (cadence + scan type) | ✓ SATISFIED | Set at registration; editable via `update_schedule` |
| ASSET-04 | 01-01 | Scheduled scan runs automatically, producing a linked Scan | ✓ SATISFIED | `scheduler.py` tick→claim→fire pipeline |
| ASSET-05 | 01-02 | Scan history/trend view | ✓ SATISFIED | `asset_detail` page: sparkline + history table |
| ASSET-06 | 01-02 | Pause/resume/delete controls | ✓ SATISFIED | `pause_asset`/`resume_asset`/`delete_asset` routes |
| ASSET-07 | 01-01 | Scheduled scan respects tier entitlement, no silent Paid/Org-verified execution on Free tier | ✓ SATISFIED | `_fire()` re-derives tier at fire time, gates `media`/`api` |
| ASSET-08 | 01-01 | Scheduling mechanism compatible with single-worker Render deployment | ✓ SATISFIED | In-process daemon thread, no external scheduler/cron dependency, DB-level claim guard for multi-worker safety even though not yet needed |

No orphaned requirements — REQUIREMENTS.md's traceability table maps all 8 ASSET-* requirements to Phase 1, and both plans together claim all 8.

### Anti-Patterns Found

None. Scanned all phase-modified core files (`scheduler.py`, `asset_routes.py`, `models.py`, `entitlements.py`, `asset_new.html`, `assets.html`, `asset_detail.html`) for `TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER`/"not yet implemented"/"coming soon" — the only matches were legitimate HTML `placeholder=` input attributes (form hint text), not debt markers. No empty-implementation patterns (`return null`/`return {}`/`=> {}`), no hardcoded-empty stub props, no console.log-only handlers.

### Human Verification Required

None required to certify the phase goal. All must-haves are either directly testable via the existing automated suite or were independently exercised by this verification (DB introspection, ad-hoc IDOR tests, direct `pytest` execution). The one item the 01-02 SUMMARY itself flagged as `human_judgment: true` (D7: icon-only buttons are visually 44px with correct `aria-label`s) is a cosmetic/accessibility detail that does not affect goal achievement — code inspection confirms `.icon-btn { min-width: 44px; min-height: 44px; }` and each button has a distinct, descriptive `aria-label`, which is sufficient for this verification's purposes; visual confirmation in a real browser is optional polish, not a phase-goal blocker.

### Gaps Summary

No gaps found. All 5 ROADMAP Success Criteria are observably true in the codebase, all 8 ASSET
requirements are satisfied with real (not stubbed) implementations, every safety-critical link
(authorization checkbox, SSRF-safe-hostname check, tier-entitlement gating, cross-tenant ownership
scoping) is wired through the exact same code paths as manual scan submission — not a weaker
parallel gate — and the scheduler genuinely fires scans without user action, re-deriving trust
decisions fresh at fire time rather than trusting stale registration-time state. The cross-tenant
IDOR fix for solo (no-org) users is real, implemented, and independently confirmed to hold for both
list-view scoping and direct-URL/mutation-route access. The full test suite (172 tests) passes when
run directly by the verifier, not merely as claimed in the SUMMARY files.

---

_Verified: 2026-08-10_
_Verifier: Claude (gsd-verifier)_
