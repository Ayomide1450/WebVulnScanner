---
phase: 01-asset-inventory-continuous-scanning
plan: 01
subsystem: infra
tags: [flask, sqlalchemy, alembic, threading, scheduler, entitlements, ssrf]

requires: []
provides:
  - "Asset model (assets table) + Scan.asset_id FK, migrated"
  - "webvulnscanner/scheduler.py: in-process daemon-thread tick loop, DB-level claim guard, fire-time SSRF/tier re-checks, dispatch through the existing _spawn_scan_thread path"
  - "webvulnscanner/asset_routes.py: /assets, /assets/new (registration + org/solo-scoped inventory list)"
  - "entitlements.effective_tier_for_org(org): org-shaped tier lookup for non-request callers"
  - "templates/asset_new.html, templates/assets.html reusing the existing dark-OLED design system"
affects: [01-02-PLAN.md]

actuals:
  tokens: 12700
  tasks: 1
  commits: 1

tech-stack:
  added: []
  patterns:
    - "In-process daemon-thread scheduler (no APScheduler/cron dep) ticking on a fixed interval, pushing a fresh app context per tick"
    - "DB-level claim guard: conditional UPDATE ... WHERE locked_until IS NULL OR locked_until < now, checked via result.rowcount, synchronize_session=False to avoid SQLAlchemy's in-Python evaluate step"
    - "Fire-time re-derivation of every trust decision (tier, SSRF safety) - never cached from registration/claim time"
    - "Org-shaped entitlement lookup (effective_tier_for_org) alongside the existing user-shaped effective_tier, sharing one Plan->Tier mapping"
    - "404-not-403 org-scoped ownership with an explicit solo-user branch (created_by_user_id) to avoid a NULL == NULL org_id leak across unrelated solo accounts"

key-files:
  created:
    - webvulnscanner/scheduler.py
    - webvulnscanner/asset_routes.py
    - templates/asset_new.html
    - templates/assets.html
    - tests/test_scheduler.py
    - tests/test_asset_routes.py
    - migrations/versions/672a304d4921_add_assets_table_and_scans_asset_id.py
  modified:
    - webvulnscanner/models.py
    - webvulnscanner/entitlements.py
    - webvulnscanner/config.py
    - webvulnscanner/__init__.py
    - templates/base.html
    - tests/conftest.py

key-decisions:
  - "Followed CONTEXT.md's locked D-01..D-04 exactly: in-process daemon thread, DB-level claim-guard column, next_run_at timestamp cadence, and failure handling that never pauses the schedule."
  - "Added synchronize_session=False to the claim-guard UPDATE (not specified in RESEARCH.md's skeleton) - SQLite round-trips DateTime(timezone=True) as tz-naive, and SQLAlchemy's default in-Python evaluate sync strategy crashed comparing a tz-naive loaded attribute against the tz-aware `now` used in the WHERE clause. Portable across Postgres/SQLite either way since the caller re-fetches by primary key afterward."
  - "GET /assets route registered as `@asset.route(\"\")` (not `\"/\"`) under url_prefix=\"/assets\" so the endpoint is exactly `/assets` with no redirect, matching the plan's literal route spec and avoiding a 308 in tests/clients that don't auto-follow redirects."

requirements-completed: [ASSET-01, ASSET-02, ASSET-04, ASSET-07, ASSET-08]

coverage:
  - id: D1
    description: "Registering an Asset creates a persistent row distinct from a manual Scan, appearing in an org/solo-scoped /assets inventory list"
    requirement: "ASSET-01"
    verification:
      - kind: integration
        ref: "tests/test_asset_routes.py#test_post_new_asset_valid_creates_asset_and_redirects"
        status: pass
      - kind: integration
        ref: "tests/test_asset_routes.py#test_registered_asset_appears_in_list"
        status: pass
    human_judgment: false
  - id: D2
    description: "Registration rejects a missing authorization checkbox or an SSRF-unsafe target with the same error copy manual scan submission uses, and creates no Asset row"
    requirement: "ASSET-02"
    verification:
      - kind: integration
        ref: "tests/test_asset_routes.py#test_post_new_asset_missing_authorized_checkbox_is_rejected"
        status: pass
      - kind: integration
        ref: "tests/test_asset_routes.py#test_post_new_asset_unsafe_target_is_rejected"
        status: pass
    human_judgment: false
  - id: D3
    description: "A due Asset is picked up by the scheduler's next tick and produces exactly one new Scan row linked via asset_id, without manual intervention"
    requirement: "ASSET-04"
    verification:
      - kind: unit
        ref: "tests/test_scheduler.py#test_tick_fires_due_asset_and_creates_one_scan"
        status: pass
    human_judgment: false
  - id: D4
    description: "A Free-tier Asset scheduled for media/api never runs that scan on a tick; upgrading the org's plan is respected at the Asset's next fire, not retroactively"
    requirement: "ASSET-07"
    verification:
      - kind: unit
        ref: "tests/test_scheduler.py#test_free_tier_media_schedule_fails_without_spawning"
        status: pass
      - kind: unit
        ref: "tests/test_scheduler.py#test_free_tier_api_schedule_fails_without_spawning"
        status: pass
      - kind: unit
        ref: "tests/test_scheduler.py#test_tier_upgrade_is_respected_at_next_fire_not_retroactively"
        status: pass
    human_judgment: false
  - id: D5
    description: "Two concurrent claim attempts on the same due Asset result in only one process winning the claim, never two Scan rows for one fire"
    requirement: "ASSET-08"
    verification:
      - kind: unit
        ref: "tests/test_scheduler.py#test_try_claim_second_call_loses_the_race"
        status: pass
      - kind: unit
        ref: "tests/test_scheduler.py#test_tick_never_double_fires_the_same_asset_in_one_tick"
        status: pass
    human_judgment: false
  - id: D6
    description: "A scheduled fire re-checks SSRF safety at fire time (not just registration) and records a FAILED Scan, never a silent skip or crash, when the target is no longer safe"
    verification:
      - kind: unit
        ref: "tests/test_scheduler.py#test_fire_time_ssrf_failure_produces_failed_scan_without_spawning"
        status: pass
      - kind: unit
        ref: "tests/test_scheduler.py#test_fire_time_ssrf_failure_does_not_pause_or_change_schedule"
        status: pass
    human_judgment: false
  - id: D7
    description: "Two different solo (no-org) users never see each other's Assets via the inventory list"
    verification:
      - kind: integration
        ref: "tests/test_asset_routes.py#test_two_solo_users_never_see_each_others_assets"
        status: pass
      - kind: integration
        ref: "tests/test_asset_routes.py#test_list_assets_scoped_to_org_excludes_other_orgs_assets"
        status: pass
    human_judgment: false

duration: 45min
completed: 2026-08-10
status: complete
---

# Phase 1 Plan 1: Asset Registration + In-Process Scheduler Tracer Summary

**Asset model + Alembic migration, a daemon-thread scheduler with a DB-level claim guard and fire-time SSRF/tier re-checks, and org/solo-scoped `/assets` registration + inventory routes — the full tracer slice for Phase 1's Asset architecture, proven end-to-end.**

## Performance

- **Duration:** ~45 min
- **Tasks:** 1 (tracer)
- **Files modified:** 13 (7 created, 6 modified)
- **Commits:** 1 task commit (`e8cae13`)

## Accomplishments
- `Asset` model (`assets` table) with a durable authorization audit trail (`authorized_by_user_id`/`authorized_at`), `next_run_at`/`locked_until`/`is_paused`/`deleted_at` schedule state, and `Scan.asset_id` FK — hand-reviewed, clean `create_table`+`add_column` Alembic migration, applied to the local dev SQLite DB.
- `webvulnscanner/scheduler.py`: an in-process daemon-thread tick loop (`start_scheduler`/`_scheduler_loop`/`_tick`/`_try_claim`/`_fire`) that claims due Assets via a conditional `UPDATE ... WHERE locked_until IS NULL OR locked_until < now`, re-derives SSRF safety and org tier at fire time (never cached from registration), and dispatches through the existing `_spawn_scan_thread` path unchanged for `base`/`media`/`api` schedule types.
- `webvulnscanner/asset_routes.py`: `/assets` (org/solo-scoped inventory list) and `/assets/new` (registration, reusing the exact authorization-checkbox and SSRF error copy `new_scan_base` already uses), with a 404-not-403 ownership check that explicitly branches on solo (no-org) users to avoid leaking one solo user's Assets to another via a naive `NULL == NULL` org_id comparison.
- `entitlements.effective_tier_for_org(org)` extracted from `effective_tier(user)` so the scheduler (which has an `Organization`, not a `User`) can look up tier without faking a user object; both functions now share one `Plan -> Tier` mapping.
- Three-part guarded scheduler startup in `create_app()` (`SCHEDULER_ENABLED` / `TESTING` / Werkzeug-reloader checks) with `SCHEDULER_ENABLED = False` in `TestConfig`, so the ~180-test suite never leaks a background thread.
- `templates/asset_new.html` / `templates/assets.html`, reusing `scan_new_base.html`'s form-card structure and `dashboard.html`'s table structure exactly, plus an "Assets" nav link in `base.html`.
- `tests/test_scheduler.py` (12 tests) + `tests/test_asset_routes.py` (8 tests): tick/claim-guard-race/tier-gate/SSRF-refire coverage and registration/authorization/ownership-scoping coverage.

## Task Commits

1. **Task 1: End-to-end Asset registration + automatic first scheduled fire** - `e8cae13` (feat)

**Plan metadata:** this SUMMARY.md + STATE.md/ROADMAP.md/REQUIREMENTS.md update (separate docs commit, see below)

## Files Created/Modified
- `webvulnscanner/models.py` - `Asset` model + `Scan.asset_id`/`Scan.asset` FK+relationship+index
- `webvulnscanner/entitlements.py` - `effective_tier_for_org(org)` extracted; `effective_tier(user)` delegates to it
- `webvulnscanner/scheduler.py` (new) - tick/claim-guard/fire scheduling engine
- `webvulnscanner/asset_routes.py` (new) - `asset` blueprint: `/assets`, `/assets/new`
- `webvulnscanner/config.py` - `SCHEDULER_ENABLED`, `SCHEDULER_POLL_INTERVAL_SECONDS`
- `webvulnscanner/__init__.py` - `_maybe_start_scheduler(app)`, `asset` blueprint registration
- `templates/asset_new.html` (new) - Asset registration form
- `templates/assets.html` (new) - Asset inventory list
- `templates/base.html` - "Assets" nav link
- `tests/conftest.py` - `SCHEDULER_ENABLED = False` on `TestConfig`, `make_asset(...)` factory
- `tests/test_scheduler.py` (new) - scheduler tick/claim-guard/tier-gate/SSRF-refire tests
- `tests/test_asset_routes.py` (new) - registration + ownership/scoping tests
- `migrations/versions/672a304d4921_add_assets_table_and_scans_asset_id.py` (new) - hand-reviewed Alembic migration

## Decisions Made
- Followed CONTEXT.md's locked decisions (D-01 in-process thread, D-02 DB claim guard, D-03 timestamp cadence, D-04 no-pause-on-failure) exactly as specified — no deviation from the scheduling architecture.
- `GET /assets` registered as `@asset.route("")` (not `"/"`) so the endpoint resolves to exactly `/assets` with no trailing-slash redirect.
- Media schedule fires default `download=False` for unattended runs, matching the plan's "more conservative default for a run nobody is watching" guidance.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Added `synchronize_session=False` to the claim-guard `UPDATE`**
- **Found during:** Task 1, first `pytest tests/test_scheduler.py` run
- **Issue:** RESEARCH.md's Pattern 3 skeleton uses a plain `db.session.execute(update(Asset)...)` with no `synchronize_session` option. SQLAlchemy's default "evaluate" strategy tries to sync the WHERE clause against already-loaded ORM objects in Python before hitting the DB. On SQLite, `DateTime(timezone=True)` columns round-trip as timezone-naive, so comparing a loaded (naive) `Asset.locked_until`/`next_run_at` attribute against the timezone-aware `now` passed into the WHERE clause raised `TypeError: can't compare offset-naive and offset-aware datetimes`.
- **Fix:** Added `.execution_options(synchronize_session=False)` to the claim UPDATE — this is a Core-style conditional UPDATE where only `result.rowcount` matters to the caller; the caller (`_tick`) already re-fetches the Asset by primary key afterward, so no in-session attribute sync is needed. Portable to Postgres (which preserves tz-aware datetimes and would not have hit this) without behavior change.
- **Files modified:** `webvulnscanner/scheduler.py`
- **Verification:** `pytest tests/test_scheduler.py` — all claim-guard and tick tests pass
- **Committed in:** `e8cae13` (Task 1 commit)

**2. [Rule 3 - Blocking] Named the `scans.asset_id` FK constraint in the generated migration**
- **Found during:** Task 1, `flask db upgrade`
- **Issue:** Flask-Migrate's autogenerate emitted `batch_op.create_foreign_key(None, 'assets', ['asset_id'], ['id'])` (unnamed). SQLite's batch-alter mode (required for adding a column + FK to an existing table) rejects an unnamed constraint with `ValueError: Constraint must have a name`.
- **Fix:** Named the constraint `fk_scans_asset_id_assets` in both `upgrade()` and the matching `downgrade()`'s `drop_constraint` call.
- **Files modified:** `migrations/versions/672a304d4921_add_assets_table_and_scans_asset_id.py`
- **Verification:** `flask db upgrade` applies cleanly to a fresh local SQLite DB
- **Committed in:** `e8cae13` (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 blocking). Both necessary for correctness; no scope creep.

## Issues Encountered

**Cross-repo `.env` leak via Flask CLI's automatic dotenv loading (caught before any write, no data affected).** This worktree has no `.env` file of its own. Flask's CLI (`flask db migrate`/`flask db upgrade`) auto-loads a `.env` by walking **upward** from the current working directory (`python-dotenv`'s `find_dotenv(usecwd=True)`) — from this worktree at `.claude/worktrees/lazy-drifting-quilt`, that walk found and loaded the **main repo's real `.env`** (three directories up), which points `SQLALCHEMY_DATABASE_URI` at what appears to be a live Postgres (Neon) database, before `webvulnscanner/config.py`'s own explicit (and correctly worktree-scoped, but no-op since no local `.env` exists) `load_dotenv()` call ever ran. The first `flask db migrate` invocation connected to that real database for its autogenerate diff (read-only introspection: `SELECT`/catalog queries only — `flask db migrate` and `flask db current` never issue DDL) and the newly-added scheduler's background thread also fired one harmless read-only `SELECT ... FROM assets WHERE ...` against it (table doesn't exist there, so it errored and logged, changing nothing). No `flask db upgrade` (the only DDL-issuing command) was ever run against that connection — this was caught and diagnosed before that step. Recovery: discarded the migration generated against the wrong DB, set `FLASK_SKIP_DOTENV=1` for every subsequent `flask` CLI invocation (skips Flask's automatic `.env`/`.flaskenv` search entirely, forcing `webvulnscanner/config.py`'s own explicit, correctly-scoped `load_dotenv()` — a no-op here — to be the only source), recreated a fresh local `webvulnscanner.db`, and regenerated the migration cleanly against it. **This is a process risk worth flagging beyond this plan**: any future `flask` CLI command run from inside this worktree without `FLASK_SKIP_DOTENV=1` will silently reconnect to the main repo's real database. Not fixed in code (no application code owns this — it's a Flask-CLI/python-dotenv interaction specific to the worktree directory layout), but is now known and documented here for the next executor.

## User Setup Required

None - no external service configuration required. The scheduler is entirely in-process/stdlib; no new environment variables are required to run it (`SCHEDULER_ENABLED`/`SCHEDULER_POLL_INTERVAL_SECONDS` both have safe defaults).

## Next Phase Readiness

- The `Asset` model, `scheduler.py` engine, and `asset_routes.py` ownership pattern are proven end-to-end (tick → claim → fire → Scan, tier/SSRF re-checks, org/solo scoping) and ready for Plan 01-02 to build pure UI expansion on top of (schedule editing, pause/resume/delete, history/trend view, ASSET-05/06 and the remaining half of ASSET-03).
- Full test suite (160 tests) green; `flask db upgrade` applies cleanly to a fresh local SQLite DB with no manual intervention.
- **Flag for the next executor / for ops before any real `flask db upgrade` against a shared DB:** confirm `SQLALCHEMY_DATABASE_URI` resolves to the intended target before running `flask db upgrade` from inside a worktree — see "Issues Encountered" above. Setting `FLASK_SKIP_DOTENV=1` (or an explicit `SQLALCHEMY_DATABASE_URI` env var) before any `flask db *` command is the safe pattern.

---
*Phase: 01-asset-inventory-continuous-scanning*
*Completed: 2026-08-10*

## Self-Check: PASSED

All created files verified present on disk; commit `e8cae13` verified present in `git log --oneline --all`.
