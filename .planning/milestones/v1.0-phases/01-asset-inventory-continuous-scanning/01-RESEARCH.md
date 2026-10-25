# Phase 1: Asset Inventory & Continuous Scanning - Research

**Researched:** 2026-08-10
**Domain:** In-process scheduled background execution inside an existing Flask app-factory /
SQLAlchemy / Alembic / gunicorn stack, layered on top of an already-shipped async-scan execution
model.
**Confidence:** MEDIUM-HIGH — the scheduling-mechanism shape is fully locked by CONTEXT.md
(D-01..D-04); this research resolves the *implementation* pitfalls of that locked shape against
the actual codebase (verified by reading source), plus cross-checked web guidance for the
mechanics that aren't project-specific (Werkzeug reloader guard, SQLAlchemy claim-UPDATE pattern).

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**D-01 — Scheduling Trigger Mechanism:** Use an in-process daemon background thread to
periodically check for due schedules, reusing the same pattern already established for scan
execution (`_spawn_scan_thread`/`_run_scan_in_background` in `glassbox/scan_routes.py`)
rather than introducing APScheduler or a separate scheduled process/Render Cron Job.

**D-02 — Multi-Worker Safety:** Add a DB-level claim guard now (e.g. a `locked_until`/
`claimed_at` column on the schedule-bearing table plus a conditional `UPDATE ... WHERE
locked_until IS NULL OR locked_until < now()`), even though the deployment is single-worker
(`--workers 1`) today. Production DB is Postgres (Neon per `render.yaml`).

**D-03 — Cadence Model:** Model cadence as a `next_run_at` timestamp on the Asset/schedule,
advanced by a fixed interval (daily/weekly/monthly) each time it fires, checked by a
fixed-interval tick (e.g. every few minutes) — not a cron-expression parser (no
`croniter`/APScheduler cron trigger).

**D-04 — Failure Handling:** A failed scheduled scan does not pause or otherwise change the
Asset's schedule state — it keeps ticking at its normal cadence next time, mirroring existing
manual-scan failure semantics (`Scan.status = FAILED`, `error_message` stored, never stuck at
`RUNNING`). No new auto-pause-after-N-failures or notification system for v1.

### Claude's Discretion

- **Schedule configuration & scan-type selection UX** — exact cadence preset options, which scan
  type(s) (base/advanced/media/API) can be attached to a schedule, and how tier gating is
  surfaced in the UI when a schedule's chosen scan type exceeds the org's current tier.
- **Asset ↔ Scan/Report relationship** — whether registering an Asset immediately triggers a
  first scan or only arms the schedule; whether one-off manual scans remain available without
  requiring an Asset to exist first; exact shape of the history/trend view (ASSET-05).
- **Pause/resume/delete + tier-downgrade semantics** — soft-delete vs. hard-delete for an Asset;
  what happens to an active schedule when an org's tier downgrades mid-cycle (the scheduled scan
  type becomes locked) — silently downgrade the scan type run, skip that tick with a stored
  reason, or pause the whole schedule. Must satisfy ASSET-07 regardless of which specific UX is
  chosen.

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope. The three Claude's-Discretion areas above are
within-phase implementation ambiguity, not new capabilities.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| ASSET-01 | Register a domain/target as a persistent Asset (name, target URL, hostname) tied to org, distinct from a one-off manual scan | Architecture Patterns → "Asset registration route"; Code Examples → migration skeleton; reuses `Scan`-table naming conventions verified in `models.py` |
| ASSET-02 | Asset registration enforces same `authorized` checkbox + `is_ssrf_safe_hostname()` gate as manual scan submission | Common Pitfalls → "Durable authorization vs. one-shot checkbox"; Code Examples → registration route skeleton reusing `_unsafe_target_error` |
| ASSET-03 | Configure recurring schedule (cadence + scan type) for an Asset | Architecture Patterns → "Cadence/next_run_at model"; Don't Hand-Roll → cadence math |
| ASSET-04 | Scheduled scan runs automatically at cadence, producing a new `Scan`/`Report` linked to the Asset | Architecture Patterns → "Scheduler tick handler"; Code Examples → tick loop + claim guard |
| ASSET-05 | View Asset scan history/trend across scheduled runs | Architecture Patterns → "Asset↔Scan relationship" (asset_id FK on Scan) |
| ASSET-06 | Pause/resume/delete an Asset's schedule | Architecture Patterns → schema design (`is_paused`, `next_run_at` semantics) |
| ASSET-07 | Scheduled scan execution respects tier-entitlement gating — no silent Paid/Org-verified checks on Free-tier schedule | Common Pitfalls → "media/api orchestrators are NOT self-gating" (the single highest-risk pitfall in this phase); Code Examples → fire-time tier recheck |
| ASSET-08 | Scheduling mechanism periodically checks due schedules and triggers scans, compatible with single-worker threaded-gunicorn Render deployment | Research Question 1 (reloader guard) + Research Question 4 (long-lived thread + app context); Common Pitfalls → "conftest.py fresh-app-per-test" |
</phase_requirements>

## Summary

The four locked decisions (D-01..D-04) fully determine the scheduling mechanism's shape: an
in-process daemon thread that ticks on a fixed interval, claims due `Asset` rows via a
conditional `UPDATE ... WHERE locked_until IS NULL OR locked_until < now()`, and fires scans
through the existing `_spawn_scan_thread`/`_run_scan_in_background` path. Nothing in this research
overturns that shape. What this research adds is the set of concrete implementation pitfalls that
sit between "the shape is decided" and "the code is correct," discovered by reading the actual
source this session rather than assuming from the pattern's name:

1. **The single highest-risk gap for ASSET-07** is that `run_media_scan`/`run_api_scan` are
   **not internally tier-gated** — `scan_engine.py`'s own module docstring documents this as an
   intentional asymmetry, with gating enforced one level up, in the *route*, before the
   orchestrator is ever called. A scheduler tick handler has no route in the loop, so if a
   schedule's `scan_type` is `media` or `api`, the tick handler itself must replicate that
   pre-check (`FEATURE_REQUIREMENTS[scan_type] <= tier`) or a Free-tier Asset scheduled for a
   Paid-tier media/API scan will silently run it every time it fires.
2. **`conftest.py`'s `app` fixture creates a brand-new Flask app per test** (fresh SQLite file
   under `tmp_path`, `_db.create_all()`/`_db.drop_all()` per test). If the scheduler thread
   auto-starts unconditionally inside `create_app()`, every one of this project's ~150+ existing
   tests spawns its own infinite background thread against a soon-to-be-deleted SQLite file.
   The thread-start must be gated behind an explicit config flag (e.g. `SCHEDULER_ENABLED`,
   default off when `TESTING` is set) in addition to the Werkzeug-reloader guard.
3. `entitlements.effective_tier(user)` is **user-shaped**, not org-shaped — it expects an object
   with `.is_authenticated`/`.organization`. The scheduler has an `Organization`, not a `User`,
   at tick time. This is a real integration gap, not a design choice; the planner needs a small
   org-shaped tier helper (or a refactor of `effective_tier`) rather than constructing a fake user.
4. The claim guard (D-02) and the reschedule (`next_run_at` advance, D-03) are separate concerns:
   the lease (`locked_until`) exists to stop two ticks from concurrently *processing* the same due
   Asset; `next_run_at` is what actually determines whether an Asset is still "due" for the next
   tick. Advancing `next_run_at` should happen as part of claiming (not after the spawned scan
   completes, since scans are async and can outlive many tick intervals).

**Primary recommendation:** Add one new `assets` table (schedule fields inline, no separate
join table — ASSET-03 describes one cadence + one scan type per Asset, not multiple schedules)
plus a nullable `asset_id` FK on the existing `scans` table; add a new bare-named module
`glassbox/scheduler.py` (not a blueprint) holding the tick loop, the claim-guard UPDATE, and
a thin wrapper around the existing `_spawn_scan_thread`/`_run_scan_in_background`; start it from
`create_app()` behind a three-part guard (config opt-out for tests, `TESTING` check, Werkzeug
reloader check) rather than a Flask request hook (`before_first_request` no longer exists in
Flask 3.x).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Asset registration (form, authorization checkbox, SSRF gate) | API/Backend (Flask route, new `asset_routes.py` blueprint or extend `scan_routes.py`) | — | Same tier as existing manual-scan submission routes; reuses `is_ssrf_safe_hostname`/`entitlements` |
| Schedule configuration (cadence, scan type) | API/Backend | Database/Storage (`next_run_at`, `is_paused` columns) | Config is a form-driven mutation of the `Asset` row, no new tier needed |
| Scheduling trigger (tick loop, claim guard) | API/Backend (in-process daemon thread inside the same Flask/gunicorn process) | Database/Storage (claim-guard UPDATE, Postgres row-level write lock) | D-01 explicitly rejects a separate process/tier (no external scheduler service) — the trigger lives inside the same backend tier as request handling |
| Scan execution (once triggered) | API/Backend (reused `_spawn_scan_thread`/`_run_scan_in_background`) | — | Unchanged — Phase 1 must route through this existing execution tier, not build a parallel one |
| Scan history / trend view | API/Backend (query) + Browser/Client (render) | Database/Storage (`Scan.asset_id` FK, indexed) | Server-rendered Jinja2 per existing convention (no client-side app-state framework in this codebase) |
| Tier/entitlement re-check at fire time | API/Backend (`entitlements.py`, extended) | — | Must be re-evaluated at fire time, not scheduling time, so a mid-cycle tier downgrade (ASSET-07) is respected on the very next fire |

## Standard Stack

### Core

No new third-party packages are required for this phase. D-01 explicitly rejects introducing
APScheduler; the scheduling mechanism is built entirely from the stdlib (`threading`, `time`,
`datetime`) plus the already-installed `Flask-SQLAlchemy`/`Flask-Migrate` used for the claim guard
and schema migration.

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `threading` (stdlib) | Python 3.12 (project-pinned, `render.yaml`) [VERIFIED: .planning/codebase/STACK.md "Python 3.12 - entire backend...pinned via PYTHON_VERSION: \"3.12.0\" in render.yaml"] | Daemon background thread for the tick loop | Already the project's sole async-execution mechanism (`_spawn_scan_thread`) — D-01 mandates reusing this pattern, not introducing a new one |
| Flask-SQLAlchemy | unpinned in `requirements.txt` [VERIFIED: .planning/codebase/STACK.md "Flask-SQLAlchemy - requirements.txt; ORM layer"] | `Asset` model, claim-guard `UPDATE`, `Scan.asset_id` FK | Already the project's ORM; no alternative under consideration |
| Flask-Migrate (Alembic) | unpinned in `requirements.txt` [VERIFIED: .planning/codebase/STACK.md "Flask-Migrate - requirements.txt; Alembic-backed schema migrations"] | New `assets` table + `scans.asset_id` column migration | Already the sanctioned schema-change mechanism (`migrations/`, confirmed live via baseline revision read this session) |

### Supporting

None new.

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| In-process daemon thread (D-01) | APScheduler (`BackgroundScheduler`) | Rejected by D-01 — adds a dependency and its own reloader/multi-worker footguns for marginal benefit over a plain `while True` loop, given the fixed-interval (not cron-expression) cadence model D-03 already locks in |
| In-process daemon thread (D-01) | Render Cron Job (separate scheduled process) | Rejected by D-01 — would require re-architecting how the trigger reaches the Flask app-context/DB, and duplicating deployment config outside `render.yaml`'s existing single web service |
| `locked_until` conditional UPDATE (D-02) | Postgres `SELECT ... FOR UPDATE SKIP LOCKED` | Not chosen — Postgres-only (breaks SQLite dev parity that this codebase deliberately preserves everywhere else, e.g. `_engine_options_for()` in `config.py`), and requires holding a transaction open across the claim+dispatch boundary, which doesn't fit the existing "commit claim, then separately dispatch async work" pattern `_run_scan_in_background` already establishes |
| `next_run_at` timestamp cadence (D-03) | `croniter`/cron-expression column | Rejected by D-03 — adds a parser dependency and scheduling power ASSET-03 doesn't ask for (only daily/weekly/monthly presets) |

**Installation:** None — no new packages to install for this phase.

**Version verification:** This environment's active Python (`python --version` → 3.14.0) and
installed `Flask`/`Werkzeug` (3.1.3 / 3.1.8, confirmed via `pip show` this session) reflect this
research sandbox, **not** the project's pinned venv (`PYTHON_VERSION: "3.12.0"` per `render.yaml`,
confirmed via `.planning/codebase/STACK.md`). Do not treat the sandbox's Python/Flask versions as
the deployment target's versions — `requirements.txt` pins none of Flask/Flask-SQLAlchemy/
Flask-Migrate explicitly [VERIFIED: .planning/codebase/STACK.md "Flask - requirements.txt
(unpinned version)"], so whatever `pip install -r requirements.txt` resolves at build time on
Render is authoritative, matching the project's existing no-lockfile convention.

## Package Legitimacy Audit

**Not applicable.** This phase introduces zero new external packages — the scheduling mechanism
is built entirely from the Python standard library (`threading`, `time`, `datetime`) plus
libraries already present in `requirements.txt` (`Flask-SQLAlchemy`, `Flask-Migrate`). No
`npm view`/`pip index versions`/registry legitimacy check is required.

**Packages removed due to [SLOP] verdict:** none (N/A — no packages evaluated)
**Packages flagged as suspicious [SUS]:** none (N/A — no packages evaluated)

## Architecture Patterns

### System Architecture Diagram

```text
┌────────────────────────────────────────────────────────────────────┐
│  create_app() (glassbox/__init__.py)                          │
│  ...existing extension init/blueprint registration unchanged...     │
│  NEW: _maybe_start_scheduler(app)                                    │
│    guard: app.config["SCHEDULER_ENABLED"] AND NOT app.config["TESTING"]│
│           AND (NOT app.debug OR WERKZEUG_RUN_MAIN == "true")         │
└───────────────────────────────┬───────────────────────────────────┘
                                 ▼ (starts once per process, daemon thread)
┌────────────────────────────────────────────────────────────────────┐
│  glassbox/scheduler.py :: _scheduler_loop(app)                 │
│  while True:                                                         │
│    with app.app_context():        # fresh context PER TICK           │
│        _tick(app)                 # see below                        │
│    time.sleep(POLL_INTERVAL_SECONDS)                                 │
└───────────────────────────────┬───────────────────────────────────┘
                                 ▼
┌────────────────────────────────────────────────────────────────────┐
│  _tick(app):                                                         │
│  1. SELECT Asset.id WHERE is_paused=false AND next_run_at <= now()   │
│  2. for each candidate: _try_claim(asset_id, now)                    │
│       UPDATE assets SET locked_until=now+LEASE, next_run_at=next     │
│       WHERE id=:id AND is_paused=false AND next_run_at<=:now         │
│         AND (locked_until IS NULL OR locked_until<:now)              │
│       -> rowcount==1 means this process won the claim                │
│  3. if claimed: recompute tier + org_verified + SSRF at FIRE time     │
│       (entitlements.py, checks.is_ssrf_safe_hostname — reused as-is) │
│  4. if scan_type in {media, api} and FEATURE_REQUIREMENTS[type]>tier:│
│       write Scan(status=FAILED, error_message="tier-locked") — no    │
│       thread spawned (ASSET-07 gate replicated, since run_media_scan/│
│       run_api_scan do not self-gate — see Common Pitfalls)           │
│     else:                                                             │
│       create Scan(asset_id=asset.id, status=QUEUED); commit;         │
│       _spawn_scan_thread(...) — REUSED UNCHANGED from scan_routes.py │
└────────────────────────────────────────────────────────────────────┘
                                 ▼ (existing, unmodified path)
┌────────────────────────────────────────────────────────────────────┐
│  _run_scan_in_background() (scan_routes.py, UNCHANGED)               │
│  pushes its own app.app_context(), runs run_scan/run_advanced_scan/  │
│  run_media_scan/run_api_scan, writes Report, sets Scan.status         │
│  COMPLETED/FAILED — identical for a scheduler-triggered Scan row     │
│  as for a manually-triggered one.                                    │
└────────────────────────────────────────────────────────────────────┘
```

### Recommended Project Structure

```
glassbox/
├── scheduler.py          # NEW — bare-named module (no _routes suffix), matches
│                          # convention: "Non-route domain logic lives in bare-named
│                          # modules" [VERIFIED: .planning/codebase/CONVENTIONS.md
│                          # "Supporting business-logic modules: bare feature name,
│                          # no _routes suffix"]. Holds _scheduler_loop, _tick,
│                          # _try_claim, and the scheduler-specific tier/SSRF re-checks.
├── asset_routes.py        # NEW — Blueprint "asset", registered in create_app() like
│                          # the other 5 blueprints. Asset CRUD (register, list,
│                          # schedule config, pause/resume/delete, history view).
├── models.py               # MODIFIED — new Asset model, Scan.asset_id FK column
├── entitlements.py         # POSSIBLY MODIFIED — add an org-shaped tier helper
│                          # (see Common Pitfalls: effective_tier is user-shaped)
├── scan_routes.py           # UNCHANGED (reused: _spawn_scan_thread, _run_scan_in_background)
└── __init__.py              # MODIFIED — start scheduler thread, guarded
migrations/versions/
└── <new>_add_assets_table.py  # NEW — flask db migrate output, hand-reviewed
```

### Pattern 1: Guarded scheduler startup inside `create_app()`

**What:** A three-part guard combining (a) an explicit config opt-out for tests, (b) the
`TESTING` flag, and (c) the standard Werkzeug-reloader guard, so the thread starts exactly once
per real process and never during the test suite.

**When to use:** Any code that must run exactly once per live process at app-factory time, when
`create_app()` may also be called many times per test session with disposable SQLite databases.

**Why all three checks are needed (not just the reloader guard alone):**
- The reloader guard alone is necessary for `flask run --debug` (dev server), where Werkzeug
  forks a child process that re-imports and re-runs `create_app()`. [CITED: cross-checked
  WebSearch results, MEDIUM confidence] The standard fix is:
  `if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true": start()` — this covers
  gunicorn production correctly too, since gunicorn's arbiter/worker processes never set
  `WERKZEUG_RUN_MAIN` and `app.debug` is `False` in production, so `not app.debug` alone is
  `True` and the thread starts unconditionally — no gunicorn-specific extra guard is needed.
- The reloader guard alone is **not sufficient** for this codebase's test suite: `tests/
  conftest.py`'s `app` fixture calls `create_app(_AppConfig)` fresh for **every single test**,
  each backed by its own throw-away SQLite file under pytest's `tmp_path`
  [VERIFIED: tests/conftest.py:38-61, quoted: "A fresh Flask app per test, backed by its own
  on-disk SQLite file under pytest's tmp_path" ... "yield application" ... "with
  application.app_context(): _db.session.remove(); _db.drop_all()"]. `TestConfig` sets
  `TESTING = True` [VERIFIED: tests/conftest.py:29-34, quoted: "class TestConfig(Config):
  TESTING = True"]. Since these test apps never run in Werkzeug debug mode, the reloader guard
  evaluates `not app.debug` → `True` and would start a scheduler thread on **every test**,
  leaking daemon threads that outlive their SQLite file's deletion.

```python
# glassbox/config.py — add alongside existing env-var-driven settings
SCHEDULER_ENABLED = os.environ.get("SCHEDULER_ENABLED", "true").lower() not in ("0", "false", "no")

# tests/conftest.py — TestConfig
class TestConfig(Config):
    TESTING = True
    SCHEDULER_ENABLED = False   # never start the scheduler thread in the test suite

# glassbox/__init__.py — inside create_app(), after all extension init
def _maybe_start_scheduler(app):
    if not app.config.get("SCHEDULER_ENABLED", True):
        return
    if app.config.get("TESTING", False):
        return
    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return
    from glassbox.scheduler import start_scheduler
    start_scheduler(app)

_maybe_start_scheduler(app)
```

### Pattern 2: Long-lived scheduler thread pushes app context PER TICK, not once

**What:** The tick loop pushes a *fresh* `app.app_context()` for every iteration, not one context
held open for the thread's entire (infinite) lifetime.

**When to use:** Any daemon thread that loops indefinitely against the DB, as distinct from a
thread that does one unit of work and exits (`_run_scan_in_background`'s existing pattern).

**Why this differs from the existing `_run_scan_in_background` pattern:** That function pushes
one `app.app_context()` for its entire body [VERIFIED: glassbox/scan_routes.py:91, quoted:
"with app.app_context():"] — safe there because the thread does one scan and then terminates
(the thread's death is what ultimately reclaims any thread-local session state). A scheduler
thread never terminates. Flask-SQLAlchemy's `scoped_session` is keyed by thread/greenlet identity
(not by individual app-context object), and `session.remove()` fires on `teardown_appcontext`
when a context is popped [CITED: cross-checked WebSearch results (Flask-SQLAlchemy GitHub issue
discussion of scoped-session/app-context-stack interaction), MEDIUM confidence]. Holding one
context open across hundreds of ticks means the scoped session's identity map is never cleared
between ticks, risking stale reads of rows another process/tick has since updated. Pushing/popping
a fresh context per tick gets an automatic fresh session and automatic cleanup each iteration —
the same effect `_db.session.remove()` provides explicitly in `conftest.py`'s teardown
[VERIFIED: tests/conftest.py:59-60, quoted: "with application.app_context(): _db.session.remove();
_db.drop_all()"].

```python
# glassbox/scheduler.py
def _scheduler_loop(app, poll_interval_seconds=60):
    while True:
        try:
            with app.app_context():
                _tick(app)
        except Exception:
            logging.exception("scheduler tick failed")  # never let one bad tick kill the loop
        time.sleep(poll_interval_seconds)

def start_scheduler(app):
    thread = threading.Thread(target=_scheduler_loop, args=(app,), daemon=True)
    thread.start()
```

### Pattern 3: Claim guard — conditional UPDATE, rowcount check, portable across Postgres/SQLite

**What:** A Core-style `UPDATE ... WHERE ... RETURNING`-free conditional update, executed via
`db.session.execute()`, whose `result.rowcount` tells the caller whether it won the claim.

**Why this shape:** [CITED: cross-checked WebSearch results on SQLAlchemy optimistic-locking/
conditional-UPDATE patterns, MEDIUM confidence] This relies only on standard SQL `UPDATE`
row-match semantics (works identically on Postgres and SQLite), unlike `SELECT ... FOR UPDATE
SKIP LOCKED` which is Postgres-specific and would break the SQLite dev-parity this codebase
already goes out of its way to preserve elsewhere (`_engine_options_for()` branches explicitly on
`db_uri.startswith("sqlite")` [VERIFIED: glassbox/config.py:71-72, quoted: "if
db_uri.startswith(\"sqlite\"): return {\"connect_args\": {\"check_same_thread\": False}}"]).
On Postgres, the `UPDATE`'s row match is atomic under the row-level write lock Postgres already
takes for any `UPDATE`; on SQLite, the whole-database writer lock makes it trivially safe (though
SQLite's coarser locking means this is effectively moot in the single-worker-today deployment —
the guard exists for the Postgres multi-worker future per D-02's own stated rationale).

```python
from sqlalchemy import update
from datetime import datetime, timedelta, timezone

LEASE_DURATION = timedelta(minutes=5)  # comfortably longer than one tick interval

def _try_claim(asset_id, now, next_run_at_for_asset):
    result = db.session.execute(
        update(Asset)
        .where(Asset.id == asset_id)
        .where(Asset.is_paused.is_(False))
        .where(Asset.next_run_at <= now)
        .where(db.or_(Asset.locked_until.is_(None), Asset.locked_until < now))
        .values(locked_until=now + LEASE_DURATION, next_run_at=next_run_at_for_asset)
    )
    db.session.commit()
    return result.rowcount == 1
```

Note the claim UPDATE **re-checks `next_run_at <= now`** in its own `WHERE`, not just `id` —
this closes the gap between the earlier `SELECT`-for-candidates step and this claim: if another
process already claimed and rescheduled this Asset in between, this UPDATE's `WHERE` no longer
matches and `rowcount` is `0`, so a stale candidate never double-fires even without holding a
lock across both steps.

The claim UPDATE also advances `next_run_at` **in the same statement** as taking the lease. This
is deliberate: `next_run_at` (not `locked_until`) is what determines "is this Asset still due,"
and rescheduling must not wait for the *scan* to finish (scan execution is async and can outlive
many tick intervals) — only for the *claim* to succeed. `locked_until` exists purely to prevent
two ticks from concurrently processing the same due-right-now Asset in the same instant; letting
it simply expire after `LEASE_DURATION` (rather than explicitly clearing it) is sufficient and
matches D-04's "never require a new state-cleanup mechanism" spirit — if the process crashes
mid-tick after claiming, the lease naturally expires and the next tick that finds the Asset due
again (per the newly-advanced `next_run_at`, at its *next* cadence boundary) can claim it cleanly.

### Pattern 4: Alembic migration for the new `Asset` table + `Scan.asset_id` FK

**What:** Standard `flask db migrate` autogenerate flow, following the project's already-live
Alembic convention exactly as the one existing baseline revision demonstrates.

[VERIFIED: migrations/versions/4621b1837a3f_baseline_schema.py:19-45 — every table in this
project's schema was created via `op.create_table(...)` with `sa.ForeignKeyConstraint(['org_id'],
['organizations.id'])`-style FK declarations generated by Alembic autogenerate, e.g. the
`crypto_invoices` table's own `org_id` FK to `organizations.id`, quoted: "op.create_table(
'crypto_invoices', ... sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),"]

```python
# glassbox/models.py — add alongside existing models
class Asset(db.Model):
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), nullable=False)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    target_url = db.Column(db.String(2048), nullable=False)   # matches Scan.target_url convention
    hostname = db.Column(db.String(255), nullable=False)
    cadence = db.Column(db.String(16), nullable=False)         # "daily" | "weekly" | "monthly"
    schedule_scan_type = db.Column(db.String(16), nullable=False)  # matches Scan.scan_type values
    next_run_at = db.Column(db.DateTime(timezone=True), nullable=True)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)
    is_paused = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    organization = db.relationship("Organization")

# Scan gains: asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=True)
```

```bash
flask db migrate -m "add assets table and scans.asset_id"
# THEN hand-review the generated migrations/versions/*.py file before upgrading —
# CLAUDE.md's own documented gotcha: "autogenerate can misclassify renamed columns
# as drop+add" [VERIFIED: .planning/codebase/CONVENTIONS.md "After changing a model,
# run flask db migrate -m \"description\" then review the generated file before flask
# db upgrade - autogenerate can misclassify renamed columns as drop+add."]
flask db upgrade
```

### Anti-Patterns to Avoid

- **Starting the scheduler thread via a Flask request hook (`before_first_request`):** Removed
  entirely in Flask 2.3+; this project runs Flask 3.1.3 in this sandbox
  [VERIFIED: `pip show flask` output this session, "Version: 3.1.3"] — the hook does not exist.
  Start the thread directly inside `create_app()`'s body, matching how every other piece of
  factory-time setup (extension `.init_app()` calls) already works.
- **Constructing a fake `User` object to call `entitlements.effective_tier()` from the scheduler:**
  `effective_tier(user)` expects `user.is_authenticated`/`user.organization`
  [VERIFIED: glassbox/entitlements.py:57-78, quoted: "def effective_tier(user): ... if user
  is None or not getattr(user, \"is_authenticated\", True): return Tier.FREE \n org =
  getattr(user, \"organization\", None)"]. The scheduler has an `Organization`, not a `User`.
  Duck-typing a fake user is fragile (couples the scheduler to `User`'s exact attribute shape).
  Prefer adding a small, explicit org-shaped helper (e.g. `effective_tier_for_org(org)` reusing
  the same `plan_to_tier` map) that both `effective_tier` and the scheduler call.
- **Treating a scheduled scan's tier gate as "handled" because `run_scan`/`run_advanced_scan`
  internally call `entitlements.allowed_checks`:** True for those two orchestrators, **false**
  for `run_media_scan`/`run_api_scan` — see Common Pitfalls below. This is the single most
  important anti-pattern to flag for ASSET-07.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Cadence math (daily/weekly/monthly → next timestamp) | A generic interval-parsing utility or a cron-expression evaluator | Plain `timedelta` arithmetic keyed off a small fixed dict (`{"daily": timedelta(days=1), "weekly": timedelta(weeks=1), "monthly": timedelta(days=30)}` — or `dateutil.relativedelta` if calendar-month accuracy matters) | D-03 explicitly locks out cron-expression power; a fixed preset dict is the entire feature surface ASSET-03 asks for |
| SSRF hostname safety check | A new hostname-validation function for Assets | `checks.is_ssrf_safe_hostname()`, reused exactly as `_unsafe_target_error()` already calls it in `scan_routes.py` | ASSET-02 explicitly requires the *same* gate, not an equivalent one; the existing function is already tested (`tests/test_ssrf_guard.py`) |
| Tier/entitlement gating | A parallel gating system for scheduled scans | `entitlements.allowed_checks()` / `FEATURE_REQUIREMENTS` / `domain_is_org_verified()`, reused (with the org-shaped-helper caveat above) | ASSET-07 explicitly requires the *same* gating system; a parallel system would inevitably drift out of sync with `FEATURE_REQUIREMENTS` the way `entitlements.py`'s own warning-on-missing-key logic already anticipates for check names |
| Async scan dispatch | A new thread-spawning mechanism for scheduled scans | `_spawn_scan_thread`/`_run_scan_in_background`, reused unchanged | D-01 explicitly mandates reuse; duplicating it would double the surface area that needs the SQLite `check_same_thread`/Postgres `pool_pre_ping` config already tuned for this exact pattern |
| Multi-worker claim safety | A distributed lock library (Redis-based `redlock`, etc.) | Plain conditional `UPDATE ... WHERE` (Pattern 3 above) | D-02 explicitly specifies this exact mechanism; introducing a new infra dependency (Redis) for a single boolean claim is disproportionate, and Redis isn't otherwise in this project's stack (only flagged as a *future* need for rate-limiting in `.planning/codebase/CONCERNS.md`, not yet added) |

**Key insight:** Every "don't hand-roll" item in this phase resolves to "reuse the existing
codebase primitive exactly, don't build a parallel one" — this phase's entire safety story
depends on scheduled scans going through the *identical* gates manual scans do, not
functionally-equivalent new ones.

## Common Pitfalls

### Pitfall 1: `run_media_scan`/`run_api_scan` are not self-gating — the scheduler must replicate the route-level tier pre-check

**What goes wrong:** A Free-tier Asset scheduled with `schedule_scan_type="media"` (Paid-tier
per `FEATURE_REQUIREMENTS`) fires successfully and silently runs the full media scan every time,
because nothing inside `run_media_scan()` itself checks tier.

**Why it happens:** `run_scan()`/`run_advanced_scan()` take `tier`/`org_verified_for_domain` and
gate internally via `entitlements.allowed_checks` — but `run_media_scan()`/`run_api_scan()` do
not [VERIFIED: .planning/codebase/ARCHITECTURE.md "Pattern: run_scan/run_advanced_scan take
tier/org_verified_for_domain and gate internally via entitlements.allowed_checks;
run_media_scan/run_api_scan are NOT gated internally — gating is enforced one level up in the
route before the orchestrator is even called (an intentional asymmetry documented in
scan_engine.py's module docstring)."]. In the existing web-UI flow this is safe because
`new_scan_media`/`new_scan_api` routes check `_tier_flags(tier)["can_run_media"]`/
`["can_run_api"]` (built from `FEATURE_REQUIREMENTS["media"]`/`["api"]`
[VERIFIED: glassbox/entitlements.py:48,53, quoted: "\"media\": Tier.PAID," and
"\"api\": Tier.PAID,"]) before ever calling `_spawn_scan_thread`. A scheduler tick handler has no
route in the loop — it calls `_spawn_scan_thread` directly.

**How to avoid:** Before spawning a scheduled scan whose `schedule_scan_type` is `"media"` or
`"api"`, the tick handler must explicitly check `FEATURE_REQUIREMENTS[scan_type] <= tier` itself
(recomputed at fire time) and, if it fails, write a `Scan(status=FAILED, error_message=...)` row
without spawning a thread at all — never call `_spawn_scan_thread` for a tier-locked media/api
schedule.

**Warning signs:** Any implementation that treats "pass `tier` into the orchestrator call" as
sufficient for all four scan types, without a scan-type-specific branch for media/api.

### Pitfall 2: `conftest.py`'s fresh-app-per-test pattern will leak scheduler threads unless startup is config-gated

**What goes wrong:** Every test in the suite (~150+ tests across `tests/test_*.py`) calls
`create_app()` fresh. Without an explicit opt-out, each test spawns its own infinite-loop daemon
thread against a SQLite file that `tmp_path` deletes at test teardown — threads accumulate for the
life of the pytest process and may throw on a dropped/deleted DB mid-tick.

**Why it happens:** `app` fixture creates a new app + SQLite file per test and tears both down
after [VERIFIED: tests/conftest.py:37-61, quoted: "@pytest.fixture() \ndef app(tmp_path): \n
\"\"\"A fresh Flask app per test..." ... "with application.app_context(): _db.session.remove();
_db.drop_all()"]. `TestConfig` sets `TESTING = True` [VERIFIED: tests/conftest.py:29-31].

**How to avoid:** Gate scheduler startup on an explicit `SCHEDULER_ENABLED` config flag (default
`True`), set `False` on `TestConfig`, in addition to the `TESTING` check and the Werkzeug-reloader
guard (belt-and-suspenders — either check alone would work here since `TESTING=True` already
implies "don't start," but an explicit flag also lets ops disable the scheduler via env var for
maintenance without a code change, matching this project's existing everything-via-env-var
convention in `config.py`).

**Warning signs:** Test suite run time growing unexpectedly slow, or `sqlite3.OperationalError`/
`ResourceWarning: unclosed database` noise appearing in test output after this phase lands.

### Pitfall 3: `effective_tier()` is user-shaped; the scheduler has an org, not a user

**What goes wrong:** Code that tries to fake a `User`-like object (`SimpleNamespace(organization=asset.organization, is_authenticated=True)`) to reuse `effective_tier()` unchanged works today, but couples the scheduler to `effective_tier`'s exact undocumented attribute contract and will silently break if that contract's shape changes later.

**Why it happens:** `effective_tier(user)`'s signature and body are written entirely in terms of
a Flask-Login-style user object [VERIFIED: glassbox/entitlements.py:57-78, quoted:
"def effective_tier(user): ... Maps an (optionally-authenticated) user to a Tier."]. Nothing in
the existing codebase computes a tier from an `Organization` directly.

**How to avoid:** Extract the `plan_to_tier` mapping logic into a small shared helper both
`effective_tier(user)` and a new `effective_tier_for_org(org)` call, or inline the three-line
`org.plan` → `Tier` lookup directly in `scheduler.py` (smallest change, but duplicates the
mapping dict — acceptable given it's 3 lines and `Tier`/`Plan` are both frozen enums unlikely to
change independently). This is a discretion call for the planner; either is safe, but a fake-user
object is not recommended.

**Warning signs:** Any `SimpleNamespace`/mock object being passed into `effective_tier()` from
non-test code.

### Pitfall 4: Durable authorization checkbox vs. one-shot manual-scan checkbox

**What goes wrong:** Manual scan submission's `authorized`/`authorized_adv`/`authorized_media`/
`authorized_api` checkboxes are checked once, immediately before that one scan runs, and are
never persisted as a DB column [VERIFIED: glassbox/scan_routes.py:274, 297-300 — the
`authorized` form field is read and validated but the `Scan` row created immediately after
(`s = Scan(user_id=..., org_id=..., target_url=..., scan_type="base",
status=ScanStatus.QUEUED)`) has no `authorized` column]. An Asset's authorization checkbox, by
contrast, is checked once at *registration* time but is relied upon to justify every future
automated fire, potentially for months — a materially different trust window than a manual scan's
"check the box, scan starts within seconds" flow.

**Why it happens:** ASSET-02 says "enforces the same authorization-checkbox... gating as manual
scan submission," which is satisfied at the literal registration-form level, but doesn't by
itself address the durability question a recurring schedule introduces.

**How to avoid:** Not a locked requirement, but a strong recommendation: persist an
`authorized_at`/`authorized_by_user_id` pair on the `Asset` row at registration time (audit trail
of who authorized recurring scanning of this target and when), even though the analogous `Scan`
table doesn't need this for one-off scans. Cheap to add now (same migration), and provides an
answer if a future compliance/audit requirement (Phase 3, COMP-*) ever asks "who authorized this
recurring scan."

**Warning signs:** None currently — this is a forward-looking recommendation, not a bug the
codebase already exhibits.

### Pitfall 5: SSRF safety can change between Asset registration and a fire many cadence-cycles later

**What goes wrong:** `is_ssrf_safe_hostname()` is checked once at Asset registration and never
again; months later the target's DNS changes (domain expires, gets repointed) to resolve to a
private/internal address, and the scheduler keeps firing scans against it without re-checking.

**Why it happens:** The existing manual-scan flow only ever needs a submission-time check because
the scan runs within seconds of that check
[VERIFIED: glassbox/checks.py:214-230 docstring, quoted: "This is a submission-time check
only - it does not pin the resolved IP for the actual scan request that happens later"] — the doc
comment's own reasoning assumes a short window between check and use, which no longer holds for a
schedule that can fire for months after registration.

**How to avoid:** Re-run `is_ssrf_safe_hostname()` (via the same `_unsafe_target_error`-style
call) at **every scheduled fire**, immediately before spawning the scan — not just at Asset
registration. If it now fails, write a `Scan(status=FAILED, error_message="target no longer
resolves to a safe address")` row (mirrors D-04's "keep ticking, don't change schedule state" —
only that specific fire fails) rather than silently scanning or silently skipping without a
record.

**Warning signs:** A scheduled-scan implementation that only calls `is_ssrf_safe_hostname()` in
the Asset-registration route and never again.

### Pitfall 6: `ScanStatus` has no "skipped" value — don't invent one for tier-locked/SSRF-failed scheduled fires

**What goes wrong:** Adding a new `ScanStatus.SKIPPED` enum value (or similar) for a tier-locked
or SSRF-failed scheduled fire, which requires an enum migration and diverges from D-04's explicit
"mirror existing failure semantics" instruction.

**Why it happens:** It can feel more precise to distinguish "the scan failed while running" from
"the scan never started because of a gate" — but D-04 explicitly says failure handling should
mirror existing semantics, and `ScanStatus` currently has exactly four values
[VERIFIED: glassbox/models.py:43-47, quoted: "class ScanStatus(enum.Enum): \n QUEUED =
\"queued\" \n RUNNING = \"running\" \n COMPLETED = \"completed\" \n FAILED = \"failed\""].

**How to avoid:** Use the existing `FAILED` status with a descriptive `error_message` ("scan type
requires Paid tier, org is currently Free" / "target no longer resolves to a safe address") for
both tier-gate and SSRF-gate rejections at fire time — no new enum value, no migration for the
enum, consistent with D-04.

**Warning signs:** A migration that alters the `scanstatus` Postgres enum type.

## Code Examples

### Full tick handler skeleton (composes Patterns 2-4 above)

```python
# glassbox/scheduler.py
"""
In-process daemon-thread scheduler for recurring Asset scans (Phase 1,
ASSET-03/04/08). Ticks on a fixed interval, claims due Assets via a
DB-level conditional UPDATE (D-02), and dispatches through the existing
scan_routes._spawn_scan_thread path unchanged (D-01). See
.planning/phases/01-asset-inventory-continuous-scanning/01-RESEARCH.md
for the design rationale.
"""
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, update

from glassbox.checks import is_ssrf_safe_hostname
from glassbox.entitlements import FEATURE_REQUIREMENTS, domain_is_org_verified
from glassbox.extensions import db
from glassbox.models import Asset, Scan, ScanStatus
from glassbox.scan_routes import _spawn_scan_thread

POLL_INTERVAL_SECONDS = 60
LEASE_DURATION = timedelta(minutes=5)
CADENCE_INTERVALS = {"daily": timedelta(days=1), "weekly": timedelta(weeks=1), "monthly": timedelta(days=30)}


def _tier_for_org(org):
    from glassbox.entitlements import Tier
    from glassbox.models import Plan
    plan_to_tier = {Plan.FREE: Tier.FREE, Plan.PAID: Tier.PAID, Plan.ORG_VERIFIED: Tier.ORG_VERIFIED}
    return plan_to_tier.get(org.plan, Tier.FREE) if org else Tier.FREE


def _try_claim(asset_id, now, next_run_at):
    result = db.session.execute(
        update(Asset)
        .where(Asset.id == asset_id, Asset.is_paused.is_(False), Asset.next_run_at <= now)
        .where(or_(Asset.locked_until.is_(None), Asset.locked_until < now))
        .values(locked_until=now + LEASE_DURATION, next_run_at=next_run_at)
    )
    db.session.commit()
    return result.rowcount == 1


def _tick(app):
    now = datetime.now(timezone.utc)
    due_ids = [a.id for a in Asset.query.filter(Asset.is_paused.is_(False), Asset.next_run_at <= now).all()]
    for asset_id in due_ids:
        asset = Asset.query.get(asset_id)
        if asset is None:
            continue
        next_run_at = now + CADENCE_INTERVALS[asset.cadence]
        if not _try_claim(asset_id, now, next_run_at):
            continue  # lost the race, or already handled
        _fire(asset)


def _fire(asset):
    tier = _tier_for_org(asset.organization)
    org_verified = domain_is_org_verified(asset.organization, asset.target_url)

    if not is_ssrf_safe_hostname(asset.hostname):
        db.session.add(Scan(asset_id=asset.id, user_id=asset.created_by_user_id, org_id=asset.org_id,
                             target_url=asset.target_url, scan_type=asset.schedule_scan_type,
                             status=ScanStatus.FAILED,
                             error_message="Target no longer resolves to a safe address."))
        db.session.commit()
        return

    if asset.schedule_scan_type in ("media", "api") and FEATURE_REQUIREMENTS[asset.schedule_scan_type] > tier:
        db.session.add(Scan(asset_id=asset.id, user_id=asset.created_by_user_id, org_id=asset.org_id,
                             target_url=asset.target_url, scan_type=asset.schedule_scan_type,
                             status=ScanStatus.FAILED,
                             error_message=f"Schedule requires a higher tier than the org's current plan."))
        db.session.commit()
        return

    s = Scan(asset_id=asset.id, user_id=asset.created_by_user_id, org_id=asset.org_id,
             target_url=asset.target_url, scan_type=asset.schedule_scan_type, status=ScanStatus.QUEUED)
    db.session.add(s)
    db.session.commit()
    _spawn_scan_thread(s.id, asset.schedule_scan_type, base_url=asset.target_url,
                        manual_test_url=None, tier=tier, org_verified=org_verified)


def _scheduler_loop(app):
    while True:
        try:
            with app.app_context():
                _tick(app)
        except Exception:
            logging.exception("scheduler tick failed")
        time.sleep(POLL_INTERVAL_SECONDS)


def start_scheduler(app):
    threading.Thread(target=_scheduler_loop, args=(app,), daemon=True).start()
```

*(This is a skeleton for planner reference, not final production code — e.g. `_spawn_scan_thread`
expects a real `current_app`-derived app object in its own call signature
[VERIFIED: glassbox/scan_routes.py:180-188, quoted: "def _spawn_scan_thread(scan_id,
scan_type, **kwargs): \n app_obj = current_app._get_current_object()"] — calling it from inside
an already-pushed `app.app_context()` means `current_app` resolves correctly without changes, but
the planner should verify this call composes cleanly when writing the actual task.)*

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| One-shot manual scan submission only (`Scan` row per manual click, no persistent target entity) | Persistent `Asset` entity + recurring schedule, `Scan.asset_id` links runs to history | This phase (Phase 1, 2026-08-10) | Enables ASSET-05 trend view; changes `Scan.asset_id` to nullable so existing manual-scan flow is preserved unchanged |

**Deprecated/outdated:** Nothing in the existing stack is deprecated by this phase — Phase 1 is
additive (new table, new nullable FK, new module, new blueprint), not a replacement of any
existing mechanism.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":` is the correct, complete guard for Werkzeug-reloader double-start, and requires no separate gunicorn-specific branch | Architecture Patterns → Pattern 1 | If wrong, the scheduler thread could start twice under `flask run --debug` (harmless duplication in dev, not production-visible) or fail to start at all in some gunicorn config variant not covered by `not app.debug` — low risk given `app.debug` is a Flask-standard attribute and gunicorn never sets it True by default |
| A2 | Flask-SQLAlchemy's `scoped_session` cleanup/staleness behavior across app-context pushes (cited from cross-checked web search, not read directly from Flask-SQLAlchemy's source in this session) generalizes to this project's Flask-SQLAlchemy version | Architecture Patterns → Pattern 2 | If Flask-SQLAlchemy's exact scoping implementation differs from the general web-search-sourced description, the per-tick-context recommendation is still safe (it's a superset of correct behavior — pushing/popping per tick can only help, not hurt), so this assumption is low-risk even if imprecise |
| A3 | `Scan.asset_id` should be nullable (to preserve existing manual-scan flow untouched) rather than requiring every `Scan` to belong to an `Asset` | Architecture Patterns → Pattern 4 | If the planner instead decides every scan must have an Asset (a bigger, in-scope-per-Claude's-Discretion decision explicitly left open by CONTEXT.md), this schema recommendation would need revision — flagged in CONTEXT.md's own Claude's Discretion section as an open question, not fully resolved here |
| A4 | Cadence stored as free-text `String(16)` ("daily"/"weekly"/"monthly") rather than an `Enum`, mirroring `Scan.scan_type`'s existing convention rather than the `Enum`-typed convention used for `ScanStatus`/`Role`/etc. | Code Examples, Architecture Patterns → Pattern 4 | Low risk — either is a valid, reversible schema choice; `Scan.scan_type` is the more directly analogous precedent (a small fixed set of scan-type strings) than the `Enum`-typed status/role columns, but this is a naming/typing convention call, not a functional risk |
| A5 | `LEASE_DURATION = 5 minutes` and `POLL_INTERVAL_SECONDS = 60` are reasonable defaults | Code Examples | Untuned; if the planner picks a much shorter lease than the tick interval, a slow claim-to-dispatch step could theoretically let the lease expire before dispatch completes, re-opening a (currently theoretical, single-worker) race — recommend lease >> tick interval, as shown |

**If this table is empty:** N/A — assumptions listed above.

## Open Questions

1. **Should Asset registration require SSRF/hostname validation to pass before the row is even
   created, or should an already-registered Asset be allowed to persist through a later
   SSRF-check failure (with the schedule simply producing FAILED scans until the target becomes
   safe again)?**
   - What we know: ASSET-02 requires the *registration* gate to match manual-scan submission
     (reject at registration time if currently unsafe) — this part is locked.
   - What's unclear: whether a later SSRF failure (Pitfall 5) should auto-pause the schedule or
     just keep producing FAILED scans indefinitely per D-04's "keep ticking" instruction.
   - Recommendation: Treat it exactly like any other scheduled-scan failure per D-04 (keep
     ticking, record FAILED with a clear `error_message`) — do not special-case SSRF failures
     with new pause/notify behavior, since D-04 explicitly rules out new pause/notify mechanisms
     for v1.

2. **Where does the `asset_routes.py` blueprint boundary sit relative to `scan_routes.py`?**
   - What we know: `scan_routes.py` already owns `/dashboard`, `/scan/*` — Asset registration/
     schedule config/history is a large enough surface (ASSET-01, 03, 05, 06) to warrant its own
     blueprint per the "New Feature (new page/blueprint)" convention
     [VERIFIED: .planning/codebase/STRUCTURE.md "Create glassbox/<feature>_routes.py
     following the Blueprint(\"<name>\", __name__) pattern"].
   - What's unclear: whether `/dashboard` should be extended to surface Assets, or whether a new
     `/assets` landing page is more consistent with the existing `/scan/new` chooser-page pattern.
   - Recommendation: New `asset_routes.py` blueprint with its own `/assets` URL namespace,
     following the existing per-concern blueprint convention; leave exact route names to the
     planner (within Claude's Discretion per CONTEXT.md).

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.12 (project-pinned) | Entire backend, `render.yaml` build | Not verified in this research sandbox (sandbox reports Python 3.14.0) — production pin confirmed via `.planning/codebase/STACK.md` only, not re-probed this session | 3.12.0 (per `render.yaml`, `.planning/codebase/STACK.md`) | N/A — existing constraint, unaffected by this phase |
| PostgreSQL (Neon) | D-02 claim guard's primary target; production DB | Not probed in this sandbox (no live DB connection attempted) — existing infra, confirmed via `.planning/codebase/STACK.md` | Managed by Render/Neon | SQLite (dev) — claim guard is portable to both, see Pattern 3 |
| gunicorn | Production WSGI server, `--workers 1 --threads 4` | Not found in this sandbox's PATH (`gunicorn: command not found`) — expected, this is a generic research shell, not the project's activated venv/deployment | Per `requirements.txt`/`render.yaml`, unpinned | N/A — existing infra, this phase adds no new gunicorn config requirement |

**Missing dependencies with no fallback:** None — this phase introduces no new external-service
dependency; all "missing" items above are artifacts of this research sandbox not being the
project's actual runtime/deployment environment, not gaps this phase needs to fill.

**Missing dependencies with fallback:** None applicable beyond the existing, already-documented
Postgres/SQLite dev-vs-prod split.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest [VERIFIED: pytest.ini:1-2, quoted: "[pytest] \n testpaths = tests"] |
| Config file | `pytest.ini` (repo root) |
| Quick run command | `pytest tests/test_<new_file>.py -x` |
| Full suite command | `pytest` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| ASSET-01 | Asset registration creates a row, appears in inventory list | integration (route) | `pytest tests/test_asset_routes.py -k registration -x` | ❌ Wave 0 |
| ASSET-02 | Registration rejects missing checkbox / unsafe hostname | integration (route) | `pytest tests/test_asset_routes.py -k authorization_and_ssrf -x` | ❌ Wave 0 |
| ASSET-03 | Schedule config (cadence + scan type) persists correctly | unit/integration | `pytest tests/test_asset_routes.py -k schedule_config -x` | ❌ Wave 0 |
| ASSET-04 | A due Asset fires a scan producing `Scan`/`Report` linked via `asset_id` | unit (scheduler) | `pytest tests/test_scheduler.py -k tick_fires_due_asset -x` | ❌ Wave 0 |
| ASSET-05 | History/trend view returns multiple scans for one Asset, ordered | integration (route) | `pytest tests/test_asset_routes.py -k history -x` | ❌ Wave 0 |
| ASSET-06 | Pause/resume/delete mutate `is_paused`/row correctly | integration (route) | `pytest tests/test_asset_routes.py -k pause_resume_delete -x` | ❌ Wave 0 |
| ASSET-07 | Free-tier Asset scheduled for media/api never runs; downgrade mid-cycle is respected at next fire | unit (scheduler) — **highest-priority new test given Pitfall 1** | `pytest tests/test_scheduler.py -k tier_gating -x` | ❌ Wave 0 |
| ASSET-08 | Two concurrent claim attempts on the same due Asset: only one succeeds | unit (claim guard) | `pytest tests/test_scheduler.py -k claim_guard_race -x` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `pytest tests/test_scheduler.py tests/test_asset_routes.py -x`
- **Per wave merge:** `pytest` (full suite — this phase touches shared modules like
  `entitlements.py` and `models.py`, so regressions could surface in unrelated existing tests,
  e.g. `tests/test_entitlements.py`, `tests/test_scan_ownership.py`)
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `tests/test_scheduler.py` — new file, covers ASSET-04/07/08 (tick loop, claim guard,
      tier-gate replication for media/api)
- [ ] `tests/test_asset_routes.py` — new file, covers ASSET-01/02/03/05/06
- [ ] `tests/conftest.py` — extend with a `make_asset(...)` factory function, following the
      existing `make_scan`/`make_org`/`make_user` pattern
      [VERIFIED: tests/conftest.py:85-118, quoted factory signatures: "def make_org(plan=Plan.FREE,
      name=\"Test Org\"):" / "def make_scan(user, org=None, target_url=\"https://example.com\",
      scan_type=\"base\", status=ScanStatus.QUEUED):"], and set `SCHEDULER_ENABLED = False` on
      `TestConfig` (see Pitfall 2 — this is a required addition, not optional)
- [ ] Framework install: none — pytest is already installed and configured

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V4 Access Control | yes | Asset ownership scoped to `org_id`; reuse the existing 404-not-403 ownership-check convention (`_check_ownership` pattern in `scan_routes.py`) for cross-org Asset access, so an Asset ID doesn't leak existence to a non-member |
| V5 Input Validation | yes | `is_ssrf_safe_hostname()` reused at both registration time and every scheduled fire (Pitfall 5); cadence/scan-type values validated against a fixed allow-list, not free text |
| V1 Architecture / Business Logic | yes | Claim-guard race-condition prevention (D-02); tier-gate replication for the scheduler's non-self-gating orchestrators (Pitfall 1) is fundamentally a business-logic authorization-boundary concern, not a "nice to have" |
| V2 Authentication | no (unchanged) | Existing Flask-Login session auth applies unchanged to the new `asset_routes.py` blueprint via `@login_required`, same as every other blueprint |
| V3 Session Management | no (unchanged) | No new session state introduced by this phase |
| V6 Cryptography | no | Not applicable — this phase introduces no new cryptographic operations |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| SSRF via a long-lived Asset whose target later resolves to a private address | Tampering / Elevation of Privilege | Re-check `is_ssrf_safe_hostname()` at every scheduled fire, not just registration (Pitfall 5) |
| Privilege escalation via tier-downgrade bypass — a Free-tier org's schedule keeps running Paid/Org-verified checks | Elevation of Privilege | Recompute `effective_tier`/`FEATURE_REQUIREMENTS` gate at fire time, not schedule-creation time (Pitfall 1, ASSET-07's core requirement) |
| Double-fire / duplicate scan execution under concurrent workers | Tampering (data integrity: duplicate `Scan` rows, wasted work, potential rate-limit/target abuse from double requests) | D-02's conditional-UPDATE claim guard (Pattern 3) |
| Cross-org Asset access (viewing/pausing/deleting another org's Asset by guessing an ID) | Information Disclosure / Elevation of Privilege | Mirror `_check_ownership`'s 404-not-403 convention for every Asset route |

## Sources

### Primary (HIGH confidence)
- Direct `Read` of this session's project source: `glassbox/scan_routes.py`,
  `glassbox/models.py`, `glassbox/__init__.py`, `glassbox/entitlements.py`,
  `glassbox/config.py`, `glassbox/checks.py` (SSRF function), `tests/conftest.py`,
  `tests/test_scan_events.py`, `migrations/versions/4621b1837a3f_baseline_schema.py`,
  `pytest.ini`, `requirements.txt` — all claims tagged `[VERIFIED: path:lines]` above were
  confirmed by reading the actual file this session, not inferred.
- `.planning/codebase/ARCHITECTURE.md`, `STACK.md`, `STRUCTURE.md`, `CONVENTIONS.md`,
  `CONCERNS.md` — pre-existing, dated 2026-08-10 codebase-mapping documents.
- `.planning/phases/01-asset-inventory-continuous-scanning/01-CONTEXT.md` — locked decisions.
- `.planning/REQUIREMENTS.md`, `.planning/PROJECT.md`, `.planning/STATE.md`.

### Secondary (MEDIUM confidence)
- Cross-checked WebSearch results (multiple independent sources agreeing) on: the
  `WERKZEUG_RUN_MAIN`/`app.debug` reloader guard idiom; SQLAlchemy conditional-`UPDATE`/rowcount
  claim patterns; Flask-Migrate autogenerate + hand-review convention; Flask-SQLAlchemy
  scoped-session/app-context interaction and staleness risk in long-lived threads. Classified
  MEDIUM via `gsd-tools query classify-confidence --provider websearch --verified` (cross-checked
  web search, no official-docs citation obtained this session).

### Tertiary (LOW confidence)
- None retained — all WebSearch findings used in this document were cross-checked across
  multiple results before being cited at MEDIUM confidence; single-source, unverified findings
  were not included.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — zero new packages, entire mechanism composed from stdlib + already-
  installed libraries confirmed via project docs and `requirements.txt`.
- Architecture: MEDIUM-HIGH — the shape is fully locked by CONTEXT.md's D-01..D-04; the specific
  pitfalls (media/api self-gating asymmetry, fresh-app-per-test, user-shaped `effective_tier`)
  are grounded in direct source reads this session, not speculation.
- Pitfalls: HIGH for the codebase-specific ones (all `[VERIFIED]` against actual source read this
  session); MEDIUM for the general Flask/SQLAlchemy mechanics (cross-checked web search, not an
  official-docs citation).

**Research date:** 2026-08-10
**Valid until:** 2026-08-24 (14 days — this research is tightly coupled to the exact current state
of `scan_routes.py`/`entitlements.py`/`models.py`; if those files change materially before
planning starts, re-verify the `[VERIFIED]`-tagged line citations above before relying on them)
