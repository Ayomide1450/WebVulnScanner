# Phase 1: Asset Inventory & Continuous Scanning - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-10
**Phase:** 1-Asset Inventory & Continuous Scanning
**Areas discussed:** Scheduling mechanism

---

## Scheduling mechanism

### Trigger

| Option | Description | Selected |
|--------|-------------|----------|
| In-process background thread | Reuses the same daemon-thread pattern already used for scan execution (`_run_scan_in_background`) — no new deployment component, ticks inside the existing web process. | ✓ |
| APScheduler library | Purpose-built BackgroundScheduler for interval/cron-style jobs, still in-process, but adds a new dependency for what's currently a simple need. | |
| Separate scheduled process | e.g. a Render Cron Job hitting an internal endpoint or running a CLI script — decouples the scheduler from web dynos but is a new deployment component to configure on Render. | |

**User's choice:** In-process background thread (recommended option)
**Notes:** None beyond selecting the recommendation.

### Multi-worker

| Option | Description | Selected |
|--------|-------------|----------|
| Add the claim guard now | A `locked_until`/`claimed_at` column + conditional UPDATE (Postgres-safe) — touches the schema/logic once now rather than risking a silent double-fire bug the day ops bumps `--workers`. | ✓ |
| Defer to Phase 4 | Keep Phase 1 simpler; single worker today means no real risk yet, but requires remembering to retrofit this before scaling workers. | |

**User's choice:** Add the claim guard now (recommended option)
**Notes:** Deployment is single-worker today (Render, `--workers 1`) but Phase 4 anticipates
scaling to multiple gunicorn workers; production DB is Postgres (Neon), making a DB-level claim
guard implementable without new infrastructure.

### Cadence model

| Option | Description | Selected |
|--------|-------------|----------|
| next_run_at timestamp + fixed tick interval | e.g. tick every 5 min, check `Asset.next_run_at <= now()`, run then advance `next_run_at` by the cadence. Simple, matches the daily/weekly/monthly preset requirement without cron parsing. | ✓ |
| Cron-expression-based | Use `croniter` or APScheduler's cron trigger for more flexible custom scheduling — more power than the preset-cadence requirement (ASSET-03) actually calls for. | |

**User's choice:** next_run_at timestamp + fixed tick interval (recommended option)
**Notes:** None beyond selecting the recommendation.

### Failure handling

| Option | Description | Selected |
|--------|-------------|----------|
| Keep ticking at normal cadence | Matches existing manual-scan failure semantics (`Scan.status=FAILED`, error stored, never stuck RUNNING) — simplest, no new notification/state system needed for v1. | ✓ |
| Pause after N consecutive failures | Prevents a permanently-broken target from silently piling up failed scans forever — adds new state/logic beyond current requirements. | |

**User's choice:** Keep ticking at normal cadence (recommended option)
**Notes:** None beyond selecting the recommendation.

---

## Claude's Discretion

Three other candidate gray areas were presented but not selected for deep-dive discussion; the
user chose "I'm ready for context" after Scheduling mechanism. Left to researcher/planner
discretion, grounded in existing codebase conventions:

- Schedule configuration & scan-type selection UX (cadence presets, which scan types can be
  scheduled, how tier gating is surfaced in the UI).
- Asset ↔ Scan/Report relationship (whether registering an Asset auto-triggers a first scan,
  whether manual one-off scans remain available without an Asset, exact history/trend view shape).
- Pause/resume/delete + tier-downgrade semantics (soft vs. hard delete; behavior when an org's
  tier downgrades mid-schedule).

## Deferred Ideas

None — discussion stayed within phase scope; no scope-creep suggestions arose during this
session.
