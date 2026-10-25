# Phase 1: Asset Inventory & Continuous Scanning - Context

**Gathered:** 2026-08-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Targets become persistent Assets that can be scanned automatically on a recurring schedule,
instead of being resubmitted by hand for every scan. This phase delivers: Asset registration
(distinct from a one-off manual scan), schedule configuration (cadence + scan type), the
scheduling mechanism that fires scans automatically, scan history/trend across an Asset's
scheduled runs, and pause/resume/delete controls — all routed through the exact same
authorization/SSRF/tier gates manual scan submission already enforces. Requirements: ASSET-01
through ASSET-08 (see REQUIREMENTS.md).

</domain>

<decisions>
## Implementation Decisions

Discussion focused on the scheduling mechanism — the area with the most implementation leverage
and risk. The other candidate areas (schedule config/scan-type UX, Asset↔Scan relationship,
pause/resume/delete + tier-downgrade semantics) were surfaced but not selected for deep-dive;
user confirmed readiness to proceed with research + planner discretion on those, grounded in
existing codebase conventions (see Claude's Discretion below).

### Scheduling Trigger Mechanism

- **D-01:** Use an in-process daemon background thread to periodically check for due schedules,
  reusing the same pattern already established for scan execution
  (`_spawn_scan_thread`/`_run_scan_in_background` in `glassbox/scan_routes.py`) rather than
  introducing APScheduler or a separate scheduled process/Render Cron Job. — **Reversibility:**
  costly — **rationale:** switching later to an external scheduler (APScheduler, a separate
  Render Cron Job/process) would mean re-architecting the trigger path and how it integrates with
  the Flask app-context lifecycle; not a one-line change, but does not require a data migration
  or break any published contract.

### Multi-Worker Safety

- **D-02:** Add a DB-level claim guard now (e.g. a `locked_until`/`claimed_at` column on the
  schedule-bearing table plus a conditional `UPDATE ... WHERE locked_until IS NULL OR
  locked_until < now()`), even though the deployment is single-worker (`--workers 1`) today.
  Production DB is Postgres (Neon per `render.yaml`), so this is implementable without extra
  infrastructure. — **Reversibility:** costly — **rationale:** the claim-guard logic would need
  to be threaded through every scheduler-tick code path; removing it later is possible but
  touches the same surface area as adding it. Deferring instead (the alternative considered) would
  have risked a silent double-fire bug the day gunicorn workers are scaled past 1 (anticipated by
  Phase 4 / HARD-01) — building it now while the schedule-checking code is first being written is
  cheaper than retrofitting it under time pressure later.

### Cadence Model

- **D-03:** Model cadence as a `next_run_at` timestamp on the Asset/schedule, advanced by a fixed
  interval (daily/weekly/monthly) each time it fires, checked by a fixed-interval tick (e.g. every
  few minutes) — not a cron-expression parser (no `croniter`/APScheduler cron trigger). Matches
  the ASSET-03 requirement's preset-cadence framing without adding scheduling power nothing asks
  for. — **Reversibility:** costly — **rationale:** moving to cron-expression-based scheduling
  later would need a new column/format and parser dependency; not a data migration in the
  destructive sense, but a real schema/logic change touching every place `next_run_at` is read.

### Failure Handling

- **D-04:** A failed scheduled scan does not pause or otherwise change the Asset's schedule state
  — it keeps ticking at its normal cadence next time, mirroring existing manual-scan failure
  semantics (`Scan.status = FAILED`, `error_message` stored, never stuck at `RUNNING`). No new
  auto-pause-after-N-failures or notification system for v1.

### Claude's Discretion

The following areas were surfaced as gray areas but not deep-dived; planner/researcher have
discretion to resolve them using existing codebase conventions and the locked decisions above as
constraints:

- **Schedule configuration & scan-type selection UX** — exact cadence preset options, which scan
  type(s) (base/advanced/media/API) can be attached to a schedule, and how tier gating is
  surfaced in the UI when a schedule's chosen scan type exceeds the org's current tier.
- **Asset ↔ Scan/Report relationship** — whether registering an Asset immediately triggers a
  first scan or only arms the schedule; whether one-off manual scans remain available without
  requiring an Asset to exist first; exact shape of the history/trend view (ASSET-05).
- **Pause/resume/delete + tier-downgrade semantics** — soft-delete vs. hard-delete for an Asset;
  what happens to an active schedule when an org's tier downgrades mid-cycle (the scheduled scan
  type becomes locked) — silently downgrade the scan type run, skip that tick with a stored
  reason, or pause the whole schedule. Must satisfy ASSET-07 (no silent Paid/Org-verified check
  execution on a Free-tier schedule) regardless of which specific UX is chosen.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & product context
- `.planning/REQUIREMENTS.md` §"Asset Inventory & Continuous Scanning (ASSET)" — ASSET-01
  through ASSET-08, the full locked requirement list for this phase.
- `.planning/PROJECT.md` §"Constraints" — safety-critical-code-frozen rule (authorization
  checkbox, SSRF guard, entitlements gating must apply identically on every new scan-trigger
  path) and the Render/single-worker-today deployment constraint.
- `.planning/ROADMAP.md` §"Phase 1" — goal and success criteria this phase is accountable to.

### House conventions from prior shipped work (same milestone family, cited in PROJECT.md as
  exemplifying conventions this phase's new work should also follow)
- `docs/superpowers/specs/2026-08-05-api-exposure-and-media-streaming-design.md` — GET-only
  probing and SPA-response-guard conventions.
- `docs/superpowers/specs/2026-08-07-page-completion-and-polish-design.md` — reuse-existing-
  design-system convention, Postgres connection-pooling fix context.

### Codebase map
- `.planning/codebase/ARCHITECTURE.md` — async scan execution model
  (`_spawn_scan_thread`/`_run_scan_in_background`, SSE progress feed) that the new scheduler must
  route through unchanged.
- `.planning/codebase/STACK.md` — Postgres (Neon) in production vs. SQLite in dev; confirms the
  claim-guard mechanism (D-02) is implementable on the production DB.
- `.planning/codebase/CONCERNS.md` — in-memory Flask-Limiter multi-worker gap (addressed in Phase
  4, not this phase) and other known residual gaps not to silently "fix" here.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `_spawn_scan_thread()` / `_run_scan_in_background()` (`glassbox/scan_routes.py:82,180`) —
  the existing daemon-thread + pushed-app-context pattern for async scan execution. The
  scheduler's tick handler should invoke scans through this same path (or a thin wrapper around
  it) rather than duplicating scan-launch logic, so every safety gate it already enforces
  (authorization, SSRF, entitlements) applies identically to scheduled scans.
- `entitlements.allowed_checks()` / `entitlements.py` tier-gating logic — reuse directly for
  ASSET-07 (no silent Paid/Org-verified check execution on a Free-tier schedule).
- `checks.is_ssrf_safe_hostname()` — reuse directly for ASSET-02 (Asset registration must enforce
  the same SSRF-safe-hostname gate as manual scan submission).

### Established Patterns
- Async execution: daemon `threading.Thread` pushing its own Flask app context, not reusing the
  request thread's context — the new scheduler thread should follow the same isolation pattern.
- Failure handling: never leave a `Scan` row stuck at `RUNNING` — any exception sets
  `status = FAILED` with `error_message` stored. The new scheduled-scan path must preserve this.
- Alembic/Flask-Migrate is now the live migration mechanism (`migrations/`) — the new
  Asset/schedule table(s) and the D-02 claim-guard column are normal `flask db migrate`
  operations, not a `db.create_all()`-only workaround.

### Integration Points
- New Asset/schedule table(s) will need a foreign key or association to the existing
  `Organization` model (tier/entitlement lookups already key off org) and likely to `Scan`/
  `Report` (so a scheduled run's results feed the same history/trend infrastructure manual scans
  use).
- The in-process scheduler thread (D-01) needs a start point inside `create_app()` or equivalent
  app-factory wiring — must not double-start under Flask's debug-mode reloader (a known footgun
  for in-process background threads started at import/app-factory time).

</code_context>

<specifics>
## Specific Ideas

No bespoke visual or behavioral references beyond the four locked scheduling decisions above —
all four were accepted as the recommended option during discussion (in-process thread trigger,
DB-level claim guard added now rather than deferred, timestamp-based cadence rather than cron,
and failure handling that mirrors existing manual-scan semantics with no new pause/notify system).

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope. No scope-creep suggestions came up during this
session; the three areas left to Claude's Discretion above are within-phase implementation
ambiguity, not new capabilities.

</deferred>

---

*Phase: 1-Asset Inventory & Continuous Scanning*
*Context gathered: 2026-08-10*
