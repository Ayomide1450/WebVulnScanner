# Phase 4: Production Hardening & Reliability - Context

**Gathered:** 2026-08-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Make the app safe to run behind more than one gunicorn worker, close the test-coverage gaps on
the 3 untested scan orchestrators (including the scheduler-triggered path Phase 1 added) and on
org invite/role/domain-verification flows, deduplicate the scoring logic that's currently
copy-pasted across all four orchestrators, and bring dashboard/billing/org-admin/scan_report
visually in line with the rest of the app's existing design system. Five locked requirements:
HARD-01 (multi-worker rate limiting), HARD-02 (orchestrator test coverage), HARD-03 (org-flow
test coverage), HARD-04 (shared scoring helper), HARD-05 (visual consistency pass). This phase is
almost entirely "how," not "what" — `REQUIREMENTS.md` and `.planning/codebase/CONCERNS.md`
already pin down most of the what.

</domain>

<decisions>
## Implementation Decisions

### HARD-01: Multi-worker rate limiting (not discussed live — see Claude's Discretion)

- **D-01:** Wire `Limiter`'s `storage_uri` to Redis via the already-present `RATELIMIT_STORAGE_URI`
  config value (currently read into `app.config` but not exercised by any test). Prove
  multi-worker-safety with a test that instantiates two separate `Limiter`/app instances against
  the same fake shared backend and confirms they share a counter — use an in-process fake
  (e.g. `fakeredis`) rather than a real Redis service container, to keep this repo's
  zero-external-service CI convention (`.github/workflows/tests.yml` currently needs no service
  containers, no `.env`) intact. Add `redis`/`fakeredis` to `requirements.txt`/
  `requirements-dev.txt` respectively.

### HARD-02: Orchestrator test coverage

- **D-02:** New tests for `run_advanced_scan`/`run_media_scan`/`run_api_scan` go beyond the
  literal "status transitions and error handling" wording to also regression-lock each
  orchestrator's safety constraints (e.g. `MAX_BRUTEFORCE_ATTEMPTS` cap, stored-XSS marker-only
  proof with no cookie exfiltration, no form auto-submission) — these are the most sensitive
  checks in the app per `CONCERNS.md`'s own priority note, and losing regression coverage on the
  safety caps specifically would be worse than losing it on plain status-transition logic.
- **D-03:** All three orchestrators' tests are fully mocked — stub check functions, no real
  network calls — matching `run_scan`'s existing convention in `tests/test_scan_events.py` and
  `TESTING.md`'s documented pattern. No precedent in this suite for hitting a live test target.
- **D-04:** `run_advanced_scan` has no scheduler-triggered path to test — confirmed via
  `webvulnscanner/scheduler.py`'s `_fire()`, which only branches on `"base"`/`"media"`/`"api"`;
  there is no `"advanced"` branch, and `Asset`'s schedule model has no field for stored
  credentials. This is intentional (advanced scans need per-run credentials/session cookies that
  don't fit unattended scheduling), not a bug to fix — test `run_advanced_scan` via direct
  invocation only. `run_media_scan`/`run_api_scan` need both direct-invocation tests and
  scheduler-fired tests (extending `tests/test_scheduler.py`'s pattern, which today only exercises
  the `"base"` branch per Phase 1).

### HARD-03: Org-flow test coverage & the invite/role-change gap

- **D-05:** Real, previously-undocumented gap found during discussion: `org_routes.py`'s
  `invite()` generates a signed token via `generate_invite_token(org_id, role)` and emails a
  link to `/signup?invite=<token>`, but `/signup` (`auth_routes.py`) never reads the `invite`
  query param at all — `decode_invite_token` is defined and never called anywhere in the
  codebase. The invite email's own body text already says so ("signup does not yet consume the
  invite token automatically"). There is also no route anywhere to change an existing member's
  role — `org_admin.html`'s role column is plain read-only text.
- **D-06:** Finish the invite flow as part of this phase: `/signup` gains an invite-mode branch
  that decodes the token, joins the token's `org_id` at the token's `role` (skipping/hiding the
  "create a new org" field in that mode), and is what HARD-03's "role-change... test coverage"
  is understood to mean — role *assignment* via invite, end-to-end tested. **No standalone
  route for changing an already-existing member's role gets built** — that would be a new admin
  capability, not hardening/consistency work, and wasn't scoped by the roadmap. If a real
  standalone role-change route is wanted later, it's a new phase/requirement, not folded in here.
- **D-07:** While finishing the invite flow, also close a real security gap found alongside it:
  `generate_invite_token`/`decode_invite_token` don't bind the invitee's email, so a
  leaked/forwarded invite link could be used by anyone to join the org at the granted role.
  Change the signature to `generate_invite_token(org_id, role, email)`; signup's invite-mode
  pre-fills/locks the email field and rejects a mismatch at decode time.
- **D-08:** Domain-verification flow (`org_routes.py`'s `verify_domain_view` +
  `domain_verification.py`) needs test coverage too per HARD-03's literal wording — this part of
  the requirement is uncontroversial (the flow already exists and works, it's just untested); no
  discussion needed on scope here, only on the invite/role-change ambiguity above.

### HARD-04: Shared scoring helper

- **D-09:** Not discussed live — `.planning/codebase/CONCERNS.md` already fully specifies the fix
  approach (extract `_score_report(findings) -> (risk_score, grade, severity_counts)` and call it
  from all four orchestrators in `scan_engine.py`), and there was no ambiguity worth a discussion
  round. Treat this as settled; research/planning should follow `CONCERNS.md`'s own note unless
  something new turns up.

### HARD-05: Visual consistency pass

- **D-10:** Reuse-only scope — apply `base.html`'s already-built primitives (`.glow-pulse`,
  `.hud-grid`, `--telemetry`/`--telemetry2`, `.table-scroll`, `.status-pill`, etc.) to
  `dashboard.html`/`billing.html`/`org_admin.html`/`scan_report.html`. No new components or
  visual patterns get invented here — this matches HARD-05's literal wording ("visually match
  the rest of the app's existing design system") and `CONCERNS.md`'s own fix-approach note. A
  fuller redesign moment was considered and explicitly declined for this phase — see Deferred
  Ideas.
- **D-11:** Run a dedicated `/gsd-ui-phase 4` UI-SPEC before planning, consistent with the
  precedent set by Phase 2 (`02-UI-SPEC.md`) and Phase 3 (`03-UI-SPEC.md`), both also flagged
  "UI hint: yes" in `ROADMAP.md`.

### Claude's Discretion

- HARD-01 (multi-worker rate limiting) was not selected for live discussion. D-01 above is the
  disclosed default the user saw and did not override before choosing "ready for context" — not
  a directly-confirmed decision, so research/planning should treat the Redis+fakeredis approach
  as a strong default rather than an immovable lock, and flag it back if research surfaces a
  reason to prefer something else (e.g. if a real Redis instance turns out to already be
  provisioned somewhere, or a memcached-backed alternative fits better).
- Exact new-test file organization for HARD-02/HARD-03 (one file per orchestrator/flow vs.
  consolidated) is left to the planner — follow `TESTING.md`'s existing "one file per feature
  area" convention unless there's a good reason to deviate.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & scope
- `.planning/REQUIREMENTS.md` — HARD-01..05, the exact locked requirement wording this phase
  must satisfy
- `.planning/ROADMAP.md` §"Phase 4: Production Hardening & Reliability" — goal, success criteria,
  dependencies
- `.planning/PROJECT.md` — Constraints section (Render-only deployment, safety-critical-code-frozen
  rule, "Detection stays rule-based" rule)

### Codebase evidence backing this phase's decisions
- `.planning/codebase/CONCERNS.md` — Tech Debt (scoring dedup fix approach for HARD-04, visual
  pass fix approach for HARD-05), Fragile Areas (background-scan-thread/SQLite caveat relevant to
  any new orchestrator test), Test Coverage Gaps (exact citations behind HARD-02/HARD-03)
- `.planning/codebase/TESTING.md` — existing test file organization, fixture/factory conventions
  (`tests/conftest.py`), the fully-mocked-check-functions convention D-03 follows, and the
  rate-limiting-disabled-by-default test convention relevant to D-01's new test
- `webvulnscanner/scheduler.py` — `_fire()`/`_tick()`; grounds D-04's scheduler-dispatch finding
- `webvulnscanner/org_routes.py`, `webvulnscanner/auth_routes.py`, `webvulnscanner/domain_verification.py`
  — grounds D-05 through D-08's invite/role/domain-verification findings
- `webvulnscanner/extensions.py`, `webvulnscanner/config.py` — existing `RATELIMIT_STORAGE_URI`/
  `TRUST_PROXY_HOPS` wiring D-01 builds on

### Prior-phase precedent
- `.planning/phases/01-asset-inventory-continuous-scanning/01-CONTEXT.md` — the scheduler's
  DB-level claim guard was already built multi-worker-safe in anticipation of this phase; HARD-01
  is scoped to the HTTP-rate-limiter layer only, not the scheduler
- `.planning/phases/02-api-cli-access/02-UI-SPEC.md`, `.planning/phases/03-compliance-framework-reporting/03-UI-SPEC.md`
  — precedent D-11 follows for running a dedicated UI-SPEC cycle

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `tests/test_scan_events.py` — the exact test shape (`progress_cb` call sequence, stubbed check
  functions, status-transition assertions) to mirror for the new orchestrator tests, adapted since
  `run_advanced_scan`/`run_media_scan`/`run_api_scan` have no `progress_cb` parameter at all
- `tests/test_scheduler.py` — existing scheduler-fire test pattern (Phase 1, `"base"` only today)
  to extend for `"media"`/`"api"` scheduler-triggered coverage
- `webvulnscanner/scheduler.py`'s `_fire()` return-value contract (returns the created `Scan` row
  on every branch, added in Phase 2) — reusable for asserting scheduler-fired scan outcomes in the
  new tests without needing new scaffolding
- `base.html`'s `.glow-pulse`/`.hud-grid`/`--telemetry`/`.table-scroll`/`.status-pill` primitives —
  the exact toolkit D-10 restricts the visual pass to

### Established Patterns
- Every check/orchestrator test in this suite mocks network calls and disables rate limiting by
  default (`RATELIMIT_ENABLED = False` in `TestConfig`) — D-01's new rate-limit test is the
  documented one exception that re-enables it, same pattern `test_auth_flows.py`'s existing
  `/login` 429 test already uses
- `CHECK_LABELS`/`CHECK_CATEGORY` coverage-regression-test convention (a test asserting every
  dispatchable check has a matching label/category entry) — `COMP-04` already extended this
  pattern to compliance mappings in Phase 3; HARD-04's scoring dedup doesn't need an equivalent
  regression test since there's only one formula after the extraction, not a per-check map to
  drift

### Integration Points
- New `/signup?invite=<token>` branch integrates into `auth_routes.py`'s existing `signup()`
  view — needs to coexist with the current create-new-org-or-solo-user path, not replace it
- New rate-limit storage wiring integrates into `webvulnscanner/extensions.py`'s existing
  `limiter = Limiter(key_func=get_remote_address)` + `webvulnscanner/__init__.py`'s
  `limiter.init_app(app)` — Flask-Limiter already reads `RATELIMIT_STORAGE_URI` from
  `app.config` automatically, no new plumbing needed beyond setting the value and adding the
  Redis client dependency

</code_context>

<specifics>
## Specific Ideas

No particular visual/UX references given beyond "reuse what already exists, don't invent new" for
HARD-05 (D-10) — the `/gsd-ui-phase 4` UI-SPEC cycle (D-11) is where more specific per-page
direction will get worked out.

</specifics>

<deferred>
## Deferred Ideas

- **A fuller HARD-05 redesign moment** (new visual patterns beyond what `base.html` already has)
  was raised and explicitly declined for this phase in favor of the reuse-only scope (D-10) — the
  phase's goal is consistency with the existing system, not a new design iteration. Worth
  revisiting as its own dedicated visual-redesign phase if wanted later.
- **A standalone member role-change route** (changing an existing member's role after they've
  already joined, not just at invite time) was raised and explicitly declined for this phase
  (D-06) as a new admin capability outside "hardening." Worth its own requirement in a future
  milestone if needed.
- **Making `run_advanced_scan` schedulable** (would need a design for storing/reusing test
  credentials for unattended runs) was raised and explicitly declined (D-04) — flagged as a
  bigger design question than fits inside Phase 4.

### Reviewed Todos (not folded)
None — `todo.match-phase 4` returned zero matches.

</deferred>

---

*Phase: 4-production-hardening-reliability*
*Context gathered: 2026-08-13*
