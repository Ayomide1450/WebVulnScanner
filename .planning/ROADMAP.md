# Roadmap: WebVulnScanner

## Overview

WebVulnScanner ships today as a solid one-shot, human-triggered vulnerability scanner with
genuinely rigorous authorization and SSRF safety engineering — but a security engineer evaluating
it against tools like Nuclei/Trivy/Semgrep will immediately notice it has no persistent asset
inventory, no continuous/scheduled scanning, no programmatic API/CLI, and no compliance-framework
mapping. This milestone closes that gap in dependency order: first give scans a persistent home
(**Asset Inventory & Continuous Scanning**, Phase 1) so a target can be registered once and
monitored over time instead of resubmitted by hand; then expose that asset/scan model
programmatically (**API & CLI Access**, Phase 2) so security teams can wire it into CI/CD and
internal tooling; then make findings audit-usable (**Compliance & Framework Reporting**, Phase 3)
by mapping them to OWASP Top 10/ASVS categories; and finally harden the whole surface — including
the new API and scheduler paths just built — to actually earn the "production ready" bar this
milestone targets (**Production Hardening & Reliability**, Phase 4). Plugin/check-extensibility
and self-hostable/open-core stay explicitly out of scope this milestone (see PROJECT.md and
REQUIREMENTS.md).

### Sequencing Rationale

Phase 1 is continuous/scheduled scanning + the asset-inventory data model, exactly as directed by
the prior session's ranked gap analysis — no deviation there. Two smaller deviations from that
ranked list's raw order are worth calling out explicitly:

- **Rank #2 (plugin/check architecture) is deferred to v2, not built this milestone.** The prior
  recommendation itself didn't push it as urgent relative to continuous scanning/API/compliance,
  and there's no concrete requirement or user request for it now — see PROJECT.md's Out of Scope
  section.

- **Rank #5 (self-hostable/open-core) stays deprioritized** per the user's explicit confirmation
  that billing/SaaS shape is locked — it was never a candidate for this milestone's phases.

So Phase 2 and Phase 3 here correspond to ranked gaps #3 (API/CLI) and #4 (compliance mapping)
respectively, skipping over #2 deliberately rather than by omission. This matches the prior
recommendation's own logic: build the asset/continuous-scanning foundation first, then API/CLI and
compliance-mapping become easier to justify once it exists.

One piece of codebase evidence changes the difficulty of Phase 1 versus what the original gap
analysis assumed: the repo has already moved from an implicit `db.create_all()`-only schema
approach to real Alembic/Flask-Migrate migrations (`migrations/`, confirmed in `CLAUDE.md` and
`webvulnscanner/__init__.py`). A new `Asset` table — and any schema evolution it needs later — is
a normal `flask db migrate` operation now, not the "add a new table because we can't ALTER"
workaround the original gap analysis's framing implied. This makes Phase 1 more tractable than it
would have looked a few sessions ago, but does not change which phase should go first.

Phase 4 (Production Hardening & Reliability) is placed last, not first, because most of what it
hardens (multi-worker rate limiting on new API-token endpoints, test coverage for
scheduler-triggered orchestrators) only fully makes sense once Phases 1–3 exist to hardened. The
remaining visual-polish debt it also picks up (`CONCERNS.md`: dashboard/billing/org-admin/
scan_report) is pre-existing and independent of phase order, but bundling it here — rather than
spreading thin "polish" slivers across every phase — keeps each of Phases 1–3 focused on a single
observable capability, per this project's granularity setting.

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Asset Inventory & Continuous Scanning** - Targets become persistent Assets that can be scanned on a recurring schedule, not just one-shot submissions.
- [x] **Phase 2: API & CLI Access** - Security teams can manage assets and scans programmatically instead of only through the web UI.
- [x] **Phase 3: Compliance & Framework Reporting** - Findings are mapped to OWASP Top 10/ASVS categories for audit-usable reporting.
- [ ] **Phase 4: Production Hardening & Reliability** - The platform holds up under real multi-worker production load with test coverage and visual consistency matching a "production ready" bar.

## Phase Details

### Phase 1: Asset Inventory & Continuous Scanning

**Goal**: Users can register a domain they own once as a persistent Asset and have
WebVulnScanner scan it automatically on a recurring schedule, building a history over time —
instead of manually resubmitting the same target for every scan.
**Depends on**: Nothing (first phase)
**Requirements**: ASSET-01, ASSET-02, ASSET-03, ASSET-04, ASSET-05, ASSET-06, ASSET-07, ASSET-08
**Success Criteria** (what must be TRUE):

  1. User can add a domain as a persistent Asset (separate from submitting a one-off scan) that
     appears in an Asset inventory list.

  2. Adding an Asset requires the same authorization checkbox and SSRF-safe-hostname check as
     submitting a manual scan — no weaker gate on the new entry point.

  3. User can set a recurring scan schedule on an Asset (cadence + scan type), and a scan runs
     automatically at that cadence without the user manually starting it.

  4. User can view an Asset's scan history/trend across multiple scheduled runs, not just the
     latest single scan.

  5. User can pause, resume, or delete an Asset's schedule; a Free-tier Asset's scheduled scan
     never silently runs Paid/Org-verified-only checks.
**Plans**: 2/2 plans executed
Plans:

- [x] 01-01-PLAN.md — Tracer: Asset registration + automatic first scheduled fire, end-to-end (ASSET-01/02/04/07/08, initial ASSET-03)
- [x] 01-02-PLAN.md — Asset detail: schedule editing, scan history/trend, pause/resume/delete (ASSET-03/05/06)

**UI hint**: yes

### Phase 2: API & CLI Access

**Goal**: Security engineers can manage assets and trigger/retrieve scans programmatically,
enabling CI/CD and internal-tooling integration instead of requiring the web UI for every action.
**Depends on**: Phase 1
**Requirements**: API-01, API-02, API-03, API-04, API-05, API-06
**Success Criteria** (what must be TRUE):

  1. Org admin can generate and revoke an API token from the web UI.
  2. Using an API token (no session cookie), a user can list their org's Assets and each Asset's
     latest scan status.

  3. Using an API token, a user can trigger a new scan on an existing Asset and retrieve its
     finished report as structured JSON, subject to the same authorization/SSRF/tier gating the
     web UI enforces.

  4. A CLI command authenticates with an API token and can list assets, start a scan, and print a
     report without opening a browser.
**Plans**: 3/3 plans executed
Plans:

- [x] 02-01-PLAN.md — Tracer: token auth end-to-end (generate/revoke UI, API-01) + first authenticated JSON route (GET /api/v1/assets, API-02)
- [x] 02-02-PLAN.md — Trigger scan (API-03) + fetch report with ownership-mismatch fix (API-04) + rate-limit/tier-gate proof (API-05)
- [x] 02-03-PLAN.md — CLI: login, assets list, scan start, report get (API-06)

**UI hint**: yes

### Phase 3: Compliance & Framework Reporting

**Goal**: Security teams can see scan findings mapped to recognized compliance frameworks (OWASP
Top 10 / ASVS) for audit and reporting purposes, not just a flat severity list.
**Depends on**: Phase 1
**Requirements**: COMP-01, COMP-02, COMP-03, COMP-04
**Success Criteria** (what must be TRUE):

  1. A scan report shows each finding's mapped OWASP Top 10 (and/or ASVS) category alongside its
     severity.

  2. User can filter or group a report's findings by compliance category, not only by severity.
  3. User can view a per-Asset compliance-coverage summary across its scan history — which
     categories have been checked, and which are currently failing.
**Plans**: 3/3 plans executed

- [x] 03-01-PLAN.md
- [x] 03-02-PLAN.md
- [x] 03-03-PLAN.md

**UI hint**: yes

### Phase 4: Production Hardening & Reliability

**Goal**: The platform is safe to run with more than one production worker and has test/visual
consistency coverage matching the "production ready" bar this milestone targets.
**Depends on**: Phase 1, Phase 2, Phase 3
**Requirements**: HARD-01, HARD-02, HARD-03, HARD-04, HARD-05
**Success Criteria** (what must be TRUE):

  1. Rate limits (login, signup, invoice, and the new API-token endpoints) enforce correctly even
     when the app runs with more than one gunicorn worker.

  2. `run_advanced_scan`, `run_media_scan`, and `run_api_scan` each have automated tests covering
     status transitions and error handling, matching the coverage `run_scan` already has —
     including the scheduler-triggered path added in Phase 1.

  3. Org invite/role-change/domain-verification flows have automated test coverage beyond the
     current single rendering test.

  4. Dashboard, billing, org-admin, and scan_report pages visually match the rest of the app's
     design system — no bland/legacy styling left on any of the four.
**Plans**: 2/5 plans executed
Plans:

- [x] 04-01-PLAN.md — Tracer: shared `_score_report()` helper across all 4 orchestrators (HARD-04) + direct-invocation coverage and safety-constraint regression locks for the 3 untested orchestrators (HARD-02)
- [x] 04-02-PLAN.md — Multi-worker rate limiting: `RATELIMIT_STORAGE_URI` proven shared via a two-limiter fakeredis test, `redis`/`fakeredis` deps, boot-time backend log (HARD-01)
- [ ] 04-03-PLAN.md — Finish the org invite flow with email-bound tokens + invite-mode signup, plus domain-verification test coverage (HARD-03)
- [ ] 04-04-PLAN.md — Scheduler-fired media/api coverage and `_run_scan_in_background` status transitions for all 3 scan types (HARD-02, remainder)
- [ ] 04-05-PLAN.md — Reuse-only visual consistency pass on dashboard/billing/org-admin/scan_report + phase documentation reconciliation (HARD-05)

**Execution waves**: wave 1 = 04-01, 04-02, 04-03 (no shared files); wave 2 = 04-04 (needs 04-01),
04-05 (needs 04-03's `org_admin.html` edit).

**UI hint**: yes

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Asset Inventory & Continuous Scanning | 2/2 | Complete | 2026-08-11 |
| 2. API & CLI Access | 3/3 | Complete | 2026-08-11 |
| 3. Compliance & Framework Reporting | 3/3 | Complete | 2026-08-11 |
| 4. Production Hardening & Reliability | 2/5 | In Progress|  |
