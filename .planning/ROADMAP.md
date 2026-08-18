# Roadmap: WebVulnScanner

## Milestones

- ✅ **v1.0 Asset Inventory, API/CLI, Compliance & Hardening** - Phases 1-4 (shipped 2026-08-13)
- 🚧 **v1.1 Production Audit, Hardening & Redesign** - Phases 5-9 (in progress)

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order. Phase numbering is
continuous across milestones (v1.1 starts at Phase 5, not Phase 1).

<details>
<summary>✅ v1.0 Asset Inventory, API/CLI, Compliance & Hardening (Phases 1-4) - SHIPPED 2026-08-13</summary>

- [x] **Phase 1: Asset Inventory & Continuous Scanning** - Targets become persistent Assets that can be scanned on a recurring schedule, not just one-shot submissions.
- [x] **Phase 2: API & CLI Access** - Security teams can manage assets and scans programmatically instead of only through the web UI.
- [x] **Phase 3: Compliance & Framework Reporting** - Findings are mapped to OWASP Top 10/ASVS categories for audit-usable reporting.
- [x] **Phase 4: Production Hardening & Reliability** - The platform holds up under real multi-worker production load with test coverage and visual consistency matching a "production ready" bar.

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
**Plans**: 5/5 plans executed

- [x] 04-01-PLAN.md — Tracer: shared `_score_report()` helper across all 4 orchestrators (HARD-04) + direct-invocation coverage and safety-constraint regression locks for the 3 untested orchestrators (HARD-02)
- [x] 04-02-PLAN.md — Multi-worker rate limiting: `RATELIMIT_STORAGE_URI` proven shared via a two-limiter fakeredis test, `redis`/`fakeredis` deps, boot-time backend log (HARD-01)
- [x] 04-03-PLAN.md — Finish the org invite flow with email-bound tokens + invite-mode signup, plus domain-verification test coverage (HARD-03)
- [x] 04-04-PLAN.md — Scheduler-fired media/api coverage and `_run_scan_in_background` status transitions for all 3 scan types (HARD-02, remainder)
- [x] 04-05-PLAN.md — Reuse-only visual consistency pass on dashboard/billing/org-admin/scan_report + phase documentation reconciliation (HARD-05)

**Execution waves**: wave 1 = 04-01, 04-02, 04-03 (no shared files); wave 2 = 04-04 (needs 04-01),
04-05 (needs 04-03's `org_admin.html` edit).

**UI hint**: yes

</details>

### 🚧 v1.1 Production Audit, Hardening & Redesign (In Progress)

**Milestone Goal:** Bring every page and every request path up to production-grade UI/UX,
accessibility, responsiveness, security, and SEO standards — a systematic audit-then-fix pass
across the whole app, not incremental feature work.

#### Overview

v1.0 proved the product concept (persistent assets, continuous scanning, API/CLI, compliance
mapping) but shipped with known, accumulated debt: a New Scan flow that predates the tiered/
verified-domain model it now needs to reflect, four independently-drifted templates' worth of
design-system inconsistency, zero systematic responsive/accessibility verification, and a
security posture that's been extended (API tokens, scheduler, asset routes, admin panel) faster
than it's been re-audited as a whole. This milestone closes that gap in five phases, sequenced so
each one builds on a stable surface rather than auditing work that's about to change underneath
it: **New Scan Flow Redesign** (Phase 5) ships the already-fully-specified guided scan-launch
flow first, since it's self-contained and adds new templates the later audit phases should cover
too; **Design System Consistency** (Phase 6) then establishes one canonical typography/spacing/
component/container standard across every template, including the ones Phase 5 just built;
**Responsive & Accessibility Compliance** (Phase 7) verifies and fixes mobile rendering and
keyboard/AT operability against that now-consolidated component set, rather than doing it twice;
**Security Re-Audit & Hardening** (Phase 8) is a dedicated, verify-and-close-gaps pass across the
full route surface (including the API/scheduler/admin surfaces added in v1.0) — deliberately not
a redesign of `authorized*`, `entitlements.py`, or `is_ssrf_safe_hostname()`, all of which stay
frozen; and **SEO, Performance & UX States** (Phase 9) closes the milestone with the smaller,
independent remaining categories — public-page discoverability, list-query scaling, and loading/
empty/error feedback — several of which reuse Phase 6's canonical alert/card components.

#### Sequencing Rationale

**Phase 5 goes first, not last**, even though "audit the whole app" reads like it should start
with the audit. SCANUX-01..05 is already fully specified from a prior session (see `handoff.md`)
and is self-contained — it doesn't depend on the design-system consolidation work in Phase 6.
Building it first means Phase 6's template-wide audit only has to pass over the New Scan pages
once, in their final form, instead of auditing the old single-form pages and then re-auditing
the redesigned ones.

**Phases 6 and 7 are sequenced adjacent, not merged into one phase**, despite both touching every
template. DESIGN-01..04 (typography/spacing/component/container consistency) and RESP-01..04 +
A11Y-01..04 (responsive rendering and keyboard/AT operability) are genuinely different, separately
observable capabilities — "the button style is consistent" and "the page doesn't overflow at
320px" are not the same claim, even though fixing both often touches the same template. Phase 7
depends on Phase 6 specifically so responsive/accessibility fixes are made against the
already-consolidated canonical components (one `.btn`, one `.card`, one alert-box style) instead
of being made twice: once against the pre-audit drift, once again after Phase 6 changes it.

**Phase 8 (Security Re-Audit) is a dedicated phase**, matching its size (10 of 36 requirements,
the largest single category) and risk profile. It is explicitly framed as **verify-and-close-gaps,
not redesign**: `authorized`/`authorized_adv`/`authorized_media`/`authorized_api`,
`entitlements.py`'s tier/domain-verification gating, and `checks.is_ssrf_safe_hostname()` are
frozen per PROJECT.md/CLAUDE.md — this phase's job is proving (with regression tests) that every
route built since the last security-focused pass (v1.0's API tokens, scheduler, asset routes,
platform-admin panel) actually enforces the same guarantees, and closing any gap found. It's
sequenced after Phases 5-7 so it audits the final template/route surface rather than one about to
change — most SEC requirements are route/data-layer and don't strictly require the UI phases to
land first, but auditing markup once instead of twice is still the cheaper order.

**Phase 9 closes the milestone** with SEO (public-page-only metadata — explicitly never touching
authenticated pages), Performance (N+1/pagination audit on list-heavy pages), and Loading/Empty/
Error States (STATE-01..03, which reuse Phase 6's canonical card/alert/pill components for
consistency). These three categories are smaller (9 requirements combined) and largely
independent of each other and of Phases 5-8, but bundling them into one closing phase — rather
than three separate thin phases — keeps this milestone at 5 phases total per the granularity
target, avoiding a "maintenance sliver" phase for any single category.

No phase in this milestone proposes changing the billing/SaaS shape (crypto invoicing, tier
model — SEC-09 audits `billing.py`'s existing verification logic, it does not redesign it), the
Fly.io always-on-VM / `threading.Thread`-per-scan deployment model, or the rule-based-only
detection convention (the AI layer continues to only explain/prioritize findings, never generate
them).

- [ ] **Phase 5: New Scan Flow Redesign** - `/scan/new` becomes a guided Select Domain → Select Type → Confirm Authorization → Start Scan flow instead of four disconnected single-form pages.
- [ ] **Phase 6: Design System Consistency** - Every template draws from one canonical typography scale, spacing scale, component style set, and container-width convention.
- [ ] **Phase 7: Responsive & Accessibility Compliance** - Every page renders correctly from 320px to desktop and is fully operable by keyboard/assistive technology.
- [ ] **Phase 8: Security Re-Audit & Hardening** - Every ID-accepting route, form, redirect, and file-serving path across the app (including v1.0's new API/scheduler/admin surfaces) is verified to enforce its existing safety guarantees, with gaps closed.
- [ ] **Phase 9: SEO, Performance & UX States** - Public pages are correctly indexable, list-heavy pages don't degrade at scale, and every page communicates loading/empty/error states clearly.

## Phase Details

### Phase 5: New Scan Flow Redesign

**Goal**: A user launching a scan moves through a guided Select Domain → Select Type → Confirm
Authorization → Start Scan sequence — picking from their org's verified domains where possible —
instead of filling out one of four disconnected single-form pages from a free-text field.
**Depends on**: Phase 4 (v1.0, complete)
**Requirements**: SCANUX-01, SCANUX-02, SCANUX-03, SCANUX-04, SCANUX-05
**Success Criteria** (what must be TRUE):

  1. Visiting `/scan/new` (or any of its 4 sub-pages) presents a linear Select Domain → Select
     Type → Confirm Authorization → Start Scan sequence, not a single flat form.

  2. The target-selection step offers a "Select Verified Domain" dropdown populated from the
     org's verified `DomainVerification`/`Asset` records, with free-text entry still available
     for unclaimed/one-off targets.

  3. The base scan type displays as "Standard Scan" in the UI, and every scan type shows one of
     Included / Requires Verified Domain / Requires Paid Plan.

  4. A tier-locked scan type shows an "Upgrade to Unlock" call-to-action rather than a disabled
     or absent control.

  5. After a scan completes, a "View Report" action is reachable from the same page context the
     scan was launched from.
**Plans**: 1/3 plans executed

Plans:
**Wave 1**

- [x] 05-01-PLAN.md — Tracer: wizard shell (stepper + Select Domain + Select Type) plus the Standard Scan end-to-end (SCANUX-01/02/03/04)

**Wave 2** *(blocked on Wave 1 completion)*

- [ ] 05-02-PLAN.md — Expansion: media, API and Advanced launch pages into the wizard shell, including D-02's Advanced deviation (SCANUX-01/03/04)

**Wave 3** *(blocked on Wave 2 completion)*

- [ ] 05-03-PLAN.md — View Report reachability: `/scan/<id>/status` endpoint plus progress-page poll for advanced/media/api (SCANUX-05)

**Execution waves**: wave 1 = 05-01; wave 2 = 05-02 (needs 05-01's route helpers and the
stepper partial); wave 3 = 05-03. All three modify `webvulnscanner/scan_routes.py`, so they
are strictly sequential — no same-wave file overlap exists.

**UI hint**: yes

### Phase 6: Design System Consistency

**Goal**: Every template — including the New Scan pages built in Phase 5 — draws from one
documented typography scale, one spacing scale, and one canonical style per shared component
(buttons, inputs, cards, tables, badges/pills, alert boxes), with no local drift left
unconsolidated.
**Depends on**: Phase 5
**Requirements**: DESIGN-01, DESIGN-02, DESIGN-03, DESIGN-04
**Success Criteria** (what must be TRUE):

  1. `base.html` defines one documented typography scale (Display/H1-H4/Body/Small/Caption/
     Label/Button/Nav), and an audit of every template's headings/body text finds no one-off
     `font-size`/`font-weight` override outside it.

  2. `base.html` defines one documented spacing scale, and arbitrary pixel margin/padding values
     found during the audit are removed or replaced with scale values.

  3. Buttons, inputs/selects/textareas, cards, tables, badges/pills, and alert/warn/error/info
     boxes each resolve to exactly one canonical style in `base.html` (or a shared partial) —
     divergent local overrides found during the audit are consolidated into it.

  4. Dashboard, form, and report page container/content max-widths are consistent — no page
     reads as unintentionally cramped or overly stretched relative to its siblings.
**Plans**: 1/4 plans executed

Plans:
**Wave 1**

- [x] 06-01-PLAN.md — Foundation: base.html design-token/canon authoring, proven end-to-end via the
      auth partial, plus the other two form partials and the legal partial (DESIGN-01/02/03/04)

**Wave 2** *(blocked on Wave 1 completion)*

- [ ] 06-02-PLAN.md — Marketing, legal, and auth pages (DESIGN-01/02/03/04)
- [ ] 06-03-PLAN.md — Logged-in app pages: dashboard/billing/org-admin/platform-admin/assets/
      api-tokens plus the three error pages (DESIGN-01/02/03/04)

- [ ] 06-04-PLAN.md — Scan-flow pages: the New Scan wizard, scan-progress, scan-report, scan-compare
      (DESIGN-01/02/03/04)

**Execution waves**: wave 1 = 06-01 (establishes base.html tokens + all shared partials); wave 2 =
06-02/06-03/06-04, all depending only on 06-01 and touching disjoint template sets, so they run in
parallel.

**UI hint**: yes

### Phase 7: Responsive & Accessibility Compliance

**Goal**: Every page renders correctly at mobile-through-desktop widths and is fully usable by
keyboard and assistive technology, built against the canonical component set Phase 6 established.
**Depends on**: Phase 6
**Requirements**: RESP-01, RESP-02, RESP-03, RESP-04, A11Y-01, A11Y-02, A11Y-03, A11Y-04
**Success Criteria** (what must be TRUE):

  1. A live browser check at 320px, 375px, 768px, and 1280px viewport widths shows no horizontal
     scroll, clipped text, or overlapping elements on every page.

  2. Auth pages (login/signup/forgot-password/reset-password/verify-email) and org setup pages
     (create org, add domain, verify domain) show a polished, non-cramped mobile layout with the
     product name correctly positioned relative to the form, verified live.

  3. The dashboard, org-admin, billing, and scan-report pages' tables use a deliberate mobile
     strategy (scroll container, stacked cards, or collapsed columns) instead of silent overflow
     clipping, and the live scan-progress feed remains legible and usable at mobile widths.

  4. Every form input has a properly associated `<label>`, every icon-only control has an
     accessible name, and every interactive element (including any clickable `<div>`s found
     during audit) is reachable and operable via keyboard alone with a visible focus state —
     confirmed by a keyboard-only walkthrough.

  5. Heading hierarchy (`h1`→`h2`→`h3`) is sequential and non-skipping on every major page
     template, and text/UI-element color contrast — including severity-colored finding text/
     badges — meets WCAG AA against the dark theme's background colors, confirmed with a
     contrast-checking tool.
**Plans**: 7 plans

Plans:
**Wave 1**

- [ ] 07-01-PLAN.md — Tracer: base.html responsive/a11y CSS foundation, proven end-to-end by converting dashboard.html's Scan History table to D-01 dual markup

**Wave 2** *(blocked on Wave 1 completion)*

- [ ] 07-02-PLAN.md — org_admin.html's four record tables + org_verify_domain.html's Domains table to dual markup, CSRF forms preserved, deletion-reason input given an accessible name
- [ ] 07-03-PLAN.md — api_tokens.html / assets.html / asset_detail.html record tables to dual markup, revoke confirm() preserved, .icon-btn deduplicated
- [ ] 07-04-PLAN.md — RESP-02 auth/org-setup mobile layout: screenshot first, then tighten the brand-to-card gap and suppress the duplicate CTA in _auth_form_styles.html
- [ ] 07-05-PLAN.md — scan_report.html's 23 diagnostic tables get correct thead/tbody semantics and a per-table 320px audit; _gauge.html's hardcoded hexes become token classes

**Wave 3** *(blocked on Wave 2 completion)*

- [ ] 07-06-PLAN.md — Heading-hierarchy fixes on marketing.html and scan_new_advanced.html, plus app-wide accessibility regression locks and the keyboard-only walkthrough

**Wave 4** *(blocked on Wave 3 completion)*

- [ ] 07-07-PLAN.md — Phase gate: four-width sweep of every page, RESP-04 scan-progress re-confirmation, and phase-wide regression locks

**Execution waves**: wave 1 = 07-01 (establishes every new base.html class, breakpoint and token so
no later plan needs to edit it); wave 2 = 07-02/07-03/07-04/07-05, all depending only on 07-01 and
touching disjoint template sets, so they run in parallel; wave 3 = 07-06, whose accessibility
locks must run over the final markup including the nine mobile-card blocks wave 2 adds; wave 4 =
07-07, the live full-app sweep and phase gate, which can only run once everything has merged.

**UI hint**: yes

### Phase 8: Security Re-Audit & Hardening

**Goal**: Every route, form, redirect target, and file-serving path across the app — including
the API tokens, scheduler, asset routes, and platform-admin panel added in v1.0 — is verified
server-side to enforce the same ownership, CSRF, SSRF, injection, and information-disclosure
guarantees the product already promises, with any gap found closed and covered by a regression
test. This phase verifies and closes gaps; it does not weaken or redesign `authorized*`,
`entitlements.py`, `checks.is_ssrf_safe_hostname()`, or `billing.py`'s verification logic.
**Depends on**: Phase 5, Phase 6, Phase 7
**Requirements**: SEC-01, SEC-02, SEC-03, SEC-04, SEC-05, SEC-06, SEC-07, SEC-08, SEC-09, SEC-10
**Success Criteria** (what must be TRUE):

  1. An automated test proves a cross-org GET/POST/PUT/DELETE on every ID-accepting route
     (scan/report/asset/domain/invoice/token/org/user, including the `/api/v1/*` surface) returns
     403/404, never 200 with another org's data — with a regression test added per route family
     where one didn't already exist.

  2. Every state-changing form/route (domain add/delete/verify, scan submission, billing actions,
     org/member changes, account changes, admin actions) is confirmed to carry CSRF protection,
     with any gap closed.

  3. A redirect-following test proves that an SSRF-safe initial hostname which 30x-redirects to a
     private/loopback/link-local/metadata address is rejected by the scan HTTP clients, not
     followed unchecked.

  4. Automated tests confirm user-controlled strings (org name, domain name, finding detail/
     title text, AI-generated summary text, error messages) are never rendered as unescaped HTML,
     no raw/string-interpolated SQL exists outside parameterized SQLAlchemy usage, and report/
     media/CSV download routes reject path-traversal input (`../`, absolute paths).

  5. Tests confirm login/logout/invite/next-param redirects only ever target the app's own
     origin everywhere a redirect target is user-influenced, a repo-wide secrets sweep finds no
     hardcoded credential added this milestone, `billing.py`/`billing_routes.py` invoice
     verification rejects replay/double-activation/amount-tampering/cross-org access, and
     production-mode 400/401/403/404/429/500 responses never leak a stack trace, file path, SQL
     fragment, or environment variable.
**Plans**: TBD

### Phase 9: SEO, Performance & UX States

**Goal**: Public marketing/legal pages are correctly discoverable and indexable while
authenticated pages stay out of search surfaces entirely, dashboard/org-admin list queries and
unbounded lists don't degrade as data grows, and every page communicates its loading/empty/error
condition clearly instead of going blank or stalling silently.
**Depends on**: Phase 6
**Requirements**: SEO-01, SEO-02, SEO-03, SEO-04, PERF-01, PERF-02, STATE-01, STATE-02, STATE-03
**Success Criteria** (what must be TRUE):

  1. Public pages (marketing home, terms, privacy) each render a correct `<title>`, meta
     description, canonical URL, and Open Graph tags; authenticated/private pages render none of
     these.

  2. `robots.txt` allows crawling of public marketing pages and disallows every authenticated app
     route (dashboard/scan/org/billing/admin/account); `sitemap.xml` lists only public URLs; a
     complete favicon set (favicon.ico, PNG sizes, apple-touch-icon) resolves correctly in
     production.

  3. Dashboard and org-admin queries that list scans/domains/members are confirmed free of N+1
     patterns (via query-count assertion or eager-loading audit) where found, and every unbounded
     list (scan history, asset list, org members, findings) that could grow large is paginated or
     otherwise capped.

  4. Every major page with a first-run/no-data condition (no assets, no scans, no domains, no
     invoices, no findings) shows a real empty-state message with a clear next action, not a
     blank area or raw empty table; every form shows a distinct in-flight submitting state
     (disabled + loading indicator) consistent with the pattern already used on the auth forms.

  5. A failed/errored scan, a timed-out scan, and a duplicate concurrent scan attempt each
     surface a clear, specific message to the user rather than a generic failure or silent stall.
**Plans**: TBD

**UI hint**: yes

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Asset Inventory & Continuous Scanning | v1.0 | 2/2 | Complete | 2026-08-11 |
| 2. API & CLI Access | v1.0 | 3/3 | Complete | 2026-08-11 |
| 3. Compliance & Framework Reporting | v1.0 | 3/3 | Complete | 2026-08-11 |
| 4. Production Hardening & Reliability | v1.0 | 5/5 | Complete | 2026-08-13 |
| 5. New Scan Flow Redesign | v1.1 | 1/3 | In Progress|  |
| 6. Design System Consistency | v1.1 | 1/4 | In Progress|  |
| 7. Responsive & Accessibility Compliance | v1.1 | 0/TBD | Not started | - |
| 8. Security Re-Audit & Hardening | v1.1 | 0/TBD | Not started | - |
| 9. SEO, Performance & UX States | v1.1 | 0/TBD | Not started | - |
