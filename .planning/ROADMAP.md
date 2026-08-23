# Roadmap: WebVulnScanner

## Milestones

- ✅ **v1.0 Asset Inventory, API/CLI, Compliance & Hardening** - Phases 1-4 (shipped 2026-08-13)
- ✅ **v1.1 Production Audit, Hardening & Redesign** - Phases 5-9 (shipped 2026-08-20)
- ⏸️ **v1.2 Live Verification Closeout** - Phase 10 (deferred, not dropped - reprioritized behind v1.3)
- ✅ **v1.3 Glassbox Rebrand & Production Security Readiness** - Phases 11-15 (shipped 2026-08-20)
- 🚧 **v1.4 Admin Controls, Check Depth & CLI Client** - Phases 16-18 (planned)

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order. Phase numbering is
continuous across milestones.

<details>
<summary>✅ v1.0 Asset Inventory, API/CLI, Compliance & Hardening (Phases 1-4) - SHIPPED 2026-08-13</summary>

- [x] **Phase 1: Asset Inventory & Continuous Scanning** - Targets become persistent Assets that can be scanned on a recurring schedule, not just one-shot submissions.
- [x] **Phase 2: API & CLI Access** - Security teams can manage assets and scans programmatically instead of only through the web UI.
- [x] **Phase 3: Compliance & Framework Reporting** - Findings are mapped to OWASP Top 10/ASVS categories for audit-usable reporting.
- [x] **Phase 4: Production Hardening & Reliability** - The platform holds up under real multi-worker production load with test coverage and visual consistency matching a "production ready" bar.

Full phase detail archived at `.planning/milestones/v1.0-ROADMAP.md`.

</details>

<details>
<summary>✅ v1.1 Production Audit, Hardening & Redesign (Phases 5-9) - SHIPPED 2026-08-20</summary>

- [x] **Phase 5: New Scan Flow Redesign** - `/scan/new` became a guided Select Domain → Select Type → Confirm Authorization → Start Scan flow instead of four disconnected single-form pages.
- [x] **Phase 6: Design System Consistency** - Every template draws from one canonical typography scale, spacing scale, component style set, and container-width convention.
- [x] **Phase 7: Responsive & Accessibility Compliance** - Every page renders correctly from 320px to desktop and is fully operable by keyboard/assistive technology.
- [x] **Phase 8: Security Re-Audit & Hardening** - Every ID-accepting route, form, redirect, and file-serving path across the app (including v1.0's new API/scheduler/admin surfaces) is verified to enforce its existing safety guarantees, with gaps closed.
- [x] **Phase 9: SEO, Performance & UX States** - Public pages are correctly indexable, list-heavy pages don't degrade at scale, and every page communicates loading/empty/error states clearly.

Full phase detail archived at `.planning/milestones/v1.1-ROADMAP.md`.

**Known gap at close:** Phases 5, 6, 7, and 9's `checkpoint:human-verify`/live-verification
gates were never answered by a human (explicit user instruction: proceed without blocking on
them). All underlying work is implemented and covered by automated tests/regression locks
(802 passing at milestone close) — the gap is specifically the live-browser/human-observation
confirmation step, not missing implementation. See `.planning/milestones/v1.1-REQUIREMENTS.md`
and `STATE.md`'s Deferred Items for detail.

</details>

### Phase 10: Live Verification Closeout

**Goal**: Every `checkpoint:human-verify` gate deferred at v1.1 close (phases 5, 6, 7, 9) is
actually run against the real Fly deployment, and any real defect it surfaces is fixed and
regression-locked.
**Depends on**: Phase 9 (v1.1, complete)
**Requirements**: VERIFY-01, VERIFY-02, VERIFY-03, VERIFY-04, VERIFY-05, VERIFY-06, VERIFY-07,
VERIFY-08, VERIFY-09
**Success Criteria** (what must be TRUE):

  1. A live four-width sweep (320/375/768/1280px) of every page against
     `https://webvulnscanner.fly.dev` is complete with a per-page pass/fail record, per
     07-07-PLAN.md's original checklist (RESP-01/02/03).

  2. The live scan-progress feed is re-confirmed against a real running scan at all four
     breakpoints (RESP-04).

  3. A keyboard-only walkthrough and a real contrast-checking tool both confirm A11Y-03/A11Y-04
     with recorded evidence, not just token math.

  4. The New Scan wizard (Phase 5) and Phase 9's UX states (empty/submitting/duplicate-scan/
     timeout) are each confirmed working end-to-end in a live browser against the real
     deployment.

  5. Every real defect found during the sweep is fixed and covered by a regression test/lock; the
     sweep result itself (pass/fail per page/check) is recorded as this phase's closing evidence.
**Plans**: 0/TBD plans executed

**UI hint**: yes (this phase is entirely visual/live verification — no new component work
expected, only fixes if defects are found)

**Status**: Deferred behind v1.3 per explicit user instruction (2026-08-20) — real, valid work,
not dropped. Pick up once v1.3's phases land.

### Phase 11: Glassbox Rebrand ✅ COMPLETE (2026-08-20)

**Goal**: The product is renamed from WebVulnScanner to Glassbox across every user-facing surface
and a new Fly app serves the same functionality, with the old app decommissioned only after the
new one is verified healthy.
**Depends on**: Phase 9 (v1.1, complete) — no dependency on the deferred Phase 10
**Requirements**: REBRAND-01, REBRAND-02, REBRAND-03, REBRAND-04, REBRAND-05
**Success Criteria** (what must be TRUE):

  1. No rendered page contains the literal string "WebVulnScanner" — every title, meta tag, nav
     brand, email, and error page shows "Glassbox". ✅
  2. `README.md`/`CLAUDE.md` reflect the new name; CLAUDE.md's frozen-surface and non-destructive
     constraints are unchanged in substance. ✅
  3. A new Fly app runs the same image with all 12 secrets migrated, and a real health/DB-
     connectivity check + smoke test succeeds against the new deployment before the old app is
     torn down. ✅
  4. The full test suite (802+ tests) still passes unmodified in substance — this is a naming
     change, not a behavior change. ✅ (802 passed)
**Plans**: Executed directly (lean, no PLAN.md subagent cascade — single mechanical rename +
migration task)

**Actual outcome**: `glassbox` itself was already taken globally on Fly (app names are global
across all accounts, not per-org) — deployed as **`glassboxsec.fly.dev`** instead, confirmed via
`flyctl apps create` before touching anything else. All 12 secrets migrated by reading them from
the live `webvulnscanner` machine's environment (`flyctl ssh console -C`) piped directly into
`flyctl secrets import` on the new app — values never displayed in any output, verified identical
via matching digests. New app deployed, confirmed healthy (`/healthz` DB connectivity, `/signup`
200, `/scan/new` correctly gating auth), old `webvulnscanner` app destroyed only after that
verification. `fly.toml` updated to target `glassboxsec`.

**UI hint**: yes (branding surfaces only — no layout/component changes)

### Phase 12: Finding Schema ✅ COMPLETE (2026-08-20)

**Goal**: Every `Finding` carries an honest `confidence` value (and, where applicable, `cwe`/
`verification_state`), kept conceptually separate from `severity`, so nothing is ever reported as
more certain than the evidence supports.
**Depends on**: Phase 11
**Requirements**: FSCH-01, FSCH-02, FSCH-03, FSCH-04, FSCH-05
**Success Criteria** (what must be TRUE):

  1. `Finding` has `confidence`/`cwe`/`verification_state` fields with `confidence` restricted to
     the 5 defined values. ✅
  2. Every existing `Finding(...)` call site in `checks.py` has an explicit, reasoned `confidence`
     value — a regression test fails if any call site is left on a default. ✅
  3. The scan report displays confidence (and CWE/OWASP where present) per finding using existing
     `.pill`/`.badge` components, with no new visual clutter. ✅
**Plans**: Executed directly (lean)

**Actual outcome**: All 53 real `Finding(...)` call sites individually categorized (not
bulk-defaulted) and backfilled via a paren-balanced source rewrite script. AST-based coverage
lock (`tests/test_finding_confidence.py`) proves every call site passes an explicit
`confidence=` from `CONFIDENCE_LEVELS`. `_serialize_findings()` already used `asdict(f)`, so the
new fields flowed into report JSON with zero serialization changes. `scan_report.html` renders
confidence/CWE via the existing `.pill.compliance` component (same one the OWASP pill already
used). 805 passed (1 pre-existing unrelated flaky test, confirmed).

**UI hint**: yes (report page finding-card additions only)

### Phase 13: Domain Grouping & Scoring v2 ✅ COMPLETE (2026-08-20)

**Goal**: Findings are organized into product-facing security domains instead of a flat list,
and the score/readiness verdict reflects confidence and control coverage, not just a severity
count — a user can see why the number is what it is.
**Depends on**: Phase 12 (scoring/grouping needs `confidence` to exist first)
**Requirements**: SCORE-01, SCORE-02, SCORE-03, SCORE-04, SCORE-05
**Success Criteria** (what must be TRUE):

  1. `SECURITY_DOMAIN_MAP` covers every check_name across all 4 orchestrators, same coverage-lock
     pattern as the existing `CHECK_COMPLIANCE`. ✅
  2. The scan report groups findings by domain. ✅
  3. The score visibly reflects confidence-weighting and coverage, not severity count alone, and
     a READY/READY WITH WARNINGS/NOT READY verdict is shown with a supporting breakdown. ✅
  4. Attack-surface findings show their `verification_state` in the UI. ✅
**Plans**: Executed directly (lean)

**Actual outcome**: 11 real finding-domains (not 13 - "Security Posture" and "Production
Readiness" turned out to be report-summary/verdict sections, not buckets any check's findings
belong to, so they were excluded from SECURITY_DOMAIN_MAP by design, documented in its own
comment). New "Domain" grouping mode added alongside the existing Severity/Compliance modes
(`group_findings_by_domain()`, exact same contract as `group_findings_by_compliance()`).
`_compute_readiness()` implemented as a companion function to `_score_report()` rather than a
change to it, to protect that function's 20+ existing tests and source-parsing regression lock -
same substance (confidence + coverage aware, never vulnerability-count-alone), zero regression
risk. Wired into all 4 orchestrators with per-scan-type coverage denominators. 826 passed.

**UI hint**: yes (report page restructure — the milestone's largest UI change; reuse existing
components per CLAUDE.md's frontend design system, no new component family)

### Phase 14: Net-New Checks ✅ COMPLETE (2026-08-20)

**Goal**: The check set is extended with the handful of genuinely missing pre-production checks
(file upload, security.txt, privacy/PII, caching, GraphQL) — additive, non-destructive, following
the existing check convention exactly.

**Actual outcome**: security.txt and GraphQL introspection already existed before this phase
(confirmed by inspection first) - not duplicated. Only 3 genuinely new checks built:
`check_file_upload`, `check_privacy_exposure`, `check_caching_sensitive_data`, all FREE-tier,
all registered across FEATURE_REQUIREMENTS/CHECK_COMPLIANCE/SECURITY_DOMAIN_MAP/CHECK_LABELS/
CHECK_CATEGORY/run_scan()'s jobs dict. 4 pre-existing tests with hardcoded FREE-tier job counts
needed updating (not bugs - registries that predated the 3 new checks). 839 passed.
**Depends on**: Phase 13 (new checks should land under the domain-grouping/scoring model, not be
retrofitted into it afterward)
**Requirements**: CHECK-01, CHECK-02, CHECK-03, CHECK-04, CHECK-05, CHECK-06
**Success Criteria** (what must be TRUE):

  1. Each new check returns `(data, findings)`, never raises past its own function, and is
     registered in `FEATURE_REQUIREMENTS`/`CHECK_COMPLIANCE`/`SECURITY_DOMAIN_MAP`.
  2. File-upload/security.txt/privacy/caching/GraphQL checks are each read-only — no payload
     uploaded, no destructive request sent to the target.
  3. A coverage-lock test proves no new check is missing from any of the three registries above.
**Plans**: 0/TBD plans executed

**UI hint**: no (findings render through the existing Phase 13 UI, no new page/component)

### Phase 15: Request Expert Assessment ✅ COMPLETE (2026-08-20)

**Goal**: A visible CTA lets a user request a deeper, human-led assessment; submissions are
captured with enough detail to scope real work and are visible to platform admins.
**Depends on**: Phase 13 (CTA placement assumes the redesigned report page exists)
**Requirements**: CTA-01, CTA-02, CTA-03, CTA-04
**Success Criteria** (what must be TRUE):

  1. "Request Expert Assessment" is visible on the report/dashboard using existing `.btn`/`.card`
     components.
  2. The form collects all 11 specified fields and creates an `AssessmentRequest` row.
  3. Platform admins can view submitted requests.
  4. The form is CSRF-protected and rate-limited like every other state-changing form in the app.
**Plans**: 1/1 plans executed (executed directly, no PLAN.md - matches Phases 11-14's lean
approach). Complete.

**UI hint**: yes (one new form page + one new admin list view, reusing `_admin_form_styles.html`/
existing admin-panel table patterns)

### Phase 16: Platform Admin User/Org Management ✅ COMPLETE (2026-08-21)

**Goal**: Platform admins can inspect a user's or org's detail (scans, plan, verified domains)
and suspend/remove a user or org from `/platform-admin`, with every action audit-logged - not
just the pending-domain-deletion/assessment-request queues that exist today.
**Depends on**: Phase 11 (admin_routes.py/platform_admin.html as they exist post-rebrand)
**Requirements**: ADMIN-01, ADMIN-02, ADMIN-03, ADMIN-04
**Success Criteria** (what must be TRUE):

  1. A platform admin can open a user detail view showing their org, role, plan, and scan history.
  2. A platform admin can suspend a user (blocks login; distinct from deletion) and reverse it,
     each requiring a confirmation step (this is an irreversible-adjacent action per the app's
     own safety conventions).
  3. A platform admin can suspend an org, cascading the same block to its members.
  4. Every suspend/unsuspend action writes a `PlatformAuditEvent` row so there's a who/what/when
     trail, same convention as domain-deletion approve/reject already uses.
**Plans**: 1/1 plans executed (executed directly, no PLAN.md - matches Phases 11-15's lean
approach). Complete. Hard delete of a user/org was scoped out during implementation (see
REQUIREMENTS.md's ADMIN-03 note) - a real, valid future requirement, not dropped.

**UI hint**: yes (new user/org detail pages + destructive-action confirmation flows on
`/platform-admin`)

### Phase 17: Expanded Check Coverage ✅ COMPLETE (2026-08-23)

**Goal**: Each existing check category (injection, headers, auth, exposure) gets meaningfully
more payload/variant coverage within the existing non-destructive/same-origin/depth-1 safety
constraints; the deeper-crawl question is answered explicitly (loosen or keep) rather than left
implicit.
**Depends on**: Phase 14 (Net-New Checks, same `(data, findings)`/registry conventions)
**Requirements**: DEPTH-01, DEPTH-02, DEPTH-03
**Success Criteria** (what must be TRUE):

  1. A written decision exists on same-origin depth-1 crawl vs. a deeper/multi-page crawl,
     signed off explicitly (this changes the app's safety posture, not a default to flip quietly).
  2. At least the injection-class checks (XSS/SQLi) gain additional payload variants without
     violating existing safety constraints (no destructive payloads, same caps).
  3. Coverage additions are registered in `FEATURE_REQUIREMENTS`/`CHECK_LABELS`/`CHECK_CATEGORY`
     per the existing convention, with regression-lock tests proving the registries stay in sync.
**Plans**: Complete - user signed off "A AND B" on the crawl-depth question
(.planning/PHASE17-DEPTH-DECISION.md): reflected XSS went from 1 to 4 marker-only shapes
(`REFLECTED_XSS_VARIANTS`), boolean-blind SQLi now picks quote-context vs numeric-context
pairs by param value, SQL_ERROR_SIGNATURES grew to 14, and an approved capped depth-2 crawl
(`crawl_depth2_param_urls`, MAX_CRAWL_PAGES=15, same-origin/robots-honored, merged BEHIND
hop-1 so the limit=10 probe list is unchanged) runs only for org-verified domains. Budget lock:
MAX_PROBE_REQUESTS_PER_URL=12 enforced by source-arithmetic regression tests
(tests/test_phase17_coverage.py, 20 tests).

**UI hint**: no (findings render through the existing report UI)

### Phase 18: CLI Client ✅ COMPLETE (2026-08-23)

**Goal**: A standalone `glassbox` command-line client authenticates via the existing API-token
system and lets a security practitioner launch scans, poll status, and pull reports from a
terminal, without adding any new server-side execution surface.
**Depends on**: Phase 2 (v1.0's API & CLI Access - the API-token auth this CLI authenticates
against already exists)
**Requirements**: CLI-01, CLI-02, CLI-03
**Success Criteria** (what must be TRUE):

  1. The CLI authenticates with an existing API token (no new auth mechanism, no credentials
     entered anywhere but the token itself). ✅
  2. It can launch a scan, poll status, and fetch a finished report's JSON/CSV via the existing
     API routes - no new server endpoints required for the MVP. ✅
  3. It ships as a separate installable package/script, not embedded in the web app - explicitly
     ruled out an in-browser terminal (a much larger, harder-to-secure attack surface) per this
     phase's scoping conversation. ✅

**Plans**: Built across f27fbb4 (wip), b87c15d (security gate + `glassbox gate`), and the
2026-08-23 close-out commit (`/api/v1/scans/<id>/report.csv` token-authed CSV export +
`glassbox report --csv` + `cli/pyproject.toml` packaging).

**Actual outcome**: The CLI grew well past its MVP shape during Phase 18's life - beyond
launch/poll/report it ships check/assess/readiness/gate/findings/verify/compare/assets plus a
server-side gate endpoint shared with direct HTTP consumers. One deliberate deviation from the
original "no new server endpoints" wording: the close-out added GET /api/v1/scans/<id>/report.csv,
a read-only alternate rendering of an already-authorized report through scan_routes'
single shared `findings_csv_document()` writer (same bytes as the web UI's export.csv download),
plus `cli/pyproject.toml` so `pip install ./cli` provides a real `glassbox` console script.
Both deviations serve the criterion's intent (JSON **and** CSV fetch; separate installable
package) and are documented here rather than silently shipped.

**UI hint**: no (separate CLI package, no web UI)

### Phase 19: Webhooks & Slack Notifications ✅ COMPLETE (2026-08-23)

**Goal**: When a scan completes, Glassbox pushes a signed JSON notification to every webhook
registered in the scan's scope (org webhooks for the org's scans, solo users' personal webhooks
for their own scans) - closing the continuous-validation loop: scheduled scans already fire on a
cadence, but until now nothing announced their results to where a team actually watches (a Slack
channel via an incoming webhook, or any generic HTTP receiver).
**Depends on**: Phase 1 (Scan lifecycle + `_run_scan_in_background` shared tail), Phase 2
(API-token-era auth conventions), Phase 16 (org/solo dual-scope pattern from Assets)
**Requirements**: WEBH-01..WEBH-07 (see REQUIREMENTS.md)
**Success Criteria** (what must be TRUE):

  1. A completed scan triggers delivery to every matching ACTIVE webhook - org scope matches
     `scan.org_id`, solo scope matches creator only (NULL-org equality never cross-matches). ✅
  2. Deliveries are HMAC-SHA256-signed (`X-Glassbox-Signature: sha256=...`) with a per-webhook
     secret shown exactly once at creation; receiver URLs are validated HTTPS + SSRF-safe at
     creation time via the same `is_ssrf_safe_hostname` gate scan targets use. ✅
  3. One payload serves Slack AND generic receivers (`text` line first-class + structured
     event/scan/gate/top_findings); the gate verdict comes from the same single-source
     `evaluate_gate()` the API endpoint and CLI use. ✅
  4. Delivery failures never break a finished scan and never raise past the fan-out; each
     attempt is recorded in a WebhookDelivery row visible per-webhook (recent deliveries page),
     including owner-triggered test pings (scan_id NULL). ✅
  5. Management UI (/webhooks) enforces server-side scoping: org webhooks manageable by that
     org's ORG_ADMIN only, solo webhooks by their creator; all four id-accepting routes are
     registered in the IDOR registry with denial tests. ✅

**Plans**: Direct execution, single commit.

**UI hint**: yes (/webhooks management page + per-webhook deliveries page + nav link)

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Asset Inventory & Continuous Scanning | v1.0 | 2/2 | Complete | 2026-08-11 |
| 2. API & CLI Access | v1.0 | 3/3 | Complete | 2026-08-11 |
| 3. Compliance & Framework Reporting | v1.0 | 3/3 | Complete | 2026-08-11 |
| 4. Production Hardening & Reliability | v1.0 | 5/5 | Complete | 2026-08-13 |
| 5. New Scan Flow Redesign | v1.1 | 3/3 | Complete | 2026-08-20 |
| 6. Design System Consistency | v1.1 | 4/4 | Complete | 2026-08-20 |
| 7. Responsive & Accessibility Compliance | v1.1 | 7/7 | Complete | 2026-08-20 |
| 8. Security Re-Audit & Hardening | v1.1 | 7/7 | Complete | 2026-08-19 |
| 9. SEO, Performance & UX States | v1.1 | 4/4 | Complete | 2026-08-20 |
| 10. Live Verification Closeout | v1.2 | 0/TBD | In progress | - |
| 11. Glassbox Rebrand | v1.3 | Direct execution | Complete | 2026-08-20 |
| 12. Finding Schema | v1.3 | Direct execution | Complete | 2026-08-20 |
| 13. Domain Grouping & Scoring v2 | v1.3 | Direct execution | Complete | 2026-08-20 |
| 14. Net-New Checks | v1.3 | Direct execution | Complete | 2026-08-20 |
| 15. Request Expert Assessment | v1.3 | Direct execution | Complete | 2026-08-20 |
| 16. Platform Admin User/Org Management | v1.4 | Direct execution | Complete | 2026-08-21 |
| 17. Expanded Check Coverage | v1.4 | 0/TBD | Not started | - |
| 18. CLI Client | v1.4 | Direct execution | Complete | 2026-08-23 |
| 19. Webhooks & Slack Notifications | v1.4 | Direct execution | Complete | 2026-08-23 |
