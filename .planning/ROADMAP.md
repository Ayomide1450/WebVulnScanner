# Roadmap: Glassbox

## Milestones

- âœ… **v1.0 Asset Inventory, API/CLI, Compliance & Hardening** - Phases 1-4 (shipped 2026-08-13)
- âœ… **v1.1 Production Audit, Hardening & Redesign** - Phases 5-9 (shipped 2026-08-20)
- â¸ï¸ **v1.2 Live Verification Closeout** - Phase 10 (deferred, not dropped - reprioritized behind v1.3)
- âœ… **v1.3 Glassbox Rebrand & Production Security Readiness** - Phases 11-15 (shipped 2026-08-20)
- ðŸš§ **v1.4 Admin Controls, Check Depth & CLI Client** - Phases 16-19 (shipped 2026-08-23)
- **v1.5 Detection Depth & Built-in Self-Test** - Phases 20-21 (shipped 2026-08-23)
- **v1.6 Platform Surface & Enterprise Readiness** - Phases 22-26 (planned)
- **v1.7 World-Class Platform Foundations** - Phases 27-30 (planned, scoped 2026-08-24)
- **v1.8 Scoring, Dedup & Coverage Gaps** - Phases 31-34 (scoped 2026-08-26)

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order. Phase numbering is
continuous across milestones.

<details>
<summary>âœ… v1.0 Asset Inventory, API/CLI, Compliance & Hardening (Phases 1-4) - SHIPPED 2026-08-13</summary>

- [x] **Phase 1: Asset Inventory & Continuous Scanning** - Targets become persistent Assets that can be scanned on a recurring schedule, not just one-shot submissions.
- [x] **Phase 2: API & CLI Access** - Security teams can manage assets and scans programmatically instead of only through the web UI.
- [x] **Phase 3: Compliance & Framework Reporting** - Findings are mapped to OWASP Top 10/ASVS categories for audit-usable reporting.
- [x] **Phase 4: Production Hardening & Reliability** - The platform holds up under real multi-worker production load with test coverage and visual consistency matching a "production ready" bar.

Full phase detail archived at `.planning/milestones/v1.0-ROADMAP.md`.

</details>

<details>
<summary>âœ… v1.1 Production Audit, Hardening & Redesign (Phases 5-9) - SHIPPED 2026-08-20</summary>

- [x] **Phase 5: New Scan Flow Redesign** - `/scan/new` became a guided Select Domain â†’ Select Type â†’ Confirm Authorization â†’ Start Scan flow instead of four disconnected single-form pages.
- [x] **Phase 6: Design System Consistency** - Every template draws from one canonical typography scale, spacing scale, component style set, and container-width convention.
- [x] **Phase 7: Responsive & Accessibility Compliance** - Every page renders correctly from 320px to desktop and is fully operable by keyboard/assistive technology.
- [x] **Phase 8: Security Re-Audit & Hardening** - Every ID-accepting route, form, redirect, and file-serving path across the app (including v1.0's new API/scheduler/admin surfaces) is verified to enforce its existing safety guarantees, with gaps closed.
- [x] **Phase 9: SEO, Performance & UX States** - Public pages are correctly indexable, list-heavy pages don't degrade at scale, and every page communicates loading/empty/error states clearly.

Full phase detail archived at `.planning/milestones/v1.1-ROADMAP.md`.

**Known gap at close:** Phases 5, 6, 7, and 9's `checkpoint:human-verify`/live-verification
gates were never answered by a human (explicit user instruction: proceed without blocking on
them). All underlying work is implemented and covered by automated tests/regression locks
(802 passing at milestone close) â€” the gap is specifically the live-browser/human-observation
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
     `https://glassbox.fly.dev` is complete with a per-page pass/fail record, per
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

**UI hint**: yes (this phase is entirely visual/live verification â€” no new component work
expected, only fixes if defects are found)

**Status**: Deferred behind v1.3 per explicit user instruction (2026-08-20) â€” real, valid work,
not dropped. Pick up once v1.3's phases land.

### Phase 11: Glassbox Rebrand âœ… COMPLETE (2026-08-20)

**Goal**: The product is renamed from Glassbox to Glassbox across every user-facing surface
and a new Fly app serves the same functionality, with the old app decommissioned only after the
new one is verified healthy.
**Depends on**: Phase 9 (v1.1, complete) â€” no dependency on the deferred Phase 10
**Requirements**: REBRAND-01, REBRAND-02, REBRAND-03, REBRAND-04, REBRAND-05
**Success Criteria** (what must be TRUE):

  1. No rendered page contains the literal string "Glassbox" â€” every title, meta tag, nav
     brand, email, and error page shows "Glassbox". âœ…
  2. `README.md`/`CLAUDE.md` reflect the new name; CLAUDE.md's frozen-surface and non-destructive
     constraints are unchanged in substance. âœ…
  3. A new Fly app runs the same image with all 12 secrets migrated, and a real health/DB-
     connectivity check + smoke test succeeds against the new deployment before the old app is
     torn down. âœ…
  4. The full test suite (802+ tests) still passes unmodified in substance â€” this is a naming
     change, not a behavior change. âœ… (802 passed)
**Plans**: Executed directly (lean, no PLAN.md subagent cascade â€” single mechanical rename +
migration task)

**Actual outcome**: `glassbox` itself was already taken globally on Fly (app names are global
across all accounts, not per-org) â€” deployed as **`glassboxsec.fly.dev`** instead, confirmed via
`flyctl apps create` before touching anything else. All 12 secrets migrated by reading them from
the live `glassbox` machine's environment (`flyctl ssh console -C`) piped directly into
`flyctl secrets import` on the new app â€” values never displayed in any output, verified identical
via matching digests. New app deployed, confirmed healthy (`/healthz` DB connectivity, `/signup`
200, `/scan/new` correctly gating auth), old `glassbox` app destroyed only after that
verification. `fly.toml` updated to target `glassboxsec`.

**UI hint**: yes (branding surfaces only â€” no layout/component changes)

### Phase 12: Finding Schema âœ… COMPLETE (2026-08-20)

**Goal**: Every `Finding` carries an honest `confidence` value (and, where applicable, `cwe`/
`verification_state`), kept conceptually separate from `severity`, so nothing is ever reported as
more certain than the evidence supports.
**Depends on**: Phase 11
**Requirements**: FSCH-01, FSCH-02, FSCH-03, FSCH-04, FSCH-05
**Success Criteria** (what must be TRUE):

  1. `Finding` has `confidence`/`cwe`/`verification_state` fields with `confidence` restricted to
     the 5 defined values. âœ…
  2. Every existing `Finding(...)` call site in `checks.py` has an explicit, reasoned `confidence`
     value â€” a regression test fails if any call site is left on a default. âœ…
  3. The scan report displays confidence (and CWE/OWASP where present) per finding using existing
     `.pill`/`.badge` components, with no new visual clutter. âœ…
**Plans**: Executed directly (lean)

**Actual outcome**: All 53 real `Finding(...)` call sites individually categorized (not
bulk-defaulted) and backfilled via a paren-balanced source rewrite script. AST-based coverage
lock (`tests/test_finding_confidence.py`) proves every call site passes an explicit
`confidence=` from `CONFIDENCE_LEVELS`. `_serialize_findings()` already used `asdict(f)`, so the
new fields flowed into report JSON with zero serialization changes. `scan_report.html` renders
confidence/CWE via the existing `.pill.compliance` component (same one the OWASP pill already
used). 805 passed (1 pre-existing unrelated flaky test, confirmed).

**UI hint**: yes (report page finding-card additions only)

### Phase 13: Domain Grouping & Scoring v2 âœ… COMPLETE (2026-08-20)

**Goal**: Findings are organized into product-facing security domains instead of a flat list,
and the score/readiness verdict reflects confidence and control coverage, not just a severity
count â€” a user can see why the number is what it is.
**Depends on**: Phase 12 (scoring/grouping needs `confidence` to exist first)
**Requirements**: SCORE-01, SCORE-02, SCORE-03, SCORE-04, SCORE-05
**Success Criteria** (what must be TRUE):

  1. `SECURITY_DOMAIN_MAP` covers every check_name across all 4 orchestrators, same coverage-lock
     pattern as the existing `CHECK_COMPLIANCE`. âœ…
  2. The scan report groups findings by domain. âœ…
  3. The score visibly reflects confidence-weighting and coverage, not severity count alone, and
     a READY/READY WITH WARNINGS/NOT READY verdict is shown with a supporting breakdown. âœ…
  4. Attack-surface findings show their `verification_state` in the UI. âœ…
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

**UI hint**: yes (report page restructure â€” the milestone's largest UI change; reuse existing
components per CLAUDE.md's frontend design system, no new component family)

### Phase 14: Net-New Checks âœ… COMPLETE (2026-08-20)

**Goal**: The check set is extended with the handful of genuinely missing pre-production checks
(file upload, security.txt, privacy/PII, caching, GraphQL) â€” additive, non-destructive, following
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
  2. File-upload/security.txt/privacy/caching/GraphQL checks are each read-only â€” no payload
     uploaded, no destructive request sent to the target.
  3. A coverage-lock test proves no new check is missing from any of the three registries above.
**Plans**: 0/TBD plans executed

**UI hint**: no (findings render through the existing Phase 13 UI, no new page/component)

### Phase 15: Request Expert Assessment âœ… COMPLETE (2026-08-20)

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

### Phase 16: Platform Admin User/Org Management âœ… COMPLETE (2026-08-21)

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

### Phase 17: Expanded Check Coverage âœ… COMPLETE (2026-08-23)

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

### Phase 18: CLI Client âœ… COMPLETE (2026-08-23)

**Goal**: A standalone `glassbox` command-line client authenticates via the existing API-token
system and lets a security practitioner launch scans, poll status, and pull reports from a
terminal, without adding any new server-side execution surface.
**Depends on**: Phase 2 (v1.0's API & CLI Access - the API-token auth this CLI authenticates
against already exists)
**Requirements**: CLI-01, CLI-02, CLI-03
**Success Criteria** (what must be TRUE):

  1. The CLI authenticates with an existing API token (no new auth mechanism, no credentials
     entered anywhere but the token itself). âœ…
  2. It can launch a scan, poll status, and fetch a finished report's JSON/CSV via the existing
     API routes - no new server endpoints required for the MVP. âœ…
  3. It ships as a separate installable package/script, not embedded in the web app - explicitly
     ruled out an in-browser terminal (a much larger, harder-to-secure attack surface) per this
     phase's scoping conversation. âœ…

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

### Phase 19: Webhooks & Slack Notifications âœ… COMPLETE (2026-08-23)

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
     `scan.org_id`, solo scope matches creator only (NULL-org equality never cross-matches). âœ…
  2. Deliveries are HMAC-SHA256-signed (`X-Glassbox-Signature: sha256=...`) with a per-webhook
     secret shown exactly once at creation; receiver URLs are validated HTTPS + SSRF-safe at
     creation time via the same `is_ssrf_safe_hostname` gate scan targets use. âœ…
  3. One payload serves Slack AND generic receivers (`text` line first-class + structured
     event/scan/gate/top_findings); the gate verdict comes from the same single-source
     `evaluate_gate()` the API endpoint and CLI use. âœ…
  4. Delivery failures never break a finished scan and never raise past the fan-out; each
     attempt is recorded in a WebhookDelivery row visible per-webhook (recent deliveries page),
     including owner-triggered test pings (scan_id NULL). âœ…
  5. Management UI (/webhooks) enforces server-side scoping: org webhooks manageable by that
     org's ORG_ADMIN only, solo webhooks by their creator; all four id-accepting routes are
     registered in the IDOR registry with denial tests. âœ…

**Plans**: Direct execution, single commit.

**UI hint**: yes (/webhooks management page + per-webhook deliveries page + nav link)

### Phase 20: Intrusive Coverage Expansion

**Goal**: Give security engineers ten new intrusive-but-non-destructive check families across
the base pipeline, chosen from the Group-1 "pure-Python wins" review - each one a single
concept a practitioner would bill for, all inside the existing authorization model
(tier-gated, org-verified where probing gets deliberate, hard-capped request budgets,
marker-only proofs).
**Depends on**: Phase 14/17 check conventions (`(data, findings)`, registry sync locks,
MAX_ constants), Phase 12 finding schema
**Requirements**: INTR-01..INTR-10 (see REQUIREMENTS.md)
**Success Criteria** (what must be TRUE):

  1. Ten new checks exist, one per INTR requirement, each following the house convention:
     `(data, findings)` return shape, `requests.RequestException` never escapes the function,
     every network loop bounded by a named `MAX_*` constant.
  2. Every new check is registered in `FEATURE_REQUIREMENTS`, `CHECK_LABELS`, and
     `CHECK_CATEGORY`; the existing regression tests proving those three stay in sync with
     `run_scan()`'s jobs dict pass unchanged.
  3. Tier mapping is deliberate and documented: PAID gets single-request reflection probes
     (SSTI, host-header, cache deception, CRLF, CSRF posture, subdomain takeover DNS);
     ORG_VERIFIED gets everything that sends deliberate multi-request bursts or active
     forgeries (path traversal, rate-limit burst, active JWT `alg:none`, GraphQL arg canary).
  4. No destructive payloads anywhere: traversal reads marker files only; rate-limit burst is
     capped at ~15 requests and stops at first 429; JWT forgery only ever hits endpoints the
     operator's own session already legally reaches; GraphQL stays read-only queries.
  5. Regression locks cover: per-check request-budget arithmetic, tier gating matrix, and
      label/category registry sync (tests/test_phase20_checks.py).
   6. Findings render in scan_report.html's detailed-check-output section and the live feed
      via CHECK_LABELS without template surgery beyond data-driven sections.

### Phase 21: Built-in Detection Self-Test

**Goal**: One-click proof that Glassbox's detection logic actually fires. An ephemeral,
loopback-only lure server hosting five planted flaws (SSTI, path traversal, JWT alg:none
acceptance, open GraphQL introspection, token-less POST form) is started inside the app
process; the ten Phase-20 checks run against it with the real crawl machinery; results are
compared against a known-good expectations matrix (five positives that MUST fire, five
negatives that MUST stay silent) and rendered as a pass/fail table at /selftest.
**Depends on**: Phase 20 checks + conventions
**Requirements**: ST-01..ST-06 (see REQUIREMENTS.md)
**Success Criteria**:

   1. `glassbox/selftest.py` starts a ThreadingHTTPServer bound to 127.0.0.1 on an
      ephemeral port; nothing binds to a wildcard or external interface.
   2. `run_selftest()` executes all ten checks in-process using the real crawler
      (`crawl_same_origin`) and returns `{passed, duration_ms, results[]}` where every row
      matches its expectation: ssti/path_traversal/jwt_active critical, graphql_deep medium,
      csrf_posture any finding; host_header/crlf/rate_limit/cache_deception/subdomain_takeover
      silent. The whole run completes in seconds and is deterministic across repeated runs
      (per-instance listener state, never module-level).
   3. No Scan row, no Report file, no external network traffic; the SSRF guard is untouched -
      no user-supplied URL participates anywhere.
   4. POST /selftest (login required, rate-limited 30/hour, CSRF-protected form) runs the
      matrix synchronously; GET renders the launcher page; results table reuses base.html
      design tokens (.card/.pill/.status-pill/.table-scroll), dashboard gains a
      "Detection Self-Test" button.
   5. tests/test_selftest.py locks the full matrix end-to-end over real HTTP, loopback-only
      binding, port release after teardown, route auth, and the no-scan-row contract.
   6. Traversal ground truth uses a decoy passwd served when the probe escapes the sandbox,
      so the matrix verifies identically on Windows dev, Linux CI, and containers.


**Plans**: Direct execution, single commit.

**UI hint**: no (findings render through the existing report UI)

### Phase 22: In-Product API Documentation

**Goal**: Every `/api/v1` endpoint, the token-auth scheme, error semantics, the `glassbox`
CLI quickstart, and webhook signature verification become discoverable in-product at
/docs/api — closing the "developer-facing API docs page" gap from the 2026-08-22 audit.
Security engineers and DevOps should not need to read source to integrate; this is the
capstone of the API/CLI surface Phases 2/18/19 built.
**Depends on**: nothing new (documents already-shipped surface)
**Requirements**: DOCS-01..DOCS-05 (see REQUIREMENTS.md)
**Success Criteria** (what must be TRUE):

   1. Single-source generation: the page renders from one server-side spec structure, not
      hand-duplicated HTML per route; a url_map-enumeration regression test fails naming any
      /api/v1 rule missing from the spec — same self-maintaining discipline as the IDOR
      registry test.
   2. Each endpoint documents method, path, required auth (session/token/public), rate limit,
      and request+response examples drawn from real fixtures used in tests.
   3. Webhook section carries a copy-pasteable HMAC-SHA256 verification snippet that a test
      proves matches `webhooks.sign_payload`'s algorithm exactly (docs can't silently drift).
   4. CLI section mirrors cli/README.md essentials (install, init, gate exit codes); a test
      keeps the section's command list in sync with the README's.
   5. Login-gated page reusing base.html tokens and the dual-markup responsive contract;
      nav link placed after API Tokens.

**Plans**: Direct execution, single commit.

**UI hint**: yes (/docs/api page + nav link)

### Phase 23: Audit Log

**Goal**: An append-only who-did-what trail for security-sensitive actions — org membership
changes, domain verification lifecycle, webhook/API-token lifecycle, billing activations,
platform-admin actions. Closes audit gap #4, gives ORG_ADMINs evidence for their own
compliance story, and gives every later feature (SSO included) a standard place to log.
**Depends on**: house conventions only (Alembic migration path, IDOR registry)
**Requirements**: AUDIT-01..AUDIT-05 (see REQUIREMENTS.md)
**Success Criteria**:

   1. `AuditEvent` model + Alembic migration; append-only in practice — no update/delete
      routes exist, proven by a test asserting their absence.
   2. Emission sites cover the enumerated mutation set (invite send/revoke/redeem, role or
      join changes, domain add/verify/request-deletion, token create/revoke, webhook
      create/toggle/delete/test, invoice verify / plan activate, platform-admin actions);
      a registry-driven test fails if a listed route stops emitting.
   3. ORG_ADMIN sees own-org events paginated at /org/audit; platform admins see all orgs;
      everyone else gets 404-not-403 with IDOR REGISTRY entries.
   4. Retention strategy decided and documented at build time (per-org trim on insert vs.
      cleanup command), bounded by a named constant either way.
   5. Events render actor/action/target/timestamp/detail in dual markup.

**Status**: Complete — `test_audit_log.py` (12 tests), `audit.py` consolidated from
`org_routes._log_org_event` / `admin_routes._log_platform_event`, emission sites
wired in api_tokens/webhooks/billing, `audit_log.html` paginated template, IDOR
registry entry with `test_audit_log_cross_org_is_404`, retention trim-on-insert
proven by `test_trim_on_insert_when_exceeding_limit`. Also fixed Phase 24 gap:
`api_docs.py` now documents `/api/v1/scans/<int:scan_id>/report.pdf`.

**Plans**: Direct execution, single commit.

**UI hint**: yes (/org/audit page)

### Phase 24: Report PDF Export

**Goal**: A finished scan exports as a professional PDF alongside JSON, CSV, and SARIF — the
deliverable non-engineer stakeholders attach to tickets and exec summaries. Closes audit
gap #2 and completes the "professional output" positioning.
**Depends on**: Phase 12 finding schema (confidence/CWE columns exist to render)
**Requirements**: PDFX-01..PDFX-08 (see REQUIREMENTS.md)
**Success Criteria**:

   1. GET /scan/<id>/report.pdf (session-authed) plus a token-authed /api/v1 twin, both
      behind the same ownership guard as report.csv, registered in the IDOR REGISTRY.
   2. WeasyPrint chosen as the rendering dependency (>=68,<70 — v68 minimum for SSRF fix
      CVE-2025-68616 + `allowed_protocols` parameter). Alpine runtime deps: pango, harfbuzz,
      harfbuzz-subset, fontconfig, font-noto (for non-ASCII/CJK text). Image size delta
      ~20MB. Decision and deps recorded in phase notes.
   3. Content sourced from the SAME report dict `save_report()` writes — score/grade,
      severity tally, per-check tables including confidence/CWE where present, AI summary
      when present; no parallel formatting logic over raw findings. Template renders ONLY
      `report["findings"]` — never `report["sensitive_paths"]` or other raw check data
      blobs (which may contain unredacted fragments per the `check_sensitive_paths` data
      flow analysis).
   4. Output validates as a parseable PDF (magic bytes + pypdf round-trip) containing the
      key report strings. Semantic equivalence test (text extraction comparison), NOT
      byte-identical comparison — WeasyPrint output varies across platforms/versions even
      with `SOURCE_DATE_EPOCH=0`. Determinism within the same version is a bonus, not a
      contract.
   5. Redaction invariant holds end-to-end: `_redact_secret`-ed values appear redacted in
      the PDF too — the export must not become a second leak of any credential. Dedicated
      test creates a report dict with a raw secret pattern and asserts the extracted PDF
      text contains only the redacted form.
   6. SSRF protection: WeasyPrint configured with `url_fetcher=URLFetcher(allowed_protocols=[])`
      to block all external resource loading (images, fonts, stylesheets from untrusted
      URLs). `presentational_hints=False` to prevent attribute-value CSS leakage
      (GHSA-jhhc-3hcp-qhm5). Finding detail text is Jinja2-autoescaped (never `| safe`).
   7. Filename sanitization: shared `safe_filename()` helper using allowlist
      `[A-Za-z0-9._-]` applied to all three exporters (CSV, SARIF, PDF) — retroactive
      hardening of the existing CSV/SARIF filename pattern.
   8. CJK smoke test: a finding with Japanese/Chinese characters renders correctly in the
      PDF (text extraction contains the original characters, not replacement boxes) —
      validates that font-noto is installed in the deploy image.

**Plans**: Direct execution, single commit.

**UI hint**: yes (download link on scan-report page, alongside existing CSV/SARIF export links)

### Phase 25: Pipeline Integrations (GitHub Actions / SIEM)

**Goal**: Move beyond generic webhooks to pipeline-native consumption: NDJSON findings
export for SIEM ingestion, a Splunk-HEC-compatible webhook payload preset, bounded delivery
retry, and a verified GitHub Actions gate recipe. Builds on Phase 19's signed-delivery
machinery rather than adding a second notification path.
**Depends on**: Phase 19 webhooks; benefits from Phase 23 audit events
**Requirements**: INTG-01..INTG-04 (see REQUIREMENTS.md)
**Success Criteria**:

   1. GET /api/v1/scans/<id>/findings.ndjson — one finding per line, token-authed, same
      ownership guard, NDJSON shape validated line-by-line in tests.
   2. Per-webhook payload_format option gains `splunk_hec` (event-keyed body Splunk HEC
      accepts); slack/generic behavior byte-unchanged — existing payload tests pass
      unmodified.
   3. Failed deliveries gain bounded retry with backoff recorded as additional
      WebhookDelivery attempts (attempt cap is a named MAX_* constant; retry never delays
      `_run_scan_in_background`'s tail).
   4. ~~A GitHub Actions recipe~~ **DEFERRED** (INTG-04) — user confirmed GitHub Actions
      cannot be used for now; deferred to a future phase.

**Plans**: Direct execution, single commit.

**UI hint**: yes (webhook form format selector; Phase 22 docs additions)

### Phase 26: SSO / SAML

**Goal**: Org-level SAML 2.0 single-sign-on — removing the last enterprise blocker from the
audit gaps list. The milestone's biggest lift, deliberately last, and gated by a feasibility
spike BEFORE the full build: whether xmlsec-class dependencies live cleanly inside the Fly
image decides go/no-go, with an explicit NO-GO escape hatch that records findings instead of
shipping a half-build.
**Depends on**: Phase 23 (SSO config changes and logins emit audit events)
**Requirements**: SSO-01..SSO-05 (see REQUIREMENTS.md)
**Success Criteria**:

   1. ✅ Spike-first: IdP-metadata parse + response signature validation proven inside the
      deploy image before feature work starts; NO-GO is an acceptable outcome recorded in
      .planning/.
   2. ✅ SP-initiated SAML login per configured org; JIT provisioning binds the asserted
      email's domain to THAT org's verified domains — mismatch refuses with an
      anti-enumeration-neutral error.
   3. ✅ Local password auth stays available unless the org explicitly disables it; disabling
      it is itself an audited event requiring fresh confirmation.
   4. ✅ All SSO config changes and SSO logins emit Phase-23 AuditEvents; IdP metadata/cert
      secrets stored encrypted at rest (app-level Fernet keyed off SECRET_KEY or equivalent,
      decision recorded).
   5. ✅ Outbound metadata/ACS fetches get SSRF-guard scrutiny equivalent to scan targets;
      cross-org config access is 404-not-403 with IDOR REGISTRY entries.

**SSO-01 Spike Result (GO)**:
- `python3-saml>=1.16,<2` installs cleanly on Windows (prebuilt `xmlsec` wheel) and in the
  Docker image (requires `libxmlsec1-dev`, `libxmlsec1-openssl`, `pkg-config` system deps —
  already added to Dockerfile).
- IdP metadata XML parsed by `OneLogin_Saml2_Settings` ✓
- SP config dict accepted ✓
- `OneLogin_Saml2_Utils.add_sign()` produces a signed Response; NameID extraction works ✓
- Tampered signature → rejected ✓
- No signature → rejected ✓
- Wrong audience → rejected (strict mode) ✓
- Finding: `strict=True` causes a subtle lxml namespace interaction during SubjectConfirmation
  validation when using `add_sign()` with manually-constructed XML trees.  Does NOT affect
  production `OneLogin_Saml2_Auth` flow.  Spike tests use `strict=False` for the happy path.
- `get_nameid()` is the current API (not `get_name_id()`).

**Plans**: Direct execution (spike committed as `test_sso_spike.py`).

**UI hint**: yes (org-admin SSO config panel; login-page "Sign in with SSO")

### Phase 21.1: Detection-Verification UX Fold-In (INSERTED)

**Goal**: Fix a real UX defect caught during live staging verification (2026-08-24, browser
walkthrough): `/selftest` shipped as its own top-level nav item next to "New Scan," presenting
raw dev-tool language ("loopback-only lure server," "planted flaws," "ground truth") and a bare
Check/Ground-truth/Detected/Verdict table to end users who have no reason to know what any of
that means. Reframes detection verification as a quiet trust signal riding on the real scan a
user already ran, instead of a standalone page they have to seek out and interpret alone.
**Depends on**: Phase 21 (selftest.py engine, unchanged)
**Requirements**: none new — UX-only rework of ST-04/ST-05's surface, tracked inline here since
it was caught post-hoc rather than planned
**Success Criteria**:

   1. `/selftest` route, its nav link, and its dashboard button are removed; no dead links.
   2. `run_scan()` calls the self-test engine once (cached per worker process, never
      per-scan-request) and attaches a `detection_verified` summary to the report dict.
   3. `scan_report.html` renders a small pill near the score — "Engine verified · N/10
      detections confirmed" — with a tooltip/caption making explicit it was checked against
      Glassbox's own internal target, never the user's site (avoids implying their site was
      re-scanned twice).
   4. A verification failure degrades to an absent badge, never a failed or delayed real scan.
   5. `tests/test_selftest.py` updated to assert the new integration; no standalone-page tests
      remain testing dead routes.

**Plans**: Direct execution, single commit.

**UI hint**: yes (scan_report.html badge; dashboard button removed)

### Phase 27: Continuous Regression Tracking

**Goal**: Turn Phase 1's existing Asset/scheduler foundation from "reruns the same checks on a
timer" into "tells you what changed" — new/resolved/recurring findings surfaced automatically
between two scheduled runs of the same Asset, with an optional webhook/email alert when a
regression appears. This is the single highest-leverage gap identified in the 2026-08-24
strategic review: a team adopts a continuous tool for the diff, not the raw re-scan.
**Depends on**: Phase 1 (Asset model + scheduler), Phase 19 (webhooks, for regression alerts)
**Requirements**: CONT-01..CONT-04 (see REQUIREMENTS.md)
**Success Criteria**:

   1. Each scheduled fire diffs its findings against the Asset's previous completed scan
      (matched by check name + finding title/path, not raw list order) and tags each finding
      `new` / `recurring` / `resolved` in the stored report.
   2. Asset detail page shows a regression timeline (findings appearing/disappearing across
      the Asset's scan history), not just the latest report.
   3. An existing webhook attached to the Asset's org fires a distinct `finding.regressed`
      event (new High/Critical finding since last scan) reusing Phase 19's signed-delivery
      machinery — no second notification path.
   4. Diffing is pure/deterministic given two report dicts — covered by unit tests with no
      network calls, matching the existing `_score_report` test-isolation discipline.

**Plans**: Direct execution, single commit.

**UI hint**: yes (Asset detail page regression timeline)

**Status**: Complete 2026-08-24 (commit 4e5947e, staging release v14). All four criteria met:
diff keyed on (case-folded check name-or-category, exact title) — order-independent, path-aware
via titles; tags land in the stored Report blob (`report["regression"]` + per-finding keys);
timeline on the Asset detail page; `finding.regressed` rides Phase 19's signed fan-out gated on
new High/Critical only; pure diff in `regressions.py` with a determinism lock
(tests/test_regressions.py).

### Phase 27.1: Risk-Score-Over-Time Chart Legibility Fix (INSERTED)

**Goal**: Fix a real UX defect caught during live staging verification of Phase 27
(2026-08-24, browser + API walkthrough — an Asset was scanned twice via
`POST /api/v1/assets/<id>/scans` specifically to exercise the new chart with real data):
the Asset detail page's "Risk score over time" sparkline (pre-existing, from Phase 1/the
dashboard's per-target trend work — not introduced by Phase 27, but the first phase to put
real user attention on this exact chart) renders as an unlabeled flat line with no axis, no
per-point value, and no severity-aware color — at a 0/100 (worst possible, Grade F) score, it
renders in the app's `--accent` green, the same color the design system uses everywhere else
to mean "good" or "passing." A trend chart that can't communicate "this got worse" at a glance
fails at its one job, and a worst-possible score rendered in the "safe" color is actively
misleading, not just plain.
**Depends on**: nothing new — same chart Phase 1's per-target dashboard sparkline already
established; only relevant precedent is the `n==1` single-point-line fix already made to that
sparkline (see `handoff.md`'s bug log) — this is a related but distinct defect on a different
instance of the same UI idea (the Asset detail page's own line, not the dashboard's).
**Requirements**: CHARTUX-01..CHARTUX-04 (see REQUIREMENTS.md)
**Success Criteria**:

   1. Each point on the line is colored by that scan's own grade/severity, not a single fixed
      `--accent` green — reuse the existing severity/grade color tokens `base.html` already
      defines (critical/high/medium/low or A-F grade colors, whichever this chart's data shape
      maps to more directly), not a new ad hoc palette.
   2. Each point shows its risk score value directly on or immediately next to the mark (a
      static label, a hover tooltip, or both) — a viewer should never have to re-read the
      caption sentence above the chart to know what a given point's score was.
   3. A light axis or gridline reference (even a simple 0/50/100 y-axis tick set) gives the eye
      a frame of reference instead of a line floating in empty space.
   4. The existing `n==1` single-point special case (flat 2-point reference line + text label,
      per the dashboard sparkline's own prior fix) still renders correctly — this fix must not
      regress the already-solved single-scan case on either the dashboard or Asset detail chart.
   5. Load the `dataviz` skill before implementing — this is exactly the "severity-aware color
      scale + labeled marks + legible small chart" problem it's designed for; don't freehand a
      new chart convention when established guidance already covers this shape.

**Plans**: Direct execution, single commit.

**UI hint**: yes (Asset detail page + dashboard sparkline, if the fix is shared between them)

### Phase 28: Check Extensibility (Plugin Architecture)

**Goal**: Let a check be added without touching `checks.py`/`scan_engine.py` core — a
declarative check format (starting narrow: HTTP request/response pattern-match checks only,
the class of check most community contributions would actually be) loaded from a
`checks/community/*.yaml`-style directory at startup, validated at load time, and run through
the exact same `(data, findings)` contract and entitlement gating as built-in checks. This is
what lets the check library outgrow what one team can hand-write — the second-biggest gap from
the 2026-08-24 review, deliberately scoped narrow so it ships instead of stalling on trying to
support every check shape on day one.
**Depends on**: nothing new (extends existing check-registration conventions)
**Requirements**: PLUG-01..PLUG-05 (see REQUIREMENTS.md)
**Success Criteria**:

   1. A loaded community check is indistinguishable to `run_scan()`/`entitlements.py` from a
      built-in one — same jobs-dict wiring, same `FEATURE_REQUIREMENTS` gating (community
      checks default to the most restrictive tier unless explicitly configured, never FREE by
      default), same `CHECK_LABELS`/`CHECK_CATEGORY` requirement.
   2. Malformed/unsafe check definitions (non-GET methods, off-target hosts, missing required
      fields) fail closed at load time with a clear error — never silently skipped, never
      executed with unsafe defaults.
   3. A schema doc + 2-3 example community checks ship in-repo as the reference for
      contributors.
   4. Load-time validation is covered by tests including at least one deliberately malformed
      fixture per rejection reason.

**Plans**: Direct execution, single commit.

**UI hint**: no (internal loader; existing report UI already renders arbitrary check output)

### Phase 29: SARIF Export

**Goal**: `GET /scan/<id>/report.sarif` (+ token-authed `/api/v1` twin) — SARIF 2.1.0 output
that GitHub's native Security tab ingests directly via `github/codeql-action/upload-sarif`,
turning findings into inline PR annotations without the user building any glue code. Low
lift relative to Phase 24's PDF export (reuses the same report dict, same ownership guard,
same CSV-export precedent) for outsized adoption leverage with the CI/CD audience Phase 18's
CLI and Phase 25's pipeline work already targets.
**Depends on**: Phase 12 finding schema (confidence/CWE fields SARIF's `level`/`rules` want)
**Requirements**: SARIF-01..SARIF-03 (see REQUIREMENTS.md)
**Success Criteria**:

   1. Output validates against the SARIF 2.1.0 JSON schema (a fixture-based test, not just
      "GitHub accepted it once").
   2. Severity maps to SARIF `level` (critical/high → error, medium → warning, low/info →
      note) via one shared mapping function, not duplicated per exporter.
   3. Same ownership guard + IDOR REGISTRY entry as report.csv/report.pdf.
   4. Verified once for real: a fixture scan's SARIF output uploaded to a scratch GitHub repo
      via `codeql-action/upload-sarif` and confirmed to render PR annotations, not just
      schema-valid in isolation.

**Plans**: Direct execution, single commit.

**UI hint**: yes (download link alongside existing CSV/PDF export)

**Status**: Complete 2026-08-24 (commit d6981c3, staging release v15). SARIF-01/02 done:
single shared writer (sarif.build_sarif_report/sarif_text) behind both the session-web
route and the token-authed /api/v1 twin - byte-identical output locked by test; schema
validation against the vendored official 2.1.0 schemastore schema via jsonschema;
severity→level mapping lives once, in checks.severity_to_sarif_level(). Live-fire on
staging: real scan #8 exported as valid SARIF (5 rules / 24 results; levels error×19/
warning×2/note×3), unauth API → 401 JSON, unauth session route → 302 login. SARIF-03
(the one real upload-sarif run against a scratch GitHub repo) is deliberately still open
- it needs Actions, which are billing-blocked until next month; tracked in REQUIREMENTS
as a pending user action.

### Phase 30: Self-Hostable / Open-Core Decision Spike

**Goal**: Not a build — a scoped, time-boxed decision spike answering whether Glassbox should
offer a self-hostable open-core edition (scan engine + CLI open, hosted dashboard/billing/org
features as the upsell), the trust-and-data-residency gap flagged in the 2026-08-22 audit as
the thing that most affects adoption by the exact security-engineer audience this product
targets. Recorded as a decision doc either way — a reasoned NO is a valid, useful outcome here,
not a failure to ship.
**Depends on**: nothing (research/decision only)
**Requirements**: OSSD-01 (see REQUIREMENTS.md)
**Success Criteria**:

   1. A decision doc at `.planning/PHASE30-OPEN-CORE-DECISION.md` covering: what a self-hosted
      edition would/wouldn't include (crypto billing and org/SaaS features almost certainly
      stay hosted-only), the licensing model considered, and the maintenance-burden cost of
      supporting two deploy shapes.
   2. If GO: a follow-up phase gets scoped separately — this phase does not itself split the
      codebase.
   3. If NO-GO: the reasoning is recorded so the question doesn't get silently re-asked next
      milestone without new information.

**Plans**: Direct execution (research + doc, no code required for a NO-GO outcome).

**UI hint**: no

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
| 17. Expanded Check Coverage | v1.4 | Direct execution | Complete | 2026-08-23 |
| 18. CLI Client | v1.4 | Direct execution | Complete | 2026-08-23 |
| 19. Webhooks & Slack Notifications | v1.4 | Direct execution | Complete | 2026-08-23 |
| 20. Intrusive Coverage Expansion | v1.5 | Direct execution | Complete | 2026-08-23 |
| 21. Built-in Detection Self-Test | v1.5 | Direct execution | Complete | 2026-08-23 |
| 22. In-Product API Documentation | v1.6 | Direct execution | Complete | 2026-08-24 |
| 23. Audit Log | v1.6 | Direct execution | Complete | 2026-08-25 |
| 24. Report PDF Export | v1.6 | Direct execution | Complete | 2026-08-25 |
| 25. Pipeline Integrations (GitHub/SIEM) | v1.6 | Direct execution | Complete | 2026-08-25 |
| 26. SSO / SAML | v1.6 | Direct execution | Complete | 2026-08-25 |
| 21.1. Detection-Verification UX Fold-In (INSERTED) | v1.5 | Direct execution | Complete | 2026-08-24 |
| 27. Continuous Regression Tracking | v1.7 | Direct execution | Complete 2026-08-24 | 4e5947e (staging v14) |
| 27.1. Risk-Score-Over-Time Chart Legibility Fix (INSERTED) | v1.7 | Direct execution | Complete 2026-08-25 | f215d92 (staging v16) |
| 28. Check Extensibility (Plugin Architecture) | v1.7 | Direct execution | Complete 2026-08-25 | bbad7b0 (staging v16) |
| 29. SARIF Export | v1.7 | Direct execution | Complete 2026-08-24 (SARIF-03 user-pending) | d6981c3 (staging v15) |
| 30. Self-Hostable / Open-Core Decision Spike | v1.7 | Direct execution | Complete 2026-08-25 | Decision doc (NO code change) |

### Phase 31: CVSS 3.1 Scoring

**Goal**: Findings optionally carry a CVSS 3.1 vector string; the report computes a CVSS base
score alongside the existing risk score, giving security engineers a standard, comparable metric
while keeping the existing severity-weight scoring for the platform's own grade/risk-score
calculation. This is an additive layer, not a replacement — `_score_report()` keeps its
battle-tested arithmetic; CVSS scores are附加 metadata on the report and per-finding detail.
**Depends on**: nothing new — Finding dataclass, _score_report, and report templates.
**Requirements**: CVSS-01..CVSS-05 (see REQUIREMENTS.md)
**Success Criteria**:

   1. A `cvss_vector` optional field on Finding accepts a CVSS 3.1 vector string
      (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).
   2. A `compute_cvss_score(vector)` helper parses the vector and returns a base score
      (0.0–10.0) + severity label (Critical/High/Medium/Low) per the CVSS 3.1 spec.
   3. Findings with a CVSS vector show their CVSS score and severity on the report page;
      findings without one degrade gracefully (no score shown, no error).
   4. The existing `_score_report()` / risk grade / severity_counts pipeline is untouched —
      CVSS is附加 metadata, not a scoring replacement.
   5. At least 5 existing check call sites (one per severity tier) are updated to supply a
      CVSS vector, proving the plumbing works end-to-end.

**Plans**: Direct execution, single commit.
**UI hint**: yes (report page CVSS column + per-finding CVSS badge)

### Phase 32: Finding Deduplication

**Goal**: The crawl-then-probe flow (Phase 17's depth-2 crawl, Phase 20's active checks) can
surface the same finding multiple times for the same URL/path/param combination. Dedup
collapse these into a single finding with a `count` field, keeping the report clean and the
risk score accurate (a finding counted once vs. three times shouldn't change the grade).
**Depends on**: Phase 31 (CVSS vectors on Findings, so dedup preserves them).
**Requirements**: DEDUP-01..DEDUP-04 (see REQUIREMENTS.md)
**Success Criteria**:

   1. A `deduplicate_findings(findings)` helper hashes each finding by
      (check_name, category, title, affected_url) and collapses duplicates into one Finding
      with a `count: int` field.
   2. The dedup runs in each orchestrator after all checks complete, before `_score_report()`.
   3. The report template shows "(×N)" beside deduplicated finding titles.
   4. Findings with different severities for the same (check_name, title, url) keep the
      highest severity — no silent downgrade.
   5. The dedup is deterministic — same input always produces same output, proven by tests.

**Plans**: Direct execution, single commit.
**UI hint**: yes (report "(×N)" badge)

### Phase 33: OWASP Gap Audit

**Goal**: Five new checks covering gaps in the OWASP Top 10 coverage that Strix and manual
audit identified: XXE detection, CSP depth analysis, HSTS depth analysis, DNSSEC verification,
and dependency-scanning depth. All follow the existing `(data, findings)` contract and
safety constraints.
**Depends on**: Phase 32 (dedup, so the new checks' findings are clean).
**Requirements**: OWGAP-01..OWGAP-05 (see REQUIREMENTS.md)
**Success Criteria**:

   1. `check_xxe`: probes for XML external entity injection on endpoints that accept
      XML Content-Type; marker-only (no real file reads), same safety as SSTI.
   2. `check_csp_depth`: deepens the existing CSP header check to evaluate directive
      quality (script-src strength, report-uri presence, nonce/hash usage).
   3. `check_hsts_depth`: deepens the existing HSTS check to evaluate max-age adequacy,
      includeSubDomains, preload eligibility.
   4. `check_dnssec`: verifies DNSSEC signing via dns.resolver AD flag + DNSKEY record
      presence.
   5. `check_dependency_audit`: enriches the existing dependency version check with
      known-CVE matching against a curated advisory list.
   6. All five registered in FEATURE_REQUIREMENTS, CHECK_LABELS, CHECK_CATEGORY, scan_engine
      jobs dict, and scan_report.html.

**Plans**: Direct execution, single commit.
**UI hint**: no (findings render through existing report UI)

### Phase 34: API Testing Enhancements

**Goal**: Three new checks for API surface testing: GraphQL depth/introspection probing,
authentication comparison (authenticated vs. unauthenticated response diff), and mass
assignment detection (sending extra fields to see if they're accepted). All read-only probes,
no destructive payloads.
**Depends on**: Phase 33 (OWASP gap checks, so the API surface has full coverage context).
**Requirements**: APIT-01..APIT-03 (see REQUIREMENTS.md)
**Success Criteria**:

   1. `check_graphql_depth`: sends nested queries to GraphQL endpoints (introspection-
      discovered or common paths) to test query depth limits and error handling.
   2. `check_auth_comparison`: for endpoints discovered by `check_api_wordlist`, sends
      the same request with and without authentication tokens, diffs response status/size
      to identify authorization gaps.
   3. `check_mass_assignment`: for discovered API endpoints, appends extra fields
      (e.g. `{"role":"admin","is_admin":true}`) to POST bodies and checks if the response
      reflects the extra field's acceptance.
   4. All three registered in FEATURE_REQUIREMENTS (ORG_VERIFIED tier), CHECK_LABELS,
      CHECK_CATEGORY, scan_engine jobs dict, and scan_report.html.

**Plans**: Direct execution, single commit.
**UI hint**: no (findings render through existing report UI)

