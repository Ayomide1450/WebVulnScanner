# Requirements: WebVulnScanner → Glassbox — v1.3 Rebrand & Production Security Readiness

**Defined:** 2026-08-20
**Core Value:** Security engineers can trust the product to run safe, authorization-gated,
non-destructive scans against their own infrastructure and get findings they can act on — without
it ever weakening its safety guarantees to become a general attack tool. This holds regardless of
product name.

**Milestone Goal:** Rebrand from WebVulnScanner to Glassbox (in-app branding + a live Fly app
migration to `glassboxsec.fly.dev`), then extend the existing scan engine — reusing all current
checks, the OWASP-mapped compliance layer, ownership verification, and scan pipelines rather than
duplicating any of it — into a full "Production Security Readiness" assessment: an extended
`Finding` schema (confidence/CWE/verification-state), domain-grouped scoring with a
READY/READY WITH WARNINGS/NOT READY verdict, a handful of net-new checks, and a "Request Expert
Assessment" lead-gen CTA. Every new check and UI change must preserve the frozen safety surface
(`authorized*`, `entitlements.py`, `is_ssrf_safe_hostname()`) and non-destructive testing
constraints exactly as CLAUDE.md already documents — this milestone extends assessment depth and
product framing, it does not change what the scanner is allowed to do to a target.

## v1 Requirements

### Rebrand (REBRAND) — Phase 11

- [x] **REBRAND-01**: Product name changed from "WebVulnScanner" to "Glassbox" across all
      user-facing surfaces — page titles, meta/OG/Twitter tags, nav brand, emails, error pages —
      with no leftover "WebVulnScanner" string in rendered output.
- [x] **REBRAND-02**: `README.md`, `CLAUDE.md`, and other project docs updated to reflect the new
      name; `CLAUDE.md`'s safety-critical constraints (frozen surface, non-destructive rules)
      carry over unchanged in substance.
- [x] **REBRAND-03**: A new Fly app (`glassboxsec` — `glassbox` itself was already taken globally
      on Fly) is stood up with all 12 existing secrets migrated
      (`SECRET_KEY`, `SQLALCHEMY_DATABASE_URI`, `EMAIL_MODE`, `RESEND_API_KEY`,
      `RESEND_FROM_EMAIL`, `GROQ_API_KEY`, `CRYPTO_RECEIVING_ADDRESS`, `POLYGONSCAN_API_KEY`,
      `USDT_CONTRACT_ADDRESS`, `USDC_CONTRACT_ADDRESS`, `TURNSTILE_SITE_KEY`,
      `TURNSTILE_SECRET_KEY`) and deployed from the same image/Dockerfile.
- [x] **REBRAND-04**: `glassboxsec.fly.dev` is confirmed healthy (health check passing, a real login/
      scan smoke test succeeds) before `webvulnscanner.fly.dev` is decommissioned — no
      destructive cutover without a verified working replacement first.
- [x] **REBRAND-05**: The rebrand does not touch `authorized*` checkboxes, `entitlements.py`, or
      `checks.is_ssrf_safe_hostname()` — cosmetic/naming change only, verified by the existing
      security test suite still passing unmodified in substance.

### Finding Schema (FSCH) — Phase 12

- [x] **FSCH-01**: `Finding` dataclass gains a `confidence` field with exactly five allowed values
      (Confirmed / Strong Evidence / Potential / Informational / Not Externally Verifiable),
      kept conceptually separate from `severity` — nothing is ever labeled "Confirmed" without
      an evidence basis for it.
- [x] **FSCH-02**: `Finding` dataclass gains an optional `cwe` field, populated only where a check
      genuinely maps to a specific CWE (not speculative/blanket-filled).
- [x] **FSCH-03**: `Finding` dataclass gains a `verification_state` field distinguishing
      Discovered / Observed / Potential Risk / Confirmed Finding, primarily for attack-surface
      and exposure-type findings.
- [x] **FSCH-04**: All existing `Finding(...)` construction sites across `checks.py` are backfilled
      with an honest `confidence` value — a regression test proves no call site is left on a
      silent/implicit default.
- [x] **FSCH-05**: The scan report renders `confidence` and, where present, `cwe`/OWASP mapping
      per finding without visually cluttering the existing report layout (reuses existing
      `.pill`/`.badge` components per `CLAUDE.md`'s frontend design system — no new component
      family introduced).

### Domain Grouping & Scoring v2 (SCORE) — Phase 13

- [x] **SCORE-01**: A new `SECURITY_DOMAIN_MAP` (parallel to the existing `CHECK_COMPLIANCE`)
      groups every check_name into one of 13 product-facing domains: Security Posture, Attack
      Surface, Authentication, Authorization, API Security, Client Security, Configuration,
      Secrets, DNS & Domains, TLS, Dependencies, Privacy, Production Readiness.
- [x] **SCORE-02**: The scan report UI is reorganized into domain-grouped sections instead of a
      flat/severity-only finding list, without adding a new page or navigation pattern.
- [x] **SCORE-03**: Scoring is extended to weight by confidence and control coverage in addition
      to severity count, documented so a user can see *why* the score is what it is — implemented
      as `scan_engine._compute_readiness()`, a companion function alongside the existing
      `_score_report()` rather than a change to it (that function has 20+ existing tests and a
      source-parsing regression lock on its exact arithmetic; extending via a new function
      achieves the same substance at zero regression risk to it).
- [x] **SCORE-04**: A production-readiness verdict (READY / READY WITH WARNINGS / NOT READY) is
      computed and displayed prominently on the report, with a supporting breakdown (severity
      counts, main risks) — not derived from vulnerability count alone.
- [x] **SCORE-05**: Attack-surface-category findings are tagged with their `verification_state`
      (Discovered/Observed/Potential Risk/Confirmed Finding) visibly in the UI.

### Net-New Checks (CHECK) — Phase 14

- [x] **CHECK-01**: A file-upload security check (where upload functionality is identified on the
      target) — dangerous extensions, absence of size limits, public accessibility of uploaded
      files — read-only/non-destructive, no payloads uploaded to the target.
- [x] **CHECK-02**: A `/.well-known/security.txt` check — presence, valid contact field,
      expiration, policy reference. Already existed before this phase (`check_sensitive_paths`'s
      security.txt probe) — confirmed by inspection, not duplicated.
- [x] **CHECK-03**: A privacy/PII exposure check — emails, phone numbers, and other sensitive
      identifiers found in publicly reachable responses.
- [x] **CHECK-04**: A caching/sensitive-data check — `Cache-Control` on responses that appear to
      carry sensitive/authenticated content, sensitive data appearing in URLs.
- [x] **CHECK-05**: A GraphQL introspection check, extending the existing API schema-exposure
      check family rather than duplicating it. Already existed before this phase
      (`check_api_schema_exposure`'s GraphQL introspection query) — confirmed, not duplicated.
- [x] **CHECK-06**: Every new check follows the existing `(data, findings)` convention, never
      raises past its own function, and is added to `FEATURE_REQUIREMENTS`/`CHECK_COMPLIANCE`/
      `SECURITY_DOMAIN_MAP` in the same pattern as existing checks (regression-tested for
      coverage, per the existing `tests/test_compliance.py`-style lock).

### Request Expert Assessment (CTA) — Phase 15

- [x] **CTA-01**: A "Request Expert Assessment" call-to-action is visible on the scan report and/
      or dashboard pages, reusing the existing `.btn`/`.card` components.
- [x] **CTA-02**: A new `AssessmentRequest` model + form collects: company, domain, contact name,
      email, phone, assessment type (External Security Assessment / Web Application Assessment /
      API Security Assessment / Authenticated Assessment / Full Security Assessment / Continuous
      Monitoring), scope, authentication requirements, number of applications/domains, preferred
      timeline, additional information.
- [x] **CTA-03**: Submitted requests are stored and visible to platform admins (reusing the
      existing platform-admin panel pattern), not just emailed and discarded.
- [x] **CTA-04**: The submission form is CSRF-protected and rate-limited like every other
      state-changing form in the app (`extensions.limiter` pattern).

### Platform Admin User/Org Management — Phase 16

- [x] **ADMIN-01**: A platform admin can open a user detail view (org, role, plan, scan history)
      from `/platform-admin`.
- [x] **ADMIN-02**: A platform admin can suspend/unsuspend a user (blocks login, distinct from
      deletion), gated behind a confirmation step.
- [x] **ADMIN-03**: A platform admin can suspend an org, cascading the block to its members.
      Scoped down from "suspend/remove" during implementation (08-21): hard delete of a user or
      org is a separate, much higher-stakes feature (data-loss semantics, cascade behavior across
      scans/reports/billing) genuinely deserving its own dedicated design pass, not a checkbox
      alongside a reversible suspend action. Suspension covers the "stop this account/org from
      doing anything" need `admin_routes.py`'s existing docstring named as the actual moderation
      goal; hard delete is a real, valid future requirement, not dropped.
- [x] **ADMIN-04**: Every suspend/remove/restore action writes an audit-trail row (who/what/when),
      same convention as the existing domain-deletion approve/reject flow.

### Expanded Check Coverage — Phase 17

- [x] **DEPTH-01**: An explicit, signed-off decision on same-origin depth-1 crawl vs. a deeper/
      multi-page crawl — this changes the app's safety posture and must not be flipped quietly.
      (Approved 2026-08-23, "A AND B": .planning/PHASE17-DEPTH-DECISION.md)
- [x] **DEPTH-02**: Injection-class checks (XSS/SQLi) gain additional payload/variant coverage
      without violating existing safety constraints (no destructive payloads, same caps).
      (4 reflected-XSS shapes, context-aware boolean pairs, 14 error signatures,
      MAX_PROBE_REQUESTS_PER_URL=12 budget lock)
- [x] **DEPTH-03**: All coverage additions are registered in `FEATURE_REQUIREMENTS`/
      `CHECK_LABELS`/`CHECK_CATEGORY` with regression-lock tests, per the existing convention.
      (No new check names - variants ride inside xss_sqli; registry locks in
      tests/test_phase17_coverage.py)

### CLI Client — Phase 18

- [x] **CLI-01**: A standalone `glassbox` CLI authenticates using the existing API-token system —
      no new auth mechanism.
- [x] **CLI-02**: The CLI can launch a scan, poll status, and fetch a finished report (JSON/CSV)
      via the existing API routes — no new server endpoints required for the MVP.
      Note (08-23 close-out): one read-only endpoint was added beyond the MVP wording —
      GET /api/v1/scans/<id>/report.csv, the token-authed twin of the web UI's export.csv route,
      sharing scan_routes.findings_csv_document() so both exports are byte-identical. Read-only
      alternate rendering of an already-authorized report; no new execution surface.
- [x] **CLI-03**: Ships as a separate installable package/script, not embedded in the web app —
      an in-browser terminal was explicitly considered and ruled out (larger, harder-to-secure
      attack surface) during this phase's scoping conversation (08-20). `cli/pyproject.toml`
      (08-23) makes `pip install ./cli` provide a real `glassbox` console script.

### Webhooks & Slack Notifications — Phase 19

- [x] **WEBH-01**: A completed scan triggers delivery to every matching ACTIVE webhook.
      Org webhooks (org_id set) fire for scans run by that org; solo users' personal webhooks
      fire only for scans they ran themselves — matched on `created_by_user_id`, never NULL-org
      equality (two different solo users both have org_id NULL). Hook lives in
      `_run_scan_in_background`'s shared tail so wizard/API/scheduler paths all converge.
- [x] **WEBH-02**: Every delivery is signed: `X-Glassbox-Signature: sha256=HMAC-SHA256(secret, body)`
      with a per-webhook secret (`secrets.token_hex(32)`) shown exactly once at creation time,
      same reveal-once convention as API tokens. Receivers can verify authenticity and integrity.
- [x] **WEBH-03**: Receiver URLs validated at creation: HTTPS required, hostname must pass the
      SAME `is_ssrf_safe_hostname` gate scan targets go through — a webhook can't be used to make
      Glassbox POST at internal services or cloud-metadata endpoints. Same documented DNS-rebinding
      caveat as the scan-target flow (submission-time check only).
- [x] **WEBH-04**: One payload serves Slack AND generic receivers: Slack renders the first-class
      `text` line; structured `event`/`scan`/`gate`/`top_findings` ride along (Slack ignores
      unknown keys). The gate verdict comes from the single-source `evaluate_gate()` shared with
      /api/v1 gate endpoint and `glassbox gate`.
- [x] **WEBH-05**: Delivery failures never break a finished scan and never raise past the fan-out;
      each attempt is recorded in a WebhookDelivery row (status/response_code/error_message),
      visible per-webhook via /webhooks/<id>/deliveries — a dead receiver is diagnosable, not silent.
- [x] **WEBH-06**: Owner-triggered test ping per webhook (rate-limited 10/hour) fires a real signed
      POST recording a scanless delivery row, proving connectivity before any scan needs it.
      Stored URLs are never rendered back in full anywhere (Slack URLs embed credentials in their
      path) — templates show redact_webhook_url()'s scheme://host/*** form only.
- [x] **WEBH-07**: Management UI (/webhooks) with server-side scoping: org webhooks manageable by
      that org's ORG_ADMIN only, solo webhooks by their creator, 404-not-403 on all cross-scope
      access; add/toggle/delete/test/deliveries routes registered in tests/test_cross_org_idor.py's
      REGISTRY with denial tests; schema via Alembic migration c3f8a91d2e47.

## Future Requirements

<!-- Deferred from this milestone, candidates for the next one. -->

- v1.2's Phase 10 (Live Verification Closeout, VERIFY-01..09 below) — reprioritized behind v1.3,
  not dropped. Real, valid, deferred work; resumed 2026-08-20 alongside v1.4 planning.
- Plugin/third-party check-extensibility system — deferred three times now (v1.0, v1.1, v1.2);
  still no concrete requirement or user request to build it.
- Self-hostable/open-core deployment model — still locked/undecided.
- A purchased custom domain for Glassbox (e.g. `glassbox.io`) — `glassboxsec.fly.dev` is this
  milestone's scope; a real domain requires a registrar purchase only the user can make.

### Intrusive Coverage Expansion — Phase 20

Ten new check families for security engineers. All follow the house convention
(`(data, findings)`, `requests.RequestException` contained, named `MAX_*` caps,
marker-only proofs, no destructive payloads). Tier mapping is deliberate:
single-request reflection probes are PAID; anything sending deliberate
multi-request bursts or active forgeries is ORG_VERIFIED (tier AND verified
domain, per the existing gating).

- [x] **INTR-01** `check_ssti`: server-side template injection canary — arithmetic
      marker pairs (`{{7*7}}`/`${7*7}`/`<%= 7*7 %>`) injected into GET params,
      confirmed only by computed-result reflection. PAID.
- [x] **INTR-02** `check_host_header_injection`: benign Host/X-Forwarded-Host
      canary reflected in the response body or location/set-cookie headers.
      Single requests, no cache manipulation. PAID.
- [x] **INTR-03** `check_cache_deception`: web-cache-deception heuristic — requests
      to `<known-authed-path>.css`-style variants compared against the plain path
      via status/body similarity, never poisoning shared caches with attacker
      content. PAID.
- [x] **INTR-04** `check_path_traversal`: read-only traversal on file-ish GET params
      (`?file=`-style), confirmed by a known static marker file's content signature;
      no writes, no deletion, capped param set. ORG_VERIFIED.
- [x] **INTR-05** `check_rate_limit_posture`: measured burst (~15 max) against one
      auth endpoint, stops at first 429/lockout signal; reports absence of any
      throttling as the finding. ORG_VERIFIED.
- [x] **INTR-06** Active JWT check: `alg:none` / weak-HMAC re-sign of the operator's
      OWN token, submitted only where that session already legitimately reaches;
      confirms acceptance or reports nothing. Extends `check_jwt_weakness`.
      ORG_VERIFIED.
- [x] **INTR-07** `check_crlf_injection`: `%0d%0a` canary in GET params and path,
      confirmed by response-header reflection (`X-Glassbox-Canary` style split).
      PAID.
- [x] **INTR-08** `check_csrf_posture`: heuristic scan of crawled forms — flags
      state-changing (POST) forms lacking any anti-CSRF token input. Forms are
      still NEVER auto-submitted. PAID.
- [x] **INTR-09** `check_subdomain_takeover`: DNS-only dangling-CNAME detection
      against known takeover fingerprints (github.io, herokuapp.com, s3, azure,
      etc.) for www/common subdomains of the target domain. No HTTP probing of
      third-party hosts beyond the fingerprint match itself. PAID.
- [x] **INTR-10** `check_graphql_deep`: GraphQL arg-level canary (read-only queries
      only) + introspection-disabled field-suggestion probing on discovered
      GraphQL endpoints. ORG_VERIFIED.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Changing `authorized*`, `entitlements.py`, or `checks.is_ssrf_safe_hostname()` | Frozen per CLAUDE.md — this milestone extends assessment depth/framing, not scan permissions |
| Destructive testing of any kind (brute force beyond existing caps, damaging load tests, uncontrolled exploitation) | Explicit safety rule carried into every new check |
| Replacing crypto-invoice billing or the tier model | Still locked, not under reconsideration |
| A purchased custom domain | Requires the user's own registrar action; `glassboxsec.fly.dev` is the in-scope target |
| Speculative checks added purely to raise the feature count | Every new check must map to a real, reasoned pre-production gap, not exist for taxonomy completeness |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| VERIFY-01..09 | Phase 10 | In progress (resumed 2026-08-20) |
| REBRAND-01..05 | Phase 11 | Complete |
| FSCH-01..05 | Phase 12 | Complete |
| SCORE-01..05 | Phase 13 | Complete |
| CHECK-01..06 | Phase 14 | Complete |
| CTA-01..04 | Phase 15 | Complete |
| ADMIN-01..04 | Phase 16 | Complete (ADMIN-03 scoped to suspend, not hard delete - see note) |
| DEPTH-01..03 | Phase 17 | Complete |
| CLI-01..03 | Phase 18 | Complete |
| WEBH-01..07 | Phase 19 | Complete |
| INTR-01..10 | Phase 20 | Complete |

### Detection Self-Test — Phase 21 (v1.5)

- [x] **ST-01** Loopback-only lure listener: `webvulnscanner/selftest.py` binds a
  `ThreadingHTTPServer` to 127.0.0.1 on an ephemeral port; never a wildcard or external
  interface; per-instance state so repeated runs see identical ground truth.
- [x] **ST-02** Five planted flaws with deterministic proofs: SSTI (`{{77*77}}` computed),
  traversal (decoy passwd served on sandbox escape - identical on Windows/Linux/CI), JWT
  cookie accepting alg:none but rejecting garbage signatures, GraphQL introspection +
  "Did you mean" leak, token-less POST form.
- [x] **ST-03** Matrix runner: all ten Phase-20 checks execute in-process against the lure
  via the real crawler; expectations = five positives fire at required severities, five
  negatives stay silent; result `{passed, duration_ms, results[]}`.
- [x] **ST-04** Route + UI: POST /selftest (login required, CSRF form, rate-limited 30/hour)
  runs the matrix synchronously; GET renders launcher; results table uses base.html tokens;
  dashboard gains "Detection Self-Test" button.
  *SUPERSEDED 2026-08-24 by explicit user direction (same deviation-note treatment as
  CLI-02): the standalone /selftest page and dashboard button read as "another scanner -
  which domain does THIS one hit?" - the exact confusion the loopback design exists to
  avoid. The route, template, and button were removed; the engine now runs once per
  worker process (cached) at the end of `run_scan()`, attaches
  `report["detection_verified"]`, and scan_report.html renders it as an "Engine verified"
  badge beside the risk score. ST-01/02/03/05/06 are untouched - the matrix itself is
  unchanged.*
- [x] **ST-05** Isolation contracts: no Scan row created, no Report file written, no
  external network traffic, SSRF guard untouched (no user-supplied URL anywhere).
- [x] **ST-06** tests/test_selftest.py: full-matrix end-to-end over real HTTP,
  determinism across runs, loopback-only binding lock, port release after teardown,
  route auth redirect, no-scan-row contract.
  *2026-08-24: the two route tests left with ST-04's surface; replaced by locks on the
  per-process cache (compute-once, errors-not-cached), `verification_summary()`'s shape,
  a /selftest-returns-404 regression lock, and structural locks tying `run_scan()` +
  scan_report.html to the `detection_verified` key.*

| ID(s) | Phase | Status |
|---|---|---|
| ST-01..06 | Phase 21 | Complete |

### In-Product API Documentation — Phase 22 (v1.6)

- [x] **DOCS-01**: /docs/api renders from ONE server-side spec structure (not hand-duplicated
      HTML per route); a url_map-enumeration regression test fails naming any `/api/v1` rule
      missing from the spec, so a new endpoint cannot ship undocumented.
      (webvulnscanner/api_docs.py API_ENDPOINTS; bidirectional lock incl. method drift)
- [x] **DOCS-02**: Every endpoint row documents method, path, required auth (session/token/
      public), rate limit, and request+response examples drawn from real test fixtures.
      (examples shaped after _serialize_asset/_serialize_scan_summary/evaluate_gate output)
- [x] **DOCS-03**: Webhook section includes a copy-pasteable HMAC-SHA256 verification snippet
      that a test proves matches `webhooks.sign_payload`'s algorithm exactly.
      (snippet is exec()ed and behaviorally compared both directions vs the real signer)
- [x] **DOCS-04**: CLI section mirrors cli/README.md essentials (install, init, gate exit
      codes); a test keeps the section's command list in sync with the README's.
      (CLI_SUBCOMMANDS set == README `glassbox <cmd>` lines, named-diff failure)
- [x] **DOCS-05**: Login-gated page on base.html tokens with the dual-markup responsive
      contract; nav link after Webhooks.
      (/docs/api; api_docs.html joins the card-conversion closed set, scope lock eight→nine)

### Audit Log — Phase 23 (v1.6)

- [ ] **AUDIT-01**: `AuditEvent` model + Alembic migration; append-only in practice — no
      update/delete routes exist, proven by a test asserting their absence.
- [ ] **AUDIT-02**: Emission sites cover the enumerated mutation set (invites, role/join
      changes, domain lifecycle, token create/revoke, webhook lifecycle, invoice verify /
      plan activation, platform-admin actions); registry-driven test fails if a listed route
      stops emitting.
- [ ] **AUDIT-03**: ORG_ADMIN sees own-org events paginated at /org/audit; platform admins
      see all; everyone else 404-not-403, registered in the IDOR REGISTRY.
- [ ] **AUDIT-04**: Retention strategy decided and documented at build time (per-org trim on
      insert vs. cleanup command), bounded by a named constant either way.
- [ ] **AUDIT-05**: Events render actor/action/target/timestamp/detail in dual markup.

### Report PDF Export — Phase 24 (v1.6)

- [ ] **PDFX-01**: GET /scan/<id>/report.pdf (session-authed) plus a token-authed /api/v1
      twin, both behind the same ownership guard as report.csv, in the IDOR REGISTRY.
- [ ] **PDFX-02**: Rendering dependency chosen deliberately for the Fly image (pure-python
      wheels preferred); decision + image-size delta recorded in phase notes.
- [ ] **PDFX-03**: Content sourced from the SAME report dict `save_report()` writes (score/
      grade, severity tally, per-check tables incl. confidence/CWE, AI summary when present);
      no parallel formatting logic over raw findings.
- [ ] **PDFX-04**: Output validates as parseable PDF (magic bytes + parser round-trip) with
      key report strings present; deterministic given identical input.
- [ ] **PDFX-05**: `_redact_secret`-ed values appear redacted in the PDF too — the export
      must not become a second leak of any credential.

### Pipeline Integrations (GitHub Actions / SIEM) — Phase 25 (v1.6)

- [ ] **INTG-01**: GET /api/v1/scans/<id>/findings.ndjson — one finding per line,
      token-authed, same ownership guard; NDJSON shape validated line-by-line in tests.
- [ ] **INTG-02**: Per-webhook payload_format gains `splunk_hec` (event-keyed body Splunk HEC
      accepts); slack/generic behavior byte-unchanged — existing payload tests unmodified.
- [ ] **INTG-03**: Failed deliveries gain bounded retry with backoff recorded as additional
      WebhookDelivery attempts (cap = named MAX_* constant; retry never delays the scan tail).
- [ ] **INTG-04**: GitHub Actions recipe (checkout → glassbox init → glassbox gate → step
      summary) published on the docs page AND executed once against staging with a real
      token before sign-off.

### SSO / SAML — Phase 26 (v1.6)

- [ ] **SSO-01**: Spike-first: IdP-metadata parse + response signature validation proven
      inside the deploy image BEFORE feature build; NO-GO recorded in .planning/ is an
      acceptable outcome instead of a half-build.
- [ ] **SSO-02**: SP-initiated SAML login per configured org; JIT provisioning binds the
      asserted email's domain to THAT org's verified domains — mismatch refuses with an
      anti-enumeration-neutral error.
- [ ] **SSO-03**: Local password auth stays available unless the org explicitly disables it;
      disabling it is an audited event requiring fresh confirmation.
- [ ] **SSO-04**: All SSO config changes and logins emit Phase-23 AuditEvents; IdP secrets
      stored encrypted at rest (app-level Fernet off SECRET_KEY or equivalent, decision
      recorded).
- [ ] **SSO-05**: Outbound metadata/ACS fetches get SSRF-guard scrutiny equivalent to scan
      targets; cross-org config access is 404-not-403 with IDOR REGISTRY entries.

### Detection-Verification UX Fold-In (UXFT) — Phase 21.1 (v1.5, INSERTED)

- [x] **UXFT-01**: `/selftest` route, nav link, and dashboard button removed entirely.
      *(Implemented: `selftest_routes.py` + `selftest.html` deleted; blueprint registration
      and dashboard button removed; `/selftest` now 404s — regression-locked by
      `test_route_requires_login_removed_with_the_route`.)*
- [x] **UXFT-02**: `run_scan()` attaches a `detection_verified` summary to every base-scan
      report, computed once per worker process (never re-run per scan request).
      *(Implemented: `selftest.detection_verification()` caches the matrix behind a
      threading.Lock once per process; `verification_summary()` produces the compact
      {passed, confirmed, total, duration_ms, failed[]} dict; `run_scan()` attaches it at
      the END of the pipeline so the live feed isn't delayed on a worker's first scan.
      Errors are NOT cached — the next scan retries.)*
- [x] **UXFT-03**: `scan_report.html` shows an "Engine verified · N/10 detections confirmed"
      pill near the score, with copy explicit that it checked Glassbox's own internal target,
      not the user's site.
      *(Implemented: `.pill.pass` beside the score with the muted caption "Verified against
      Glassbox's internal check target — not your site."; drift degrades to a medium pill
      naming failed checks; reuses existing severity classes, no new color family.)*
- [x] **UXFT-04**: A verification failure/exception degrades to an absent badge — never fails
      or delays the real scan.
      *(Implemented: key omitted when verification unavailable; template guards with
      `{% if r.get('detection_verified') %}`; locked by test_verification_error_is_not_cached,
      test_verification_summary_none_when_engine_unavailable, and the run_scan ordering
      source-parse lock.)*

### Continuous Regression Tracking (CONT) — Phase 27 (v1.7)

- [ ] **CONT-01**: Each scheduled Asset fire diffs findings against that Asset's previous
      completed scan (matched by check name + finding title/path) and tags each finding
      `new` / `recurring` / `resolved` in the stored report.
- [ ] **CONT-02**: Asset detail page renders a regression timeline across the Asset's scan
      history, not just the latest report.
- [ ] **CONT-03**: A `finding.regressed` webhook event fires via Phase 19's existing signed-
      delivery machinery when a new High/Critical finding appears since the last scan — no
      second notification path built.
- [ ] **CONT-04**: The diff function is pure/deterministic (two report dicts in, tagged
      findings out) and unit-tested with no network calls.

### Check Extensibility / Plugin Architecture (PLUG) — Phase 28 (v1.7)

- [ ] **PLUG-01**: A declarative (YAML-based, HTTP request/response pattern-match only)
      community-check format loads from a `checks/community/*.yaml` directory at startup.
- [ ] **PLUG-02**: A loaded community check runs through the identical `(data, findings)`
      contract, jobs-dict wiring, and `FEATURE_REQUIREMENTS` tier-gating as a built-in check —
      defaulting to the most restrictive tier, never FREE, unless explicitly configured.
- [ ] **PLUG-03**: Malformed or unsafe check definitions (non-GET methods, off-target hosts,
      missing required fields) fail closed at load time with a clear error — never silently
      skipped, never executed with unsafe defaults.
- [ ] **PLUG-04**: A schema doc plus 2-3 example community checks ship in-repo as the
      contributor reference.
- [ ] **PLUG-05**: Load-time validation is covered by tests, including one deliberately
      malformed fixture per rejection reason.

### SARIF Export (SARIF) — Phase 29 (v1.7)

- [ ] **SARIF-01**: `GET /scan/<id>/report.sarif` (session-authed) plus a token-authed
      `/api/v1` twin, both behind the same ownership guard as report.csv, registered in the
      IDOR REGISTRY.
- [ ] **SARIF-02**: Output validates against the SARIF 2.1.0 JSON schema (fixture-based test);
      severity maps to SARIF `level` via one shared mapping function, not duplicated per
      exporter.
- [ ] **SARIF-03**: Verified once for real — a fixture scan's SARIF output uploaded to a
      scratch GitHub repo via `codeql-action/upload-sarif`, confirmed to render PR
      annotations, not just schema-valid in isolation.

### Self-Hostable / Open-Core Decision Spike (OSSD) — Phase 30 (v1.7)

- [ ] **OSSD-01**: A decision doc at `.planning/PHASE30-OPEN-CORE-DECISION.md` records what a
      self-hosted edition would/wouldn't include, the licensing model considered, and the
      maintenance-burden cost of two deploy shapes — GO or NO-GO, either is an acceptable,
      complete outcome for this phase.

| ID(s) | Phase | Status |
|---|---|---|
| DOCS-01..05 | Phase 22 | Complete |
| AUDIT-01..05 | Phase 23 | Planned |
| PDFX-01..05 | Phase 24 | Planned |
| INTG-01..04 | Phase 25 | Planned |
| SSO-01..05 | Phase 26 | Planned |
| UXFT-01..04 | Phase 21.1 | Complete |
| CONT-01..04 | Phase 27 | Planned |
| PLUG-01..05 | Phase 28 | Planned |
| SARIF-01..03 | Phase 29 | Planned |
| OSSD-01 | Phase 30 | Planned |

**Coverage:** 105/105 requirements mapped (9 deferred from v1.2 now resumed, 23 shipped for
v1.3 across 5 phases, 17 new for v1.4 across 4 phases, 16 for v1.5 across 2 phases - all
complete; 24 planned for v1.6 across 5 phases; 4 for the Phase 21.1 UX fix; 12 planned for
v1.7 across 4 phases, scoped 2026-08-24 from the strategic "what makes this world-class"
review).

