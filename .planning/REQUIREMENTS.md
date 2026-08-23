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

**Coverage:** 59/59 requirements mapped (9 deferred from v1.2 now resumed, 23 shipped for v1.3
across 5 phases, 17 new for v1.4 across 4 phases, 10 new for v1.5 across 1 phase - all complete).

