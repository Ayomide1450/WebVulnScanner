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

- [ ] **CTA-01**: A "Request Expert Assessment" call-to-action is visible on the scan report and/
      or dashboard pages, reusing the existing `.btn`/`.card` components.
- [ ] **CTA-02**: A new `AssessmentRequest` model + form collects: company, domain, contact name,
      email, phone, assessment type (External Security Assessment / Web Application Assessment /
      API Security Assessment / Authenticated Assessment / Full Security Assessment / Continuous
      Monitoring), scope, authentication requirements, number of applications/domains, preferred
      timeline, additional information.
- [ ] **CTA-03**: Submitted requests are stored and visible to platform admins (reusing the
      existing platform-admin panel pattern), not just emailed and discarded.
- [ ] **CTA-04**: The submission form is CSRF-protected and rate-limited like every other
      state-changing form in the app (`extensions.limiter` pattern).

## Future Requirements

<!-- Deferred from this milestone, candidates for the next one. -->

- v1.2's Phase 10 (Live Verification Closeout, VERIFY-01..09 below) — reprioritized behind v1.3,
  not dropped. Real, valid, deferred work.
- Plugin/third-party check-extensibility system — deferred three times now (v1.0, v1.1, v1.2);
  still no concrete requirement or user request to build it.
- Self-hostable/open-core deployment model — still locked/undecided.
- A purchased custom domain for Glassbox (e.g. `glassbox.io`) — `glassboxsec.fly.dev` is this
  milestone's scope; a real domain requires a registrar purchase only the user can make.

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
| VERIFY-01..09 | Phase 10 | Deferred (not dropped) |
| REBRAND-01..05 | Phase 11 | Complete |
| FSCH-01..05 | Phase 12 | Complete |
| SCORE-01..05 | Phase 13 | Complete |
| CHECK-01..06 | Phase 14 | Complete |
| CTA-01..04 | Phase 15 | Pending |

**Coverage:** 32/32 requirements mapped (9 deferred from v1.2, 23 new for v1.3 across 5 phases).
