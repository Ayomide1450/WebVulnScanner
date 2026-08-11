# Requirements: WebVulnScanner

**Defined:** 2026-08-10
**Core Value:** Security engineers can trust WebVulnScanner to run safe, authorization-gated,
non-destructive scans against their own infrastructure and get findings they can act on — without
it ever weakening its safety guarantees to become a general attack tool.

## v1 Requirements

Requirements for this milestone ("production ready for security engineers and teams"). Each maps
to exactly one roadmap phase.

### Asset Inventory & Continuous Scanning (ASSET)

- [x] **ASSET-01**: User can register a domain/target as a persistent "Asset" (name, target URL,
      hostname) tied to their org — distinct from submitting a one-off manual scan.

- [x] **ASSET-02**: Asset registration enforces the same authorization-checkbox and
      `is_ssrf_safe_hostname()` gating as manual scan submission — no weaker safety check for the
      new entry point.

- [x] **ASSET-03**: User can configure a recurring scan schedule for an Asset (cadence, e.g.
      daily/weekly/monthly, plus which scan type to run).

- [x] **ASSET-04**: A scheduled scan runs automatically at its configured cadence without the user
      manually starting it, producing a new `Scan`/`Report` linked to that Asset.

- [x] **ASSET-05**: User can view an Asset's scan history/trend across multiple scheduled runs
      (risk score/findings over time), not just the latest single scan.

- [x] **ASSET-06**: User can pause, resume, or delete an Asset's schedule.
- [x] **ASSET-07**: Scheduled scan execution respects the same tier-entitlement gating
      (`entitlements.py`) as manually triggered scans — a Free-tier Asset cannot silently run
      Paid/Org-verified checks on a schedule.

- [x] **ASSET-08**: A scheduling mechanism exists that periodically checks due schedules and
      triggers scans automatically, compatible with the existing single-worker threaded-gunicorn
      Render deployment (no required re-architecture to a different execution model).

### API & CLI Access (API)

- [x] **API-01**: Org admin can generate and revoke API tokens scoped to their org, separate from
      session-cookie auth.

- [x] **API-02**: Authenticated API requests can list an org's Assets and each Asset's latest scan
      status/report summary.

- [x] **API-03**: Authenticated API requests can trigger a new scan against an existing Asset,
      subject to the same authorization/SSRF/tier gating as the web UI.

- [x] **API-04**: Authenticated API requests can retrieve a completed scan's full report
      (findings, score) as structured JSON.

- [x] **API-05**: API endpoints are rate-limited and tier-gated consistent with existing
      entitlement rules — no API path that bypasses tier restrictions enforced elsewhere.

- [x] **API-06**: A CLI tool (thin wrapper over the API) lets a user authenticate, list assets,
      trigger a scan, and fetch a report from the command line.

### Compliance & Framework Reporting (COMP)

- [x] **COMP-01**: Each check/finding category is tagged with the OWASP Top 10 category (and/or
      ASVS control) it maps to.

- [x] **COMP-02**: A scan report includes a compliance-framework view — findings grouped/filterable
      by framework category, not only by severity.

- [x] **COMP-03**: User can view a per-Asset compliance-coverage summary across its scan history
      (which framework categories have been checked, and which are currently failing).

- [x] **COMP-04**: Compliance mapping data is maintained per check in a way that stays in sync as
      new checks are added, following the same coverage-regression-test convention already used
      for `CHECK_LABELS`/`CHECK_CATEGORY`.

### Production Hardening & Reliability (HARD)

- [ ] **HARD-01**: Rate limits (login, signup, invoice, and new API-token endpoints) enforce
      correctly even when the app runs with more than one gunicorn worker (shared rate-limit
      backend, not in-memory-only).

- [ ] **HARD-02**: `run_advanced_scan`, `run_media_scan`, and `run_api_scan` each have automated
      test coverage for status transitions and error handling, matching what `run_scan` already
      has in `tests/test_scan_events.py`.

- [ ] **HARD-03**: Org invite / role-change / domain-verification flows have automated test
      coverage beyond the current single rendering test in `tests/test_org_routes.py`.

- [ ] **HARD-04**: Scoring logic (risk score, letter grade, `severity_counts`) is deduplicated into
      a single shared helper used by all scan orchestrators, including any new scheduled-scan path
      from Phase 1.

- [ ] **HARD-05**: Dashboard, billing, org-admin, and scan_report pages visually match the rest of
      the app's existing design system (no remaining bland/legacy styling), completing the visual
      pass `CLAUDE.md` already flags as open.

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Extensibility

- **PLUGIN-01**: Third-party/user-authored custom checks can be registered without editing
  `checks.py` directly.

- **PLUGIN-02**: A documented plugin contract exists (input/output shape, entitlement-tier
  assignment, safety requirements) for community or internal check authors.

### Platform Model

- **HOST-01**: Users can self-host WebVulnScanner without the crypto-invoice billing/SaaS
  requirement (open-core split).

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Plugin/check-extensibility system | Ranked gap #2 in prior analysis, but no concrete requirement or user request this milestone; deferred to v2 (see PLUGIN-01/02) |
| Self-hostable/open-core deployment model | Billing/SaaS shape is locked per project decision; not under reconsideration this milestone (see HOST-01 in v2) |
| Replacing crypto-invoice billing with a different payment processor | Explicitly locked constraint, not a variable to redesign around |
| DNS-rebinding-proof SSRF pinning (resolving-and-pinning the exact IP for the scan request) | Documented, accepted residual gap in existing code; not raised as a requirement for this milestone |
| Vercel-compatible bounded-request redesign of the SSE progress feed | Render is the confirmed primary deployment target; Vercel is a partial/limited alternate with known, documented limitations that aren't blocking this milestone |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| ASSET-01 | Phase 1 | Complete |
| ASSET-02 | Phase 1 | Complete |
| ASSET-03 | Phase 1 | Complete |
| ASSET-04 | Phase 1 | Complete |
| ASSET-05 | Phase 1 | Complete |
| ASSET-06 | Phase 1 | Complete |
| ASSET-07 | Phase 1 | Complete |
| ASSET-08 | Phase 1 | Complete |
| API-01 | Phase 2 | Complete |
| API-02 | Phase 2 | Complete |
| API-03 | Phase 2 | Complete |
| API-04 | Phase 2 | Complete |
| API-05 | Phase 2 | Complete |
| API-06 | Phase 2 | Complete |
| COMP-01 | Phase 3 | Complete |
| COMP-02 | Phase 3 | Complete |
| COMP-03 | Phase 3 | Complete |
| COMP-04 | Phase 3 | Complete |
| HARD-01 | Phase 4 | Pending |
| HARD-02 | Phase 4 | Pending |
| HARD-03 | Phase 4 | Pending |
| HARD-04 | Phase 4 | Pending |
| HARD-05 | Phase 4 | Pending |

**Coverage:**

- v1 requirements: 23 total
- Mapped to phases: 23
- Unmapped: 0 ✓

---
*Requirements defined: 2026-08-10*
*Last updated: 2026-08-10 after initial roadmap creation*
