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

- [x] **HARD-01**: Rate limits (login, signup, invoice, and new API-token endpoints) enforce
      correctly even when the app runs with more than one gunicorn worker (shared rate-limit
      backend, not in-memory-only).

- [x] **HARD-02**: `run_advanced_scan`, `run_media_scan`, and `run_api_scan` each have automated
      test coverage for status transitions and error handling, matching what `run_scan` already
      has in `tests/test_scan_events.py`.

- [x] **HARD-03**: Org invite / role-change / domain-verification flows have automated test
      coverage beyond the current single rendering test in `tests/test_org_routes.py`.

- [x] **HARD-04**: Scoring logic (risk score, letter grade, `severity_counts`) is deduplicated into
      a single shared helper used by all scan orchestrators, including any new scheduled-scan path
      from Phase 1.

- [x] **HARD-05**: Dashboard, billing, org-admin, and scan_report pages visually match the rest of
      the app's existing design system (no remaining bland/legacy styling), completing the visual
      pass `CLAUDE.md` already flags as open.

## v1.1 Requirements

Requirements for milestone v1.1 ("Production Audit, Hardening & Redesign"). Each maps to exactly
one roadmap phase.

### New Scan Flow (SCANUX)

- [x] **SCANUX-01**: `/scan/new` (and its 4 sub-pages) present a "Select Domain → Select Type →
      Confirm Authorization → Start Scan" flow, replacing today's single-form-per-type pages.

- [x] **SCANUX-02**: User picks a target via a "Select Verified Domain" dropdown (populated from
      their org's verified `DomainVerification`/`Asset` records) instead of only free-typing a URL;
      free-text entry remains available for unclaimed/one-off targets.

- [x] **SCANUX-03**: The base scan type is labeled "Standard Scan" in the UI (code/route names
      unchanged) and each scan type shows plain-language availability labels: Included /
      Requires Verified Domain / Requires Paid Plan.

- [x] **SCANUX-04**: A tier-locked scan type shows an "Upgrade to Unlock" call-to-action instead of
      a disabled/absent control.

- [x] **SCANUX-05**: After a scan completes, the flow offers a clear "View Report" action from the
      same page context the user launched it from.

### Design System Consistency (DESIGN)

- [x] **DESIGN-01**: A single documented typography scale (Display/H1–H4/Body/Small/Caption/
      Label/Button/Nav) is defined in `base.html` and every template's headings/body text conform
      to it — no one-off `font-size`/`font-weight` overrides.

- [x] **DESIGN-02**: A single documented spacing scale is used for margin/padding across templates
      — arbitrary pixel values that don't map to the scale are removed where found.

- [x] **DESIGN-03**: Buttons, inputs/selects/textareas, cards, tables, badges/pills, and alert/
      warn/error/info boxes each have exactly one canonical style in `base.html` (or a shared
      partial) — divergent local overrides found during audit are consolidated into it.

- [x] **DESIGN-04**: Page container/content max-widths are consistent across dashboard, forms, and
      report pages — no page reads as unintentionally cramped or overly stretched relative to its
      siblings.

### Responsive & Mobile (RESP)

- [x] **RESP-01**: Every page renders without horizontal scroll, clipped text, or overlapping
      elements at 320px, 375px, 768px, and 1280px viewport widths, verified live.

- [x] **RESP-02**: Auth pages (login/signup/forgot-password/reset-password/verify-email) and org
      setup pages (create org, add domain, verify domain) have a polished, non-cramped mobile
      layout with the product name correctly positioned relative to the form.

- [x] **RESP-03**: The dashboard, org-admin, billing, and scan-report pages degrade gracefully on
      mobile — tables use a deliberate mobile strategy (scroll container, stacked cards, or
      collapsed columns), not silent overflow clipping.

- [x] **RESP-04**: The live scan-progress feed (SOC view) remains legible and usable at mobile
      widths (already partially verified in a prior session — re-confirm, don't assume).

### Accessibility (A11Y)

- [x] **A11Y-01**: Every form input has a properly associated `<label>` (for/id or wrapping), and
      every icon-only control has an accessible name (`aria-label` or visually-hidden text).

- [x] **A11Y-02**: Heading hierarchy (`h1`→`h2`→`h3`) is sequential and non-skipping on every major
      page template.

- [x] **A11Y-03**: All interactive elements (including any clickable `<div>`s found during audit)
      are reachable and operable via keyboard alone, with a visible focus state.

- [x] **A11Y-04**: Text and UI-element color contrast meets WCAG AA against the dark theme's
      background colors, including severity-colored finding text/badges.

### Security Re-Audit (SEC)

- [x] **SEC-01**: Every route that accepts an object ID (scan/report/asset/domain/invoice/token/
      org/user) is verified server-side to enforce ownership/org-membership before returning data —
      audited across GET/POST/PUT/DELETE and the `/api/v1/*` surface, with a regression test per
      route family where one doesn't already exist.

- [x] **SEC-02**: Every state-changing form/route (domain add/delete/verify, scan submission,
      billing actions, org/member changes, account changes, admin actions) is confirmed to carry
      CSRF protection, with any gap closed.

- [x] **SEC-03**: `is_ssrf_safe_hostname()` and its call sites are re-verified against redirect-
      following behavior in the scan HTTP clients — an SSRF-safe initial hostname that redirects to
      a private/loopback/metadata address must not be followed unchecked.

- [x] **SEC-04**: A targeted sweep for reflected/stored XSS confirms user-controlled strings (org
      name, domain name, finding detail/title text, AI-generated summary text, error messages) are
      never rendered as unescaped HTML.

- [x] **SEC-05**: A sweep of all database queries confirms no raw/string-interpolated SQL exists
      outside parameterized SQLAlchemy usage.

- [x] **SEC-06**: Report/media/CSV download and any file-path-accepting route are confirmed to
      reject path-traversal input (`../`, absolute paths) and cannot serve a file outside its
      intended directory.

- [x] **SEC-07**: Login/logout/invite/next-param redirect targets are confirmed to only ever
      redirect within the app's own origin (`_safe_next()`-style guard applied everywhere a
      redirect target is user-influenced).

- [x] **SEC-08**: A repo-wide secrets sweep confirms no API key/password/token/wallet credential is
      hardcoded in source, templates, JS, logs, or committed history added this milestone.

- [x] **SEC-09**: `billing.py`/`billing_routes.py` invoice verification is re-confirmed to reject
      replay, double-activation, amount tampering, and cross-org invoice access — extending the
      existing collision-retry test coverage if a gap is found.

- [x] **SEC-10**: 400/401/403/404/429/500 error responses are confirmed to never leak a stack
      trace, file path, SQL fragment, or environment variable in production mode.

### SEO & Metadata (SEO)

- [x] **SEO-01**: Public pages (marketing home, terms, privacy) each have a correct `<title>`, meta
      description, canonical URL, and Open Graph tags; authenticated/private pages do not.

- [x] **SEO-02**: A `robots.txt` allows crawling of public marketing pages and disallows
      authenticated app routes (dashboard/scan/org/billing/admin/account).

- [x] **SEO-03**: A `sitemap.xml` lists only public URLs — no dashboard/scan/report/org/billing/
      admin/account URL ever appears in it.

- [x] **SEO-04**: A complete favicon set (favicon.ico, PNG sizes, apple-touch-icon) resolves
      correctly in production, referenced from `base.html`.

### Performance (PERF)

- [x] **PERF-01**: Dashboard and org-admin queries that list scans/domains/members are audited for
      N+1 patterns and fixed (eager loading or a single query) where found.

- [x] **PERF-02**: Any unbounded list (scan history, asset list, org members, findings) that could
      grow large is paginated or otherwise capped, not loaded in full on every page view.

### Loading, Empty & Error States (STATE)

- [x] **STATE-01**: Every major page with a first-run/no-data condition (no assets, no scans, no
      domains, no invoices, no findings) shows a real empty-state message with a clear next action,
      not a blank area or raw empty table.

- [x] **STATE-02**: Every form shows a distinct in-flight submitting state (disabled + loading
      indicator) to prevent duplicate submission, consistent with the pattern already used on the
      auth forms.

- [x] **STATE-03**: A failed/errored scan, timed-out scan, and duplicate concurrent scan attempt
      each surface a clear, specific message to the user rather than a generic failure or silent
      stall.

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
| HARD-01 | Phase 4 | Complete |
| HARD-02 | Phase 4 | Complete |
| HARD-03 | Phase 4 | Complete |
| HARD-04 | Phase 4 | Complete |
| HARD-05 | Phase 4 | Complete |
| SCANUX-01 | Phase 5 | Complete |
| SCANUX-02 | Phase 5 | Complete |
| SCANUX-03 | Phase 5 | Complete |
| SCANUX-04 | Phase 5 | Complete |
| SCANUX-05 | Phase 5 | Complete |
| DESIGN-01 | Phase 6 | Complete |
| DESIGN-02 | Phase 6 | Complete |
| DESIGN-03 | Phase 6 | Complete |
| DESIGN-04 | Phase 6 | Complete |
| RESP-01 | Phase 7 | Complete |
| RESP-02 | Phase 7 | Complete |
| RESP-03 | Phase 7 | Complete |
| RESP-04 | Phase 7 | Complete |
| A11Y-01 | Phase 7 | Complete |
| A11Y-02 | Phase 7 | Complete |
| A11Y-03 | Phase 7 | Complete |
| A11Y-04 | Phase 7 | Complete |
| SEC-01 | Phase 8 | Complete |
| SEC-02 | Phase 8 | Complete |
| SEC-03 | Phase 8 | Complete |
| SEC-04 | Phase 8 | Complete |
| SEC-05 | Phase 8 | Complete |
| SEC-06 | Phase 8 | Complete |
| SEC-07 | Phase 8 | Complete |
| SEC-08 | Phase 8 | Complete |
| SEC-09 | Phase 8 | Complete |
| SEC-10 | Phase 8 | Complete |
| SEO-01 | Phase 9 | Complete |
| SEO-02 | Phase 9 | Complete |
| SEO-03 | Phase 9 | Complete |
| SEO-04 | Phase 9 | Complete |
| PERF-01 | Phase 9 | Complete |
| PERF-02 | Phase 9 | Complete |
| STATE-01 | Phase 9 | Complete |
| STATE-02 | Phase 9 | Complete |
| STATE-03 | Phase 9 | Complete |

**Coverage:**

- v1 requirements: 23 total — mapped to phases: 23 — unmapped: 0 ✓
- v1.1 requirements: 36 total — mapped to phases: 36 — unmapped: 0 ✓
- Combined: 59 total — mapped to phases: 59 — unmapped: 0 ✓

---
*Requirements defined: 2026-08-10 (v1.0), extended 2026-08-15 (v1.1)*
*Last updated: 2026-08-15 — v1.1 roadmap created (Phases 5-9), 100% requirement coverage validated*
