# Requirements: WebVulnScanner — v1.2 Live Verification Closeout

**Defined:** 2026-08-20
**Core Value:** Security engineers can trust WebVulnScanner to run safe, authorization-gated,
non-destructive scans against their own infrastructure and get findings they can act on — without
it ever weakening its safety guarantees to become a general attack tool.

**Milestone Goal:** v1.1 shipped its full requirement scope but closed with an explicit
verification gap: the `checkpoint:human-verify` gates for phases 5, 6, 7, and 9 were never
actually run in a live browser (an override was recorded in `STATE.md`/`PROJECT.md` at milestone
close, per user instruction not to block on them). Every underlying implementation is done and
test-covered — this milestone is exclusively about actually performing that live verification
against the real Fly deployment (`https://webvulnscanner.fly.dev`) and fixing whatever real defect
it surfaces. No new feature work.

## v1 Requirements

### Verification (VERIFY)

- [ ] **VERIFY-01**: A live four-width sweep (320px, 375px, 768px, 1280px) of every page in the
      app against the real Fly deployment confirms no horizontal scroll, clipped text, or
      overlapping elements — closing RESP-01's original checkpoint (07-07-PLAN.md's checklist).
- [ ] **VERIFY-02**: Auth pages (login/signup/forgot-password/reset-password/verify-email) and org
      setup pages (create org, add domain, verify domain) are confirmed live to show a polished,
      non-cramped mobile layout with the product name correctly positioned — closing RESP-02.
- [ ] **VERIFY-03**: The dashboard, org-admin, billing, and scan-report pages' table strategies
      (scroll container, stacked cards) are confirmed live to work without silent overflow
      clipping at mobile widths — closing RESP-03.
- [ ] **VERIFY-04**: The live scan-progress feed (SSE) is confirmed against a real running scan at
      1280px, 768px, 480px, and 320px per 07-07-PLAN.md's exact breakpoint checklist — closing
      RESP-04.
- [ ] **VERIFY-05**: A keyboard-only walkthrough confirms every interactive element (including any
      clickable non-native controls) is reachable and operable via keyboard alone with a visible
      focus state — closing A11Y-03.
- [ ] **VERIFY-06**: Text and UI-element color contrast (including severity-colored finding
      text/badges) is confirmed to meet WCAG AA against the dark theme's background colors using a
      real contrast-checking tool, not token math alone — closing A11Y-04.
- [ ] **VERIFY-07**: The New Scan wizard (Phase 5: Select Domain → Select Type → Confirm
      Authorization → Start Scan, including the Advanced Smart Setup path and View Report
      reachability for every scan type) is confirmed working end-to-end in a live browser against
      the real deployment.
- [ ] **VERIFY-08**: Phase 9's UX states — empty states, submitting states, duplicate-concurrent-
      scan rejection, and scan timeout — are each confirmed to actually surface their intended
      message live, not just pass their unit-test assertions.
- [ ] **VERIFY-09**: Any real defect found by VERIFY-01 through VERIFY-08 is fixed and covered by
      a regression test/lock so it can't silently regress again.

## Future Requirements

<!-- Deferred from this milestone, candidates for the next one. -->

- Plugin/third-party check-extensibility system — deferred twice now (v1.0, v1.1); still no
  concrete requirement or user request to build it, revisit for v1.3.
- Self-hostable/open-core deployment model — still locked/undecided, not part of this milestone.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Any new feature, redesign, or capability | This milestone is exclusively closing v1.1's carried-forward verification debt — see Milestone Goal above |
| Fixing anything not surfaced by the live sweep itself | Prevents scope creep back into a full redesign; only real defects the sweep actually finds get fixed (VERIFY-09) |
| Replacing crypto-invoice billing, self-hostable deployment, or any other v1.0/v1.1-locked constraint | Still explicitly locked, not under reconsideration |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| VERIFY-01 | Phase 10 | Pending |
| VERIFY-02 | Phase 10 | Pending |
| VERIFY-03 | Phase 10 | Pending |
| VERIFY-04 | Phase 10 | Pending |
| VERIFY-05 | Phase 10 | Pending |
| VERIFY-06 | Phase 10 | Pending |
| VERIFY-07 | Phase 10 | Pending |
| VERIFY-08 | Phase 10 | Pending |
| VERIFY-09 | Phase 10 | Pending |

**Coverage:** 9/9 requirements mapped to Phase 10 (single phase — this milestone is narrow and
verification-only, not a multi-phase feature build).
