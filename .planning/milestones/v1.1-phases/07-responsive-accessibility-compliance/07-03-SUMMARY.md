---
phase: 07-responsive-accessibility-compliance
plan: 03
subsystem: ui
tags: [css, responsive, accessibility, jinja, api-tokens, assets, dual-markup, d-01, a11y-01]

# Dependency graph
requires:
  - phase: 07-responsive-accessibility-compliance
    plan: 01
    provides: "--bp-card breakpoint token, .record-card* mobile-card CSS pattern, .icon-btn promoted to base.html"
provides:
  - "api_tokens.html Tokens table, assets.html Assets table, asset_detail.html Scan history
    table all in dual markup (desktop table + mobile record-cards)"
  - "asset_detail.html Compliance coverage table gains thead/tbody only (D-01 triage: no
    per-row action, stays a table at every width)"
  - "asset_detail.html's local .icon-btn rule removed - resolves against base.html's
    promoted rule (07-01)"
affects: [07-06-a11y-hierarchy-and-heading-fixes, 07-07-phase-gate-viewport-sweep]

tech-stack:
  added: []
  patterns:
    - "Same dual-markup pattern as 07-02: <div class='table-scroll desktop-table'> wrapping
      a <thead>/<tbody> table, plus a sibling <ul class='mobile-record-cards'> iterating the
      identical collection in the identical order - CSS (base.html's --bp-card media query)
      decides which renders, not template logic."
    - "Destructive-action forms (token revoke) copied verbatim into the card block - same
      csrf_token, same class name (revoke-token-form), same data-token-name attribute - so
      the existing querySelectorAll('.revoke-token-form') confirm()-dialog JS fires
      identically whether the click originates from the desktop row or the mobile card."

key-files:
  created: []
  modified:
    - templates/api_tokens.html
    - templates/assets.html
    - templates/asset_detail.html
    - tests/test_responsive_asset_tables.py

key-decisions:
  - "asset_detail.html's Compliance coverage table (OWASP category -> status) stays a table
    at every width, gains thead/tbody only - it's a two-column diagnostic dump with no
    per-row action or detail view to link a card to, so D-01's card-conversion rule doesn't
    apply (documented inline in the template as a comment, matching 07-RESEARCH.md's
    'curated-vs-diagnostic table triage' guidance)."
  - "asset_detail.html's local .icon-btn rule deleted only after confirming byte-identical
    to base.html's promoted rule (07-01) - the three icon-only asset actions (pause/resume/
    delete) keep their 44px touch target and per-asset aria-label wording unchanged."

# Metrics
duration: unknown (executed across a background agent that stalled twice on transient
  errors - network error, then account-wide session limit - before writing this SUMMARY;
  code was independently verified and committed by the session coordinator)
completed: 2026-08-18
status: complete

coverage:
  - id: D1
    description: "api_tokens.html Tokens table, assets.html Assets table, asset_detail.html
      Scan history table all render as stacked cards at 320px (no horizontal scroll) and as
      semantic thead/tbody tables at 1280px"
    requirement: "RESP-03"
    verification:
      - kind: unit
        ref: "tests/test_responsive_asset_tables.py (38 tests, full suite green: 530 passed)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Token-revoke form copied into the mobile card keeps class=revoke-token-form,
      data-token-name, POST method, and hidden csrf_token - the existing confirm()-dialog JS
      fires identically from card or table row"
    requirement: "A11Y-01"
    verification:
      - kind: unit
        ref: "tests/test_responsive_asset_tables.py assertions on class/attribute/action/csrf_token presence"
        status: pass
    human_judgment: false
  - id: D3
    description: "asset_detail.html's icon-only pause/resume/delete controls resolve against
      base.html's promoted .icon-btn (44px touch target) with per-asset aria-label text intact"
    requirement: "A11Y-04"
    verification:
      - kind: unit
        ref: "tests/test_responsive_asset_tables.py aria-label assertions"
        status: pass
    human_judgment: false
  - id: D4
    description: "Live visual/contrast/keyboard confirmation at 320px across all three pages,
      including actually tapping Revoke on a mobile card and seeing the confirm() dialog"
    verification: []
    human_judgment: true
    rationale: "Task 3 is an explicit checkpoint:human-verify (gate=blocking) covering
      rendered-pixel contrast (.pill.not-checked opacity-blend over .card gradient) and
      long-value wrap/ellipsis behavior at 320px - neither is provable from static markup,
      matching the 07-01/07-02 precedent for this same class of check."

# Self-Check
