---
phase: 07-responsive-accessibility-compliance
plan: 02
subsystem: ui
tags: [css, responsive, accessibility, jinja, org-admin, dual-markup, d-01, a11y-01]

# Dependency graph
requires:
  - phase: 07-responsive-accessibility-compliance
    plan: 01
    provides: "base.html's complete D-01 CSS surface (--bp-card, .mobile-record-cards/.record-card* family, the 430px table/card display swap, .icon-btn) and dashboard.html's Scan History as the proven tracer instance"
provides:
  - "org_admin.html's four record tables (Members, Pending Invitations, Verified domains, Scan History) and org_verify_domain.html's Domains table converted to the dual-markup table/card shape - the highest-risk half of D-01's conversion, since these five tables carry every destructive/CSRF-protected action in the org surface"
  - "The codebase's one remaining unlabelled form control (org_admin.html's `reason` deletion input) now carries `aria-label=\"Deletion reason for {{ dv.domain }}\"` in both markup blocks - closes A11Y-01's one real gap"
  - "org_verify_domain.html's long per-domain proof instructions (DNS TXT value / well-known URL+body) moved behind a native `<details class=\"record-card-details\">` disclosure on the mobile card - the first use of that class defined in 07-01's base.html CSS surface"
  - "tests/test_responsive_org_tables.py: -k org_admin / -k verify_domain selectors, plus a reusable `_ids_in(body)` rendered-body id-uniqueness helper other wave-2 plans (07-03, 07-05) can import instead of re-implementing"
affects: [07-06]

# Actuals (#2632)
actuals:
  tokens: 21000
  tasks: 3
  commits: 5

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Same dual-markup table/card pattern from 07-01, applied to five more record-list tables, four of which carry real destructive POST forms in their action cell/card - each form copied byte-identical (csrf_token, hidden discriminator fields, url_for target) into the card, with only the submit button re-classed from .verify-btn to .btn.{secondary|destructive}.block"
    - "aria-label over <label for>+id for a form control that exists inside two simultaneously-rendered DOM blocks - a duplicated id would be invalid HTML and would mis-bind label association, so the reason input gets an interpolated aria-label instead, in both blocks"
    - "Native <details><summary> for progressive disclosure of long per-record content (proof instructions) inside a mobile card - no JS, free keyboard operability and :focus-visible support via base.html's global rule"

key-files:
  created:
    - tests/test_responsive_org_tables.py
  modified:
    - templates/org_admin.html
    - templates/org_verify_domain.html

key-decisions:
  - "Task 1 committed one table at a time (4 commits) per the plan's explicit action instruction, rather than one commit for the whole task - isolates which table a mistake would belong to"
  - "org_verify_domain.html's Verify form's CSRF-preservation test asserts against the template SOURCE (`{{ add_form.csrf_token }}` appears twice), not the rendered body - that field is a WTForms FlaskForm field, and the test suite runs with WTF_CSRF_ENABLED=False (tests/conftest.py's TestConfig), so it renders empty in tests even though the form is genuinely CSRF-protected in production. org_admin.html's forms use the raw `{{ csrf_token() }}` template global instead (unconditional), so those are asserted against the rendered body directly."
  - "Zero-record / id-uniqueness assertions are scoped to the real markup class (`'class=\"card record-card\"' not in body`), never a bare `\"record-card\"` substring check - base.html's own embedded `<style>` block contains that prose/selector substring on every page regardless of whether any card renders (same false-positive class 07-01-SUMMARY.md's Rule 1 fix already documented)"

patterns-established:
  - "Reusable rendered-body id-uniqueness helper (`_ids_in`) in tests/test_responsive_org_tables.py - available for 07-03/07-05 to import rather than re-implement, per the plan's <output> instruction"

requirements-completed: []  # Not marked complete yet - Task 3 (checkpoint:human-verify, gate=blocking) is pending human confirmation

coverage:
  - id: D1
    description: "org_admin.html's four record tables (Members, Pending Invitations, Verified domains, Scan History) each render BOTH a semantic <thead>/<tbody> table (desktop-table wrapper) and a .mobile-record-cards list from the same collection, with matching card/row counts and no duplicate empty-state"
    requirement: "RESP-03"
    verification:
      - kind: unit
        ref: "tests/test_responsive_org_tables.py -k org_admin (7 tests) - dual-markup presence (4x each of desktop-table/mobile-record-cards/thead/tbody), card-count parity, CSRF preservation for revoke/resend/request-deletion, id uniqueness, empty-branch singularity, hud-grid anchor preserved"
        status: pass
      - kind: unit
        ref: "python -m pytest tests/test_org_routes.py tests/test_org_invite.py tests/test_domain_verification.py tests/test_template_consistency.py -q (59 passed)"
        status: pass
    human_judgment: false
  - id: D2
    description: "org_verify_domain.html's Domains table renders dual markup with the long proof instructions behind a native <details> disclosure; the Verify POST form (csrf_token, action=verify, domain_id) is preserved verbatim in both blocks; page keeps .wrap, never gains auth-wrap"
    requirement: "RESP-03"
    verification:
      - kind: unit
        ref: "tests/test_responsive_org_tables.py -k verify_domain (5 tests) - dual-markup presence, details/summary disclosure, hidden-field preservation (source-level CSRF check + rendered domain_id/action checks), id uniqueness, .wrap/not-auth-wrap, zero-domain warn-box singularity"
        status: pass
    human_judgment: false
  - id: D3
    description: "org_admin.html's deletion-reason text input (previously the codebase's one form control with no label, no id, and no aria-label) now has an accessible name in both markup blocks"
    requirement: "A11Y-01"
    verification:
      - kind: unit
        ref: "tests/test_responsive_org_tables.py::test_org_admin_request_domain_deletion_csrf_and_aria_label - every rendered `name=\"reason\"` input carries an aria-label; template contains `aria-label=\"Deletion reason for {{ dv.domain }}\"` exactly twice"
        status: pass
    human_judgment: false
  - id: D4
    description: "Live verification of all five tables at 320/375/768/1280px, keyboard tab order at 320px, and actually submitting a deletion request and a domain verify from a mobile card"
    verification: []
    human_judgment: true
    rationale: "Task 3 is an explicit checkpoint:human-verify (gate=blocking) - real viewport rendering, tab order, and an end-to-end POST submitted through a real browser cannot be proven by a rendered-HTML pytest assertion (this repo has no browser-driving tool); left genuinely pending per the plan's instruction, not fabricated here."

# Metrics
duration: ~35min
completed: 2026-08-18
status: complete
---

# Phase 7 Plan 2: Org-Admin Record Tables to Dual-Markup Table/Card Summary

**Converted org_admin.html's four record-list tables (Members, Pending Invitations, Verified domains, Scan History) and org_verify_domain.html's Domains table to the D-01 dual-markup table/card shape, with every destructive CSRF-protected form (resend/revoke invitation, request domain deletion, verify domain) preserved byte-identical in both markup blocks, the long per-domain proof instructions moved behind a native `<details>` disclosure, and the codebase's one remaining unlabelled form control given an accessible name.**

## Performance

- **Duration:** ~35 min
- **Completed:** 2026-08-18
- **Tasks:** 2 of 3 (Task 3 is a `checkpoint:human-verify`, gate=blocking, genuinely pending)
- **Files modified:** 2 templates + 1 new test file

## Accomplishments

- `templates/org_admin.html`'s four tables (Members, Pending Invitations, Verified domains, Scan History) each gained a `<thead>`/`<tbody>` desktop table (marked `table-scroll desktop-table`) plus a sibling `<ul class="mobile-record-cards">` iterating the identical collection, inside the same existing `{% if %}` conditional with the existing empty-state branch reused verbatim.
- Every destructive form moved into a card - Resend/Revoke invitation, Request Deletion - was copied with its `url_for(...)` action, hidden `csrf_token` input and (for deletion) the `reason` text input intact; only the submit button's class changed, from `.verify-btn`/`.verify-btn.danger` to `.btn.secondary.block`/`.btn.destructive.block`.
- The `reason` input (previously the app's only form control with no `<label>`, no `id`, no `aria-label`) now carries `aria-label="Deletion reason for {{ dv.domain }}"` in both the table cell and the card block - closes A11Y-01's one real gap.
- Scan History's card reproduces the pulsing `<span class="dot glow-pulse">` status-pill treatment exactly as the table cell renders it (Phase 4's HARD-05 lock), and the `class="card hud-grid"` anchor on the surrounding `<div>` is untouched (still exactly one occurrence).
- `templates/org_verify_domain.html`'s Domains table gained the same dual-markup treatment; its long per-domain proof block (the DNS TXT value, or the well-known URL + expected body) now lives inside a `<details class="record-card-details"><summary>How to prove ownership</summary>...</details>` on the card rather than on the card face - keyboard-operable for free via `base.html`'s global `:focus-visible` ring, no JS. The Verify form (`add_form.csrf_token`, hidden `action=verify`, hidden `domain_id`) is copied verbatim, submit button re-classed to `.btn.secondary.block`. The page still uses `.wrap`, never `.auth-wrap`.
- `tests/test_responsive_org_tables.py` (new, 12 tests): 7 selectable via `-k org_admin`, 5 via `-k verify_domain`. Covers dual-markup presence, card/row count parity, CSRF/hidden-field preservation for all four destructive actions, the `reason` input's aria-label coverage, the `class="card hud-grid"` anchor, empty-branch singularity, the `.wrap`/not-`auth-wrap` assertion, and a reusable `_ids_in(body)` id-uniqueness helper.
- No new CSS class, breakpoint, or template partial was added anywhere - every class used (`.mobile-record-cards`, `.record-card*`, `.btn.secondary/.destructive.block`, `.icon-btn`) already existed in `base.html` after plan 07-01.

## Task Commits

Each table was committed atomically, one at a time per the plan's explicit instruction so a mistake would be isolated to a single table:

1. **Task 1a: Members table** - `01cb560` (feat)
2. **Task 1b: Pending Invitations table** - `880b097` (feat)
3. **Task 1c: Verified domains table + reason input aria-label** - `cc7ec5b` (feat)
4. **Task 1d: Scan History table** - `a16f9e5` (feat)
5. **Task 2: org_verify_domain.html Domains table + tests/test_responsive_org_tables.py** - `b27002a` (feat)

Task 3 (`checkpoint:human-verify`, gate=blocking) has no code commit - it is a manual visual-verification gate. See "Next Phase Readiness" below.

## Files Created/Modified

- `templates/org_admin.html` - four tables gain `<thead>`/`<tbody>`, the `desktop-table` wrapper class, and a `.mobile-record-cards` sibling block each; the `reason` deletion input gains `aria-label` in both blocks
- `templates/org_verify_domain.html` - Domains table gains the same dual-markup shape, plus a `<details class="record-card-details">` progressive-disclosure block for its proof instructions
- `tests/test_responsive_org_tables.py` (new) - 12 tests across `-k org_admin` and `-k verify_domain`, plus a reusable `_ids_in()` helper

## Decisions Made

- Task 1's four tables were committed one at a time (4 separate commits) rather than as one Task-1 commit, following the plan's explicit "one table at a time, committing after each" instruction - a stricter granularity than the standard one-commit-per-task protocol, applied here because the plan called for it directly.
- org_verify_domain.html's CSRF-preservation test for the Verify form asserts against the **template source** (`{{ add_form.csrf_token }}` appears exactly twice), not the rendered body - `add_form.csrf_token` is a WTForms `FlaskForm` field that renders empty when `WTF_CSRF_ENABLED=False` (the test suite's config), even though the form is genuinely CSRF-protected against a real Flask-WTF-enabled app. org_admin.html's forms use the raw `{{ csrf_token() }}` template global instead, which renders unconditionally, so those four assertions check the rendered body directly.
- The "no cards / one empty message" and id-uniqueness assertions are scoped to the real card markup class (`'class="card record-card"'`) rather than a bare `"record-card"` substring - `base.html`'s own embedded `<style>` block contains that substring in prose/selectors on every page, a false-positive class already documented and fixed once in 07-01-SUMMARY.md.

## Deviations from Plan

None - plan executed exactly as written. All must_haves, acceptance criteria and prohibitions were satisfied: no `<a href>`/click-handler ever replaced a destructive `<form>`, no `csrf_token` was dropped or renamed, no `id` is duplicated between a table block and its card counterpart, no `confirm()` dialog was added, `org_verify_domain.html` kept `.wrap` and never gained `.auth-wrap`, `.verify-btn`/`.verify-btn.danger` sizing was never reused inside a card, `templates/base.html` was never touched, and no page-local override of `.card`/`.btn`/`table, th, td` was added.

## Issues Encountered

The full-suite run (`python -m pytest -q`, 530 tests) showed 3 failures on that one combined run: `tests/test_org_invite.py::test_decode_invite_token_rejects_tampered_signature` and two tests in `tests/test_responsive_asset_tables.py`. All three passed immediately when re-run in isolation (`test_org_invite.py`'s test alone: 1 passed; `test_responsive_asset_tables.py` alone: 16 passed) - this is the same full-suite-load flakiness pattern `06-01-SUMMARY.md` and `07-01-SUMMARY.md` already documented, not a regression from this plan's changes. `tests/test_responsive_asset_tables.py` belongs to plan 07-03 (`api_tokens.html`/`assets.html` dual-markup conversion), which is running concurrently in a separate agent on disjoint files (`git log` confirms its commit `c4342cd` landed mid-session, interleaved with this plan's commits) - this plan does not touch `asset_detail.html`, `api_tokens.html`, `assets.html`, or any `.py` file, so neither failure originates here. The targeted verification subset this plan owns (`tests/test_responsive_org_tables.py`, `tests/test_org_routes.py`, `tests/test_org_invite.py`, `tests/test_domain_verification.py`, `tests/test_template_consistency.py`) is green in every run, isolated and combined (59 passed).

## User Setup Required

None - no external service configuration required. Task 3's live verification needs a local dev server (`set FLASK_APP=app.py`, `flask db upgrade`, `python app.py`) and a browser with device-toolbar/responsive-mode support, both already documented in the plan's `<how-to-verify>`.

## Next Phase Readiness

Tasks 1 and 2 (the full code deliverable) are complete, committed, and verified:
- `python -m pytest tests/test_responsive_org_tables.py -q` - 12 passed
- `python -m pytest tests/test_responsive_org_tables.py -k org_admin -q` - 7 passed
- `python -m pytest tests/test_responsive_org_tables.py -k verify_domain -q` - 5 passed
- `python -m pytest tests/test_template_consistency.py -q` - green (Phase 4's org-admin `hud-grid`/status-pill assertions unaffected)
- `python -m pytest tests/test_org_routes.py tests/test_org_invite.py tests/test_domain_verification.py tests/test_template_consistency.py -q` - 59 passed
- Full suite `python -m pytest -q` - 527 passed / 3 failed on the combined run, all 3 confirmed pre-existing/unrelated flakiness (see Issues Encountered), 0 failed when each affected module is run in isolation

**Task 3 (`checkpoint:human-verify`, gate=blocking) is genuinely pending human confirmation - not fabricated here.** The plan's `<how-to-verify>` requires a human with a real browser and a logged-in org admin (org with 1+ other member, 1 pending invitation, 1 domain, 1 scan) to:

1. On `/org/admin` at 320px/375px: confirm all four sections show stacked cards (no horizontal scroll), verify Members/Pending Invitations/Verified domains/Scan History card content reads cleanly, confirm Resend/Revoke are full-width buttons (Revoke destructive-red), and **actually submit a deletion request on a throwaway domain** to prove the CSRF-protected form still works from the card.
2. On `/org/admin` at 768px/1280px: confirm all four sections render as tables again with visible column headers.
3. On `/org/verify-domain` at 320px: confirm the Domains card, the "How to prove ownership" disclosure opening cleanly, and **actually click Verify** on one domain to confirm the POST reaches the server.
4. Keyboard walkthrough at 320px on both pages: confirm each card's action receives focus exactly once with a visible ring, the `<details>` summary toggles with Enter/Space, and no second/invisible focus stop exists on the hidden desktop table.

`requirements-completed` is left empty in this SUMMARY's frontmatter pending that confirmation, matching the `07-01` precedent. Once approved, RESP-03/A11Y-01 should be marked complete in `REQUIREMENTS.md`.

**For plans 07-03/07-05 (still in flight in parallel agents):** `tests/test_responsive_org_tables.py`'s `_ids_in(body)` helper (a single `re.findall(r'id="([^"]*)"', body)` call) is available to import rather than re-implement for any id-uniqueness assertion those plans still need.

## Self-Check: PASSED

- FOUND: `templates/org_admin.html` (four tables converted)
- FOUND: `templates/org_verify_domain.html` (Domains table converted)
- FOUND: `tests/test_responsive_org_tables.py` (12 tests, all passing in isolation and as part of the combined 59-test verification subset)
- FOUND: commit `01cb560` (Members table)
- FOUND: commit `880b097` (Pending Invitations table)
- FOUND: commit `cc7ec5b` (Verified domains table + aria-label)
- FOUND: commit `a16f9e5` (Scan History table)
- FOUND: commit `b27002a` (org_verify_domain.html + test module)
