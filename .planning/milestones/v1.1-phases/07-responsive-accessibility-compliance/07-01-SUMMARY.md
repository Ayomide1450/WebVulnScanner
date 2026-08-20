---
phase: 07-responsive-accessibility-compliance
plan: 01
subsystem: ui
tags: [css, responsive, accessibility, jinja, base.html, dual-markup, d-01]

# Dependency graph
requires:
  - phase: 06-design-system-consistency
    plan: 01
    provides: base.html's design-token/component canon (.card, .btn family, h1-h4, table/th/td, :focus-visible)
provides:
  - "base.html's complete D-01 CSS surface: --bp-card token, .mobile-record-cards/.record-card* class family, the @media (max-width:430px) table/card display swap, four .gauge-fg severity stroke classes, and .icon-btn's 44px touch-target floor promoted from asset_detail.html"
  - "dashboard.html's Scan History as the proven tracer instance of the dual-markup table/card pattern - a semantic <thead>/<tbody> table for desktop and a curated .mobile-record-cards list for phone widths, both rendered from the same scans collection inside the same {% if scans %} conditional"
  - "tests/test_responsive_markup.py: -k table_cards (dual-markup presence) and -k base_css_surface (base.html CSS-surface regression lock) selectors for wave-2 plans to reuse"
affects: [07-02, 07-03, 07-04, 07-05, 07-06]

# Actuals (#2632)
actuals:
  tokens: 8500
  tasks: 3
  commits: 2

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Dual-markup table/card: every record-list table renders BOTH a <table> (wrapped .table-scroll.desktop-table) and a .mobile-record-cards <ul> from the same Jinja for-loop, swapped via a single @media (max-width:430px) display rule - never two data sources, never two conditionals"
    - "Documentation-only CSS custom property (--bp-card: 430px) paired with a literal breakpoint value in the @media rule, since media queries cannot consume custom properties"
    - "Promote-to-base.html-then-leave-local-duplicate-inert pattern reused from Phase 6 (.icon-btn promoted from asset_detail.html; the local copy is untouched, removed later by the plan that owns that file)"

key-files:
  created:
    - tests/test_responsive_markup.py
  modified:
    - templates/base.html
    - templates/dashboard.html

key-decisions:
  - "Card meta line renders risk score as '{{ s.risk_score }} / 100' (not the table's bare '-'-or-number cell) per 07-UI-SPEC.md's curated-subset guidance, joined with the existing &middot; separator convention"
  - "record-card-id given no id attribute (only a class) - both markup blocks are in the DOM simultaneously and a duplicated id would be invalid HTML, would break <label for> association on wave-2 pages that carry form controls (T-07-02 in the plan's threat register)"
  - ".icon-btn promoted to base.html now (Task 2) rather than deferred, even though dashboard.html itself never uses it - defined here so base.html, the sole wave-1-owned file, already carries the complete class surface before wave 2's five parallel plans start; asset_detail.html's local duplicate is left in place, inert, for plan 07-03 to remove"

patterns-established:
  - "Any future record-list table (invitations, domains, API tokens, assets, admin members) converts to this exact table+.mobile-record-cards pair rather than inventing its own mobile treatment"

requirements-completed: []  # Not marked complete yet - Task 3 (checkpoint:human-verify, gate=blocking) is pending human confirmation; see Next Phase Readiness.

coverage:
  - id: D1
    description: "dashboard.html's Scan History renders BOTH a semantic <thead>/<tbody> table (desktop-table wrapper) and a .mobile-record-cards list from the same scans collection, with matching row/card counts and no duplicate empty-state"
    requirement: "RESP-01, RESP-03"
    verification:
      - kind: unit
        ref: "tests/test_responsive_markup.py -k table_cards (5 tests) - dual-markup presence, thead/th nesting, 2-scan count parity, card content (target_url/status pill/detail link), zero-scan no-cards/no-tbody/exactly-one-empty-state"
        status: pass
      - kind: unit
        ref: "python -m pytest -q (502 passed, 0 failed)"
        status: pass
    human_judgment: false
  - id: D2
    description: "base.html carries the complete Phase 7 CSS surface (--bp-card, .mobile-record-cards/.record-card* family, the 430px media swap, four .gauge-fg severity stroke rules, .icon-btn) so none of wave 2's five plans need to edit base.html; .card/table,th,td/.btn.block/:focus-visible are byte-identical to their pre-plan state"
    requirement: "RESP-01, A11Y-04"
    verification:
      - kind: unit
        ref: "tests/test_responsive_markup.py -k base_css_surface (5 tests) - class/media-query presence, unaltered .gauge-fg base rule, .icon-btn touch-target floor, unchanged .btn.block/:focus-visible, unchanged .card/th,td source strings"
        status: pass
      - kind: unit
        ref: "git diff templates/base.html shows zero removed lines across both commits (additive-only)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Live verification of the table/card swap at 1280/768/431/430/375/320px, card count/order parity, keyboard Tab-order (no double-focus on the hidden table), empty-state singularity, and the measured .btn:disabled contrast ratio"
    verification: []
    human_judgment: true
    rationale: "Task 3 is an explicit checkpoint:human-verify (gate=blocking) - real viewport rendering, tab order, and composited-pixel contrast measurement cannot be proven by a rendered-HTML pytest assertion (this repo has no browser-driving tool); requires a human with a real browser. Not fabricated here per explicit instruction."

# Metrics
duration: ~10min (this session's continuation; full plan spans two work sessions - see Deviations)
completed: 2026-08-18
status: complete
---

# Phase 7 Plan 1: Responsive Foundation - Dual-Markup Table/Card Tracer Summary

**Established the complete D-01 dual-markup CSS surface in `base.html` (breakpoint token, six `.record-card*` classes, the 430px table/card display swap, four `.gauge-fg` severity stroke rules, and a promoted `.icon-btn` touch-target class) and proved it end-to-end on exactly one table — dashboard.html's Scan History now renders both a semantic `<thead>/<tbody>` table and a curated stacked-card list from the same `scans` collection — before eight more tables copy the pattern in wave 2.**

## Performance

- **Duration:** ~10 min this session (resuming after Task 1 was committed by the coordinator; see Deviations)
- **Completed:** 2026-08-18T13:48:33+01:00
- **Tasks:** 2 of 3 (Task 3 is a `checkpoint:human-verify`, gate=blocking, awaiting human confirmation)
- **Files modified:** 2 templates + 1 new test file

## Accomplishments

- `templates/base.html` gained the complete D-01 CSS surface: a documentation-only `--bp-card: 430px` custom property; `.mobile-record-cards` (default `display:none`, no bullet/indent); `.record-card` (padding/margin adjustments only, applied together with `.card` on the same `<li>` so background/border/border-radius stay `.card`'s); `.record-card-top`/`.record-card-id`/`.record-card-meta`/`.record-card-details`(+`summary`, 44px-tall)/`.record-card-action`(+`form`); the `@media (max-width: 430px)` swap hiding `.desktop-table` and showing `.mobile-record-cards` as a flex column; four `.gauge-fg.{pass,medium,high,critical}` token-based stroke rules additive to the existing base `.gauge-fg` rule; and `.icon-btn`/`.icon-btn .icon` promoted from `asset_detail.html`'s local-only copy as the phase-wide 44px touch-target floor for icon-only controls.
- `templates/dashboard.html`'s Scan History table converted to dual markup: the existing table gained `<thead>`/`<tbody>` (header row unchanged inside `<thead>`, the existing `{% for s in scans %}` loop unchanged inside `<tbody>`) and the `desktop-table` marker class on its `.table-scroll` wrapper; a sibling `<ul class="mobile-record-cards">` iterates the identical `scans` collection in the identical order, rendering one `<li class="card record-card">` per scan with a Understand→Act→View-details anatomy (target URL + status pill on the top row, curated scan-type/score/date meta line, full-width "View →" action button to the same route the table's row-link uses). Neither block carries an `id` attribute (T-07-02: avoids invalid duplicate-id HTML and `<label for>` mis-association on wave-2 pages with real form controls).
- `tests/test_responsive_markup.py` (new, 10 tests): 5 tests selectable via `-k table_cards` lock the dual-markup contract (both blocks present, `<th>` cells nested inside `<thead>`, 2-scan card/row count parity, card content — target URL, status pill, detail-link href — and the zero-scan case showing no cards, no `<tbody>`, exactly one `empty-state` block); 5 tests selectable via `-k base_css_surface` are a source-level regression lock (every `.record-card*` class + the media query + the token, the four `.gauge-fg` severity rules plus the unaltered base rule, `.icon-btn`'s touch-target floor, and byte-identical `.btn.block`/`:focus-visible`/`.card`/`th,td` source strings) so a wave-2 executor can confirm `base.html` hasn't drifted with one targeted `pytest` selection instead of five plans each independently discovering a missing class.
- Confirmed via `git diff templates/base.html` (both commits) that the diff is purely additive — zero lines removed from the pre-plan file, satisfying the plan's "no local-override regression" acceptance criterion for `.card`, `table`/`th, td`, `.btn.block`, and `:focus-visible`.

## Task Commits

Each task was committed atomically:

1. **Task 1: End-to-end dual-markup table/card slice — dashboard Scan History only** - `9182abe` (feat)
2. **Task 2: Confirm base.html's CSS surface is complete for wave 2 and carries no local-override regression** - `5008fcd` (feat)

**Plan metadata:** commit pending (this SUMMARY)

Task 3 (`checkpoint:human-verify`, gate=blocking) has no code commit — it is a manual visual-verification gate. See "Next Phase Readiness" below.

## Files Created/Modified

- `templates/base.html` - `--bp-card` token, six `.record-card*`/`.mobile-record-cards` classes, the 430px display-swap media query, four `.gauge-fg` severity stroke rules, `.icon-btn` promotion
- `templates/dashboard.html` - Scan History table gained `<thead>`/`<tbody>` and the `desktop-table` wrapper class; new sibling `<ul class="mobile-record-cards">` block
- `tests/test_responsive_markup.py` (new) - 10 tests across `-k table_cards` (dual-markup presence) and `-k base_css_surface` (CSS-surface regression lock)

## Decisions Made

- Card meta line renders the risk score as `"{{ s.risk_score }} / 100"` (not the table cell's bare `-`-or-number), per 07-UI-SPEC.md's curated-subset card anatomy, joined with the app's existing `&middot;` separator convention.
- No `id` attribute anywhere in either new markup block — both blocks coexist in the DOM simultaneously at all times (the `@media` rule only toggles `display`, both are always rendered), and a duplicate `id` would be invalid HTML and would break `<label for>` association on the wave-2 pages that do carry real form controls in their card actions (recorded as T-07-02 in the plan's threat register).
- `.icon-btn` promoted into `base.html` in Task 2 even though `dashboard.html` itself never consumes it — defined now because `base.html` is the sole wave-1-owned file and all five wave-2 plans run in parallel on top of it; `asset_detail.html`'s identical local copy is left untouched (inert duplicate) since plan 07-03 owns that file and removes it there.

## Deviations from Plan

### Session continuity (not a code deviation)

Task 1's implementation (the `base.html` D-01 CSS surface, `dashboard.html`'s dual-markup conversion, and the initial `tests/test_responsive_markup.py` test file — 5 `-k table_cards` tests) was completed and verified green in this session, but a transient tool/network stall occurred immediately before the commit step. The coordinating session verified the working-tree diff independently and committed it as `9182abe`. This executor verified that commit's authenticity before continuing (`git cat-file -t 9182abe`, `git show --stat 9182abe` — file set and content matched exactly what had just been authored and tested) rather than assuming the claim, then resumed from Task 2: promoting `.icon-btn` into `base.html`, confirming the additive-only diff, and extending `tests/test_responsive_markup.py` with the 5 `-k base_css_surface` tests (committed as `5008fcd`). No task was skipped, redone, or fabricated — both commits are real, both are traceable to this plan's action items, and the full suite (502 passed) was re-verified after each.

### Auto-fixed Issues (Rule 1 — test-correctness bugs found during Task 1 verification)

**1. [Rule 1] Substring false-positive in the zero-scan empty-state test**
- **Found during:** first run of `tests/test_responsive_markup.py`
- **Issue:** `assert "record-card" not in body` and `assert body.count("empty-state") == 1` both failed against a correct implementation — `base.html`'s own embedded `<style>` block contains the prose substrings `"...mobile-record-cards block..."` and CSS selectors `.empty-state {` / `.empty-state .icon {` on every page, scans or not, so a bare-substring check has false matches unrelated to actual card/row markup.
- **Fix:** Scoped both assertions to the real markup: `'class="card record-card"' not in body` and `body.count('class="empty-state"') == 1`.
- **Files modified:** `tests/test_responsive_markup.py`
- **Commit:** `9182abe`

None of the above are architectural — both are test-assertion corrections made before the commit, not template/CSS changes.

## Issues Encountered

The full-suite `python -m pytest -q` run (502 passed, 0 failed, run twice — once mid-session, once as the final gate) surfaced 5 transient failures in `tests/test_scheduler.py` on the interim full-suite run only; `tests/test_scheduler.py` run in isolation passed 16/16 immediately after. This matches the exact flakiness pattern documented in `06-01-SUMMARY.md`'s Issues Encountered (background-thread/real-DNS timing sensitivity under full-suite load, not a regression from this plan's CSS/template-only diff) — this plan touches zero `.py` files. The final full-suite run (502 passed, 0 failed, no scheduler flakiness) is the authoritative result recorded above.

## User Setup Required

None — no external service configuration required. Task 3's live verification needs a local dev server (`set FLASK_APP=app.py`, `flask db upgrade`, `python app.py`) and a browser with device-toolbar/responsive-mode support, both already documented in the plan's `<how-to-verify>`.

## Next Phase Readiness

Tasks 1 and 2 (the full code deliverable) are complete, committed, and verified: `python -m pytest -q` is green (502 passed, 0 failed — 10 more than the 492-test pre-plan baseline, all new tests belonging to this plan's `tests/test_responsive_markup.py`), `tests/test_responsive_markup.py -k table_cards` (5 tests) and `-k base_css_surface` (5 tests) both pass in isolation, and `git diff templates/base.html` across both commits shows zero removed lines (purely additive against `.card`, `table`/`th, td`, `.btn.block`, `:focus-visible`).

**Task 3 (`checkpoint:human-verify`, gate=blocking) is genuinely pending human confirmation — not fabricated here.** The plan's `<how-to-verify>` requires a human with a real browser to:

1. Load `/dashboard` (a user with 2+ scans) and confirm the table renders (no card list, no horizontal scroll) at 1280px, 768px, and 431px.
2. Confirm the swap to stacked cards happens at exactly 430px (report which markup is visible at exactly 430px vs. exactly 431px).
3. At 375px/320px, confirm cards read cleanly (target URL wraps/ellipsizes rather than overflowing, status pill doesn't overlap the URL, meta line is legible, "View" button is full-width and tappable) and the page has no horizontal scrollbar.
4. Confirm card count/order matches the table's row count/order (newest first).
5. Confirm keyboard Tab order at 320px visits each card's "View" link exactly once with a visible focus ring — never a second, invisible focus stop on the hidden table.
6. Confirm the empty-state case shows exactly one "No scans yet" message, not two.
7. **Measure and report the actual `.btn:disabled` composited contrast ratio** (via WebAIM Contrast Checker or DevTools color picker, sampling `/scan/new/base`'s disabled submit button) — `.btn:disabled { opacity: .5 }` is suspected of dropping a passing color below 4.5:1 once composited over `.card`'s gradient; this is a `backstop`-verification must_have from the plan and cannot be computed from the token value alone.

`requirements-completed` is left empty in this SUMMARY's frontmatter pending that confirmation, matching the `06-01`/`06-04` precedent. Once approved (including the measured contrast ratio from item 7 — and, if it's below 4.5:1, the `.btn:disabled` opacity value should be raised, e.g. `.5` → `.6`, within the existing token set, before wave 2 copies this pattern), RESP-01/RESP-03/A11Y-04 should be marked complete in `REQUIREMENTS.md` and wave 2's five parallel plans can begin — `base.html` is confirmed to already carry every class/token they will reference.

## Self-Check: PASSED

- FOUND: `.planning/phases/07-responsive-accessibility-compliance/07-01-SUMMARY.md`
- FOUND: commit `9182abe` (Task 1)
- FOUND: commit `5008fcd` (Task 2)
- FOUND: `tests/test_responsive_markup.py` (10 tests, all passing in isolation and as part of the 502-test full suite)
