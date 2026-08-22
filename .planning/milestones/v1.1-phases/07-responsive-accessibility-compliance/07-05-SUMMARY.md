---
phase: 07-responsive-accessibility-compliance
plan: 05
subsystem: ui
tags: [css, accessibility, jinja, scan-report, thead-tbody, gauge, d-01, a11y-04]

# Dependency graph
requires:
  - phase: 07-responsive-accessibility-compliance
    plan: 01
    provides: "base.html's .gauge-fg.pass/.medium/.high/.critical severity stroke rules, consumed here by _gauge.html's class-ternary swap"
provides:
  - "scan_report.html's 23 diagnostic tables all carry correct table semantics: <tbody> on all 23, <thead> on the 21 column-header tables, scope=\"row\" (no <thead>) on the two key-value tables (TLS certificate, DNS/email records)"
  - "scan_report.html keeps all 23 tables as tables, wrapped in .table-scroll - D-01's named diagnostic-table exception, decided by a per-table audit rather than assumed, with the decision recorded inline in the template"
  - "_gauge.html emits a token-backed severity class (pass/medium/high/critical) instead of a hardcoded hex stroke, resolving against base.html's four .gauge-fg.* rules on all three including pages (dashboard, scan report, asset detail)"
  - "tests/test_report_table_semantics.py: -k thead_tbody (8 tests) / -k gauge (10 tests) selectors"
affects: [07-07-phase-gate-viewport-sweep]

# Actuals (#2632)
actuals:
  tokens: 33000
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Column-header table retrofit: <thead> wraps the existing header <tr>, <tbody> wraps the existing data-row loop (including its {% for %}/{% endfor %}), with a single <tbody> per table even when data rows come from more than one loop/conditional branch."
    - "Row-header (key-value) table retrofit: no <thead> at all; every <th> gets scope=\"row\" instead, with an inline comment above each of the two tables recording that the shape is deliberate so a later pass doesn't 'fix' it into a <thead> table."
    - "Gauge stroke colour resolved via a Jinja class ternary ({% set _gauge_severity = ... %}) at the same >=90/>=60/>=40/below-40 thresholds the old hex ternary used, appended to the existing gauge-fg class rather than replacing a stroke attribute value - base.html's CSS does the rest."

key-files:
  created:
    - tests/test_report_table_semantics.py
  modified:
    - templates/scan_report.html
    - templates/_gauge.html

key-decisions:
  - "Continued from a prior session's partial commit (a04b5f7, 14 of 23 tables done) rather than redoing it - audited all 23 tables individually against actual file content before touching anything, per the user's instruction not to assume the prior agent's state was correct. Confirmed a04b5f7's 14 tables (including both key-value tables) were already correct; the remaining 9 (SQLi login bypass + time-based, brute-force, stored-XSS variants, IDOR, media items, and the three API tables) were the ones actually missing wrappers."
  - "_gauge.html's fix had not been started by the prior session (still had the four hex-literal stroke ternary) - implemented in this session as its own commit."
  - "Test counting helper strips both Jinja `{# #}` and HTML `<!-- -->` comments before any substring/regex count - this plan's own required inline comments narrate the decision using the literal strings '<thead>', '<th>', '.table-scroll', and '.mobile-record-cards' in prose, which would otherwise inflate a naive count by exactly the number of comments (caught and fixed during test-writing: initial runs showed 24 not 23 for table-scroll, a spurious 5th <th> in the DNS/email block, etc. - all traced to this same class of false positive, not a markup bug)."
  - "Chose /dashboard (not a full 'base'-scan-type scan_report render) as the rendered call site for the four-band gauge class-resolution test - dashboard.html's gauge include reads Scan.risk_score directly with no other report-JSON scaffolding required, keeping the fixture minimal while still exercising a real page render through the real route."

patterns-established:
  - "_strip_comments()/_extract_block() helpers in tests/test_report_table_semantics.py, reusable by 07-06/07-07 if they need scoped source-level assertions against scan_report.html again."

requirements-completed: []  # Not marked complete - Task 3 (checkpoint:human-verify, gate=blocking) is pending human confirmation

coverage:
  - id: D1
    description: "All 23 tables in scan_report.html carry <tbody>; the 21 with a column-header row also carry <thead>"
    requirement: "RESP-03"
    verification:
      - kind: unit
        ref: "tests/test_report_table_semantics.py -k thead_tbody (8 tests) - source-level counts (23/21/23 tbody/thead/table, comment-stripped), table-scroll count unchanged, no mobile-record-cards/desktop-table anywhere"
        status: pass
    human_judgment: false
  - id: D2
    description: "The TLS certificate table and DNS/email records table are row-header tables: scope=\"row\" on every <th>, no <thead>"
    requirement: "A11Y-04"
    verification:
      - kind: unit
        ref: "tests/test_report_table_semantics.py::test_thead_tbody_tls_certificate_table_is_row_header_not_thead, ::test_thead_tbody_dns_email_table_is_row_header_not_thead, ::test_thead_tbody_key_value_tables_account_for_all_scope_row_th_cells"
        status: pass
    human_judgment: false
  - id: D3
    description: "No table on scan_report.html was converted to stacked cards; the Findings section still renders as .finding cards via finding_card()"
    requirement: "RESP-03"
    verification:
      - kind: unit
        ref: "tests/test_report_table_semantics.py::test_thead_tbody_no_mobile_record_cards_or_desktop_table, ::test_thead_tbody_rendered_report_still_shows_finding_card_markup"
        status: pass
    human_judgment: false
  - id: D4
    description: "_gauge.html emits pass/medium/high/critical at the unchanged >=90/>=60/>=40/below-40 thresholds, no hex literal remains, id/script/thresholds untouched, and the ring renders on all three including pages"
    requirement: "A11Y-04"
    verification:
      - kind: unit
        ref: "tests/test_report_table_semantics.py -k gauge (10 tests) - no-hex-literal source check, thresholds/id source checks, 4-band parametrised rendered class-resolution test via /dashboard, and a 3-page (dashboard/scan-report/asset-detail) gauge-fg smoke test"
        status: pass
    human_judgment: false
  - id: D5
    description: "Per-table 320px fits/scrolls/breaks audit of all 23 tables (accordions opened), and the four gauge-ring contrast-ratio measurements against WCAG's 3:1 non-text threshold"
    verification: []
    human_judgment: true
    rationale: "Task 3 is an explicit checkpoint:human-verify (gate=blocking) - rendered-pixel overflow behavior and contrast-checker-tool measurements cannot be proven by a rendered-HTML pytest assertion (this repo has no browser-driving tool). Left genuinely pending, not fabricated here, matching the 07-01/07-02/07-03 precedent for this same class of check."

# Metrics
duration: ~50min (continuation session; prior session's partial work reused where correct)
completed: 2026-08-18
status: complete
---

# Phase 7 Plan 5: scan_report.html Table Semantics + _gauge.html Token Migration Summary

**All 23 diagnostic tables on the scan-report page now carry correct `<thead>`/`<tbody>` (or, for the two key-value tables, `scope="row"` row headers with no `<thead>`) — purely additive markup, no table converted to cards — and `_gauge.html`'s four hardcoded hex stroke colours are replaced by a token-backed severity class resolving against `base.html`'s existing `.gauge-fg.pass/.medium/.high/.critical` rules.**

## Performance

- **Duration:** ~50 min (continuation from a prior session that stalled on an account-wide session-limit error after committing 14 of 23 tables)
- **Completed:** 2026-08-18
- **Tasks:** 2 of 3 (Task 3 is a `checkpoint:human-verify`, gate=blocking, genuinely pending)
- **Files modified:** 2 templates + 1 new test file

## Starting-State Audit

Before writing anything, every one of the 23 `<table>` elements in `templates/scan_report.html` was checked individually against the file as it actually existed (not assumed from the plan's line numbers, which had already shifted slightly from prior-session edits):

- `<table` count: 23 (unchanged throughout - no table added or removed)
- `<thead` (comment-stripped): 12 real tags present → needed 9 more
- `<tbody` (comment-stripped): 14 present → needed 9 more
- Both key-value tables (TLS certificate ~L280, DNS/email records ~L572) already had `<tbody>` + `scope="row"` + the deliberate-shape comment from the prior session's commit `a04b5f7` - confirmed correct, left untouched.
- `_gauge.html` still had all four hex literals (`#34d399`/`#fbbf24`/`#fb923c`/`#fb7185`) in its `stroke` ternary - the prior session had not started this half of the plan.

The 9 tables missing wrappers were all column-header tables in the `advanced`/`media`/`api` scan-type sections (not reachable in the `base`-scan-type sections the prior session had already finished): SQLi auth-bypass payloads, SQLi time-based payloads, brute-force attempts, stored-XSS variants, IDOR resources, media items (the widest table on the page, 7 columns), API schema/GraphQL introspection, API path wordlist, and API JS-discovered endpoints.

## Accomplishments

- Wrapped the header `<tr>` of each of the 9 remaining column-header tables in `<thead>`, and their data-row `{% for %}` loop in `<tbody>` - byte-identical cell content, classes, and Jinja logic; only wrapper tags added.
- Added the D-01-exception comment above the `{% if scan.scan_type == 'base' %}` block that opens "Detailed check output", recording that all 23 of this page's tables deliberately stay tables (not `.mobile-record-cards`) per 07-RESEARCH.md Pattern 3 / 07-UI-SPEC.md, and that the 320px audit result lives in this SUMMARY.
- `_gauge.html`: replaced the `stroke="{{ hex ternary }}"` attribute with `{% set _gauge_severity = 'pass' if score >= 90 else (...) %}` appended to the circle's existing `gauge-fg` class (`class="gauge-fg {{ _gauge_severity }}"`), at the identical four thresholds. `id`, `cx`/`cy`/`r`, `stroke-dasharray`/`stroke-dashoffset`, the `.gauge-num` block, and the entire inline animation `<script>` are byte-identical - the script only ever reads/writes `stroke-dasharray`/`strokeDashoffset` via `getElementById`, never `stroke`, so removing the attribute cannot affect the fill animation. Extended the partial's docstring comment to record the token migration and that the four old hex values were near-misses of `--pass`/`--medium`/`--high`/`--critical`, not deliberate distinct choices.
- `tests/test_report_table_semantics.py` (new, 18 tests): 8 selectable via `-k thead_tbody`, 10 via `-k gauge`. Covers comment-stripped source-level `<table>`/`<thead>`/`<tbody>`/`table-scroll` counts (23/21/23/23), absence of `mobile-record-cards`/`desktop-table`, both key-value tables' `scope="row"` shape with no `<thead>`, a rendered-report smoke test proving `finding_card` markup still renders, `_gauge.html`'s no-hex-literal/unchanged-thresholds/unchanged-id source checks, a parametrised rendered test asserting the resolved class for all four score bands (95→pass, 75→medium, 50→high, 20→critical) via `/dashboard`'s real include site, and a three-page smoke test confirming `gauge-fg` renders on dashboard, scan report, and asset detail.
- No CSS change anywhere - `git diff templates/base.html` across this entire plan's commits is empty, confirmed both by the acceptance criterion and directly (`git diff a04b5f7 HEAD -- templates/base.html` returns 0 lines).

## Task Commits

1. **Task 1 (continued): remaining 9 tables + D-01-exception comment** - `4cf358a` (feat)
2. **Task 2a: `_gauge.html` hex-to-class-ternary swap** - `268ae2f` (feat)
3. **Task 2b: `tests/test_report_table_semantics.py`** - `e6495f1` (test)

(Prior session's commit `a04b5f7` - the first 14 tables - predates this session and is unchanged/reused.)

Task 3 (`checkpoint:human-verify`, gate=blocking) has no code commit - it is a manual visual-verification + contrast-measurement gate. See "Next Phase Readiness" below.

## Files Created/Modified

- `templates/scan_report.html` - all 23 tables now carry correct semantics (12 → 21 `<thead>`, 14 → 23 `<tbody>`); one new inline comment recording the D-01 exception decision
- `templates/_gauge.html` - stroke ternary replaced with class ternary; docstring extended
- `tests/test_report_table_semantics.py` (new) - 18 tests across `-k thead_tbody` and `-k gauge`

## Decisions Made

- Audited the file's actual current state before touching anything rather than trusting the plan's line numbers or the prior session's stated progress - the prior session's commit message claimed specific tables were done, and this was independently re-verified against real byte counts (comment-stripped) before writing a single edit.
- Comment-stripping in the test module's counting helpers was necessary, not optional - the plan's own required prose (recording the row-header exception and the D-01 diagnostic-table decision) uses the literal strings this plan's assertions are counting, and a first draft of the tests initially failed against genuinely-correct markup for exactly this reason before the helper was added.
- Used `/dashboard` rather than a full `base`-scan-type `scan_report.html` render for the four-band gauge test - avoids constructing ~15 report-JSON keys the `base` branch of `scan_report.html` needs just to reach the gauge include, while still exercising one of the three real call sites end-to-end through the real route and login flow.

## Deviations from Plan

None - plan executed exactly as written for the automatable tasks. All must_haves, acceptance criteria and prohibitions were satisfied: no cell content, severity class, `<details>` default, or conditional branch changed (`git diff templates/scan_report.html` across both sessions' commits shows only wrapper tags / `scope="row"` / comments / re-indentation); no `.mobile-record-cards` or `desktop-table` introduced; `.table-scroll` count unchanged at 23; `templates/base.html` untouched; no fifth gauge colour or new token introduced; gauge thresholds unchanged.

## Known Stubs

None.

## Threat Flags

None - this plan touches only markup wrappers (`<thead>`/`<tbody>`/`scope="row"`) and a stroke-attribute-to-class swap on already-rendered, already-autoescaped data. No new endpoint, auth path, or trust boundary introduced (see the plan's own `<threat_model>` - all four in-scope threats were `mitigate`/`accept` dispositions already satisfied by the additive-markup-only constraint, which held).

## Issues Encountered

None beyond the test-writing false-positives described above (caught and fixed before commit, not a markup defect). Full suite (`python -m pytest -q`) is green: 548 passed, 0 failed, in a single combined run (no flakiness observed this session).

## User Setup Required

None - no external service configuration required. Task 3's live verification needs a local dev server (`set FLASK_APP=app.py`, `flask db upgrade`, `python app.py`), a browser with device-toolbar/responsive-mode support, and a contrast-checking tool (WebAIM Contrast Checker or browser DevTools' colour picker) - all already documented in the plan's `<how-to-verify>`.

## Next Phase Readiness

Tasks 1 and 2 (the full code deliverable) are complete, committed, and verified:

- `python -m pytest tests/test_report_table_semantics.py -q` - 18 passed
- `python -m pytest tests/test_report_table_semantics.py -k thead_tbody -q` - 8 passed
- `python -m pytest tests/test_report_table_semantics.py -k gauge -q` - 10 passed
- `python -m pytest tests/test_template_consistency.py tests/test_scan_routes.py -q` - 32 passed
- `git diff templates/base.html` - empty (confirmed both by this plan's commits alone and against the pre-session baseline `a04b5f7`)
- Full suite `python -m pytest -q` - **548 passed, 0 failed** (single combined run)

**Task 3 (`checkpoint:human-verify`, gate=blocking) is genuinely pending human confirmation - not fabricated here.** The plan's `<how-to-verify>` requires a human with a real browser to:

1. Run the app, open a completed **base scan's report** at 320px, open every `<details>` accordion, and classify each of the 23 tables `fits`/`scrolls`/`breaks` - paying particular attention to the media items table (7 columns, the widest on the page), the exposed-secrets table, the JWT tokens table, and the crawled-forms table. `scrolls` is an acceptable, expected outcome (D-01's named horizontal-scroll exception); `breaks` on any table is a finding to act on.
2. Confirm the page frame at 320px: no page-level horizontal scrollbar, the gauge renders with a visible ring and readable number/grade, the Findings `.finding` cards read cleanly, and every `<details>` summary is tappable with a visible focus ring.
3. Confirm the gauge on all three including pages (`/dashboard`, scan report, asset detail) shows a visible, non-black coloured ring with an animated fill, and that its colour now visually matches a same-severity-band pill elsewhere on the page.
4. Measure the four gauge-band stroke colours (>=90/>=60/>=40/<40) against their immediate background with a contrast-checking tool, reporting each ratio against WCAG's **3:1 non-text** threshold.

**Resume signal required:** "approved" plus (a) the per-table fits/scrolls/breaks list for all 23 tables, and (b) the four gauge contrast ratios. If any table comes back "breaks", name it first - per the plan, that is the one case where D-01's card exception may need to apply to this page after all, decided from the observation rather than a guess.

`requirements-completed` is left empty in this SUMMARY's frontmatter pending that confirmation, matching the `07-01`/`07-02`/`07-03` precedent. Once approved, RESP-03/A11Y-04 progress toward completion should be recorded in `REQUIREMENTS.md` at the phase gate (07-07).

## Self-Check: PASSED

- FOUND: `templates/scan_report.html` (all 23 tables carry correct semantics)
- FOUND: `templates/_gauge.html` (token-backed severity class, no hex literal)
- FOUND: `tests/test_report_table_semantics.py` (18 tests, all passing)
- FOUND: commit `4cf358a` (remaining 9 tables + D-01-exception comment)
- FOUND: commit `268ae2f` (`_gauge.html` hex-to-class-ternary swap)
- FOUND: commit `e6495f1` (test module)
- FOUND: prior-session commit `a04b5f7` (first 14 tables, confirmed correct and reused)
