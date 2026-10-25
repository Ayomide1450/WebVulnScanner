---
phase: 03-compliance-framework-reporting
plan: 02
subsystem: compliance-reporting
tags: [owasp, jinja, flask, findings, grouping, query-param-allowlist]

# Dependency graph
requires:
  - phase: 03-compliance-framework-reporting (plan 01)
    provides: "Finding.check_name field, CHECK_COMPLIANCE dict, and the inline
      compliance pill already wired into scan_report()'s render context"
provides:
  - "GROUPING_MODES allowlist tuple (glassbox/scan_routes.py) - only
    'severity'/'compliance' ever reach render_template() or the page"
  - "group_findings_by_compliance(findings, mapping) pure helper - buckets
    findings by OWASP category, Uncategorized always last, preserves arrival
    order within a group"
  - "finding_card(f) Jinja macro (templates/scan_report.html) - single
    rendering path shared by both grouping branches"
  - "'Group by:' toggle control + compliance-grouped accordion branch on
    scan_report.html, reachable via ?group=compliance"
affects: [03-03-per-asset-compliance-coverage]

# Actuals (#2632)
actuals:
  tokens: 4400
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Server-computed grouping over template-computed sorting: Jinja's
      sort(attribute=...) can't sort on a computed key (OWASP category is
      derived from CHECK_COMPLIANCE[f.check_name], not a field already on
      the finding dict), so grouping happens in a pure Python helper and the
      template just iterates ready-made (category, [findings]) pairs. This
      also makes the grouping unit-testable without rendering a page - same
      shape as diff_reports()/index_by_key() already in this module."
    - "Query-parameter allowlist coercion: request.args.get('group') is
      coerced against a module-level GROUPING_MODES tuple before it ever
      reaches render_template() or the page; toggle hrefs are built with
      url_for(), never by echoing request.args or concatenating request.url."
    - "One finding-card macro, two grouping branches: the existing inline
      finding markup was extracted into finding_card(f) and called from both
      the severity loop and the new compliance loop, so the compliance pill,
      escaping discipline, and severity badge can't drift between modes."

key-files:
  created: []
  modified:
    - glassbox/scan_routes.py
    - templates/scan_report.html
    - tests/test_compliance.py

key-decisions:
  - "Toggle active/inactive classes written as two literal `btn secondary`/
    `btn ghost` blocks (if/else) rather than a computed ternary expression -
    keeps the literal class strings greppable/auditable in the template
    source and matches the plan's acceptance-criteria grep checks exactly."
  - "compliance_groups is computed and passed to the template only when the
    coerced mode is 'compliance' (empty list otherwise), so the template's
    branch condition is the mode itself, not data presence - a future bug
    that leaves compliance_groups non-empty in severity mode can't leak
    into the wrong view."

patterns-established: []

requirements-completed: [COMP-02]

coverage:
  - id: D1
    description: "A scan report with findings offers a 'Group by:' control
      with Severity and Compliance options."
    requirement: COMP-02
    verification:
      - kind: integration
        ref: "tests/test_compliance.py::test_scan_report_group_param_matrix_returns_200"
        status: pass
    human_judgment: false
  - id: D2
    description: "No group parameter renders the pre-existing severity-
      grouped accordion; group=banana falls back to the same severity mode
      silently and returns 200 (no error page, no echoed value)."
    requirement: COMP-02
    verification:
      - kind: integration
        ref: "tests/test_compliance.py::test_scan_report_unrecognized_group_value_matches_no_param_grouping_mode"
        status: pass
      - kind: integration
        ref: "tests/test_compliance.py::test_scan_report_group_param_matrix_returns_200"
        status: pass
    human_judgment: false
  - id: D3
    description: "group=compliance renders one accordion group per OWASP
      category present among the findings, using the same accordion markup
      the severity grouping uses."
    requirement: COMP-02
    verification:
      - kind: integration
        ref: "tests/test_compliance.py::test_scan_report_compliance_mode_shows_owasp_heading_and_finding_title"
        status: pass
    human_judgment: false
  - id: D4
    description: "Findings whose check_name has no CHECK_COMPLIANCE mapping
      group under an explicit 'Uncategorized' heading rather than being
      dropped; the heading is absent when every finding is mapped (D-04)."
    requirement: COMP-02
    verification:
      - kind: integration
        ref: "tests/test_compliance.py::test_scan_report_compliance_mode_shows_uncategorized_heading_for_unmapped_finding"
        status: pass
      - kind: integration
        ref: "tests/test_compliance.py::test_scan_report_compliance_mode_omits_uncategorized_heading_when_all_mapped"
        status: pass
      - kind: unit
        ref: "tests/test_compliance.py::test_group_findings_by_compliance_uncategorized_group_is_always_last"
        status: pass
    human_judgment: false
  - id: D5
    description: "The grouping control is rendered only when the report has
      at least one finding; a zero-finding report shows the existing 'No
      findings.' empty state with no dead toggle."
    requirement: COMP-02
    verification:
      - kind: integration
        ref: "tests/test_compliance.py::test_scan_report_zero_findings_shows_no_findings_and_no_toggle"
        status: pass
    human_judgment: false
  - id: D6
    description: "The inline compliance pill and ASVS caption render
      identically in both grouping modes."
    requirement: COMP-02
    verification:
      - kind: integration
        ref: "tests/test_compliance.py::test_scan_report_compliance_pill_appears_in_both_grouping_modes"
        status: pass
    human_judgment: false
  - id: D7
    description: "The grouping mode is presentation-only: it never widens
      the finding set or bypasses the ownership check that gates the report
      route (T-03-23)."
    requirement: COMP-02
    verification:
      - kind: integration
        ref: "tests/test_compliance.py::test_scan_report_non_owner_gets_ownership_response_for_compliance_mode"
        status: pass
    human_judgment: false
  - id: D8
    description: "group_findings_by_compliance() is a pure, unit-testable
      helper: empty input, shared-category grouping, unmapped/missing
      check_name fallback, and category-ascending-then-Uncategorized-last
      ordering all behave as specified."
    requirement: COMP-02
    verification:
      - kind: unit
        ref: "tests/test_compliance.py::test_group_findings_by_compliance_empty_input_returns_empty_list"
        status: pass
      - kind: unit
        ref: "tests/test_compliance.py::test_group_findings_by_compliance_two_findings_share_a_category"
        status: pass
      - kind: unit
        ref: "tests/test_compliance.py::test_group_findings_by_compliance_unmapped_check_name_is_uncategorized"
        status: pass
      - kind: unit
        ref: "tests/test_compliance.py::test_group_findings_by_compliance_missing_check_name_key_is_uncategorized"
        status: pass
    human_judgment: false
  - id: D9
    description: "Switching grouping mode is a full server-rendered GET with
      no client-side fetch/loading state, consistent with every other page
      in this app."
    verification: []
    human_judgment: true
    rationale: "Structural property of the implementation (toggle links are
      plain <a href> to the same route, no JS/fetch added anywhere in this
      plan's diff) rather than something a route-level pytest assertion
      demonstrates - confirmed by direct code read of the toggle markup
      added to templates/scan_report.html, no async request path exists to
      test the absence of."
  - id: D10
    description: "The two toggle labels ('Severity'/'Compliance') are short
      fixed strings with no overflow risk at any viewport (03-UI-SPEC
      overflow row, backstop)."
    verification: []
    human_judgment: true
    rationale: "Plan/UI-SPEC flags this as a backstop requiring a viewport
      visual check, not a route-level assertion - the strings themselves are
      dictionary-sourced and fixed-length, but confirming no wrap/clip at a
      narrow viewport needs human/visual verification per 03-UI-SPEC's own
      backstop classification for this element."
    requirement: COMP-02

# Metrics
duration: ~30min
completed: 2026-08-11
status: complete
---

# Phase 3 Plan 02: Compliance-Grouped Report View Summary

**A scan report's Findings section now offers a low-emphasis "Group by: Severity | Compliance"
toggle that regroups the same finding cards under OWASP Top 10 category headings (Uncategorized
last), computed by a pure `group_findings_by_compliance()` helper and reachable via an
allowlisted `?group=` query parameter.**

## Performance

- **Duration:** ~30 min active work
- **Completed:** 2026-08-11
- **Tasks:** 2 (both `type="auto"`, no checkpoints)
- **Files modified:** 3 (`glassbox/scan_routes.py`, `templates/scan_report.html`,
  `tests/test_compliance.py`)

## Accomplishments

- Added `GROUPING_MODES = ("severity", "compliance")` as the allowlist for the report route's
  `?group=` query parameter — the raw `request.args` value is coerced against this tuple before
  it ever reaches `render_template()` or the page, so an unrecognized value silently falls back
  to the severity default and still returns 200 (T-03-21).
- Added `group_findings_by_compliance(findings, mapping)`, a pure, Flask-free helper (same shape
  as the existing `diff_reports()`/`index_by_key()` pattern) that buckets findings by their
  mapped OWASP category, sorts mapped categories ascending, and always puts a non-empty
  `Uncategorized` group last while preserving each finding's arrival order within its group.
- Extracted the existing per-finding markup (severity badge, compliance pill, optional ASVS
  caption, title/detail/recommendation) into a `finding_card(f)` macro in `scan_report.html`,
  called identically from both the pre-existing severity loop and the new compliance loop — one
  rendering path, so escaping discipline and the compliance pill can't drift between modes.
- Added a "Group by:" toggle above the Findings heading, rendered only when the report has at
  least one finding; active/inactive states use `.btn.secondary`/`.btn.ghost` only (never
  accent), hrefs built via `url_for('scan.scan_report', ...)`, and the active link carries
  `aria-current="true"`.
- Branched the findings section on the coerced `group` value: compliance mode iterates the
  `compliance_groups` pairs into the same `<details>`/`<summary>`/`.details-body` accordion shell
  the severity loop already used; severity mode is untouched byte-for-byte apart from now calling
  `finding_card(f)` instead of inlining the markup.
- Added 18 new tests to `tests/test_compliance.py`: 6 unit tests for the grouping helper (empty
  input, shared category, unmapped/missing `check_name`, Uncategorized-last ordering) and 12
  route-level tests covering the `?group=` parameter matrix, the OWASP/Uncategorized headings,
  the compliance pill appearing in both modes, the zero-finding empty state with no toggle, and
  non-owner access to the compliance mode.

## Task Commits

Each task was committed atomically:

1. **Task 1: Server-side grouping — allowlisted mode plus a pure compliance-grouping helper** -
   `149b9e8` (feat)
2. **Task 2: Report page — grouping toggle and the compliance-grouped accordion** - `b9cba3a`
   (feat)

## Files Created/Modified

- `glassbox/scan_routes.py` — `GROUPING_MODES` allowlist, `group_findings_by_compliance()`
  helper, `scan_report()` coerces `?group=` and computes `compliance_groups` only in compliance
  mode
- `templates/scan_report.html` — `finding_card(f)` macro, "Group by:" toggle control + page-scoped
  CSS, compliance-grouped accordion branch
- `tests/test_compliance.py` — grouping-helper unit tests and route-level grouping/toggle tests

## Decisions Made

- Wrote the toggle's active/inactive classes as two literal `if`/`else` blocks (`class="btn
  secondary"` / `class="btn ghost"`) rather than a single computed ternary expression, so the
  literal class strings stay directly greppable in the template source (matches the plan's own
  acceptance-criteria grep checks) rather than only existing as an interpolated runtime value.
- Passed `compliance_groups` into the render context only when the coerced mode is `"compliance"`
  (empty list in severity mode), per the plan's `key_links` contract — the template's branch
  condition is the mode itself, not whether grouped data happens to be present.

## Deviations from Plan

None — plan executed exactly as written, including the deliberate deviation from 03-PATTERNS.md
already called out in the plan's own `<objective>` (grouping computed in Python, not a second
Jinja `sort(attribute=...)` loop).

## Issues Encountered

None — the ambient `python` interpreter lacks `pytest`; ran the suite against the documented
`.venv` at the main repo checkout (`C:\Users\Arktech_Designs\Documents\Glassbox\.venv\Scripts\python.exe`),
same convention plan 03-01 already established for this worktree.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

`group_findings_by_compliance()` and the `finding_card(f)` macro are the shared building blocks
plan 03-03 (per-Asset compliance coverage) can reuse when it needs to reason about a scan's
findings by OWASP category outside the report page itself. No blockers.

---
*Phase: 03-compliance-framework-reporting*
*Completed: 2026-08-11*

## Self-Check: PASSED

- FOUND: `glassbox/scan_routes.py`
- FOUND: `templates/scan_report.html`
- FOUND: `tests/test_compliance.py`
- FOUND: `.planning/phases/03-compliance-framework-reporting/03-02-SUMMARY.md`
- FOUND commit: `149b9e8`
- FOUND commit: `b9cba3a`
