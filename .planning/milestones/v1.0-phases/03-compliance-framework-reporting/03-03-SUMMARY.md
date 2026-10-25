---
phase: 03-compliance-framework-reporting
plan: 03
subsystem: compliance-reporting
tags: [owasp, asvs, jinja, flask, findings, asset-inventory, coverage-summary]

# Dependency graph
requires:
  - phase: 03-compliance-framework-reporting (plan 01)
    provides: "Finding.check_name field, SCAN_TYPE_CHECK_NAMES, and the
      26-entry CHECK_COMPLIANCE OWASP/ASVS mapping dict this plan's
      summarize_compliance() reads"
  - phase: 01-asset-inventory-continuous-scanning
    provides: "Asset model, asset_detail.html, and _check_asset_access(a) -
      the ownership guard this plan's compliance_coverage() sits behind"
provides:
  - "summarize_compliance(reports_by_scan_type) - pure aggregation turning
    per-scan-type report dicts into ordered passing/failing/not_checked rows"
  - "compliance_coverage(asset) - loads the newest COMPLETED scan's report
    JSON per scan_type an Asset has run, behind _check_asset_access"
  - "'Compliance coverage' card on asset_detail.html - one row per OWASP
    category checked across an Asset's scan history, with a required scope
    hint and tier-locked upgrade copy reused from scan_report.html"
affects: []

# Actuals (#2632)
actuals:
  tokens: 6900
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Coverage-from-executed-checks, not findings: summarize_compliance()
      derives each scan_type's executed-check set from report-shape-specific
      fields (base: CHECK_LABELS minus locked_checks; advanced: ran; api:
      results.keys(); media: the constant {'media'}) so a clean scan reports
      full coverage instead of zero coverage."
    - "Untaggable-legacy-report exclusion: a report with any finding lacking
      a non-empty check_name contributes no executed checks and no findings
      at all, so its categories fall through to not_checked rather than
      being counted as clean - the same explicit-bucket-over-silent-pass
      philosophy the plan's prohibition locks."
    - "Newest-per-scan-type report loading with per-file failure isolation:
      compliance_coverage() reads at most one report JSON per scan_type
      (walking Scans newest-first, stopping once every present scan_type has
      a kept scan with a Report row), skipping a missing/unreadable/invalid
      file via try/except rather than failing the whole page."
    - "IDOR guard by construction, not by convention: compliance_coverage()
      takes the already-authorized Asset object and queries strictly by
      asset.id - no scan id, asset id, or scan type is ever read from the
      request - and is wired into _render_asset_detail(), whose only two
      callers both call _check_asset_access(a) first."

key-files:
  created: []
  modified:
    - glassbox/asset_routes.py
    - templates/asset_detail.html
    - tests/test_asset_routes.py

key-decisions:
  - "Split the plan's three tasks into three atomic commits by temporarily
    reducing the shared file (asset_routes.py) to each task's own scope -
    stripping Task 2/3 imports, compliance_coverage(), and the coverage=
    render_template kwarg for Task 1's commit, then restoring them - same
    technique 01-02's SUMMARY documented for the same shared-file problem."
  - "The tier-locked 'Not checked' row reuses scan_report.html's locked_card
    Paid-tier copy verbatim ('Requires the Paid plan... Upgrade to Paid')
    rather than replicating its org_verified_checks branch, since a
    compliance-coverage row is category-level (can aggregate check names
    spanning both Paid and Org-verified tiers) while locked_card's branch is
    per-check. Documented here as a deliberate simplification, not an
    oversight - acceptance criteria (a Billing link present) are satisfied
    either way."
  - "'Uncategorized' is treated as a normal candidate category (reachable
    whenever robots_sitemap's own CHECK_COMPLIANCE entry - literally
    {'owasp': 'Uncategorized'} - is a candidate check for a present scan
    type), not only as a fallback bucket for a check_name absent from
    CHECK_COMPLIANCE entirely. Both paths render identical text but are
    tallied/sorted through the same code path, verified by dedicated unit
    tests for each case."

patterns-established: []

requirements-completed: [COMP-03]

coverage:
  - id: D1
    description: "summarize_compliance() is a pure, DB-free aggregation:
      empty input returns [], a clean base report yields every reachable
      category as passing (including robots_sitemap's own 'Uncategorized'
      mapping), a mapped finding yields a failing row with the right count/
      top severity, two same-category findings collapse into one row with
      the worse severity, and mapped-category ordering is ascending with
      Uncategorized always last."
    requirement: COMP-03
    verification:
      - kind: unit
        ref: "tests/test_asset_routes.py::test_summarize_compliance_empty_input_returns_empty_list"
        status: pass
      - kind: unit
        ref: "tests/test_asset_routes.py::test_summarize_compliance_clean_base_report_all_categories_passing"
        status: pass
      - kind: unit
        ref: "tests/test_asset_routes.py::test_summarize_compliance_one_finding_yields_failing_row_others_stay_passing"
        status: pass
      - kind: unit
        ref: "tests/test_asset_routes.py::test_summarize_compliance_two_findings_same_category_count_and_worst_severity"
        status: pass
    human_judgment: false
  - id: D2
    description: "A category whose every mapped check is tier-locked in the
      report renders not_checked with locked=True, never passing; an
      untagged-legacy finding makes its whole scan_type's categories
      not_checked, never passing (this plan's prohibition)."
    requirement: COMP-03
    verification:
      - kind: unit
        ref: "tests/test_asset_routes.py::test_summarize_compliance_all_checks_for_a_category_locked_is_not_checked_and_locked"
        status: pass
      - kind: unit
        ref: "tests/test_asset_routes.py::test_summarize_compliance_untagged_finding_makes_whole_report_not_checked"
        status: pass
    human_judgment: false
  - id: D3
    description: "A finding whose check_name has no CHECK_COMPLIANCE entry
      lands in a trailing Uncategorized row rather than being dropped; the
      row is absent when no finding routes there; only scan types present in
      the input contribute candidate rows (an advanced-only Asset never
      shows a base-only category)."
    requirement: COMP-03
    verification:
      - kind: unit
        ref: "tests/test_asset_routes.py::test_summarize_compliance_unmapped_check_name_lands_in_uncategorized_last"
        status: pass
      - kind: unit
        ref: "tests/test_asset_routes.py::test_summarize_compliance_no_finding_maps_to_uncategorized_omits_the_row"
        status: pass
      - kind: unit
        ref: "tests/test_asset_routes.py::test_summarize_compliance_only_present_scan_types_contribute_candidate_rows"
        status: pass
    human_judgment: false
  - id: D4
    description: "compliance_coverage(asset) loads the newest COMPLETED
      scan's report per scan_type, skips a scan whose report file is missing
      or unreadable without erroring the page, and aggregates multiple scan
      types (base + api) into one coverage summary."
    requirement: COMP-03
    verification:
      - kind: integration
        ref: "tests/test_asset_routes.py::test_compliance_coverage_loads_newest_completed_base_report"
        status: pass
      - kind: integration
        ref: "tests/test_asset_routes.py::test_compliance_coverage_skips_scan_whose_report_file_is_missing"
        status: pass
      - kind: integration
        ref: "tests/test_asset_routes.py::test_compliance_coverage_aggregates_base_and_api_scan_types"
        status: pass
    human_judgment: false
  - id: D5
    description: "The asset detail route renders 200 with compliance data
      computed, and a cross-org request for the Asset still gets the
      existing 404 with no OWASP category string from the owner's scan
      leaked into the response body (IDOR guard)."
    requirement: COMP-03
    verification:
      - kind: integration
        ref: "tests/test_asset_routes.py::test_get_asset_detail_route_200_with_completed_scan_and_report"
        status: pass
      - kind: integration
        ref: "tests/test_asset_routes.py::test_get_asset_detail_compliance_coverage_cross_org_is_404_and_leaks_no_category"
        status: pass
    human_judgment: false
  - id: D6
    description: "The asset detail page renders a 'Compliance coverage'
      heading, at least one OWASP category string, and the required
      most-recent-completed-scan-per-scan-type scope hint for an Asset with
      a completed, tagged scan; an Asset whose scans are all queued shows
      the not-enough-scans hint with no category text leaked; an Asset with
      a fully tier-locked category shows 'Not checked' (never 'Passing')
      plus the reused Paid-plan upgrade link."
    requirement: COMP-03
    verification:
      - kind: integration
        ref: "tests/test_asset_routes.py::test_asset_detail_renders_compliance_coverage_heading_category_and_scope_hint"
        status: pass
      - kind: integration
        ref: "tests/test_asset_routes.py::test_asset_detail_all_scans_queued_shows_not_enough_scans_hint_no_category"
        status: pass
      - kind: integration
        ref: "tests/test_asset_routes.py::test_asset_detail_tier_locked_category_shows_not_checked_not_passing"
        status: pass
    human_judgment: false
  - id: D7
    description: "The Compliance coverage section is omitted entirely (not a
      second empty box) for an Asset that has never been scanned - it is
      nested inside asset_detail.html's existing {% if scans %} branch,
      whose {% else %} branch is the page's only empty state for that case."
    requirement: COMP-03
    verification: []
    human_judgment: true
    rationale: "Structural property of the template (the new section sits
      inside the pre-existing {% if scans %} branch, confirmed by direct
      code read of templates/asset_detail.html) rather than a dedicated
      route-level assertion - the existing
      test_get_asset_detail_shows_schedule_and_empty_history test already
      exercises a never-scanned Asset and passes, but does not itself assert
      the negative (absence of the new heading), so this is flagged for
      human/visual confirmation rather than claimed as auto-verified."
  - id: D8
    description: "Switching or loading the Compliance coverage card is a
      full server-rendered GET with no client-side fetch/loading state, and
      every new string this phase renders (OWASP category names, Passing/
      Not checked/finding-count wording) is short and dictionary-sourced
      with no truncation risk."
    verification: []
    human_judgment: true
    rationale: "Structural/typographic properties of the implementation
      (no JS or fetch added anywhere in this plan's diff; all row text comes
      from CHECK_COMPLIANCE's fixed OWASP strings or the small closed set of
      status words) rather than something a route-level pytest assertion
      demonstrates - same backstop classification 03-UI-SPEC.md already
      gives these rows (loading: E4, overflow: E4)."

# Metrics
duration: ~55min
completed: 2026-08-11
status: complete
---

# Phase 3 Plan 03: Per-Asset Compliance Coverage Summary

**Each Asset's detail page now shows a "Compliance coverage" card listing every OWASP Top 10
category its scan history has checked (Passing / N findings, highest severity / Not checked),
computed from the most recent completed scan of each scan type - with coverage always derived
from which checks actually ran, never from the mere absence of findings.**

## Performance

- **Duration:** ~55 min active work
- **Completed:** 2026-08-11
- **Tasks:** 3 (all `type="auto"`, no checkpoints - `autonomous: true`)
- **Files modified:** 3 (`glassbox/asset_routes.py`, `templates/asset_detail.html`,
  `tests/test_asset_routes.py`)

## Accomplishments

- Added `summarize_compliance(reports_by_scan_type)` to `asset_routes.py`: a pure, DB-free
  function that derives each scan_type's executed/locked check-name sets from its
  report-shape-specific fields (base's `locked_checks`, advanced's `ran`, api's `results` keys,
  media's implicit single check), tallies findings into OWASP categories via `CHECK_COMPLIANCE`,
  and buckets every candidate category into `passing`/`failing`/`not_checked` - proven by 9 unit
  tests to never mark a tier-locked or untaggable-legacy category as `passing`.
- Added `compliance_coverage(asset)`: loads the newest `COMPLETED` scan's report JSON per
  scan_type an Asset has run (at most 4 file reads), skipping a missing/unreadable/invalid report
  file without breaking the page, and wired it into `_render_asset_detail()` - reachable only
  through the two callers that already call `_check_asset_access(a)` first.
- Added a "Compliance coverage" card to `asset_detail.html`, sitting between "Risk score over
  time" and "Schedule" at the same visual weight as "Scan history": one row per OWASP category
  with a `.pill.pass`/severity pill/muted `.pill.not-checked` status, a required scope hint
  stating the most-recent-completed-scan-per-scan-type semantics, a separate not-enough-scans
  hint when no completed scan exists yet, and the reused Paid-plan upgrade link for tier-locked
  rows - all inside the page's existing `{% if scans %}` branch so a never-scanned Asset shows no
  second empty box.
- 17 new tests across the three tasks, including a cross-org IDOR test asserting both the
  existing 404 and the absence of the owning org's OWASP category string from the response body.

## Task Commits

Each task was committed atomically:

1. **Task 1: summarize_compliance() - the pure checked/failing/not-checked aggregation** -
   `bcaa43c` (feat)
2. **Task 2: compliance_coverage() - load the newest completed report per scan type behind the
   existing access guard** - `d1f04ac` (feat)
3. **Task 3: "Compliance coverage" card on the asset detail page** - `9fc77c1` (feat)

## Files Created/Modified

- `glassbox/asset_routes.py` - `_category_for_check()` helper, `summarize_compliance()`,
  `compliance_coverage()`, `coverage=` wired into `_render_asset_detail()`
- `templates/asset_detail.html` - "Compliance coverage" card, `.pill.not-checked` CSS
- `tests/test_asset_routes.py` - 9 `summarize_compliance` unit tests, 5 `compliance_coverage`/
  route tests, 3 card-rendering tests

## Decisions Made

- Split the plan's three shared-file tasks into three atomic commits by temporarily reducing
  `asset_routes.py` to each task's own scope (stripping Task 2/3's imports,
  `compliance_coverage()`, and the `coverage=` render kwarg before Task 1's commit, then
  restoring them) - the same technique 01-02's SUMMARY documented for an identical
  shared-file-across-tasks situation.
- The tier-locked "Not checked" row reuses `scan_report.html`'s `locked_card` Paid-tier copy
  verbatim rather than replicating its `org_verified_checks` branch, since a coverage row is
  category-level (can aggregate check names spanning both Paid and Org-verified tiers) while
  `locked_card`'s branch is per-check. This is a deliberate simplification - the plan's own
  acceptance criteria (a Billing link present) are satisfied either way, and no wording was
  invented that doesn't already exist verbatim elsewhere in the app.
- `"Uncategorized"` is treated as a normal, always-candidate category (reached via
  `robots_sitemap`'s own `CHECK_COMPLIANCE` entry, which is literally `{"owasp":
  "Uncategorized"}`) rather than only as a fallback for a `check_name` missing from
  `CHECK_COMPLIANCE` entirely - both paths render identical text but are exercised by separate
  unit tests, since they represent different underlying facts (evaluated-and-uncategorizable vs.
  simply-unknown-to-the-mapper), mirroring 03-01's identical distinction for `robots_sitemap`.

## Deviations from Plan

None - plan executed exactly as written, including both discretion decisions (card placement,
most-recent-per-scan-type semantics) and the prohibition's exact wording (locked/untagged/
unreadable data always renders `not_checked`, never `passing`).

## Issues Encountered

None - the ambient `python` interpreter lacks `pytest`; ran the suite against the documented
`.venv` at the main repo checkout (`C:\Users\Arktech_Designs\Documents\Glassbox\.venv\Scripts\python.exe`),
same convention plans 03-01 and 03-02 already established for this worktree. The full suite (up to
260 tests by the final task) takes several minutes on this machine; ran it via a background task
after each of the three task commits to confirm no interaction with plan 03-02's same-working-tree
changes (`scan_routes.py`, `scan_report.html`, `test_compliance.py`).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

COMP-03 is complete. All three of Phase 3's requirements (COMP-01/02/03; COMP-04 was folded into
03-01's coverage-regression tests) are now shipped across the phase's three plans - this closes
Phase 3 (Compliance & Framework Reporting) at 3/3 plans. No blockers for Phase 4 (Production
Hardening & Reliability).

---
*Phase: 03-compliance-framework-reporting*
*Completed: 2026-08-11*

## Self-Check: PASSED

- FOUND: `glassbox/asset_routes.py`
- FOUND: `templates/asset_detail.html`
- FOUND: `tests/test_asset_routes.py`
- FOUND: `.planning/phases/03-compliance-framework-reporting/03-03-SUMMARY.md`
- FOUND commit: `bcaa43c`
- FOUND commit: `d1f04ac`
- FOUND commit: `9fc77c1`
