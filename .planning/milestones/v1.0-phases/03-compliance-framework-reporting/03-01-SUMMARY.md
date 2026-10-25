---
phase: 03-compliance-framework-reporting
plan: 01
subsystem: compliance-reporting
tags: [owasp, asvs, jinja, flask, findings, security-taxonomy]

# Dependency graph
requires:
  - phase: 01-asset-inventory-continuous-scanning
    provides: run_scan/run_advanced_scan/run_media_scan/run_api_scan orchestrators and the
      Finding dataclass this plan attaches check_name to
provides:
  - "Finding.check_name field (default \"\"), set centrally by all 4 scan_engine.py orchestrators"
  - "SCAN_TYPE_CHECK_NAMES dict (checks.py): scan_type -> set of dispatchable check names, the
    single source of truth for COMP-04's coverage tests and plan 03-03's per-Asset aggregation"
  - "CHECK_COMPLIANCE dict (checks.py): 26-entry check_name -> {owasp, asvs} OWASP Top 10:2021 /
    ASVS 4.0.3 mapping, human-approved at the Task 2 checkpoint"
  - "CHECK_COMPLIANCE passed into scan_report.html's render context"
  - ".pill.compliance neutral CSS variant (base.html) + inline OWASP pill/ASVS caption on every
    finding card in scan_report.html, with an Uncategorized fallback for unmapped/legacy findings"
  - "tests/test_compliance.py: 12 tests covering COMP-01 tagging (all 4 orchestrators),
    report-rendering (mapped/legacy/escaped), and COMP-04 key-set coverage regression"
affects: [03-02-compliance-grouped-report-view, 03-03-per-asset-compliance-coverage]

# Actuals (#2632)
actuals:
  tokens: 7240
  tasks: 3
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Centralized per-check metadata tagging: Finding.check_name is set once per check at each
      orchestrator's finding-collection point, not at any of the ~50 Finding(...) construction
      sites in checks.py - same shape as CHECK_LABELS/CHECK_CATEGORY's existing convention,
      extended from base-scan-only to all 4 scan types."
    - "Read-time compliance overlay: CHECK_COMPLIANCE is applied when a report is rendered, not
      baked into the stored report JSON at scan-time - a future mapping-value correction takes
      effect immediately for every historical report, no backfill needed."
    - "Source-parsing coverage-regression tests (COMP-04): tests read scan_engine.py's live
      jobs-dict and results[...] = data assignments via regex, the same technique
      tests/test_entitlements.py already uses for FEATURE_REQUIREMENTS, so a future check added
      without a CHECK_COMPLIANCE entry fails the suite instead of silently defaulting."

key-files:
  created:
    - tests/test_compliance.py
  modified:
    - glassbox/checks.py
    - glassbox/scan_engine.py
    - glassbox/scan_routes.py
    - templates/base.html
    - templates/scan_report.html

key-decisions:
  - "CHECK_COMPLIANCE transcribed verbatim from 03-RESEARCH.md's Pattern 2 table (all 26 rows,
    including the literal owasp value \"Uncategorized\" for robots_sitemap - a check that
    genuinely doesn't map to any OWASP category, distinct from D-04's render-time fallback for a
    check_name entirely absent from the dict) and human-approved as-is at the Task 2 checkpoint,
    with no row changes."
  - "API scan compliance keys use run_api_scan()'s own results sub-keys (schema/wordlist/
    js_discovery), not entitlements.FEATURE_REQUIREMENTS's single \"api\" tier-gating bucket -
    preserves the schema-exposure vs. unauthenticated-endpoint OWASP distinction (03-RESEARCH.md
    Pitfall 2)."
  - "Compliance-mapping tests report dicts use scan_type=\"other\" (not base/advanced/media/api)
    so the report-rendering tests exercise only the shared findings-list section (where the
    compliance pill lives) without needing to stub every scan-type-specific \"Detailed check
    output\" field scan_report.html's other template blocks read."

patterns-established:
  - "SCAN_TYPE_CHECK_NAMES as the shared source of truth for 'which check names can this scan
    type dispatch' - reused as-is (not re-derived) by plan 03-03's per-Asset coverage aggregation,
    per the plan's key_links contract."

requirements-completed: [COMP-01, COMP-04]

coverage:
  - id: D1
    description: "Every finding produced by run_scan() carries a non-empty check_name that is a
      CHECK_COMPLIANCE key (COMP-01 tracer)."
    requirement: COMP-01
    verification:
      - kind: unit
        ref: "tests/test_compliance.py::test_run_scan_tags_every_finding_with_a_mapped_check_name"
        status: pass
    human_judgment: false
  - id: D2
    description: "Every finding produced by run_advanced_scan(), run_media_scan(), and
      run_api_scan() carries a non-empty check_name that is a CHECK_COMPLIANCE key (D-03: all 4
      scan types, not just base)."
    requirement: COMP-01
    verification:
      - kind: unit
        ref: "tests/test_compliance.py::test_run_media_scan_tags_its_finding_with_check_name"
        status: pass
      - kind: unit
        ref: "tests/test_compliance.py::test_run_api_scan_tags_each_of_its_three_findings_with_check_name"
        status: pass
      - kind: unit
        ref: "tests/test_compliance.py::test_run_advanced_scan_tags_each_group_finding_with_check_name"
        status: pass
    human_judgment: false
  - id: D3
    description: "CHECK_COMPLIANCE has exactly 26 entries (union of SCAN_TYPE_CHECK_NAMES's
      values), every entry has a non-empty owasp value, and asvs is a non-empty string or None
      (never empty string) (D-01)."
    requirement: COMP-01
    verification:
      - kind: unit
        ref: "tests/test_compliance.py::test_check_compliance_covers_every_dispatchable_check_name"
        status: pass
      - kind: unit
        ref: "tests/test_compliance.py::test_check_compliance_has_no_stale_keys"
        status: pass
      - kind: unit
        ref: "tests/test_compliance.py::test_check_compliance_every_entry_has_owasp_and_valid_asvs"
        status: pass
    human_judgment: false
  - id: D4
    description: "COMP-04: adding/renaming/removing a check in any of the 4 orchestrators without
      updating CHECK_COMPLIANCE fails the test suite, not silently degrades. Mutation-proved:
      temporarily removing CHECK_COMPLIANCE['idor'] failed
      test_check_compliance_covers_every_dispatchable_check_name with 'CHECK_COMPLIANCE is
      missing entries for {idor}'; restoring the key made it pass again."
    requirement: COMP-04
    verification:
      - kind: unit
        ref: "tests/test_compliance.py::test_scan_type_check_names_base_matches_run_scan_jobs_and_out_of_band"
        status: pass
      - kind: unit
        ref: "tests/test_compliance.py::test_advanced_and_api_results_assignments_are_covered_by_scan_type_check_names"
        status: pass
    human_judgment: false
  - id: D5
    description: "A scan report page renders each finding's mapped OWASP category as a
      .pill.compliance tag beside its severity badge, visible in the default Severity grouping
      mode (E2)."
    requirement: COMP-01
    verification:
      - kind: integration
        ref: "tests/test_compliance.py::test_scan_report_shows_mapped_owasp_category_for_check_name"
        status: pass
    human_judgment: false
  - id: D6
    description: "A finding whose check_name is absent from CHECK_COMPLIANCE (including every
      report JSON written before this phase) renders the literal 'Uncategorized' pill and is
      never dropped from the page (D-04)."
    requirement: COMP-01
    verification:
      - kind: integration
        ref: "tests/test_compliance.py::test_scan_report_shows_uncategorized_for_legacy_finding_without_check_name"
        status: pass
    human_judgment: false
  - id: D7
    description: "Finding title/detail text still renders HTML-escaped after the new compliance
      markup lands (no |safe filter introduced)."
    verification:
      - kind: integration
        ref: "tests/test_compliance.py::test_scan_report_escapes_finding_title_containing_script_tag"
        status: pass
    human_judgment: false
  - id: D8
    description: "The ASVS caption ('ASVS {ref}') renders only when CHECK_COMPLIANCE[...]['asvs']
      is truthy, with no placeholder text when it's None (D-01); and the compliance pill is
      visually ranked below/secondary to the OWASP pill (D-02's dual-audience layering)."
    verification: []
    human_judgment: true
    rationale: "Confirmed by direct code read of scan_report.html's {% if compliance_entry.get('asvs') %}
      conditional and base.html's .pill/.cat sizing (11.5px bold pill vs. smaller muted caption,
      per 03-UI-SPEC.md's inherited Pill/caption typography row) - no dedicated automated
      assertion exists for ASVS-caption presence/absence or the two layers' relative visual
      weight, since this app has no template-rendering-assertion test convention beyond
      route-level 200/content-contains checks (used for D5/D6 above)."
  - id: D9
    description: "The compliance pill plus optional ASVS caption sit inline after the severity
      badge and wrap to a second line on a narrow viewport without overlapping or clipping the
      finding body (plan's backstop truth)."
    verification: []
    human_judgment: true
    rationale: "Plan explicitly marks this a 'backstop' truth (verification: backstop) requiring a
      narrow-viewport visual check per the task's <verify><human-check> - not something a
      route-level pytest assertion can confirm; deferred to /gsd-verify-work per the plan's own
      verification step."

# Metrics
duration: ~35min (active work; excludes the Task 2 human-verification checkpoint wait)
completed: 2026-08-11
status: complete
---

# Phase 3 Plan 01: Compliance Mapping Data Layer & OWASP Pill Summary

**Every finding across all 4 scan types (base/advanced/media/api) now carries a `check_name` that
resolves through a human-approved 26-entry `CHECK_COMPLIANCE` dict to an OWASP Top 10:2021
category (plus an optional ASVS 4.0.3 reference), rendered as a neutral `.pill.compliance` tag
beside every finding's severity badge on `scan_report.html`.**

## Performance

- **Duration:** ~35 min active work (Task 1 + Task 2 checkpoint + Task 3); the Task 2 checkpoint
  itself paused execution for a separate human-review turn, excluded from this figure.
- **Completed:** 2026-08-11
- **Tasks:** 3 (Task 1 tracer, Task 2 checkpoint, Task 3 remaining-orchestrators + COMP-04 lock-in)
- **Files modified:** 6 (5 modified, 1 new test file)

## Accomplishments

- Added `Finding.check_name` (default `""`), `SCAN_TYPE_CHECK_NAMES`, and the 26-entry
  `CHECK_COMPLIANCE` OWASP/ASVS mapping dict to `checks.py`, mirroring `CHECK_LABELS`/
  `CHECK_CATEGORY`'s existing convention but widened to cover all 4 scan types (base 17 +
  advanced 5 + media 1 + api 3 = 26), per D-03.
- Tagged all 9 finding-collection points across all 4 orchestrators in `scan_engine.py`
  (`run_scan`'s 3, `run_media_scan`'s 1, `run_api_scan`'s 3, `run_advanced_scan`'s 5) with the
  producing check's name, centrally, without touching any of the ~50 `Finding(...)` construction
  sites in `checks.py`.
- Wired `CHECK_COMPLIANCE` into `scan_report.html`'s render context and added a neutral
  `.pill.compliance` CSS variant plus inline OWASP pill + optional `ASVS {ref}` caption on every
  finding card, with a graceful `"Uncategorized"` fallback for findings whose `check_name` is
  missing or unmapped (including every report JSON written before this phase shipped).
- Human-approved the full 26-row `CHECK_COMPLIANCE` table (including the 5 flagged ambiguous
  rows — `cookies`, `dns_email`, `open_redirect`, `media`, `secrets` — and confirmed OWASP Top
  10:2021 as the correct edition) at the Task 2 checkpoint, with zero row changes requested.
- Locked the mapping with 5 COMP-04 regression tests that source-parse `scan_engine.py`'s live
  `jobs` dict and `results[...] = data` assignments, mutation-proved by temporarily removing
  `CHECK_COMPLIANCE['idor']` (test failed with a clear "missing entries for {idor}" message) and
  restoring it (test passed again).

## Task Commits

Each task was committed atomically:

1. **Task 1: End-to-end "a base-scan finding shows its OWASP category"** - `74c92bd` (feat)
2. **Task 2: Checkpoint — sanity-check the 26 OWASP/ASVS assignments** - no commit (human-verify
   checkpoint; approved with no changes)
3. **Task 3: Tag the remaining 3 orchestrators and lock the mapping with COMP-04 regression
   tests** - `383c3cc` (feat)

## Files Created/Modified

- `glassbox/checks.py` - `Finding.check_name` field, `SCAN_TYPE_CHECK_NAMES` dict, 26-entry
  `CHECK_COMPLIANCE` dict
- `glassbox/scan_engine.py` - `check_name` tagging at all 9 finding-collection points across
  the 4 orchestrators
- `glassbox/scan_routes.py` - imports and passes `CHECK_COMPLIANCE` into `scan_report()`'s
  render context
- `templates/base.html` - new `.pill.compliance` neutral CSS variant
- `templates/scan_report.html` - inline OWASP pill + optional ASVS caption on every finding card
- `tests/test_compliance.py` (new) - 12 tests: run_scan/run_media_scan/run_api_scan/
  run_advanced_scan tagging, 3 report-rendering tests, 5 COMP-04 coverage-regression tests

## Decisions Made

- Transcribed `CHECK_COMPLIANCE` verbatim from `03-RESEARCH.md`'s Pattern 2 table rather than
  adjusting any individual assignment ahead of the Task 2 checkpoint, so the human review at
  Task 2 was reviewing exactly what shipped, not a pre-edited variant.
- Kept `robots_sitemap`'s `owasp` value as the literal string `"Uncategorized"` (an explicit,
  deliberate mapping entry) rather than omitting the key entirely — distinct from D-04's
  render-time fallback for a `check_name` that isn't a `CHECK_COMPLIANCE` key at all; both produce
  identical rendered text but represent different underlying facts (evaluated-and-uncategorizable
  vs. simply-unknown-to-the-mapper).
- Used `scan_type="other"` (not `base`/`advanced`/`media`/`api`) in the new report-rendering
  tests, so they exercise only the shared findings-list section without needing to stub every
  scan-type-specific "Detailed check output" field the template's other conditional blocks read.

## Deviations from Plan

None - plan executed exactly as written, including the mutation-proof step and the human
checkpoint (approved as-is, no row changes).

## Issues Encountered

None - the ambient `python` interpreter (3.14) lacked `pytest`; resolved by running the suite
against the documented `.venv` at the main repo checkout
(`C:\Users\Arktech_Designs\Documents\Glassbox\.venv\Scripts\python.exe`), matching
`CLAUDE.md`'s "Tests" section (the plan's own relative `../../../.venv/...` path assumes a
`.venv` inside this worktree, which doesn't exist since `.venv/` is gitignored and worktrees don't
share it).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

`Finding.check_name`, `SCAN_TYPE_CHECK_NAMES`, and `CHECK_COMPLIANCE` are in place and
regression-tested, giving plan 03-02 (compliance-grouped report view) and plan 03-03 (per-Asset
compliance-coverage summary) the shared source of truth their `key_links` contract requires. No
blockers.

---
*Phase: 03-compliance-framework-reporting*
*Completed: 2026-08-11*

## Self-Check: PASSED

- FOUND: `tests/test_compliance.py`
- FOUND: `.planning/phases/03-compliance-framework-reporting/03-01-SUMMARY.md`
- FOUND commit: `74c92bd`
- FOUND commit: `383c3cc`
