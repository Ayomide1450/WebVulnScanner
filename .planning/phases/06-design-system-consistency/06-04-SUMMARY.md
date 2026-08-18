---
phase: 06-design-system-consistency
plan: 04
subsystem: ui
tags: [css, design-tokens, jinja, scan-flow, typography]

# Dependency graph
requires:
  - phase: 06-design-system-consistency
    plan: 01
    provides: base.html's 11-role typography scale, 2-weight (400/600) collapse, --radius-sm/--radius-md/--radius tokens
provides:
  - "All ten scan-flow templates (wizard shell, 4 launch pages, progress, report, compare, stepper partial) retokenized onto 06-01's base.html cascade"
affects: [07-responsive-accessibility]

# Actuals (#2632)
actuals:
  tokens: 5022
  tasks: 2
  commits: 2

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Locked-state/scan-type-grid <h2> elements cascade from base.html's global h2 rule (20px) instead of carrying a shadowing inline font-size"
    - "Report-family h1/h2.section rules are deleted locally and inherited from base.html; only a page-specific top-margin bump (matching dashboard.html's idiom) stays local"

key-files:
  created: []
  modified:
    - templates/scan_new_type.html
    - templates/scan_new_base.html
    - templates/scan_new_media.html
    - templates/scan_new_api.html
    - templates/scan_new_advanced.html
    - templates/scan_progress.html
    - templates/scan_report.html
    - templates/scan_compare.html
    - tests/test_template_consistency.py

key-decisions:
  - "Extended the plan's named checkbox-label weight:500->400 fix (only explicitly named for scan_new_advanced.html) to the identical 'I own this domain...' pattern in scan_new_base.html/scan_new_media.html (both checkboxes)/scan_new_api.html - the plan's own success_criteria states zero font-weight:500 must remain across all 10 files, and this is the exact full-sentence-instructional-checkbox-label category the plan already carves an exception for"
  - "Fixed a second hardcoded #34c759 occurrence in scan_new_advanced.html (#advDetectStatus.found) not named in the task's action steps but required by the task's own mechanical acceptance criterion (grep -c '#34c759|rgba(52, 199, 89' returns 0) - same bug class as the named .adv-detected-badge fix, same file"
  - "Fixed scan_progress.html's .intel-row strong (font-weight:700->600) and .feed-empty .feed-label (font-weight:500->600) - not individually named in the action steps but required by the task's acceptance criterion (zero font-weight:700/800 in scan_progress.html) and the plan-wide zero-500 success criterion; .feed-empty .feed-label is italic empty-state text, not a checkbox label, so it snaps to 600 (default), not 400"

patterns-established: []

requirements-completed: []  # Not marked complete yet - Task 3 (checkpoint:human-verify, gate=blocking) is pending human confirmation; see Next Phase Readiness. DESIGN-01..04 are shared across 06-01/06-02/06-03/06-04 and should only be marked complete once all four plans' checkpoints clear.

coverage:
  - id: D1
    description: "The four wizard Step-2/Step-3 pages no longer carry an inline font-size:16px override on their locked-state/scan-type-grid h2 - all cascade from base.html's 20px h2 rule"
    requirement: "DESIGN-01"
    verification:
      - kind: unit
        ref: "grep -c 'font-size:16px' templates/scan_new_type.html templates/scan_new_media.html templates/scan_new_api.html templates/scan_new_advanced.html - all 0"
        status: pass
      - kind: unit
        ref: "python -m pytest -q (492 passed)"
        status: pass
    human_judgment: false
  - id: D2
    description: "scan_report.html and scan_compare.html no longer duplicate base.html's h1/h2.section rules; the pre-existing test collision this causes is fixed in the same commit"
    requirement: "DESIGN-01"
    verification:
      - kind: unit
        ref: "grep -c 'h2.section {' / 'h1 { font-size: 24px' templates/scan_report.html templates/scan_compare.html - all 0"
        status: pass
      - kind: unit
        ref: "tests/test_template_consistency.py::test_scan_report_no_longer_duplicates_table_rule - updated assertion, passing"
        status: pass
    human_judgment: false
  - id: D3
    description: "scan_new_advanced.html's Auto-detected badge and detection-status text use the app's real --accent green instead of a slightly different hardcoded green; checkbox label weight collapsed to 400"
    requirement: "DESIGN-03"
    verification:
      - kind: unit
        ref: "grep -c '34c759|rgba(52, 199, 89' templates/scan_new_advanced.html - 0"
        status: pass
    human_judgment: false
  - id: D4
    description: "No selector across the 10 scan-flow templates sets font-weight:700, 800, or 500 after this plan lands"
    requirement: "DESIGN-01"
    verification:
      - kind: unit
        ref: "grep -n 'font-weight:\\s*[57]00|font-weight:\\s*800' across all 10 files - zero matches"
        status: pass
    human_judgment: false
  - id: D5
    description: "Visual walkthrough of the full scan-launch and report flow (locked-state headings, Advanced badge color, progress-page heading, report/compare H1 and section dividers) confirms nothing looks broken"
    verification: []
    human_judgment: true
    rationale: "Task 3 is an explicit checkpoint:human-verify (gate=blocking) - visual rendering quality and 'nothing looks broken' cannot be proven by an automated assertion; requires a human to load the pages and confirm. Not fabricated here per explicit instruction."

# Metrics
duration: 35min
completed: 2026-08-18
status: complete
---

# Phase 6 Plan 4: New-Scan Wizard, Progress, Report & Compare Pages Summary

**Removed the four copy-pasted shadowed-16px `<h2>` overrides, deleted `scan_report.html`'s/`scan_compare.html`'s local `h1`/`h2.section` duplicates of `base.html`'s canonical rules, fixed a hardcoded off-brand green in the Advanced page's Smart-Setup UI, and collapsed every remaining 700/800/500 font-weight across all ten scan-flow templates to the documented 400/600 scale.**

## Performance

- **Duration:** ~35 min
- **Started:** 2026-08-18T07:35:00Z (approx.)
- **Completed:** 2026-08-18T08:10:33Z
- **Tasks:** 2 of 3 (Task 3 is a `checkpoint:human-verify`, gate=blocking, awaiting human confirmation)
- **Files modified:** 8 templates + 1 test file (2 additional files in scope, `scan_new.html` and `_scan_wizard_stepper.html`, audit-confirmed to need zero code change)

## Accomplishments

- `scan_new_type.html`, `scan_new_media.html`, `scan_new_api.html`, `scan_new_advanced.html`: removed the inline `font-size:16px` override that shadowed `base.html`'s new global `h2` rule (20px) on every locked-state/scan-type-grid heading — a bug copy-pasted identically across all four pages.
- `scan_new_advanced.html`: `.adv-group`'s accordion-container `border-radius` promoted `10px` → `var(--radius)` (12px, the container-not-control family); `summary h4` cascades from the new global `h4` rule instead of a local `15px` override; the "Auto-detected" badge and the Smart-Setup detection-status text both now use the app's real `--accent` green (`rgba(34,197,94,.14)` / `var(--accent)`) instead of a slightly different hardcoded `#34c759`/`rgba(52,199,89,...)`; `.adv-field-help` 12px → 13px (Small role); checkbox-label weight 500 → 400.
- `scan_progress.html`: `.soc-header h1` no longer shadows `base.html`'s 28px `h1` rule (kept only the page-specific top-margin); every remaining local declaration in `.console-feed`/`.intel-row` snapped to the documented Small (13px)/Caption (11px) roles; `font-weight:700`/`500` collapsed to `600`.
- `scan_report.html`/`scan_compare.html`: deleted the local `h1 { font-size: 24px; ... }` and `h2.section { font-size: 15px; ... }` rules that fully duplicated `base.html`'s canonical values (except a few-px margin drift with no documented intent), keeping only the page-specific `h1 { margin-top: 20px; }` bump (matching `dashboard.html`'s idiom); every `.sp-*`/`.ai-*`/`.group-toggle`/`.note` declaration snapped to the Caption/Small/Body scale per the plan's general snapping rule; every `font-weight:700`/`800` collapsed to `600`.
- `scan_new_base.html`/`scan_new_media.html`/`scan_new_api.html`: extended the checkbox-label weight fix (500 → 400) to the three sibling "I own this domain..." authorization checkboxes carrying the identical pattern named for `scan_new_advanced.html`.
- `_scan_wizard_stepper.html`/`scan_new.html`: audit-confirmed clean — no local `<style>` block, no inline font-size/font-weight override, no code change needed.
- `tests/test_template_consistency.py::test_scan_report_no_longer_duplicates_table_rule`: updated its second assertion from "still contains `h2.section`" to "no longer contains `h2.section {`", matching the new intentional post-Phase-6 state (this was the one pre-existing test collision the plan flagged in advance).

## Task Commits

Each task was committed atomically:

1. **Task 1: Wizard shell + Standard/Media/API launch pages — the repeated inline-h2 fix** - `c0bea15` (feat)
2. **Task 2: Advanced launch page, scan-progress, scan-report, scan-compare, stepper partial** - `d69e742` (feat)

**Plan metadata:** commit pending (this SUMMARY)

Task 3 (`checkpoint:human-verify`, gate=blocking) has no code commit — it is a manual visual-verification gate. See "Next Phase Readiness" below.

## Files Created/Modified

- `templates/scan_new_type.html` - Removed shadowed 16px inline `<h2>` override
- `templates/scan_new_base.html` - Checkbox-label weight 500→400 (audit-confirmed h1 needs no change)
- `templates/scan_new_media.html` - Removed shadowed 16px inline `<h2>` override (locked state); both checkbox labels weight 500→400
- `templates/scan_new_api.html` - Removed shadowed 16px inline `<h2>` override (locked state); checkbox label weight 500→400
- `templates/scan_new_advanced.html` - `.adv-group` radius→`var(--radius)`, `summary h4` font-size removed, badge + detection-status color fixed to `--accent`, `.adv-field-help` 12→13px, checkbox label weight 500→400, locked-state `<h2>` fixed
- `templates/scan_progress.html` - `.soc-header h1` no longer shadows global h1; `.console-feed`/`.intel-row` family snapped to Small/Caption scale; weight 700/500→600
- `templates/scan_report.html` - Deleted local `h1`/`h2.section` rules; `.score-summary h2` font-size removed; every `.sp-*`/`.ai-*`/`.group-toggle`/`.note` declaration snapped to documented scale; weight 700/800→600
- `templates/scan_compare.html` - Deleted local `h1`/`h2.section` rules; `.delta` weight 700→600
- `tests/test_template_consistency.py` - Flipped `test_scan_report_no_longer_duplicates_table_rule`'s `h2.section` assertion to assert absence

## Decisions Made

- Extended the checkbox-label `font-weight:500`→`400` fix beyond the one file the task's action steps explicitly named (`scan_new_advanced.html`) to the three sibling launch pages carrying the byte-identical "I own this domain, or I have explicit authorization..." pattern. The plan's own success criteria ("No selector ... sets font-weight:700, 800, or 500 after this plan lands") is unambiguous and unqualified across all 10 files; the task-level action list appears to have simply omitted enumerating the three repeats of a pattern it names once. Applied mechanically, zero risk (identical CSS category to the named fix), documented here per the deviation rules' scope-boundary guidance.
- Fixed a second hardcoded `#34c759` occurrence in `scan_new_advanced.html` (`#advDetectStatus.found`) that the task's action steps didn't name but its own acceptance criterion (`grep -c '#34c759|rgba(52, 199, 89' templates/scan_new_advanced.html` returns 0) required — same off-brand-green bug class as the explicitly named `.adv-detected-badge` fix, same file, same root cause.
- Fixed `scan_progress.html`'s `.intel-row strong` (`font-weight:700`→`600`) and `.feed-empty .feed-label` (`font-weight:500`→`600`) — not individually named in the action steps but required by the task's own acceptance criterion (zero `font-weight:700/800` in `scan_progress.html`) and the plan-wide zero-500 success criterion. `.feed-empty .feed-label` is italic empty-state status text, not a checkbox label, so it snaps to the default `600` rather than the `400` carve-out reserved for full-sentence instructional checkbox labels.
- `scan_new.html` and `templates/_scan_wizard_stepper.html` received zero code changes — both audit-confirmed (per D-03) to already be clean: no local `<style>` block, no inline font-size/font-weight anywhere.

## Deviations from Plan

### Auto-fixed Issues (Rule 1/2 — completing the plan's own explicit, unqualified success criteria)

**1. [Rule 2] Checkbox-label weight fix extended to 3 sibling files not named in Task 1's action steps**
- **Found during:** Task 1
- **Issue:** `scan_new_base.html`, `scan_new_media.html` (2 checkboxes), `scan_new_api.html` each carry the identical `style="margin:0; font-weight:500;"` authorization-checkbox label the plan explicitly names and fixes only for `scan_new_advanced.html` in Task 2 — yet the plan's plan-wide success criteria mandates zero `font-weight:500` remains anywhere in the 10 files.
- **Fix:** Applied the identical `500`→`400` fix already established for the named instance.
- **Files modified:** `templates/scan_new_base.html`, `templates/scan_new_media.html`, `templates/scan_new_api.html`
- **Commit:** `c0bea15`

**2. [Rule 1] Second hardcoded `#34c759` occurrence in `scan_new_advanced.html`**
- **Found during:** Task 2 acceptance-criteria verification (the plan's own `grep -c '#34c759|rgba(52, 199, 89'` check returned 1, not the required 0, after only fixing the named `.adv-detected-badge`)
- **Issue:** `#advDetectStatus.found { color: #34c759; }` — the same off-brand hardcoded green as the badge, in the same file, not caught by the task's action-step prose but caught by its own mechanical acceptance check.
- **Fix:** Changed to `color: var(--accent);`.
- **Files modified:** `templates/scan_new_advanced.html`
- **Commit:** `d69e742`

**3. [Rule 1] Two more font-weight 700/500 instances in `scan_progress.html`**
- **Found during:** Task 2 acceptance-criteria verification (`grep -c 'font-weight:\s*700\|font-weight:\s*800' templates/scan_progress.html` required 0)
- **Issue:** `.intel-row strong { font-weight:700; }` and `.feed-empty .feed-label { font-weight:500; }` weren't named in the task's action-step prose (which only named `.soc-header h1` and four font-size snaps) but are covered by the task's own acceptance criterion and the plan-wide zero-500/700/800 success criterion.
- **Fix:** `.intel-row strong` → `600`; `.feed-empty .feed-label` → `600` (default collapse target; not a checkbox label, so no `400` carve-out applies).
- **Files modified:** `templates/scan_progress.html`
- **Commit:** `d69e742`

None of the three deviations above touch scope outside this plan's 10 named files, and all three are mechanical applications of a fix pattern the plan already establishes elsewhere in the same task set — no architectural decision, no new component, no ambiguity requiring a Rule 4 stop.

## Issues Encountered

None. Both `python -m pytest -q` runs (isolated `tests/test_template_consistency.py` subset, then the full 492-test suite) were green with zero failures on the first attempt after each task's edits.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

Tasks 1 and 2 (the full code deliverable) are complete, committed, and verified: `python -m pytest -q` is green (492 passed, 0 failed) after both tasks, `tests/test_template_consistency.py`'s 18 tests all pass including the updated `test_scan_report_no_longer_duplicates_table_rule`, and every mechanical `grep`-based acceptance criterion named in the plan (plus the two 700/500 spot-checks this plan's deviations closed) returns the required count.

**Task 3 (`checkpoint:human-verify`, gate=blocking) is pending human confirmation** — per explicit instruction for this run, this is not fabricated. The walkthrough specified in the plan covers: `/scan/new` → `/scan/new/type` → locked `/scan/new/media` and `/scan/new/api` (Free tier), locked `/scan/new/advanced` (no verified domain), unlocked Advanced form with Smart-Setup badge color, a live `/scan/<id>` progress page, a completed `/scan/<id>` report, and `/scan/<id>/compare/<other_id>`. `requirements-completed` is left empty in this SUMMARY's frontmatter pending that confirmation, matching `06-01-SUMMARY.md`'s precedent — `DESIGN-01..04` are shared requirements across all four Phase 6 plans and should only be marked complete once every plan's checkpoint clears.

This plan touched only the 8 templates + 1 test file listed above — `git diff --stat` for `master`'s current working tree also shows unrelated in-flight changes to `templates/asset_detail.html`, `templates/asset_new.html`, `templates/assets.html`, `templates/dashboard.html`, and `templates/api_tokens.html` from the parallel `06-02`/`06-03` agents; none of those were staged or touched by either of this plan's two commits.

## Self-Check: PASSED

- FOUND: `.planning/phases/06-design-system-consistency/06-04-SUMMARY.md`
- FOUND: commit `c0bea15` (Task 1)
- FOUND: commit `d69e742` (Task 2)
