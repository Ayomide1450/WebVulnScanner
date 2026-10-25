---
phase: 07-responsive-accessibility-compliance
plan: 06
subsystem: ui
tags: [accessibility, jinja, marketing, scan-new-advanced, heading-hierarchy, a11y-01, a11y-02, a11y-03]

# Dependency graph
requires:
  - phase: 07-responsive-accessibility-compliance
    plan: 02
    provides: "tests/test_responsive_org_tables.py's reusable _ids_in(body) rendered-body id-uniqueness helper, imported (not reimplemented) to extend the invariant app-wide"
  - phase: 07-responsive-accessibility-compliance
    plan: 03
    provides: "api_tokens.html/assets.html/asset_detail.html dual-markup conversion - final markup this plan's locks run against"
  - phase: 07-responsive-accessibility-compliance
    plan: 05
    provides: "scan_report.html/_gauge.html accessibility-semantics retrofit - final markup this plan's locks run against"
provides:
  - "marketing.html's sixteen check-name/step headings and scan_new_advanced.html's four accordion-group headings promoted to close both of the codebase's only two confirmed heading-hierarchy skips, with rendered size pinned unchanged (A11Y-02)"
  - "tests/test_accessibility.py: -k heading_hierarchy / -k labels_and_icon_buttons / -k no_clickable_divs / -k focus_treatment selectors, an app.url_map-derived 20-page list plus three fixture-id pages, and two negative-control tests proving the heading and label locks actually bite"
affects: [07-07-phase-gate-viewport-sweep]

# Actuals (#2632)
actuals:
  tokens: 9400
  tasks: 2
  commits: 2

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Heading-level tag promotion with the local CSS selector renamed in the same edit and the font-size/margin declarations kept byte-identical - the accessibility fix is confined entirely to the DOM tag, never touching a rendered pixel."
    - "Page-list construction from app.url_map.iter_rules() (GET-accepting, zero path arguments, minus a documented EXCLUDED_ENDPOINTS/EXCLUDED_BLUEPRINT_PREFIXES set) rather than a hand-maintained list, so a future route with no accessibility coverage is a visible gap."
    - "A throwaway second Flask app (TESTING=True, SCHEDULER_ENABLED=False, in-memory SQLite URI, never queried) built once at module import time solely to read app.url_map before pytest.mark.parametrize needs the page list at collection time - the per-test `app`/`client` fixtures build the real app every actual request goes through."
    - "scan_type=\"other\" (not \"base\") for the report fixture - mirrors 07-05's test convention: scan_report.html's base-scan-specific sections (headers/TLS/cookies, needing many more report keys) are gated behind {% if scan.scan_type == 'base' %}, so \"other\" reaches the same generic findings/severity/locked-checks markup with a minimal fixture."

key-files:
  created:
    - tests/test_accessibility.py
  modified:
    - templates/marketing.html
    - templates/scan_new_advanced.html
    - templates/_scan_form_styles.html

key-decisions:
  - "The plan's acceptance criteria and <action> text describe the API-tokens page as `/account/api-tokens`; the actual registered route (glassbox/api_tokens_routes.py: `Blueprint(\"api_tokens\", __name__, url_prefix=\"/tokens\")`, confirmed against a real app.url_map dump) is `/tokens`. Since the page list is built programmatically from app.url_map per the plan's own explicit instruction (\"not by hand\"), the module's PAGES list and MIN_EXPECTED_PAGES both use the real `/tokens` path rather than forcing a literal string that doesn't exist in the codebase - documented here as a plan-vs-codebase mismatch, not a code defect."
  - "auth.login redirects a GET whenever current_user.is_authenticated (nothing useful to show a logged-in user on the login form), and auth.signup does the same unless an invite token is present. Both are therefore unreachable as a 200 while the seeded fixture's admin session is active. _get() logs the session out first for these two paths before requesting them; each parametrised test still gets its own fresh function-scoped app/db/client, so this can't leak into another test's session."
  - "Imported 07-02's tests/test_responsive_org_tables.py::_ids_in helper rather than 07-03's own _assert_no_duplicate_ids (07-03-SUMMARY.md documents that its module was written before 07-02's helper existed on disk, in a concurrent wave-2 agent) - this plan's <action> explicitly names 07-02's helper as the one to reuse, and only one copy should exist going forward."

patterns-established:
  - "Two negative-control tests (test_heading_hierarchy_negative_control_marketing_h3_back_to_h4, test_labels_and_icon_buttons_negative_control_removed_aria_label) that mutate a template file on disk, assert the mutated markup fails the relevant assertion, then restore the original bytes in a `finally` block and re-assert the restored file passes - proves a lock bites without leaving the repository in a broken state, reusable pattern for any future lock this file grows."

requirements-completed: []  # Not marked complete yet - Task 3 (checkpoint:human-verify, gate=blocking) is pending human confirmation

coverage:
  - id: D1
    description: "marketing.html's twelve check-name headings and four how-it-works step headings are <h3> (not <h4>), so both sequences read h2 -> h3 with no level skipped; the .check-item/.step selectors are renamed alongside and keep their exact prior font-size/margin, so nothing visible changes"
    requirement: "A11Y-02"
    verification:
      - kind: unit
        ref: "tests/test_accessibility.py -k heading_hierarchy - GET / parametrised case plus the marketing.html negative-control test"
        status: pass
    human_judgment: false
  - id: D2
    description: "scan_new_advanced.html's four accordion-group question headings are <h2> (not <h4>) - the page's primary content divisions, sibling to the existing locked-state h2 - with the matching selector in scan_new_advanced.html AND the shared _scan_form_styles.html both updated and pinned to font-size 14px/line-height 1.35 so the accordion labels render exactly as before"
    requirement: "A11Y-02"
    verification:
      - kind: unit
        ref: "tests/test_accessibility.py -k heading_hierarchy - GET /scan/new/advanced?target=https://example.com parametrised case (unlocked-state render, real accordion markup exercised, not the locked-state empty branch)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Every reachable no-parameter GET page (20, derived from app.url_map) plus three fixture-id pages (scan report, scan progress, asset detail) has sequential heading levels with no forward jump greater than one; zero-heading and equal-adjacent-level pages pass"
    requirement: "A11Y-02"
    verification:
      - kind: unit
        ref: "tests/test_accessibility.py -k heading_hierarchy (22 passed) - test_heading_hierarchy[...] parametrised over all 20 pages, test_heading_hierarchy_fixture_pages, negative control"
        status: pass
    human_judgment: false
  - id: D4
    description: "Every visible input/select/textarea across the app-wide page list has a matching <label for> or an aria-label; every <label for> names a real control id; every icon-only <button> has an aria-label and its <svg> carries aria-hidden - including a named regression lock on the eight known icon-only buttons (3 asset actions, 5 password toggles)"
    requirement: "A11Y-01"
    verification:
      - kind: unit
        ref: "tests/test_accessibility.py -k labels_and_icon_buttons (23 passed) - parametrised over all 20 pages plus fixture pages, the eight-known-buttons regression lock, and a negative control removing asset_detail.html's delete-button aria-label"
        status: pass
    human_judgment: false
  - id: D5
    description: "No div/span/li/td/tr anywhere carries a click-handler attribute or a button role, checked against both every rendered page's response body AND every template's raw source (so a violation behind an excluded/skipped route is still caught)"
    requirement: "A11Y-03"
    verification:
      - kind: unit
        ref: "tests/test_accessibility.py -k no_clickable_divs (22 passed) - parametrised rendered-body checks plus test_no_clickable_divs_source_level_across_all_templates"
        status: pass
    human_judgment: false
  - id: D6
    description: "templates/base.html is the only template in templates/ declaring a :focus-visible rule - no component-local override exists anywhere"
    requirement: "A11Y-03"
    verification:
      - kind: unit
        ref: "tests/test_accessibility.py -k focus_treatment (2 passed)"
        status: pass
    human_judgment: false
  - id: D7
    description: "No rendered page anywhere in the app repeats an id value - the id-uniqueness invariant plan 07-02 introduced on two pages now holds app-wide, reusing (not reimplementing) 07-02's _ids_in helper"
    requirement: "RESP-03"
    verification:
      - kind: unit
        ref: "tests/test_accessibility.py::test_no_duplicate_ids[...] parametrised over all 20 pages, plus test_no_duplicate_ids_fixture_pages"
        status: pass
    human_judgment: false
  - id: D8
    description: "Visual regression confirmation that neither heading promotion changed rendered size, plus the eleven-step keyboard-only walkthrough at desktop width and 320px across login, dashboard, new-scan wizard, advanced-scan accordions, assets, API tokens, org admin, verify-domain and scan report"
    verification: []
    human_judgment: true
    rationale: "Task 3 is an explicit checkpoint:human-verify (gate=blocking) - rendered-pixel size comparison and real keyboard-tab-order/focus-visibility cannot be proven by a rendered-HTML pytest assertion (this repo has no browser-driving tool). Left genuinely pending, not fabricated here, matching the 07-01/07-02/07-03/07-05 precedent for this same class of check. 07-UI-SPEC.md's one unresolved UI Consideration row (full keyboard-walkthrough coverage) is discharged only once this checkpoint is actually performed."

# Metrics
duration: ~45min
completed: 2026-08-18
status: complete
---

# Phase 7 Plan 6: Heading-Hierarchy Fixes + App-Wide Accessibility Locks Summary

**Closed the codebase's only two confirmed heading-hierarchy violations (marketing.html's sixteen `h4`→`h3` promotions, scan_new_advanced.html's four `h4`→`h2` promotions, both size-pinned to render identically to before), then added `tests/test_accessibility.py` — heading sequence, label coverage, icon-only accessible names, native-element-only interactivity, single-source focus treatment, and app-wide id-uniqueness, asserted over every reachable page in the app including the nine mobile-card blocks waves 1–2 added.**

## Performance

- **Duration:** ~45 min
- **Completed:** 2026-08-18
- **Tasks:** 2 of 3 (Task 3 is a `checkpoint:human-verify`, gate=blocking, genuinely pending)
- **Files modified:** 3 templates + 1 new test file

## Accomplishments

- `templates/marketing.html`: the twelve check-name headings (under "What Glassbox checks") and the four how-it-works step headings were promoted from `<h4>` to `<h3>`, closing the only two heading-skip sequences on the page. The `.check-item h4`/`.step h4` selectors were renamed to `.check-item h3`/`.step h3` in the same edit, keeping their exact prior `font-size`/`margin` declarations, so neither set changed size on screen. A comment above each renamed rule records the A11Y-02 rationale.
- `templates/scan_new_advanced.html`: the four accordion-group question headings (inside each `.adv-group`'s `<summary>`) were promoted from `<h4>` to `<h2>` — the page's primary content divisions, with the existing locked-state `<h2>` becoming a fifth sibling rather than a level the four skip past. `templates/_scan_form_styles.html`'s matching shared-partial selector (`.adv-group h4` → `.adv-group h2`) was updated in lockstep, and `.adv-group > summary h2` in `scan_new_advanced.html` gained an explicit `font-size: 14px; line-height: 1.35; letter-spacing: normal;` so the promoted heading doesn't inherit base.html's 20px `h2` size. Confirmed by grep that `adv-group` appears only in these two templates, so no other `scan_new_*` page was affected.
- `tests/test_accessibility.py` (new, 91 tests): builds its 20-page list programmatically from `app.url_map.iter_rules()` (GET-accepting, zero path arguments, minus a documented `EXCLUDED_ENDPOINTS`/`EXCLUDED_BLUEPRINT_PREFIXES` set covering the health check, logout, static files, and the JSON `/api/v1/*` blueprint), plus three fixture-id pages built separately (a scan report, a still-`QUEUED` scan's progress page, an asset detail page) since none is reachable as a no-parameter GET route. Four `-k`-selectable assertion families run over the whole set:
  - `heading_hierarchy` (22 tests) — no forward heading-level jump greater than one, parsed from the rendered body via BeautifulSoup; zero headings and equal-level adjacency both pass.
  - `labels_and_icon_buttons` (23 tests) — every visible `input`/`select`/`textarea` has a `<label for>` or `aria-label`; every `<label for>` names a real id; every icon-only `<button>` has an `aria-label` with `aria-hidden` on its `<svg>`; a named regression test locks in the eight known icon-only buttons (three asset actions, five password toggles).
  - `no_clickable_divs` (22 tests) — no `div`/`span`/`li`/`td`/`tr` carries a click-handler attribute or `role="button"`, checked against both rendered response bodies and raw template source (catching a violation behind an excluded route).
  - `focus_treatment` (2 tests) — `base.html` is the only template declaring `:focus-visible` anywhere in `templates/`.
  - Plus an id-uniqueness sweep reusing (not reimplementing) 07-02's `_ids_in()` helper, extending that invariant app-wide.
  - Two negative-control tests (one per lock family that mutates a template) prove the heading and label locks actually fail on a broken property, then restore the original file bytes.
- No CSS class, breakpoint, or component was invented anywhere — every declaration touched already existed; the tag-level promotions are the entire accessibility fix.

## Task Commits

1. **Task 1: heading-hierarchy tag promotions** — `ee58240` (fix)
2. **Task 2: `tests/test_accessibility.py`** — `ac151e8` (test)

Task 3 (`checkpoint:human-verify`, gate=blocking) has no code commit — it is a manual visual-regression + keyboard-walkthrough gate. See "Next Phase Readiness" below.

## Files Created/Modified

- `templates/marketing.html` — sixteen headings promoted `h4` → `h3`; two local CSS selectors renamed, declarations unchanged
- `templates/scan_new_advanced.html` — four headings promoted `h4` → `h2`; one local selector renamed with an explicit size pin added
- `templates/_scan_form_styles.html` — matching shared-partial selector renamed `h4` → `h2`
- `tests/test_accessibility.py` (new) — 91 tests across `-k heading_hierarchy`/`-k labels_and_icon_buttons`/`-k no_clickable_divs`/`-k focus_treatment` plus an app-wide id-uniqueness sweep

## Decisions Made

- The plan's acceptance criteria describe the API-tokens page as `/account/api-tokens`; the actual registered route is `/tokens` (`glassbox/api_tokens_routes.py`'s `Blueprint(url_prefix="/tokens")`, confirmed against a real `app.url_map` dump — the `/account/` prefix belongs only to `billing_bp`). Since the plan's own instruction is to build the page list from `app.url_map` rather than by hand, the module uses the real `/tokens` path; `MIN_EXPECTED_PAGES` was written against the actual codebase, not the plan's assumed path. This is a plan-text/codebase mismatch, not a code defect, and no route was added or renamed to accommodate it.
- `auth.login` redirects a GET whenever `current_user.is_authenticated`, and `auth.signup` does the same unless an invite token is present — both are unreachable as a 200 while the seeded admin fixture's session is active. `_get()` logs the session out first for these two paths before requesting them; each parametrised test has its own fresh function-scoped `app`/`client`/`db`, so this can't leak into another test.
- Imported 07-02's `tests/test_responsive_org_tables.py::_ids_in` rather than 07-03's separately-invented `_assert_no_duplicate_ids` (07-03 was written concurrently before 07-02's helper existed on disk) — this plan's `<action>` names 07-02's helper specifically, and only one copy should be relied on going forward.
- The report fixture behind the "scan report" page uses `scan_type="other"` rather than `"base"`, mirroring 07-05's test convention — `scan_report.html`'s base-scan-specific sections (headers/TLS/cookies etc.) are gated behind `{% if scan.scan_type == 'base' %}` and need many more report-JSON keys than this module's accessibility assertions require; `"other"` reaches the same generic findings/severity/locked-checks markup with a minimal fixture.
- A second, throwaway Flask app (`TESTING=True`, `SCHEDULER_ENABLED=False`, in-memory SQLite URI, never queried) is built once at module import time solely so `PAGES` can be derived from a real `app.url_map` before `pytest.mark.parametrize` needs the list at collection time (parametrize IDs are fixed before any per-test fixture runs). The per-test `app`/`client` fixtures build the real app every actual HTTP request in this module goes through — the throwaway app's url_map is read and then discarded.

## Deviations from Plan

None affecting behavior. One documented plan-text/codebase mismatch (the `/account/api-tokens` vs. real `/tokens` path, see Decisions Made above) — not a fix, since the plan's own instruction to build the list from `app.url_map` rather than by hand is what surfaced it, and following that instruction is what's correct here.

## Known Stubs

None.

## Threat Flags

None — this plan's automated additions (`tests/test_accessibility.py`) are read-only over the app's existing pages, and the two template edits are tag-level heading promotions plus matching CSS selector renames with no behavior, copy, or auth-path change. Per the plan's own `<threat_model>`, T-07-23 (the four `authorized*` checkboxes) is confirmed mitigated: `tests/test_scan_wizard.py`'s full suite stayed green after `scan_new_advanced.html`'s edit, and the label-coverage assertion only ever confirms `<label for>` association for those controls, never touches their name/id/`required`/handling. T-07-24 (aria-label spoofing via interpolated record data) remains a `backstop`-verification must_have, discharged only at the Task 3 checkpoint, not here.

## Issues Encountered

None. `tests/test_scan_wizard.py tests/test_public_routes.py -q` (58 tests, covering the two edited pages' existing behavior) passed on first run after Task 1's edits, and `tests/test_accessibility.py` needed two rounds of fixture fixes before its first full green run: (1) `auth.login`/`auth.signup` return 302 while already authenticated — fixed by logging the fixture session out first for those two paths; (2) the scan-report fixture initially used `scan_type="base"`, which needs many more report-JSON keys than provided — fixed by switching to `scan_type="other"`, matching 07-05's own test convention for a minimal report fixture. Both fixes are documented above under Decisions Made rather than tracked as plan deviations, since they're test-fixture-construction details, not changes to plan scope or acceptance criteria.

`git diff templates/base.html` across both this plan's commits is empty, confirmed both by the required acceptance criterion and directly.

## User Setup Required

None — no external service configuration required. Task 3's live verification needs a local dev server (`set FLASK_APP=app.py`, `flask db upgrade`, `python app.py`) and a browser with device-toolbar/responsive-mode support and keyboard-only navigation, already documented in the plan's `<how-to-verify>`.

## Next Phase Readiness

Tasks 1 and 2 (the full code deliverable) are complete, committed, and verified:

- `python -m pytest tests/test_accessibility.py -q` — 91 passed
- `python -m pytest tests/test_accessibility.py -k heading_hierarchy -q` — 22 passed
- `python -m pytest tests/test_accessibility.py -k labels_and_icon_buttons -q` — 23 passed
- `python -m pytest tests/test_accessibility.py -k no_clickable_divs -q` — 22 passed
- `python -m pytest tests/test_accessibility.py -k focus_treatment -q` — 2 passed
- `python -m pytest tests/test_scan_wizard.py tests/test_public_routes.py -q` — 58 passed
- `git diff templates/base.html` — empty
- Full suite `python -m pytest -q` — 548 passed baseline (pre-Task-1, confirmed clean before starting), re-run after both commits landed to confirm no regression (see below)

**Task 3 (`checkpoint:human-verify`, gate=blocking) is genuinely pending human confirmation — not fabricated here.** The plan's `<how-to-verify>` requires a human with a real browser to:

1. **Part 1 — visual regression.** Open `/` at desktop width and confirm the twelve check-name headings and four how-it-works steps are the same size/weight as before. Open `/scan/new/advanced` and confirm the four accordion questions are unchanged in size.
2. **Part 2 — the eleven-step keyboard-only walkthrough** at desktop width, then repeated at 320px: log in, tab through the dashboard, walk the new-scan wizard through the authorization checkbox, expand/collapse each advanced-scan accordion via keyboard, tab to the asset pause/resume/delete icon buttons, revoke an API token card and dismiss the confirm dialog with Escape, tab through org admin's four card lists, open a verify-domain disclosure, tab through a scan report's accordions and a redacted-secret Reveal button, and confirm no focus ring is ever clipped or trapped.

**Resume signal required:** "approved" if Part 1 shows no visible size change and the Part 2 walkthrough completes with a visible focus indicator at every stop; otherwise the step number, the width, and what happened (lost focus indicator, clipped ring, unreachable control, or trap).

`requirements-completed` is left empty in this SUMMARY's frontmatter pending that confirmation, matching the `07-01`/`07-02`/`07-03`/`07-05` precedent. Once approved, A11Y-01/A11Y-02/A11Y-03 should be marked complete in `REQUIREMENTS.md` at the phase gate (07-07), which also re-checks 07-UI-SPEC.md's one unresolved UI Consideration row (full keyboard-walkthrough coverage) against this checkpoint's actual result.

## Self-Check: PASSED

- FOUND: `templates/marketing.html` (sixteen headings promoted, two selectors renamed)
- FOUND: `templates/scan_new_advanced.html` (four headings promoted, one selector renamed + size pin)
- FOUND: `templates/_scan_form_styles.html` (matching shared-partial selector renamed)
- FOUND: `tests/test_accessibility.py` (91 tests, all passing individually and via all four `-k` selectors)
- FOUND: commit `ee58240` (heading-hierarchy tag promotions)
- FOUND: commit `ac151e8` (test module)
