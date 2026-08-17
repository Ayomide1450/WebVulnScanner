---
phase: 05-new-scan-flow-redesign
plan: 01

subsystem: ui
tags: [flask, jinja, scan-routes, wizard, ssrf-guard, entitlements]

# Dependency graph
requires:
  - phase: 01-asset-inventory-continuous-scanning
    provides: DomainVerification model and verified_at semantics consumed by _verified_domain_choices()
provides:
  - "/scan/new (Step 1: Select Domain) with verified-domain dropdown + equally-visible free-text input"
  - "/scan/new/type (Step 2: Select Type) 4-card grid with SCANUX-03 availability labels and SCANUX-04 Upgrade-to-Unlock CTAs"
  - "/scan/new/base restructured as Step 3 (Confirm Authorization + Start Scan) with target prefill and in-flight submit state"
  - "_scan_wizard_stepper.html shared 4-node stepper partial reused by 05-02's remaining three scan-type Step-3 pages"
  - "_verified_domain_choices/_prefill_target/_scan_type_availability helpers and SCAN_TYPE_CARDS/AVAILABILITY_* constants in scan_routes.py"
affects: [05-02-media-api-advanced-wizard-steps, 05-03-scan-status-polling, 06-design-system-consistency]

# Actuals (#2632)
actuals:
  tokens: 10400
  tasks: 3
  commits: 2

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "?target= as the wizard's cross-step state carrier (no server-side session state) — every Step 2/3 route and CTA link round-trips it"
    - "Display-only availability helper (_scan_type_availability) kept strictly separate from the POST-time authorization gate (FEATURE_REQUIREMENTS/authorized*/_unsafe_target_error), which remains the single source of truth"
    - "select sharing the input[type=text] CSS rule pair (same precedent as _admin_form_styles.html) instead of a bespoke select style"

key-files:
  created:
    - templates/_scan_wizard_stepper.html
    - templates/scan_new_type.html
  modified:
    - webvulnscanner/scan_routes.py
    - templates/base.html
    - templates/_scan_form_styles.html
    - templates/scan_new.html
    - templates/scan_new_base.html
    - tests/test_scan_wizard.py

key-decisions:
  - "D-01 implemented: verified-domain dropdown sources org-scoped DomainVerification rows only (never Asset rows); free-text target stays an equally-visible parallel input, never hidden behind a toggle."
  - "D-03 implemented: Upgrade-to-Unlock CTA resolves its href from whichever gate is actually blocking a scan type — /billing for a plan-tier block, org.verify_domain_view for a domain-verification block — with plan-tier checked first since only a plan upgrade can move a blocked user forward."
  - "_scan_type_availability() is documented and tested as display-only; every new_scan_* POST handler keeps its own tier/authorized/SSRF gate unchanged, verified by byte-identical diffs on entitlements.py and checks.py."

patterns-established:
  - "Shared wizard-step partial (_scan_wizard_stepper.html) driven by a caller-set wizard_step (1/2/3) Jinja variable, with step 3 marking both the Confirm Authorization and Start Scan nodes active on one screen."
  - "_prefill_target(field) helper: POST branch reads request.form so a validation-error re-render never clears user input; GET branch reads ?target= so scan_report.html's existing re-scan link becomes functional."

requirements-completed: [SCANUX-01, SCANUX-02, SCANUX-03, SCANUX-04]

coverage:
  - id: D1
    description: "Step 1 (/scan/new) renders the 4-node stepper and a verified-domain dropdown (org-scoped, verified_at set) plus an equally-visible free-text target input"
    requirement: "SCANUX-01"
    verification:
      - kind: unit
        ref: "tests/test_scan_wizard.py (Step 1 tests: stepper labels, org-scoped dropdown, empty-state placeholder, error re-render)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Step 2 (/scan/new/type) resolves verified_domain vs typed target (dropdown wins), re-validates via normalize_target + _unsafe_target_error, and renders 4 cards with SCANUX-03 availability labels"
    requirement: "SCANUX-02"
    verification:
      - kind: unit
        ref: "tests/test_scan_wizard.py (Step 2 tests: target resolution precedence, SSRF error re-render, Standard Scan title)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Locked cards render an Upgrade to Unlock anchor routed by the actual blocking gate (billing for tier, org.verify_domain_view for unverified domain), never a disabled control"
    requirement: "SCANUX-03"
    verification:
      - kind: unit
        ref: "tests/test_scan_wizard.py (availability-label and CTA-href tests for free-tier and ORG_VERIFIED-tier callers)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Step 3 (/scan/new/base) prefills target from ?target=, preserves typed input on validation error, shows Confirm Authorization + Start Scan stepper state and selection summary, and launches single/bulk scans unchanged"
    requirement: "SCANUX-04"
    verification:
      - kind: unit
        ref: "tests/test_scan_wizard.py (Step 3 tests: prefill on GET, preserved input on error, single/bulk Scan-row creation, SSRF rejection)"
        status: pass
    human_judgment: false
  - id: D5
    description: "Live browser walk of Steps 1-3: stepper states, select/input visual parity, empty-state hint, Continue enable/disable, locked-card CTA destinations, target prefill into Step 3, in-flight Starting scan... state, redirect to progress/report"
    verification:
      - kind: manual_procedural
        ref: "Task 3 checkpoint:human-verify, approved in prior session"
        status: pass
    human_judgment: true
    rationale: "Visual/interaction verification (stepper highlighting, focus-state parity between select and input, disabled-button behavior, CTA routing, page-to-page redirects) requires a human eyeball on rendered UI, not just HTTP-response assertions. Two sub-paths were NOT walked live in this session: narrow-viewport (~360px) reflow, because this environment's browser tool has no working resize_window control, and the locked-card Upgrade-to-Unlock path, because the verifying account is fully unlocked (Org-verified + Paid). Both are covered by automated assertions instead: the reflow relies on the pre-existing, untouched .scan-type-grid repeat(auto-fit, minmax(240px, 1fr)) CSS rule (not modified by this plan), and the locked-card path is covered by tests/test_scan_wizard.py's free-tier and ORG_VERIFIED-without-verified-domain assertions on card labels and Upgrade to Unlock href targets. The human approved the checkpoint on this basis in the prior session; treated as fully passed here, not re-run."

duration: ~15min (spans two sessions; this session only ran verification + wrote closing artifacts)
completed: 2026-08-17
status: complete
---

# Phase 5 Plan 1: Select Domain -> Select Type -> Start Scan Wizard Summary

**Replaced the flat 4-card scan chooser with a linear 3-step wizard (verified-domain dropdown + free-text target, availability-labeled type grid, prefilled confirm-and-launch) sharing one stepper partial, with the Standard Scan path wired end to end and 24 new tests.**

## Performance

- **Duration:** ~15 min this session (tasks 1-2 executed and committed in a prior session; this session ran the full test suite once and produced closing artifacts)
- **Started:** 2026-08-15T20:33:14+01:00 (Task 1 commit)
- **Completed:** 2026-08-17 (this closing session)
- **Tasks:** 3 (2 auto/tracer tasks + 1 checkpoint:human-verify, all complete)
- **Files modified:** 8 (`webvulnscanner/scan_routes.py`, `templates/base.html`, `templates/_scan_wizard_stepper.html`, `templates/_scan_form_styles.html`, `templates/scan_new.html`, `templates/scan_new_type.html`, `templates/scan_new_base.html`, `tests/test_scan_wizard.py`)

## Accomplishments
- `/scan/new` is now Step 1 (Select Domain): a `<select>` populated only from the caller org's verified `DomainVerification` rows (D-01), an equally-visible free-text target input never behind a toggle, and the 4-node stepper.
- New `/scan/new/type` route (Step 2, Select Type): resolves the chosen target (dropdown wins over free text), re-validates it through `normalize_target`/`_unsafe_target_error`, and renders a 4-card grid where the base card reads "Standard Scan" and every card carries exactly one of the three SCANUX-03 labels (`Included` / `Requires Verified Domain` / `Requires Paid Plan`), with locked cards showing an `Upgrade to Unlock` anchor routed by whichever gate is actually blocking (D-03).
- `/scan/new/base` is now Step 3 (Confirm Authorization + Start Scan): target prefilled from `?target=`, a Target/Scan-type selection summary, both stepper nodes 3 and 4 active, and a "Starting scan..." in-flight submit state — single and bulk-target launch, the authorized checkbox, and the SSRF gate all unchanged.
- `_scan_type_availability()` is display-only and documented as such; every `new_scan_*` POST handler keeps its own tier/authorized/SSRF checks as the single source of truth (verified by byte-identical `entitlements.py`/`checks.py` diffs).
- 24 new tests in `tests/test_scan_wizard.py` covering all three steps; full suite (430 tests) green with zero failures.

## Task Commits

Each task was committed atomically:

1. **Task 1: Select Domain -> Select Type -> launch, one path end to end** - `f67478f` (feat, tracer)
2. **Task 2: Standard Scan page becomes Step 3 (Confirm Authorization + Start Scan)** - `eeb58de` (feat)
3. **Task 3: Walk Steps 1-3 in a browser** - checkpoint:human-verify, approved in prior session (no code commit; verification-only task)

**Plan metadata:** (this commit — see Final Commit below)

_Both code tasks were TDD (`tdd="true"`): tests were written/extended in `tests/test_scan_wizard.py` alongside each task's implementation and run to green before commit; no separate RED-only commit was produced for this tracer/auto pairing (single commit per task per plan convention)._

## Files Created/Modified
- `webvulnscanner/scan_routes.py` - `_verified_domain_choices`, `_prefill_target`, `_scan_type_availability` helpers; `AVAILABILITY_*`/`SCAN_TYPE_CARDS` constants; new `new_scan_type()` route; `new_scan()` repurposed as Step 1; `new_scan_base()` passes `prefill_target` into all 5 render sites
- `templates/base.html` - added `#icon-check` sprite symbol only (no other changes)
- `templates/_scan_wizard_stepper.html` - new shared 4-node stepper partial
- `templates/_scan_form_styles.html` - additive `select` styling (shares `input[type=text]` rule pair), `.wizard-steps`/`.wizard-step`/`.or-divider`/`.wizard-summary` classes
- `templates/scan_new.html` - rewritten as Step 1 (verified-domain dropdown + free-text target)
- `templates/scan_new_type.html` - new Step 2 template (4-card availability grid)
- `templates/scan_new_base.html` - rewritten as Step 3 (stepper, selection summary, prefill, in-flight submit state)
- `tests/test_scan_wizard.py` - 24 tests across all three steps

## Decisions Made
- D-01 and D-03 (from 05-UI-SPEC.md) implemented exactly as specified — no deviation.
- `?target=` chosen as the wizard's cross-step state carrier (query parameter, not server session) — this is the contract 05-02's remaining three Step-3 pages and `scan_report.html`'s existing re-scan link consume; flagged in the plan as a "costly" reversibility item, accepted as-is.

## Deviations from Plan

None - plan executed exactly as written. No Rule 1-4 auto-fixes were needed; `entitlements.py` and `checks.py` remain byte-identical to their pre-task state as required by the plan's acceptance criteria.

## Issues Encountered

None during task execution. In this closing session, `python -m pytest` needed to be invoked via the project's `.venv/Scripts/python.exe` (bare `python -m pytest` failed with "No module named pytest" since the system Python has no dev dependencies installed) — not a plan deviation, just the correct local invocation per CLAUDE.md's documented test command.

## Checkpoint Verification (Task 3)

Live-verified and approved in a prior session. Confirmed working end to end: Select Domain (verified-domain dropdown + free-text) -> Select Type (Standard Scan title, correct availability pills, correct 4-card grid) -> Confirm Authorization + Start Scan (target/domain correctly prefilled) -> submit shows "Starting scan..." disabled state -> redirects to progress page -> auto-redirects to report with real findings.

Two sub-paths from the plan's `<how-to-verify>` were **not** walked live, with justification recorded in this SUMMARY's `coverage` block (D5):
- **Narrow-viewport (~360px) reflow** on Step 2 — this environment's browser tool has no working `resize_window` control. Accepted on the strength of the 24 automated tests plus the fact that the reflow relies entirely on the pre-existing, unmodified `.scan-type-grid { repeat(auto-fit, minmax(240px, 1fr)) }` rule — this plan did not touch that CSS.
- **Locked-card "Upgrade to Unlock" path** — the verifying test account is fully unlocked (Paid + Org-verified), so no locked card was available to click through live. Covered instead by `tests/test_scan_wizard.py`'s automated assertions on free-tier and ORG_VERIFIED-without-verified-domain responses (card label text and `Upgrade to Unlock` anchor `href` values for both `/billing` and `org.verify_domain_view` destinations).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `_scan_wizard_stepper.html`, the `input[type=text], select` CSS pairing, `SCAN_TYPE_CARDS`, `_scan_type_availability()`, and the `?target=` carrier contract are all in place and ready for 05-02 to extend the media/API/advanced scan pages into Step-3 wizard pages the same way `scan_new_base.html` was converted here.
- No blockers. `entitlements.py`, `checks.py`, and every validation/SSRF gate are verified unchanged (byte-identical diffs), so 05-02 inherits a frozen, trusted safety surface to build against.

## Self-Check: PASSED

All 8 files listed under Files Created/Modified were verified present on disk, and both task
commit hashes (`f67478f`, `eeb58de`) were verified present in `git log --oneline --all`.

---
*Phase: 05-new-scan-flow-redesign*
*Completed: 2026-08-17*
