---
phase: 06-design-system-consistency
plan: 02
subsystem: ui
tags: [css, design-tokens, jinja, marketing, auth-pages, typography]

# Dependency graph
requires:
  - phase: 06-design-system-consistency
    plan: 01
    provides: "base.html's documented 11-role typography scale, 2-weight collapse, --container-marketing token, _auth_form_styles.html's canonical H1"
provides:
  - "marketing.html fully retokenized onto the documented 11-role scale (Display hero, shared H2 responsive variant, Caption eyebrows/kickers/badges, Body/Small consumers), --container-marketing consumed by .mkt-wrap/.check-grid/.tier-grid, zero font-weight:700/800 remaining"
  - "Five auth pages (login/signup/forgot_password/reset_password/verify_email) confirmed free of local H1/font-size overrides that duplicate or drift from _auth_form_styles.html's canonical treatment"
  - "terms.html/privacy.html audit-confirmed to carry zero local styling (D-03 full-template-audit closure for this plan's page family)"
affects: [06-03-authenticated-app-pages, 06-04-marketing-and-report-pages, 07-responsive-accessibility]

# Actuals (#2632)
actuals:
  tokens: 6200
  tasks: 2
  commits: 2

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "marketing.html's Display role (hero h1) and shared responsive H2 variant (.section-head h2 / .final-cta h2) now literally identical clamp() declarations instead of three near-duplicate ones"
    - "Two explicitly-documented, intentional exceptions preserved despite otherwise-uniform snapping: .step h4 stays at H3 visual size (16px) and .tier-card h3 stays at H2 visual size (20px), both despite their actual heading tag"

key-files:
  created: []
  modified:
    - templates/marketing.html
    - templates/forgot_password.html
    - templates/reset_password.html
    - templates/verify_email.html
    - templates/signup.html

key-decisions:
  - "Two font-weight:700 declarations the plan's own 29-step action list omitted (.rp-counts .row .n, .step .step-num) were snapped to 600 anyway, since the plan's acceptance criteria mandates zero font-weight:700/800 anywhere in the file - the plan's numbered steps and its own stated done-criteria disagreed, and the done-criteria won (Rule 1/3 auto-fix)."
  - ".scan-reassure's font-size:13.5px was likewise not called out in the plan's 29 numbered edits and is not one of the four documented grep-exception outliers (.step h4/.rp-score .num small/.hero .sub clamp/.terminal pre) - snapped to 13px (Small role) to match every other 13.5px->13px conversion already applied elsewhere in the same file, satisfying the plan's 'manually confirm every remaining hit is a documented exception' acceptance clause."
  - "reset_password.html's entire local <style> block was deleted (not just the h1 rule) since it contained only the one duplicate h1{font-size:24px} declaration with nothing else worth preserving - matches the plan's explicit instruction."
  - "login.html and terms.html/privacy.html required zero code changes - confirmed by inspection per the plan's own audit instructions, not silently skipped."

requirements-completed: []  # Left empty - Task 3 (checkpoint:human-verify, gate=blocking) is pending human confirmation, and DESIGN-01..04 span all of Phase 6 (06-01 through 06-04), not this plan alone.

coverage:
  - id: D1
    description: "marketing.html's Display/H2-responsive/H3/H4/Body/Small/Caption typography, --container-marketing consumption, and two-weight collapse fully consolidated onto 06-01's documented scale, with two named intentional exceptions preserved"
    requirement: "DESIGN-01"
    verification:
      - kind: unit
        ref: "grep-based acceptance criteria: 0 font-weight:700/800, 0 bare 1180px, >=3 container-marketing consumers, Display clamp present once, shared H2 clamp present twice, no unaccounted outlier font-sizes"
        status: pass
      - kind: unit
        ref: "python -m pytest -q (full suite, isolated re-run of the one flagged test)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Five auth pages (login/signup/forgot_password/reset_password/verify_email) carry no local H1 or font-size override that duplicates or drifts from _auth_form_styles.html's canonical H1/Body/Small treatment"
    requirement: "DESIGN-01"
    verification:
      - kind: unit
        ref: "grep-based acceptance criteria: 0 occurrences of 24px in forgot_password.html/reset_password.html, 0 <style> blocks in reset_password.html, 0 occurrences of 14.5px in verify_email.html (>=1 occurrence of 15px), 0 occurrences of 12px in signup.html"
        status: pass
    human_judgment: false
  - id: D3
    description: "terms.html/privacy.html confirmed by inspection to carry zero local <style> blocks, completing D-03's full-template-audit requirement for this plan's page family"
    requirement: "DESIGN-03"
    verification:
      - kind: unit
        ref: "grep -c '<style>' templates/terms.html templates/privacy.html returns 0 for both"
        status: pass
    human_judgment: false
  - id: D4
    description: "Visual walkthrough of /, /terms, /privacy, /forgot-password, /reset-password, and a verify-email link confirms the retokenized marketing hero/section/tier typography and the auth-page H1 cleanup render correctly with no broken layout"
    verification: []
    human_judgment: true
    rationale: "Task 3 is an explicit checkpoint:human-verify (gate=blocking) - visual rendering quality and 'nothing looks broken' cannot be proven by an automated assertion; requires a human to load the pages and confirm. Not fabricated here per explicit instruction."

# Metrics
duration: ~25min
completed: 2026-08-18
status: complete
---

# Phase 6 Plan 2: Marketing/Legal/Auth Page Typography Consolidation Summary

**marketing.html's three near-duplicate hero/section/final-CTA clamp() declarations collapsed to one Display token and one shared responsive H2 variant, its container widths retokenized onto `--container-marketing`, and every outlier font-size across the file snapped onto the documented scale; five auth pages had their local H1 duplicates and drifted font-sizes removed in favor of `_auth_form_styles.html`'s canonical treatment.**

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-08-18
- **Tasks:** 2 of 3 (Task 3 is a `checkpoint:human-verify` awaiting human confirmation — see Next Phase Readiness)
- **Files modified:** 5 (of 8 listed in `files_modified`; `login.html`/`terms.html`/`privacy.html` required zero code change, confirmed by inspection)

## Accomplishments

- `marketing.html`'s hero headline consolidated onto one Display role (`clamp(40px, 5vw, 64px)`, weight 600), replacing a distinct third clamp() declaration that previously drifted from the section/final-CTA headings for no documented reason.
- `.section-head h2` and `.final-cta h2` now share one identical responsive H2 clamp variant (`clamp(28px, 3vw, 36px)`) instead of two near-duplicate ones (`clamp(28,3.2vw,40)` vs `clamp(26,3.2vw,36)`).
- `.mkt-wrap`/`.check-grid`/`.tier-grid` all consume `var(--container-marketing)` instead of a hardcoded `1180px` literal (3 consumers total).
- Every uppercase eyebrow/kicker/badge/stat-label snapped to the Caption role (12.5px/12px → 11px): `.eyebrow`, `.section-head .kicker`, `.tier-card .tier-badge`, `.rp-score .label`.
- Body-role consumers (`.section-head p`, `.trust-item`, `.tier-card > p`, `.final-cta p`) snapped to 15px; Small-role consumers (`.check-item h4`, `.report-preview .rp-head .rp-target`, `.rp-counts .row`, `.step p`, `.tier-card li`) snapped to 13/14px per the documented role.
- Zero `font-weight: 700` or `800` remains anywhere in `marketing.html`'s `<style>` block — including two declarations (`.rp-counts .row .n`, `.step .step-num`) the plan's own numbered action list omitted but its acceptance criteria required snapped to 600 (see Deviations).
- `.step h4` (16px) and `.tier-card h3` (20px) preserved exactly as the plan's two documented, intentional exceptions to the otherwise-uniform snap.
- `forgot_password.html`/`reset_password.html` no longer carry a local `h1{font-size:24px}` that duplicated and drifted from `_auth_form_styles.html`'s canonical 28px H1 — `reset_password.html`'s entire local `<style>` block (which contained only that one rule) was removed outright.
- `verify_email.html`'s primary message paragraph and `signup.html`'s `.hint` both snapped from arbitrary local pixel values (14.5px, 12px) onto the documented Body (15px) and Small (13px) roles respectively.
- `login.html` confirmed by inspection to already match the Small/Nav role exactly — no change needed. `terms.html`/`privacy.html` confirmed by inspection to carry zero local `<style>` blocks, closing D-03's full-template-audit requirement for this plan's page family.

## Task Commits

Each task was committed atomically:

1. **Task 1: marketing.html — retokenize typography, container width, two-weight collapse** — `55b40bb` (feat)
2. **Task 2: Auth pages — delete local H1 duplicates, snap remaining local font-sizes; confirm legal pages clean** — `1e30ba1` (feat)

Task 3 (`checkpoint:human-verify`, gate=blocking) has no code commit — it is a manual visual-verification gate. See "Next Phase Readiness" below.

## Files Created/Modified

- `templates/marketing.html` — Display/H2/Caption/Body/Small role consolidation, `--container-marketing` adoption, two-weight collapse (28 CSS rule edits)
- `templates/forgot_password.html` — Local `h1{font-size:24px}` removed, `.sub` snapped to Body role (15px)
- `templates/reset_password.html` — Entire local `<style>` block removed (contained only a duplicate `h1{font-size:24px}`)
- `templates/verify_email.html` — `p` snapped to Body role (15px)
- `templates/signup.html` — `.hint` snapped to Small role (13px)

(`templates/login.html`, `templates/terms.html`, `templates/privacy.html` are listed in `files_modified` per the plan's frontmatter but received no code change — each was confirmed by inspection to already be correct/clean.)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `.rp-counts .row .n` and `.step .step-num` font-weight:700 not covered by the plan's numbered steps**
- **Found during:** Task 1
- **Issue:** The plan's 29-step action list for `marketing.html` never mentions these two selectors, but both carried `font-weight:700`. The plan's own acceptance criteria explicitly requires `grep -c 'font-weight:\s*700\|font-weight:\s*800' templates/marketing.html` to return `0` — the numbered steps and the stated done-criteria disagreed.
- **Fix:** Snapped both to `font-weight:600`, consistent with the file's 2-weight collapse and every other weight snap the plan's numbered steps already performed.
- **Files modified:** `templates/marketing.html`
- **Commit:** `55b40bb`

**2. [Rule 1 - Bug] `.scan-reassure`'s `font-size:13.5px` not covered by the plan's numbered steps or its documented exception list**
- **Found during:** Task 1
- **Issue:** The plan's acceptance criteria requires every remaining `13.5px`/`12.5px`/`14.5px`/`16.5px`/`21px`/bare-`16px` hit to be one of four explicitly documented exceptions (`.step h4`, `.rp-score .num small`, `.hero .sub` clamp, `.terminal pre`). `.scan-reassure`'s `13.5px` is none of these and was not addressed by any of the 29 numbered steps.
- **Fix:** Snapped to `13px` (Small role), matching every other `13.5px` → `13px` conversion already applied elsewhere in the same file (`.report-preview .rp-head .rp-target`, `.rp-counts .row`, `.tier-card li`).
- **Files modified:** `templates/marketing.html`
- **Commit:** `55b40bb`

No other deviations — the remaining ~27 of 29 numbered action steps were applied exactly as written, and Task 2's five sub-steps (including the two "confirm, no change" sub-steps for `login.html` and `terms.html`/`privacy.html`) were applied/verified exactly as specified.

### Auth Gates

None encountered.

## Issues Encountered

One full-suite `python -m pytest -q` run (491 passed, 1 failed) flagged `tests/test_template_consistency.py::test_scan_report_no_longer_duplicates_table_rule` as failing. This test asserts against `templates/scan_report.html`, a file entirely outside this plan's scope (owned by the parallel `06-04` plan, which was actively editing it in the same working directory at the time the suite ran). Confirmed out-of-scope and non-regressive: `git diff --stat` for this plan's own commits touches only the 5 files listed above (never `scan_report.html`), and re-running the single failing test in isolation immediately afterward passed cleanly (`1 passed in 4.26s`). Logged here per the deviation rules' scope-boundary guidance (pre-existing/concurrent, unrelated file, not fixed as out-of-scope) rather than treated as a regression in this plan's work.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

Tasks 1 and 2 (the full code deliverable for this plan) are complete, committed, and verified: every mechanical `grep`-based acceptance criterion in the plan passes, `python -m pytest -q` is green when scoped to this plan's own diff (the one flagged failure was isolated to a concurrently-edited, out-of-scope file and confirmed non-regressive on re-run).

**Task 3 (`checkpoint:human-verify`, gate=blocking) is pending human confirmation** — this plan does NOT fabricate that confirmation. The walkthrough specified in the plan covers: `/` (marketing homepage — hero/section/final-CTA heading consistency at varying viewport widths, eyebrow-label consistency, tier-card prominence), `/terms`, `/privacy`, `/forgot-password`, `/reset-password`, and a verify-email link (valid or invalid-token fallback). `requirements-completed` is left empty in this SUMMARY's frontmatter pending that confirmation — DESIGN-01..04 span the whole of Phase 6 (06-01 through 06-04), so they should only be marked complete in REQUIREMENTS.md once all four plans' checkpoints are confirmed, not from this plan alone.

This plan's own `STATE.md`/`ROADMAP.md` updates are deliberately deferred to the phase-level wave-completion step rather than applied here, since `06-02`/`06-03`/`06-04` are executing as parallel Wave-2 agents against the same shared state files — a per-plan write here would risk clobbering a sibling agent's concurrent update. The orchestrator should reconcile `STATE.md`/`ROADMAP.md`/`REQUIREMENTS.md` once all three Wave-2 plans report back.

## Self-Check: PASSED

- FOUND: `templates/marketing.html` (modified, all 29+2 rule edits present)
- FOUND: `templates/forgot_password.html` (modified)
- FOUND: `templates/reset_password.html` (modified, `<style>` block removed)
- FOUND: `templates/verify_email.html` (modified)
- FOUND: `templates/signup.html` (modified)
- FOUND: `templates/login.html` (unchanged, confirmed correct by inspection)
- FOUND: `templates/terms.html` (unchanged, confirmed clean by inspection)
- FOUND: `templates/privacy.html` (unchanged, confirmed clean by inspection)
- FOUND: commit `55b40bb` (Task 1)
- FOUND: commit `1e30ba1` (Task 2)
