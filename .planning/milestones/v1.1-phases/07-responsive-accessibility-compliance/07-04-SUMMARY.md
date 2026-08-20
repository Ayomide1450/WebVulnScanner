---
phase: 07-responsive-accessibility-compliance
plan: 04
subsystem: ui
tags: [css, responsive, accessibility, auth, jinja, d-02]

# Dependency graph
requires:
  - phase: 07-responsive-accessibility-compliance
    plan: 01
    provides: "base.html's Phase 7 CSS token surface and the @media(max-width:640px) topnav-stack rule this plan's fix reuses"
provides:
  - "_auth_form_styles.html's narrow-width @media (max-width: 640px) block: .auth-wrap padding-top reduced to var(--space-5), .topnav .nav-links a.cta-link hidden - scoped to the five auth pages only by this partial's inclusion set"
affects: [07-07]

# Actuals (#2632)
actuals:
  tokens: 4500
  tasks: 1
  commits: 1

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Page-scoping-by-inclusion: an unscoped .topnav selector placed inside a partial that is {% include %}-d by exactly N templates behaves as page-scoped without needing a class prefix, provided the inclusion set is verified by grep before relying on it."

key-files:
  created: []
  modified:
    - templates/_auth_form_styles.html

key-decisions:
  - "Task 1's 'screenshot before fixing' checkpoint could not be performed live - no browser-automation tool was available in this execution environment. Proceeded with static analysis of the CSS/markup instead (see Deviations), which corroborates 07-RESEARCH.md's diagnosis, but this is explicitly NOT a substitute for the live check the plan calls for. Task 1 and Task 3 (both checkpoint:human-verify, gate=blocking) are left genuinely pending - not fabricated."
  - "Implemented the plan's documented default fix exactly as specified in Task 2, since the static-analysis pass found no evidence contradicting the diagnosis (no local .auth-wrap override in any of the five templates; base.html's topnav stack rule and .auth-wrap's 48px padding-top are exactly as 07-RESEARCH.md described)."

patterns-established: []

requirements-completed: []  # Not marked complete - Task 1 and Task 3 (checkpoint:human-verify, gate=blocking) are pending live human verification; see Next Phase Readiness.

coverage:
  - id: D-02
    description: "_auth_form_styles.html carries one narrow-width @media block that reduces .auth-wrap's top padding to var(--space-5) and hides the topnav's duplicate Sign-up CTA (a.cta-link only) on the five auth pages, without touching base.html, org_verify_domain.html, or any of the five templates' markup"
    requirement: "RESP-02"
    verification:
      - kind: unit
        ref: "python -m pytest tests/test_auth_flows.py -q (31 passed) - auth routes, anti-enumeration, single-use tokens, _safe_next() guard all unchanged"
        status: pass
      - kind: unit
        ref: "python -m pytest -q (502 passed, 0 failed)"
        status: pass
      - kind: manual
        ref: "GET /login, /signup, /forgot-password via Flask test client - all 200, body contains both auth-wrap and cta-link (CTA stays in DOM, suppressed only via CSS at <=640px, so a screen reader / no-CSS client still finds the link)"
        status: pass
      - kind: static
        ref: "git diff templates/_auth_form_styles.html - pure addition (16 lines added, 0 removed); git diff templates/base.html and templates/org_verify_domain.html both empty for this plan; grep confirms _auth_form_styles.html is {% include %}-d by exactly the five auth templates"
        status: pass
    human_judgment: true
    rationale: "Task 1 (before) and Task 3 (after) are both explicit checkpoint:human-verify tasks, gate=blocking, requiring real-browser rendering at 320px/375px, tab-order and click-through confirmation, and non-leakage checks on /dashboard, /, and /org/verify-domain. No browser-automation tool was available in this execution environment; static analysis is not a substitute per the plan's own framing (07-UI-SPEC.md explicitly states its best-informed default 'is not a substitute for the screenshot'). Not fabricated here."

# Metrics
duration: ~20min
completed: 2026-08-18
status: complete
---

# Phase 7 Plan 4: Auth-Page Mobile Layout (RESP-02) Summary

**Added one narrow-width `@media (max-width: 640px)` block to `_auth_form_styles.html` — reducing `.auth-wrap`'s top padding from 48px to 24px and hiding the topnav's duplicate "Sign up" CTA — scoped to exactly the five auth pages (login/signup/forgot_password/reset_password/verify_email) by the partial's own inclusion set, with `base.html` and `org_verify_domain.html` both left byte-identical.**

## Performance

- **Duration:** ~20 min
- **Completed:** 2026-08-18
- **Tasks:** 1 of 3 code/analysis tasks completed (Task 2, the only `type="auto"` task); Task 1 and Task 3 are `checkpoint:human-verify` (gate=blocking) and are genuinely pending
- **Files modified:** 1 template partial

## Accomplishments

- `templates/_auth_form_styles.html` gained a single `@media (max-width: 640px)` block, appended after the existing `.swap` rules, containing exactly two declarations: `.auth-wrap { padding-top: var(--space-5); }` (24px, overriding only the top padding from line 15's `padding: var(--space-7) 22px calc(var(--space-7) * 2)` — side gutters and bottom breathing room untouched) and `.topnav .nav-links a.cta-link { display: none; }` (hides only the green "Sign up" CTA, never the plain Login link or the brand link).
- Confirmed by reading (not editing) all five auth templates that none locally re-declares `.auth-wrap`'s padding, so the fix needed no per-page markup change — exactly the expected outcome the plan called out.
- Confirmed the five-page inclusion set via `grep -rl "_auth_form_styles.html" templates/` (matched only login/signup/forgot_password/reset_password/verify_email as actual `{% include %}` sites; two other files matched only in prose comments, not includes), which is what makes the otherwise-unscoped `.topnav` selector page-scoped in practice.

## Task Commits

Each task was committed atomically:

1. **Task 2: Tighten the auth-page narrow-width layout in `_auth_form_styles.html`** - `a60d11f` (feat)

Task 1 (`checkpoint:human-verify`, gate=blocking, "screenshot before fixing") and Task 3 (`checkpoint:human-verify`, gate=blocking, "live verification after the fix") have no code commits — both are manual visual-verification gates. See "Next Phase Readiness" below.

## Files Created/Modified

- `templates/_auth_form_styles.html` - one appended `@media (max-width: 640px)` block (16 lines); line 15's original `.auth-wrap` declaration and every other existing rule unchanged

## Decisions Made

- Implemented the plan's documented default fix from `07-UI-SPEC.md` exactly as Task 2 specified, since the static-analysis pass (see Deviations) found nothing contradicting 07-RESEARCH.md's diagnosis.
- Did not touch `templates/base.html` or `templates/org_verify_domain.html` — confirmed both have empty `git diff` for this plan.
- Left the `a.cta-link` markup itself in the DOM on all five pages (only its `display` is toggled via CSS at narrow widths) rather than conditionally omitting it server-side, matching the plan's `<action>` instructions precisely and keeping the change reversible by deleting the one CSS block.

## Deviations from Plan

### No browser-automation tool available in this execution environment (affects Task 1 and Task 3)

**Issue:** This plan is explicitly screenshot-first — Task 1 requires setting a 320x667/375x812 device-toolbar viewport in a real browser and answering five observational questions (A-E) per page **before** any CSS is written, and Task 3 requires the same live re-check after the fix plus three non-leakage checks on `/dashboard`, `/`, and `/org/verify-domain`. No browser-driving tool (e.g. Playwright/Chrome automation) was available in this execution environment, so neither checkpoint could be performed as specified.

**What was done instead:** Static analysis of the relevant CSS and markup, standing in for — but explicitly not equivalent to — the live check:
- Confirmed `base.html`'s existing `@media (max-width: 640px) { .topnav { flex-direction: column; ... } }` rule (base.html lines 304-307) does stack brand-then-nav-links vertically below 640px, exactly as 07-RESEARCH.md described.
- Confirmed `.auth-wrap`'s pre-fix `padding-top` was `var(--space-7)` (48px) via the shorthand `padding: var(--space-7) 22px calc(var(--space-7) * 2)` on line 15, with no responsive override before this plan.
- Confirmed (via `grep`) none of the five auth templates locally re-declares `.auth-wrap`'s padding in their own inline `<style>` blocks, so nothing could win over the new media-query rule.
- Confirmed each template's counterpart-link situation matches the plan's must-haves: login/signup/forgot_password end with a `.swap` div, verify_email has an `a.back`, reset_password has neither (so its topnav Login link must stay visible — it does, since only `a.cta-link` is hidden).
- Used a Flask test-client GET against `/login`, `/signup`, `/forgot-password` to confirm all three return 200 and the response body contains both `auth-wrap` and `cta-link` markup (server-rendered content unaffected — the suppression is CSS-only, so the link remains in the DOM and reachable to any client that doesn't apply the narrow-width stylesheet, e.g. a screen reader with CSS disabled).

**What this does NOT confirm**, and why Task 1 and Task 3 are left genuinely pending rather than marked done:
- The actual rendered gap size, whether it "reads as deliberate" (07-RESEARCH.md's own words describe this as unknowable from static reading — that's precisely why Task 1 exists as a separate step from Task 2)
- Real-browser keyboard tab order and focus-ring visibility on the password-toggle button
- Visual absence of horizontal scroll/clipping/overlap, including the long-validation-error wrap case
- The three live non-leakage checks: authenticated `/dashboard` topnav still showing its full link set, the marketing page `/` still showing its Sign-up CTA, and `/org/verify-domain` still rendering as the wide app-shell layout (its `git diff` being empty is a strong static signal but not the same as viewing the rendered page)

Per explicit instruction for this execution: "if browser tooling isn't available in your environment, do your best with static analysis of the CSS and note the limitation in the SUMMARY rather than fabricating a visual confirmation." That is what this section records. Task 1 and Task 3's `<resume-signal>`s have not been answered by a human and are not fabricated here.

### Concurrent-worktree commit collision (process note, not a code deviation)

During the commit step, `git add templates/_auth_form_styles.html` staged only this plan's file, but a parallel Wave 2 agent (working in the same shared working directory, not an isolated worktree) had concurrently staged its own in-progress changes (`templates/api_tokens.html`, `templates/assets.html`, `tests/test_responsive_asset_tables.py` — evidently 07-05's scope) at the same moment. The first `git commit` picked up all four staged paths into one commit. This was caught immediately by inspecting `git show --stat HEAD` before moving on: `git reset --soft HEAD~1` undid the commit (keeping everything staged as it was), then `git reset templates/api_tokens.html templates/assets.html tests/test_responsive_asset_tables.py` unstaged the other agent's files back to their pre-collision state (unstaged/untracked, unchanged content — nothing of theirs was lost or altered), and a clean re-commit (`a60d11f`) was made containing only `templates/_auth_form_styles.html`. Verified via `git show --stat a60d11f`: 1 file changed, 16 insertions, 0 deletions.

## Issues Encountered

None beyond the two items above. `python -m pytest -q` ran the full suite once, standalone, 502 passed / 0 failed in ~4m39s, with only pre-existing SQLAlchemy `LegacyAPIWarning`/`DeprecationWarning` noise unrelated to this plan's template-only change.

## User Setup Required

None for the code change itself. Task 1 and Task 3's live verification require a local dev server (`set FLASK_APP=app.py`, `flask db upgrade`, `python app.py`) and a browser with device-toolbar/responsive-mode support, as documented in the plan's `<how-to-verify>` sections — this is unchanged from the plan and is what remains outstanding.

## Next Phase Readiness

The code deliverable (Task 2) is complete, committed (`a60d11f`), and verified: `python -m pytest tests/test_auth_flows.py -q` is green (31 passed), the full suite `python -m pytest -q` is green (502 passed, 0 failed), `git diff templates/_auth_form_styles.html` is a pure 16-line addition, `git diff templates/base.html` and `git diff templates/org_verify_domain.html` are both empty for this plan, and a Flask test-client check confirms `/login`, `/signup`, `/forgot-password` all return 200 with the expected markup present.

**Task 1 and Task 3 (both `checkpoint:human-verify`, gate=blocking) are genuinely pending human confirmation — not fabricated here.** A human with a real browser still needs to:

1. **Task 1 (retroactive, since the fix is already applied):** Given the code is already in place, the strict "before" screenshot is no longer obtainable without a revert. If a true before/after comparison is still wanted, `git show a60d11f^:templates/_auth_form_styles.html` reproduces the pre-fix file for a temporary local revert-and-screenshot pass.
2. **Task 3 (the primary remaining gate):** Load each of the five pages at 320x667 and 375x812, confirm the first form field (or verify_email's message) is visible without scrolling, confirm the gap above the card reads as deliberate rather than as dead space, confirm the topnav shows Login but not Sign-up while each card's own counterpart link still works, confirm no horizontal scroll/clipping (including a submitted long validation error on `/login`), confirm the password-toggle eye button still works and shows a focus ring on Tab. Then the three non-leakage checks: `/dashboard` logged in still shows its full authenticated link set, `/` logged out still shows its Sign-up CTA, `/org/verify-domain` still renders as the wide app-shell layout.

`requirements-completed` is left empty in this SUMMARY's frontmatter pending that confirmation, matching the `07-01` precedent for a plan whose only remaining gate is a live checkpoint. Once approved, RESP-02 should be marked complete in `REQUIREMENTS.md`, and 07-07's final sweep can re-check these five pages against the "before" diagnosis recorded here.

## Self-Check: PASSED

- FOUND: `.planning/phases/07-responsive-accessibility-compliance/07-04-SUMMARY.md`
- FOUND: commit `a60d11f` (Task 2)
- FOUND: `templates/_auth_form_styles.html` contains `@media (max-width: 640px)`, `.auth-wrap { padding-top: var(--space-5); }`, and `.topnav .nav-links a.cta-link { display: none; }`
