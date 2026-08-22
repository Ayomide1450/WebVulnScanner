---
phase: 09-seo-performance-ux-states
plan: 02
subsystem: ui-states
tags: [empty-state, submitting-state, forms, ux]
dependency-graph:
  requires: []
  provides: ["templates/_empty_state.html"]
  affects:
    - templates/dashboard.html
    - templates/assets.html
    - templates/org_admin.html
    - templates/billing.html
    - templates/api_tokens.html
    - templates/org_verify_domain.html
tech-stack:
  added: []
  patterns:
    - "Jinja {% call %} block instead of a |safe-filtered icon variable, to stay inside the SEC-04 no-|safe regression lock"
key-files:
  created:
    - templates/_empty_state.html
    - tests/test_ui_states.py
  modified:
    - templates/dashboard.html
    - templates/assets.html
    - templates/org_admin.html
    - templates/billing.html
    - templates/api_tokens.html
    - templates/org_verify_domain.html
decisions:
  - "empty_state(title, message, cta_label=none, cta_url=none) uses a {% call %} block for the icon's inner SVG markup instead of the UI-SPEC's literal `{{ icon|safe }}` signature, since this codebase has a Phase-8 regression lock that fails the suite on any |safe usage anywhere - achieves byte-identical output without tripping it"
  - "Migrating org_verify_domain.html's old standalone .warn-box empty state onto the new partial closes the CLAUDE.md-documented open exception as a side effect of Task 2, not a separate request"
  - "Scoped the submitting-state gap closure (STATE-02) to the real 12 gaps found by grounding against actual templates, not a blanket re-touch of all forms - 6 forms (4 scan-launch + login/signup) already had the full disabled+text-swap pattern"
metrics:
  duration: "~3 hours"
  completed: 2026-08-20
status: complete
actuals:
  tokens: unknown (session predates this SUMMARY.md write)
  tasks: 3
  commits: 1
---

# Phase 9 Plan 2: STATE-01/02 Summary

Shared `_empty_state.html` partial (migrates 3 existing inline empty-states + adopts 7 new call
sites, closing the org_verify_domain.html `.warn-box` exception CLAUDE.md documented as
outstanding) and closure of the 12 real submitting-state gaps found by grounding the plan against
actual templates rather than assuming a blanket fix was needed.

## What was built

**`templates/_empty_state.html`** - single `empty_state(title, message, cta_label=none,
cta_url=none)` macro, called via Jinja's `{% call %}` block construct (the icon's inner SVG
markup is the call-block body) rather than a `|safe`-filtered variable - this codebase has a
Phase-8 SEC-04 regression lock (`test_no_template_disables_autoescaping_or_uses_safe_filter`)
that fails the whole suite if any template anywhere uses `|safe`, with no per-file exemption.
The call-block approach achieves the same rendered output with real template markup, verified
against this app's actual Jinja2 version before writing the file.

**Adopted on**: dashboard.html and assets.html (migrated from their own one-off inline markup),
org_admin.html, billing.html, api_tokens.html, and org_verify_domain.html (new adoptions) -
7 call sites total across 6 templates.

**Submitting-state gap closure (STATE-02)**: closed the 12 real gaps (forgot_password.html,
reset_password.html, org_admin.html's invite form, org_verify_domain.html's add/verify forms,
billing.html's create/verify-invoice forms) rather than re-touching the 6 forms that already had
the disabled+text-swap pattern (4 scan-launch forms, login.html, signup.html).

**`tests/test_ui_states.py`** - coverage for the partial's rendering and the gap closures.

## Deviations from Plan

- Signature deviates from 09-UI-SPEC.md's literal `{{ icon|safe }}` form for the SEC-04 reason
  above - documented in the partial's own file-header comment, not a silent departure.

## Self-Check

- `templates/_empty_state.html` - FOUND
- `tests/test_ui_states.py` - FOUND
- Commit `f3811f6` - FOUND in `git log`
- Full suite: one pre-existing-markup test
  (`test_responsive_org_tables.py::test_verify_domain_zero_records_shows_no_cards_and_one_warn_box`)
  needed its assertion updated from `.warn-box` to `.empty-state` to match the intentional
  migration - fixed in the same commit, confirmed passing (12/12 in that file, 791 passed on
  merged master overall)

## Self-Check: PASSED

**Note:** this SUMMARY.md was written retroactively during milestone close-out (2026-08-20) -
the plan's execution predates this file (background `gsd-executor` worktree agent, verified and
merged in an earlier session in this conversation). Content reconstructed from the plan's actual
commit and diff, not guessed.
