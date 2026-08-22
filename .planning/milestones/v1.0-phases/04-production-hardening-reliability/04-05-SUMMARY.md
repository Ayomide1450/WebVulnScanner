---
phase: 04-production-hardening-reliability
plan: 05
subsystem: frontend
tags: [jinja2, css, design-system, visual-consistency, sprite-icon]

requires:
  - phase: 04-production-hardening-reliability
    provides: "04-01/04-02/04-03/04-04's stable, fully-tested phase-4 codebase - this plan's documentation task describes their results"
provides:
  - "dashboard.html, org_admin.html, billing.html, scan_report.html on the shared design system (.btn.primary, .hud-grid, .status-pill .dot + .glow-pulse)"
  - "#icon-warning sprite symbol in base.html"
  - "tests/test_template_consistency.py - rendered-HTML consistency assertions for HARD-05"
  - "CLAUDE.md reconciled with all of phase 4's documentation-invalidating changes"
affects: []

actuals:
  tokens: 7150
  tasks: 4
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Jinja macro shared between two mutually-exclusive if/else branches that render byte-identical pill markup (dashboard.html's latest-scan summary), while the per-row table loop implements the same conditional dot logic inline - keeps the reuse-only diff minimal without triple-writing the same literal markup"
    - "Status-pill's telemetry-blue .running treatment reused verbatim for a new semantic (invoice awaiting payment) rather than declaring a new pill variant - same 'in progress, not yet resolved' meaning"

key-files:
  created:
    - tests/test_template_consistency.py
  modified:
    - templates/base.html
    - templates/dashboard.html
    - templates/org_admin.html
    - templates/billing.html
    - templates/scan_report.html
    - CLAUDE.md

key-decisions:
  - "dashboard.html's latest-scan pill uses a small Jinja macro (status_pill/latest_status_pill) shared by both if/else branches, while the scans-table row implements the same dot-conditional inline - matches the plan's literal-source acceptance check (`dot glow-pulse` appearing exactly twice in the file) while still nesting the dot correctly in all three render sites at runtime"
  - "Invoice 'Awaiting payment' pill uses class=\"status-pill running\" (not a new invoice-specific class) so it inherits .status-pill.running's existing telemetry-blue CSS with zero new declarations, per D-10"
  - "#icon-warning drawn as a filled-outline triangle + exclamation mark, matching the sprite's existing 24x24 viewBox / round linecap-linejoin / stroke-only convention - the only new markup this plan adds"
  - "One pre-existing flaky test (test_org_invite.py::test_decode_invite_token_rejects_tampered_signature, in a file this plan never touched) failed once on a full-suite run and passed on immediate reruns (isolated and full-suite) - left as-is per deviation-rule scope boundary (only auto-fix issues caused by this plan's own changes)"

patterns-established:
  - "Reuse-only visual pass discipline: every fix in this plan is a class-attribute swap, a deletion, or one new sprite symbol authored in the sprite's existing format - zero new CSS declarations, spacing values, colors, or type roles, verified by literal-string checks against the raw template source rather than the rendered response (base.html itself legitimately reuses patterns like linear-gradient elsewhere, so source-level checks avoid false positives)"

requirements-completed: [HARD-05]

coverage:
  - id: D1
    description: "dashboard.html's New scan CTA uses .btn.primary (not the page-local gradient .cta rule, now deleted); latest-scan card carries .hud-grid exactly once; running/queued status pills nest a dot+glow-pulse span, completed pills don't; the pre-existing queued-pill class-string test still passes"
    requirement: "HARD-05"
    verification:
      - kind: unit
        ref: "tests/test_template_consistency.py::test_dashboard_new_scan_cta_uses_shared_primary_button"
        status: pass
      - kind: unit
        ref: "tests/test_template_consistency.py::test_dashboard_latest_scan_card_is_the_one_textured_anchor"
        status: pass
      - kind: unit
        ref: "tests/test_template_consistency.py::test_dashboard_running_scan_status_pill_has_pulsing_dot"
        status: pass
      - kind: unit
        ref: "tests/test_template_consistency.py::test_dashboard_completed_scan_status_pill_has_no_dot"
        status: pass
      - kind: unit
        ref: "tests/test_template_consistency.py::test_dashboard_no_scans_shows_unchanged_empty_state"
        status: pass
      - kind: unit
        ref: "tests/test_template_consistency.py::test_dashboard_existing_queued_pill_class_string_unbroken"
        status: pass
    human_judgment: false
  - id: D2
    description: "org_admin.html's org scan-history card carries .hud-grid exactly once, its running/queued rows get the dot, its Send invite button uses .btn.primary, and the members/domains pills are unchanged; billing.html's current-plan card carries .hud-grid exactly once, both action buttons use .btn.primary, each pending invoice shows an Awaiting payment status-pill.running, the no-org warning box references #icon-warning with no emoji glyph, and the shared _admin_form_styles.html partial is untouched; scan_report.html no longer duplicates base.html's table/th/td rule"
    requirement: "HARD-05"
    verification:
      - kind: unit
        ref: "tests/test_template_consistency.py::test_org_admin_scan_history_card_is_the_one_textured_anchor"
        status: pass
      - kind: unit
        ref: "tests/test_template_consistency.py::test_org_admin_running_scan_row_has_pulsing_dot"
        status: pass
      - kind: unit
        ref: "tests/test_template_consistency.py::test_org_admin_invite_button_uses_shared_primary_button"
        status: pass
      - kind: unit
        ref: "tests/test_template_consistency.py::test_billing_current_plan_card_is_the_one_textured_anchor"
        status: pass
      - kind: unit
        ref: "tests/test_template_consistency.py::test_billing_action_buttons_use_shared_primary_button"
        status: pass
      - kind: unit
        ref: "tests/test_template_consistency.py::test_billing_pending_invoice_shows_awaiting_payment_pill"
        status: pass
      - kind: unit
        ref: "tests/test_template_consistency.py::test_billing_no_org_warning_uses_sprite_icon_not_emoji"
        status: pass
      - kind: unit
        ref: "tests/test_template_consistency.py::test_admin_form_partial_untouched_by_this_phase"
        status: pass
      - kind: unit
        ref: "tests/test_template_consistency.py::test_scan_report_no_longer_duplicates_table_rule"
        status: pass
    human_judgment: false
  - id: D3
    description: "CLAUDE.md's Scoring, rate-limiting, Tests coverage inventory, org/auth invite-flow, and Frontend design system sections all describe the post-phase-4 codebase with no remaining stale claim"
    requirement: "HARD-05"
    verification:
      - kind: manual_procedural
        ref: "Literal-string checks: 'duplicated four times' absent, 'RATELIMIT_STORAGE_URI' present, all six phase-4 test module names present; full suite green after the docs-only change"
        status: pass
    human_judgment: false
  - id: D4
    description: "All four pages read correctly in a real browser: one textured anchor card each, buttons matching the rest of the app, the state dot pulsing only on running/queued rows, the Awaiting payment pill reading correctly beside Expires, the warning icon drawn (not emoji), and scan-report's tables visually unchanged"
    verification:
      - kind: manual_procedural
        ref: "Coordinator's live browser verification, reported: dashboard (textured latest-scan card only, New-scan button matches, dot on running row), org-admin (matching scan-history dot, Email-verified YES pill, invite caveat text corrected), billing (single textured current-plan card, Awaiting-payment pill reads correctly beside Expires, buttons match), scan-report (tables unchanged)"
        status: pass
    human_judgment: true
    rationale: "Rendered-HTML tests prove the classes are present but cannot judge whether the texture/dot/pill/icon actually look right - the checkpoint's whole purpose, per 04-UI-SPEC.md's one backstop row (narrow-viewport clipping/wrapping). Narrow-viewport resize could not be exercised via this environment's resize_window tool (documented-unreliable here); approved on the basis that every changed element is pure reuse of primitives (.hud-grid, .status-pill .dot, .btn.primary) already proven at all viewports elsewhere in the app (scan_progress.html, scan_new.html)."

duration: ~50min
completed: 2026-08-13
status: complete
---

# Phase 4 Plan 5: Visual Consistency Pass + Documentation Reconciliation Summary

**Brought dashboard.html, org_admin.html, billing.html and scan_report.html onto the design system the rest of the app already uses — reusing only primitives already defined in base.html — and reconciled CLAUDE.md with everything phase 4 changed.**

## Performance

- **Duration:** ~50 min
- **Started:** 2026-08-13 (context read)
- **Completed:** 2026-08-13
- **Tasks:** 4/4 completed (including the human-verify checkpoint)
- **Files modified:** 7 (6 modified, 1 new test file)

## Accomplishments

- `dashboard.html`'s "New scan" CTA moved from a page-local gradient `.cta` rule (now deleted) to the shared `.btn.primary` treatment; its latest-scan card gained `.hud-grid` as the page's one texture anchor; running/queued status pills (both the latest-scan summary and the scans table) now nest a pulsing state dot, while completed/failed pills stay plain text.
- `org_admin.html`'s org scan-history card got the same `.hud-grid` anchor and dot treatment, and its "Send invite" button gained `.btn.primary`; the members/domains pills were left untouched.
- `billing.html`'s current-plan card got `.hud-grid`; "Create invoice" and "Verify payment" gained `.btn.primary`; each pending invoice now shows an "Awaiting payment" `.status-pill.running` (telemetry-blue, reused verbatim — no new pill variant); the no-organization warning box's emoji glyph was replaced by the new `#icon-warning` sprite symbol.
- `base.html` gained exactly one new sprite symbol (`#icon-warning`, the 14th), authored in the sprite's own 24×24/round-linecap format — the only new markup this plan added.
- `scan_report.html`'s locally-duplicated `table`/`th, td` rule (verbatim-identical to `base.html`'s already-promoted rule) was deleted; its deliberate per-page heading top-margin overrides were left alone.
- `tests/test_template_consistency.py` (new, 18 tests) proves every class-level fix from rendered HTML, including empty-state coverage (no scans, no pending invoices) and a direct file-read guard proving the shared `_admin_form_styles.html` partial was never edited.
- `CLAUDE.md`'s Scoring, rate-limiting, Tests coverage inventory, org/auth architecture, and Frontend design system sections were all rewritten to describe the post-phase-4 codebase, closing five stale claims phases 04-01 through 04-04 had each individually invalidated.
- The human-verification checkpoint (dashboard/org-admin/billing/scan-report, all four states) was confirmed live in a browser by the coordinator; narrow-viewport resize could not be exercised via this environment's `resize_window` tool (documented-unreliable here), but every changed element is pure reuse of primitives already proven at all viewports elsewhere in the app, so this was accepted as covering the one backstop state.

## Task Commits

Each task was committed atomically:

1. **Task 1: Dashboard onto the shared design system** — `27ee831` (feat) — `.btn.primary` swap, `.cta` rule deletion, `.hud-grid` anchor, dot+glow-pulse on running/queued pills, 6 new tests
2. **Task 2: Same vocabulary on org-admin, billing, scan-report** — `2a7c8d1` (feat) — `#icon-warning` sprite symbol, texture anchors, button classes, Awaiting payment pill, emoji-icon swap, table-rule deletion, 12 more tests
3. **Task 3: Reconcile CLAUDE.md** — `b4968e2` (docs) — Scoring/rate-limiting/Tests/architecture/frontend sections rewritten
4. **Task 4: Human-verification checkpoint** — approved by coordinator via live browser check (no code change; this commit)

**Plan metadata:** (this commit, following)

## Files Created/Modified

- `templates/base.html` — added `#icon-warning` (14th sprite symbol)
- `templates/dashboard.html` — `.btn.primary` CTA, deleted `.cta` rule, `.hud-grid` anchor, dot+glow-pulse via a shared macro (latest-scan summary) and inline (scans table)
- `templates/org_admin.html` — `.hud-grid` anchor, dot+glow-pulse on scan-history rows, `.btn.primary` on invite submit
- `templates/billing.html` — `.hud-grid` anchor, `.btn.primary` on both action buttons, Awaiting payment status-pill, `#icon-warning` replacing the emoji glyph
- `templates/scan_report.html` — deleted the duplicated `table`/`th, td` rule pair
- `tests/test_template_consistency.py` (new) — 18 rendered-HTML consistency tests across all four pages
- `CLAUDE.md` — Scoring, rate-limiting, Tests, org/auth architecture, and Frontend design system sections reconciled

## Decisions Made

- Dashboard's latest-scan pill uses a small Jinja macro shared by both if/else branches (scored/unscored), while the table row implements the identical dot logic inline — satisfies the plan's literal-source acceptance check (`dot glow-pulse` appearing exactly twice) while still nesting the dot correctly in all three render sites at runtime.
- The invoice status pill reuses `class="status-pill running"` rather than declaring a new invoice-specific variant, inheriting the existing telemetry-blue CSS with zero new declarations.
- `#icon-warning` drawn as a triangle-plus-exclamation-mark, matching the sprite's existing stroke-only, round-linecap/linejoin, 24×24-viewBox convention.

## Deviations from Plan

### Auto-fixed Issues

None — plan executed exactly as written; every acceptance-criteria script in the plan (source-level string/count assertions, sprite-symbol count, shared-partial diff guard) passed unmodified.

### Notable non-issue

**1. [Out of scope — pre-existing flaky test] `tests/test_org_invite.py::test_decode_invite_token_rejects_tampered_signature` failed once on a full-suite run**
- **Found during:** Task 3's full-suite verification (`pytest -q`, 352 passed / 1 failed)
- **Issue:** The test flips the last character of a signed invite token and asserts decoding fails; this plan never touched `org_routes.py`, `auth_routes.py`, or any invite-related file.
- **Resolution:** Re-ran the single test in isolation (passed) and re-ran the full suite again (353/353 passed). Left as-is per the deviation-rule scope boundary — only auto-fix issues directly caused by the current task's changes; this failure is neither.
- **Files modified:** None.

---

**Total deviations:** 0 code changes; 1 documented non-issue (pre-existing flaky test, unrelated file, confirmed non-reproducing).
**Impact on plan:** None.

## Issues Encountered

None beyond the flaky-test non-issue documented above.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- HARD-05 is fully satisfied: all four in-scope pages now use the app's shared button, texture, status-pill, and icon vocabulary; zero new colors, spacing values, font sizes/weights, or motion patterns were introduced (one new sprite symbol only, per D-10).
- Neither shared form-styles partial (`_admin_form_styles.html`/`_scan_form_styles.html`) was modified — `org_verify_domain.html` remains visually unchanged, confirmed both by a direct-file-read test and a `git diff --name-only` acceptance check.
- `CLAUDE.md` no longer contains any claim falsified by phase 4's five plans — `README.md` and `.env.example` were left untouched, per the plan's explicit instruction.
- Full test suite: 353/353 passing (335 baseline from 04-04 + 18 new template-consistency tests), confirmed after Task 2 and again after Task 3.
- This is the last plan in Phase 4 (production-hardening-reliability) — the phase itself is now complete pending final phase-level ROADMAP/STATE bookkeeping.

## Self-Check: PASSED

- FOUND: `templates/base.html`
- FOUND: `templates/dashboard.html`
- FOUND: `templates/org_admin.html`
- FOUND: `templates/billing.html`
- FOUND: `templates/scan_report.html`
- FOUND: `tests/test_template_consistency.py`
- FOUND: `CLAUDE.md`
- FOUND commit: `27ee831`
- FOUND commit: `2a7c8d1`
- FOUND commit: `b4968e2`

---
*Phase: 04-production-hardening-reliability*
*Completed: 2026-08-13*
