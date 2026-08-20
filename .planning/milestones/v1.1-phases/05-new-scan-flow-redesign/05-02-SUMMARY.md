---
phase: 05-new-scan-flow-redesign
plan: 02

subsystem: ui
tags: [flask, jinja, scan-routes, wizard, smart-setup, copy-audit]

# Dependency graph
requires:
  - phase: 05-new-scan-flow-redesign
    plan: 01
    provides: "_scan_wizard_stepper.html, _prefill_target/_scan_type_availability helpers, SCAN_TYPE_CARDS, the ?target= carrier contract"
provides:
  - "/scan/new/media and /scan/new/api restructured as wizard Step 3 (Task 1, as originally planned)"
  - "/scan/new/advanced restructured as a URL-first Smart Setup page with auto-detected login-form pre-fill (Task 2 SUPERSEDED - see D-02a in 05-CONTEXT.md)"
  - "checks.detect_login_form() and POST /scan/new/advanced/detect - read-only UX aid, never a gate, never runs before authorization is confirmed"
  - "_availability_for()/_media_render_kwargs()/_api_render_kwargs()/_advanced_render_kwargs() helpers in scan_routes.py"
  - "Plain-language copy pass across scan_new.html, scan_new_type.html, and all four scan-type pages' titles/blurbs"
affects: [05-03-scan-status-polling, 06-design-system-consistency]

# Actuals
actuals:
  tasks: 2 of 3 (Task 1 as planned; Task 2 superseded by the Smart Setup redesign; Task 3 checkpoint not run)
  commits: pending

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "_availability_for(key, tier, org, target_url) delegates to _scan_type_availability() so a per-type Step 3 page's pill can never drift from Step 2's card grid - one shared source of truth, not a second copy of the labeling rule"
    - "Smart Setup: a read-only detection endpoint (POST /scan/new/advanced/detect) that independently re-requires authorized_adv=on in its own request body, so it cannot be triggered by a stray client call before the user has confirmed authorization - a UX aid layered on top of, never inside, the existing safety gates"
    - "Progressive disclosure (collapsed <details> per advanced check group, auto-expanded only on a detection hit) replaces a flat 16-field form for a non-technical user, without changing any field name _parse_advanced_form reads"

key-files:
  created:
    - tests/test_detect_login_form.py
  modified:
    - webvulnscanner/checks.py
    - webvulnscanner/scan_routes.py
    - templates/scan_new_media.html
    - templates/scan_new_api.html
    - templates/scan_new_advanced.html
    - templates/scan_new.html
    - templates/scan_new_type.html
    - tests/test_scan_wizard.py

key-decisions:
  - "D-02a (supersedes D-02's 'stays as-is' clause, recorded in 05-CONTEXT.md): Advanced's intake form opens URL-first (one target field + the authorization checkbox) instead of exposing all 16 credential fields immediately. Only after authorization is confirmed does the page call the new detect endpoint, which crawls the target for a real <input type=\"password\"> form and pre-fills the login-bypass group. All four check groups render as plain-language, non-jargon collapsed cards. Field names, _parse_advanced_form, the four has_*_group predicates, and every server-side gate are byte-identical to before - only presentation changed."
  - "Crawl timing is a locked constraint (user-confirmed this session): detect_login_form() must never run before authorized_adv is present in the same request. Enforced server-side (the /detect endpoint 400s without it, verified never calling detect_login_form), not just client-side JS discipline."
  - "Site-wide copy audit scoped to the scan-creation flow only (base/media/api/advanced/type/domain pages) per this session's explicit instruction - other pages (dashboard, billing, org admin, etc.) are out of scope and unaudited."

patterns-established:
  - "detect_login_form(base_url, session=None, extra_paths=()) tries the base URL, a short list of common login paths, and same-origin AUTH_LIKE_PATH_HINTS links from the homepage; returns the form's POST action (not the page it was found on) plus a best-effort username-field guess, or None - network errors on individual candidates are swallowed so one dead path doesn't fail the whole attempt, same convention every check_* function in checks.py already follows."

requirements-completed: [SCANUX-01, SCANUX-03, SCANUX-04]

coverage:
  - id: D1
    description: "Media and API launch pages are wizard Step 3 with target prefill, the shared availability pill, Upgrade to Unlock on the locked render, and validation-error field retention"
    requirement: "SCANUX-01"
    verification:
      - kind: unit
        ref: "tests/test_scan_wizard.py (20 media/api tests: prefill, locked-state, validation-error redisplay, free-tier-cannot-POST-around-lock, paid-tier launch+redirect, XSS-escape)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Advanced's intake is URL-first; auto-detection never fires before authorized_adv is confirmed; a detection hit pre-fills and auto-expands the login group; the form still launches on partial fill and still refuses on no group filled, unchanged"
    requirement: "SCANUX-01, SCANUX-03, SCANUX-04"
    verification:
      - kind: unit
        ref: "tests/test_scan_wizard.py (15 advanced/detect tests) + tests/test_detect_login_form.py (8 crawl/parse unit tests)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Scan-creation flow copy (page titles, card blurbs, headers) reads in plain language with no unexplained security jargon"
    verification:
      - kind: unit
        ref: "tests/test_scan_wizard.py's existing title/label assertions continue to pass against the rewritten copy (Standard Scan/Media Scan/API Scan/Advanced Scan titles, plain-language SCAN_TYPE_CARDS blurbs)"
        status: pass
    human_judgment: true
    rationale: "Whether copy genuinely reads as plain-language/non-generic to a non-technical user is a subjective judgment a test suite can assert consistency for but not originate - the user directly reviewed and directed this rewrite in conversation this session."

duration: ~1.5hr (this session, combined with 05-03)
completed: 2026-08-17
status: executed (Task 3 human-verify checkpoint outstanding; Task 2 as originally written is superseded, not executed)
---

# Phase 5 Plan 2: Media/API Wizard Steps + Advanced Smart Setup Summary

**Media and API launch pages became wizard Step 3 exactly as planned; Advanced's Step 3 shipped as a URL-first "Smart Setup" page (auto-detected login form, progressive-disclosure plain-language groups) instead of the originally-planned unchanged 16-field form, per an explicit user request this session - recorded as D-02a, superseding D-02's "stays as-is" clause. A copy audit also rewrote page titles and card blurbs across the scan-creation flow into plain language.**

## Accomplishments
- **Media & API (Task 1, as planned):** `_availability_for()` added; both routes pass `prefill_target`/`availability` at every render site; both templates rebuilt with the stepper, back-link, selection summary, `Starting scan...` submit state, and `Upgrade to Unlock` locked render. Fixed the same input-loss defect class CLAUDE.md flags for this page family (`media_target`/`api_target` now carry `value="{{ prefill_target }}"`).
- **Advanced Smart Setup (Task 2, superseded shape):** `checks.detect_login_form()` crawls a target (only after authorization is confirmed) for a real password-shaped form and returns its POST action plus a best-effort username-field guess. `POST /scan/new/advanced/detect` is the read-only endpoint the page's JS calls, independently re-checking `authorized_adv` server-side. The form now opens with just a target field + checkbox; the four check groups (login-bypass, SQLi UNION, stored XSS, IDOR) are collapsed `<details>` cards with plain-English questions and field-level micro-copy (exact DevTools steps for a session cookie, etc.), with the login group auto-expanding on a detection hit.
- **Copy audit:** `scan_new.html`/`scan_new_type.html` headers rewritten as direct questions ("Which website do you want to scan?" / "What kind of scan do you want to run?"); `SCAN_TYPE_CARDS` blurbs rewritten from technical jargon ("Auth-bypass SQLi, brute-force, UNION/error/time-based SQLi...") to plain outcomes ("Tests things only a logged-in attacker could try...").
- 23 new tests across `tests/test_scan_wizard.py` (Advanced page + detect endpoint) and `tests/test_detect_login_form.py` (crawl/parse unit tests), plus the 20 media/API tests above - all passing alongside the full pre-existing suite.

## Files Created/Modified
- `webvulnscanner/checks.py` - `detect_login_form()`, `_guess_login_fields()`, `_USERNAME_FIELD_HINTS`.
- `webvulnscanner/scan_routes.py` - `new_scan_advanced_detect()` route; `_availability_for()`, `_advanced_render_kwargs()`, `_media_render_kwargs()`, `_api_render_kwargs()` helpers; `SCAN_TYPE_CARDS` blurbs rewritten; `jsonify`/`detect_login_form` imports added. Every existing tier/authorization/SSRF check in `new_scan_media`/`new_scan_api`/`new_scan_advanced` is untouched.
- `templates/scan_new_media.html`, `templates/scan_new_api.html` - Step 3 restructure.
- `templates/scan_new_advanced.html` - full rewrite: URL-first intake, progressive disclosure, Smart Setup JS.
- `templates/scan_new.html`, `templates/scan_new_type.html` - copy audit.
- `tests/test_scan_wizard.py` - 35 new tests (20 media/api + 15 advanced/detect).
- `tests/test_detect_login_form.py` - new module, 8 tests.

## Decisions Made
- D-02a recorded in `05-CONTEXT.md` under a new subsection, explicitly framed as superseding only D-02's *shape* clause, not its scope decision (Advanced still routes into its own dedicated Step 3 form, per D-02 unchanged).
- `05-02-PLAN.md`'s Task 2 marked `superseded` inline (not deleted) so the historical record of the original design stays visible without silently contradicting what's shipped.

## Deviations from Plan
- Task 2 as written (media/API-style flat-field Step 3 for Advanced, all 16 fields immediately visible) was not executed. Superseded per explicit user direction mid-session, after the user flagged the 16-field form as likely to lose non-technical users. See D-02a.

## Issues Encountered
None blocking. Full test suite (base + this plan's additions) green throughout.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Task 3's checkpoint (browser walkthrough of media/API/advanced launch, including the Smart Setup detection flow) has not been run this session.
- `entitlements.py`/`checks.py`'s check functions/`scan_engine.py` orchestrators are unchanged; `checks.detect_login_form` is additive only.

---
*Phase: 05-new-scan-flow-redesign*
*Completed: 2026-08-17*
