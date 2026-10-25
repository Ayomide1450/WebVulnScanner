---
phase: 08-security-re-audit-hardening
plan: 02
subsystem: testing
tags: [csrf, flask-wtf, security-testing, source-parsing-lock]

# Dependency graph
requires:
  - phase: 08-security-re-audit-hardening
    provides: 08-RESEARCH.md's CSRF architecture finding (app-wide CSRFProtect,
      single csrf.exempt(api) call, no server-side CSRF enforcement test in
      the 646-test suite) and the "CSRF-enforcement regression test" pattern
      sketch this plan makes real
provides:
  - tests/test_csrf_enforcement.py - the repo's first executable proof that
    Flask-WTF's CSRFProtect actually rejects a token-less/wrong-token POST,
    not just that a hidden field is rendered
  - a reusable "second CSRF-enabled app instance" pattern (_CSRFEnabledConfig,
    csrf_app/csrf_client/csrf_db fixtures) any future CSRF-adjacent test in
    this repo can reuse
affects: [08-03, 08-04, 08-05, 08-06, 08-07]

# Actuals (#2632)
actuals:
  tokens: 4993
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Second, independently-configured Flask app instance with one
      TestConfig flag flipped back on (WTF_CSRF_ENABLED=True), mirroring
      test_login_rate_limit_is_enforced's established shape for
      RATELIMIT_ENABLED - never touches the shared app/client/db fixtures
      or tests/conftest.py."
    - "Source-parsing regression lock (inspect.getsource-free variant: plain
      file read + comment-stripped substring scan) for csrf.exempt() call
      sites, same shape as test_scan_engine.py's inline-scoring-block lock
      and test_scheduler.py's no-advanced-branch lock."
    - "CSRF token mutation must flip the FIRST character of an itsdangerous
      URLSafeTimedSerializer token, not the last - the trailing base64
      character of the signature segment often carries only padding bits
      that Python's base64 decoder doesn't validate as zero, so a
      last-character flip can silently decode to identical bytes and leave
      a 'tampered' token still valid. See _mutate_token's docstring."

key-files:
  created:
    - tests/test_csrf_enforcement.py
  modified: []

key-decisions:
  - "Token mutation flips the token's first character, not the last -
    discovered mid-task that flipping the last character of the itsdangerous
    signature is unreliable (~6-7% of the time it decodes to the same bytes
    due to base64 padding-bit slack), which would have made the wrong-token
    test flaky/vacuous."
  - "Smart Setup's csrf-token-input assertion required seeding a real
    ORG_VERIFIED-tier org with a verified DomainVerification row for the
    exact target - scan_new_advanced.html only renders its form (and
    therefore its csrf_token input) once availability.unlocked is true, so
    a plain MEMBER/FREE-tier user never sees the form at all."
  - "csrf.exempt() scope lock and template-idiom lock use a plain
    read_text()+substring scan rather than inspect.getsource/AST, since the
    checks operate over whole files (glassbox/**/*.py,
    templates/*.html) rather than single functions."

patterns-established:
  - "csrf_app/csrf_client/csrf_db fixtures + _login()/_extract_csrf_token()/
    _mutate_token() helpers in tests/test_csrf_enforcement.py - reusable by
    any future test needing real CSRF enforcement without touching
    tests/conftest.py's suite-wide WTF_CSRF_ENABLED=False default."

requirements-completed: [SEC-02]

coverage:
  - id: D1
    description: "A CSRF-enabled app instance exists in the suite; a
      token-less POST to /org/admin/invite returns 400 with no Invitation
      row created, a wrong-but-well-formed token also 400s with no row, and
      a valid token returns 302 and creates exactly one row."
    requirement: "SEC-02"
    verification:
      - kind: unit
        ref: "tests/test_csrf_enforcement.py::test_invite_without_csrf_token_returns_400_and_creates_no_row"
        status: pass
      - kind: unit
        ref: "tests/test_csrf_enforcement.py::test_invite_with_wrong_csrf_token_returns_400_and_creates_no_row"
        status: pass
      - kind: unit
        ref: "tests/test_csrf_enforcement.py::test_invite_with_valid_csrf_token_returns_302_and_creates_one_row"
        status: pass
    human_judgment: false
  - id: D2
    description: "One token-less-POST-returns-400 proof (with a paired
      no-side-effect assertion) per cookie-authenticated blueprint: auth,
      billing, asset, api_tokens, scan (org covered by D1)."
    requirement: "SEC-02"
    verification:
      - kind: unit
        ref: "tests/test_csrf_enforcement.py::test_auth_forgot_password_without_csrf_token_returns_400_no_reset_row"
        status: pass
      - kind: unit
        ref: "tests/test_csrf_enforcement.py::test_billing_create_invoice_without_csrf_token_returns_400_no_invoice_row"
        status: pass
      - kind: unit
        ref: "tests/test_csrf_enforcement.py::test_asset_delete_without_csrf_token_returns_400_not_deleted"
        status: pass
      - kind: unit
        ref: "tests/test_csrf_enforcement.py::test_api_tokens_create_without_csrf_token_returns_400_no_token_row"
        status: pass
      - kind: unit
        ref: "tests/test_csrf_enforcement.py::test_scan_new_base_without_csrf_token_returns_400_no_scan_row"
        status: pass
    human_judgment: false
  - id: D3
    description: "Smart Setup lock: the Advanced scan form renders a
      csrf_token input once unlocked, and /scan/new/advanced/detect rejects
      a token-less POST with 400."
    requirement: "SEC-02"
    verification:
      - kind: unit
        ref: "tests/test_csrf_enforcement.py::test_advanced_form_renders_a_csrf_token_input"
        status: pass
      - kind: unit
        ref: "tests/test_csrf_enforcement.py::test_advanced_detect_without_csrf_token_returns_400"
        status: pass
    human_judgment: false
  - id: D4
    description: "csrf.exempt() is applied to exactly one call site
      (glassbox/api_routes.py, the api blueprint) and nowhere else,
      with a demonstrated negative control; the Bearer-token API surface
      still works under CSRF enforcement; every POST-form template in
      templates/ emits a csrf token by one of the two known idioms."
    requirement: "SEC-02"
    verification:
      - kind: unit
        ref: "tests/test_csrf_enforcement.py::test_csrf_exempt_applied_to_exactly_one_blueprint"
        status: pass
      - kind: unit
        ref: "tests/test_csrf_enforcement.py::test_bearer_token_trigger_scan_not_blocked_by_csrf_enforcement"
        status: pass
      - kind: unit
        ref: "tests/test_csrf_enforcement.py::test_every_post_form_template_emits_a_known_csrf_idiom"
        status: pass
    human_judgment: false

duration: 55min
completed: 2026-08-19
status: complete
---

# Phase 8 Plan 2: CSRF Enforcement Proof (SEC-02) Summary

**First executable proof in the repo that Flask-WTF's `CSRFProtect` actually rejects forged cross-site POSTs - 13 new tests in `tests/test_csrf_enforcement.py`, zero production code changed.**

## Performance

- **Duration:** ~55 min
- **Tasks:** 3
- **Files modified:** 1 (`tests/test_csrf_enforcement.py`, new)

## Accomplishments

- Built a second, independently-configured Flask app instance
  (`_CSRFEnabledConfig(TestConfig)` with `WTF_CSRF_ENABLED=True`) plus
  `csrf_app`/`csrf_client`/`csrf_db` fixtures and token-aware login/extraction
  helpers - the established `test_login_rate_limit_is_enforced` pattern,
  applied to CSRF instead of rate limiting.
- Proved CSRF enforcement end-to-end on `/org/admin/invite`: a token-less POST
  returns **400** and creates zero `Invitation` rows; a wrong-but-well-formed
  token also returns **400** with zero rows; a valid token returns **302** and
  creates exactly one row.
- Proved the same token-less-POST-returns-400 shape, each with a
  route-specific no-side-effect assertion, across all five remaining
  cookie-authenticated blueprints: auth (`/forgot-password`, no
  `PasswordReset` row), billing (`/account/billing/invoice`, no
  `CryptoInvoice` row), asset (`/assets/<id>/delete`, `deleted_at` stays
  `None`), api_tokens (`/tokens/new`, no `ApiToken` row), scan
  (`/scan/new/base`, no `Scan` row - and no background thread, since
  `CSRFProtect`'s `before_request` hook runs before the view body's own SSRF
  check ever executes).
- Locked the Smart Setup edge: the Advanced scan form renders a `csrf_token`
  input once unlocked (`ORG_VERIFIED` tier + verified `DomainVerification`
  row), and `/scan/new/advanced/detect` rejects a token-less POST with 400 -
  closing the gap where the JS's `if (csrfInput)` conditional could silently
  degrade to a no-op if the input were ever removed.
- Locked `csrf.exempt()`'s scope with a comment-filtered, exact-set
  source-parsing assertion over `glassbox/`: exactly one call site
  exists, in `api_routes.py`, applied to the `api` blueprint. Demonstrated the
  negative control (a second exempt call fails the test, naming both sites)
  and reverted.
- Proved the Bearer-token API surface (`POST /api/v1/assets/<id>/scans`)
  still succeeds under CSRF enforcement - the exemption isn't collateral
  damage of the hardening.
- Proved every `templates/*.html` file containing a POST form emits a csrf
  token by one of the app's two known idioms (explicit `csrf_token()` input,
  10 templates; WTForms `hidden_tag()`, 6 templates; `org_admin.html` uses
  both across different forms on the same page).

## Task Commits

1. **Task 1: CSRF-enabled app harness + one end-to-end enforcement proof** -
   `7ff792a` (test)
2. **Task 2: One enforcement proof per cookie-authenticated blueprint** -
   `074aa28` (test)
3. **Task 3: Lock the csrf.exempt() scope and the two token-emission idioms** -
   `6269549` (test)

**Plan metadata:** committed alongside this SUMMARY.

_TDD framing: each task's own "prove the enforcement path exists and is
correct" tests were written and run green against real (not mocked) route
behavior - there was no separate RED phase since the routes/mechanism already
existed (08-RESEARCH.md's finding) and the point was proving existing
behavior, not building new behavior._

## Files Created/Modified

- `tests/test_csrf_enforcement.py` (new, 497 lines) - see Accomplishments
  above for full contents; also see frontmatter's `coverage` block for the
  test-by-test map to SEC-02's must-haves.

## Decisions Made

- **Token mutation flips the token's FIRST character, not the last.**
  Discovered while writing the wrong-token test: the itsdangerous
  `URLSafeTimedSerializer` token's trailing base64 signature character
  frequently encodes only 2 significant bits (base64's padding-bit slack at
  a non-multiple-of-3 byte boundary), which Python's base64 decoder does not
  validate as zero - so a specific last-character replacement has roughly a
  1-in-16 chance of decoding to the exact same bytes, leaving a "tampered"
  token still valid. `_mutate_token()` flips the first character instead,
  which always corrupts the decoded payload. Verified this reliably
  invalidates the token across repeated runs.
- **Smart Setup tests seed a real `ORG_VERIFIED`-tier org + verified
  `DomainVerification` row.** `scan_new_advanced.html`'s form (csrf_token
  included) only renders once `availability.unlocked` is true - a plain
  `FREE`-tier `MEMBER` never sees the form, so the csrf-token-presence
  assertion would otherwise silently test nothing.
- **Exemption-scope and template-idiom locks use a plain
  `read_text()`+substring scan**, not `inspect.getsource`/AST, since both
  checks scan whole directories of files rather than a single function's
  source - same intent as `test_scan_engine.py`'s/`test_scheduler.py`'s
  source-parsing locks, adapted to a multi-file scope.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed the wrong-token mutation helper's last-character flaw before it shipped**
- **Found during:** Task 1, writing `test_invite_with_wrong_csrf_token_returns_400_and_creates_no_row`
- **Issue:** The initial `_mutate_token()` flipped the token's last character.
  The test failed intermittently (302 instead of 400) because base64's
  trailing-character padding-bit slack meant the mutated token sometimes
  decoded to the identical bytes as the original, still validating.
- **Fix:** Flip the first character instead (verified this reliably
  corrupts the decoded payload across manual repeated trials before
  finalizing).
- **Files modified:** `tests/test_csrf_enforcement.py` (this plan's only
  file - fixed before the Task 1 commit, so no separate commit exists for
  this fix)
- **Verification:** Manual script confirmed first-character mutation always
  produces a 400; `pytest tests/test_csrf_enforcement.py -q` green.
- **Committed in:** `7ff792a` (part of the Task 1 commit - the working
  version was committed, not the buggy intermediate one)

**2. [Rule 1 - Bug, out of scope, logged not fixed] Discovered a pre-existing flaky test in `tests/test_org_invite.py`**
- **Found during:** Task 3's full-suite wave-gate run
  (`.venv\Scripts\python -m pytest -q`)
- **Issue:** `tests/test_org_invite.py::test_decode_invite_token_rejects_tampered_signature`
  has the *exact same* base64 last-character bug described above (it flips
  `token[-1]`, not `token[0]`), applied to org-invite tokens instead of CSRF
  tokens. Measured empirically at ~6.9% failure rate (343/5000 trials with
  varying payloads) - see `.planning/phases/08-security-re-audit-hardening/deferred-items.md`
  for the full writeup.
- **Not fixed here:** `tests/test_org_invite.py` is not in this plan's
  `files_modified` and was never touched by 08-02 - per the executor's SCOPE
  BOUNDARY rule, only issues directly caused by this task's own changes are
  auto-fixed. This is a pre-existing, unrelated latent flake, logged instead.
- **Tracked in:** `.planning/WINDOWS.md` (kind: `deviation`, phase 8, open,
  entry id 1) and `.planning/phases/08-security-re-audit-hardening/deferred-items.md`.
- **Suggested fix (not applied):** mirror `_mutate_token()`'s fix - flip the
  first character of the tampered token instead of the last.

---

**Total deviations:** 2 (1 self-corrected before commit, 1 logged/deferred - a pre-existing, unrelated flaky test discovered incidentally)
**Impact on plan:** No scope creep. The self-corrected mutation-helper bug
was fixed before any commit existed with the broken version. The deferred
item does not affect SEC-02's own correctness - `tests/test_csrf_enforcement.py`
passed the full-suite wave gate cleanly on its own merits (see Issues
Encountered below for the exact gate-run history).

## Issues Encountered

- The full-suite wave gate (`.venv\Scripts\python -m pytest -q`) failed once
  on an unrelated test (`tests/test_org_invite.py::test_decode_invite_token_rejects_tampered_signature`,
  1 failed / 658 passed) during a background run. Reproduced the same test in
  isolation (pass), paired with `tests/test_csrf_enforcement.py` (pass, 29/29),
  and via a targeted statistical script confirming it's an intermittent,
  pre-existing base64-signature-mutation flake unrelated to this plan's
  diff (see Deviations #2 above). `tests/test_csrf_enforcement.py`'s own 13
  tests passed on every run, including every full-suite run.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SEC-02 is closed: CSRF enforcement is now proven server-side, not just
  markup-asserted, across every cookie-authenticated blueprint plus the
  Smart Setup edge case, with the exemption scope and template coverage
  locked against regression.
- No blockers for 08-03..08-07. One pre-existing, unrelated flaky test
  (`tests/test_org_invite.py`) is logged in `.planning/WINDOWS.md` for
  future cleanup - does not block this plan or this phase.

---
*Phase: 08-security-re-audit-hardening*
*Completed: 2026-08-19*

## Self-Check: PASSED

- FOUND: `tests/test_csrf_enforcement.py`
- FOUND: `.planning/phases/08-security-re-audit-hardening/08-02-SUMMARY.md`
- FOUND: `.planning/phases/08-security-re-audit-hardening/deferred-items.md`
- FOUND: `.planning/WINDOWS.md`
- FOUND commit: `7ff792a` (Task 1)
- FOUND commit: `074aa28` (Task 2)
- FOUND commit: `6269549` (Task 3)
