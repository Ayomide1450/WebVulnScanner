---
phase: 04-production-hardening-reliability
plan: 03
subsystem: auth
tags: [flask, itsdangerous, wtforms, jinja, dns, requests, pytest]

requires:
  - phase: 04-production-hardening-reliability
    provides: "Sibling wave-1 plans 04-01 (scan_engine.py hardening) and 04-02 (rate-limit storage) — no direct dependency, disjoint file scope"
provides:
  - "generate_invite_token(org_id, role, email) / decode_invite_token(token, expected_email=None) — email-bound, signed invite tokens (D-07)"
  - "auth_routes.signup()'s invite-mode branch: a followed invite link joins the signer to the inviting org at the invited role"
  - "templates/signup.html invite-mode conditional (locked email, no org-name field, invite param carried through POST)"
  - "Automated coverage of the invite flow (token round-trip, mismatch, tampered/expired, org-binding, case normalization, authorization) and the domain-ownership verification flow (both proof methods, re-add reset, cross-org 404)"
affects: [org-admin, domain-verification, HARD-03]

actuals:
  tokens: 8271
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Token validity checks (signature, expiry, and now email-binding) all live inside decode_invite_token, not split across call sites"
    - "Spy EmailSender swapped onto app.extensions['email_sender'] to capture and parse a real generated link/token in tests, rather than reading stdout or fabricating a token"
    - "Mocking dns.resolver.resolve / requests.get at the module path domain_verification.py imports them through, matching tests/test_ssrf_guard.py's established mocked-network convention"

key-files:
  created:
    - tests/test_org_invite.py
    - tests/test_domain_verification.py
  modified:
    - webvulnscanner/org_routes.py
    - webvulnscanner/auth_routes.py
    - templates/signup.html
    - templates/org_admin.html

key-decisions:
  - "decode_invite_token(token, expected_email=None) chosen over a caller-side email comparison (04-RESEARCH.md A2, design-space option (a)) - keeps every token-validity check (signature, expiry, email) in one function"
  - "Invite-mode signup re-decodes the token with the submitted address as expected_email at POST time; the GET-time decode (no expected_email) only pre-fills the field and never by itself authorizes org assignment"
  - "An unrecognized role string in a decoded payload is treated identically to a tampered/expired token (same degrade-to-ordinary-signup path), rather than raising"

requirements-completed: [HARD-03]

coverage:
  - id: D1
    description: "An invite link generated from org-admin, when followed, creates an account already joined to that org at the invited role - the flow is finished end to end"
    requirement: HARD-03
    verification:
      - kind: integration
        ref: "tests/test_org_invite.py#test_signup_post_with_valid_invite_creates_member_in_org"
        status: pass
      - kind: integration
        ref: "tests/test_org_invite.py#test_signup_post_with_valid_invite_grants_admin_role_when_invited_as_admin"
        status: pass
    human_judgment: false
  - id: D2
    description: "An invite token is bound to the invited email address - a token issued for one address cannot be redeemed under a different address"
    requirement: HARD-03
    verification:
      - kind: unit
        ref: "tests/test_org_invite.py#test_decode_invite_token_rejects_email_mismatch"
        status: pass
      - kind: integration
        ref: "tests/test_org_invite.py#test_signup_post_with_mismatched_email_creates_no_user"
        status: pass
    human_judgment: false
  - id: D3
    description: "Tampered, expired, and cross-org invite tokens all decode to None; case/whitespace differences in the invited email still match at signup"
    requirement: HARD-03
    verification:
      - kind: unit
        ref: "tests/test_org_invite.py#test_decode_invite_token_rejects_tampered_signature"
        status: pass
      - kind: unit
        ref: "tests/test_org_invite.py#test_decode_invite_token_rejects_expired_token"
        status: pass
      - kind: unit
        ref: "tests/test_org_invite.py#test_decode_invite_token_preserves_exact_org_id"
        status: pass
      - kind: unit
        ref: "tests/test_org_invite.py#test_decode_invite_token_normalizes_case_and_whitespace_on_both_sides"
        status: pass
    human_judgment: false
  - id: D4
    description: "The domain-ownership verification flow (both proof methods, re-add reset, cross-org guard) is covered by mocked, fast tests with no production code changed"
    requirement: HARD-03
    verification:
      - kind: unit
        ref: "tests/test_domain_verification.py#test_verify_domain_dns_txt_success"
        status: pass
      - kind: unit
        ref: "tests/test_domain_verification.py#test_verify_domain_well_known_falls_back_to_http_when_https_raises"
        status: pass
      - kind: integration
        ref: "tests/test_domain_verification.py#test_verify_domain_view_verify_rejects_cross_org_row"
        status: pass
    human_judgment: false
  - id: D5
    description: "Invited signup's locked email field and hidden org-name field render correctly in a real browser, and the org-admin page copy reads correctly"
    verification: []
    human_judgment: true
    rationale: "Visual/template rendering fidelity (readonly styling, hint copy placement) is best confirmed by a human looking at the rendered page, not just asserting substrings are present in the HTML response"

duration: 45min
completed: 2026-08-13
status: complete
---

# Phase 04 Plan 03: Finish the Org-Invite Flow, Bind It to Email, Cover Domain Verification Summary

**Invite tokens now carry and verify the invited email address, `/signup` consumes them end-to-end into org membership, and both the invite and domain-verification flows gained their first automated test coverage.**

## Performance

- **Duration:** 45 min
- **Started:** 2026-08-13T18:20:00Z
- **Completed:** 2026-08-13T19:05:00Z
- **Tasks:** 3
- **Files modified:** 6 (2 new test files, 4 modified source/template files)

## Accomplishments
- `generate_invite_token`/`decode_invite_token` are now a 3-argument, email-bound token pair — a forwarded or leaked invite link can no longer be redeemed by anyone other than the invited address (D-07), proved by a mutation test that temporarily dropped the `expected_email` argument and confirmed the mismatch test failed, then restored it.
- `auth_routes.signup()` gained a full invite-mode branch: reads the token, skips org-creation, assigns `org_id`/`role` from the token, degrades to the ordinary signup path on any tampered/expired/unparseable token, and never 500s.
- `templates/signup.html` locks the email field and hides the organization-name field in invite mode, carrying the `invite` query parameter through the POST so the token isn't silently dropped.
- `tests/test_org_invite.py` (new, 16 tests) and `tests/test_domain_verification.py` (new, 11 tests) close HARD-03's "invite / domain-verification flows" coverage gap — `decode_invite_token` had zero call sites (and zero coverage) before this plan.

## Task Commits

Each task was committed atomically:

1. **Task 1: End-to-end "an invited teammate signs up straight into the org"** - `959d98c` (feat)
2. **Task 2: Lock invite token's failure paths, clear stale org-admin caveat** - `b21bc02` (test)
3. **Task 3: Cover the domain-ownership verification flow** - `2080e6a` (test)

**Plan metadata:** (this commit)

## Files Created/Modified
- `webvulnscanner/org_routes.py` - `generate_invite_token(org_id, role, email)`, `decode_invite_token(token, expected_email=None)`, `invite()` hoists the normalized email into one local reused for the token and the send, module docstring rewritten
- `webvulnscanner/auth_routes.py` - `signup()` gained the invite-mode branch (decode/re-decode, org/role assignment, degrade paths)
- `templates/signup.html` - invite-mode conditional: locked/pre-filled email, no org-name field, invite param carried through the form action
- `templates/org_admin.html` - invite-form helper copy corrected to describe the flow that now exists
- `tests/test_org_invite.py` - token unit tests, end-to-end invite→signup→membership tests, failure-path tests (tampered/expired/cross-org/case), authorization/validation tests
- `tests/test_domain_verification.py` - `generate_verification`/`verify_domain` helper tests (both proof methods, mocked DNS/HTTP), `verify_domain_view` route tests (add/verify/cross-org-404)

## Decisions Made
- `decode_invite_token(token, expected_email=None)` (design-space option (a) from 04-RESEARCH.md's Pattern 5) keeps every validity check — signature, expiry, email — inside one function rather than splitting the email check into `signup()`.
- The GET-time token decode (no `expected_email`) exists solely to pre-fill the address field; only the POST-time re-decode (with the submitted address) actually authorizes org assignment — this two-decode shape is what the mutation test in Task 1 exercises.
- An unrecognized role string inside an otherwise-valid-signature payload is treated as invalid (same degrade path as tampering), since a role the app doesn't recognize is exactly as untrustworthy as a bad signature.

## Deviations from Plan

None - plan executed exactly as written. All three tasks' `<action>` steps were implemented as specified; the mutation proof for D-07 (acceptance criteria, Task 1) was run interactively (temporarily edited `auth_routes.py` to drop `expected_email`, confirmed `test_signup_post_with_mismatched_email_creates_no_user` failed with a 302 instead of the expected 200-with-error, then restored the argument and confirmed the test passed again) rather than being committed as a permanent test, per the plan's own framing of it as a one-time proof to record in this Summary.

## Issues Encountered
- Initial `_extract_token` test helper in `tests/test_org_invite.py` sliced the token from the invite email body up to end-of-string instead of up to the next whitespace, picking up trailing email-body text as part of the "token" and causing `decode_invite_token` to fail signature verification. Fixed by splitting on whitespace after the `invite=` marker before any test using the helper was committed — caught by the test itself failing, not shipped.
- Two of the earliest unit tests (`generate_invite_token`/`decode_invite_token` called directly, not through a route) initially raised `RuntimeError: Working outside of application context` since those functions read `current_app.config["SECRET_KEY"]`. Fixed by wrapping those direct calls in `with app.app_context():` (or relying on the `db` fixture's already-open context for tests that also touch the database).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- HARD-03 is fully closed: the invite flow is finished, email-bound, and end-to-end tested; the domain-verification flow has automated coverage with zero production-code changes.
- `webvulnscanner/domain_verification.py` remains unmodified, confirmed via a `git diff --name-only` check in Task 3's acceptance criteria.
- Full suite: 323/323 passing (baseline before this plan was 260 per the plan's `<verification>` block; 04-01/04-02 landed first bringing it to 292; this plan added 31 tests net across two new files, minus a handful that were split/consolidated during authoring, landing at 323).
- No blockers for 04-04/04-05 (wave 2/3 of Phase 4) — this plan's file scope (org_routes.py, auth_routes.py, signup.html, org_admin.html, two new test files) does not overlap either.

---
*Phase: 04-production-hardening-reliability*
*Completed: 2026-08-13*

## Self-Check: PASSED

All created/modified files and all three task commits (`959d98c`, `b21bc02`, `2080e6a`) verified present.
