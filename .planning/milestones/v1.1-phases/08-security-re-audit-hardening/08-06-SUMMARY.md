---
phase: 08-security-re-audit-hardening
plan: 06
subsystem: auth-error-handling-tooling
tags: [open-redirect, error-leakage, secrets-sweep, csrf, flask-wtf, werkzeug, security]

# Dependency graph
requires:
  - phase: 08-security-re-audit-hardening (08-01..08-05)
    provides: "Green wave-1/2/3 baseline (720 passed) this plan's precondition required before touching production code; specifically 08-04's _SSRFSafeSession and 08-05's read_report_file()/escaping locks that this plan's source-scanning idiom reuses"
provides:
  - "Parametrized adversarial next-param coverage in tests/test_auth_flows.py (absolute http/https, protocol-relative, backslash-prefixed, whitespace-prefixed absolute, embedded newline, double-percent-encoded) each asserting Location == /dashboard exactly, plus a positive control and a logout-ignores-next assertion"
  - "A comment-filtered, exact-set source lock proving _safe_next() is the only user-influenced redirect() argument anywhere in webvulnscanner/, plus a companion lock proving only one next-parameter-style helper is defined - both negative-controlled live"
  - "A live-finding fix to auth_routes._safe_next(): now also rejects a backslash or CR/LF character in the next value, closing a real (if not currently browser-exploitable) gap and an unhandled-crash bug, both found via a throwaway probe script before being fixed"
  - "tests/test_error_leakage.py: the first TESTING=False/DEBUG=False Flask app config in this repo's history, proving all six SEC-10 status codes (400/401/403/404/429/500) leak none of five forbidden shapes, that the three handled codes render the app's own themed templates, and that the three unhandled ones carry no repo branding"
  - "scripts/secrets_sweep_phase8.py + tests/test_secrets_hygiene.py: a re-runnable, self-tested, this-app-tuned secrets sweep over both the milestone commit range and the working tree, with a text-keyed (not location-keyed) allowlist so the same entry covers a literal's appearance in both surfaces"
affects: [08-07]

actuals:
  tokens: 12900
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Text-keyed (not location-keyed) allowlist for a regex-based sweep spanning two different scan surfaces (working tree vs. git-diff text) with unrelated line-numbering schemes - a location-keyed allowlist entry cannot straddle both; matching on the literal matched substring itself works identically for either surface and survives unrelated line-shift churn."
    - "Second, independently-configured Flask app instance built directly off the real Config class (not TestConfig) to get genuine TESTING=False/DEBUG=False behavior, extending the test_login_rate_limit_is_enforced / test_csrf_enforcement.py precedent of flipping exactly the flags a test needs on a throwaway app+DB rather than touching the shared fixtures."
    - "Comment-filtered, full-line-only source scanning for an exact-set call-site lock (redirect() argument classification) and a function-definition-name lock (next-parameter helper count) - same idiom as 08-02's csrf.exempt() scope lock and 08-05's autoescape/Markup/execute-call-site locks."

key-files:
  created:
    - scripts/secrets_sweep_phase8.py
    - tests/test_error_leakage.py
    - tests/test_secrets_hygiene.py
  modified:
    - tests/test_auth_flows.py
    - webvulnscanner/auth_routes.py

key-decisions:
  - "Fixed a live finding in auth_routes._safe_next() (Rule 1, D-03) rather than only testing around it, despite the plan's own prohibition against modifying _safe_next() - that prohibition is explicitly conditioned on 'unless a case reveals a genuine bypass', and two of Task 1's adversarial payloads did: a backslash-prefixed next value passed the guard's two literal conditions verbatim (safe today only because Werkzeug's own header-writing machinery happens to percent-encode the backslash before it reaches a Location header - not because the guard itself rejects it), and an embedded-newline value raised an unhandled ValueError straight out of Flask's redirect helper. Both proven live via a throwaway, unstaged probe script before any test or fix was written."
  - "Discovered and fixed a design bug in the secrets-sweep script's own allowlist before it was ever committed: an initial (file-path, line-number)-keyed allowlist worked for the working-tree sweep but could never match a git-range hit, since that surface's source label is a synthetic 'git-range:<range>' string with a line number counted within a concatenated diff blob, unrelated to any real file+line. Switched to keying by the exact matched text instead, which works identically for both surfaces and is immune to line-shift churn. Recorded in the Task 3 commit message and here so a future reader doesn't reintroduce the same bug."
  - "SEC-07's Task 1 does not add a new invite-flow-specific test: 08-06-PLAN.md's must_haves names the invite flow's org-binding-not-request-derived behavior as a truth needing verification, but that behavior is about org membership assignment, not the next-param redirect target, and is already proven by tests/test_org_invite.py's existing test_signup_post_with_valid_invite_creates_member_in_org / ..._grants_admin_role_when_invited_as_admin (both assert user.org_id == org.id from the decoded token, never from a request parameter). Cited rather than duplicated."
  - "The realistic 401 path (/api/v1/* with no Authorization header) returns the api blueprint's own minimal JSON body (api_login_required in api_routes.py), not Werkzeug's raw default page - a deliberate deviation from 08-06-PLAN.md's 'Werkzeug's generic pages' framing for 400/401/403, recorded explicitly rather than silently reinterpreted. It is still asserted against the same forbidden-substring list and confirmed to carry no repo branding, satisfying SEC-10's actual intent (no leak) even though the literal mechanism differs from 400/403's true Werkzeug fallthrough."

patterns-established:
  - "A live-finding-driven bugfix inside an otherwise test-only task, proven via a throwaway, never-committed probe script run before writing the real test/fix, not reasoned about in the abstract - the same discipline plan 08-04 used when its resolve_redirects() assumption was empirically falsified."

requirements-completed: [SEC-07, SEC-08, SEC-10]

coverage:
  - id: D1
    description: "Seven adversarial next-param shapes (absolute http, absolute https, protocol-relative, backslash-prefixed, whitespace-prefixed absolute, embedded newline, double-percent-encoded double-slash) each redirect to the exact in-app default, not merely somewhere off-payload"
    requirement: SEC-07
    verification:
      - kind: unit
        ref: "tests/test_auth_flows.py::test_login_rejects_adversarial_next_params_and_falls_back_to_default[...], ::test_login_rejects_double_percent_encoded_next_param"
        status: pass
    human_judgment: false
  - id: D2
    description: "A legitimate relative next path is still honored (positive control)"
    requirement: SEC-07
    verification:
      - kind: unit
        ref: "tests/test_auth_flows.py::test_login_honors_relative_next_param"
        status: pass
    human_judgment: false
  - id: D3
    description: "logout() redirects in-app and ignores any next parameter supplied on the request itself"
    requirement: SEC-07
    verification:
      - kind: unit
        ref: "tests/test_auth_flows.py::test_logout_ends_the_session, ::test_logout_ignores_a_next_param_supplied_on_the_logout_request"
        status: pass
    human_judgment: false
  - id: D4
    description: "_safe_next() is the only user-influenced redirect() argument anywhere in webvulnscanner/ - a comment-filtered, exact-set source lock over module+line, negative-controlled live"
    requirement: SEC-07
    verification:
      - kind: unit
        ref: "tests/test_auth_flows.py::test_only_safe_next_redirects_take_a_request_derived_argument"
        status: pass
      - kind: manual
        ref: "Negative control: scratch route added redirecting request.args.get('next') directly, ran alone, failed naming webvulnscanner\\auth_routes.py:301; reverted, git diff --stat confirmed empty"
        status: pass
    human_judgment: false
  - id: D5
    description: "Exactly one next-parameter-style helper is defined in the codebase"
    requirement: SEC-07
    verification:
      - kind: unit
        ref: "tests/test_auth_flows.py::test_only_one_next_parameter_helper_is_defined"
        status: pass
      - kind: manual
        ref: "Negative control: second helper _get_safe_next_url added, ran alone, failed naming it; reverted, diff confirmed empty"
        status: pass
    human_judgment: false
  - id: D6
    description: "Live finding: _safe_next() now rejects a backslash or CR/LF in the next value, closing an implicit-safety-net gap and an unhandled-crash bug"
    requirement: SEC-07
    verification:
      - kind: unit
        ref: "tests/test_auth_flows.py::test_login_rejects_adversarial_next_params_and_falls_back_to_default[backslash_prefixed_path], [embedded_newline]"
        status: pass
      - kind: manual
        ref: "Proven live via a throwaway probe script before the fix: backslash case returned Location '/%5Cevil.example.com' (not /dashboard); embedded-newline case raised an uncaught ValueError. Both re-probed clean after the fix."
        status: pass
    human_judgment: false
  - id: D7
    description: "All six status codes SEC-10 names (400/401/403/404/429/500) leak none of five forbidden shapes under a genuine TESTING=False/DEBUG=False app"
    requirement: SEC-10
    verification:
      - kind: unit
        ref: "tests/test_error_leakage.py (all six status-code tests)"
        status: pass
    human_judgment: false
  - id: D8
    description: "404/429/500 render the app's own themed templates under production mode; 400/403 carry no repo branding (Werkzeug's own default); 401 is the api blueprint's own minimal JSON, also carrying no repo branding - recorded as the one deliberate deviation from the generic-Werkzeug-page framing"
    requirement: SEC-10
    verification:
      - kind: unit
        ref: "tests/test_error_leakage.py::test_404_renders_themed_template_and_leaks_nothing, ::test_429_renders_themed_template_and_leaks_nothing, ::test_500_renders_themed_template_and_does_not_echo_exception_message, ::test_403_renders_generic_page_and_leaks_nothing, ::test_400_renders_generic_page_and_leaks_nothing, ::test_401_returns_a_minimal_json_body_and_leaks_nothing"
        status: pass
    human_judgment: false
  - id: D9
    description: "An unhandled exception's own message is not echoed into the 500 response body"
    requirement: SEC-10
    verification:
      - kind: unit
        ref: "tests/test_error_leakage.py::test_500_renders_themed_template_and_does_not_echo_exception_message"
        status: pass
    human_judgment: false
  - id: D10
    description: "A re-runnable, self-tested, this-app-tuned secrets sweep runs clean over both the milestone commit range (108 commits) and the working tree (265 files) - no un-allowlisted credential-shaped literal found"
    requirement: SEC-08
    verification:
      - kind: unit
        ref: "tests/test_secrets_hygiene.py::test_working_tree_sweep_is_clean, ::test_git_range_sweep_is_clean_or_skips_cleanly_on_shallow_checkout"
        status: pass
      - kind: manual
        ref: "scripts/secrets_sweep_phase8.py run directly: exit 0, '265 file(s) scanned... 108 commit(s) swept... CLEAN'"
        status: pass
    human_judgment: false
  - id: D11
    description: "The sweep's self-test proves the patterns actually fire against a synthetic credential in a temporary file"
    requirement: SEC-08
    verification:
      - kind: unit
        ref: "tests/test_secrets_hygiene.py::test_self_test_proves_the_patterns_fire"
        status: pass
    human_judgment: false
  - id: D12
    description: "Every allowlist entry carries a non-empty, written reason"
    requirement: SEC-08
    verification:
      - kind: unit
        ref: "tests/test_secrets_hygiene.py::test_every_allowlist_entry_has_a_non_empty_reason"
        status: pass
    human_judgment: false
  - id: D13
    description: "The milestone commit range (00ae203..HEAD) resolves; the git-range half skips with a recorded reason on a shallow checkout rather than failing"
    requirement: SEC-08
    verification:
      - kind: unit
        ref: "tests/test_secrets_hygiene.py::test_milestone_commit_range_resolves, ::test_git_range_sweep_is_clean_or_skips_cleanly_on_shallow_checkout"
        status: pass
    human_judgment: false

duration: ~3h
completed: 2026-08-19
status: complete
---

# Phase 8 Plan 06: Redirect-Origin Confinement, Error-Leakage, and Secrets Sweep Summary

**Closed SEC-07, SEC-08 and SEC-10 - adversarial redirect-origin coverage that surfaced and fixed a real gap in `_safe_next()`, the first `TESTING=False`/`DEBUG=False` error-leakage proof across all six named status codes, and a re-runnable, self-tested secrets sweep over both the milestone commit range and the working tree.**

## Performance

- **Duration:** ~3h
- **Completed:** 2026-08-19
- **Tasks:** 3 of 3 completed
- **Files modified:** 5 (2 created new test modules, 1 new script, 2 modified)

## Accomplishments

- Extended `tests/test_auth_flows.py`'s existing `_safe_next()` section with a parametrized adversarial family (absolute http/https, protocol-relative, backslash-prefixed, whitespace-prefixed absolute, embedded newline, plus a distinct double-percent-encoded case) - every case asserts the `Location` header **equals** `/dashboard`, not merely differs from the payload, with the positive control (a legitimate relative path) kept immediately adjacent.
- Added an explicit assertion that `logout()` ignores a `next` parameter supplied on the logout request itself, alongside the existing "ends the session" test.
- Added a comment-filtered, exact-set source lock proving `_safe_next()` is the only `redirect()` call in `webvulnscanner/` that takes a request-derived argument (three known call sites: `auth_routes.py:161,273,287`), plus a companion lock proving only one next-parameter-style helper is defined. Both negative-controlled live (a scratch route / a second helper added, run alone, observed to fail by name, reverted).
- **Found and fixed a live gap in `_safe_next()` (Rule 1, D-03)**, proven with a throwaway probe script *before* writing the real test or the fix: a backslash-prefixed `next` value (`/\evil.example.com`) passed the guard's original two conditions verbatim - safe today only because Werkzeug's own header-writing machinery percent-encodes the backslash to `%5C` before it ever reaches a `Location` header, not because the guard itself rejects it - and an embedded-newline `next` value raised an **unhandled `ValueError`** straight out of Flask's redirect call (`Header values must not contain newline characters`), which under `TESTING=True` crashes the request outright and under `TESTING=False` (SEC-10) would fall through to the generic 500 page instead of a redirect at all. Fixed by also rejecting any `next` value containing a backslash or a CR/LF character, so both shapes now fall through to the ordinary default redirect like every other invalid shape the function already handled. Re-probed clean after the fix; locked by the adversarial parametrize family.
- Confirmed (not re-tested - already covered) that the invite flow's post-signup org assignment derives from the decoded, email-bound token's org binding, never from a request parameter, via `tests/test_org_invite.py`'s existing `test_signup_post_with_valid_invite_creates_member_in_org` / `..._grants_admin_role_when_invited_as_admin`.
- Created `tests/test_error_leakage.py`: the first `TESTING=False`/`DEBUG=False` Flask app config in this repo's ~730-test history, built directly off the real `Config` class (not `TestConfig`) so CSRF and rate-limiting are genuinely enforced. Triggers all six status codes SEC-10 names through the most realistic available path (404 via a nonexistent URL, 403 via `org_admin_required` with an under-privileged member, 401 via `/api/v1/*` with no `Authorization` header, 400 via a token-less POST under real CSRF enforcement, 429 by tripping `/login`'s real 10/min limit with a valid CSRF token per attempt, 500 via a scratch route registered on the test's own app instance) and asserts every response against one shared forbidden-substring constant (traceback marker, interactive-debugger markers, the repo-root path, a SQL keyword sequence, and every env-var name derived by regex-scanning `config.py` itself).
- Confirmed 404/429/500 render the app's own themed templates under production mode (proving the handlers are wired outside `TESTING=True` too, not just inside it) and that 400/403 carry no repo branding. The realistic 401 path turned out to be the `api` blueprint's own minimal JSON body (`api_login_required`), not Werkzeug's raw default page - recorded explicitly as a deviation from the plan's "generic Werkzeug page" framing rather than silently reinterpreted; it is still proven leak-free and brand-free.
- Confirmed a raised exception's own message is never echoed into the 500 response body.
- Created `scripts/secrets_sweep_phase8.py`: sweeps both the milestone commit-range diff (`00ae203..HEAD`, cross-checked against `.planning/STATE.md`/`PROJECT.md`'s recorded v1.1 kickoff date) and the current working tree, using patterns derived from this app's real configuration surface (`config.py`'s `os.environ.get(...)` names) plus provider-specific shapes (Groq, Resend, Sentry DSN) and hex wallet/private-key shapes. No scanning package installed - stdlib + `git` CLI only, per 08-RESEARCH.md's rejection of `detect-secrets`/`gitleaks`.
- Built the script as importable functions (`sweep_working_tree`, `sweep_git_range`, `self_test`) plus a `__main__` guard; `tests/test_secrets_hygiene.py` calls the working-tree sweep and self-test in-process.
- **Found and fixed a design bug in the sweep's own allowlist before committing it**: an initial allowlist keyed by `(file_path, line_number)` worked for the working-tree surface but could never match a git-range hit, since that surface's synthetic source label (`git-range:<range>`) carries a line number counted within a concatenated diff blob with no relationship to any real file+line - four genuine allowlisted findings (a SHA256 hash, two token placeholders, a wallet address) still showed up as "un-allowlisted" in the git-range pass. Switched the allowlist to key by the exact matched text instead, which works identically for both surfaces.
- Ran the actual sweep over the full range: **265 files scanned in the working tree, 108 commits swept in `00ae203..HEAD`**, 25 + 4 raw hits respectively, all allowlisted with written reasons (two test-only `SECRET_KEY` fallbacks, `config.py`'s documented dev-only placeholder, `grant_full_access.py`'s dev-only `DomainVerification.token` placeholder, a synthetic AWS-key-shaped planning-doc example, two synthetic test-fixture token literals, a synthetic sequential EVM wallet-address test fixture, a SHA256 source-identity hash from plan 08-04, `check_sqli_login`'s baseline bad-password literal, and this script's own self-test constant). **No real credential found; no rotation outstanding.**
- Full targeted suite (`tests/test_auth_flows.py tests/test_error_leakage.py tests/test_secrets_hygiene.py`): **51 passed**. Full suite (`.venv\Scripts\python -m pytest -q`): **740 passed**, 0 failures - confirmed at every stage: 720 before this plan's precondition (merged wave-3 baseline), 728 after Task 1 alone, 740 after all three tasks (720 + 8 new adversarial-family tests + 7 error-leakage tests + 5 secrets-hygiene tests = 740, exact arithmetic match).

## Task Commits

1. **Task 1: Adversarial redirect-origin coverage and the sole-surface lock (SEC-07)** - `c6ac274` (test)
2. **Task 2: Production-mode error-leakage coverage across all six status codes (SEC-10)** - `dd3b463` (test)
3. **Task 3: Re-runnable milestone secrets sweep (SEC-08)** - `eeeb679` (feat)

## Files Created/Modified

- `tests/test_auth_flows.py` - extended `_safe_next()` section: parametrized adversarial family, positive control, logout-ignores-next assertion, comment-filtered source locks (sole-surface + single-helper), both negative-controlled live.
- `webvulnscanner/auth_routes.py` - `_safe_next()` now also rejects a backslash or CR/LF character (live finding fix, D-03) - the only production file touched by this plan; documented as a deliberate deviation below.
- `tests/test_error_leakage.py` - new module: the first `TESTING=False`/`DEBUG=False` app config in this repo, six status-code proofs against one shared forbidden-substring constant, themed-vs-generic-vs-JSON classification.
- `tests/test_secrets_hygiene.py` - new module: working-tree sweep asserted clean, self-test asserted to pass, allowlist-reason completeness lock, milestone commit-range-resolves assertion, git-range clean-or-skip assertion.
- `scripts/secrets_sweep_phase8.py` - new script: working-tree + git-range sweeps, this-app-tuned patterns, text-keyed reason-annotated allowlist, self-test, `__main__` guard.

## Decisions Made

- Fixed a live finding in `auth_routes._safe_next()` rather than only testing around it (see Deviations below) - the plan's own text explicitly conditions its "do not modify" instruction on no genuine bypass being found, and this session found one.
- Kept the invite-flow org-binding truth as a citation to existing coverage (`tests/test_org_invite.py`) rather than duplicating it, since that behavior concerns org membership assignment, not the `next`-param redirect target Task 1 is scoped to.
- Recorded the 401 case's actual mechanism (the `api` blueprint's own JSON response, not Werkzeug's default) explicitly rather than silently reinterpreting the plan's "generic Werkzeug page" language to fit.
- Redesigned the secrets-sweep allowlist from location-keyed to text-keyed after discovering live (during authoring, before any commit) that a location-keyed allowlist cannot cover the git-range sweep at all.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug, escalated per D-03] `_safe_next()` passed a backslash-prefixed next value through verbatim; an embedded newline crashed the redirect call**
- **Found during:** Task 1, while designing the adversarial payload set - proven live with a throwaway, never-committed probe script (`_scratch_probe_safe_next.py`, created and deleted twice, never staged) before writing any test or fix.
- **Issue:** `_safe_next()`'s original two conditions (`starts with "/"`, `not startswith("//")`) do not reject a backslash immediately after the leading slash - `/\evil.example.com` passes both verbatim. The probe showed the resulting `Location` header was `/%5Cevil.example.com` (Werkzeug's own header-encoding neutralizes the exploit path today, but the guard itself does not), not `/dashboard`. Separately, a `next` value containing a real CR/LF character (reachable via a URL-encoded `%0d%0a` in the query string, which Werkzeug decodes before `_safe_next()` ever sees it) is also passed through unrejected, and Flask's `redirect()` call then raises an uncaught `ValueError: Header values must not contain newline characters` - a genuine unhandled-exception bug, independent of the open-redirect question.
- **Fix:** `_safe_next()` now also rejects any `next` value containing a backslash, `\r`, or `\n`, falling through to the default redirect exactly like every other invalid shape the function already handled. The function's docstring documents both cases, why the backslash case is not currently browser-exploitable but is fixed anyway (relying on an unrelated layer's incidental behavior is not a guarantee), and cites SEC-10 for why the newline case is also independently a bug.
- **Files modified:** `webvulnscanner/auth_routes.py` (the sole production-code change in this plan; `webvulnscanner/checks.py` and `entitlements.py` remain untouched).
- **Verification:** Re-ran the probe script after the fix - both cases now redirect to `/dashboard` cleanly. Locked by `tests/test_auth_flows.py`'s parametrized adversarial family (`backslash_prefixed_path`, `embedded_newline` cases).
- **Committed in:** `c6ac274` (Task 1 commit).

---

**Total deviations:** 1 auto-fixed (Rule 1 escalated per D-03's "fix live findings immediately" instruction).
**Impact on plan:** This plan's own top-level `<verification>` section states "`git diff --stat` lists no file under `webvulnscanner/`" - that expectation assumed no genuine bypass would be found (matching 08-RESEARCH.md's assessment that SEC-07 was "essentially already met"). Task 1's own action text explicitly anticipates the alternative ("If any case reveals a genuine bypass, that is a live finding under D-03 - fix it and record..."), and this session's adversarial probing found one. The fix is minimal (6 added conditions, well-documented), backward-compatible (every pre-existing `_safe_next()` test and the full suite remain green), and directly required by empirical proof rather than speculation. No scope creep beyond `_safe_next()` itself - `entitlements.py`, `authorized*` checkbox handling, and `checks.is_ssrf_safe_hostname()` remain untouched.

## Issues Encountered

- The secrets-sweep script's allowlist was initially designed keyed by `(file_path, line_number)`, following the exact-set-lock idiom plans 08-02/08-05 already established for source-code call-site locks. This works for the working-tree sweep (real files, real line numbers) but silently fails for the git-range sweep, whose "source" is a synthetic `git-range:<range>` label with a line number counted within one large concatenated diff-text blob - a location that has no relationship to any real file+line. Caught by actually running the sweep against the real repo before committing (not by reasoning about it in the abstract): four genuine, already-known-safe findings (a SHA256 hash, two token placeholders, a wallet address) showed up as "un-allowlisted" in the git-range pass despite being correctly allowlisted in the working-tree pass. Fixed by switching the allowlist to key on the exact matched text instead of location - resolved before any commit, so no follow-up fix was needed after the fact.
- The full-suite background run launched immediately after Task 3's commit did not produce readable interim output while this summary was being drafted (Windows pipe buffering appears to withhold all output until process exit on this host, consistent with the ~450-500s runtime observed three times in this session for the identical command). It completed with 740 passed by the time the summary was finished - confirmed above, not left as an open question.

## User Setup Required

None - no external service configuration required. No credential rotation is outstanding (SEC-08's sweep found no real credential).

## Next Phase Readiness

- SEC-07, SEC-08 and SEC-10 are closed. Combined with plans 08-01 through 08-05, all ten of this phase's requirements (SEC-01..SEC-10) are now code-complete.
- Phase 8's remaining work is Wave 5 (plan 08-07): the non-autonomous phase gate plus D-01/D-02's live dev-server probe pass, which needs a real running instance and human involvement rather than a plain executor dispatch.
- No blockers. `webvulnscanner/auth_routes.py`'s `_safe_next()` fix is small, additive, and fully covered by the new adversarial test family - nothing here should affect 08-07's live-probe pass other than making it slightly more likely to observe correct behavior on the backslash/newline edge cases if they happen to be probed.

## Self-Check: PASSED

- FOUND: scripts/secrets_sweep_phase8.py
- FOUND: tests/test_error_leakage.py
- FOUND: tests/test_secrets_hygiene.py
- FOUND: tests/test_auth_flows.py
- FOUND: webvulnscanner/auth_routes.py
- FOUND commit c6ac274 (Task 1)
- FOUND commit dd3b463 (Task 2)
- FOUND commit eeeb679 (Task 3)

---
*Phase: 08-security-re-audit-hardening*
*Completed: 2026-08-19*
