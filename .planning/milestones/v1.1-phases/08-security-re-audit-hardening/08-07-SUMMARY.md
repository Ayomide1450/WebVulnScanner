---
phase: 08-security-re-audit-hardening
plan: 07
subsystem: testing
tags: [live-probe, requests, evidence-gate, phase-gate, pytest, security]

# Dependency graph
requires:
  - phase: 08-security-re-audit-hardening (08-01..08-06)
    provides: "Every one of SEC-01..SEC-10's code-complete, test-client-proven fixes and locks - this plan's live probe re-verifies the boundaries those six plans built, and its evidence gate cites their recorded observations rather than re-deriving them"
provides:
  - "scripts/live_probe_phase8.py - a standalone requests-based prober, seeder and three hard guardrails (loopback-only, self-created-database-only, FLASK_SKIP_DOTENV-required), run for real against a live python app.py process with a disposable SQLite database; all 10 cases passed, exit code 0"
  - "tests/test_live_probe_script.py's phase-gate collection assertion: all six of this phase's new test modules explicitly named and proven to collect >=1 test each, closing T-08-48 (a module lost to a bad merge across five waves now fails the suite by name)"
  - "The completed phase evidence gate: every one of SEC-01..SEC-10 has a filled row naming its summary file and specific recorded observation - the mechanism Phase 7 lacked (STATE.md's Current Position records eight Phase 7 requirements code-complete but unconfirmed for exactly this reason)"
  - "08-VALIDATION.md's Per-Task Verification Map, Wave 0 Requirements, Manual-Only Verifications and Validation Sign-Off sections all updated to reflect the real, verified outcome; wave_0_complete and nyquist_compliant frontmatter set to true"
affects: []

actuals:
  tokens: 14660
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Real-import collection assertion (not a source-text scan): imports each of the six phase-8 test modules via the tests.* package and counts module-level test_* functions/classes, mirroring what pytest's own collector would gather - closer to the actual failure mode (a module present but empty/broken) than a regex over file text."
    - "The live probe script's own three hard guardrails (loopback-only base URL, self-created-database-only, FLASK_SKIP_DOTENV required) were exercised for real in Task 2, not just unit-tested against mocks - the printed seed path was independently confirmed to be a temp file, not webvulnscanner.db, proving the guardrail worked under real conditions, not just its own test suite."

key-files:
  created: []
  modified:
    - tests/test_live_probe_script.py
    - .planning/phases/08-security-re-audit-hardening/08-VALIDATION.md

key-decisions:
  - "The collection assertion checks real Python import + attribute inspection (importlib.import_module + vars()/inspect.isfunction) rather than a regex source scan, since all six phase-8 modules use plain test_ functions (confirmed by reading each module's own summary before writing the check) - this proves the module actually collects, not merely that its text superficially looks like a test file."
  - "SEC-03's evidence row explicitly states the live probe cannot cover it and why (a redirect-following probe would need a real scan against a real external target, which CLAUDE.md's authorized-use constraint governs) rather than leaving the row ambiguous or silently omitting it - the plan's own must_haves required this statement verbatim in spirit."
  - "REQUIREMENTS.md's SEC-01..SEC-10 checkboxes and Traceability table were NOT modified by this plan - out of this plan's explicit scope per the orchestrator's instruction that STATE.md/ROADMAP.md updates happen after merge; this summary's evidence table is what those later updates will cite."

patterns-established:
  - "Phase evidence gate as a literal completed table in the closing summary, cross-referencing each requirement to the specific summary file and observation that discharges it - the mechanism this plan exists to install so a future phase doesn't repeat Phase 7's silent code-complete-but-unconfirmed outcome."

requirements-completed: [SEC-01, SEC-02, SEC-03, SEC-04, SEC-05, SEC-06, SEC-07, SEC-08, SEC-09, SEC-10]

coverage:
  - id: D1
    description: "Live probe (D-01/D-02) run against a real python app.py process with a disposable SQLite database - all 10 cross-org IDOR/CSRF cases passed, exit code 0, foreign-Origin CSRF case behaved as the app's own design predicts (no independent Origin/Referer check exists)"
    requirement: "SEC-01"
    verification:
      - kind: manual_procedural
        ref: "scripts/live_probe_phase8.py --probe run by the orchestrator against a real local dev instance (recorded verbatim in this summary's Task 2 section)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Phase-gate collection assertion: all six of this phase's new test modules exist on disk and each collects >=1 test; negative control performed live (renamed test_error_leakage.py, confirmed the failure names the missing module and its creating plan) and reverted"
    requirement: null
    verification:
      - kind: unit
        ref: "tests/test_live_probe_script.py::test_all_six_phase_8_test_modules_exist_and_collect_at_least_one_test"
        status: pass
    human_judgment: false
  - id: D3
    description: "Full suite green on the fully merged phase: 757 passed, 0 failures (one known pre-existing flake in tests/test_org_invite.py, unrelated to this plan, reproduced clean in isolation and on re-run)"
    requirement: null
    verification:
      - kind: unit
        ref: "`.venv\\Scripts\\python -m pytest -q` (757 passed)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Every row of the phase evidence gate filled with a summary filename and specific recorded observation - all ten of SEC-01..SEC-10 plus the live probe row"
    requirement: null
    verification:
      - kind: manual_procedural
        ref: "This summary's Phase Evidence Gate (Completed) table"
        status: pass
    human_judgment: false

duration: ~90min
completed: 2026-08-19
status: complete
---

# Phase 8 Plan 07: Live Dev-Server Probe and Phase Evidence Gate Summary

**Fired 10 real HTTP requests at a real running `python app.py` process (not the Flask test client) to independently re-verify cross-org IDOR/CSRF boundaries proven by plans 08-01 through 08-06 - all 10 passed, exit code 0 - then closed the phase by filling a per-requirement evidence gate table instead of sealing on a green suite alone, the exact discipline Phase 7 skipped.**

## Performance

- **Duration:** ~90 min (across Task 1 build, Task 2 live-server run, Task 3 evidence gate)
- **Completed:** 2026-08-19
- **Tasks:** 3 of 3 completed
- **Files modified:** 2 in Task 3 (`tests/test_live_probe_script.py`, `08-VALIDATION.md`); Task 1's `scripts/live_probe_phase8.py` and `tests/test_live_probe_script.py` were committed separately (see Task Commits)

## Accomplishments

- **Task 1 (already committed, `1935fef`):** Built `scripts/live_probe_phase8.py` - a standalone `requests`-based prober with a two-org disposable-SQLite seeder, three hard guardrails (loopback-only base URL, self-created-database-only, `FLASK_SKIP_DOTENV` required), an authentication pre-check that aborts rather than reporting a false pass from an unsent `Secure` cookie, and a case list pairing each probe case with its named regression test. `tests/test_live_probe_script.py` locked everything checkable without a running server (16 tests at that point).
- **Task 2 (checkpoint:human-verify, run for real by the orchestrator - not re-run here per this task's explicit instructions):** The probe was seeded into a disposable SQLite file at a confirmed-temporary path (`webvulnscanner_live_probe_phase8.db`, NOT `webvulnscanner.db` - the guardrail worked as designed), run against a real `python app.py` on `http://127.0.0.1:5000` with `FLASK_SKIP_DOTENV=1`/`SESSION_COOKIE_SECURE=false`/`ALLOW_INSECURE_DEV_SECRET_KEY=true` set. **All 10 cases passed, exit code 0.** Full per-case table below. Cleanup confirmed: both `python app.py` processes stopped, port 5000 free, disposable `.db` + `_ids.json` deleted.
- **Task 3 (this session):** Added the phase-gate collection assertion (`test_all_six_phase_8_test_modules_exist_and_collect_at_least_one_test`) to `tests/test_live_probe_script.py` - imports all six of this phase's new test modules via the `tests.*` package and counts module-level `test_*` functions/classes, failing by name if any module is missing, fails to import, or collects zero tests. Negative-controlled live: temporarily removed `tests/test_error_leakage.py`, the assertion failed naming exactly `tests/test_error_leakage.py (created by plan 08-06) is MISSING from disk entirely`; reverted, `git status --short` confirmed clean before re-committing.
- Ran the full suite twice: first run showed `1 failed, 756 passed` (the known pre-existing `tests/test_org_invite.py::test_decode_invite_token_rejects_tampered_signature` flake, WINDOWS.md entry #1, ~6.9% intermittent rate documented since 08-02 and unrelated to this plan's diff - reproduced clean in isolation immediately after); second full run came back **757 passed, 0 failures**.
- Walked the phase evidence gate row by row against all seven summaries (08-01 through this plan) and filled every row with a specific recorded observation and its source summary - see the completed table below.
- Updated `08-VALIDATION.md`: Per-Task Verification Map status column set to ✅ green for all ten requirements with evidence citations; Wave 0 Requirements and Manual-Only Verifications marked done with results recorded; `wave_0_complete: true` and `nyquist_compliant: true` set in frontmatter; Validation Sign-Off checklist all checked.
- Confirmed no file under `webvulnscanner/` was touched by this plan (`git diff --stat` for the whole plan lists only `scripts/`, `tests/`, and `.planning/phases/08-security-re-audit-hardening/08-VALIDATION.md`).

## Task Commits

1. **Task 1: The live probe script and its disposable-environment guardrails** - `1935fef` (test) [merged as part of `77b8db7`]
2. **Task 2: Run the live probe against a real dev instance (D-01)** - checkpoint:human-verify, no code commit (results recorded in this summary, provided by the orchestrator's real dev-server run)
3. **Task 3: Phase evidence gate - every requirement backed by a recorded observation** - `8686ae5` (test)

**Plan metadata:** this commit (docs: complete plan)

## Files Created/Modified

- `scripts/live_probe_phase8.py` - created in Task 1 (see `1935fef`), unmodified in this session.
- `tests/test_live_probe_script.py` - Task 1's 16 locks plus this session's phase-gate collection assertion (`test_all_six_phase_8_test_modules_exist_and_collect_at_least_one_test`), 17 tests total.
- `.planning/phases/08-security-re-audit-hardening/08-VALIDATION.md` - Per-Task Verification Map status column, Wave 0 Requirements, Manual-Only Verifications, and Validation Sign-Off all updated to the real, verified outcome; `wave_0_complete`/`nyquist_compliant` frontmatter set to `true`, `status: complete`.

## Task 2: Live Probe Result (D-01/D-02), Recorded Verbatim

Run against a real `python app.py` process on `http://127.0.0.1:5000`, seeded via
`scripts/live_probe_phase8.py --seed` into a disposable SQLite file at
`C:\Users\ARKTEC~1\AppData\Local\Temp\webvulnscanner_live_probe_phase8.db` (confirmed NOT
`webvulnscanner.db` - guardrail worked as designed), with `FLASK_SKIP_DOTENV=1`,
`SESSION_COOKIE_SECURE=false`, `ALLOW_INSECURE_DEV_SECRET_KEY=true` set in both shells.

**Command:** `.venv\Scripts\python scripts\live_probe_phase8.py --probe --base-url http://127.0.0.1:5000`

**Exit code:** 0

```
CASE                                       ROUTE                                            EXPECT   OBSERVED RESULT COVERING TEST
----------------------------------------------------------------------------------------------------------------------------------
billing_verify_invoice_cross_org           /account/billing/invoice/{org_b[invoice_id]}/verify 403      403      PASS   tests/test_billing_routes.py::test_cross_org_verify_is_refused_and_makes_no_changes
api_trigger_scan_cross_org                 /api/v1/assets/{org_b[asset_id]}/scans           404      404      PASS   tests/test_api_routes.py::test_trigger_scan_different_org_gets_404_no_scan_created
api_tokens_revoke_cross_user               /tokens/{org_b[api_token_id]}/revoke             404      404      PASS   tests/test_api_tokens_routes.py::test_user_cannot_revoke_another_users_token
asset_detail_cross_org                     /assets/{org_b[asset_id]}                        404      404      PASS   tests/test_asset_routes.py::test_get_asset_detail_for_other_org_is_404
org_resend_invitation_cross_org            /org/admin/invite/{org_b[invitation_id]}/resend  404      404      PASS   tests/test_org_routes.py::test_cross_org_resend_invitation_is_404_and_leaves_invitation_and_audit_log_untouched
scan_detail_cross_org                      /scan/{org_b[scan_id]}                           404      404      PASS   tests/test_scan_ownership.py::test_admin_of_a_different_org_cannot_view_scan
csrf_missing_token_invite                  /org/admin/invite                                400      400      PASS   tests/test_csrf_enforcement.py::test_invite_without_csrf_token_returns_400_and_creates_no_row
csrf_wrong_token_invite                    /org/admin/invite                                400      400      PASS   tests/test_csrf_enforcement.py::test_invite_with_wrong_csrf_token_returns_400_and_creates_no_row
csrf_valid_token_invite                    /org/admin/invite                                302      302      PASS   tests/test_csrf_enforcement.py::test_invite_with_valid_csrf_token_returns_302_and_creates_one_row
foreign_origin_valid_token_invite          /org/admin/invite                                302      302      PASS   tests/test_csrf_enforcement.py::test_invite_with_valid_csrf_token_returns_302_and_creates_one_row

  NOTE (foreign_origin_valid_token_invite): This app's CSRFProtect validates the submitted token only, not the Origin/Referer header (no WTF_CSRF_SSL_STRICT/Referer check is configured anywhere in webvulnscanner/) - a valid token from a real session is expected to succeed regardless of Origin. A real browser's own SameSite=Lax cookie policy (not this app) is what would actually withhold the session cookie on a genuine cross-site POST navigation; requests does not enforce SameSite, so this case's value is confirming the app itself has no independent Origin check to fall back on.

ALL 10 CASE(S) PASSED.
```

**Confirmations:** Step 1's printed seed path was a temporary file under the OS temp dir, not
`webvulnscanner.db` - the guardrail behaved correctly. Both `python app.py` processes were
stopped after the run, port 5000 confirmed free, the disposable `.db` and its companion
`_ids.json` file both deleted by the orchestrator.

**The foreign-`Origin` CSRF case succeeded (302), as the app's own design predicts** - this is
the "backstop" finding the plan's own `must_haves` flagged as previously unverified (D-01's
purpose), and it is now verified/recorded as expected behavior, not a failure. No live finding
came out of Task 2 itself - all 10 cases passed on the first run, unlike the SEC-03
`_mk_session()` fix (plan 08-04), which was a genuine live vulnerability found and fixed earlier
in the phase.

## Phase Evidence Gate (Completed)

Every row filled with a specific recorded observation and its source summary, per this plan's
own `<phase_evidence_gate>` table:

| Requirement | Evidence required | Recorded in | Status |
|---|---|---|---|
| SEC-01 | The full ID-accepting route inventory table (21 `<int:>`-accepting rules, programmatically enumerated via `app.url_map.iter_rules()`); the enumeration-lock negative controls (unregistered-route and stale-registry-entry, both reproduced live and reverted); the three newly-covered routes (`org.resend_invitation`/`org.revoke_invitation`, `scan.scan_report_csv`, `asset.update_schedule`) with their no-side-effect/no-leak assertions; the platform-admin-deletion `RoleGated` reasoning (cross-org by design, not a gap) | 08-01-SUMMARY.md | ✅ met |
| SEC-02 | The observed status code for each of the three token conditions (400/400/302) proven end-to-end on `/org/admin/invite`; the six cookie-authenticated blueprints each with a token-less-POST-returns-400 proof and a route-specific no-side-effect assertion; the `csrf.exempt()` exact-set scope lock's negative-control message (fails naming both call sites); both token-emission idioms (`csrf_token()` input, `hidden_tag()`) proven present across every POST-form template | 08-02-SUMMARY.md | ✅ met |
| SEC-03 | Confirmation that overriding `get_redirect_target()` (not `resolve_redirects()` as 08-RESEARCH.md's Assumption A3 originally proposed - that approach was built, tested against a real server, and empirically falsified) intercepts pre-fetch; the before/after of `_mk_session()` now returning `_SSRFSafeSession`; three legitimate-redirect regression tests (scheme-upgrade, apex-to-www, cross-domain-but-public) passing; the orchestrator-session-construction negative-control message naming `run_api_scan`; the explicit DNS-rebinding residual-gap sentence. **Not covered by the live probe** - a redirect-following probe would need a real scan against a real external target, which CLAUDE.md's authorized-use constraint governs; the app's own routes are the only legitimate probe surface, and Task 2's case list is entirely cross-org-IDOR/CSRF, not redirect-following | 08-04-SUMMARY.md | ✅ met |
| SEC-04 | Six escaped fields (finding title, finding detail, `ai_summary`, org name, domain name, flashed error) each with an escaped-form-present/raw-form-absent assertion; two source-scan negative-control messages (`\|safe` filter injection into `marketing.html`, `Markup()` construction in `public_routes.py`, both naming the exact file:line); the CSV-export counter-case (deliberately NOT escaped, pinned as correct behavior not a bug) | 08-05-SUMMARY.md | ✅ met |
| SEC-05 | The exact-set raw-SQL lock's two allowlisted module+function pairs (`public_routes.healthz`, `scheduler._try_claim`); the literal-string-constant assertion on the healthcheck's argument and the bound-`.values()`-parameter assertion on the scheduler's Core `update()`; the negative-control message naming a third injected call site | 08-05-SUMMARY.md | ✅ met |
| SEC-06 | The reachability analysis (only `scan_engine.save_report()` writes `Report.json_path`, always from a server-generated `hostname_timestamp.json`, never from a request parameter - traversal is not exploitable today, this is defence in depth); the containment cases (traversal, absolute path, resolution-raising value) each proven with a real sentinel file outside `REPORTS_DIR` whose content is asserted never to appear; one on-disk-fallback positive control per converted call site (`scan_routes`, `api_routes`, `asset_routes`, each keeping its own failure contract); the inline-open lock's negative-control message | 08-05-SUMMARY.md | ✅ met |
| SEC-07 | Seven adversarial `next` shapes (absolute http/https, protocol-relative, backslash-prefixed, whitespace-prefixed absolute, embedded newline, double-percent-encoded) each asserting `Location == /dashboard` exactly; the relative-path positive control; the logout-ignores-next case; the sole-surface source-lock negative-control message naming the exact scratch-route line. **Live finding fixed**: `_safe_next()` now also rejects a backslash or CR/LF, closing a real gap (proven live with a throwaway probe script before the fix) and an unhandled-crash bug | 08-06-SUMMARY.md | ✅ met |
| SEC-08 | The resolved milestone commit range (`00ae203..HEAD`, cross-checked against STATE.md's v1.1 kickoff date), 265 files scanned in the working tree and 108 commits swept at the time of the sweep (114 commits as of this plan's HEAD, unswept re-run not required since no production code changed after 08-06); clean result, every allowlisted hit carrying a written reason; the self-test proving the patterns actually fire against a synthetic credential; no credential rotation outstanding | 08-06-SUMMARY.md | ✅ met |
| SEC-09 | The 403 on cross-org `verify_invoice_route` with all four unchanged-state assertions (invoice row, `Organization.plan`, zero `Subscription` rows, zero Polygonscan calls) proving the guard fires before the network call; the replay-on-PAID-invoice comparison (byte-identical before/after); the four `create_invoice` tamper-gate assertions (unknown plan, non-purchasable plan, unsupported token, invalid cycle, each `CryptoInvoice.query.count() == 0`); the injected-`org_id` result (ignored); the PAID replay state seeded via the real `billing._activate_subscription()` function, not a hand-built approximation | 08-03-SUMMARY.md | ✅ met |
| SEC-10 | All six status codes (400/401/403/404/429/500) triggered under a genuine `TESTING=False`/`DEBUG=False` app - the first such config in this repo's history; the forbidden-substring constant's contents (traceback marker, debugger markers, repo-root path, SQL keyword sequence, every env-var name regex-scanned from `config.py`); 404/429/500 confirmed to render the app's own themed templates (handlers wired outside `TESTING=True` too), 400/403 confirmed to carry no repo branding, 401 confirmed to be the `api` blueprint's own minimal JSON (a recorded deviation from "generic Werkzeug page," still leak-free); the unhandled-exception message assertion (never echoed into the 500 body) | 08-06-SUMMARY.md | ✅ met |
| Live probe (D-01/D-02) | The per-case table with exit code 0; confirmation the seeded database path was a temporary file; the foreign-`Origin` CSRF case's outcome (302, as the app's own design predicts - no independent Origin/Referer check exists) | 08-07-SUMMARY.md (this plan, Task 2 section above) | ✅ met |

**Every row met.** No requirement is marked complete on the strength of a green suite alone -
each row cites a specific recorded observation. This is the mechanism Phase 7 lacked: STATE.md's
Current Position section records eight Phase 7 requirements as code-complete but unconfirmed
because their evidence was never recorded and their `checkpoint:human-verify` gates were never
answered. Phase 8 does not repeat that outcome.

## Live Findings This Phase Produced (D-03)

**One confirmed-open vulnerability found and fixed, nine requirements confirmed
already-correct and now locked.** This is a more useful phase outcome than an unqualified
"all green":

1. **SEC-03 - `checks._mk_session()` did not re-validate redirect hops against
   `is_ssrf_safe_hostname()`.** A real, currently-open SSRF gap: an SSRF-safe initial hostname
   that 30x-redirected to a private/loopback/link-local/metadata address would have been
   followed unchecked by every one of the 33 `requests` call sites in `checks.py` and all four
   scan orchestrators. **Fixed** in plan 08-04: `_mk_session()` now returns a `_SSRFSafeSession`
   overriding `get_redirect_target()` to re-check each hop before it is ever fetched, delegating
   to the existing, unmodified `is_ssrf_safe_hostname()`. **Locked** by
   `tests/test_ssrf_guard.py`'s real-`http.server`-harness proofs (blocked-hop cases, three
   legitimate-redirect regression tests, frozen-surface and delegation locks) plus
   `tests/test_scan_engine.py`'s per-orchestrator session-construction lock.

2. **SEC-07 - `_safe_next()` passed a backslash-prefixed `next` value through verbatim; an
   embedded newline crashed the redirect call.** Found in plan 08-06 via adversarial payload
   testing (proven live with a throwaway probe script before any test or fix was written): a
   `/\evil.example.com`-shaped `next` value passed the guard's original two conditions
   verbatim - safe today only because Werkzeug's own header-encoding machinery percent-encodes
   the backslash before it reaches a `Location` header, not because the guard itself rejects
   it - and a `next` value containing a real CR/LF raised an unhandled `ValueError` straight out
   of Flask's `redirect()` call. **Fixed**: `_safe_next()` now also rejects any `next` value
   containing a backslash, `\r`, or `\n`. **Locked** by `tests/test_auth_flows.py`'s
   parametrized adversarial family.

No other production-code file was modified anywhere in this phase - every other requirement
(SEC-01, SEC-02, SEC-04, SEC-05, SEC-06, SEC-08, SEC-09, SEC-10) was code-complete and correct
before this phase started; this phase's work on those was proving it and locking it against
regression, not fixing it. `entitlements.py`, the `authorized*` checkbox handling,
`checks.is_ssrf_safe_hostname()`'s body, and `billing.py` remain byte-identical to their
milestone-start state (confirmed by SEC-03's frozen-surface source-identity lock and the
milestone secrets sweep).

## Decisions Made

- The phase-gate collection assertion imports each module for real (`importlib.import_module` +
  attribute inspection) rather than scanning source text with a regex, since every one of the
  six modules uses plain `test_*` functions (confirmed by reading each module's own summary
  before writing the check) - this catches a module that's present-but-broken or
  present-but-empty, not just one that's textually absent.
- SEC-03's evidence row states explicitly, in the row itself, why the live probe cannot cover it
  (a redirect-following probe would need a real scan against a real external target, which
  CLAUDE.md's authorized-use constraint governs) rather than leaving the row ambiguous.
- `REQUIREMENTS.md`'s SEC-01..SEC-10 checkboxes and Traceability table rows were left untouched
  by this plan - per the orchestrator's explicit instruction, STATE.md/ROADMAP.md/REQUIREMENTS.md
  updates happen after merge, not inside this worktree. This summary's completed evidence table
  is the source the post-merge update will cite.

## Deviations from Plan

None - Task 3 executed exactly as written. Task 1 and Task 2 were completed and recorded before
this session began (Task 1 committed at `1935fef`/merged at `77b8db7`; Task 2's real results were
provided verbatim by the orchestrator per this task's explicit instructions and are reproduced
above unmodified).

## Issues Encountered

- The full-suite run (`.venv\Scripts\python -m pytest -q`) came back `1 failed, 756 passed` on
  its first execution in this session - the failure was
  `tests/test_org_invite.py::test_decode_invite_token_rejects_tampered_signature`, the
  pre-existing, unrelated flaky test discovered incidentally during plan 08-02 (see
  `.planning/WINDOWS.md` entry 1 and `deferred-items.md`: it flips only the *last* character of
  an `itsdangerous` signature, which ~6.9% of the time lands in the same base64
  decode-equivalence class as the original due to unused padding bits, so the "tampered" token
  still validates). Reproduced in isolation immediately after (`1 passed`) and confirmed clean on
  a full second full-suite run (`757 passed, 0 failures`). This flake is not caused by, and is
  out of scope for, this plan - `tests/test_org_invite.py` is not in this plan's `files_modified`
  and was not touched by any commit in this plan or this phase. It remains open in
  `.planning/WINDOWS.md` (entry 1) for future cleanup.

## User Setup Required

None - no external service configuration required. Task 2's live-server run needed
`FLASK_SKIP_DOTENV=1`/`SESSION_COOKIE_SECURE=false`/`ALLOW_INSECURE_DEV_SECRET_KEY=true` set in
the shell running the server, which the orchestrator handled directly (not a standing setup
requirement for future work).

## Next Phase Readiness

- **Phase 8 is complete.** All ten of SEC-01 through SEC-10 have a filled evidence row citing a
  specific recorded observation in a named summary file. The live probe (D-01/D-02) has been run
  against a real local dev instance with a disposable database and its per-case table recorded
  verbatim above. The full suite is green on the fully merged phase (757 passed) with all six of
  the phase's new test modules present and collecting, locked by a standing collection assertion.
  The phase's one live finding (SEC-03) and one secondary live finding (SEC-07) are both fixed
  and regression-locked; the other eight requirements were confirmed already-correct and are now
  proven and locked against regression.
- **Outstanding, not blocking this phase:** the pre-existing flaky test in
  `tests/test_org_invite.py` (WINDOWS.md entry 1) remains open for future cleanup - the suggested
  fix (mirror `_mutate_token()`'s first-character-flip approach) is recorded there. Phase 6 and
  Phase 7's `checkpoint:human-verify` gates also remain open per STATE.md's Current Position
  section - unrelated to this plan, not discharged by it.
- Whatever milestone-closing step runs next (e.g. `/gsd-ship`) should update
  `.planning/REQUIREMENTS.md`'s SEC-01..SEC-10 checkboxes and Traceability table, and
  `.planning/STATE.md`/`.planning/ROADMAP.md`'s phase-8 status, from this summary's completed
  evidence gate table - deliberately left untouched by this plan per the orchestrator's ownership
  of those files after merge.

## Self-Check: PASSED

- FOUND: scripts/live_probe_phase8.py
- FOUND: tests/test_live_probe_script.py
- FOUND: .planning/phases/08-security-re-audit-hardening/08-VALIDATION.md
- FOUND: .planning/phases/08-security-re-audit-hardening/08-07-SUMMARY.md
- FOUND commit: 1935fef (Task 1)
- FOUND commit: 8686ae5 (Task 3)

---
*Phase: 08-security-re-audit-hardening*
*Completed: 2026-08-19*
