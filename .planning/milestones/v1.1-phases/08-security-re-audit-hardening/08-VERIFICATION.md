---
phase: 08-security-re-audit-hardening
verified: 2026-08-19T15:35:00Z
status: passed
score: 10/10 must-haves verified (all 10 SEC-01..SEC-10 requirements + all 5 ROADMAP success criteria)
behavior_unverified: 0
overrides_applied: 0
re_verification: null
---

# Phase 8: Security Re-Audit & Hardening Verification Report

**Phase Goal:** Every route, form, redirect target, and file-serving path across the app —
including the API tokens, scheduler, asset routes, and platform-admin panel added in v1.0 — is
verified server-side to enforce the same ownership, CSRF, SSRF, injection, and
information-disclosure guarantees the product already promises, with any gap found closed and
covered by a regression test. This phase verifies and closes gaps; it does not weaken or redesign
`authorized*`, `entitlements.py`, `checks.is_ssrf_safe_hostname()`, or `billing.py`'s verification
logic.

**Verified:** 2026-08-19
**Status:** PASSED (VERIFIED)
**Re-verification:** No — initial verification

## Method

This verification did not trust 08-07-SUMMARY.md's evidence table at face value. It:

1. Independently re-ran the full test suite from a clean shell (`./.venv/Scripts/python -m pytest -q`
   from the repo root), not reading any cached/reported count.
2. Read all seven plan SUMMARY.md files plus 08-CONTEXT.md and 08-VALIDATION.md.
3. Computed `git diff --stat <phase-start-commit>..HEAD -- glassbox/` directly and read
   every line of the resulting diff, rather than trusting the summaries' "only these files
   changed" claims.
4. Spot-checked 8 of the 10 evidence-gate rows against the actual test/source code they cite
   (SEC-01, SEC-02, SEC-03, SEC-04/05/06, SEC-07, SEC-08, SEC-09) by opening the named test
   functions and the route code they exercise side by side.
5. Confirmed the frozen-surface claim by diffing `entitlements.py` (zero changes) and locating
   `is_ssrf_safe_hostname()`'s definition line relative to the single diff hunk in `checks.py`
   (the hunk starts and ends well before that function).

Phase-start commit used for all diffs: `27bf56f` ("docs(08): create phase plan — 7 plans across 5
waves for SEC-01..SEC-10"), the last commit before 08-01's work began.

## Goal Achievement

### Observable Truths (ROADMAP.md Phase 8 Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Cross-org GET/POST/PUT/DELETE on every ID-accepting route returns 403/404, never 200 with another org's data, with regression tests added per route family | ✓ VERIFIED | `tests/test_cross_org_idor.py`'s `REGISTRY` enumeration lock covers all 21 `<int:>`-accepting routes (programmatically built from `app.url_map.iter_rules()`); read the guard code (`org_routes.py:335`, `billing_routes.py:95-96`) and the covering tests (`test_org_routes.py`, `test_billing_routes.py`) directly — guards and tests match. App has no PUT/DELETE routes at all (asserted by `test_registered_method_set_is_get_head_options_post_only`), so GET/POST is the actual full method surface. |
| 2 | Every state-changing form/route carries CSRF, with any gap closed | ✓ VERIFIED | `tests/test_csrf_enforcement.py` (13 tests) proves token-less/wrong-token POSTs return 400 with no side effect across all six cookie-authenticated blueprints, verified by reading `test_invite_without_csrf_token_returns_400_and_creates_no_row` directly. `csrf.exempt()` confirmed to have exactly one call site in the codebase (`glassbox/api_routes.py:33`, `grep -rn "csrf.exempt" glassbox/` returns one line). |
| 3 | A redirect-following test proves an SSRF-safe hostname that 30x-redirects to a private/loopback/metadata address is rejected | ✓ VERIFIED | `glassbox/checks.py` diff confirms `_SSRFSafeSession(requests.Session)` overriding `get_redirect_target()`, delegating to unmodified `is_ssrf_safe_hostname()`; `tests/test_ssrf_guard.py` uses a real `http.server.BaseHTTPRequestHandler`-based local server (`class _RoutedHandler`), not a mock, confirmed by reading the test file directly. |
| 4 | User-controlled strings never render unescaped HTML, no raw/string-interpolated SQL exists, report/media/CSV routes reject path traversal | ✓ VERIFIED | `tests/test_injection_and_traversal.py` (SEC-04/05/06 combined module) confirmed to exist with escaping proofs, an exact-set raw-`execute()` allowlist (2 call sites), and `glassbox/scan_engine.read_report_file()` — read directly, confirmed it double-`realpath()`s both `REPORTS_DIR` and the candidate before `os.path.commonpath()` containment check, and that all three prior inline `open()` call sites (`scan_routes.py`, `api_routes.py`, `asset_routes.py`) were converted to call it, each keeping its distinct original failure contract (verified via diff). |
| 5 | Redirects confined to app origin, secrets sweep clean, billing rejects replay/tampering/cross-org, error responses leak nothing | ✓ VERIFIED | `glassbox/auth_routes.py`'s `_safe_next()` diff confirmed to add backslash/CR/LF rejection (a real live-finding fix, not just a test). `scripts/secrets_sweep_phase8.py` and `tests/test_secrets_hygiene.py` both exist. `tests/test_billing_routes.py::test_cross_org_verify_is_refused_and_makes_no_changes` read directly — asserts 403, zero Polygonscan calls (`mock_get.assert_not_called()`), and unchanged invoice state, matching `billing_routes.py:91-96`'s actual guard code read side-by-side. `tests/test_error_leakage.py` confirmed to build the first `TESTING=False`/`DEBUG=False` app config in the repo's history. |

**Score:** 5/5 ROADMAP success criteria verified; 10/10 SEC-01..SEC-10 requirements verified.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `tests/test_cross_org_idor.py` | SEC-01 completeness lock | ✓ VERIFIED | Exists, contains `REGISTRY` + 4 enumeration tests |
| `tests/test_csrf_enforcement.py` | SEC-02 CSRF proof | ✓ VERIFIED | Exists, 13 tests, second CSRF-enabled app instance |
| `tests/test_ssrf_guard.py` | SEC-03 redirect-guard proof | ✓ VERIFIED | Exists, real `http.server` harness confirmed |
| `glassbox/checks.py`'s `_SSRFSafeSession` | SEC-03 fix | ✓ VERIFIED | Present, `_mk_session()` returns it, `is_ssrf_safe_hostname()` untouched |
| `tests/test_injection_and_traversal.py` | SEC-04/05/06 sweep | ✓ VERIFIED | Exists, escaping/SQL/traversal proofs present |
| `glassbox/scan_engine.py`'s `read_report_file()` | SEC-06 containment reader | ✓ VERIFIED | Present, double-realpath containment check, 3 call sites converted |
| `tests/test_billing_routes.py` (extended) | SEC-09 route-level proof | ✓ VERIFIED | Grew from 2 to 15 tests; cross-org/replay/tamper coverage confirmed by reading test bodies |
| `glassbox/auth_routes.py`'s `_safe_next()` fix | SEC-07 fix | ✓ VERIFIED | Backslash/CR/LF rejection present in diff |
| `tests/test_error_leakage.py` | SEC-10 proof | ✓ VERIFIED | Exists, genuine `TESTING=False` app config |
| `scripts/secrets_sweep_phase8.py` + `tests/test_secrets_hygiene.py` | SEC-08 sweep | ✓ VERIFIED | Both exist |
| `scripts/live_probe_phase8.py` + `tests/test_live_probe_script.py` | D-01/D-02 live probe | ✓ VERIFIED | Both exist; live-probe results recorded verbatim in 08-07-SUMMARY.md (10/10 cases, exit 0) |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `checks._mk_session()` | `_SSRFSafeSession.get_redirect_target()` | direct instantiation | ✓ WIRED | `s = _SSRFSafeSession()` confirmed in diff |
| `_SSRFSafeSession.get_redirect_target()` | `is_ssrf_safe_hostname()` | function call, unmodified | ✓ WIRED | `if not hostname or not is_ssrf_safe_hostname(hostname): return None` |
| `scan_routes._load_report_json` / `api_routes.fetch_report` / `asset_routes.compliance_coverage` | `scan_engine.read_report_file()` | import + call | ✓ WIRED | All three call sites confirmed converted in diff, each preserving its own failure contract |
| `auth_routes._safe_next()` | login/signup/reset_password redirects | sole surface | ✓ WIRED | Source lock (`test_only_safe_next_redirects_take_a_request_derived_argument`) confirmed to name exactly 3 call sites, all through `_safe_next()` |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|--------------|--------|----------|
| SEC-01 | 08-01 | Cross-org IDOR on every ID-accepting route | ✓ SATISFIED | 21-route registry + enumeration lock, spot-checked |
| SEC-02 | 08-02 | CSRF on every state-changing route | ✓ SATISFIED | 13 tests across 6 blueprints, spot-checked |
| SEC-03 | 08-04 | SSRF redirect-following rejected | ✓ SATISFIED | Real fix + real-server test, spot-checked |
| SEC-04 | 08-05 | No unescaped user-controlled HTML | ✓ SATISFIED | 6 escaping proofs + standing locks |
| SEC-05 | 08-05 | No raw/string-interpolated SQL | ✓ SATISFIED | Exact-set 2-site allowlist |
| SEC-06 | 08-05 | File-serving routes reject traversal | ✓ SATISFIED | `read_report_file()` containment check, spot-checked |
| SEC-07 | 08-06 | Redirects confined to app origin | ✓ SATISFIED | Real fix (`_safe_next()`) + adversarial test family, spot-checked |
| SEC-08 | 08-06 | No hardcoded secrets added | ✓ SATISFIED | Sweep script + self-test exist |
| SEC-09 | 08-03 | Billing rejects replay/tamper/cross-org | ✓ SATISFIED | 15 route-level tests, spot-checked |
| SEC-10 | 08-06 | Error responses leak nothing in production mode | ✓ SATISFIED | First `TESTING=False` app config in repo history |

No orphaned requirements — `.planning/REQUIREMENTS.md`'s traceability table lists exactly
SEC-01..SEC-10 for Phase 8, all ten `[x]`/Complete, matching the plans' `requirements-completed`
frontmatter across 08-01 through 08-07.

### Anti-Patterns Found

None. No `TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER` markers found in the six touched
production files (`checks.py`, `auth_routes.py`, `scan_engine.py`, `scan_routes.py`,
`api_routes.py`, `asset_routes.py`) within the phase's diff. No stub returns, no hardcoded-empty
data flowing to a response.

### Behavioral Spot-Checks / Full Suite

**Independently re-run from a clean shell** (not reading any cached count):

```
./.venv/Scripts/python -m pytest -q
757 passed, 246 warnings in 506.33s (0:08:26)
```

0 failures — matches the phase's claimed count exactly, including the previously-documented
~6.9%-intermittent flaky test (`tests/test_org_invite.py::test_decode_invite_token_rejects_tampered_signature`,
tracked in `.planning/WINDOWS.md` entry 1, pre-existing and unrelated to this phase's diff — did
not trip on this run). All 246 warnings are pre-existing SQLAlchemy `Query.get()` legacy-API
deprecation warnings, unrelated to Phase 8.

### Frozen-Surface Verification (explicit check per task instructions)

```
git diff 27bf56f..HEAD -- glassbox/entitlements.py   → empty (zero changes)
git diff 27bf56f..HEAD -- glassbox/                  → 6 files changed:
    api_routes.py    (10 lines: read_report_file() call site swap)
    asset_routes.py  (12 lines: read_report_file() call site swap)
    auth_routes.py   (45 lines: _safe_next() backslash/CRLF rejection — SEC-07 fix)
    checks.py        (71 lines: new _SSRFSafeSession class + _mk_session() one-line change — SEC-03 fix)
    scan_engine.py   (45 lines: new read_report_file() function)
    scan_routes.py   (17 lines: read_report_file() call site swap + import cleanup)
```

`is_ssrf_safe_hostname()` is defined at `checks.py:451`; the diff's single hunk in that file
starts at line 358 and inserts 69 new lines before `_mk_session()` (which itself changes from
`requests.Session()` to `_SSRFSafeSession()`, a one-line body change) — the hunk ends well before
line 451, so the function body is byte-identical pre/post phase, confirming the frozen-surface
claim independently of the phase's own source-identity test.

No occurrence of `authorized` anywhere in the phase's `glassbox/` diff (`git diff ... |
grep authorized` returns nothing) — the `authorized*`/`authorized_adv`/`authorized_media`/
`authorized_api` checkbox handling was not touched.

`billing.py` has zero diff lines in the phase range (confirmed via the file list above — it does
not appear at all in the 6-file changed list).

### Human Verification Required

None. Every must-have was independently verifiable via test re-run, source-diff inspection, or
direct reading of the cited test/route code.

## Context Notes (not blockers to Phase 8 itself)

- **ROADMAP.md lists Phase 8 as "Depends on: Phase 5, Phase 6, Phase 7,"** and those three
  phases are not yet complete (Phase 5: 1/3 plans, Phase 6: 1/4 plans, Phase 7: 6/7 plans, per
  this worktree's `.planning/ROADMAP.md`). Per `08-CONTEXT.md` and `.planning/STATE.md`'s Current
  Position section, this was an explicit, recorded user instruction (2026-08-18) to proceed to
  Phase 8's route/data-layer audit without waiting on the UI phases' `checkpoint:human-verify`
  walkthroughs, on the reasoning that most SEC requirements don't depend on the template surface.
  This is a pre-existing, already-acknowledged sequencing deviation, not something this
  verification pass introduces or resolves — flagged here for visibility, not as a Phase-8 gap.
- **ROADMAP.md and STATE.md in this worktree are stale relative to 08-07's actual completion**
  (both still show "6/7 plans executed" / 08-07 unchecked, and STATE.md's `current_phase` block
  predates the 08-07 merge). `.planning/REQUIREMENTS.md` was already flipped to Complete for all
  ten SEC items by commit `2ae8356` in this worktree. This verification pass updates
  ROADMAP.md/STATE.md to close that gap (see below).

## Verdict

**VERIFIED.** All 5 ROADMAP.md Phase 8 success criteria and all 10 SEC-01..SEC-10 requirements
are independently confirmed against the actual codebase, not merely against summary claims. The
two claimed live findings (SEC-03's `_mk_session()` SSRF-redirect fix, SEC-07's `_safe_next()`
backslash/CRLF fix) are real, are the only substantive production-code changes in the phase
(the SEC-06 `read_report_file()` refactor is defence-in-depth, explicitly not a live-vulnerability
fix per its own docstring and the phase's own reachability analysis), and are each backed by a
regression test that was read and confirmed to assert the claimed behavior. The frozen surfaces
(`entitlements.py`, `is_ssrf_safe_hostname()`'s body, `billing.py`, `authorized*` checkbox
handling) are confirmed untouched. The full test suite passes cleanly at 757/757 on an
independent, from-scratch run.

---
_Verified: 2026-08-19_
_Verifier: Claude (gsd-verifier)_
