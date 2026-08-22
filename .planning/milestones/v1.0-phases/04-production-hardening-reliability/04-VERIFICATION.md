---
phase: 04-production-hardening-reliability
verified: 2026-08-13T00:00:00Z
status: passed
score: 4/4 must-haves verified
behavior_unverified: 0
overrides_applied: 0
---

# Phase 4: Production Hardening & Reliability Verification Report

**Phase Goal:** The platform is safe to run with more than one production worker and has
test/visual consistency coverage matching the "production ready" bar this milestone targets.
**Verified:** 2026-08-13
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Rate limits (login, signup, invoice, and the new API-token endpoints) enforce correctly even when the app runs with more than one gunicorn worker | ✓ VERIFIED | `Config.RATELIMIT_STORAGE_URI` (`webvulnscanner/config.py:121`) is read into Flask-Limiter's `storage_uri` at `limiter.init_app(app)` (`webvulnscanner/__init__.py:97`); `tests/test_ratelimit_storage.py` proves two independently-constructed `Limiter` instances (simulating two gunicorn workers) sharing a `redis://` URI (fakeredis-backed) actually share a counter, with an in-memory negative control proving they don't without it, and a config-key-pinning test proving `Config.RATELIMIT_STORAGE_URI` is the exact key `flask_limiter.constants.ConfigVars.STORAGE_URI` reads. `/login` (`auth_routes.py:182`), `/signup` (`:70`), invoice create/verify (`billing_routes.py:48,84`), and the token-authenticated `/api/v1/*` routes (`api_routes.py:105,113,139`) all route through the same shared `limiter` singleton, so all become multi-worker-safe once `RATELIMIT_STORAGE_URI` is set. A boot-time log line (`__init__.py:99-115`) names the active backend's scheme only (never the credential-bearing full URI). Independently re-ran `tests/test_ratelimit_storage.py` — 4/4 pass. |
| 2 | `run_advanced_scan`, `run_media_scan`, and `run_api_scan` each have automated tests covering status transitions and error handling, matching the coverage `run_scan` already has — including the scheduler-triggered path added in Phase 1 | ✓ VERIFIED | `tests/test_scan_engine.py` (549 lines) covers all three orchestrators' completed-return shape and error-propagation directly (`test_run_media_scan_completed_shape_no_findings`, `test_run_api_scan_completed_shape_no_findings`, `test_run_advanced_scan_all_allowed_runs_every_group_and_locks_nothing`, plus lock/run-matrix and safety-constraint regression tests). `tests/test_scheduler.py` covers the scheduler-triggered path for `media`/`api` (entitled-plan fire, dispatch kwargs, rescheduling, fire-time SSRF refusal) and a source-parsing lock proving `_fire` has no `advanced` branch (by design, D-04 — `Asset` stores no credentials for an unattended advanced run). `tests/test_scan_routes.py` covers `_run_scan_in_background`'s Scan-row COMPLETED/FAILED transitions for media/api/advanced (and an unknown-scan-type path). Independently re-ran all three files — 109/109 relevant tests pass (subset run); full suite includes them at 353/353. |
| 3 | Org invite/role-change/domain-verification flows have automated test coverage beyond the current single rendering test | ✓ VERIFIED | `tests/test_org_invite.py` (292 lines, 16 tests) covers the full invite→signup→membership flow end to end, including the email-binding (D-07) that ties role assignment to the invite token (a forwarded/leaked link can't be redeemed under a different address), tampered/expired/cross-org tokens, and case/whitespace normalization. `tests/test_domain_verification.py` (229 lines, 11 tests) covers both proof methods (DNS TXT, well-known), re-add reset, and the cross-org 404 guard. `webvulnscanner/org_routes.py`'s module docstring documents a deliberate design decision (D-06): changing an *already-joined* member's role is intentionally not a route anywhere in the app — role is only ever assigned at invite time — so "role" coverage is satisfied via the invite-token tests (`test_signup_post_with_valid_invite_grants_admin_role_when_invited_as_admin`), not a separate role-change endpoint that does not exist by design. `tests/test_org_routes.py` (the prior single-rendering-test file) remains 15 lines — coverage genuinely came from the two new files. Independently re-ran both new files — 27/27 tests pass (subset), confirmed again in the full 353-test run. |
| 4 | Dashboard, billing, org-admin, and scan_report pages visually match the rest of the app's design system — no bland/legacy styling left on any of the four | ✓ VERIFIED | Grepped all four templates: `dashboard.html` uses `.btn.primary` for its "New scan" CTA (page-local `.cta` gradient rule deleted) and `.hud-grid` on its one latest-scan anchor card; `org_admin.html`'s scan-history card has `.hud-grid`, "Send invite" uses `.btn.primary`; `billing.html`'s current-plan card has `.hud-grid`, both action buttons use `.btn.primary`, pending invoices show a `.status-pill.running` "Awaiting payment" pill, and the no-org warning box now uses the new `#icon-warning` sprite symbol instead of an emoji glyph; `scan_report.html`'s duplicated `table`/`th, td` CSS rule (verbatim-identical to `base.html`'s promoted rule) was deleted. `tests/test_template_consistency.py` (18 tests) asserts these class-level facts against rendered HTML for all four pages, including empty states. Reuse-only discipline confirmed: no new colors/spacing/motion primitives were added, only one new sprite symbol (`#icon-warning`) authored in the sprite's existing format. Visual rendering itself (not just class presence) was human-checkpoint-verified during 04-05's execution by the coordinator in a live browser (documented in 04-05-SUMMARY.md's D4, human_judgment: true, status: pass) — narrow-viewport resize could not be exercised in that environment, but every changed element is a reuse of primitives already proven at all viewports elsewhere in the app. Independently re-ran `tests/test_template_consistency.py` — 18/18 pass. |

**Score:** 4/4 truths verified (0 present-but-behavior-unverified)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `webvulnscanner/scan_engine.py::_score_report` | Single shared scoring helper (HARD-04) | ✓ VERIFIED | All four orchestrators (`run_scan`, `run_advanced_scan`, `run_media_scan`, `run_api_scan`) call `_score_report(findings)`; none retains an inline copy. `test_no_orchestrator_carries_an_inline_scoring_block` is a source-parsing regression lock. |
| `webvulnscanner/config.py`, `extensions.py`, `__init__.py` | `RATELIMIT_STORAGE_URI` wiring + boot-time backend log (HARD-01) | ✓ VERIFIED | `Config.RATELIMIT_STORAGE_URI` present, read at `limiter.init_app`, boot log names scheme only. |
| `tests/test_ratelimit_storage.py` | Multi-worker rate-limit storage proof | ✓ VERIFIED | 4 tests, all pass on independent re-run; positive proof + negative in-memory control + config-key pin. |
| `tests/test_scan_engine.py` | Direct-invocation orchestrator coverage (HARD-02) | ✓ VERIFIED | 32 tests: scoring arithmetic, three previously-untested orchestrators, safety-constraint regression locks (`check_bruteforce`, `check_xss_stored`). |
| `tests/test_scheduler.py`, `tests/test_scan_routes.py` | Scheduler-fired + status-transition coverage (HARD-02 remainder) | ✓ VERIFIED | 16 + 12 tests respectively; entitled-plan media/api fire, no-advanced-branch source lock, COMPLETED/FAILED transitions for media/api/advanced. |
| `webvulnscanner/org_routes.py`, `auth_routes.py`, `templates/signup.html` | Email-bound invite flow (HARD-03) | ✓ VERIFIED | `generate_invite_token`/`decode_invite_token(token, expected_email=None)` present; `signup()`'s invite-mode branch present; template locks email field in invite mode. |
| `tests/test_org_invite.py`, `tests/test_domain_verification.py` | Invite + domain-verification coverage (HARD-03) | ✓ VERIFIED | 16 + 11 tests; both pass independently. |
| `templates/{dashboard,org_admin,billing,scan_report}.html` | Visual-consistency pass (HARD-05) | ✓ VERIFIED | Confirmed via grep: `.btn.primary`, `.hud-grid`, `.status-pill .dot.glow-pulse`, `#icon-warning` all present at the documented sites; no new CSS declarations added. |
| `tests/test_template_consistency.py` | Visual-consistency assertions | ✓ VERIFIED | 18 tests, all pass independently. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `webvulnscanner/__init__.py` | `flask_limiter.Limiter` | `limiter.init_app(app)` reads `app.config["RATELIMIT_STORAGE_URI"]` | ✓ WIRED | Confirmed by `test_flask_limiter_reads_the_exact_config_key_the_app_writes` pinning against `flask_limiter.constants.ConfigVars.STORAGE_URI`. |
| `auth_routes.py` / `billing_routes.py` / `api_routes.py` | `webvulnscanner/extensions.py::limiter` | `@limiter.limit(...)` decorators, same singleton | ✓ WIRED | grep confirms all rate-limited routes decorate with the same shared `limiter` object — no per-route isolated Limiter instance. |
| `scan_engine.run_scan/run_advanced_scan/run_media_scan/run_api_scan` | `scan_engine._score_report` | Direct function call | ✓ WIRED | grep confirms all four call sites; source-parsing regression test guards against silent re-inlining. |
| `scheduler.py::_fire` | `scan_routes._spawn_scan_thread` | dispatch on `base`/`media`/`api` scan types | ✓ WIRED | `test_fire_dispatches_only_on_base_media_api_no_advanced_branch` source-parsing lock confirms the exact literal set; media/api entitled-fire tests confirm dispatch kwargs. |
| `auth_routes.signup()` | `org_routes.decode_invite_token` | POST-time re-decode with submitted email as `expected_email` | ✓ WIRED | `test_signup_post_with_mismatched_email_creates_no_user` confirms a mismatched email is rejected; `test_signup_post_with_valid_invite_creates_member_in_org` confirms the happy path. |
| `templates/billing.html` | `templates/base.html` sprite | `<use href="#icon-warning"/>` | ✓ WIRED | `#icon-warning` symbol present in `base.html`'s sprite (14th symbol); `billing.html`'s warn-box references it, no emoji glyph remains at that site. |

### Behavioral Spot-Checks / Test Execution

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full project test suite (independent run, fresh `.venv` built for this verification) | `.venv/Scripts/python -m pytest -q` | **353 passed, 0 failed** in 232.24s | ✓ PASS |
| Rate-limit storage proof (isolated re-run) | `pytest tests/test_ratelimit_storage.py -q` | 4 passed | ✓ PASS |
| Orchestrator + scheduler + status-transition + template-consistency subset (isolated re-run) | `pytest tests/test_scan_engine.py tests/test_org_invite.py tests/test_domain_verification.py tests/test_scheduler.py tests/test_scan_routes.py tests/test_template_consistency.py -q` | 109 passed | ✓ PASS |
| No debt markers in phase-4-modified files | grep `TBD\|FIXME\|XXX\|TODO\|HACK\|PLACEHOLDER` across `scan_engine.py`, `extensions.py`, `__init__.py`, `org_routes.py`, `auth_routes.py`, `scan_routes.py`, `scheduler.py`, and the four visually-updated templates | No matches | ✓ PASS |
| Git working tree clean, all claimed commits present | `git status --short` / `git log --oneline` | Clean; all 15 commits referenced across the 5 SUMMARYs present on HEAD | ✓ PASS |

**Note on test-suite independence:** This worktree had no local `.venv`. A fresh venv was built from `requirements.txt` + `requirements-dev.txt` specifically for this verification and the suite run twice (once mid-install with a partial dependency set that correctly failed on `ModuleNotFoundError`, then successfully after the install completed) — the SUMMARY-claimed 353/353 was independently reproduced, not trusted.

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| HARD-01 | 04-02 | Rate limits multi-worker-safe via shared backend | ✓ SATISFIED | `RATELIMIT_STORAGE_URI` wiring + `test_ratelimit_storage.py` |
| HARD-02 | 04-01, 04-04 | Orchestrator + scheduler + status-transition test coverage | ✓ SATISFIED | `test_scan_engine.py`, `test_scheduler.py`, `test_scan_routes.py` |
| HARD-03 | 04-03 | Org invite / domain-verification test coverage | ✓ SATISFIED | `test_org_invite.py`, `test_domain_verification.py` |
| HARD-04 | 04-01 | Shared scoring helper across all orchestrators | ✓ SATISFIED | `_score_report`, regression lock |
| HARD-05 | 04-05 | Visual-consistency pass on 4 pages | ✓ SATISFIED | Template diffs + `test_template_consistency.py` + human-checkpoint |

No orphaned requirements — all 5 HARD-* requirements map to a plan in this phase, and all 5 plans together claim all 5.

### Anti-Patterns Found

None. Scanned every phase-4-modified core file (`scan_engine.py`, `extensions.py`, `__init__.py`, `org_routes.py`, `auth_routes.py`, `scan_routes.py`, `scheduler.py`, `dashboard.html`, `org_admin.html`, `billing.html`, `scan_report.html`, `signup.html`) for `TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER` — no matches. No empty-implementation patterns, no hardcoded-empty stub data, no console-log-only handlers found in the reviewed files.

### Human Verification Required

None required to certify the phase goal. The one inherently visual truth (SC4, visual consistency) was already exercised via a documented, coordinator-run live-browser checkpoint during 04-05's execution (04-05-SUMMARY.md D4), backed by 18 passing rendered-HTML consistency tests and a reuse-only diff (no new CSS primitives) that is independently confirmable by reading the template source, which this verification did. Re-litigating that checkpoint would not surface new information the code/tests don't already provide.

### Gaps Summary

No gaps found. All 5 HARD-* requirements are satisfied with real (not stubbed) implementations, all 4 ROADMAP Success Criteria are observably true in the codebase, and the full test suite (353 tests) passes when run directly by the verifier in a freshly-built virtual environment — not merely as claimed across the 5 SUMMARY.md files. The one wording ambiguity worth flagging (ROADMAP/HARD-03's "role-change flows") resolves cleanly: the codebase makes a deliberate, documented design decision (D-06, in `org_routes.py`'s module docstring) that member roles are only ever set at invite time, never changed after joining — so there is no separate "role-change" route to test, and the invite-token tests already cover role assignment. This is a documented scope resolution, not an overlooked gap.

---

_Verified: 2026-08-13_
_Verifier: Claude (gsd-verifier)_
