---
phase: 02-api-cli-access
fixed_at: 2026-08-11T00:00:00Z
review_path: .planning/phases/02-api-cli-access/02-REVIEW.md
iteration: 1
findings_in_scope: 5
fixed: 5
skipped: 0
status: all_fixed
---

# Phase 2: Code Review Fix Report

**Fixed at:** 2026-08-11T00:00:00Z
**Source review:** .planning/phases/02-api-cli-access/02-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 5 (CR-01, WR-01, WR-02, WR-03, WR-04 — critical_warning scope; IN-01/IN-02/IN-03 excluded per instructions)
- Fixed: 5
- Skipped: 0

**Verification environment note:** this agent session runs inside an
already-isolated Claude Code worktree
(`.claude/worktrees/lazy-drifting-quilt`, branch `worktree-lazy-drifting-quilt`),
separate from the main checkout. Per the fixer's own isolation rationale
(avoid racing a foreground session sharing the same working tree), no
additional nested `git worktree` was created for this run — edits and
commits happened directly in this already-dedicated worktree. All syntax
checks and the full test suite ran here, using the sibling checkout's
venv (`C:\Users\Arktech_Designs\Documents\Glassbox\.venv`) since this
worktree has no local `.venv` of its own — results are reproducible from
this worktree's current state.

## Fixed Issues

### CR-01: Bearer-token auth is not scoped to `/api/v1/*`

**Files modified:** `glassbox/extensions.py`, `tests/test_api_routes.py`
**Commit:** `06896cf`
**Applied fix:** `load_user_from_request` (the `login_manager.request_loader`
callback) now returns `None` immediately for any request whose path does
not start with `/api/v1/`, before touching the `Authorization` header at
all. This means Flask-Login falls through to normal session-cookie-only
handling (redirect to login) for every non-API `@login_required` route,
closing the full-app session-equivalent access gap a leaked API token
previously granted. Added the reviewer-recommended regression test:
`GET /dashboard` with a valid `Authorization: Bearer <token>` header and no
session cookie now asserts a 302 redirect to `/login`, not a 200. Ran the
new test plus the full `test_api_routes.py`/`test_api_tokens_routes.py`/
`test_cli.py` suite (37 passed) before committing.

### WR-01: `trigger_scan`/`fetch_report` don't exclude soft-deleted Assets

**Files modified:** `glassbox/api_routes.py`, `tests/test_api_routes.py`
**Commit:** `00ccae8`
**Applied fix:** `trigger_scan` now looks the Asset up with
`Asset.query.filter_by(id=asset_id, deleted_at=None).first_or_404()`,
matching `_scoped_asset_query()`'s own filter. `fetch_report`'s
Asset-linked branch now checks `s.asset.deleted_at is not None` and
`abort(404)`s before calling `_check_asset_access`; the manual-scan
(`_check_ownership`) branch is unchanged. Added regression tests for both
routes against a soft-deleted Asset (404, no Scan created / no report
leaked). Full `test_api_routes.py` suite (24 tests) passed before
committing.

### WR-02: `fetch_report`'s file read isn't guarded

**Files modified:** `glassbox/api_routes.py`, `tests/test_api_routes.py`
**Commit:** `bb21a63`
**Applied fix:** Wrapped the `open()`/`json.load()` call in
`try/except (OSError, ValueError)`, returning `jsonify(error="report file
is unavailable"), 500` instead of letting the exception fall through to
the app's global HTML 500 error page. Added a regression test with a
`Report` row pointing at a nonexistent `json_path`, asserting a JSON 500
body. Full `test_api_routes.py` suite (25 tests) passed before committing.

### WR-03: CLI HTTP calls have no `timeout`

**Files modified:** `cli/wvs.py`, `tests/test_cli.py`
**Commit:** `181f6d7`
**Applied fix:** Added a module-level `REQUEST_TIMEOUT_SECONDS = 15` and
passed `timeout=REQUEST_TIMEOUT_SECONDS` to all four `requests.get`/
`requests.post` call sites (`login`, `assets list`, `scan start`,
`report get`). `requests.Timeout` is already a subclass of
`requests.RequestException`, so the existing exception handling now
actually catches timeouts. Added four regression tests asserting
`timeout=` is passed at each call site. Full `test_cli.py` suite (13
tests, then 14 after adding WR-04's test) passed before each commit.

### WR-04: `wvs login` silently resets a previously-saved custom `api_url`

**Files modified:** `cli/wvs.py`, `tests/test_cli.py`
**Commit:** `c90a0c4`
**Applied fix:** `login()` now resolves `api_url` via
`_load_config().get("api_url") or DEFAULT_API_URL` when `--api-url`/
`WVS_API_URL` isn't supplied, matching `_resolve_api_url()`'s precedence
used by every other command. Added a regression test: a stored config with
a custom `api_url` is reused by a plain `wvs login --token <new>` call
(no `--api-url` flag), and the saved config after login still has the
original custom URL. Full `test_cli.py` suite (14 tests) passed before
committing.

## Skipped Issues

None — all 5 in-scope findings (CR-01, WR-01, WR-02, WR-03, WR-04) were
fixed. IN-01, IN-02, IN-03 were explicitly out of scope for this pass per
the orchestrator's instructions and were not attempted.

## Full Test Suite

Ran `python -m pytest -q` (via the sibling checkout's venv, per
instructions, since this worktree has no local `.venv`) after all five
fixes were committed:

```
217 passed, 90 warnings in 101.34s (0:01:41)
```

All warnings are pre-existing `LegacyAPIWarning`s from SQLAlchemy 1.x-style
`Query.get()` calls elsewhere in the codebase, unrelated to this fix pass.
No failures, no new warnings introduced.

---

_Fixed: 2026-08-11T00:00:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
