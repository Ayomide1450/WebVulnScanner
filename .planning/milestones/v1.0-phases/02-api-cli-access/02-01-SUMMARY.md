---
phase: 02-api-cli-access
plan: 01
subsystem: api
tags: [flask-login, bearer-token, sha256, sqlalchemy, request_loader]

requires:
  - phase: 01-asset-inventory-continuous-scanning
    provides: Asset model, _scoped_asset_query (org/solo-scoped query pattern reused unchanged)
provides:
  - ApiToken model (hash-only, soft-revoke, user-scoped)
  - login_manager.request_loader Bearer-token auth + _ApiAwareSessionInterface (no Set-Cookie on token-authenticated responses)
  - /tokens self-service token-management UI (create/list/revoke)
  - GET /api/v1/assets - first token-authenticated JSON endpoint
affects: [02-02-trigger-scan-fetch-report, 02-03-cli, api_routes.py]

actuals:
  tokens: 9800
  tasks: 1
  commits: 1

tech-stack:
  added: []
  patterns:
    - "login_manager.request_loader dual-auth: session cookie OR Bearer token, mutually exclusive per request"
    - "Hash-only credential storage: sha256(raw) persisted, raw value shown exactly once at creation (mirrors PasswordReset precedent)"
    - "Soft-revoke via nullable revoked_at timestamp (mirrors Asset.deleted_at)"
    - "Blueprint-scoped 404 JSON error handler keeps API responses JSON-only, independent of the app's global HTML 404 page"

key-files:
  created:
    - webvulnscanner/api_tokens_routes.py
    - webvulnscanner/api_routes.py
    - templates/api_tokens.html
    - migrations/versions/e1d41aad57db_add_api_tokens_table.py
    - tests/test_api_tokens_routes.py
    - tests/test_api_routes.py
  modified:
    - webvulnscanner/models.py
    - webvulnscanner/extensions.py
    - webvulnscanner/__init__.py
    - templates/base.html
    - tests/conftest.py

key-decisions:
  - "D-01 (locked in 02-CONTEXT.md): tokens are hash-only - only sha256(raw) persisted, raw value never re-displayed after creation"
  - "D-02 (locked, one-way): tokens are user-scoped, not org-scoped - do not build toward org-scoped tokens later"
  - "D-03 (locked): soft-revoke via nullable revoked_at, mirroring Asset.deleted_at"
  - "D-04 (locked): users may hold multiple concurrently-active named tokens"
  - "D-05 (locked): token creation is self-service (any org member), not admin-gated"

patterns-established:
  - "Dual-auth request_loader: checks Authorization: Bearer first, falls through to normal session-cookie auth - both paths converge on the same current_user"
  - "Token-identity rate-limiting key (distinct from IP-based Flask-Limiter keys elsewhere in the app)"

requirements-completed: [API-01, API-02]

coverage:
  - id: D1
    description: "User can generate a named token from /tokens, sees the raw secret exactly once with copy-to-clipboard, and it never reappears after that render"
    requirement: "API-01"
    verification:
      - kind: integration
        ref: "tests/test_api_tokens_routes.py#test_create_token_shows_raw_value_exactly_once"
        status: pass
    human_judgment: false
  - id: D2
    description: "Token list shows only hash-derived metadata (name, created, last-used, status) - no raw value stored or re-displayed"
    requirement: "API-01"
    verification:
      - kind: integration
        ref: "tests/test_api_tokens_routes.py#test_tokens_list_shows_only_hash_derived_metadata"
        status: pass
    human_judgment: false
  - id: D3
    description: "Revoking a token sets revoked_at and immediately fails Bearer-auth on the next request"
    requirement: "API-01"
    verification:
      - kind: integration
        ref: "tests/test_api_tokens_routes.py#test_revoke_sets_revoked_at_and_immediately_fails_api_auth"
        status: pass
      - kind: manual_procedural
        ref: "prior-session curl verification (cookie jar + scraped CSRF token, worked around a confirm()-dialog CDP freeze): revoked_at confirmed via direct SQLite query, subsequent curl with same token got 401 immediately - see handoff.md Phase-2-Wave-1 entry"
        status: pass
    human_judgment: false
  - id: D4
    description: "A user can hold multiple concurrently-active, independently-revocable named tokens"
    requirement: "API-01"
    verification:
      - kind: unit
        ref: "tests/test_api_tokens_routes.py#test_creating_second_token_does_not_affect_first"
        status: pass
    human_judgment: false
  - id: D5
    description: "A Bearer-token-authenticated request never receives a Set-Cookie session header and never mutates the session store"
    requirement: "API-02"
    verification:
      - kind: unit
        ref: "tests/test_api_routes.py#test_token_authenticated_response_has_no_set_cookie_header"
        status: pass
    human_judgment: false
  - id: D6
    description: "GET /api/v1/assets returns only the caller's own org/solo-scoped Assets plus latest Scan status/risk_score; missing/invalid/revoked auth gets 401 JSON, never a redirect or HTML page"
    requirement: "API-02"
    verification:
      - kind: unit
        ref: "tests/test_api_routes.py#test_list_assets_scoped_to_callers_org"
        status: pass
      - kind: unit
        ref: "tests/test_api_routes.py#test_list_assets_includes_latest_scan_summary"
        status: pass
      - kind: unit
        ref: "tests/test_api_routes.py#test_solo_user_only_sees_own_assets"
        status: pass
      - kind: unit
        ref: "tests/test_api_routes.py#test_no_authorization_header_gets_401_json"
        status: pass
      - kind: unit
        ref: "tests/test_api_routes.py#test_malformed_authorization_header_gets_401_json"
        status: pass
      - kind: unit
        ref: "tests/test_api_routes.py#test_nonexistent_token_gets_401_json"
        status: pass
      - kind: unit
        ref: "tests/test_api_routes.py#test_revoked_token_gets_401_json"
        status: pass
    human_judgment: false
  - id: D7
    description: "An ownership-check 404 inside /api/v1/* returns JSON via the blueprint-scoped handler, not the app's styled HTML 404 page"
    requirement: "API-02"
    verification: []
    human_judgment: true
    rationale: "The blueprint-scoped @api.errorhandler(404) handler exists (api_routes.py:48) but GET /api/v1/assets is list-only with no per-ID ownership check to trigger it this wave - first real exercise is 02-02's fetch-report endpoint. Not proven yet, not just unclassified."
  - id: D8
    description: "Token-management page reuses the existing .card/.btn/.pill/.warn-box component classes exactly, per 02-UI-SPEC.md, with zero new colors/spacing"
    verification:
      - kind: manual_procedural
        ref: "prior-session live browser verification via claude-in-chrome"
        status: pass
    human_judgment: true
    rationale: "Visual/design-system conformance was eyeballed live in a prior session but is not asserted by an automated test - routing to human keeps the audit trail honest per the deterministic-contract default."
  - id: D9
    description: "Empty state, missing-name field-error, and failed-revoke flash message all render via existing conventions"
    verification:
      - kind: unit
        ref: "tests/test_api_tokens_routes.py#test_create_token_requires_a_name"
        status: pass
    human_judgment: true
    rationale: "Missing-name field-error is test-covered; the empty-state and failed-revoke-flash render paths were not independently asserted by a test in this wave."
  - id: D10
    description: "Long token names wrap; the raw token secret renders in a scrollable readonly monospace input rather than wrapping"
    verification: []
    human_judgment: true
    rationale: "Backstop-tier visual requirement in the plan's must_haves - not exercised by an automated test or confirmed live in the prior session's verification pass."
  - id: D11
    description: "Revoke-in-flight disables its submit button via the existing button:disabled + submit-time-JS-disable pattern"
    verification: []
    human_judgment: true
    rationale: "Backstop-tier requirement, new to a table-row context per the plan - not independently confirmed."
  - id: D12
    description: "The token value stays visible/selectable in the readonly input regardless of navigator.clipboard support"
    verification: []
    human_judgment: true
    rationale: "Backstop-tier requirement - not independently confirmed. The Copy button's happy-path behavior (label swap to 'Copied') was confirmed live per handoff.md, but the no-clipboard-API fallback path specifically was not."

duration: 20min
completed: 2026-08-10
status: complete
---

# Phase 2 Plan 1: Token Auth End-to-End Summary

**Hash-only Bearer-token API auth via Flask-Login's `request_loader`, a self-service `/tokens` UI, and the first token-authenticated endpoint (`GET /api/v1/assets`)**

## Performance

- **Duration:** ~20 min
- **Started:** 2026-08-10T18:16:49+01:00 (prior commit, planning docs)
- **Completed:** 2026-08-10T18:36:50+01:00
- **Tasks:** 1 (single-task tracer plan by design)
- **Files modified:** 11

## Accomplishments
- `ApiToken` model + hand-reviewed migration: hash-only (`token_hash`, sha256), soft-revoke (`revoked_at`), user-scoped (`user_id` FK)
- `login_manager.request_loader` Bearer-token auth + `_ApiAwareSessionInterface` — token-authenticated responses never get a `Set-Cookie` header
- `/tokens` self-service UI: create (raw value shown exactly once, copy-to-clipboard), list (hash-derived metadata only), revoke
- `GET /api/v1/assets`: first token-authenticated JSON endpoint, reuses `_scoped_asset_query` unchanged (no new scoping logic), JSON 401 on missing/invalid/revoked auth — never a redirect or HTML page
- 15 new tests (`test_api_tokens_routes.py`, `test_api_routes.py`), full suite 187/187 passing

## Task Commits

1. **Task 1: Token auth end-to-end - generate/revoke UI + first authenticated JSON route** - `5945262` (feat)

**Plan metadata:** this SUMMARY.md (backfilled - see "Issues Encountered")

_Note: this is a single-task tracer plan; one commit covers the full task._

## Files Created/Modified
- `webvulnscanner/models.py` - `ApiToken` model
- `webvulnscanner/extensions.py` - `load_user_from_request` + `_ApiAwareSessionInterface`
- `webvulnscanner/api_tokens_routes.py` - `/tokens` blueprint (new)
- `webvulnscanner/api_routes.py` - `/api/v1` blueprint, `GET /api/v1/assets` (new)
- `webvulnscanner/__init__.py` - blueprint registration
- `templates/api_tokens.html` - token-management UI (new)
- `templates/base.html` - icon-key/icon-copy sprite symbols, nav link
- `migrations/versions/e1d41aad57db_add_api_tokens_table.py` - `api_tokens` table (new)
- `tests/conftest.py` - `make_api_token()` factory
- `tests/test_api_tokens_routes.py` - 6 new tests (new)
- `tests/test_api_routes.py` - 9 new tests (new)

## Decisions Made
D-01..D-05 from `02-CONTEXT.md` carried through unchanged (hash-only, user-scoped, soft-revoke, multi-token, self-service) — see that file for full rationale. No new decisions were needed during implementation; the commit's file list matches the plan's declared `files_modified` exactly.

## Deviations from Plan

None against the plan's task content — the commit's diff matches the plan's declared scope and artifact list exactly.

One **process** deviation, not a code one: this SUMMARY.md plus the STATE.md/ROADMAP.md sync were not produced when the task was originally executed and committed (prior session) — discovered via execute-phase's `safe_resume_gate` (production commit present, no matching SUMMARY.md, no async-job manifest explaining the gap). Backfilled now, before Wave 2 dispatch, after confirming `git show --stat 5945262` matches this plan's file list exactly and the full suite (187/187) passes on current HEAD — see `handoff.md`'s "Where things stand" note for the prior session's own account of this same gap.

## Issues Encountered
- Manual browser verification (prior session, documented in `handoff.md`) hit a real `claude-in-chrome` limitation: clicking the Revoke button's native `confirm()` dialog froze the CDP connection (matches the tool's own documented modal-dialog warning). Worked around via `curl` with a cookie jar + scraped CSRF token instead of the browser — confirmed `revoked_at` was set via a direct SQLite query and that a subsequent `curl` with the same token got 401 immediately.
- One cosmetic bug found, not yet fixed: the tokens table's "Created" column renders a raw Python `datetime` repr (`2026-08-10 17:51:39.479090`, full microseconds) instead of a human-formatted date. Small, non-blocking — worth a quick fix whenever `api_tokens.html`/`api_tokens_routes.py` is next touched.

## User Setup Required
None — no external service configuration required (no new env vars or config keys).

## Next Phase Readiness
Token-authentication architecture is proven end-to-end (self-service creation, Bearer-auth, no session-cookie leakage, org/solo-scoped data access, JSON-only error responses) before any further route is built on top of it. Ready for 02-02 (trigger-scan + fetch-report, including the `_check_asset_access`-routed ownership-404 case D7 flags as not yet exercised) and 02-03 (CLI).

---
*Phase: 02-api-cli-access*
*Completed: 2026-08-10*
