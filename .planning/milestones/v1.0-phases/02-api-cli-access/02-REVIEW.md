---
phase: 02-api-cli-access
reviewed: 2026-08-11T00:00:00Z
depth: standard
files_reviewed: 16
files_reviewed_list:
  - cli/__init__.py
  - cli/wvs.py
  - migrations/versions/e1d41aad57db_add_api_tokens_table.py
  - requirements.txt
  - templates/api_tokens.html
  - templates/base.html
  - tests/conftest.py
  - tests/test_api_routes.py
  - tests/test_api_tokens_routes.py
  - tests/test_cli.py
  - glassbox/__init__.py
  - glassbox/api_routes.py
  - glassbox/api_tokens_routes.py
  - glassbox/extensions.py
  - glassbox/models.py
  - glassbox/scheduler.py
findings:
  critical: 1
  warning: 4
  info: 3
  total: 8
status: issues_found
---

# Phase 2: Code Review Report

**Reviewed:** 2026-08-11T00:00:00Z
**Depth:** standard
**Files Reviewed:** 16
**Status:** issues_found

## Summary

This phase adds Bearer-token API authentication (`login_manager.request_loader` in
`extensions.py`), three `/api/v1/*` JSON endpoints (`api_routes.py`), self-service token
generate/revoke UI (`api_tokens_routes.py`, `api_tokens.html`), and a standalone CLI
(`cli/wvs.py`). Token storage (SHA-256 hash-only, 256-bit `secrets.token_urlsafe(32)` raw
value, unique constraint, soft-revoke) is sound, and the ownership/IDOR reuse for
`trigger_scan`/`fetch_report` (`_check_asset_access`/`_check_ownership`) is correctly wired
and well covered by `tests/test_api_routes.py`'s cross-org/cross-user tests. No SSRF-guard or
tier-gating bypass was found — `trigger_scan` reuses `scheduler._fire()` unchanged, which still
re-checks `is_ssrf_safe_hostname` and `FEATURE_REQUIREMENTS` at fire time.

The main defect is architectural: `login_manager.request_loader` is registered globally, not
scoped to the `api` blueprint, so a Bearer token authenticates **every** `@login_required`
route in the app (dashboard, assets, billing, org admin, HTML scan/report pages), not just the
three documented `/api/v1/*` endpoints — and none of those other routes carry the API
blueprint's 60/30-per-minute rate limits. A secondary cluster of issues affects error-handling
robustness (unguarded file I/O in `fetch_report`, no timeouts in the CLI's HTTP calls) and one
small state-consistency gap (soft-deleted Assets remain scannable/reportable through the new
token-authenticated routes). I verified the rate-limiting decorator stacking in
`api_routes.py` directly against Flask-Limiter's source (`_limits.py`'s `RouteLimit.__call__`
+ the `app.before_request(self._check_request_limit)` hook registered in `init_app`) before
ruling it out as a false lead — Flask-Limiter's `before_request` hook fires ahead of any view
code regardless of decorator order, so the `@api_login_required` / `@limiter.limit` ordering in
this file is *not* a bug, despite looking suspicious at a glance.

## Critical Issues

### CR-01: Bearer-token auth is not scoped to `/api/v1/*` — a leaked token grants full-app session-equivalent access, unthrottled by the API's rate limits

**File:** `glassbox/extensions.py:57-83`, `glassbox/__init__.py:132-138`
**Issue:**
`load_user_from_request` (the `login_manager.request_loader` callback) is registered once,
globally, on `login_manager` in `extensions.py`. Flask-Login's `request_loader` mechanism is
invoked for **every** request that reaches a `current_user.is_authenticated` check with no
session-authenticated user — this is not scoped to the `api` blueprint in any way (no
`request.blueprint` / `request.path` check inside `load_user_from_request`, and no
`before_request` guard registered anywhere in `glassbox/__init__.py`).

Every other blueprint in the app (`asset`, `scan`, `org`, `billing`, `api_tokens`, ...) protects
its routes with plain `@login_required`, which only checks `current_user.is_authenticated` —
it has no idea whether that authentication came from the session cookie or from a Bearer
token. The result: a valid API token (minted from `/tokens/new`, meant per the module
docstrings and this phase's own scope to authenticate the three JSON endpoints in
`api_routes.py`) in fact authenticates the token's owner against `/dashboard`, `/assets`,
`/assets/<id>` (HTML), `/account/billing`, `/org/admin` (if `ORG_ADMIN`), `/scan/<id>` and
`/scan/<id>/report` (HTML), `/tokens` (lists all the user's other token names/metadata), etc.

This matters because:
- None of those other routes carry the `api` blueprint's `_api_rate_limit_key`-based 60/min or
  30/min limits (or any limit at all, in most cases) — so a stolen token gets *unthrottled*
  access to a strictly larger surface than the one this phase was built and rate-limited for.
- `tests/test_api_routes.py`'s `test_token_authenticated_response_has_no_set_cookie_header`
  only proves no-Set-Cookie-leakage *for the api blueprint*; there is no test anywhere in this
  diff asserting a Bearer token is *rejected* on a non-`/api/v1/*` route, so this gap shipped
  with no regression coverage at all.
- `models.py:190`'s comment ("acts as the exact user who created it ... reused unchanged for
  token-authenticated requests") and `api_routes.py`'s own module docstring ("D-02: ... so a
  token can never see more than its creating user's session already could") describe *ownership
  scoping within the API endpoints*, not an intent to expose the entire HTML application via a
  machine credential — but as written, the code does the latter.

CSRF still blocks state-changing `POST` forms on the web UI for a Bearer-token-only client
(Flask-WTF's CSRF token is tied to a session that never gets persisted back to the client
because `_ApiAwareSessionInterface` suppresses `Set-Cookie` for token-authenticated requests),
so this is not a full account-takeover-with-write-access path — but every `GET`-rendered page
(including ones showing org membership, invite state, billing/invoice data, and scan reports)
is fully exposed.

**Fix:** Scope `request_loader` to the API surface explicitly, e.g.:
```python
@login_manager.request_loader
def load_user_from_request(request):
    if not request.path.startswith("/api/v1/"):
        return None
    auth_header = request.headers.get("Authorization", "")
    ...
```
or register a blueprint-local `before_request` on `api` that performs the Bearer-token lookup
and sets `current_user`/`g.login_via_request` itself, leaving `login_manager.request_loader`
unset (so no other blueprint's `@login_required` can ever be satisfied by a Bearer header). Add
a regression test asserting `GET /dashboard` (or any non-API `@login_required` route) with a
valid `Authorization: Bearer <token>` header and no session cookie returns a redirect-to-login
(302), not a 200.

## Warnings

### WR-01: `trigger_scan`/`fetch_report` don't exclude soft-deleted Assets

**File:** `glassbox/api_routes.py:111-130`, `glassbox/api_routes.py:133-162`
**Issue:** Both routes look the target up with `Asset.query.get_or_404(asset_id)` /
`Scan.query.get_or_404(scan_id)` and then call `_check_asset_access(a)` (imported from
`asset_routes.py`), which checks org/solo ownership but never checks `Asset.deleted_at`. The
web UI's own asset list (`_scoped_asset_query()`) filters `deleted_at=None`, and
`asset_routes.delete_asset` treats deletion as revoking the Asset from active use
(`is_paused=True`, removed from scheduling) — but this new machine-credential surface lets a
caller keep firing scans (`POST /api/v1/assets/<id>/scans`) and pulling reports
(`GET /api/v1/scans/<id>/report`) against an Asset that has been "deleted" through the UI,
since neither `Asset.query.get_or_404` nor `_check_asset_access` filters on it. This is new
attack surface for this phase (the web UI has no equivalent action-triggering route reachable
after delete other than `/resume`, which itself has the same latent gap, but that's pre-existing
Phase 1 code, not part of this diff).
**Fix:**
```python
@api.route("/assets/<int:asset_id>/scans", methods=["POST"])
@api_login_required
@limiter.limit("30 per minute", key_func=_api_rate_limit_key)
def trigger_scan(asset_id):
    a = Asset.query.filter_by(id=asset_id, deleted_at=None).first_or_404()
    _check_asset_access(a)
    ...
```
and similarly guard `fetch_report`'s Asset-linked branch (`if s.asset_id is not None and
s.asset.deleted_at is None: ...` else fall back to `_check_ownership`, or simply reject with 404
if the linked Asset has been deleted).

### WR-02: `fetch_report`'s file read isn't guarded — a missing/corrupt report file 500s with an HTML body, not JSON

**File:** `glassbox/api_routes.py:156-162`
**Issue:**
```python
with open(os.path.join(REPORTS_DIR, s.report.json_path), encoding="utf-8") as f:
    report = json.load(f)
```
has no `try/except`. If the file is missing (e.g. `reports/` isn't on persistent storage across
a redeploy/restart, or it was manually cleaned up) or contains malformed JSON, this raises
`FileNotFoundError`/`json.JSONDecodeError`, which is not caught anywhere in this blueprint.
Unlike 404s (`@api.errorhandler(404)` exists specifically so `abort(404)`/`get_or_404()` return
JSON instead of falling through to the app's HTML 404 page), there is no `@api.errorhandler(500)`
here, so the request falls through to the global `@app.errorhandler(500)` in
`glassbox/__init__.py`, which renders `500.html` — an HTML page returned to what the
CLI/scripts expect to always be a JSON response, breaking `_raise_for_error_response`'s parsing
in `cli/wvs.py` (it degrades to raw HTML text, not a clean error message, but at least doesn't
crash the CLI outright).
**Fix:**
```python
try:
    with open(os.path.join(REPORTS_DIR, s.report.json_path), encoding="utf-8") as f:
        report = json.load(f)
except (OSError, ValueError):
    return jsonify(error="report file is unavailable"), 500
```

### WR-03: CLI HTTP calls have no `timeout` — every `wvs` command can hang indefinitely

**File:** `cli/wvs.py:102-106` (login), `:137-140` (assets list), `:172-176` (scan start),
`:203-207` (report get)
**Issue:** None of the four `requests.get`/`requests.post` call sites pass `timeout=`. Against
an unresponsive server, a dropped connection, or a misconfigured `--api-url`, any `wvs` command
blocks forever with no feedback — a real problem for a tool whose own docstring says it's
"meant to be piped/redirected by CI tooling" (CI pipelines need bounded-time failures, not
indefinite hangs).
**Fix:** Add a module-level `REQUEST_TIMEOUT_SECONDS = 15` and pass `timeout=REQUEST_TIMEOUT_SECONDS`
to every `requests.get`/`requests.post` call; catch `requests.Timeout` alongside the existing
`requests.RequestException` handling (it already is a subclass, so the existing `except
requests.RequestException` blocks will catch it, but only once a `timeout=` argument is
actually supplied).

### WR-04: `wvs login` silently resets a previously-saved custom `api_url` back to the default

**File:** `cli/wvs.py:94-100`
**Issue:**
```python
if not api_url:
    api_url = DEFAULT_API_URL
```
`login()` never consults `_load_config()`/the existing `~/.wvs/config.json` for a previously
saved `api_url` — unlike `_resolve_api_url()` (used by every other command), which correctly
falls back to the stored config value before `DEFAULT_API_URL`. A user who ran
`wvs login --api-url https://scanner.example.com` once, then later re-runs plain `wvs login`
(e.g. to rotate an expiring token) without repeating `--api-url`, silently gets logged in
against `http://127.0.0.1:5000` instead, overwriting their previously configured URL with no
warning.
**Fix:**
```python
if not api_url:
    api_url = _load_config().get("api_url") or DEFAULT_API_URL
```

## Info

### IN-01: `POST /tokens/new` has no rate limit

**File:** `glassbox/api_tokens_routes.py:39-65`
**Issue:** Unlike the careful per-route rate limiting this phase applies to `/api/v1/*`
(`_api_rate_limit_key`, 60/30 per minute) and the app's pre-existing `/login`/`/signup` limits,
`create_token` has no `@limiter.limit(...)`. A compromised session or a buggy automation script
could mint an unbounded number of tokens for one account (each a permanent row until manually
revoked), which is low-severity (self-scoped, no cross-user impact) but inconsistent with the
rest of this phase's rate-limiting discipline.
**Fix:** Add a modest limit, e.g. `@limiter.limit("10 per hour")`, matching the existing
`/signup` precedent in `auth_routes.py`.

### IN-02: CLI doesn't guard against malformed/unexpected JSON bodies on success responses

**File:** `cli/wvs.py:148 (a['name']/a.get('latest_scan'))`, `:184-185 (body['scan_id'])`,
`:215 (resp.json())`
**Issue:** `_raise_for_error_response` carefully catches `ValueError` when parsing a non-2xx
body, but the success paths (`assets_list`'s `resp.json()["assets"]`, `scan_start`'s
`body['scan_id']`, `report_get`'s `resp.json()`) assume the server always returns well-formed
JSON with the expected keys on 200/202. A malformed response from a misbehaving/incompatible
server version would raise an uncaught `ValueError`/`KeyError`, printing a raw Python traceback
instead of the clean `click.ClickException` the rest of the module is careful to always surface.
**Fix:** Wrap the `resp.json()` calls / key access in the same `try/except (ValueError, KeyError)
-> click.ClickException` pattern already used for error responses.

### IN-03: `_serialize_asset` issues one extra query per Asset (N+1)

**File:** `glassbox/api_routes.py:87-100`
**Issue:** `list_assets` calls `_serialize_asset(a)` once per Asset in the result set, and each
call does its own `Scan.query.filter_by(asset_id=a.id).order_by(...).first()` — an N+1 query
pattern. Flagged for awareness only; per the review's scope, performance issues are out of v1
scope and this is not a correctness defect.

---

_Reviewed: 2026-08-11T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
