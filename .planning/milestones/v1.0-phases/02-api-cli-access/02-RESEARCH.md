# Phase 2: API & CLI Access - Research

**Researched:** 2026-08-10
**Domain:** Token-based API authentication (Flask), REST endpoint design over an existing scan
orchestration layer, and a thin HTTP-client CLI — all layered on a codebase that already has
Flask-Login session auth, Flask-Limiter, Alembic migrations, and a proven Asset/scan pipeline.
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Token Storage & Verification**

- **D-01:** Tokens are hash-only: a random secret is generated and shown to the user exactly once
  at creation time; only its hash (not a prefix-split scheme) is persisted, looked up via an
  indexed hash-column query at request time. No plaintext secret is ever stored or logged. —
  **Reversibility:** costly — **rationale:** moving to a prefix+secret split scheme later (e.g.
  for secret-scanning integration) would require a new column, a token-format change, and
  invalidating/reissuing all existing tokens — not a data migration in the destructive sense, but
  a real breaking change for anyone already using a token.

**Token Scope**

- **D-02:** A token is user-scoped — it acts as the specific user who created it and inherits
  that user's exact existing role/permissions (admin vs. member, org membership). No new
  authorization model is introduced; every existing authorization check (ownership,
  `entitlements.py` tier gating, `_check_asset_access`) applies unchanged to a token-authenticated
  request exactly as it would to that user's session-authenticated request. — **Reversibility:**
  one-way — **rationale:** switching to org-scoped tokens with independent roles later would be a
  genuine breaking change to the token's authorization semantics — existing tokens' behavior would
  change or need reissuing, and every route that assumes "the token IS a user" would need
  reworking. This is a foundational decision for how every subsequent API route authorizes
  requests — **do not build routes that assume org-scoped tokens are coming**; build for
  user-scoped semantics as the durable model, not a placeholder.

**Revocation**

- **D-03:** Revocation is soft: a `revoked_at` timestamp is set, not a row deletion — mirroring
  Phase 1's `Asset.deleted_at` soft-delete convention. A revoked token fails auth immediately but
  its row (and any audit/usage history attached to it) persists. — **Reversibility:** reversible —
  switching to hard-delete later is a straightforward behavior change, no data-shape migration
  required beyond dropping the soft-delete check.

**Token Count**

- **D-04:** A user can hold multiple concurrent, independently-revocable named tokens (e.g. one
  for a CI pipeline, one for a personal script) — not a single-token-per-user model. Requires a
  `name`/label field per token for identification in the token-management UI. — **Reversibility:**
  reversible — collapsing to single-token-per-user later is a UI/validation constraint change, not
  a data-model rewrite (the schema already supports multiple rows per user).

### Claude's Discretion

The following areas were surfaced as gray areas but not deep-dived; researcher/planner have
discretion to resolve them using existing codebase conventions and the locked decisions above as
constraints:

- **API route design & versioning** — exact URL prefix/blueprint structure (e.g. `/api/v1/...`),
  JSON response/error envelope shape, and pagination approach for the asset-list endpoint (API-02).
  Must be consistent with this project's existing blueprint-per-feature convention (Phase 1's
  `asset` blueprint, `auth_routes.py`, `org_routes.py`, etc.).
- **CLI distribution & authentication** — how the CLI tool (API-06) ships (installable
  console-script entry point vs. a single downloadable script) and how it authenticates locally
  (token in a config file vs. environment variable vs. CLI flag). Must accept a user-scoped token
  (per D-02) and use it exactly as the web UI's session would for authorization purposes.
- **Rate-limit & tier-gate consistency** — how API endpoints reuse Flask-Limiter and
  `entitlements.py` so token-authenticated access cannot bypass what the web UI and Phase 1's
  scheduler already enforce (API-05). Must mirror Phase 1's fire-time tier re-check pattern
  (`entitlements.effective_tier_for_org`/`allowed_checks`) — tier is checked fresh per request,
  never cached on the token.

**This research's resolution of those discretion areas** (see Architecture Patterns / Standard
Stack sections below for full rationale): `/api/v1/...` URL prefix on a new `api` blueprint,
`jsonify(error=...)`-style error envelope matching `public_routes.py`'s existing `healthz` JSON
pattern, no pagination for v1 (Asset counts are expected to stay small; flagged, not blocking); CLI
ships as a plain `click` script (not a pip console-script) authenticating via `--token` flag or
`WVS_API_TOKEN` env var; rate limiting reuses `extensions.limiter` keyed by token identity via a
custom `key_func`, falling back to IP pre-auth.

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope. No scope-creep suggestions came up during this
session; the three areas left to Claude's Discretion above are within-phase implementation
ambiguity, not new capabilities.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| API-01 | Org admin can generate and revoke API tokens scoped to their org, separate from session-cookie auth. | `ApiToken` model (D-01/D-04), hash-only generation/storage pattern (Pattern 1's `hashlib.sha256`/`secrets.token_urlsafe`), soft-revoke (`revoked_at`, D-03), `api_tokens_routes.py` HTML CRUD blueprint (Code Examples). **Note:** the literal "Org admin" phrasing in this requirement is in tension with D-02's user-scoped design — see Open Question 1 / Assumption A2. |
| API-02 | Authenticated API requests can list an org's Assets and each Asset's latest scan status/report summary. | Reuses `asset_routes._scoped_asset_query`'s org/solo scoping unchanged (D-02); `GET /assets` route sketch in Architecture Patterns / System Architecture Diagram. |
| API-03 | Authenticated API requests can trigger a new scan against an existing Asset, subject to the same authorization/SSRF/tier gating as the web UI. | 100% reuse of `scheduler._fire(asset)` (Pattern 3) — no new dispatch/SSRF/tier logic; `_check_asset_access` reused unchanged for ownership. |
| API-04 | Authenticated API requests can retrieve a completed scan's full report (findings, score) as structured JSON. | Reuses `scan_routes.scan_report`'s exact on-disk JSON read pattern, `jsonify(report)` instead of `render_template`; **requires the ownership-check fix in Pitfall 1** (`_check_asset_access(scan.asset)` instead of `_check_ownership(scan)` for Asset-linked Scans) for correct org-shared access. |
| API-05 | API endpoints are rate-limited and tier-gated consistent with existing entitlement rules — no API path that bypasses tier restrictions enforced elsewhere. | `extensions.limiter` reused with a token-identity `key_func` (Pattern 4); tier gating comes for free via `scheduler._fire`'s existing `entitlements.effective_tier_for_org` re-check (Pattern 3) — no separate tier-check code needed for API-03; API-02/04 are read-only and don't need tier gating beyond ownership. |
| API-06 | A CLI tool (thin wrapper over the API) lets a user authenticate, list assets, trigger a scan, and fetch a report from the command line. | `cli/wvs.py` using `click` + `requests` (already-installed, zero new footprint) as a pure HTTP client over `/api/v1/*` — see Recommended Project Structure and Standard Stack / Alternatives Considered. |
</phase_requirements>

## Summary

This phase adds a second, parallel authentication path (hash-only Bearer tokens) alongside the
existing Flask-Login session auth, then exposes a thin JSON surface over machinery Phase 1 already
built and proved (`Asset`, `scheduler._fire()`, `_check_asset_access`, `_check_ownership`,
`entitlements.effective_tier_for_org`, `is_ssrf_safe_hostname`), plus a CLI that is nothing more
than an HTTP client for that surface. Nothing here needs a new dependency for the hard part: Python's
stdlib `secrets`/`hashlib` handle token generation/hashing, and Flask-Login's own
`request_loader` hook (documented, first-class API) lets token-authenticated requests populate
`current_user` exactly like session auth does — so every existing `@login_required`,
`_check_asset_access`, `_check_ownership`, and `entitlements`-based tier check applies to a
token-authenticated request completely unchanged, which is exactly what CONTEXT.md's D-02 requires.

The highest-leverage reuse in this phase is `scheduler._fire(asset)` (Phase 1): it already does
everything API-03 needs — re-derive tier at fire time, re-check `is_ssrf_safe_hostname`, create a
`Scan` row, dispatch via `_spawn_scan_thread` — with zero new scan-dispatch logic required. The one
piece of genuine cross-cutting risk this research surfaced is that `_fire()` attributes the created
`Scan.user_id` to the *Asset's creator*, not the caller, which collides with `scan_routes.
_check_ownership`'s creator-or-org-admin-only rule when a non-admin org member (via their own API
token) triggers or fetches the report for an org-shared Asset's scan — see Pitfall 1, this is a
pre-existing Phase 1 gap this phase's API-04 will otherwise inherit, not a new one it introduces.

**Primary recommendation:** New `ApiToken` model (FK to `User`, `token_hash` unique-indexed,
`name`, `revoked_at`) verified via `secrets.token_urlsafe(32)` + `hashlib.sha256(...).hexdigest()`
hash-lookup, wired into Flask-Login via `login_manager.request_loader`. Two new blueprints —
`api_tokens_routes.py` (session-authenticated HTML CRUD, API-01) and `api_routes.py`
(token-authenticated JSON under `/api/v1`, API-02..05) — plus a standalone `cli/wvs.py` `click`
script (API-06) that is a pure HTTP client over `/api/v1`, no Flask import at all.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Token generation/storage/revocation | API / Backend | Database / Storage | New `ApiToken` model + `api_tokens_routes.py`; hash lookup is a DB-indexed query, no separate service |
| Token-management web UI | Frontend Server (SSR) | — | Session-authenticated Jinja2 page, same pattern as `asset_new.html`/`assets.html` |
| Token verification per request | API / Backend | — | `login_manager.request_loader`, evaluated fresh every request, never cached |
| Asset listing / latest-scan status (API-02) | API / Backend | Database / Storage | Read-only query reuse of `Asset`/`Scan` models, same scoping as `asset_routes._scoped_asset_query` |
| Scan triggering (API-03) | API / Backend | — | Delegates entirely to `scheduler._fire(asset)` — no new orchestration logic |
| Report retrieval (API-04) | API / Backend | Database / Storage (`reports/` on-disk JSON) | Reuses `scan_routes.scan_report`'s exact file-read pattern, JSON instead of HTML |
| Rate limiting / tier gating (API-05) | API / Backend | — | Existing `extensions.limiter` + `entitlements.py`, no new mechanism |
| CLI (API-06) | Client (out-of-process) | — | Pure HTTP client; talks only to the API tier, never touches Flask/DB/models directly |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `secrets` (stdlib) | Python 3.12 | Cryptographically-secure random token generation | Stdlib, zero dependency risk; `secrets.token_urlsafe(n)` is the documented, recommended way to generate security tokens in Python [CITED: docs.python.org/3/library/secrets.html] |
| `hashlib` (stdlib) | Python 3.12 | SHA-256 hashing of the raw token before storage | Token is already 256 bits of high-entropy randomness (not a human password) — a fast cryptographic hash (SHA-256) is the correct tool, not a slow password-hash (bcrypt/PBKDF2/scrypt), which exists specifically to slow down brute-forcing *low-entropy* human passwords. Applying `werkzeug.security.generate_password_hash` to a 256-bit random token would be the wrong tool for the job and pure overhead. [ASSUMED — general, well-established security-engineering practice; not verified against a single authoritative source this session] |
| Flask-Login `request_loader` | 0.6.3 (installed) | Populates `current_user` for Bearer-token requests without touching the session cookie | Official, documented Flask-Login mechanism for exactly this "login via header/API key, no cookie" case [CITED: flask-login.readthedocs.io/en/0.6.3/] |
| `click` | 8.4.2 (already installed, transitive via Flask) | CLI argument/subcommand framework for `cli/wvs.py` | Already resolves in this project's venv (Flask's own `flask` CLI is click-based) — adding it to `requirements.txt` explicitly costs nothing new to install and gives declarative subcommands/options instead of hand-rolled `argparse` parsing for 4+ commands (`login`, `assets list`, `scan start`, `report get`) [VERIFIED: pip show click in project venv → 8.4.2; PyPI registry confirms `click` is the official Pallets project, github.com/pallets/click] |
| `requests` | 2.34.2 (already installed, direct dependency) | HTTP client the CLI uses to call `/api/v1/*` | Already in `requirements.txt` for `checks.py`/`billing.py`/`email_stub.py` — zero new dependency for the CLI's HTTP layer [VERIFIED: requirements.txt:2; pip show requests → 2.34.2] |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| Flask-Limiter (existing) | 4.1.1 (installed) | Rate-limit `/api/v1/*` routes, keyed by token identity instead of IP | `@limiter.limit(..., key_func=...)` per-route override — official recipe pattern [CITED: flask-limiter.readthedocs.io/en/stable/recipes.html] |
| Flask-WTF `flask_wtf.csrf` (existing) | installed | CSRF protection on the token-management HTML forms only | `api_tokens_routes.py`'s create/revoke forms are session-authenticated HTML POSTs — same CSRF requirement as every other form in the app. The JSON `/api/v1/*` routes do **not** need CSRF (no cookie-based session state is being changed by them; CSRF exists to protect cookie-authenticated state changes, and token auth is not cookie-based) |
| Alembic / Flask-Migrate (existing) | 4.1.0 (installed) | `ApiToken` table migration | Same `flask db migrate` → hand-review → `flask db upgrade` flow Phase 1 already used for `assets` |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| stdlib `secrets`+`hashlib` hash-lookup tokens | Flask-HTTPAuth's `HTTPTokenAuth` | Adds a new dependency for what's ~15 lines of stdlib code; also doesn't natively support this project's hash-only-storage + soft-revocation model (D-01/D-03) without the same custom lookup function underneath anyway — no real leverage gained |
| stdlib `secrets`+`hashlib` hash-lookup tokens | `itsdangerous`'s `URLSafeTimedSerializer` (already used in `org_routes.py` for invite links) | Signed tokens are self-contained (decodable, not opaque) and stateless by design — revocation would require a separate server-side blocklist anyway, defeating the point of using a stateless signer. D-01 ("hash-only... looked up via an indexed hash-column query") and D-03 (soft-revocation via a DB row) both assume a DB-row-per-token model from the start, which a signed/stateless token doesn't naturally give you. Not a fit for this phase's locked decisions. |
| `click`-based CLI | stdlib `argparse` + `requests` | Zero new footprint (argparse is stdlib) but noticeably more boilerplate for subcommands (`assets list`, `scan start`, `report get`) — since `click` already resolves in this venv via Flask, there's no real dependency-count benefit to argparse here |
| Pip-installable console-script (`entry_points` in `pyproject.toml`) | Plain executable script (`python cli/wvs.py ...`) | This repo has **no** `pyproject.toml`/`setup.py` today (confirmed via `STRUCTURE.md`/`STACK.md` — packaging is `requirements.txt`-only). A console-script entry point would require introducing packaging infrastructure this project has never needed, just for phase 2's CLI. Recommend a plain script for v1; console-script distribution can be added later without touching any of the CLI's actual logic. |

**Installation:**
```bash
# click is already resolved transitively via Flask - add it explicitly since
# cli/wvs.py imports it directly (not just an implicit sub-dependency anymore)
echo "click" >> requirements.txt
```
No other new packages are required — `requests`, Flask-Login, Flask-Limiter, Flask-Migrate are all
already direct dependencies.

**Version verification:** Verified live against this project's own virtualenv
(`C:\Users\Arktech_Designs\Documents\Glassbox\.venv`), not just training-data versions:
```
Flask-Login    0.6.3
Flask-Limiter  4.1.1
Flask-SQLAlchemy 3.1.1
Flask-Migrate  4.1.0
click          8.4.2
requests       2.34.2
```
[VERIFIED: `pip show` output, this session, against the project's own venv — see command output above]

## Package Legitimacy Audit

Only one new line is being added to `requirements.txt` this phase (`click`); everything else this
phase uses is already an installed, direct or transitive dependency of this project.

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|-------------|---------|-------------|
| `click` | PyPI | 15+ years (Pallets project, first released 2014) | Very high (Flask's own CLI dependency; effectively pulled in by every Flask install) | github.com/pallets/click | OK | Approved — already installed transitively via Flask, confirmed present in this project's venv at 8.4.2, official Pallets/Flask-family project |

**Packages removed due to [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

No new runtime dependency is introduced beyond `click`, which is a first-party Pallets (Flask's own
maintainers) package already resident in this project's dependency tree — no `npm view`/`pip index
versions` legitimacy gate was needed beyond the `pip show`/PyPI registry check already performed
above, since this is not a new, unvetted package being pulled in cold.

## Architecture Patterns

### System Architecture Diagram

```text
                    ┌─────────────────────────────┐
                    │   Browser (session cookie)   │
                    └──────────────┬────────────────┘
                                   │ POST /tokens/new, /tokens/<id>/revoke
                                   ▼
                    ┌─────────────────────────────────────┐
                    │ api_tokens_routes.py (Blueprint      │
                    │ "api_tokens", url_prefix "/tokens")  │
                    │ @login_required (session auth only)  │
                    └──────────────┬────────────────────────┘
                                   │ generates secrets.token_urlsafe(32),
                                   │ stores sha256 hash only, shows raw
                                   │ token once
                                   ▼
                    ┌─────────────────────────────────────┐
                    │      ApiToken table (Postgres/       │
                    │      SQLite) — token_hash indexed,    │
                    │      revoked_at nullable              │
                    └──────────────▲────────────────────────┘
                                   │ hash-lookup, revoked_at IS NULL
                                   │
   ┌───────────────┐   Authorization: Bearer <token>   ┌───────────────────────────┐
   │ CLI (cli/wvs.py│──────────────────────────────────▶│ login_manager.request_    │
   │ requests+click)│                                    │ loader (extensions.py)    │
   └───────────────┘                                    └──────────────┬─────────────┘
                                                                        │ sets current_user
                                                                        │ for THIS request only
                                                                        │ (no session cookie set)
                                                                        ▼
                                              ┌───────────────────────────────────────────┐
                                              │ api_routes.py (Blueprint "api",             │
                                              │ url_prefix "/api/v1")                       │
                                              │ - GET  /assets                              │
                                              │ - GET  /assets/<id>                         │
                                              │ - POST /assets/<id>/scans   (API-03)        │
                                              │ - GET  /scans/<id>/report   (API-04)        │
                                              │ each route reuses:                          │
                                              │  _check_asset_access / _check_ownership     │
                                              │  entitlements.effective_tier_for_org        │
                                              │  is_ssrf_safe_hostname (via scheduler._fire)│
                                              └──────────────┬───────────────────────────────┘
                                                             │ POST /assets/<id>/scans calls
                                                             ▼
                                              ┌───────────────────────────────────────────┐
                                              │  scheduler._fire(asset)  [Phase 1, reused   │
                                              │  UNCHANGED] - re-checks SSRF + tier fresh,  │
                                              │  creates Scan row, calls                    │
                                              │  scan_routes._spawn_scan_thread()           │
                                              └───────────────────────────────────────────┘
```

### Recommended Project Structure
```
glassbox/
├── api_tokens_routes.py   # NEW - Blueprint "api_tokens": session-auth HTML CRUD (API-01)
├── api_routes.py          # NEW - Blueprint "api": token-auth JSON /api/v1/* (API-02..05)
├── extensions.py          # MODIFIED - add login_manager.request_loader
├── models.py              # MODIFIED - add ApiToken model
├── scheduler.py           # MODIFIED (small) - _fire() returns the created Scan row
templates/
├── api_tokens.html        # NEW - token list + create form, dashboard.html table conventions
migrations/versions/
├── <hash>_add_api_tokens_table.py   # NEW - op.create_table('api_tokens', ...)
cli/                        # NEW top-level package, sibling to glassbox/
├── __init__.py
├── wvs.py                  # click entrypoint: login, assets list, scan start, report get
tests/
├── test_api_tokens_routes.py   # NEW
├── test_api_routes.py          # NEW
├── test_cli.py                  # NEW (mocks requests, tests command parsing/output)
```

### Pattern 1: Token verification via Flask-Login `request_loader`
**What:** Register a `login_manager.request_loader` callback that inspects the `Authorization`
header, hashes the presented token, looks it up, and returns the owning `User` — exactly the same
mechanism Flask-Login already uses for session auth (`user_loader`), just triggered from the
request instead of the session cookie.
**When to use:** Every request to `/api/v1/*`. Because `request_loader` is checked by Flask-Login's
own `_load_user()` whenever there's no valid session, `current_user` and `@login_required` continue
to work exactly as they do today across the *entire* app — no parallel `g.current_api_user`
variable, no forked authorization logic.
**Example:**
```python
# Source: flask-login.readthedocs.io/en/0.6.3/ (Request Loader Example) - adapted to this
# project's hash-lookup token model. Add to glassbox/extensions.py, near
# the existing @login_manager.user_loader.
import hashlib

@login_manager.request_loader
def load_user_from_request(request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    raw_token = auth_header[len("Bearer "):].strip()
    if not raw_token:
        return None

    from glassbox.models import ApiToken

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    row = ApiToken.query.filter_by(token_hash=token_hash, revoked_at=None).first()
    if row is None:
        return None
    return row.user
```
**Session-cookie caveat (important):** Flask-Login's own docs flag that `request_loader`-based auth
should typically NOT set a session cookie on the response (an API client shouldn't get a
`Set-Cookie` header back) — the documented fix is a custom `SessionInterface` that skips saving the
session when a flag (e.g. `g.login_via_request`) is set. [CITED: flask-login.readthedocs.io/en/0.6.3/
— "Disabling Session Cookie for APIs"] This should be applied specifically to `/api/v1/*` responses.

### Pattern 2: API routes get a dedicated 401 responder, not `@login_required`'s redirect
**What:** Flask-Login's `@login_required` calls `login_manager.unauthorized()` on failure, whose
default behavior is an HTML redirect to `login_view` ("auth.login") — correct for browser routes,
wrong for a JSON API (a CLI/script hitting an expired token should get `401` + JSON body, not a 302
to a login page).
**When to use:** Every route in `api_routes.py`.
**Example:**
```python
# glassbox/api_routes.py
from functools import wraps
from flask import Blueprint, current_app, g, jsonify, request
from flask_login import current_user

api = Blueprint("api", __name__, url_prefix="/api/v1")


def api_login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify(error="missing or invalid API token"), 401
        return view_func(*args, **kwargs)
    return wrapped
```
This keeps `@login_required`'s browser-redirect behavior untouched everywhere else in the app while
giving `/api/v1/*` its own JSON-appropriate failure mode — `current_user.is_authenticated` reflects
whichever loader (session OR `request_loader`) actually succeeded, so this decorator works
identically for a browser-with-cookie hitting the API by accident and a CLI with a Bearer token.

### Pattern 3: Reuse `scheduler._fire()` for on-demand (API-triggered) scans
**What:** API-03 ("trigger a new scan against an existing Asset") is *exactly* what
`scheduler._fire(asset)` (Phase 1, `glassbox/scheduler.py:70-124`) already does — re-derive
tier fresh, re-check SSRF fresh, create the `Scan` row, dispatch via `_spawn_scan_thread`. The only
gap: `_fire()` currently returns `None`; the API route needs the created `Scan`'s id/status to
respond with. Recommend a **minimal, backward-compatible** change: have `_fire()` `return s` (or
the FAILED-scan row) on every branch. `_tick()` (Phase 1's only existing caller) already ignores the
return value, so this doesn't change any existing behavior.
**When to use:** `POST /api/v1/assets/<id>/scans`.
**Example:**
```python
# glassbox/api_routes.py
from glassbox.asset_routes import _check_asset_access
from glassbox.models import Asset
from glassbox.scheduler import _fire

@api.route("/assets/<int:asset_id>/scans", methods=["POST"])
@api_login_required
def trigger_scan(asset_id):
    a = Asset.query.get_or_404(asset_id)
    _check_asset_access(a)  # same 404-not-403 ownership check the web UI uses, unchanged
    s = _fire(a)  # re-checks SSRF + tier fresh; never trusts anything cached on the token
    return jsonify(scan_id=s.id, status=s.status.value), 202
```
No new scan-dispatch, SSRF-check, or tier-check code is written for API-03 — it is 100% reuse.

### Pattern 4: Rate-limit `/api/v1/*` by token identity, falling back to IP pre-auth
**What:** The existing `extensions.limiter` singleton is reused (per CONTEXT.md's discretion note
— "should register limits through it rather than introducing a second rate-limiting mechanism"),
but keyed by the authenticated user's id (derived from the token) rather than `get_remote_address`
— matching Flask-Limiter's own official per-user recipe, adapted from session `current_user` to
this project's token-populated `current_user`.
**Example:**
```python
# Source: flask-limiter.readthedocs.io/en/stable/recipes.html (per-user key_func recipe,
# `key_func=lambda: current_user.username`) - adapted: fall back to remote address before
# auth succeeds, so an attacker can't dodge rate limiting entirely by omitting/mangling a token.
from flask_limiter.util import get_remote_address
from flask_login import current_user

def _api_rate_limit_key():
    if current_user.is_authenticated:
        return f"user:{current_user.id}"
    return get_remote_address()

@api.route("/assets")
@api_login_required
@limiter.limit("60 per minute", key_func=_api_rate_limit_key)
def list_assets():
    ...
```
This is consistent with, not a fix for, the existing documented gap: Flask-Limiter's in-memory
storage is still not multi-worker-safe (CONCERNS.md, HARD-01/Phase 4). This phase should not attempt
to fix that — just apply the same limiter singleton and pattern the rest of the app already uses.

### Anti-Patterns to Avoid
- **Don't build a parallel `g.current_api_user` / a second ownership-check codepath for API
  routes.** `login_manager.request_loader` makes `current_user` work identically for session and
  token auth — every existing `_check_asset_access`/`_check_ownership`/`entitlements.*` call reused
  unchanged is a direct requirement of D-02, not just a nice-to-have.
- **Don't hash the raw token with a slow password hash (bcrypt/PBKDF2/scrypt/`werkzeug.security.
  generate_password_hash`).** The token is already a 256-bit random secret; a fast SHA-256 hash is
  correct and a slow hash only adds unnecessary per-request CPU cost with no security benefit for
  an already-high-entropy secret.
- **Don't use `itsdangerous`'s stateless signed tokens for this scheme.** D-03's soft-revocation
  requires a real DB row per token to flip `revoked_at` on — a stateless signed token has nothing to
  revoke without a separate blocklist, which just re-adds the DB-row requirement through the back
  door while losing the simplicity D-01 was asking for.
- **Don't gate `/api/v1/*` behind `@login_required`+redirect.** Use a dedicated JSON-401
  `api_login_required` decorator (Pattern 2) so CLI/script callers get a parseable error, not an
  HTML login page.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Token generation | A custom random-string generator | `secrets.token_urlsafe(32)` | Stdlib, cryptographically secure by design, already the pattern this codebase uses elsewhere (`auth_routes.py`'s `verify_token`, `org_routes.py`'s domain-verification token) |
| Constant-time comparison concerns | Manual timing-safe compare loop | A DB-indexed equality lookup on the SHA-256 hash (not a raw-secret Python `==`) — this is the same approach GitHub/Stripe/Django REST Framework use for API-token hashing; `hmac.compare_digest` is only strictly necessary if you fetch a candidate row by prefix and then compare a full secret in application code, which D-01's "no prefix-split scheme" design deliberately avoids | Avoids an entirely separate class of bug (a hand-rolled timing-safe compare that isn't actually timing-safe) for a problem the DB-index-on-a-hash design already sidesteps |
| Scan dispatch/SSRF-recheck/tier-recheck for API-triggered scans | A parallel "APITriggeredScan" orchestration path | `scheduler._fire(asset)` (Phase 1, unchanged except a `return` statement) | Exactly the re-derive-everything-at-fire-time logic API-03 needs already exists, tested, and proven in Phase 1 (12 scheduler tests) |
| Session/token dual authentication | A custom "check session OR check header" decorator duplicated on every route | `login_manager.request_loader` (Flask-Login's own documented mechanism) | Keeps exactly one source of truth for "who is `current_user`" across the whole app, session or token alike |
| CLI subcommand parsing | Hand-rolled `sys.argv` parsing or bare `argparse` boilerplate for 4+ subcommands with options | `click` (already resolved via Flask, add explicitly to `requirements.txt`) | Declarative `@click.group()`/`@click.command()`/`@click.option()` — the same framework Flask's own CLI uses, no new install footprint |

**Key insight:** This phase's biggest risk isn't missing library knowledge — every hard problem
(secure token generation, constant-time-safe verification, dual-auth `current_user`, SSRF/tier
re-checking) already has either a stdlib answer or an existing, tested Phase 1 function. The real
risk is *not reusing* what's already there and accidentally building a second, subtly different
authorization surface for API routes than the one the web UI already trusts.

## Common Pitfalls

### Pitfall 1: `scan_routes._check_ownership` and Asset-scoped Scan visibility disagree
**What goes wrong:** Any `Scan` created via `scheduler._fire()` (both the existing scheduler tick
path AND this phase's new API-03 trigger path) sets `Scan.user_id = asset.created_by_user_id` —
the Asset's *original creator*, not whoever caused this particular fire. But
`scan_routes._check_ownership(s)` only grants access to `s.user_id == current_user.id` OR an
`ORG_ADMIN` of `s.org_id`. So a **non-admin** org member who can see and trigger a scan on a
shared Asset (per `asset_routes._check_asset_access`'s org-shared model — "every org member sees
the org's Assets, not just admins") will get a 404 from `_check_ownership` when trying to view the
report of the very scan they just triggered, unless they happen to be the Asset's original creator
or an ORG_ADMIN.
**Why it happens:** This is a **pre-existing Phase 1 gap**, not new to this phase —
`templates/asset_detail.html` already links its scan-history rows to `scan.scan_detail`/
`scan.scan_report` (both `_check_ownership`-gated) for scheduler-fired scans, so the same 404 can
already happen today for a non-admin, non-creating org member viewing an Asset's own scan history
page. This phase's API-03 (trigger) + API-04 (fetch report) exercises the identical surface via a
new access path (API tokens), so it will silently inherit the bug unless addressed.
**How to avoid:** For any `Scan` with `asset_id IS NOT NULL`, check ownership via
`_check_asset_access(scan.asset)` (org-shared, matching how the Asset itself is scoped) instead of
`_check_ownership(scan)` (creator-or-admin-only). This is in-scope for API-04's new route at
minimum; whether to also patch the existing web-UI `/scan/<id>` and `/scan/<id>/report` routes for
consistency is a call for the planner/user — flagging it here so it isn't rediscovered as a
"regression" during verification.
**Warning signs:** A test where User B (non-admin, same org, did NOT create the Asset) triggers a
scan via their own token and then can't fetch its report — confirms this exact gap.

### Pitfall 2: `request_loader` firing on every request, including ones with no auth intent
**What goes wrong:** `login_manager.request_loader` is checked by Flask-Login on **every** request
where there's no session-authenticated user — including plain web-UI page loads by an anonymous
visitor. If the callback does a DB query unconditionally (rather than short-circuiting when there's
no `Authorization: Bearer` header at all), every anonymous page view pays an extra DB round trip.
**Why it happens:** Easy to write the callback assuming it only ever runs for API requests.
**How to avoid:** Return `None` immediately if `Authorization` header is absent or doesn't start
with `"Bearer "` — see Pattern 1's example, which does this before touching the DB.
**Warning signs:** Slower-than-expected page loads on public/marketing routes after this change
ships; a query-count assertion in tests catching an unexpected extra `SELECT` on anonymous requests.

### Pitfall 3: SQLite batch-mode migration pitfall from Phase 1 does NOT apply to a brand-new table
**What goes wrong:** Phase 1's migration needed `with op.batch_alter_table(...)` specifically
because it ALTERed the existing `scans` table (added a column + FK) on SQLite, which requires
batch mode. A brand-new `ApiToken` table is a plain `op.create_table(...)` with an inline
`sa.ForeignKeyConstraint` — batch mode is not needed for table creation, only for altering an
existing table.
**Why it happens:** Copy-pasting Phase 1's migration pattern wholesale (including batch-mode
wrapping) for a `CREATE TABLE` that doesn't need it — harmless but unnecessary, and easy to get the
constraint-naming requirement (Phase 1's Pitfall 2, "Constraint must have a name" under SQLite batch
mode) confused with plain `op.create_table`, which does NOT require an explicit constraint name.
**How to avoid:** Model the new migration directly on the `op.create_table('assets', ...)` block of
`migrations/versions/672a304d4921_add_assets_table_and_scans_asset_id.py` (lines 21-41) — no
`batch_alter_table` wrapper needed for the table itself; only wrap in batch mode if this migration
*also* alters an existing table (it shouldn't need to for `ApiToken`).
**Warning signs:** An autogenerated migration wrapping the whole `create_table` in
`batch_alter_table` unnecessarily — hand-review (per this project's own migration convention) and
simplify.

### Pitfall 4: Token shown once — don't let SQLAlchemy's default `repr`/logging leak it
**What goes wrong:** The raw token only exists in memory for the single request that creates it
(D-01: "no plaintext secret is ever stored or logged"). If `ApiToken.__repr__` includes the raw
token, or if the create-route's flash message/redirect accidentally re-fetches and displays a
*stored* value instead of the in-memory raw string generated at creation time, or if Sentry/logging
captures the request body/response on that route, the "shown exactly once" guarantee breaks.
**Why it happens:** Easy to structure the create-route as "save row → flash message referencing
`token.value`" if a raw-value column exists even temporarily on the model instance.
**How to avoid:** Never add a raw-token column to `ApiToken` at all (only `token_hash` should exist
in the schema) — generate the raw string in the view function, hash it for storage, and pass the
*local variable* (never a model attribute) to the template for the one-time display. Exclude the
token-creation route from any request/response body logging (Sentry's default Flask integration
does not log request bodies by default, but verify before enabling any additional logging
middleware on this route).
**Warning signs:** Any `ApiToken.__repr__`/`__str__` override that includes anything other than
`id`/`name`/`created_at`/`revoked_at`.

## Code Examples

### `ApiToken` model
```python
# Source: modeled directly on glassbox/models.py's Asset class (soft-delete → soft-revoke
# convention) and PasswordReset/DomainVerification's token-column precedent - verbatim column
# types drawn from glassbox/models.py:103-135 (PasswordReset/DomainVerification), read this
# session.
class ApiToken(db.Model):
    """A user-scoped, hash-only API token (Phase 2, API-01/D-01..D-04). Acts as the exact user
    who created it - no independent authorization model, see entitlements.py/asset_routes.py's
    existing checks, all reused unchanged for token-authenticated requests via
    login_manager.request_loader (extensions.py)."""
    __tablename__ = "api_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String(255), nullable=False)  # D-04: user-facing label, e.g. "CI pipeline"
    token_hash = db.Column(db.String(64), unique=True, nullable=False)  # sha256 hexdigest, D-01
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)
    last_used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    # NULL = active. Soft-revoke only (D-03), mirrors Asset.deleted_at's convention exactly.
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    user = db.relationship("User")
```
Note: `token_hash` needs a unique index for the request_loader's lookup to be an index scan, not a
table scan — either `unique=True` (creates one implicitly on most backends) or an explicit
`db.Index("ix_api_tokens_token_hash", "token_hash")` in `__table_args__`, matching the explicit-index
style Phase 1's `Asset` model already uses for `next_run_at`/`org_id`+`deleted_at`.

### Token creation route (API-01, web UI)
```python
# glassbox/api_tokens_routes.py - follows asset_routes.py's structure/docstring
# conventions (blueprint at module top, ownership helper, one route per action).
import hashlib
import secrets
from datetime import datetime, timezone

from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from glassbox.extensions import db
from glassbox.models import ApiToken

api_tokens = Blueprint("api_tokens", __name__, url_prefix="/tokens")


@api_tokens.route("", methods=["GET"])
@login_required
def list_tokens():
    tokens = (
        ApiToken.query.filter_by(user_id=current_user.id)
        .order_by(ApiToken.created_at.desc())
        .all()
    )
    return render_template("api_tokens.html", tokens=tokens)


@api_tokens.route("/new", methods=["POST"])
@login_required
def create_token():
    name = request.form.get("name", "").strip()
    if not name:
        return render_template(
            "api_tokens.html",
            tokens=ApiToken.query.filter_by(user_id=current_user.id).all(),
            error="Enter a name for this token.",
        )
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    t = ApiToken(user_id=current_user.id, name=name, token_hash=token_hash)
    db.session.add(t)
    db.session.commit()
    # raw_token is a LOCAL VARIABLE, never persisted or re-derivable - shown exactly once.
    return render_template(
        "api_tokens.html",
        tokens=ApiToken.query.filter_by(user_id=current_user.id).all(),
        new_token_value=raw_token,
        new_token_name=name,
    )


@api_tokens.route("/<int:token_id>/revoke", methods=["POST"])
@login_required
def revoke_token(token_id):
    t = ApiToken.query.get_or_404(token_id)
    if t.user_id != current_user.id:
        from flask import abort
        abort(404)  # same 404-not-403 convention as _check_asset_access/_check_ownership
    t.revoked_at = datetime.now(timezone.utc)
    db.session.commit()
    return redirect(url_for("api_tokens.list_tokens"))
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| N/A — this is new capability for this codebase, not a replacement of an existing pattern | Hash-only, revocable, user-scoped Bearer tokens verified via `login_manager.request_loader` | This phase | Adds a second first-class authentication path without touching the existing session-auth code at all |

**Deprecated/outdated:** None — this is greenfield within the app, no prior API-auth scheme to
migrate away from.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Use SHA-256 (fast hash), not a slow password-hash function, for token verification | Standard Stack / Anti-Patterns | Low if wrong in the "too slow" direction (extra CPU per request only); the actual security requirement — token unguessability — comes from the 256-bit `secrets.token_urlsafe` generation, not the hash algorithm choice, so this is a performance/convention concern, not a security hole either way |
| A2 | "Who may create/revoke a token" is self-service (any authenticated user manages their own tokens), not restricted to `Role.ORG_ADMIN` | Architecture Patterns / Don't Hand-Roll | REQUIREMENTS.md's literal API-01 text says "Org admin can generate and revoke API tokens" but CONTEXT.md's locked D-02 says a token "acts as the specific user who created it" with no mention of a creation-authority restriction — these two statements are in tension. If the intended behavior is admin-only token issuance, `api_tokens_routes.py`'s routes need `@org_admin_required` added (one-line decorator addition, low cost) rather than self-service `@login_required` alone. **Recommend the planner confirm this explicitly before implementation** — this was surfaced but not resolved in `/gsd-discuss-phase`'s session (see CONTEXT.md's "Claude's Discretion" list, which does not cover token-creation authority). |
| A3 | CLI ships as a plain script (`cli/wvs.py`, no `pyproject.toml` console-script entry point) | Standard Stack — Alternatives Considered | Low — this is purely a packaging/distribution choice, reversible later without touching CLI logic; if the user actually wants `pip install -e .` + a `wvs` command on `$PATH`, that's an additive change, not a rewrite |
| A4 | Pitfall 1's `_check_ownership`/`_check_asset_access` mismatch should be fixed at least for the new API-04 route, and optionally for the pre-existing web-UI routes too | Common Pitfalls | Medium — if left unaddressed, API-04 will 404 for legitimate org members trying to fetch a report for a scan they triggered via their own token, on an Asset they didn't personally create; this directly undermines API-03/04's success criteria for any org with more than one member |

**If this table is empty:** N/A — see entries above; A2 in particular should be resolved (or
explicitly deferred with a documented default) before planning finalizes the token-management
route's access control.

## Open Questions

1. **Who is authorized to create/revoke an API token — any user, or only `Role.ORG_ADMIN`?**
   - What we know: D-02 defines what a token *does* once it exists (acts as its creating user);
     REQUIREMENTS.md's API-01 text says "Org admin can generate and revoke..."; CONTEXT.md's
     Claude's Discretion list does not cover this specific question.
   - What's unclear: Whether "Org admin" in API-01's phrasing was intentional access-control
     language or just loose product-copy shorthand for "an authorized user of the org."
   - Recommendation: Default to self-service (any authenticated user manages only their own
     tokens) as the interpretation most consistent with D-02's "acts as the specific user" framing,
     since a token issued by an org admin "for the org" would still, per D-02, only ever act as
     that specific admin — there's no meaningful difference in authorization semantics either way,
     only in *who is allowed to click the button*. Flag this default to the user during planning
     rather than silently deciding it.

2. **Should `_check_ownership`/`_check_asset_access` be reconciled for Asset-linked Scans app-wide,
   or only for this phase's new API-04 route?**
   - What we know: The mismatch (Pitfall 1) is real and pre-existing in the web UI already.
   - What's unclear: Whether fixing the web-UI routes too is in-scope for this phase (it wasn't
     asked for) or should be filed as a separate, tracked gap.
   - Recommendation: Fix it for API-04's new route (required for API-03/04 to actually work for
     non-admin org members); file the pre-existing web-UI instance as a noted gap for the user to
     decide on, rather than silently expanding this phase's scope to "fix" `scan_routes.py`.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.12 | Everything | ✓ | 3.12 (per `render.yaml`/`STACK.md`) | — |
| `click` | CLI (API-06) | ✓ (transitive via Flask, needs explicit `requirements.txt` line) | 8.4.2 | — |
| `requests` | CLI (API-06) | ✓ (direct dependency already) | 2.34.2 | — |
| Flask-Login `request_loader` support | Token auth (API-01..05) | ✓ | 0.6.3 (well above the version that introduced `request_loader`) | — |
| Flask-Limiter custom `key_func` support | Rate limiting (API-05) | ✓ | 4.1.1 | — |
| Alembic / Flask-Migrate | `ApiToken` migration | ✓ | 4.1.0 | — |

**Missing dependencies with no fallback:** none.
**Missing dependencies with fallback:** none — everything this phase needs is already present in
the project's dependency tree; only one new `requirements.txt` line (`click`, already resolved
transitively) is needed.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest (per `pytest.ini`, `testpaths = tests`) |
| Config file | `pytest.ini` (repo root) |
| Quick run command | `pytest tests/test_api_tokens_routes.py tests/test_api_routes.py -x` |
| Full suite command | `pytest` (172 tests as of end of Phase 1, per `01-02-SUMMARY.md`) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| API-01 | User generates a token, sees the raw value exactly once, list shows only hash-derived metadata; revoke sets `revoked_at` and immediately fails auth | integration | `pytest tests/test_api_tokens_routes.py -x` | ❌ Wave 0 |
| API-02 | `GET /api/v1/assets` lists only the caller's org/solo-scoped Assets + each one's latest Scan status, same scoping as `_scoped_asset_query` | integration | `pytest tests/test_api_routes.py::test_list_assets_scoped -x` | ❌ Wave 0 |
| API-03 | `POST /api/v1/assets/<id>/scans` creates a `Scan` via `scheduler._fire`, re-checks SSRF/tier fresh, 404s for a non-owning org (token holder) | integration | `pytest tests/test_api_routes.py::test_trigger_scan -x` | ❌ Wave 0 |
| API-04 | `GET /api/v1/scans/<id>/report` returns the same JSON `scan_engine.save_report()` wrote, 404s for a non-owning caller (per Pitfall 1's fix) | integration | `pytest tests/test_api_routes.py::test_fetch_report -x` | ❌ Wave 0 |
| API-05 | A revoked/invalid token gets 401 not 500; a Free-tier token triggering a `media`/`api` scan gets the same tier-gate failure the scheduler already produces; rate limit returns 429 past threshold | integration | `pytest tests/test_api_routes.py::test_tier_gating_and_rate_limit -x` | ❌ Wave 0 |
| API-06 | CLI `login`/`assets list`/`scan start`/`report get` commands call the right endpoint and format output correctly, against a mocked/local API server | unit (mocked HTTP) | `pytest tests/test_cli.py -x` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** targeted `pytest tests/test_api_tokens_routes.py tests/test_api_routes.py tests/test_cli.py -x`
- **Per wave merge:** full `pytest`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `tests/test_api_tokens_routes.py` — covers API-01
- [ ] `tests/test_api_routes.py` — covers API-02, API-03, API-04, API-05
- [ ] `tests/test_cli.py` — covers API-06 (mock `requests` calls; no live Flask server needed)
- [ ] `tests/conftest.py` extension: a `make_api_token(user, name="test", revoked=False)` factory,
      mirroring the existing `make_asset`/`make_scan`/`make_user` helpers exactly — returns both the
      `ApiToken` row and the raw token string (generated inline, matching the real create-route's
      shape) so tests can authenticate as `Authorization: Bearer <raw>` without going through the
      HTML create-route first
- [ ] Framework install: none — pytest is already configured; no new test framework needed

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | Hash-only stored secrets (SHA-256 of a `secrets.token_urlsafe(32)` value), never plaintext, never logged — matches ASVS V2 token-storage guidance in spirit (store a verifier, not the credential) |
| V3 Session Management | yes (partial) | Token auth is deliberately **not** session-based — `request_loader` must not set a session cookie for token-authenticated requests (Pattern 1's caveat) |
| V4 Access Control | yes | Every existing ownership/tier check (`_check_asset_access`, `_check_ownership`, `entitlements.effective_tier_for_org`) reused unchanged per D-02 — no new authorization model introduced |
| V5 Input Validation | yes | `Authorization` header format validated (`Bearer <token>` prefix check) before any DB query; existing form validation patterns (`asset_routes.py`'s `name`/`cadence`/`schedule_scan_type` allow-lists) apply unchanged to token-management forms |
| V6 Cryptography | yes | `secrets.token_urlsafe` (CSPRNG-backed) for generation, `hashlib.sha256` for storage-hash — never hand-roll a random generator or hash function |
| V13 API and Web Service | yes | Rate limiting + tier gating (API-05) directly maps to ASVS V13's "verify that authorization is enforced at the API layer, not just the UI" — this phase's entire point is proving that |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Token leaked via logs/error pages | Information Disclosure | Never store/log the raw token past the single create-request (Pitfall 4); exclude the create-token route from any verbose request-body logging |
| Token replay after revocation | Elevation of Privilege | `request_loader`'s lookup filters `revoked_at IS NULL` on every single request — never cached, matches Phase 1's "re-check at fire time, never cached from registration" convention exactly |
| Cross-org data leak via a token (org-scoped tokens acting beyond their creator) | Elevation of Privilege | D-02 explicitly forbids this by design — a token can never see/do more than its creating user's session already could, since `current_user` resolves identically either way |
| Brute-forcing token values | Elevation of Privilege | 256 bits of `secrets.token_urlsafe` entropy makes brute force computationally infeasible; rate-limiting `/api/v1/*` (API-05) additionally throttles guess attempts against valid-but-wrong tokens |
| SSRF via API-triggered scan bypassing the web UI's checks | Tampering / Elevation of Privilege | `scheduler._fire()` reuse (Pattern 3) guarantees `is_ssrf_safe_hostname` and tier gating run identically for API-triggered and scheduler-triggered scans — this is the entire reason Pattern 3 recommends reuse over a parallel implementation |

## Sources

### Primary (HIGH confidence)
- `flask-login.readthedocs.io/en/0.6.3/` — Request Loader Example, Disabling Session Cookie for
  APIs (fetched this session, quoted in Pattern 1)
- `flask-limiter.readthedocs.io/en/stable/recipes.html` — per-user `key_func` rate-limiting recipe
  (fetched this session, quoted in Pattern 4)
- `docs.python.org/3/library/secrets.html` — `secrets.token_urlsafe` as the recommended token
  generator (training knowledge, standard/stable stdlib API, unlikely to have changed)
- This project's own source, read this session: `glassbox/models.py` (Asset/User/Scan
  schemas, lines 62-319), `glassbox/asset_routes.py` (`_check_asset_access`, full file),
  `glassbox/scan_routes.py` (`_check_ownership`, `_spawn_scan_thread`, `scan_report`, full
  file), `glassbox/scheduler.py` (`_fire`, full file), `glassbox/entitlements.py` (full
  file), `glassbox/extensions.py` (full file), `glassbox/decorators.py` (full file),
  `glassbox/config.py` (full file), `glassbox/checks.py` lines 195-240
  (`is_ssrf_safe_hostname`, `normalize_target`), `glassbox/__init__.py` (full file),
  `migrations/versions/672a304d4921_add_assets_table_and_scans_asset_id.py` (full file),
  `tests/conftest.py` (full file), `templates/asset_detail.html` lines 99-207 (scan-link
  targets, confirming Pitfall 1), `requirements.txt` (full file)
- `pip show click requests flask-login flask-limiter flask-sqlalchemy flask-migrate` run against
  this project's own venv this session (confirms exact installed versions)

### Secondary (MEDIUM confidence)
- General WebSearch results on Flask bearer-token auth patterns (`hmac.compare_digest`,
  constant-time comparison framing) — corroborated against, not solely relied on, since this
  project's DB-indexed hash-lookup design sidesteps the specific timing-attack scenario those
  results describe (see Don't Hand-Roll table)

### Tertiary (LOW confidence)
- The recommendation to use SHA-256 (not a slow password hash) for token verification is based on
  general, well-established security-engineering reasoning (high-entropy secret ⇒ fast hash is
  correct) rather than a single fetched authoritative source this session — flagged `[ASSUMED]` in
  the Standard Stack table and Assumptions Log (A1), though the risk if wrong is a performance
  concern, not a security one.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — every library/version claim was verified against this project's own venv
  or an official docs fetch this session; no new dependency beyond `click`, which is already
  resident
- Architecture: HIGH — every reusable function/pattern cited (`_check_asset_access`,
  `_check_ownership`, `scheduler._fire`, `entitlements.effective_tier_for_org`,
  `is_ssrf_safe_hostname`, `login_manager.request_loader`) was read directly from source this
  session, not inferred
- Pitfalls: HIGH for Pitfall 1 (directly confirmed by reading `asset_detail.html`'s scan links
  against `scan_routes._check_ownership`'s logic); MEDIUM for Pitfalls 2-4 (standard Flask-Login/
  migration/logging gotchas, not specific to this codebase but well-grounded in how Flask-Login and
  Alembic actually behave)

**Research date:** 2026-08-10
**Valid until:** 30 days (stable stack — Flask/Flask-Login/Flask-Limiter/click are all mature,
slow-moving projects; re-verify installed versions if this research is reused after a
`pip install -U` or a long gap)
