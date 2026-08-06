# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

WebVulnScanner is a multi-tenant Flask SaaS for checking a website's security posture:
accounts, organizations, crypto-invoice billing, and a tiered entitlement system (Free / Paid /
Org-verified) that gates which checks a scan is allowed to run. The most intrusive checks
(reflected/stored XSS, SQLi, IDOR, brute-force) additionally require server-verified domain
ownership (DNS TXT or `/.well-known/`) tied to the org, not just a checkbox. See README.md for
the full check list per tier and the documented false-positive fix (CDN edge ports being
misreported as exposed services) — that history matters when touching `check_open_ports`.

**Only ever test against domains the user owns or has explicit permission to test.** Do not
weaken or remove: the `authorized` / `authorized_adv` / `authorized_media` / `authorized_api`
server-side checkbox checks, the `entitlements.py` tier/domain-verification gating that sits in
front of the intrusive checks, or `checks.is_ssrf_safe_hostname()` (called by every
`new_scan_*` route in `scan_routes.py` before a `Scan` row is created — blocks scans targeting
loopback/link-local/RFC1918/cloud-metadata addresses; see its docstring for what it does and
does not protect against).

## Commands

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env    # set SECRET_KEY at minimum
python app.py
```

Then open http://127.0.0.1:5000. SQLite tables are created automatically on first run. There is
no build step, linter, or test suite configured in this repo.

**`SECRET_KEY` is required, not optional** — `config.py` raises `RuntimeError` at import time if
it's unset, since it signs session cookies, the remember-me cookie, and org-invite tokens. For
local development only, set `ALLOW_INSECURE_DEV_SECRET_KEY=true` instead of a real key to fall
back to a hardcoded placeholder — never set that variable anywhere but a throwaway local
`.env`. `.env.example` at the repo root could not be edited by this assistant (sandboxed —
dotfile directory access denied); add both `SECRET_KEY`/`ALLOW_INSECURE_DEV_SECRET_KEY` and
`SESSION_COOKIE_SECURE` (see below) to it by hand if it doesn't already list them.

Session/remember cookies default to `Secure` (HTTPS-only) — a plain-`http://` local dev server
won't have the cookie sent back by the browser at all unless you set
`SESSION_COOKIE_SECURE=false` in `.env` for local testing.

## Architecture

`app.py` at the repo root is a thin app-factory shim (`from webvulnscanner import create_app`).
Everything else — models, blueprints, checks, orchestrators, entitlement gating — lives in the
`webvulnscanner/` package, with Jinja templates still in `templates/` (all extending
`templates/base.html`).

| Module | Responsibility |
|---|---|
| `webvulnscanner/auth_routes.py` | Signup, login, logout, email verification |
| `webvulnscanner/org_routes.py`, `domain_verification.py` | Org admin, invites, domain-ownership verification (DNS TXT / well-known) |
| `webvulnscanner/billing_routes.py`, `billing.py` | Crypto (USDT/USDC on Polygon) invoicing and plan activation |
| `webvulnscanner/entitlements.py` | `Tier` enum + `FEATURE_REQUIREMENTS` map; the single place that gates checks by plan/domain-verification |
| `webvulnscanner/scan_routes.py` | `/dashboard`, `/scan/new` (+ `/base`/`/advanced`/`/media`/`/api`), `/scan/<id>`, `/scan/<id>/events`, `/scan/<id>/report`, `/scan/<id>/compare/<other_id>`; spawns each scan in a background thread |
| `webvulnscanner/scan_engine.py` | The four scan orchestrators (`run_scan`/`run_advanced_scan`/`run_media_scan` moved intact from the old `app.py`; `run_api_scan` ported later from the `api-exposure-media-streaming` branch) |
| `webvulnscanner/checks.py` | Every individual check function |
| `webvulnscanner/models.py` | SQLAlchemy models: `Organization`, `User`, `DomainVerification`, `Scan`, `Report`, `Subscription`, `CryptoInvoice` |
| `webvulnscanner/public_routes.py` | `/` marketing page |

Scan results are persisted as `Report` rows (queryable for the dashboard/compare view) and still
also written to `reports/` as timestamped JSON; media downloads still go to `downloads/`.

### Four independent scan pipelines, one dedicated page each

Each scan type has its own GET+POST route/template (`/scan/new/base` → `scan_new_base.html`,
`/scan/new/advanced` → `scan_new_advanced.html`, `/scan/new/media` → `scan_new_media.html`,
`/scan/new/api` → `scan_new_api.html`), each calling its own view function
(`new_scan_base`/`new_scan_advanced`/`new_scan_media`/`new_scan_api` in `scan_routes.py`), which
dispatches to its orchestrator in `scan_engine.py`. `/scan/new` itself is a GET-only landing page
(`scan_new.html`) linking to the four. They don't share state — a target is re-fetched from
scratch in each:

| `scan_type` | Orchestrator | Purpose |
|---|---|---|
| `base` | `run_scan()` | Passive/recon checks: headers, TLS, cookies, ports, CORS, secrets, crawl-then-probe XSS/SQLi, etc. Free tier runs the passive subset only; Paid unlocks active checks (crawl, ports, CORS, methods, redirect, listing); Org-verified unlocks the XSS/SQLi canary. |
| `advanced` | `run_advanced_scan()` | Opt-in, form-field-driven, Org-verified-only checks needing credentials/session cookies: SQLi login bypass, stored XSS, IDOR across two test accounts, brute-force. Each check group only runs if its required form fields are all present. |
| `media` | `run_media_scan()` | Same-origin media crawl (images/video), EXIF/GPS leakage, suspicious-path detection, optional download-to-disk. Paid tier. |
| `api` | `run_api_scan()` | API exposure: OpenAPI/Swagger/GraphQL-introspection exposure, an unauthenticated-path wordlist (SPA-response guarded), and endpoints discovered from the site's own JS (`fetch`/`axios`/`.ajax` calls). Paid tier — read-only probing, no injection payloads. |

`media` and `api` are both gated route-level (before the `Scan` row/thread is created), not
inside their orchestrators — see each orchestrator's docstring in `scan_engine.py` for why.

`entitlements.allowed_checks()` filters the requested check names against the caller's `Tier`
*before* the orchestrator runs them — a locked check never executes, it just gets reported back
as `locked` so the UI can show an upgrade prompt.

### Check function convention

Every individual check is a plain function that returns `(data, findings)`:
- `data` is whatever raw/structured info the results template needs to render (rows, dicts).
- `findings` is a `list[Finding]` — a dataclass with `category`, `title`, `severity`
  (`critical|high|medium|low|info|pass`), `detail`, `recommendation`.

`run_scan()` fans most checks out concurrently via a `ThreadPoolExecutor` (see the `jobs` dict),
then runs `check_open_ports` separately since it does its own internal threading per-port.
When adding a new check, follow this `(data, findings)` return convention and never let a check
raise past its own function — network calls should be wrapped in
`try/except requests.RequestException` so one failing check doesn't kill the whole scan.

### Scoring

All four orchestrators independently: start at 100, subtract `SEVERITY_WEIGHT[finding.severity]`
per finding, clamp to `[0, 100]`, then map the score to a letter grade (`A`–`F`) and tally
`severity_counts`. This scoring block is duplicated four times in `scan_engine.py` (`run_scan`,
`run_media_scan`, `run_advanced_scan`, `run_api_scan`) rather than shared — keep that in mind if
changing the formula, it needs updating in all four places.

### Adding a new base-scan check

1. Write `check_foo(...) -> (data, findings)` near the other checks in `checks.py` (headers/
   cookies/network checks are grouped near the top; media checks and advanced/authenticated
   checks each have their own labeled section with a comment banner).
2. Add a `FEATURE_REQUIREMENTS` entry in `entitlements.py` under the matching tier — a check
   missing from this map defaults to `Tier.FREE` (allowed) and logs a warning, so don't skip it
   for anything above passive/recon.
3. Register it in the `jobs` dict inside `run_scan()` (in `scan_engine.py`) if it can run
   concurrently and only needs `base_url`/`session`/`hostname`/`home_html`; call it directly
   afterward (like `check_open_ports`) if it needs its own threading or must run after the crawl.
4. Add its `data` to the returned report dict, and render it in `templates/scan_report.html`.

### Safety constraints baked into the design

- The crawler (`crawl_same_origin`, `crawl_media`) is same-origin only and depth-1.
- Forms are enumerated (action/method/inputs) for display but **never auto-submitted** — only
  GET requests with query parameters are sent during probing.
- `check_bruteforce` is hard-capped at `MAX_BRUTEFORCE_ATTEMPTS` (5) and stops on first success.
- Secrets found by `check_exposed_secrets` are redacted (`_redact_secret`) before being put in
  the report — the report file itself must not become a second leak of the credential.
- `check_xss_stored` proves execution via a marker string; it explicitly does not exfiltrate
  cookies even though it notes that'd be the trivial next step.
- Time-based blind SQLi checks (`TIME_BLIND_DELAY = 4`) are used sparingly and stop after the
  first confirmed hit rather than probing every DB engine once one succeeds.
- Intrusive checks (`xss_sqli`, `sqli_login`, `bruteforce`, `sqli_union`, `xss_stored`, `idor`)
  require both `Tier.ORG_VERIFIED` *and* a verified `DomainVerification` row for the exact target
  hostname (`entitlements.domain_is_org_verified`) — a paid-but-unverified org cannot reach them.
- API probing (`check_api_wordlist`, `check_api_js_discovery`) only counts a `200` as a hit if the
  response actually looks like API output (`_looks_like_api_response`: JSON/XML content-type or a
  `{`/`[`-leading body) — guards against SPAs that return their `index.html` shell for every path.
- `checks.is_ssrf_safe_hostname()` resolves every user-supplied absolute URL's hostname and
  rejects private/loopback/link-local/reserved/multicast addresses before any `Scan` row is
  created. It's a submission-time check only — it does not pin the resolved IP for the actual
  scan request, so it does not protect against DNS rebinding; see its docstring before assuming
  more coverage than that.

Preserve these constraints when modifying the corresponding checks — they're what keeps this a
non-destructive, authorized-use-only tool rather than a general attack script.

### Other hardening in `webvulnscanner/`

- `extensions.limiter` (Flask-Limiter, in-memory storage — fine for the current single dev-
  server-process reality, not multi-worker-safe) rate-limits `/login` (10/min),
  `/signup` (5/hour), and invoice create/verify (10/hour, 30/hour) in `auth_routes.py` /
  `billing_routes.py`.
- `billing.create_invoice()` re-rolls its random amount-offset (up to
  `MAX_OFFSET_COLLISION_RETRIES` times) if it collides with another `PENDING` invoice's
  `expected_amount` for the same plan, since `verify_invoice()` matches purely by amount — a
  collision would otherwise let one real payment activate the wrong org's plan.
  `CryptoInvoice.matched_tx_hash` also has a DB-level unique constraint as defense in depth.
- 404/429/500 all render inside the app's own theme (`templates/404.html`/`429.html`/`500.html`,
  registered in `webvulnscanner/__init__.py`) instead of Flask's raw default error page.

## Frontend design system

`templates/base.html` defines the shared design tokens (CSS custom properties) every other
template inherits: OLED-dark palette (`--bg`/`--panel`/`--accent` etc.), Fira Sans (UI) / Fira
Code (data, monospace) typography. Templates should reuse `.card`, `.btn`, `.pill`/`.badge`,
`.finding`, `.warn-box`/`.error-box`/`.info-box`, and the `.icon` SVG convention rather than
hardcoding colors or new component styles — and never use emoji as icons (inline SVG only).
`base.html` also defines bare severity text-color utilities (`td.critical`/`.text-high`/etc.,
distinct from the `.pill`/`.badge`/`.dot` compound selectors) for result-table cells.

The four `scan_new_*.html` pages plus the `scan_new.html` chooser share their form/card CSS via
`templates/_scan_form_styles.html` (included, not promoted into `base.html`, since it has
unscoped `label`/`input`/`button` selectors that would otherwise leak into every other form in
the app).
