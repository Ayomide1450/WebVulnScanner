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
weaken or remove: the `authorized` / `authorized_adv` / `authorized_media` server-side checkbox
checks, or the `entitlements.py` tier/domain-verification gating that sits in front of the
intrusive checks.

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
| `webvulnscanner/scan_routes.py` | `/dashboard`, `/scan/new`, `/scan/<id>`, `/scan/<id>/events`, `/scan/<id>/report`, `/scan/<id>/compare/<other_id>`; spawns each scan in a background thread |
| `webvulnscanner/scan_engine.py` | The three scan orchestrators (moved intact from the old `app.py`) |
| `webvulnscanner/checks.py` | Every individual check function |
| `webvulnscanner/models.py` | SQLAlchemy models: `Organization`, `User`, `DomainVerification`, `Scan`, `Report`, `Subscription`, `CryptoInvoice` |
| `webvulnscanner/public_routes.py` | `/` marketing page |

Scan results are persisted as `Report` rows (queryable for the dashboard/compare view) and still
also written to `reports/` as timestamped JSON; media downloads still go to `downloads/`.

### Three independent scan pipelines

`scan_routes.new_scan()` dispatches to one of three orchestrators in `scan_engine.py` based on
`scan_type`. They don't share state — a target is re-fetched from scratch in each:

| `scan_type` | Orchestrator | Purpose |
|---|---|---|
| `base` | `run_scan()` | Passive/recon checks: headers, TLS, cookies, ports, CORS, secrets, crawl-then-probe XSS/SQLi, etc. Free tier runs the passive subset only; Paid unlocks active checks (crawl, ports, CORS, methods, redirect, listing); Org-verified unlocks the XSS/SQLi canary. |
| `advanced` | `run_advanced_scan()` | Opt-in, form-field-driven, Org-verified-only checks needing credentials/session cookies: SQLi login bypass, stored XSS, IDOR across two test accounts, brute-force. Each check group only runs if its required form fields are all present. |
| `media` | `run_media_scan()` | Same-origin media crawl (images/video), EXIF/GPS leakage, suspicious-path detection, optional download-to-disk. Paid tier. |

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

All three orchestrators independently: start at 100, subtract `SEVERITY_WEIGHT[finding.severity]`
per finding, clamp to `[0, 100]`, then map the score to a letter grade (`A`–`F`) and tally
`severity_counts`. This scoring block is duplicated three times in `scan_engine.py` (`run_scan`,
`run_media_scan`, `run_advanced_scan`) rather than shared — keep that in mind if changing the
formula, it needs updating in all three places.

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

Preserve these constraints when modifying the corresponding checks — they're what keeps this a
non-destructive, authorized-use-only tool rather than a general attack script.

## Frontend design system

`templates/base.html` defines the shared design tokens (CSS custom properties) every other
template inherits: OLED-dark palette (`--bg`/`--panel`/`--accent` etc.), Fira Sans (UI) / Fira
Code (data, monospace) typography. Templates should reuse `.card`, `.btn`, `.pill`/`.badge`,
`.finding`, `.warn-box`/`.error-box`/`.info-box`, and the `.icon` SVG convention rather than
hardcoding colors or new component styles — and never use emoji as icons (inline SVG only).
