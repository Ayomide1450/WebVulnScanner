# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Glassbox (product name as of v1.3; formerly WebVulnScanner - the Python package `webvulnscanner/`,
repo name, and DB are unchanged, see README.md) is a multi-tenant Flask SaaS for checking a
website's security posture:
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
set FLASK_APP=app.py
flask db upgrade          # applies migrations/ - see "Database migrations" below
python app.py
```

Then open http://127.0.0.1:5000. There is no build step or linter configured in this repo.

**Database migrations (infra track)**: `db.create_all()` no longer runs automatically in
`create_app()` - schema is owned by Alembic via Flask-Migrate (`migrations/`). Run
`flask db upgrade` once after cloning (creates all tables) and again after pulling any commit
that adds a `migrations/versions/*.py` file. After changing a model, run
`flask db migrate -m "description"` then review the generated file before `flask db upgrade` -
autogenerate is good but not infallible (renamed columns show up as drop+add, for one). This
replaced the old "no migrations, add a new table instead of altering one" constraint entirely.

**Deploying (Render)**: `render.yaml` + `Procfile` are set up for Render's Blueprint deploy
(gunicorn, `flask db upgrade` runs before the app starts, `/healthz` as the health-check path).
Postgres works out of the box - `config.py` rewrites a `postgres://` URI to `postgresql://`
(what SQLAlchemy 2.x requires) and only applies the SQLite-only `check_same_thread` engine
option when the URI is actually sqlite. Real email needs `EMAIL_MODE=resend` +
`RESEND_API_KEY` + `RESEND_FROM_EMAIL` (a domain verified in Resend) - unset, it stays on the
console stub. None of this creates accounts for you - see handoff.md's infra-track section for
the exact steps only a human can do (Render/Neon/Resend/Sentry/UptimeRobot signups).

**Tests**: `pip install -r requirements-dev.txt` then `pytest` (or
`.venv\Scripts\python -m pytest`). `tests/conftest.py` builds a fresh Flask app per test against
its own on-disk SQLite file under pytest's `tmp_path` (not `:memory:` — see the fixture's
docstring for why), with CSRF and rate-limiting disabled and env vars defaulted so the suite
needs no `.env` file. Runs on every push/PR via `.github/workflows/tests.yml` (GitHub Actions,
Python 3.12, `ubuntu-latest`). Coverage so far: `entitlements.py` tier-gating (`allowed_checks`,
`effective_tier`, `domain_is_org_verified`, plus a regression check that `FEATURE_REQUIREMENTS`
covers every check name `run_scan`'s jobs dict can dispatch), `_check_ownership`'s IDOR guard in
`scan_routes.py` across all four call sites, `checks.is_ssrf_safe_hostname` /
`scan_routes._unsafe_target_error` (mocked `socket.getaddrinfo` for the address-class matrix,
plus route-level tests confirming a blocked target creates no `Scan` row), and
`auth_routes.py`'s signup/verify-email/login/logout/forgot-password/reset-password flows
(anti-user-enumeration on both the login and forgot-password forms, single-use verify/reset
tokens, the `_safe_next()` open-redirect guard, and one dedicated test that turns
`RATELIMIT_ENABLED` back on to confirm `/login`'s 10/min limit actually trips a 429 — every
other test leaves rate limiting disabled since `Limiter`'s in-memory storage is a
process-wide singleton shared across every test app instance, see `extensions.py`), and the
live scan-progress feed (`tests/test_scan_events.py` — `ScanEvent` model, `CHECK_LABELS`
coverage, `run_scan()`'s `progress_cb` call sequence against stubbed check functions,
`_serialize_new_events`, and the `scan_events()` ownership guard; see that module's docstring
for why `_run_scan_in_background` is called there with short-lived `with app.app_context():`
blocks rather than the shared `db` fixture — holding an outer context open while calling it
causes its otherwise-successful commits to read back stale through that same session, a broader
instance of the concurrency caveat below).

Phase 4 added: `tests/test_scan_engine.py` — the shared `_score_report` scoring helper and the
three previously-untested orchestrators (`run_media_scan`/`run_api_scan`/`run_advanced_scan`),
including safety-constraint regression locks on `check_bruteforce`'s attempt cap and
`check_xss_stored`'s marker-only, no-cookie-exfiltration proof; `tests/test_ratelimit_storage.py`
— the multi-worker rate-limit storage proof (two independent `Limiter` instances sharing a
fakeredis-backed `redis://` counter) plus its in-memory negative control; `tests/test_org_invite.py`
— the email-bound invite flow end to end (token round-trip, mismatch/tampered/expired rejection,
org-binding, case normalization); `tests/test_domain_verification.py` — the domain-ownership
verification flow (both proof methods, re-add reset, cross-org guard); `tests/test_scheduler.py`
— the scheduler's entitled-plan media/api fire paths (dispatch kwargs, rescheduling, fire-time
SSRF refusal) plus a source-parsing lock proving no `advanced` branch exists; `tests/test_scan_routes.py`
— `_run_scan_in_background`'s per-scan-type Scan-row status transitions (COMPLETED/FAILED, report
filename prefix) for media/api/advanced; and `tests/test_template_consistency.py` — rendered-HTML
consistency assertions for the four pages' visual pass (dashboard/org-admin/billing/scan-report).

**Gotcha**: `email_validator` (backing WTForms' `Email()` validator) statically rejects
reserved TLDs (`.test`/`.invalid`/`.localhost`) even with deliverability checking off — use
`.com`/`.org`/`.dev`-style fake domains for test fixture emails, not `.test`.

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
| `webvulnscanner/org_routes.py`, `domain_verification.py` | Org admin, invites, domain-ownership verification (DNS TXT / well-known). An invite issues a signed, **email-bound** token (`generate_invite_token`/`decode_invite_token`) — `auth_routes.signup()` consumes it end to end, joining the signer to the inviting org at the invited role; a forwarded/leaked link cannot be redeemed under a different address (the token is re-decoded against the submitted email at POST time). Changing an already-joined member's role is still deliberately not a route. |
| `webvulnscanner/billing_routes.py`, `billing.py` | Crypto (USDT/USDC on Polygon) invoicing and plan activation |
| `webvulnscanner/entitlements.py` | `Tier` enum + `FEATURE_REQUIREMENTS` map; the single place that gates checks by plan/domain-verification |
| `webvulnscanner/scan_routes.py` | `/dashboard`, `/scan/new` (+ `/base`/`/advanced`/`/media`/`/api`), `/scan/<id>`, `/scan/<id>/events`, `/scan/<id>/report`, `/scan/<id>/compare/<other_id>`; spawns each scan in a background thread |
| `webvulnscanner/scan_engine.py` | The four scan orchestrators (`run_scan`/`run_advanced_scan`/`run_media_scan` moved intact from the old `app.py`; `run_api_scan` ported later from the `api-exposure-media-streaming` branch) |
| `webvulnscanner/checks.py` | Every individual check function |
| `webvulnscanner/ai_summary.py` | AI-assisted remediation summary (Groq/open-source LLM), Paid tier and above |
| `webvulnscanner/models.py` | SQLAlchemy models: `Organization`, `User`, `DomainVerification`, `Scan`, `ScanEvent` (per-check live-feed timeline, base scans only — see "Live scan-progress feed" below), `Report`, `Subscription`, `CryptoInvoice` |
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

### Live scan-progress feed (base scans only)

`templates/scan_progress.html` shows a real-time, per-check feed while a scan runs (not just a
percentage bar) — each check appears as a row that goes pulsing-blue ("started") →
green/"completed" or red/"failed", with `checks.CHECK_LABELS` supplying the human-readable name
and an optional `detail` string (e.g. the header grade). The data path: `run_scan()`'s
`progress_cb(name, phase, done, total, detail=None)` calls (fired for `headers`/`cookies`
synchronously, and for every parallel job in the `ThreadPoolExecutor` both before submission —
`"started"` — and on `as_completed` — `"completed"`/`"failed"`) → `_run_scan_in_background`'s
closure in `scan_routes.py` writes one `ScanEvent` row per call (new table, not a `Scan` column —
same no-migrations reason `PasswordReset` is its own table) → `scan_events()`'s SSE endpoint
streams only the rows newer than the client's last-seen cursor each tick, via the standalone
`_serialize_new_events(scan_id, after_id)` helper (kept out of the `generate()` closure
specifically so it's unit-testable without ever consuming the live stream).

**A tier-locked `open_ports` gets `phase=None`, not a fabricated `"completed"` event** — the
`progress_current`/`progress_total` counters still bump unconditionally (existing behavior,
preserved), but no `ScanEvent` row is written for a check that never ran. If you add a new
check to `run_scan()`'s `jobs` dict, add its label to `CHECK_LABELS` too (a regression test in
`tests/test_scan_events.py` checks this stays in sync, mirroring `entitlements.py`'s own
`FEATURE_REQUIREMENTS`-coverage test) — a missing entry only degrades to a title-cased raw key,
it doesn't break anything.

**Only base scans have this mechanism.** `run_advanced_scan`/`run_media_scan`/`run_api_scan` have
no `progress_cb` parameter at all; their scan-progress pages still degrade to the plain
bar/status-line-only view. Extending the live feed to them is a deferred, separate piece of work
(would need each orchestrator to grow the same `jobs`-dict-`+`-`as_completed` pattern `run_scan`
already has).

`ScanEvent` also carries `finding_count`/`top_severity` (set only on completed/failed rows, via
`scan_engine._top_severity()`/`_extract_detail()`) so the feed shows findings surfacing live, not
just pass/fail dots - `checks.CHECK_CATEGORY` maps each check to one of 6 icon-sprite keys
(`templates/base.html`'s `<symbol id="icon-*">` sprite) for the same reason `CHECK_LABELS` exists:
kept in sync via a regression test, falls back to `"shield"` if a future check is missed.
`scan_progress.html`'s current layout (status bar + two-column Investigation Log / Live
Intelligence grid, `scan-sweep` motif) is the Phase 2 "SOC" redesign - keep both `CHECK_LABELS`
and `CHECK_CATEGORY` updated together when `run_scan()`'s jobs dict changes.

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

`scan_engine._score_report(findings)` is the single place the risk score, letter grade and
severity tally are computed: start at 100, subtract `SEVERITY_WEIGHT[finding.severity]` per
finding, clamp to `[0, 100]`, then map the score to a letter grade (`A`–`F`) and tally
`severity_counts`. All four orchestrators (`run_scan`, `run_media_scan`, `run_advanced_scan`,
`run_api_scan`) call it — none carries its own inline copy of the arithmetic anymore, so changing
the formula is now a one-function edit. `tests/test_scan_engine.py` includes a source-parsing
regression lock that fails if any orchestrator ever re-inlines the block.

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

- `extensions.limiter` (Flask-Limiter) rate-limits `/login` (10/min), `/signup` (5/hour), and
  invoice create/verify (10/hour, 30/hour) in `auth_routes.py` / `billing_routes.py`. It's
  constructed without a storage URI; the backend is selected by `RATELIMIT_STORAGE_URI` (an env
  var, read into `Config.RATELIMIT_STORAGE_URI`) at `init_app()` time. Unset (the default) means
  in-memory storage, which is correct only for a single process — raising gunicorn's `--workers`
  count above 1 **requires setting `RATELIMIT_STORAGE_URI` first** (a `redis://[:password]@host:
  port[/db]` URL), or each worker will enforce its own, independent counters. A boot-time log line
  in `create_app()` names the active backend by scheme only, never the full URI (which may carry a
  password). `redis` is a production dependency (`requirements.txt`); `fakeredis` + `lupa` are
  dev/test-only (`requirements-dev.txt`) — see `tests/test_ratelimit_storage.py` for the proof
  that two independently-constructed `Limiter` instances pointed at the same `redis://` URI (via a
  fakeredis-backed `redis.from_url`) actually share a counter, plus an in-memory negative control
  showing they don't without it.
- `billing.create_invoice()` re-rolls its random amount-offset (up to
  `MAX_OFFSET_COLLISION_RETRIES` times) if it collides with another `PENDING` invoice's
  `expected_amount` for the same plan, since `verify_invoice()` matches purely by amount — a
  collision would otherwise let one real payment activate the wrong org's plan.
  `CryptoInvoice.matched_tx_hash` also has a DB-level unique constraint as defense in depth.
- 404/429/500 all render inside the app's own theme (`templates/404.html`/`429.html`/`500.html`,
  registered in `webvulnscanner/__init__.py`) instead of Flask's raw default error page.

## AI-assisted remediation summaries

`webvulnscanner/ai_summary.py`'s `generate_remediation_summary()` layers an LLM-generated,
plain-English summary + prioritized remediation steps on top of a scan's already-deterministic
findings — vulnerability *detection* stays 100% rule-based in `checks.py`; the AI's only job is
explaining/prioritizing what was already found. Called once per scan, for Paid tier and above,
from `_run_scan_in_background`'s shared tail in `scan_routes.py` (all four scan types alike),
stored as `report["ai_summary"]` in the same JSON blob `save_report()` already writes — no DB
schema change. Uses Groq's free, OpenAI-compatible API (`GROQ_API_KEY`/`GROQ_MODEL` in
`config.py`) serving an open-source model (Llama 3.1 8B Instant by default); the `openai` package
is used only as an HTTP client against Groq's endpoint, not OpenAI itself.

**Safety constraint**: finding `detail`/`title` text can contain content drawn directly from the
*scanned site's own HTTP responses* (header values, secret snippets, probe output) — not fully
trusted input, even though it's the user's authorized target. `SYSTEM_PROMPT` in `ai_summary.py`
explicitly frames all finding data as data-to-summarize inside `<findings>` delimiters, never as
instructions to follow, and the model's output is read-only report text with no tool-use
attached — bounds a successful prompt injection to "a wrong sentence in a report," not an
action. Preserve this framing if the prompt is ever changed.

`generate_remediation_summary()` never raises — a missing/invalid `GROQ_API_KEY`, network
failure, or malformed response all return `None`, and the report simply omits the section, same
degrade-gracefully convention as every `check_*` function in `checks.py`.

## Frontend design system

`templates/base.html` defines the shared design tokens (CSS custom properties) every other
template inherits: OLED-dark palette (`--bg`/`--panel`/`--accent` etc.), Fira Sans (UI) / Fira
Code (data, monospace) typography. Templates should reuse `.card`, `.btn`, `.pill`/`.badge`,
`.finding`, `.warn-box`/`.error-box`/`.info-box`, and the `.icon` SVG convention rather than
hardcoding colors or new component styles — and never use emoji as icons (inline SVG only, one
remaining exception in `org_verify_domain.html`'s empty-state `.warn-box`, not yet cleaned up;
`billing.html`'s matching exception was closed in Phase 4 — its warn-box now references the
sprite's `#icon-warning` symbol like every other `.warn-box` in the app). `base.html` also
defines bare severity text-color utilities
(`td.critical`/`.text-high`/etc., distinct from the `.pill`/`.badge`/`.dot` compound selectors)
for result-table cells, `.card`'s canonical gradient/16px-radius shape (every template that uses
it already independently converged on this — see the git history for the reconciliation), and
`h1`/`h2.section`/`table, th, td` promoted the same way from four near-identical local overrides
(`dashboard.html`/`billing.html`/`org_admin.html`/`org_verify_domain.html`).

The four `scan_new_*.html` pages plus the `scan_new.html` chooser share their form/card CSS via
`templates/_scan_form_styles.html`; `billing.html`/`org_admin.html`/`org_verify_domain.html`
share theirs via `templates/_admin_form_styles.html`. Neither is promoted into `base.html`: both
have unscoped `label`/`input`/`select`/`button` selectors that would otherwise leak into every
other form in the app (auth pages included) — keep this pattern for any future form-heavy page
rather than adding bare element selectors to `base.html` directly.

### "Evolved operator console" motion language (SUPERSEDED 2026-08-26 — see de-glow note below)

`base.html` defines `--telemetry`/`--telemetry2` (a blue accent distinct from `--accent`'s
green, for "in progress" states) and `.telemetry-dot`/`.done`/`.failed` (the live scan-progress
feed's state-dot classes) — these are still live and in use. `.glow-pulse` (a
`drop-shadow(currentColor)` pulse, reduced-motion-gated) and `.hud-grid` (a static ambient grid
texture) are **still defined in `base.html` but deliberately removed from every page that used
to carry them** — see below. The icon sprite also has `#icon-warning` (24×24 viewBox,
`stroke-linecap`/`stroke-linejoin: round`), still current.

**De-glow/flatten decision (2026-08-26, user-directed, commit `934394d` + `28475c5`/`67946fe`)**:
the earlier "reuse `.hud-grid`/`.glow-pulse`, don't invent new treatments" guidance below is
**no longer the house style**. The redesign pass flattened the look across login/signup/
marketing/dashboard/scan_report: `.hud-grid` texture removed, gradients flattened, mobile tap
targets widened, `base.html`'s CSS custom-property *values* (not names) switched to a darker
palette from a user-supplied reference mockup, and login/signup gained a decorative
terminal-window title bar. `.status-pill`'s dot+`.glow-pulse` on running/queued scan rows is the
one motion treatment that survived the pass. **Do not re-add `.hud-grid` texture to new pages** —
treat the flattened, darker-palette look as current; the "Phase 4 reuse-only" paragraph that used
to follow this note (mandating a `.hud-grid`-textured anchor card on every major page) is
retracted along with it.
