# Context

Extracted from `DOC`-classified documents (implementation plans). Running notes keyed by topic,
appended verbatim/paraphrased with source attribution.

## Topic: API Exposure Scan + Media Stream Discovery — implementation plan
- source: docs/superpowers/plans/2026-08-05-api-exposure-and-media-streaming.md
- Goal: Add a fourth scan pipeline (`/scan-api`) that detects exposed API schemas/docs,
  unauthenticated common API paths, and endpoints discovered from the site's own JS; strengthen
  the existing media scan to discover and verify HLS/DASH video streams.
- Architecture: Everything lives in `app.py`, following existing conventions (see `CLAUDE.md`):
  every check function returns `(data, findings)`, `Finding` objects drive a severity-weighted
  scoring formula duplicated per orchestrator, and all new checks are `GET`-only except one
  narrow read-only GraphQL introspection `POST`. A new shared helper (`_fetch_same_origin_js`) is
  extracted from existing code and reused by two new features.
- Tech stack: Flask, `requests`, `BeautifulSoup4`, stdlib `re`/`urllib.parse`/`concurrent.futures`.
  No new dependencies. No test framework added — verification uses throwaway scratch scripts
  (`verify_taskN.py`) with a hand-rolled fake `requests.Session`, never committed.
- Global constraints (from plan): no new pip dependencies; every new network call
  try/except-guarded; no destructive requests; no automated test suite introduced; follow the
  existing `Finding(...)` dataclass shape and `SEVERITY_WEIGHT`/`SEVERITY_ORDER` scoring pattern;
  new report files follow `reports/<prefix>_<hostname>_<timestamp>.json` naming.
- Task breakdown (10 tasks): (1) extract shared same-origin JS-fetch helper
  `_fetch_same_origin_js`; (2) HLS/DASH stream discovery in `crawl_media` (changes its return
  signature to a 4-tuple); (3) verify + report discovered streams in `check_media`; (4)
  `check_api_schema_exposure` (schema/GraphQL introspection); (5) `check_api_wordlist` with
  SPA-response guard; (6) JS-based API endpoint discovery (`check_api_js_discovery`); (7)
  `run_api_scan` orchestrator; (8) `/scan-api` Flask route + `index.html` form section; (9)
  `templates/api_results.html`; (10) update `CLAUDE.md` and `README.md` docs.
- Self-review notes (plan author): all three API-exposure checks, the shared JS-fetch refactor,
  HLS/DASH discovery+verification, and both templates/docs are covered by Tasks 1-10; no
  TBD/TODO; type consistency confirmed across `crawl_media`'s new 4-tuple return,
  `_fetch_same_origin_js`'s signature (identical at 3 call sites), and reuse of
  `_looks_like_api_response`/`_api_path_severity` between Tasks 5 and 6.

## Topic: Page Completion & Visual Polish — implementation plan
- source: docs/superpowers/plans/2026-08-07-page-completion-and-polish.md
- Goal: Fix three confirmed render/reliability bugs, add the two missing legal pages plus a
  site-wide footer, bring remaining bland-but-functional pages up to the existing design system's
  visual standard, and add a code-only keep-alive heartbeat — with zero changes to
  `entitlements.py`, `checks.py`, the SSRF guard, or any ownership/auth check.
- Architecture: Template/CSS/JS-only changes plus one backend config line
  (`SQLALCHEMY_ENGINE_OPTIONS`). No new routes beyond `/terms` and `/privacy`, no schema changes,
  no new dependencies. Every visual change reuses existing `base.html` tokens/components
  (`.card`, `.pill`, `.warn-box`, `.glow-pulse`, `.hud-grid`).
- Tech stack: Flask/Jinja2, vanilla CSS (custom properties in `base.html`), vanilla JS (no
  framework), pytest + Flask test client.
- Global constraints (from plan): reuse existing design-system components rather than hardcoding
  new colors/styles; never use emoji as icons (inline SVG only); no changes to `entitlements.py`,
  `checks.py`, `checks.is_ssrf_safe_hostname()`, or any `_check_ownership` call site; `.env`/
  `.env.example` are sandbox-blocked from Read/Bash; Terms/Privacy content is a clearly-marked
  draft, never presented as final legal advice; run the full `pytest` suite before considering any
  task's tests "passing" in isolation (the codebase's `Limiter` is a process-wide singleton —
  cross-test interference is a real risk).
- Task breakdown (11 tasks): (1) fix Postgres connection reliability
  (`_engine_options_for`/`pool_pre_ping`); (2) fix `marketing.html` hiding hero content behind
  boot animation; (3) fix dashboard sparkline's single-scan case; (4) add Terms of
  Service/Privacy Policy pages + site footer + `current_year` context var; (5) dashboard visual
  polish — status pills + row hover; (6) billing visual polish — crypto invoice payment card; (7)
  org admin visual polish — pill badges + row hover; (8) `scan_report.html`/`scan_compare.html`
  spacing refinement; (9) `scan_new_*` consistency pass via `_scan_form_styles.html`; (10)
  code-only keep-alive heartbeat pinging `/healthz` every 4 minutes while tab visible; (11) full
  verification pass (automated suite + manual click-through at desktop and mobile widths).
- File structure table lists exact files touched: `glassbox/config.py`,
  `tests/test_config.py` (new), `templates/marketing.html`, `templates/dashboard.html`,
  `tests/test_scan_routes.py` (new), `glassbox/public_routes.py`, `templates/terms.html`
  (new), `templates/privacy.html` (new), `templates/base.html`, `glassbox/__init__.py`,
  `tests/test_public_routes.py`, `templates/billing.html`, `tests/test_billing_routes.py` (new),
  `templates/org_admin.html`, `tests/test_org_routes.py` (new), `templates/scan_report.html`,
  `templates/scan_compare.html`, `templates/_scan_form_styles.html`.
