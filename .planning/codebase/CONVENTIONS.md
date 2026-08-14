# Coding Conventions

**Analysis Date:** 2026-08-10

## Naming Patterns

**Files:**
- `snake_case.py` throughout `webvulnscanner/` (e.g. `auth_routes.py`, `domain_verification.py`, `scan_engine.py`).
- Route modules end in `_routes.py` (`auth_routes.py`, `org_routes.py`, `billing_routes.py`, `scan_routes.py`, `public_routes.py`); one module per Flask blueprint.
- Non-route domain logic lives in bare-named modules: `checks.py`, `entitlements.py`, `billing.py`, `ai_summary.py`, `domain_verification.py`, `email_stub.py`.
- Templates mirror route names (`scan_new_base.html` ↔ `new_scan_base` view), with shared-style partials prefixed `_` (`templates/_scan_form_styles.html`, `templates/_admin_form_styles.html`, `templates/_gauge.html`, `templates/_legal_styles.html`, `templates/_auth_form_styles.html`).

**Functions:**
- `snake_case`. Internal/private helpers prefixed with a single underscore, e.g. `_check_ownership`, `_redact_secret`, `_top_severity`, `_extract_detail`, `_serialize_new_events`, `_unsafe_target_error`, `_engine_options_for`, `_init_sentry` (`webvulnscanner/scan_routes.py`, `webvulnscanner/checks.py`, `webvulnscanner/scan_engine.py`, `webvulnscanner/config.py`, `webvulnscanner/__init__.py`).
- Every scan check function is named `check_<thing>` and returns `(data, findings)` — see "Check function convention" below.

**Variables:**
- `snake_case`. Module-level constants `UPPER_SNAKE_CASE` (`MAX_BRUTEFORCE_ATTEMPTS`, `TIME_BLIND_DELAY`, `SEVERITY_WEIGHT`, `CHECK_LABELS`, `CHECK_CATEGORY`, `FEATURE_REQUIREMENTS` — `webvulnscanner/checks.py`, `webvulnscanner/scan_engine.py`, `webvulnscanner/entitlements.py`).

**Types / Enums:**
- `PascalCase` for SQLAlchemy models and enums: `Organization`, `User`, `DomainVerification`, `Scan`, `ScanEvent`, `Report`, `Subscription`, `CryptoInvoice`, `Plan`, `Role`, `ScanStatus`, `ScanEventPhase`, `Tier` (`webvulnscanner/models.py`, `webvulnscanner/entitlements.py`).
- Dataclass results named as nouns: `Finding` (category/title/severity/detail/recommendation) in `webvulnscanner/checks.py`.

## Code Style

**Formatting:**
- No formatter/linter is configured in the repo. CLAUDE.md states explicitly: "There is no build step or linter configured in this repo." No `.flake8`, `setup.cfg`, `pyproject.toml`, `ruff.toml`, or `.pre-commit-config.yaml` files exist.
- Style is inferred from existing code only — long, heavily-commented docstrings at module/function top explaining *why*, not just *what*.

**Linting:**
- None configured. Match existing style manually; there is no automated gate besides `pytest` in CI (`.github/workflows/tests.yml`).

## Import Organization

**Order (observed in `webvulnscanner/scan_routes.py`, `webvulnscanner/__init__.py`):**
1. Standard library (`json`, `os`, `threading`, `time`, `datetime`, `urllib.parse`)
2. Third-party (`flask`, `flask_login`, `werkzeug`)
3. Local `webvulnscanner.*` absolute imports (never relative imports)

**Local imports:**
- Blueprint modules are imported lazily inside `create_app()` (`webvulnscanner/__init__.py`) to avoid import-time circularity, one `from webvulnscanner.X_routes import X as X_blueprint` / `app.register_blueprint(X_blueprint)` pair per blueprint.
- Models are imported for side effects only inside `with app.app_context():` at the end of `create_app()` (`# noqa: F401`), not for schema creation (see gotchas below).

**Path Aliases:** None — always full `webvulnscanner.module` absolute imports.

## Error Handling

**Check functions never raise past themselves** (`webvulnscanner/checks.py`, documented in CLAUDE.md's "Check function convention"): every `check_*` function wraps its own network calls in `try/except requests.RequestException` (or similar) so one failing check doesn't kill the whole scan orchestrator.

**AI summary degrades gracefully**: `webvulnscanner/ai_summary.py`'s `generate_remediation_summary()` never raises — a missing/invalid `GROQ_API_KEY`, network failure, or malformed response all return `None` and the report simply omits that section.

**Best-effort integrations never raise**: `_init_sentry()` in `webvulnscanner/__init__.py` is a silent no-op (with a log line) if `sentry-sdk` isn't installed or `SENTRY_DSN` isn't set — same "degrade gracefully" convention.

**Ownership checks use 404, not 403**: `_check_ownership()` in `webvulnscanner/scan_routes.py` and the equivalent pattern in `webvulnscanner/org_routes.py` call `abort(404)` for unauthorized access rather than 403, so a resource ID's existence isn't leaked to a caller who isn't entitled to see it.

**Fail-fast for critical config**: `webvulnscanner/config.py` raises `RuntimeError` at import time if `SECRET_KEY` is unset (rather than silently falling back to an insecure default) — opt into the old insecure-default behavior explicitly via `ALLOW_INSECURE_DEV_SECRET_KEY=true`.

**500 handler rolls back the session**: `webvulnscanner/__init__.py`'s `_server_error` errorhandler calls `db.session.rollback()` before rendering `500.html`.

## Routes / Blueprints Structure

- One `Blueprint` per concern, defined at module top (`scan = Blueprint("scan", __name__)` in `scan_routes.py`; similarly `auth`, `org`, `billing_bp`, `public`), registered in `webvulnscanner/__init__.py`'s `create_app()`.
- Route modules open with a long module docstring explaining routes owned, and documenting non-obvious design decisions inline as "**X decision**:" paragraphs (see `webvulnscanner/scan_routes.py`'s docstring for "Per-type route decision", "Ownership decision", "Dashboard scoping decision", "Diff placement decision").
- Each of the four scan types (`base`/`advanced`/`media`/`api`) gets its own dedicated GET+POST route + template + view function (`new_scan_base`, `new_scan_advanced`, `new_scan_media`, `new_scan_api` in `webvulnscanner/scan_routes.py`) rather than one shared multiplexed route — deliberate, documented decision (keeps browser URL in sync with which form failed validation).
- `@login_required` (flask_login) decorates protected views; custom decorators live in `webvulnscanner/decorators.py`.
- Section banners (`# --- Ownership ---` style comment blocks) divide route modules into logical groups (see `scan_routes.py`).

## Check function convention (domain-specific, `webvulnscanner/checks.py`)

Every individual check is a plain function returning `(data, findings)`:
- `data`: raw/structured info for the results template.
- `findings`: `list[Finding]` — dataclass with `category`, `title`, `severity` (`critical|high|medium|low|info|pass`), `detail`, `recommendation`.

When adding a new check (documented step-by-step in CLAUDE.md's "Adding a new base-scan check"):
1. Write `check_foo(...) -> (data, findings)` in `webvulnscanner/checks.py`, grouped near related checks (labeled section comment banners divide headers/cookies/network vs. media vs. advanced/authenticated checks).
2. Add a `FEATURE_REQUIREMENTS` entry in `webvulnscanner/entitlements.py` — a check missing from this map defaults to `Tier.FREE` (allowed) and logs a warning.
3. Register it in the `jobs` dict inside `run_scan()` (`webvulnscanner/scan_engine.py`) if it can run concurrently via the `ThreadPoolExecutor`; call it directly afterward (like `check_open_ports`) if it needs its own internal threading or must run after the crawl.
4. Add its `data` to the returned report dict and render it in `templates/scan_report.html`.
5. Add its label to `CHECK_LABELS` and its icon category to `CHECK_CATEGORY` (`checks.py`) — a regression test (`tests/test_scan_events.py`) checks these stay in sync with `run_scan()`'s `jobs` dict.

## Comments / Docstrings

- Module-level docstrings are long-form prose explaining architecture/design decisions, not just a one-line summary — this is the dominant documentation style across `webvulnscanner/*.py` (see `scan_routes.py`, `config.py`, `__init__.py`).
- Inline comments frequently explain *why* a non-obvious choice was made (e.g. "not `:memory:` because...", "404 not 403 because...") rather than restating the code.
- No enforced docstring format (no Google/NumPy/Sphinx style detected) — free-form prose paragraphs.

## Config / Env Vars

- All configuration is read from environment variables in `webvulnscanner/config.py`, loaded via `python-dotenv`'s `load_dotenv()` pointed at a `.env` file in the repo root; `.env.example` documents every supported variable (also see `docs/env-vars.md`).
- `SECRET_KEY` is mandatory — `config.py` raises `RuntimeError` at import time if unset, unless `ALLOW_INSECURE_DEV_SECRET_KEY=true` is set (dev-only, logs a warning and uses a hardcoded insecure placeholder).
- `SESSION_COOKIE_SECURE` defaults true (HTTPS-only cookies); must be set to `false` for local `http://` development.
- Postgres URIs of the form `postgres://` are rewritten to `postgresql://` in `config.py` (SQLAlchemy 2.x requirement); the SQLite-only `check_same_thread: False` engine option is applied only when the URI is actually `sqlite` (`_engine_options_for()` in `config.py`, unit-tested in `tests/test_config.py`).
- `TRUST_PROXY_HOPS` controls whether `ProxyFix` is applied in `webvulnscanner/__init__.py` (0 disables it, for direct/unproxied deployment).
- Real outbound email requires `EMAIL_MODE=resend` + `RESEND_API_KEY` + `RESEND_FROM_EMAIL`; unset, it stays on the console stub (`webvulnscanner/email_stub.py`).
- `GROQ_API_KEY` (+ optional `GROQ_MODEL`, default `llama-3.1-8b-instant`) enables AI remediation summaries (`webvulnscanner/ai_summary.py`); missing key degrades gracefully (see Error Handling).
- **Never read or quote `.env` contents** — only its existence/variable names as documented in `.env.example` / `docs/env-vars.md`.

## Frontend / Template Conventions (documented in CLAUDE.md)

- All templates extend `templates/base.html`, which defines shared CSS custom-property design tokens (OLED-dark palette, Fira Sans/Fira Code typography).
- Reuse existing component classes (`.card`, `.btn`, `.pill`/`.badge`, `.finding`, `.warn-box`/`.error-box`/`.info-box`) rather than hardcoding new colors or component styles.
- **Never use emoji as icons** — inline SVG only (one pre-existing exception in `billing.html`/`org_verify_domain.html`'s empty-state `.warn-box`, not yet cleaned up).
- Form-heavy page groups share CSS via dedicated partials (`templates/_scan_form_styles.html` for the four `scan_new_*.html` pages; `templates/_admin_form_styles.html` for `billing.html`/`org_admin.html`/`org_verify_domain.html`) rather than being promoted into `base.html`, since both partials use unscoped element selectors (`label`/`input`/`select`/`button`) that would otherwise leak into every other form in the app.
- Motion/texture primitives (`.glow-pulse`, `.hud-grid`, `.telemetry-dot`/`.done`/`.failed`, `--telemetry`/`--telemetry2`) are defined once in `base.html` and should be reused rather than inventing new ad hoc glow/motion CSS; `.glow-pulse` is gated under `@media (prefers-reduced-motion: no-preference)` with a steady-glow fallback.

## Gotchas / Non-Obvious Rules (from CLAUDE.md)

- **No more "no-migrations" rule.** `db.create_all()` no longer runs automatically in `create_app()` — schema is owned by Alembic via Flask-Migrate (`migrations/`). Run `flask db upgrade` after cloning and after pulling any commit that adds a `migrations/versions/*.py` file. After changing a model, run `flask db migrate -m "description"` then **review the generated file** before `flask db upgrade` — autogenerate can misclassify renamed columns as drop+add. This *replaces* an older, no-longer-applicable "no migrations, add a new table instead of altering one" constraint mentioned historically in CLAUDE.md.
- **Never weaken or remove**: the `authorized`/`authorized_adv`/`authorized_media`/`authorized_api` server-side checkbox checks, the `entitlements.py` tier/domain-verification gating in front of intrusive checks, or `checks.is_ssrf_safe_hostname()` (called by every `new_scan_*` route in `webvulnscanner/scan_routes.py` before a `Scan` row is created).
- `checks.is_ssrf_safe_hostname()` is a **submission-time check only** — it does not pin the resolved IP for the actual scan request, so it does not protect against DNS rebinding (see its docstring in `webvulnscanner/checks.py`).
- The scoring block (start at 100, subtract `SEVERITY_WEIGHT[finding.severity]` per finding, clamp to `[0,100]`, map to letter grade `A`–`F`) is **duplicated four times** in `webvulnscanner/scan_engine.py` (`run_scan`, `run_media_scan`, `run_advanced_scan`, `run_api_scan`) rather than shared — any formula change needs updating in all four places.
- `extensions.limiter` (Flask-Limiter) uses **in-memory storage**, a process-wide singleton — fine for a single dev-server process, not multi-worker-safe. This is why tests must set `RATELIMIT_ENABLED = False` (see TESTING.md).
- `billing.create_invoice()` re-rolls its random amount-offset (up to `MAX_OFFSET_COLLISION_RETRIES` times) on collision with another `PENDING` invoice's `expected_amount` for the same plan, since `verify_invoice()` matches purely by amount; `CryptoInvoice.matched_tx_hash` also has a DB-level unique constraint as defense in depth.
- Only **base scans** have the live `ScanEvent` progress feed; `run_advanced_scan`/`run_media_scan`/`run_api_scan` have no `progress_cb` parameter at all.
- `.env.example` at the repo root reportedly could not be edited by a prior assistant session (sandboxed, dotfile access denied) — verify `SECRET_KEY`/`ALLOW_INSECURE_DEV_SECRET_KEY`/`SESSION_COOKIE_SECURE` are present in it by hand if missing.

---

*Convention analysis: 2026-08-10*
