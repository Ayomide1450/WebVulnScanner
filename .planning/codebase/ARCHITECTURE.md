<!-- refreshed: 2026-08-10 -->
# Architecture

**Analysis Date:** 2026-08-10

## System Overview

```text
┌─────────────────────────────────────────────────────────────┐
│                        `app.py` (thin factory)                │
│              from webvulnscanner import create_app            │
└──────────────────────────┬────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│           `webvulnscanner/__init__.py::create_app()`          │
│  Flask app factory: ProxyFix, Sentry, extensions.init_app,    │
│  email_sender, blueprint registration, error handlers          │
└───┬───────┬───────┬───────┬───────┬───────────────────────────┘
    ▼       ▼       ▼       ▼       ▼
┌───────┐┌───────┐┌────────┐┌───────┐┌────────┐
│ auth  ││ org   ││billing ││ scan  ││ public │  Blueprints
│routes ││routes ││_routes ││routes ││_routes │  `webvulnscanner/*_routes.py`
└───┬───┘└───┬───┘└───┬────┘└───┬───┘└────────┘
    │        │        │         │
    ▼        ▼        ▼         ▼
┌─────────────────────────────────────────────────────────────┐
│  Business logic: `entitlements.py` (tier gating),             │
│  `domain_verification.py`, `billing.py`, `scan_engine.py`     │
│  (orchestrators), `checks.py` (1523-line check library),      │
│  `ai_summary.py` (Groq remediation summary)                   │
└───────────────────────────┬─────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  `models.py` (SQLAlchemy ORM) + `extensions.py` (db, login,    │
│  csrf, limiter, migrate singletons)                            │
└─────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| App factory | Wires extensions, registers 5 blueprints, error handlers, Sentry | `webvulnscanner/__init__.py` |
| Config | Env-var driven config, `TRUST_PROXY_HOPS`, SQLite `check_same_thread` engine option | `webvulnscanner/config.py` |
| Extensions | Uninitialized `db`, `login_manager`, `csrf`, `limiter`, `migrate` singletons + `user_loader` | `webvulnscanner/extensions.py` |
| Auth blueprint | Signup/login/logout/email verification/password reset | `webvulnscanner/auth_routes.py` |
| Org blueprint | Org admin panel, invites, domain-ownership verification UI | `webvulnscanner/org_routes.py` |
| Domain verification | Token issuance + DNS TXT / meta-tag lookup for org-domain ownership | `webvulnscanner/domain_verification.py` |
| Billing | Stripe (or crypto invoice) subscription logic | `webvulnscanner/billing.py` |
| Billing routes | Checkout/portal endpoints, webhook handler | `webvulnscanner/billing_routes.py` |
| Entitlements | `Tier` IntEnum, `FEATURE_REQUIREMENTS` map, `effective_tier()`, `allowed_checks()`, `domain_is_org_verified()` | `webvulnscanner/entitlements.py` |
| Scan routes | `/dashboard`, `/scan/new*`, `/scan/<id>`, `/scan/<id>/events` (SSE), `/scan/<id>/report`, `/scan/<id>/compare/<id>` | `webvulnscanner/scan_routes.py` |
| Scan engine | `run_scan`/`run_advanced_scan`/`run_media_scan`/`run_api_scan` orchestrators, `save_report()` | `webvulnscanner/scan_engine.py` |
| Checks | Individual vulnerability checks (headers, cookies, TLS, XSS/SQLi, SSRF guard, port scan, media/API discovery) | `webvulnscanner/checks.py` |
| AI summary | Optional Groq-backed remediation summary, degrades gracefully | `webvulnscanner/ai_summary.py` |
| Public routes | `/` marketing page, `/terms`, `/privacy`, `/healthz` | `webvulnscanner/public_routes.py` |
| Models | `Organization`, `User`, `PasswordReset`, `DomainVerification`, `Scan`, `ScanEvent`, `Report`, `Subscription`, `CryptoInvoice` + enums (`Role`, `Plan`, `SubStatus`, `ScanStatus`, `VerifyMethod`, `InvoiceStatus`, `ScanEventPhase`) | `webvulnscanner/models.py` |
| Decorators | `@org_admin_required` (403, no login redirect since `@login_required` already handles auth) | `webvulnscanner/decorators.py` |
| Email | Pluggable email sender (stub/Resend), stashed on `app.extensions["email_sender"]` | `webvulnscanner/email_stub.py` |

## Pattern Overview

**Overall:** Flask application-factory pattern with feature-oriented blueprints, each blueprint co-locating its routes with request-scoped business logic; deeper business logic (checks, scan orchestration, entitlements, billing) is extracted into separate non-blueprint modules that blueprints import.

**Key Characteristics:**
- `app.py` at repo root is a documented "thin shim" — its docstring explicitly states it replaced the old monolithic single-file app (WS4 cutover) and now only calls `create_app()`.
- Blueprints are registered inside `create_app()` via local imports (`from webvulnscanner.auth_routes import auth as auth_blueprint`), not at module top-level, to avoid import-order/circular-import issues with `extensions.py` and `models.py`.
- `entitlements.py` is the single sanctioned bridge between DB-backed concepts (`models.Plan`, `models.DomainVerification`) and the tier-comparison system (`Tier` `IntEnum`) — `checks.py` and `scan_engine.py` intentionally have zero dependency on `models.py` to keep the check/orchestration layer free of Flask-Login/DB coupling (per `entitlements.py` module docstring).
- Async scan execution: a `Scan(status=QUEUED)` row is created inside the request thread, then a daemon `threading.Thread` runs the orchestrator inside a pushed Flask app context (`_run_scan_in_background`, `webvulnscanner/scan_routes.py:82`), requiring `SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"check_same_thread": False}}` (`webvulnscanner/config.py`) since the background thread shares the request thread's SQLite connection pool.
- Live progress is streamed to the browser via Server-Sent Events at `GET /scan/<id>/events` (`webvulnscanner/scan_routes.py:511`), polling `ScanEvent` rows written by the background thread's `progress_cb` closure.

## Layers

**Routes (Blueprints):**
- Purpose: HTTP request/response handling, form parsing, auth/ownership checks, redirect flow.
- Location: `webvulnscanner/*_routes.py` (`auth_routes.py`, `org_routes.py`, `billing_routes.py`, `scan_routes.py`, `public_routes.py`)
- Contains: Flask `Blueprint` objects, `@login_required`/`@org_admin_required` decorated view functions, `flask_wtf` CSRF-protected forms.
- Depends on: `extensions.db`, `models`, `entitlements`, `scan_engine`, `ai_summary`, `checks` (for constants like `REPORTS_DIR`, `is_ssrf_safe_hostname`).
- Used by: Flask's URL dispatcher after registration in `create_app()`.

**Business/Domain logic:**
- Purpose: Tier gating, scan orchestration, domain verification, billing state transitions.
- Location: `webvulnscanner/entitlements.py`, `webvulnscanner/scan_engine.py`, `webvulnscanner/domain_verification.py`, `webvulnscanner/billing.py`
- Contains: Pure(ish) functions and orchestrator functions; `scan_engine.py` explicitly stays free of `current_user`/Flask-Login coupling — callers pass `tier`/`org_verified_for_domain` values computed via `entitlements.py`.
- Depends on: `checks.py` (individual check functions), `entitlements.py` (`FEATURE_REQUIREMENTS`, `allowed_checks`).
- Used by: route layer.

**Checks library:**
- Purpose: Individual vulnerability checks (headers, cookies, TLS cert, HTTPS redirect, sensitive paths, robots/sitemap, CORS, HTTP methods, open redirect, directory listing, mixed content, DNS/email security, vulnerable JS, XSS/SQLi, exposed secrets, SRI, open ports, media discovery, SQLi login/union, bruteforce, stored XSS, IDOR, API schema/wordlist/JS discovery).
- Location: `webvulnscanner/checks.py` (1523 lines — largest module in the package)
- Contains: `Finding` dataclass (`checks.py:146`), `is_ssrf_safe_hostname()` (`checks.py:214`), `REPORTS_DIR`/`DOWNLOADS_DIR` path constants, per-check functions each returning `(raw_data, [Finding, ...])`.
- Depends on: `requests`, `socket`/`ipaddress` (for SSRF guard), no Flask/DB imports.
- Used by: `scan_engine.py` orchestrators.

**Persistence:**
- Purpose: SQLAlchemy ORM models, schema owned by Alembic migrations (not implicit `db.create_all()`).
- Location: `webvulnscanner/models.py`, `migrations/` (Alembic env + versioned scripts)
- Contains: `Organization`, `User` (Flask-Login `UserMixin`), `PasswordReset`, `DomainVerification`, `Scan`, `ScanEvent`, `Report`, `Subscription`, `CryptoInvoice`, plus enums.
- Depends on: `extensions.db`.
- Used by: routes, `entitlements.py` (lazy-imported to avoid circularity).

## Data Flow

### Primary Scan Request Path (base scan)

1. User submits `POST /scan/new/base` with target URL + `authorized` checkbox (`webvulnscanner/scan_routes.py:266`).
2. Route validates the `authorized` checkbox is checked (`webvulnscanner/scan_routes.py:274`), rejects otherwise with an inline template error.
3. Route calls `_unsafe_target_error(url)` → `checks.is_ssrf_safe_hostname()` (`webvulnscanner/scan_routes.py:243`, `webvulnscanner/checks.py:214`) to reject private/loopback/link-local/reserved/multicast targets before any `Scan` row exists.
4. Route computes `tier = effective_tier(current_user)` (`webvulnscanner/entitlements.py:57`) and `org_verified = domain_is_org_verified(...)` (`webvulnscanner/entitlements.py:107`).
5. A `Scan(status=QUEUED)` row is created and committed in the request thread.
6. `_spawn_scan_thread()` (`webvulnscanner/scan_routes.py:180`) starts a daemon `threading.Thread` targeting `_run_scan_in_background()`, passing the real Flask app object (`current_app._get_current_object()`) so the thread can push its own app context.
7. Request thread immediately redirects to `GET /scan/<id>` (`scan_detail`, `webvulnscanner/scan_routes.py:470`), which renders `scan_progress.html` and opens an `EventSource` to `/scan/<id>/events`.
8. Background thread (`webvulnscanner/scan_routes.py:82`) sets `Scan.status = RUNNING`, calls `scan_engine.run_scan()` with a `progress_cb` closure that writes `ScanEvent` rows (only for real started/completed/failed phases, not tier-locked-and-skipped checks) and updates `progress_current`/`progress_total` on every callback.
9. `scan_engine.run_scan()` (`webvulnscanner/scan_engine.py`) calls `entitlements.allowed_checks()` to split requested checks into allowed/locked per `tier`, then runs allowed checks (some concurrently via `ThreadPoolExecutor`) from `checks.py`, collecting `Finding` objects.
10. On completion: if `tier >= Tier.PAID`, `ai_summary.generate_remediation_summary()` is called (never raises — degrades to no summary on Groq outage); `scan_engine.save_report()` writes the JSON report to `REPORTS_DIR`; a `Report` row is created; `Scan.status = COMPLETED`, `risk_score` set.
11. On any exception, `Scan.status = FAILED` and `error_message` is stored — the row is never left stuck at `RUNNING`.
12. Browser's `EventSource` at `/scan/<id>/events` (`webvulnscanner/scan_routes.py:511`) polls new `ScanEvent` rows via `_serialize_new_events()` (`webvulnscanner/scan_routes.py:478`) and, on terminal status, the client redirects to `/scan/<id>/report`.

### Authentication / Session Flow

1. `POST /signup` (`webvulnscanner/auth_routes.py:69`) creates a `User` + sends verification email via `app.extensions["email_sender"]`.
2. `GET /verify-email/<token>` (`webvulnscanner/auth_routes.py:113`) marks the account verified.
3. `POST /login` (`webvulnscanner/auth_routes.py:126`) authenticates via Flask-Login; `_safe_next()` (`webvulnscanner/auth_routes.py:60`) guards the post-login redirect target against open-redirect.
4. `login_manager.user_loader` (`webvulnscanner/extensions.py:38`) lazy-imports `User` to avoid a `models.py`↔`extensions.py` circular import.

**State Management:**
- Server-side session state is Flask-Login's cookie session; no client-side app state framework — templates are server-rendered Jinja2 (`templates/`) with vanilla JS driving the SSE progress view.
- Scan progress state lives entirely in the DB (`Scan.status`, `Scan.progress_current/total`, `ScanEvent` rows), not in-memory — this is what makes the SSE endpoint safely re-pollable/stateless per request.

## Key Abstractions

**`Finding` dataclass:**
- Purpose: Uniform representation of a single vulnerability finding (severity, message, etc.) returned by every check function.
- Examples: `webvulnscanner/checks.py:146`, consumed throughout `scan_engine.py` (`SEVERITY_WEIGHT`, `SEVERITY_ORDER`, `asdict(f)`).
- Pattern: every `check_*()` function returns `(raw_data_for_display, [Finding, ...])`.

**`Tier` / `FEATURE_REQUIREMENTS`:**
- Purpose: Ordered (`IntEnum`) tier-gating system (`FREE < PAID < ORG_VERIFIED`) mapped against a flat dict of check-name → minimum tier.
- Examples: `webvulnscanner/entitlements.py:22-54`.
- Pattern: `allowed_checks(names, tier)` splits a list of check names into `(allowed, locked)` via one `<=` comparison per name; a missing key defaults to `Tier.FREE` (allowed) with a logged warning, treated as a map-sync bug rather than a security failure mode.

**Scan orchestrator functions:**
- Purpose: One function per scan type (`run_scan`, `run_advanced_scan`, `run_media_scan`, `run_api_scan`), each assembling `check_*()` results into one report dict (`target`, `hostname`, `scanned_at`, `score`, `risk_grade`, `severity_counts`, `findings`, plus type-specific keys).
- Examples: `webvulnscanner/scan_engine.py`.
- Pattern: `run_scan`/`run_advanced_scan` take `tier`/`org_verified_for_domain` and gate internally via `entitlements.allowed_checks`; `run_media_scan`/`run_api_scan` are NOT gated internally — gating is enforced one level up in the route before the orchestrator is even called (an intentional asymmetry documented in `scan_engine.py`'s module docstring).

## Entry Points

**`app.py` (WSGI entry):**
- Location: `app.py`
- Triggers: `flask run` / gunicorn / Render's Procfile
- Responsibilities: Calls `create_app()` only; no routes, no logic.

**`api/index.py`:**
- Location: `api/index.py`
- Triggers: Vercel serverless deployment entry point (see `docs/vercel-migration.md`, `vercel.json`)
- Responsibilities: Adapts the Flask app for Vercel's Python runtime.

**`create_app()` (app factory):**
- Location: `webvulnscanner/__init__.py:41`
- Triggers: Called once per process by `app.py`/`api/index.py`/tests' `conftest.py`.
- Responsibilities: Extension init, ProxyFix, Sentry, email sender, blueprint registration, error handlers, model import for `db.Model` registration.

## Architectural Constraints

- **Threading:** Request handling is standard Flask (single request per thread under a WSGI server); each scan spawns its own daemon `threading.Thread` (`_spawn_scan_thread`, `webvulnscanner/scan_routes.py:180`) that pushes a fresh Flask app context rather than reusing the request's context.
- **SQLite thread-sharing:** Background scan threads share the request thread's SQLite connection pool, requiring `check_same_thread: False` in `SQLALCHEMY_ENGINE_OPTIONS` (`webvulnscanner/config.py`) — a documented fragility point if the DB is swapped or concurrency increases.
- **In-memory rate limiting:** `Limiter` (`webvulnscanner/extensions.py:29`) uses Flask-Limiter's default in-memory storage — limits are NOT shared across multiple gunicorn worker processes; the module docstring flags this as needing a Redis backend if the app scales beyond one worker.
- **Circular imports avoided by convention:** `entitlements.py` lazily imports `models` inside functions (not at module top) specifically to keep `checks.py`/`scan_engine.py` free of any `models`/Flask-Login dependency; `extensions.py`'s `user_loader` lazily imports `User` for the same reason.
- **Global state:** `db`, `login_manager`, `csrf`, `limiter`, `migrate` are module-level singletons in `webvulnscanner/extensions.py`, uninitialized until `create_app()` calls `.init_app(app)`.

## Anti-Patterns

### None identified as active anti-patterns in the reviewed code

The codebase's own docstrings call out and justify departures from "obvious" simpler designs (e.g., per-scan-type routes instead of one multiplexed route; asymmetric gating between `run_scan`/`run_media_scan`). No unexplained anti-pattern was found during this pass; see CONCERNS.md-equivalent notes below for residual gaps.

**SSRF guard is submission-time only:**
**What happens:** `is_ssrf_safe_hostname()` (`webvulnscanner/checks.py:214`) validates the hostname via `socket.getaddrinfo()` at scan-submission time only; the actual HTTP requests made later during the scan re-resolve DNS independently.
**Why it's wrong:** A DNS-rebinding attacker controlling their own DNS could pass the submission-time check then resolve to a private/internal address for the real scan request.
**Do this instead:** The module docstring itself acknowledges this: closing the gap fully would require a custom `requests` Transport/Adapter that pins and connects to the exact IP verified at submission time; this is documented as a known, accepted residual gap, not an oversight.

## Error Handling

**Strategy:** Centralized Flask `errorhandler`s for 404/500/429 render themed templates (`webvulnscanner/__init__.py:104-115`) instead of Flask's default unstyled error pages; the 500 handler explicitly calls `db.session.rollback()` before rendering.

**Patterns:**
- Ownership checks use `abort(404)` (not 403) to avoid confirming a resource's existence to an unauthorized viewer — documented convention shared by `scan_routes.py:_check_ownership` and `org_routes.py`.
- Background scan thread wraps orchestrator calls in `try/except Exception` and always transitions `Scan.status` to `FAILED` with `error_message` set rather than leaving the row `RUNNING` indefinitely (`webvulnscanner/scan_routes.py:173`).
- `ai_summary.generate_remediation_summary()` never raises — a Groq API outage degrades to "no AI summary" rather than failing the whole scan.

## Cross-Cutting Concerns

**Logging:** Standard `logging` module (e.g., `entitlements.py`'s warning on a missing `FEATURE_REQUIREMENTS` key); Sentry is optionally wired in `_init_sentry()` (`webvulnscanner/__init__.py:16`) as a best-effort, silently-no-op-if-absent integration.

**Validation:** Form-field presence/stripping done manually in route functions (e.g., `_parse_advanced_form()`, `webvulnscanner/scan_routes.py:196`); CSRF protection via `flask_wtf.CSRFProtect` initialized globally in `create_app()`.

**Authentication/Authorization:** Flask-Login (`@login_required`) for session auth; `@org_admin_required` (`webvulnscanner/decorators.py:14`) for org-scoped admin actions (403, not a login redirect, since `@login_required` already guarantees an authenticated user); tier-based feature gating layered on top via `entitlements.py`; every user-supplied scan target is checked by `is_ssrf_safe_hostname()` before a `Scan` row is created; every "new scan" form requires an explicit "I own or am authorized to test this domain" checkbox (`authorized`/`authorized_adv`/`authorized_media`/`authorized_api` — `webvulnscanner/scan_routes.py:274,318,382,436`), rejected server-side if unchecked.

---

*Architecture analysis: 2026-08-10*
