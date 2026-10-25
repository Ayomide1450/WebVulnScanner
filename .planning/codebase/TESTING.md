# Testing Patterns

**Analysis Date:** 2026-08-10

## Test Framework

**Runner:**
- pytest, configured via `pytest.ini`:
  ```ini
  [pytest]
  testpaths = tests
  ```
- Dev/test dependencies pinned in `requirements-dev.txt` (installed separately from `requirements.txt`).

**Assertion Library:**
- Plain `assert` statements (pytest-native), no separate assertion library.

**Run Commands:**
```bash
pip install -r requirements-dev.txt
pytest                                  # run all tests
.venv\Scripts\python -m pytest          # equivalent, explicit interpreter (Windows)
pytest -v                               # CI runs this (.github/workflows/tests.yml)
```
No coverage tool or `--cov` flag is configured anywhere in the repo (no `.coveragerc`, no `pytest-cov` reference found).

## CI Config

`.github/workflows/tests.yml`:
- Triggers on push to any branch (`branches: ["**"]`) and on pull_request.
- `ubuntu-latest`, Python 3.12 (`actions/setup-python@v5`), pip cache keyed on `requirements-dev.txt`.
- Steps: `pip install -r requirements-dev.txt` then `pytest -v`.
- No `.env` or real secrets are needed in CI — `tests/conftest.py` defaults every env var `config.py` reads at import time, so the suite is fully self-contained (comment directly in the workflow file references CLAUDE.md's "Tests" section).

## Test File Organization

**Location:** All tests live flat under `tests/` (no subdirectories), one file per feature area:

| File | Lines | Covers |
|---|---|---|
| `tests/conftest.py` | 127 | Shared fixtures, factories |
| `tests/test_auth_flows.py` | 414 | Signup/verify-email/login/logout/forgot-password/reset-password flows, anti-user-enumeration, single-use tokens, `_safe_next()` open-redirect guard, `/login` rate-limit 429 |
| `tests/test_billing.py` | 259 | Crypto invoice creation/verification logic (`glassbox/billing.py`) |
| `tests/test_billing_routes.py` | 58 | Billing blueprint routes |
| `tests/test_config.py` | 98 | `config.py`'s `_engine_options_for()` (SQLite vs Postgres branches), `postgres://`→`postgresql://` rewrite |
| `tests/test_email_stub.py` | 52 | `glassbox/email_stub.py` console/Resend email sender selection |
| `tests/test_entitlements.py` | 247 | `entitlements.py` tier-gating: `allowed_checks`, `effective_tier`, `domain_is_org_verified`, plus a regression test that `FEATURE_REQUIREMENTS` covers every check name `run_scan`'s jobs dict can dispatch |
| `tests/test_org_routes.py` | 15 | Org routes (minimal coverage) |
| `tests/test_public_routes.py` | 33 | Marketing/public routes |
| `tests/test_scan_events.py` | 338 | `ScanEvent` model, `CHECK_LABELS`/`CHECK_CATEGORY` coverage regression tests, `run_scan()`'s `progress_cb` call sequence against stubbed check functions, `_serialize_new_events`, `scan_events()` SSE ownership guard |
| `tests/test_scan_ownership.py` | 167 | `_check_ownership`'s IDOR guard in `scan_routes.py` across all four call sites |
| `tests/test_scan_routes.py` | 68 | Scan route-level behavior |
| `tests/test_ssrf_guard.py` | 213 | `checks.is_ssrf_safe_hostname()` / `scan_routes._unsafe_target_error()` — mocked `socket.getaddrinfo` across the address-class matrix, plus route-level tests confirming a blocked target creates no `Scan` row |
| `tests/__init__.py` | 0 | Package marker only |

**Naming:** `test_<area>.py` files; test functions/methods follow pytest default `test_*` discovery (no explicit class-based suites observed in `conftest.py`'s pattern, though individual files may use `TestX` classes — check the specific file if adding tests there).

## Fixtures (`tests/conftest.py`)

- **`app(tmp_path)`**: builds a fresh Flask app per test via `create_app(_AppConfig)`, where `_AppConfig` subclasses a `TestConfig(Config)` with `TESTING=True`, `WTF_CSRF_ENABLED=False`, `RATELIMIT_ENABLED=False`, and a per-test `SQLALCHEMY_DATABASE_URI` pointing at `sqlite:///{tmp_path}/test.db`. Creates schema via `_db.create_all()` inside an `app_context()` (not a real Alembic migration replay), tears down via `_db.session.remove()` + `_db.drop_all()`.
- **`client(app)`**: `app.test_client()`.
- **`db(app)`**: yields the `db` extension with an app context held open for the life of the test, so direct ORM calls work without every test needing its own `with app.app_context():` block.
- **Factory functions** (plain functions, not fixtures — call multiple times with different args to build multi-user/multi-org scenarios; require the `db` fixture first for an active app context):
  - `make_org(plan=Plan.FREE, name="Test Org")`
  - `make_user(email, org=None, role=Role.MEMBER, password="password123", verified=True)`
  - `make_scan(user, org=None, target_url="https://example.com", scan_type="base", status=ScanStatus.QUEUED)`
  - `login(client, email, password="password123")` — logs in via the real `/login` route (not a session-cookie shortcut) so ownership/entitlement tests exercise the same auth path a real request would.

## Environment Setup for Tests

`tests/conftest.py` sets safe defaults with `os.environ.setdefault(...)` **before** importing anything under `glassbox/` (since `config.py` reads env vars at module-import time and raises `RuntimeError` if `SECRET_KEY` is unset):
```python
os.environ.setdefault("SECRET_KEY", "test-only-secret-never-used-outside-pytest")
os.environ.setdefault("SESSION_COOKIE_SECURE", "false")  # test client talks http, not https
os.environ.setdefault("EMAIL_MODE", "console")
os.environ.setdefault("GROQ_API_KEY", "")
```
`setdefault` (not a hard assignment) is used deliberately so a developer's real `.env` (loaded via python-dotenv inside `config.py`) still wins for values they've explicitly set — but no test depends on that; every value has a safe, deterministic fallback so the suite runs green in CI with no `.env` file at all.

## Documented Testing Gotchas (from CLAUDE.md / conftest.py docstrings)

- **SQLite `tmp_path` file, not `:memory:`.** An in-memory SQLite DB is a single connection only; this app's `SQLALCHEMY_ENGINE_OPTIONS` (`check_same_thread: False`) plus Flask-SQLAlchemy's per-request connections need a real file to share state across them — same constraint documented in `config.py` for the background-scan-thread case. See the `app` fixture's docstring in `tests/conftest.py`.
- **Rate limiting must stay disabled in most tests.** `extensions.limiter` (Flask-Limiter) uses in-memory storage that is a **process-wide singleton shared across every test app instance** — without `RATELIMIT_ENABLED = False` in `TestConfig`, rate-limit counters from one test's requests would leak into the next test's app. One dedicated test in `tests/test_auth_flows.py` turns `RATELIMIT_ENABLED` back on to confirm `/login`'s 10/min limit actually trips a 429 — every other test leaves rate limiting off.
- **`email_validator` (backing WTForms' `Email()` validator) statically rejects reserved TLDs** (`.test`/`.invalid`/`.localhost`) even with deliverability checking off. Use `.com`/`.org`/`.dev`-style fake domains for test fixture emails, **not** `.test`.
- **Nested `app_context()` causes stale reads in background-thread tests.** `tests/test_scan_events.py` calls `_run_scan_in_background` with short-lived `with app.app_context():` blocks per call rather than the shared `db` fixture's held-open context — holding an outer context open while calling it causes its otherwise-successful commits to read back stale through that same session (see that module's docstring; described in CLAUDE.md as "a broader instance of the concurrency caveat" around SQLite/background-thread state sharing).
- **Schema creation in tests bypasses Alembic.** `create_app()` no longer calls `db.create_all()` itself (schema is Alembic's job via `migrations/` — see CONVENTIONS.md's migrations gotcha) — the `app` fixture calls `_db.create_all()` directly for instant fresh schema per test run, not a real migration replay. Keep this in mind: a test-suite pass does not verify that `migrations/versions/*.py` files are consistent with `models.py`.
- **No `.env` required for tests** — `tests/conftest.py` plus `TestConfig` fully self-contain the suite; CI (`.github/workflows/tests.yml`) explicitly relies on this.

---

*Testing analysis: 2026-08-10*
