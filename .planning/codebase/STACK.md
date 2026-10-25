# Technology Stack

**Analysis Date:** 2026-08-10

## Languages

**Primary:**
- Python 3.12 - entire backend (`glassbox/`, `app.py`, `api/index.py`); pinned via `PYTHON_VERSION: "3.12.0"` in `render.yaml`

**Secondary:**
- Jinja2 HTML templates - `templates/`
- SQL (Alembic migration scripts) - `migrations/`

## Runtime

**Environment:**
- CPython 3.12.0 (`render.yaml` `envVars: PYTHON_VERSION`)
- No `.python-version` or `runtime.txt` file present in repo root

**Package Manager:**
- pip, dependencies declared in `requirements.txt` and `requirements-dev.txt`
- No lockfile present (no `requirements.lock`, `Pipfile.lock`, or `poetry.lock`)

## Frameworks

**Core:**
- Flask - `requirements.txt` (unpinned version); app factory in `glassbox/__init__.py`
- Flask-SQLAlchemy - `requirements.txt`; ORM layer, models in `glassbox/models.py`
- Flask-Login - `requirements.txt`; session auth, `glassbox/auth_routes.py`, `glassbox/extensions.py`
- Flask-WTF - `requirements.txt`; CSRF protection (`csrf = CSRFProtect()` in `glassbox/extensions.py`)
- Flask-Limiter - `requirements.txt`; rate limiting (`limiter = Limiter(key_func=get_remote_address)` in `glassbox/extensions.py`)
- Flask-Migrate - `requirements.txt`; Alembic-backed schema migrations (`migrate = Migrate()` in `glassbox/extensions.py`, scripts in `migrations/`)

**Testing:**
- pytest - `requirements-dev.txt`; config in `pytest.ini` (`testpaths = tests`), tests in `tests/`

**Build/Dev:**
- gunicorn - `requirements.txt`; WSGI server used in production start commands (`Procfile`, `render.yaml`)
- python-dotenv - `requirements.txt`; local `.env` loading

## Key Dependencies

**Critical:**
- requests - `requirements.txt`; HTTP client used for vulnerability checks (`glassbox/checks.py`), Polygonscan billing verification (`glassbox/billing.py`), and Resend email API (`glassbox/email_stub.py`)
- beautifulsoup4 - `requirements.txt`; HTML parsing for scan engine (`glassbox/scan_engine.py`, `glassbox/checks.py`)
- dnspython - `requirements.txt`; DNS-based checks (`glassbox/checks.py`, `glassbox/domain_verification.py`)
- Pillow - `requirements.txt`; image processing (likely screenshot/report media handling)
- openai - `requirements.txt`; used only as an OpenAI-compatible HTTP client pointed at Groq's API (`glassbox/ai_summary.py`), not against OpenAI itself
- email-validator - `requirements.txt`; email format validation, used with Flask-WTF/WTForms validators

**Infrastructure:**
- Flask-SQLAlchemy + psycopg2-binary - `requirements.txt`; Postgres driver for production DB (Neon, per `render.yaml` comments), SQLite used for local/dev
- Flask-Migrate (Alembic) - schema migrations, `migrations/`

## Configuration

**Environment:**
- Centralized in `glassbox/config.py` (`class Config`), all values read via `os.environ.get(...)`
- `.env` file supported via `python-dotenv` (existence only noted; not read for contents)
- Documented env var list: `docs/env-vars.md`

**Build:**
- No frontend build step / bundler config detected (server-rendered Jinja2 templates in `templates/`, no `package.json` found)
- `pytest.ini` - test discovery config

## Database

**ORM:** Flask-SQLAlchemy (`glassbox/extensions.py`: `db = SQLAlchemy()`)

**Dev/default:** SQLite - `glassbox/config.py` line ~92, default URI `sqlite:///` + `glassbox.db` in `APP_DIR` when `SQLALCHEMY_DATABASE_URI` env var is unset

**Production:** PostgreSQL (Neon, per `render.yaml` comments) via `SQLALCHEMY_DATABASE_URI` env var and `psycopg2-binary` driver. `glassbox/config.py` rewrites `postgres://` → `postgresql://` scheme since SQLAlchemy 1.4+ requires the latter.

**Migrations:** Alembic via Flask-Migrate, migration scripts in `migrations/`; `render.yaml`/`Procfile` both run `flask db upgrade` before starting gunicorn.

**Schema/Models:** `glassbox/models.py` - `Organization`, `User`, `PasswordReset`, `DomainVerification`, `Scan`, `ScanEvent`, `Report`, `Subscription`, `CryptoInvoice`, plus enums (`Role`, `Plan`, `SubStatus`, `ScanStatus`, `VerifyMethod`, `InvoiceStatus`, `ScanEventPhase`)

## Deployment Configuration

**Render (`render.yaml`):**
- `type: web`, `runtime: python`, `plan: free`
- Build: `pip install -r requirements.txt`
- Start: `flask db upgrade && gunicorn app:app --workers 1 --threads 4 --timeout 120`
- Health check: `/healthz`
- Env vars declared in blueprint: `FLASK_APP=app.py`, `SESSION_COOKIE_SECURE=true`, `PYTHON_VERSION=3.12.0`; secrets (SECRET_KEY, GROQ_API_KEY, RESEND_API_KEY, SQLALCHEMY_DATABASE_URI, etc.) set manually in Render dashboard, not committed

**Procfile:**
- `web: flask db upgrade && gunicorn app:app --workers 1 --threads 4 --timeout 120` (mirrors `render.yaml`, Heroku-style)

**Vercel (`vercel.json`):**
- `builds`: `api/index.py` using `@vercel/python`
- `routes`: all paths (`/(.*)`) routed to `api/index.py`
- Explicit caveat in the config's own `"//"` comment: "Web/API layer only ... Scan execution, the SSE progress feed, and local report/media storage are NOT serverless-safe as currently implemented" — see `docs/vercel-migration.md`

**Error monitoring:**
- Sentry (`sentry-sdk`, optional) - best-effort init in `glassbox/__init__.py` (`_init_sentry` around line 20), guarded so a missing `SENTRY_DSN` or missing package never raises; configured via `SENTRY_DSN` env var (`glassbox/config.py`)

## Platform Requirements

**Development:**
- Python 3.12
- SQLite (no external DB required)
- `.env` file for local secrets (via python-dotenv)

**Production:**
- Deployed to Render (primary, per `render.yaml`) as a `gunicorn` web service against a Postgres (Neon) database
- Vercel config present as an alternate/partial deployment target for the web/API layer only, with known serverless limitations documented in `docs/vercel-migration.md`

---

*Stack analysis: 2026-08-10*
