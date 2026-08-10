# External Integrations

**Analysis Date:** 2026-08-10

## APIs & External Services

**Crypto payment verification — Polygonscan:**
- Service: Polygonscan free-tier `tokentx` API, used to verify USDT/USDC crypto payments on the Polygon chain
  - Endpoint: `https://api.polygonscan.com/api` (`POLYGONSCAN_API_URL` in `webvulnscanner/billing.py`)
  - Client: `requests.get(...)` with a 10s timeout (`POLYGONSCAN_TIMEOUT`), `webvulnscanner/billing.py` (~line 141)
  - Auth: `POLYGONSCAN_API_KEY` env var, read via `current_app.config["POLYGONSCAN_API_KEY"]` (set in `webvulnscanner/config.py`)
  - Purpose: This is a self-built billing system, not Stripe/a payment processor. It generates a `CryptoInvoice` (`webvulnscanner/models.py`) with a unique-amount offset, then polls Polygonscan's `tokentx` endpoint to match an incoming on-chain transfer to a receiving address (`CRYPTO_RECEIVING_ADDRESS` env var) by amount. Contract addresses for USDT/USDC are configured via `USDT_CONTRACT_ADDRESS`/`USDC_CONTRACT_ADDRESS` env vars.
  - Related config: `CRYPTO_CHAIN` (default `"polygon"`), `INVOICE_EXPIRY_MINUTES` (default 60), `INVOICE_MIN_CONFIRMATIONS` (default 5) — all in `webvulnscanner/config.py`
  - Routes: `webvulnscanner/billing_routes.py`; core logic: `webvulnscanner/billing.py`

**AI remediation summaries — Groq:**
- Service: Groq's free, OpenAI-compatible chat completion API, used to generate natural-language remediation summaries for scan reports
  - Endpoint: `https://api.groq.com/openai/v1` (`GROQ_BASE_URL` in `webvulnscanner/ai_summary.py`)
  - Client: `openai` Python package (`from openai import OpenAI`) instantiated with `base_url=GROQ_BASE_URL` — explicitly not calling OpenAI itself, just reusing its client as an HTTP wrapper (`webvulnscanner/ai_summary.py` `_client()`, ~line 51)
  - Auth: `GROQ_API_KEY` env var (`webvulnscanner/config.py`)
  - Model: `GROQ_MODEL` env var, default `"llama-3.1-8b-instant"` (`webvulnscanner/config.py`)
  - Function: `generate_remediation_summary(report, api_key, model)` in `webvulnscanner/ai_summary.py` (~line 60) — degrades gracefully: returns no summary (never raises) if the API key is missing/invalid or the Groq call fails, per the module's own docstring and a `logging.warning(...)` at ~line 92

**Transactional email — Resend:**
- Service: Resend HTTP API for real transactional email (verification links, password resets, org invites)
  - Endpoint: `https://api.resend.com/emails` (`ResendEmailSender.send()`, `webvulnscanner/email_stub.py`)
  - Client: plain `requests.post(...)` with a 10s timeout, no `resend` SDK package used
  - Auth: `RESEND_API_KEY` env var, sent as `Authorization: Bearer {api_key}` header
  - Sender identity: `RESEND_FROM_EMAIL` env var
  - Activation: controlled by `EMAIL_MODE` env var (`webvulnscanner/config.py`); `EMAIL_MODE=resend` selects `ResendEmailSender`, default mode is `"console"` which uses `ConsoleEmailSender` (prints to stdout, no real delivery — dev-only stub)
  - Fail-fast behavior: `ResendEmailSender.__init__` raises `RuntimeError` immediately if `RESEND_API_KEY` or `RESEND_FROM_EMAIL` is missing, so a misconfigured `EMAIL_MODE=resend` deploy fails at startup rather than silently dropping emails (`webvulnscanner/email_stub.py`)
  - Sender is instantiated in `create_app()` and stashed at `app.extensions["email_sender"]`, accessed via `current_app.extensions["email_sender"]` from route code (`webvulnscanner/__init__.py`, `webvulnscanner/auth_routes.py`, `webvulnscanner/org_routes.py`)

## Data Storage

**Databases:**
- SQLite (dev/default) or PostgreSQL/Neon (production)
  - Connection: `SQLALCHEMY_DATABASE_URI` env var (`webvulnscanner/config.py`)
  - Client/ORM: Flask-SQLAlchemy (`webvulnscanner/extensions.py`)

**File Storage:**
- Local filesystem only — no cloud object storage (S3, GCS, etc.) integration detected. `docs/vercel-migration.md` and `vercel.json`'s own comment flag that "local report/media storage" is not serverless-safe as currently implemented.

**Caching:**
- Flask-Limiter's in-memory storage is the default rate-limit backend (`RATELIMIT_STORAGE_URI` env var, empty by default) — `webvulnscanner/extensions.py` comments flag this as unsuitable for multi-worker gunicorn deployments; no Redis or other shared cache integration detected.

## Authentication & Identity

**Auth Provider:**
- Custom (no third-party auth provider like Auth0/Clerk detected)
  - Implementation: Flask-Login session-based auth, `webvulnscanner/auth_routes.py`, user loader in `webvulnscanner/extensions.py`
  - Password reset / email verification flows use the internal email sender abstraction (`webvulnscanner/email_stub.py`) rather than a third-party auth API

## Monitoring & Observability

**Error Tracking:**
- Sentry (optional, best-effort) — `sentry-sdk` with `FlaskIntegration`, initialized in `webvulnscanner/__init__.py` (`_init_sentry`, ~line 20-38), `traces_sample_rate=0.1`
  - Auth: `SENTRY_DSN` env var (`webvulnscanner/config.py`); init is skipped silently if the DSN is unset or the package import fails — never raises, never required (matches the same degrade-gracefully convention as `GROQ_API_KEY`, per code comment)

**Logs:**
- Standard Python `logging` module used for warnings (e.g. Groq call failures in `webvulnscanner/ai_summary.py`); no structured logging service (e.g. Datadog, Logtail) detected

## CI/CD & Deployment

**Hosting:**
- Render (primary) — `render.yaml`, gunicorn web service
- Vercel (alternate, web/API layer only, partial/limited) — `vercel.json`, `api/index.py`, documented caveats in `docs/vercel-migration.md`

**CI Pipeline:**
- None detected (no `.github/workflows/`, no other CI config found in repo root)

## Environment Configuration

**Required/notable env vars** (from `webvulnscanner/config.py`, full list in `docs/env-vars.md`):
- `SECRET_KEY` — Flask session secret
- `SQLALCHEMY_DATABASE_URI` — DB connection string
- `SESSION_COOKIE_SECURE`, `WTF_CSRF_ENABLED`, `RATELIMIT_STORAGE_URI`, `TRUST_PROXY_HOPS`
- `SENTRY_DSN` — Sentry error tracking
- `CRYPTO_RECEIVING_ADDRESS`, `CRYPTO_CHAIN`, `POLYGONSCAN_API_KEY`, `USDT_CONTRACT_ADDRESS`, `USDC_CONTRACT_ADDRESS`, `INVOICE_EXPIRY_MINUTES`, `INVOICE_MIN_CONFIRMATIONS` — Polygonscan/crypto billing
- `EMAIL_MODE`, `RESEND_API_KEY`, `RESEND_FROM_EMAIL` — email delivery
- `GROQ_API_KEY`, `GROQ_MODEL` — AI remediation summaries

**Secrets location:**
- Local: `.env` file (loaded via python-dotenv; existence not content-inspected per this document's constraints)
- Production (Render): set manually in the Render dashboard's Environment tab, explicitly not committed to `render.yaml` (per the file's own header comment)

## Webhooks & Callbacks

**Incoming:**
- None detected — crypto payment confirmation is polled (`webvulnscanner/billing.py` calls out to Polygonscan), not received via webhook

**Outgoing:**
- None detected beyond the outbound API calls listed above (Polygonscan, Groq, Resend)

---

*Integration audit: 2026-08-10*
