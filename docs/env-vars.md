# Environment variables reference

Source of truth: `webvulnscanner/config.py`. `.env.example` at the repo root is the local-dev
template but is sandbox-blocked from editing by this assistant (dotfile directory access
denied) — this file is the maintained reference instead. Never commit real values for any of
these; set them in Render's/Vercel's dashboard Environment tab.

## Required in every environment

| Variable | Purpose | Notes |
|---|---|---|
| `SECRET_KEY` | Signs session cookies, remember-me cookie, org-invite tokens | `config.py` raises `RuntimeError` at import time if unset. For local dev only, set `ALLOW_INSECURE_DEV_SECRET_KEY=true` instead of a real key — never in a deployed environment. |
| `SQLALCHEMY_DATABASE_URI` | Database connection string | Defaults to a local SQLite file if unset. `postgres://` URIs are auto-rewritten to `postgresql://` (SQLAlchemy 2.x requirement). Production should point at Neon Postgres. |

## Session / security

| Variable | Purpose | Notes |
|---|---|---|
| `SESSION_COOKIE_SECURE` | Marks session/remember cookies `Secure` (HTTPS-only) | Defaults to `true`. Set to `false` for local `http://` dev, or the browser won't send the cookie back at all. |
| `WTF_CSRF_ENABLED` | Enables CSRF protection | Defaults to `true`. Disabled only by the test suite's `TestConfig`. |

## AI remediation summaries (Groq)

| Variable | Purpose | Notes |
|---|---|---|
| `GROQ_API_KEY` | Groq API key (OpenAI-compatible endpoint) | Missing/invalid key degrades gracefully — `generate_remediation_summary()` returns `None` and the report just omits the AI section. Paid tier and above. |
| `GROQ_MODEL` | Model name | Defaults to `llama-3.1-8b-instant`. |

## Crypto billing (USDT/USDC on Polygon)

| Variable | Purpose | Notes |
|---|---|---|
| `CRYPTO_RECEIVING_ADDRESS` | Wallet address invoices are issued against | |
| `CRYPTO_CHAIN` | Chain identifier | Defaults to `polygon`. |
| `POLYGONSCAN_API_KEY` | Used by `verify_invoice()` to check for a matching on-chain transfer | |
| `USDT_CONTRACT_ADDRESS` / `USDC_CONTRACT_ADDRESS` | Token contract addresses on the configured chain | |
| `INVOICE_EXPIRY_MINUTES` | How long a pending invoice stays valid | Defaults to `60`. |
| `INVOICE_MIN_CONFIRMATIONS` | Confirmations required before an on-chain transfer counts | Defaults to `5`. |

## Email

| Variable | Purpose | Notes |
|---|---|---|
| `EMAIL_MODE` | `console` (dev stub, prints to server log) or `resend` (real delivery) | Defaults to `console`. |
| `RESEND_API_KEY` | Resend API key | Required when `EMAIL_MODE=resend`. |
| `RESEND_FROM_EMAIL` | Sending address | Must be a domain verified in Resend. |

## Rate limiting

| Variable | Purpose | Notes |
|---|---|---|
| `RATELIMIT_STORAGE_URI` | Flask-Limiter storage backend | Defaults to empty, which Flask-Limiter treats as unset and falls back to in-memory storage (fine for a single dev-server process). Set to a Redis URL (e.g. `redis://...`, such as Upstash's) once running behind more than one worker process — otherwise counters aren't shared and rate limits become per-process instead of global. See `webvulnscanner/extensions.py`. |

## Reverse proxy trust

| Variable | Purpose | Notes |
|---|---|---|
| `TRUST_PROXY_HOPS` | Number of reverse-proxy hops whose `X-Forwarded-*` headers to trust | Defaults to `1` (Render's and Vercel's edge proxies are both exactly one hop). Without this, `request.remote_addr` is always the proxy's IP for every visitor — silently breaking per-IP rate limiting into one shared bucket — and `request.is_secure` reads `False` even over real HTTPS, producing `http://` links in any `url_for(..., _external=True)` (e.g. password-reset emails). Set to `0` only for a direct, unproxied deployment — trusting forwarded headers from an untrusted, non-proxied client would let it spoof its own IP/scheme. |

## Error monitoring (Sentry)

| Variable | Purpose | Notes |
|---|---|---|
| `SENTRY_DSN` | Sentry project DSN | Empty by default. `sentry-sdk` is **not** in `requirements.txt` — `webvulnscanner/__init__.py`'s `_init_sentry()` is a no-op (with a log line) if either the DSN or the package is missing, same degrade-gracefully convention as `GROQ_API_KEY`. To activate: add `sentry-sdk[flask]` to `requirements.txt` and set this variable. |

## Planned, not yet wired into the code (target Vercel architecture)

These don't exist in `config.py` yet — listed here so they're not a surprise when the
worker/queue/storage pieces described in `docs/vercel-migration.md` get built:

| Variable (proposed) | Purpose |
|---|---|
| `QUEUE_REDIS_URL` | Upstash Redis (or similar) connection string for the scan job queue |
| `OBJECT_STORAGE_*` (bucket/key/secret/endpoint) | Cloudflare R2 or S3-compatible bucket for report JSON / media downloads, replacing local `reports/`/`downloads/` |

## Reference: what's already documented in `render.yaml`

Non-secret vars declared there today: `FLASK_APP`, `SESSION_COOKIE_SECURE`, `PYTHON_VERSION`.
Everything else (`SECRET_KEY`, `GROQ_API_KEY`, `SQLALCHEMY_DATABASE_URI`, crypto/email vars) is
set manually in Render's dashboard, never committed — the same pattern applies to Vercel's
Environment tab.
