"""
Config for the webvulnscanner package.

Reads everything from the environment (via python-dotenv, so a local `.env`
file next to the repo root is picked up automatically) with sane local-dev
fallbacks. See `.env.example` at the repo root for the full list of
supported variables.
"""
import logging
import os

from dotenv import load_dotenv

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(APP_DIR, ".env"))

_DEV_SECRET_KEY = "dev-only-insecure-secret-key-change-me"


def _allow_insecure_dev_secret():
    return os.environ.get("ALLOW_INSECURE_DEV_SECRET_KEY", "").lower() in ("1", "true", "yes")


_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    # A missing SECRET_KEY used to fall back to a hardcoded, source-visible
    # string with only a log line as a warning - since this key signs
    # session cookies, Flask-Login's remember-me cookie, and org-invite
    # tokens (org_routes.py), a deploy that forgot to set it would silently
    # run with a publicly-known secret (full session forgery / CSRF
    # bypass), not just "insecure for advanced use" as the old warning
    # implied. Fail fast instead - the only way to get the old behavior
    # back is to opt in explicitly, one env var at a time, never silently.
    if _allow_insecure_dev_secret():
        logging.warning(
            "SECRET_KEY is not set - using the insecure placeholder key "
            "because ALLOW_INSECURE_DEV_SECRET_KEY is set. Never set that "
            "variable outside local development."
        )
        _secret_key = _DEV_SECRET_KEY
    else:
        raise RuntimeError(
            "SECRET_KEY is not set. Generate one (e.g. `python -c "
            "\"import secrets; print(secrets.token_hex(32))\"`) and set it "
            "in your environment or .env file. For local development only, "
            "set ALLOW_INSECURE_DEV_SECRET_KEY=true instead to use an "
            "insecure placeholder key."
        )


def _engine_options_for(db_uri):
    """Pure function (no app/class-body coupling) so tests can exercise both
    branches directly - see tests/test_config.py.

    check_same_thread only means anything to SQLite (scans run in a
    background thread that writes to the same connection pool as the
    request thread) - Postgres connections are already safe to share across
    threads via the pool, and passing this connect_arg to psycopg2 would be
    a TypeError, not a no-op.

    pool_pre_ping/pool_recycle only matter for a real network DB (Postgres/
    Neon): a managed Postgres provider can silently close an idle connection
    server-side (confirmed live: psycopg2.OperationalError "server closed
    the connection unexpectedly") - pool_pre_ping issues a cheap SELECT 1
    before handing a pooled connection back out and transparently
    reconnects if it's dead, and pool_recycle (280s, comfortably under
    Neon's typical idle timeout) forces a connection to be replaced before
    it gets that stale in the first place. Neither means anything for
    SQLite's single local file.
    """
    if db_uri.startswith("sqlite"):
        return {"connect_args": {"check_same_thread": False}}
    return {"pool_pre_ping": True, "pool_recycle": 280}


class Config:
    SECRET_KEY = _secret_key

    # Secure by default. Local dev over plain http needs SESSION_COOKIE_SECURE=false
    # (a browser will not set a Secure cookie over http at all, so leaving
    # this true against a plain-http dev server just means login silently
    # doesn't persist - set the env var rather than flipping the default).
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() not in (
        "0", "false", "no",
    )
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"

    # Idle-session timeout (security hardening): a logged-in user is signed
    # out server-side after this many minutes with no request, regardless
    # of "Remember me" - see webvulnscanner/__init__.py's
    # _enforce_idle_timeout before_request hook, which is what actually
    # reads this value. Overridable via env for e.g. a longer local-dev
    # session; production keeps the 5-minute default.
    IDLE_TIMEOUT_MINUTES = int(os.environ.get("IDLE_TIMEOUT_MINUTES", "5"))

    _db_uri = os.environ.get(
        "SQLALCHEMY_DATABASE_URI",
        "sqlite:///" + os.path.join(APP_DIR, "webvulnscanner.db"),
    )
    # Render/Heroku/most managed-Postgres providers (Neon included) hand out
    # connection strings starting "postgres://" - SQLAlchemy 1.4+ only
    # accepts the "postgresql://" scheme, so this rewrite is required, not
    # cosmetic, for the app to even boot against one of those URLs.
    if _db_uri.startswith("postgres://"):
        _db_uri = _db_uri.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = _db_uri
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = _engine_options_for(_db_uri)

    WTF_CSRF_ENABLED = os.environ.get("WTF_CSRF_ENABLED", "true").lower() not in (
        "0",
        "false",
        "no",
    )

    # Flask-Limiter reads this key from app.config automatically at
    # init_app() time (see extensions.py's Limiter() construction, which
    # deliberately doesn't pass storage_uri itself). Left unset, Flask-
    # Limiter's own default applies (in-memory storage) - unchanged
    # behavior for local dev / single-process deploys. Set to a Redis URL
    # (e.g. "redis://...") once running behind more than one worker
    # process, where in-memory counters would silently stop being shared -
    # see extensions.py's docstring for why that's not just a nice-to-have
    # on Vercel/multi-worker gunicorn specifically.
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "")

    # Trust exactly one reverse-proxy hop's X-Forwarded-* headers (Render's
    # own edge proxy, or Vercel's). Without this, request.remote_addr is
    # always the proxy's IP for every request behind it - Flask-Limiter's
    # get_remote_address key func would then bucket every visitor into one
    # shared rate limit instead of limiting per real client IP, and
    # request.is_secure would read as False even over real HTTPS (wrong
    # scheme in any url_for(..., _external=True) link, e.g. password-reset
    # emails). Defaults on, since every documented deployment target
    # (Render/Vercel) sits behind exactly one such proxy; set
    # TRUST_PROXY_HOPS=0 to disable if running directly, unproxied.
    TRUST_PROXY_HOPS = int(os.environ.get("TRUST_PROXY_HOPS", "1"))

    # Cloudflare Turnstile (bot-check on signup, auth_routes.py). Empty by
    # default: signup() skips verification entirely (with a log line) if
    # either key is missing, same degrade-gracefully convention as
    # GROQ_API_KEY/SENTRY_DSN - local dev never needs a real Turnstile
    # account. TURNSTILE_SITE_KEY is public (embedded in signup.html's
    # widget script); TURNSTILE_SECRET_KEY is not - it's only ever used
    # server-side, in the siteverify POST.
    TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
    TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")

    # Error monitoring (Sentry) - see webvulnscanner/__init__.py's
    # _init_sentry(). Empty by default: sentry-sdk isn't a hard dependency
    # (not in requirements.txt) and initialization is skipped entirely,
    # with a log line, if either the package or this DSN is missing - same
    # degrade-gracefully convention as GROQ_API_KEY/ai_summary.py.
    SENTRY_DSN = os.environ.get("SENTRY_DSN", "")

    # Crypto billing (self-built USDT/USDC invoicing, see billing.py in a later workstream)
    CRYPTO_RECEIVING_ADDRESS = os.environ.get("CRYPTO_RECEIVING_ADDRESS", "")
    CRYPTO_CHAIN = os.environ.get("CRYPTO_CHAIN", "polygon")
    POLYGONSCAN_API_KEY = os.environ.get("POLYGONSCAN_API_KEY", "")
    USDT_CONTRACT_ADDRESS = os.environ.get("USDT_CONTRACT_ADDRESS", "")
    USDC_CONTRACT_ADDRESS = os.environ.get("USDC_CONTRACT_ADDRESS", "")
    INVOICE_EXPIRY_MINUTES = int(os.environ.get("INVOICE_EXPIRY_MINUTES", "60"))
    INVOICE_MIN_CONFIRMATIONS = int(os.environ.get("INVOICE_MIN_CONFIRMATIONS", "5"))

    # Email delivery mode: "console" prints to stdout (see email_stub.py).
    EMAIL_MODE = os.environ.get("EMAIL_MODE", "console")
    RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
    RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "")

    # AI-assisted remediation summaries (see webvulnscanner/ai_summary.py) -
    # Groq's free, OpenAI-compatible API serving an open-source model.
    # Empty-string default: generate_remediation_summary() treats a missing
    # key as "no summary available" and degrades gracefully, it does not
    # fail the scan.
    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
    GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")

    # In-process daemon-thread scheduler (Phase 1, D-01/webvulnscanner/scheduler.py) -
    # ticks periodically to fire due Assets. Default on; set false to disable
    # entirely (e.g. ops maintenance) without a code change. TestConfig
    # (tests/conftest.py) sets this False unconditionally - required, or
    # every test in the suite leaks an infinite background thread against a
    # soon-to-be-deleted SQLite file (see 01-RESEARCH.md Pitfall 2).
    SCHEDULER_ENABLED = os.environ.get("SCHEDULER_ENABLED", "true").lower() not in (
        "0", "false", "no",
    )
    SCHEDULER_POLL_INTERVAL_SECONDS = int(os.environ.get("SCHEDULER_POLL_INTERVAL_SECONDS", "60"))
