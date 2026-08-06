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
    # check_same_thread only means anything to SQLite (scans run in a
    # background thread that writes to the same connection pool as the
    # request thread) - Postgres connections are already safe to share
    # across threads via the pool, and passing this connect_arg to
    # psycopg2 would be a TypeError, not a no-op.
    SQLALCHEMY_ENGINE_OPTIONS = (
        {"connect_args": {"check_same_thread": False}} if _db_uri.startswith("sqlite") else {}
    )

    WTF_CSRF_ENABLED = os.environ.get("WTF_CSRF_ENABLED", "true").lower() not in (
        "0",
        "false",
        "no",
    )

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
