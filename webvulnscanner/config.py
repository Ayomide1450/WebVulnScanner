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

_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    logging.warning(
        "SECRET_KEY is not set in the environment - falling back to an "
        "insecure development key. Set SECRET_KEY in .env before anything "
        "beyond local single-user use."
    )
    _secret_key = _DEV_SECRET_KEY


class Config:
    SECRET_KEY = _secret_key

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "SQLALCHEMY_DATABASE_URI",
        "sqlite:///" + os.path.join(APP_DIR, "webvulnscanner.db"),
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Needed because scans run in a background thread (Workstream 4) that
    # writes to the same SQLite connection pool as the request thread.
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False}}

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
