"""Tests for webvulnscanner/config.py's engine-options branching, plus the
production-readiness additions (proxy trust, rate-limit storage backend,
Sentry no-op) - see webvulnscanner/__init__.py's create_app()/_init_sentry().

_engine_options_for() is a pure function specifically so these can run
without reloading the config module or spinning up a Flask app - config.py
computes SQLALCHEMY_ENGINE_OPTIONS once at class-body/import time, so
testing the branches directly (rather than via importlib.reload gymnastics)
is both simpler and doesn't risk leaking state into other tests' already-
imported Config subclasses.
"""
import logging

from werkzeug.middleware.proxy_fix import ProxyFix

from webvulnscanner.config import _engine_options_for


def test_sqlite_engine_options_keep_check_same_thread_false():
    assert _engine_options_for("sqlite:///whatever.db") == {
        "connect_args": {"check_same_thread": False},
    }


def test_postgres_engine_options_add_pool_pre_ping_and_recycle():
    # Confirmed live: a dropped idle Neon/Postgres connection surfaces as a
    # hard psycopg2.OperationalError ("server closed the connection
    # unexpectedly") without this - pool_pre_ping issues a cheap SELECT 1
    # before handing a pooled connection back out and transparently
    # reconnects if it's dead.
    assert _engine_options_for("postgresql://user:pass@host/db") == {
        "pool_pre_ping": True,
        "pool_recycle": 280,
    }


def test_default_config_trusts_one_proxy_hop():
    # Render/Vercel both sit exactly one reverse-proxy hop in front of the
    # app - default-on so rate limiting keys on the real client IP and
    # HTTPS-scheme detection is correct out of the box on either target,
    # without every deployer needing to remember to set this themselves.
    from webvulnscanner.config import Config

    assert Config.TRUST_PROXY_HOPS == 1


def test_app_wraps_wsgi_app_with_proxy_fix_when_hops_positive(app):
    # `app` fixture (conftest.py) builds via create_app(TestConfig), which
    # inherits Config's default TRUST_PROXY_HOPS=1 - confirms create_app()
    # actually wires ProxyFix in, not just that the config default exists.
    assert isinstance(app.wsgi_app, ProxyFix)


def test_app_skips_proxy_fix_when_hops_zero(tmp_path):
    from webvulnscanner import create_app
    from tests.conftest import TestConfig

    class NoProxyConfig(TestConfig):
        TRUST_PROXY_HOPS = 0
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + str(tmp_path / "noproxy.db")

    unwrapped = create_app(NoProxyConfig)
    assert not isinstance(unwrapped.wsgi_app, ProxyFix)


def test_sentry_init_is_a_noop_without_dsn(app, caplog):
    # SENTRY_DSN defaults to "" (Config) - _init_sentry() must not raise or
    # log a warning in the common case of Sentry simply not being
    # configured (distinct from the DSN-set-but-package-missing case below).
    from webvulnscanner import _init_sentry

    with caplog.at_level(logging.WARNING):
        _init_sentry(app)  # must not raise
    assert "sentry-sdk" not in caplog.text


def test_sentry_init_warns_but_does_not_raise_when_package_missing(app, caplog):
    # sentry-sdk isn't in requirements.txt (see _init_sentry()'s docstring) -
    # a DSN set without the package installed must degrade to a logged
    # warning, the same convention ai_summary.py uses for a missing
    # GROQ_API_KEY, never a hard crash on startup.
    from webvulnscanner import _init_sentry

    app.config["SENTRY_DSN"] = "https://example.invalid/123"
    with caplog.at_level(logging.WARNING):
        _init_sentry(app)  # must not raise even though sentry_sdk isn't installed
    assert "sentry-sdk" in caplog.text


def test_ratelimit_storage_uri_defaults_empty_so_limiter_falls_back_to_memory():
    # Empty string, not None: Flask-Limiter's own config.get(..., None) +
    # `if not storage_uri_from_config` check treats "" the same as unset and
    # falls back to its in-memory default - see flask_limiter/_extension.py.
    # This just pins that the default stays empty (opt-in only) rather than
    # silently changing local-dev behavior.
    from webvulnscanner.config import Config

    assert Config.RATELIMIT_STORAGE_URI == ""
