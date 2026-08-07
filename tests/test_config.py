"""Tests for webvulnscanner/config.py's engine-options branching.

_engine_options_for() is a pure function specifically so these can run
without reloading the config module or spinning up a Flask app - config.py
computes SQLALCHEMY_ENGINE_OPTIONS once at class-body/import time, so
testing the branches directly (rather than via importlib.reload gymnastics)
is both simpler and doesn't risk leaking state into other tests' already-
imported Config subclasses.
"""
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
