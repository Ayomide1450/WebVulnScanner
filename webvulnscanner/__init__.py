"""
App factory for the webvulnscanner package.

`app.py` at the repo root is now the thin factory around this package
(Workstream 4's cutover): `from webvulnscanner import create_app; app =
create_app()`. All 5 blueprints (auth, org, billing, scan, public) are
registered here.
"""
import logging
import os

from flask import Flask, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

from webvulnscanner.config import Config
from webvulnscanner.email_stub import make_email_sender
from webvulnscanner.extensions import (
    _ApiAwareSessionInterface,
    csrf,
    db,
    limiter,
    login_manager,
    migrate,
)


def _maybe_start_scheduler(app):
    """Three-part guard (01-RESEARCH.md Pattern 1) so the in-process
    scheduler thread starts exactly once per real process and never during
    the test suite:
      (a) explicit config opt-out (SCHEDULER_ENABLED, e.g. ops maintenance)
      (b) TESTING - tests/conftest.py's `app` fixture creates a fresh Flask
          app (and disposable SQLite file) per test; without this check
          every test would leak an infinite background thread
      (c) the standard Werkzeug-reloader guard - `flask run --debug` forks a
          child process that re-imports/re-runs create_app(); only the
          reloader's actual child process (WERKZEUG_RUN_MAIN == "true")
          should start the thread. Production (gunicorn) never sets
          app.debug True, so `not app.debug` alone covers it there.
    """
    if not app.config.get("SCHEDULER_ENABLED", True):
        return
    if app.config.get("TESTING", False):
        return
    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return
    from webvulnscanner.scheduler import start_scheduler

    start_scheduler(app)


def _init_sentry(app):
    """Best-effort Sentry init - never raises, never required. sentry-sdk
    isn't a hard dependency (not in requirements.txt): if it's not
    installed, or SENTRY_DSN isn't set, this is a silent no-op with a log
    line, same degrade-gracefully convention as ai_summary.py's Groq call.
    Add `sentry-sdk[flask]` to requirements.txt and set SENTRY_DSN to
    actually activate it - see docs/env-vars.md."""
    dsn = app.config.get("SENTRY_DSN")
    if not dsn:
        return
    try:
        import sentry_sdk
        from sentry_sdk.integrations.flask import FlaskIntegration
    except ImportError:
        logging.warning(
            "SENTRY_DSN is set but sentry-sdk isn't installed - add "
            "sentry-sdk[flask] to requirements.txt to activate it."
        )
        return
    sentry_sdk.init(dsn=dsn, integrations=[FlaskIntegration()], traces_sample_rate=0.1)


def create_app(config_class=Config):
    app = Flask(__name__, template_folder="../templates")
    app.config.from_object(config_class)

    # Trust exactly one reverse-proxy hop's X-Forwarded-* headers (Render's
    # edge proxy / Vercel's) - see config.py's TRUST_PROXY_HOPS docstring
    # for why this matters for both rate limiting and HTTPS-scheme
    # detection. A value of 0 (set TRUST_PROXY_HOPS=0) disables this for a
    # direct/unproxied deployment, where trusting forwarded headers from an
    # arbitrary client would let them spoof their own IP/scheme.
    hops = app.config.get("TRUST_PROXY_HOPS", 0)
    if hops > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops, x_host=hops)

    _init_sentry(app)

    db.init_app(app)
    login_manager.init_app(app)
    # A Bearer-token-authenticated request (Phase 2, login_manager.request_loader
    # in extensions.py) must never receive a Set-Cookie session header back -
    # Flask-Login's own documented recommendation. Set once, right after
    # login_manager.init_app(app), per 02-RESEARCH.md's Pattern 1 caveat.
    app.session_interface = _ApiAwareSessionInterface()
    csrf.init_app(app)
    limiter.init_app(app)
    migrate.init_app(app, db)

    # Email sender is stashed on app.extensions (Flask's own convention for
    # extension-owned, app-scoped state) so route code can reach it via
    # current_app.extensions["email_sender"].
    app.extensions["email_sender"] = make_email_sender(
        app.config["EMAIL_MODE"], app.config["RESEND_API_KEY"], app.config["RESEND_FROM_EMAIL"],
    )

    from webvulnscanner.auth_routes import auth as auth_blueprint

    app.register_blueprint(auth_blueprint)

    from webvulnscanner.org_routes import org as org_blueprint

    app.register_blueprint(org_blueprint)

    from webvulnscanner.billing_routes import billing_bp as billing_blueprint

    app.register_blueprint(billing_blueprint)

    from webvulnscanner.scan_routes import scan as scan_blueprint

    app.register_blueprint(scan_blueprint)

    from webvulnscanner.asset_routes import asset as asset_blueprint

    app.register_blueprint(asset_blueprint)

    from webvulnscanner.public_routes import public as public_blueprint

    app.register_blueprint(public_blueprint)

    from webvulnscanner.api_tokens_routes import api_tokens as api_tokens_blueprint

    app.register_blueprint(api_tokens_blueprint)

    from webvulnscanner.api_routes import api as api_blueprint

    app.register_blueprint(api_blueprint)

    from webvulnscanner.models import Role

    @app.context_processor
    def inject_role_enum():
        # base.html's nav checks current_user.role == Role.ORG_ADMIN;
        # base.html's footer and terms.html/privacy.html use current_year.
        from datetime import datetime, timezone

        return {"Role": Role, "current_year": datetime.now(timezone.utc).year}

    # Custom error pages so 404/500 stay inside the app's own dark theme
    # (nav, back-to-dashboard link) instead of dropping a logged-in user
    # into Flask's raw unstyled default error page.
    @app.errorhandler(404)
    def _not_found(_e):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def _server_error(_e):
        db.session.rollback()
        return render_template("500.html"), 500

    @app.errorhandler(429)
    def _rate_limited(_e):
        return render_template("429.html"), 429

    with app.app_context():
        # Import only, to register models with db.Model - schema creation is
        # now owned by Alembic (`flask db upgrade`, see migrations/ and
        # CLAUDE.md's Commands section), not an implicit db.create_all() here.
        # That unconditional call used to run on every app start, which is
        # also what silently masked adding a column to an existing table
        # never actually applying to a real, already-created DB - the exact
        # failure mode migrations exist to fix.
        from webvulnscanner import models  # noqa: F401

    _maybe_start_scheduler(app)

    return app
