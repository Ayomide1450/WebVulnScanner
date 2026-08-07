"""
App factory for the webvulnscanner package.

`app.py` at the repo root is now the thin factory around this package
(Workstream 4's cutover): `from webvulnscanner import create_app; app =
create_app()`. All 5 blueprints (auth, org, billing, scan, public) are
registered here.
"""
from flask import Flask, render_template

from webvulnscanner.config import Config
from webvulnscanner.email_stub import make_email_sender
from webvulnscanner.extensions import csrf, db, limiter, login_manager, migrate


def create_app(config_class=Config):
    app = Flask(__name__, template_folder="../templates")
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
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

    from webvulnscanner.public_routes import public as public_blueprint

    app.register_blueprint(public_blueprint)

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

    return app
