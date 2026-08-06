"""
App factory for the webvulnscanner package.

`app.py` at the repo root is now the thin factory around this package
(Workstream 4's cutover): `from webvulnscanner import create_app; app =
create_app()`. All 5 blueprints (auth, org, billing, scan, public) are
registered here.
"""
from flask import Flask

from webvulnscanner.config import Config
from webvulnscanner.email_stub import make_email_sender
from webvulnscanner.extensions import csrf, db, login_manager


def create_app(config_class=Config):
    app = Flask(__name__, template_folder="../templates")
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Email sender is stashed on app.extensions (Flask's own convention for
    # extension-owned, app-scoped state) so route code can reach it via
    # current_app.extensions["email_sender"].
    app.extensions["email_sender"] = make_email_sender(app.config["EMAIL_MODE"])

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
        # base.html's nav checks current_user.role == Role.ORG_ADMIN
        return {"Role": Role}

    with app.app_context():
        from webvulnscanner import models  # noqa: F401  (registers models with db.Model)

        db.create_all()

    return app
