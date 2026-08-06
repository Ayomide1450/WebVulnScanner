"""
Flask extension instances, created uninitialized here and wired up via
`.init_app(app)` inside `create_app()` (see `webvulnscanner/__init__.py`).
Kept in their own module so other modules (models, routes) can import them
without triggering circular imports with the app factory.
"""
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

login_manager.login_view = "auth.login"


# The user_loader callback lives here (rather than models.py) so that
# extensions.py stays the single place that configures login_manager
# end-to-end. It imports User lazily (inside the function) to avoid a
# models.py <-> extensions.py circular import at module load time.
@login_manager.user_loader
def load_user(user_id):
    from webvulnscanner.models import User

    return User.query.get(int(user_id))
