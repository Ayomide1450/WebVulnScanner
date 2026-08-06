"""
Flask extension instances, created uninitialized here and wired up via
`.init_app(app)` inside `create_app()` (see `webvulnscanner/__init__.py`).
Kept in their own module so other modules (models, routes) can import them
without triggering circular imports with the app factory.
"""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
# Alembic-backed migrations (infra track) - replaces the old "db.create_all()
# only, no migrations, add a new table instead of altering one" constraint.
# `flask db migrate`/`flask db upgrade` now own schema changes; db.create_all()
# in create_app() stays only as a first-run convenience for a brand-new empty
# DB (a fresh `flask db upgrade` accomplishes the same thing and is what a
# real deploy should run instead - see CLAUDE.md's Commands section).
migrate = Migrate()
# In-memory storage (Flask-Limiter's default) - fine for this app's current
# single dev-server-process reality (same caveat as SQLite's
# check_same_thread config), but limits won't be shared across multiple
# worker processes if this is ever run behind gunicorn with >1 worker.
# Switch storage_uri to a shared backend (e.g. Redis) if that changes.
limiter = Limiter(key_func=get_remote_address)

login_manager.login_view = "auth.login"


# The user_loader callback lives here (rather than models.py) so that
# extensions.py stays the single place that configures login_manager
# end-to-end. It imports User lazily (inside the function) to avoid a
# models.py <-> extensions.py circular import at module load time.
@login_manager.user_loader
def load_user(user_id):
    from webvulnscanner.models import User

    return User.query.get(int(user_id))
