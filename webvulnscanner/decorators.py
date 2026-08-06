"""
Small shared route decorators used by more than one blueprint.

`org_admin_required` lives here (rather than duplicated inside
`org_routes.py` and `billing_routes.py`) since both blueprints need the
exact same "must be logged in AND role == ORG_ADMIN" gate.
"""
from functools import wraps

from flask import abort
from flask_login import current_user


def org_admin_required(view_func):
    """403s unless the current user is authenticated and is an ORG_ADMIN.

    Deliberately does not redirect to login - `@login_required` (applied
    alongside this on every route that uses it) already handles the
    not-authenticated case; this decorator only needs to add the role
    check on top.
    """

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        from webvulnscanner.models import Role

        if not current_user.is_authenticated or current_user.role != Role.ORG_ADMIN:
            abort(403)
        return view_func(*args, **kwargs)

    return wrapped
