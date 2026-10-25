"""
Small shared route decorators used by more than one blueprint.

`org_admin_required` lives here (rather than duplicated inside
`org_routes.py` and `billing_routes.py`) since both blueprints need the
exact same "must be logged in AND role == ORG_ADMIN" gate.

`platform_admin_required` gates the separate, cross-org website-staff
surface (`glassbox/admin_routes.py`) - deliberately a different
check than `org_admin_required`: an ORG_ADMIN only has authority within
their own org, while a platform admin (`User.is_platform_admin`) can act
across every org (e.g. approving a domain-deletion request an org admin
submitted about their own org - see org_routes.py's approve/reject
routes, which require this instead of org_admin_required for exactly
that separation-of-duties reason).
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
        from glassbox.models import Role

        if not current_user.is_authenticated or current_user.role != Role.ORG_ADMIN:
            abort(403)
        return view_func(*args, **kwargs)

    return wrapped


def platform_admin_required(view_func):
    """403s unless the current user is authenticated and
    `User.is_platform_admin` is True. Independent of `role`/`org_id` -
    a platform admin does not need to be an ORG_ADMIN of, or even a member
    of, the org whose data a route touches."""

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_platform_admin:
            abort(403)
        return view_func(*args, **kwargs)

    return wrapped
