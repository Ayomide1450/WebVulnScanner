"""
Blueprint `api_tokens`: /tokens.

Session-authenticated HTML CRUD for a user's own API tokens (API-01, Phase
2). Self-service per CONTEXT.md's D-05: no @org_admin_required anywhere in
this file - REQUIREMENTS.md's literal "org admin" phrasing is resolved by
D-05 to mean "any authenticated org member," matching D-02's "a token acts
as the specific user who created it" premise. Follows asset_routes.py's
structure/docstring conventions (blueprint at module top, ownership helper,
one route per action).
"""
import hashlib
import secrets
from datetime import datetime, timezone

from flask import Blueprint, abort, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from glassbox.audit import log_org_event
from glassbox.extensions import db
from glassbox.models import ApiToken

api_tokens = Blueprint("api_tokens", __name__, url_prefix="/tokens")


def _user_tokens():
    return (
        ApiToken.query.filter_by(user_id=current_user.id)
        .order_by(ApiToken.created_at.desc())
        .all()
    )


@api_tokens.route("", methods=["GET"])
@login_required
def list_tokens():
    return render_template("api_tokens.html", tokens=_user_tokens())


@api_tokens.route("/new", methods=["POST"])
@login_required
def create_token():
    name = request.form.get("name", "").strip()
    if not name:
        return render_template(
            "api_tokens.html",
            tokens=_user_tokens(),
            error='Enter a name for this token, e.g. "CI pipeline" or "Personal script".',
        )

    # Pitfall 4 (02-RESEARCH.md): raw_token is a LOCAL VARIABLE, never
    # persisted, never re-derivable, never flashed, never put in a URL -
    # this response is the only place it ever exists outside the caller's
    # own client (D-01).
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    t = ApiToken(user_id=current_user.id, name=name, token_hash=token_hash)
    db.session.add(t)
    log_org_event("api_token_created", detail=f"Token \"{name}\" created")
    db.session.commit()

    return render_template(
        "api_tokens.html",
        tokens=_user_tokens(),
        new_token_value=raw_token,
        new_token_name=name,
    )


@api_tokens.route("/<int:token_id>/revoke", methods=["POST"])
@login_required
def revoke_token(token_id):
    t = ApiToken.query.get_or_404(token_id)
    if t.user_id != current_user.id:
        # 404-not-403, matching _check_asset_access/_check_ownership's
        # convention - a token ID doesn't confirm its own existence to
        # someone who doesn't own it.
        abort(404)
    t.revoked_at = datetime.now(timezone.utc)
    log_org_event("api_token_revoked", detail=f"Token \"{t.name}\" revoked")
    db.session.commit()
    return redirect(url_for("api_tokens.list_tokens"))
