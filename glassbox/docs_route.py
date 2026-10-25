"""
Blueprint `docs`: in-product API reference at /docs/api (Phase 22, DOCS-05).

Session-authenticated HTML page rendering glassbox/api_docs.py's spec -
the single source of truth for the /api/v1 surface. Login-required like every
other authenticated HTML page: the reference includes live base-URL-aware
examples, and there is no reason to expose your API's complete shape to
anonymous crawlers.

Read-only by construction - no POST/PUT/DELETE routes here, nothing to CSRF-
protect beyond Flask-WTF's global GET safety.
"""
from flask import Blueprint, render_template
from flask_login import login_required

from glassbox.api_docs import (
    CLI_SUBCOMMANDS,
    CURL_EXAMPLE,
    ERROR_SEMANTICS,
    API_ENDPOINTS,
    WEBHOOK_VERIFY_SNIPPET,
)

docs_bp = Blueprint("api_docs", __name__, url_prefix="/docs")


@docs_bp.route("/api", methods=["GET"])
@login_required
def api_reference():
    return render_template(
        "api_docs.html",
        endpoints=API_ENDPOINTS,
        error_semantics=ERROR_SEMANTICS,
        curl_example=CURL_EXAMPLE,
        webhook_snippet=WEBHOOK_VERIFY_SNIPPET,
        cli_subcommands=CLI_SUBCOMMANDS,
    )
