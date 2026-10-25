"""
App factory for the glassbox package.

`app.py` at the repo root is now the thin factory around this package
(Workstream 4's cutover): `from glassbox import create_app; app =
create_app()`. All 5 blueprints (auth, org, billing, scan, public) are
registered here.
"""
import logging
import os
from datetime import UTC
from urllib.parse import urlsplit, urlunsplit

import click
from flask import Flask, flash, g, jsonify, redirect, render_template, request, url_for
from flask_wtf.csrf import CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix

from glassbox.config import Config
from glassbox.email_stub import make_email_sender
from glassbox.extensions import (
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
    from glassbox.scheduler import start_scheduler

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


def _safe_referrer():
    # Same-origin-only redirect target for the CSRFError handler below,
    # built from request.referrer - an attacker-controllable request
    # header, not trusted input, so it must never reach a redirect call
    # unvalidated, the same class of bug auth_routes.py's `next` param
    # guards against (SEC-07). Kept as its own named function (mirroring
    # _safe_next()'s pattern) rather than inlined, so
    # tests/test_auth_flows.py::test_only_safe_next_redirects_take_a_
    # request_derived_argument - which source-scans glassbox/ for
    # every redirect call site and fails closed on anything that isn't
    # url_for(...) or a named, reviewed safe-redirect helper - has a
    # second, equally auditable pattern to recognize instead of a raw
    # inline referrer value reaching a redirect call unaudited.
    #
    # Falls back to the homepage when there's no referrer, or it isn't
    # same-origin (scheme+host match request.host) - a CSRF-token expiry
    # is common (idle timeout, a stale second tab) and deliberately never
    # reaches this codepath from a genuinely cross-site request in the
    # first place (that's what CSRFProtect just rejected), but the
    # referrer header itself is still not proof of that on its own.
    referrer = request.referrer
    if referrer:
        parsed = urlsplit(referrer)
        if (not parsed.scheme or parsed.scheme in ("http", "https")) and parsed.netloc == request.host:
            return urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    return url_for("public.index")


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
    # Operator-facing confirmation of which rate-limit storage backend this
    # worker actually attached to (HARD-01) - a misconfigured worker
    # otherwise fails silently by enforcing its own private in-memory
    # counters instead of the shared backend an operator thinks it's using.
    # Logs the URI scheme only, never the full RATELIMIT_STORAGE_URI value -
    # a redis:// URL routinely carries a password.
    _storage_uri = app.config.get("RATELIMIT_STORAGE_URI", "")
    if _storage_uri:
        _storage_scheme = _storage_uri.split("://", 1)[0]
        logging.info(
            "Rate limiting: using %s:// storage backend (shared across workers)",
            _storage_scheme,
        )
    else:
        logging.info(
            "Rate limiting: using in-memory storage (NOT shared across workers - "
            "single-process only; set RATELIMIT_STORAGE_URI for a multi-worker deploy)"
        )
    migrate.init_app(app, db)

    # Email sender is stashed on app.extensions (Flask's own convention for
    # extension-owned, app-scoped state) so route code can reach it via
    # current_app.extensions["email_sender"].
    app.extensions["email_sender"] = make_email_sender(
        app.config["EMAIL_MODE"], app.config["RESEND_API_KEY"], app.config["RESEND_FROM_EMAIL"],
    )

    from glassbox.auth_routes import auth as auth_blueprint

    app.register_blueprint(auth_blueprint)

    from glassbox.org_routes import org as org_blueprint

    app.register_blueprint(org_blueprint)

    from glassbox.admin_routes import admin as admin_blueprint

    app.register_blueprint(admin_blueprint)

    from glassbox.billing_routes import billing_bp as billing_blueprint

    app.register_blueprint(billing_blueprint)

    from glassbox.scan_routes import scan as scan_blueprint

    app.register_blueprint(scan_blueprint)

    from glassbox.asset_routes import asset as asset_blueprint

    app.register_blueprint(asset_blueprint)

    from glassbox.public_routes import public as public_blueprint

    app.register_blueprint(public_blueprint)

    from glassbox.api_tokens_routes import api_tokens as api_tokens_blueprint

    app.register_blueprint(api_tokens_blueprint)

    from glassbox.webhook_routes import webhooks_bp as webhooks_blueprint

    app.register_blueprint(webhooks_blueprint)

    from glassbox.api_routes import api as api_blueprint

    app.register_blueprint(api_blueprint)

    from glassbox.assessment_routes import assessment as assessment_blueprint

    app.register_blueprint(assessment_blueprint)

    from glassbox.docs_route import docs_bp as docs_blueprint

    app.register_blueprint(docs_blueprint)

    from glassbox.sso_routes import sso as sso_blueprint

    app.register_blueprint(sso_blueprint)

    # Idle-session timeout: a session-cookie-authenticated user is signed
    # out server-side after IDLE_TIMEOUT_MINUTES with no request, regardless
    # of "Remember me" - logout_user() clears the remember cookie too, so a
    # stale remember cookie can't silently re-authenticate the next request.
    # Bearer-token (API) auth is explicitly exempt: those requests set
    # flask.g.login_via_request in extensions.py's request_loader and never
    # receive a session cookie back in the first place (see
    # _ApiAwareSessionInterface) - tokens have their own separate
    # revoke/expiry model in api_tokens_routes.py, not this one.
    @app.before_request
    def _enforce_idle_timeout():
        from datetime import datetime, timedelta, timezone

        import flask
        from flask import request, session
        from flask_login import current_user, logout_user

        if not current_user.is_authenticated:
            return
        if getattr(flask.g, "login_via_request", False):
            return

        # A user (or their org) suspended by a platform admin mid-session
        # (Phase 16, ADMIN-02/03) must lose access on their very next
        # request, not merely be blocked from a future login - the session
        # cookie alone would otherwise keep working until it naturally
        # expires. Same forced-logout shape as the idle-timeout branch
        # below, checked first since it doesn't depend on _last_seen.
        if not current_user.is_active:
            logout_user()
            session.clear()
            return

        now = datetime.now(UTC)
        timeout = timedelta(minutes=app.config.get("IDLE_TIMEOUT_MINUTES", 5))
        last_seen_raw = session.get("_last_seen")
        if last_seen_raw:
            try:
                last_seen = datetime.fromisoformat(last_seen_raw)
            except ValueError:
                last_seen = None
            if last_seen is not None and now - last_seen > timeout:
                logout_user()
                session.clear()
                return
        # scan_progress.html's background status poll (2s) / SSE feed both
        # send the session cookie (credentials: same-origin) but are not
        # user activity - bumping _last_seen on every tick would keep an
        # AFK session alive indefinitely for the duration of any scan. Every
        # other request still refreshes it normally.
        if not (request.path.endswith("/status") or request.path.endswith("/events")):
            session["_last_seen"] = now.isoformat()

    from glassbox.models import Role

    # ---------------------------------------------------------------- #
    # Our own security response headers.
    #
    # checks.py's SECURITY_HEADERS table (see `check_headers`) grades every
    # scanned site on exactly these six headers and rates two of them
    # "high" - and until 2026-10-25 Glassbox itself sent none of them. A
    # self-scan would have failed its own audit six times over. Beyond the
    # obvious credibility problem, the app genuinely was framable and had
    # no browser-enforced containment for an XSS.
    #
    # CSP uses a per-request nonce rather than 'unsafe-inline', because the
    # app carries ~21 inline <script> blocks it cannot drop without a build
    # step. script-src therefore allows ONLY nonce'd scripts - the strong
    # half of the policy. Inline `style="..."` *attributes* (151 of them
    # across the templates) cannot take a nonce at all, so style-src-attr
    # keeps 'unsafe-inline'; that is a far smaller risk than script
    # injection and is the standard trade-off.
    #
# The ONE permitted third party is Cloudflare Turnstile, the signup
    # bot-check (`signup.html` loads its api.js and the widget renders in a
    # Cloudflare-hosted iframe, so it needs both script-src and frame-src).
    # Everything else is 'self': fonts were self-hosted in the same release,
    # closing the fonts.googleapis.com IP leak. Do not widen these without
    # knowingly giving up that property.
    # ---------------------------------------------------------------- #
    TURNSTILE_ORIGIN = "https://challenges.cloudflare.com"

    @app.before_request
    def _issue_csp_nonce():
        import secrets

        g.csp_nonce = secrets.token_urlsafe(16)

    @app.after_request
    def _set_security_headers(response):
        nonce = getattr(g, "csp_nonce", None)
        if nonce:
            script_src = f"'self' 'nonce-{nonce}' {TURNSTILE_ORIGIN}"
            style_src = f"'self' 'nonce-{nonce}'"
        else:
            # No nonce (e.g. a 500 raised before before_request ran). Fail
            # closed on inline scripts rather than silently allowing them.
            script_src = f"'self' {TURNSTILE_ORIGIN}"
            style_src = "'self'"

        response.headers.setdefault(
            "Content-Security-Policy",
            "; ".join(
                [
                    "default-src 'self'",
                    f"script-src {script_src}",
                    f"style-src {style_src}",
                    # Inline style attributes only - see note above.
                    "style-src-attr 'unsafe-inline'",
                    "img-src 'self' data:",
                    "font-src 'self'",
                    "connect-src 'self'",
                    # The Turnstile widget renders inside a Cloudflare iframe.
                    f"frame-src {TURNSTILE_ORIGIN}",
                    "object-src 'none'",
                    "base-uri 'none'",
                    "form-action 'self'",
                    "frame-ancestors 'none'",
                ]
            ),
        )
        # Belt-and-braces alongside CSP frame-ancestors, for older browsers.
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")

        # HSTS only over a genuine HTTPS request. Sending it on plain http
        # is ignored by browsers anyway, and sending it in local dev would
        # pin localhost to https in the developer's browser - a genuinely
        # annoying footgun to undo. SESSION_COOKIE_SECURE already tracks
        # "are we deployed over TLS", so reuse that signal.
        if request.is_secure and app.config.get("SESSION_COOKIE_SECURE", True):
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    @app.context_processor
    def inject_role_enum():
        # base.html's nav checks current_user.role == Role.ORG_ADMIN;
        # base.html's footer and terms.html/privacy.html use current_year.
        from datetime import datetime, timezone

        return {
            "Role": Role,
            "current_year": datetime.now(UTC).year,
            "idle_timeout_minutes": app.config.get("IDLE_TIMEOUT_MINUTES", 5),
            # Templates stamp this on every inline <script>/<style> tag:
            # <script nonce="{{ csp_nonce }}">. A tag that forgets it will
            # be blocked by the policy above, which is the intended
            # failure mode - silently dropping to 'unsafe-inline' would
            # make the whole header decorative.
            "csp_nonce": getattr(g, "csp_nonce", ""),
        }

    # v1.8 CVSS-02: expose compute_cvss_score to all Jinja templates so
    # scan_report.html can render per-finding CVSS badges.
    from glassbox.checks import compute_cvss_score
    app.jinja_env.globals["compute_cvss_score"] = compute_cvss_score

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

    # A CSRF token expires with the session that issued it (SESSION_COOKIE
    # ... / PERMANENT_SESSION_LIFETIME) - hitting an idle-timeout logout,
    # then submitting a form still open in another tab, is a completely
    # ordinary way to trip this, not an attack. Flask-WTF's CSRFProtect
    # raises this as a raw 400 with no handler registered, which used to
    # surface Flask's unstyled default error page (and its literal
    # "The CSRF token has expired." message) straight to the user - a
    # backend implementation detail leaking through, and confusing since
    # every other error in this app stays inside the themed error pages
    # above. Bounce back to the page that was submitted (its GET render
    # mints a fresh token via csrf_token()/hidden_tag()) with a plain-
    # English flash instead.
    @app.errorhandler(CSRFError)
    def _csrf_error(_e):
        # scan_new_advanced.html's Smart Setup fetch() call (the only
        # X-Requested-With: XMLHttpRequest sender in the app) expects a
        # JSON error body it can show inline, not an HTML redirect a fetch()
        # would just follow and then fail to JSON.parse - give it the same
        # shape its view already uses for its own validation errors.
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(error="Your session expired - please refresh and try again."), 400

        flash("Your session expired - please try again.", "error")
        return redirect(_safe_referrer())

    @app.cli.command("grant-platform-admin")
    @click.argument("email")
    def grant_platform_admin(email):
        """Grants User.is_platform_admin to an existing account by email.

        The only way to create a platform admin - no route or UI can set
        this flag (see User.is_platform_admin's docstring in models.py),
        so bootstrapping the first one is deliberately a server-access-only
        operation: `flask grant-platform-admin someone@example.com`.
        """
        from glassbox.models import User

        user = User.query.filter_by(email=email.strip().lower()).first()
        if user is None:
            click.echo(f"No user found with email {email!r}.")
            return
        user.is_platform_admin = True
        db.session.commit()
        click.echo(f"Granted platform-admin to {user.email}.")

    @app.cli.command("revoke-platform-admin")
    @click.argument("email")
    def revoke_platform_admin(email):
        """Reverses grant-platform-admin."""
        from glassbox.models import User

        user = User.query.filter_by(email=email.strip().lower()).first()
        if user is None:
            click.echo(f"No user found with email {email!r}.")
            return
        user.is_platform_admin = False
        db.session.commit()
        click.echo(f"Revoked platform-admin from {user.email}.")

    with app.app_context():
        # Import only, to register models with db.Model - schema creation is
        # now owned by Alembic (`flask db upgrade`, see migrations/ and
        # CLAUDE.md's Commands section), not an implicit db.create_all() here.
        # That unconditional call used to run on every app start, which is
        # also what silently masked adding a column to an existing table
        # never actually applying to a real, already-created DB - the exact
        # failure mode migrations exist to fix.
        from glassbox import models  # noqa: F401

    _maybe_start_scheduler(app)

    return app
