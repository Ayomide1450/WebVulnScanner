"""
Blueprint `auth`: /signup, /verify-email/<token>, /login, /logout.

Password hashing uses werkzeug.security (already a Flask dependency, no
new package). CSRF protection comes from Flask-WTF's CSRFProtect
(initialized in create_app()) plus {{ form.hidden_tag() }} in the
templates.

Decision (per the plan): unverified email does NOT block login - a user
can log in immediately after signup. Email verification instead gates
org-tier features later (entitlements.py, a later workstream), not
authentication itself.
"""
import secrets
from datetime import datetime, timedelta, timezone

import requests
from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import BooleanField, PasswordField, StringField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional

from webvulnscanner.extensions import db, limiter
from webvulnscanner.models import Organization, PasswordReset, Plan, Role, User

auth = Blueprint("auth", __name__)

RESET_TOKEN_EXPIRY_MINUTES = 30

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
TURNSTILE_TIMEOUT = 8  # same request-budget convention as checks.py's REQUEST_TIMEOUT


def _turnstile_passes(remote_ip=None):
    """True iff either Turnstile isn't configured (local dev - see
    config.py's TURNSTILE_SITE_KEY/SECRET_KEY docstring) or the submitted
    `cf-turnstile-response` token verifies against Cloudflare's siteverify
    endpoint. Network/API failures fail closed (return False) here, unlike
    checks.py's degrade-open convention - a broken bot check must not
    silently become no bot check on signup, an abuse-sensitive endpoint."""
    secret = current_app.config.get("TURNSTILE_SECRET_KEY")
    if not secret:
        return True

    token = request.form.get("cf-turnstile-response", "")
    if not token:
        return False

    try:
        resp = requests.post(
            TURNSTILE_VERIFY_URL,
            data={"secret": secret, "response": token, "remoteip": remote_ip or ""},
            timeout=TURNSTILE_TIMEOUT,
        )
        return bool(resp.json().get("success"))
    except (requests.RequestException, ValueError):
        return False


class SignupForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField(
        "Confirm password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    org_name = StringField("Organization name (optional)", validators=[Optional()])


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember me")


class ResendVerificationForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])


class ForgotPasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])


class ResetPasswordForm(FlaskForm):
    password = PasswordField("New password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField(
        "Confirm new password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )


def _safe_next(default="/dashboard"):
    """Only follow a `next` param if it's a relative in-app path - avoids
    turning the post-login redirect into an open redirect.

    Beyond the original two conditions (starts with a single slash, does
    not start with two), also rejects any value containing a backslash or
    a CR/LF control character (SEC-07 adversarial-input hardening, added
    08-06):

    - A backslash right after the leading slash (e.g. "/\\evil.example.com")
      is not rejected by "starts with / and not //" alone - it still passes
      both conditions verbatim. Today this app is not actually exploitable
      by it (Werkzeug's header-writing machinery percent-encodes the
      backslash to %5C before it ever reaches a Location header, so a
      browser never sees a literal "\\" to normalize into "//" per the
      WHATWG URL Standard's special-scheme backslash handling) - but that
      safety is Werkzeug's behavior, not this guard's, and relying on an
      unrelated layer to neutralize an input this function was supposed to
      already reject is exactly the kind of implicit safety net that can
      silently disappear (a different WSGI middleware, a raw
      string-concatenated Location header written some other way, etc.).
      Reject it here explicitly so "only a plain in-app relative path
      passes" is this function's own guarantee, not an accident of what
      happens to sit downstream of it.
    - A CR or LF character is not rejected either, and is a genuine live
      bug independent of the open-redirect question: request.args already
      URL-decodes a percent-encoded newline before this function ever sees
      it, so a value like "next=/ok%0d%0aX" reaches here as a real "\\r\\n"
      in the string; passing it straight into Flask's redirect helper then
      raises an uncaught ValueError ("Header values must not contain
      newline characters") from inside login()/signup()/reset_password()
      with TESTING=True, and would fall through to the app's generic 500
      page under TESTING=False (SEC-10) - not a redirect at all. Rejecting
      it here means a malformed `next` value degrades to the ordinary
      default redirect, the same as every other invalid shape this
      function already handles, instead of crashing the request.
    """
    next_url = request.args.get("next")
    if (
        next_url
        and next_url.startswith("/")
        and not next_url.startswith("//")
        and "\\" not in next_url
        and "\r" not in next_url
        and "\n" not in next_url
    ):
        return next_url
    return default


@auth.route("/signup", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def signup():
    # Local import to avoid a module-level circular import - org_routes.py
    # doesn't import auth_routes.py, so this is safe, but importing lazily
    # here (rather than at the top of the file) keeps the dependency
    # direction obvious: auth_routes reaches into org_routes for the token
    # codec, not the other way around.
    from webvulnscanner.org_routes import decode_invite_token

    invite_token = request.args.get("invite")
    # An already-logged-in user hitting a bare /signup shouldn't see the
    # signup form rendered under their own authenticated nav (Logout, org
    # links, etc.) - confusing, and there's nothing useful to do there.
    # GET-only: skip the redirect when an invite token is present so a
    # logged-in user following a real invite link can still land on the
    # form to join a different org, and don't touch POST at all - some
    # tests deliberately submit /login or /signup while already
    # authenticated as a different user to switch identity within one
    # test, without an intervening GET/logout.
    if request.method == "GET" and current_user.is_authenticated and not invite_token:
        return redirect(_safe_next())
    # Decoded without an expected_email here - this pass only pre-fills the
    # address on GET; it never by itself authorizes an org assignment. The
    # POST path below re-decodes with the submitted address, which is the
    # only decode that actually grants membership (D-07).
    invite_payload = decode_invite_token(invite_token) if invite_token else None
    if invite_token and invite_payload is None:
        # Tampered, expired, or unparseable - degrade to the ordinary
        # signup path rather than 500ing or silently granting membership
        # (04-RESEARCH.md Pitfall 6).
        flash("This invite link is invalid or has expired. You can still sign up below.", "error")
    invite_mode = invite_payload is not None
    invite_email = invite_payload["email"] if invite_payload else None

    form = SignupForm()
    if invite_mode and request.method == "GET":
        form.email.data = invite_email

    if form.validate_on_submit():
        if not _turnstile_passes(request.remote_addr):
            flash("Bot check failed - please try again.", "error")
            return render_template(
                "signup.html", form=form, invite_mode=invite_mode, invite_email=invite_email,
            )

        email = form.email.data.strip().lower()

        if invite_mode:
            payload = decode_invite_token(invite_token, expected_email=email)
            if payload is None:
                flash("This invite link was issued for a different email address.", "error")
                return render_template(
                    "signup.html", form=form, invite_mode=True, invite_email=invite_email,
                )
            try:
                invite_role = Role(payload["role"])
            except ValueError:
                # An unrecognized role string is as untrustworthy as a bad
                # signature - same degrade path as a tampered token.
                flash(
                    "This invite link is invalid or has expired. You can still sign up below.",
                    "error",
                )
                return render_template("signup.html", form=form, invite_mode=False, invite_email=None)
            invite_org_id = payload["org_id"]

        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
            return render_template(
                "signup.html", form=form, invite_mode=invite_mode, invite_email=invite_email,
            )

        org = None
        role = Role.MEMBER
        org_id = None
        if invite_mode:
            # Invite mode never creates a new organization, regardless of
            # any org_name value submitted alongside it - the only org an
            # invite-mode signup can join is the token's.
            org_id = invite_org_id
            role = invite_role
        else:
            org_name = (form.org_name.data or "").strip()
            if org_name:
                org = Organization(name=org_name, plan=Plan.FREE)
                db.session.add(org)
                db.session.flush()  # populate org.id before the user row references it
                role = Role.ORG_ADMIN
                org_id = org.id

        verify_token = secrets.token_urlsafe(32)
        user = User(
            email=email,
            password_hash=generate_password_hash(form.password.data),
            org_id=org_id,
            role=role,
            verify_token=verify_token,
        )
        db.session.add(user)
        db.session.commit()

        verify_url = url_for("auth.verify_email", token=verify_token, _external=True)
        sender = current_app.extensions["email_sender"]
        sender.send(
            to=email,
            subject="Verify your Glassbox email",
            body=f"Click the link below to verify your email address:\n\n{verify_url}",
        )

        flash("Account created. Check the server console for your verification link.", "info")
        return redirect(url_for("auth.login"))

    return render_template("signup.html", form=form, invite_mode=invite_mode, invite_email=invite_email)


@auth.route("/verify-email/<token>")
def verify_email(token):
    user = User.query.filter_by(verify_token=token).first()
    if user is None:
        flash("Invalid or expired verification link.", "error")
        return render_template("verify_email.html", verified=False)

    user.email_verified_at = datetime.now(timezone.utc)
    user.verify_token = None
    db.session.commit()
    return render_template("verify_email.html", verified=True)


@auth.route("/resend-verification", methods=["POST"])
@limiter.limit("5 per hour")
def resend_verification():
    """Re-sends the verification email for a pending account. Deliberately
    anti-enumeration: the flashed response is IDENTICAL whether or not the
    address has an account, is already verified, or is unknown - an
    attacker probing addresses learns nothing. Only a genuinely pending
    (unverified) account gets a new email; a legacy unverified row without
    a stored token gets a fresh one minted here."""
    form = ResendVerificationForm()
    neutral = (
        "If that address belongs to an account awaiting verification, a "
        "fresh verification link has been sent to it."
    )
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()
        if user is not None and user.email_verified_at is None:
            if not user.verify_token:
                # Legacy/edge row: pending but tokenless - mint a token so
                # the link actually works.
                user.verify_token = secrets.token_urlsafe(32)
                db.session.commit()
            verify_url = url_for("auth.verify_email", token=user.verify_token, _external=True)
            sender = current_app.extensions["email_sender"]
            sender.send(
                to=email,
                subject="Verify your Glassbox email",
                body=f"Click the link below to verify your email address:\n\n{verify_url}",
            )
    flash(neutral, "info")
    return redirect(url_for("auth.login"))


@auth.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "GET" and current_user.is_authenticated:
        return redirect(_safe_next())
    form = LoginForm()
    if form.validate_on_submit():
        if not _turnstile_passes(request.remote_addr):
            flash("Bot check failed - please try again.", "error")
            return render_template("login.html", form=form)

        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()
        if user is None or not check_password_hash(user.password_hash, form.password.data):
            flash("Invalid email or password.", "error")
            return render_template("login.html", form=form)

        # Email verification is required before login (reversed from the
        # old documented decision that it wasn't): an unverified account
        # must not be able to create assets, launch scans, or accept org
        # invites. Same anti-enumeration reasoning as the suspension branch
        # below - the password has already been proven correct at this
        # point, so naming the real reason leaks nothing an attacker
        # doesn't already know.
        if user.email_verified_at is None:
            flash(
                "Please verify your email address before logging in. "
                "Check your inbox for the verification link, or use the "
                "resend option below.",
                "error",
            )
            return render_template("login.html", form=form, resend_email=email)

        # A suspended user (or a member of a suspended org - User.is_active
        # checks both) has correctly-verified credentials at this point, so
        # telling them specifically why login is refused isn't a user-
        # enumeration leak the way it would be before password
        # verification - they already know the account exists and the
        # password is right. login_user() itself refuses (returns False)
        # without touching the session when is_active is False; check the
        # return value rather than assuming success, which used to redirect
        # to _safe_next() while current_user stayed unauthenticated - a
        # silent failure with no explanation (Phase 16, ADMIN-02).
        if not login_user(user, remember=form.remember.data):
            flash("This account has been suspended. Contact support if you believe this is a mistake.", "error")
            return render_template("login.html", form=form)

        return redirect(_safe_next())

    return render_template("login.html", form=form)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@auth.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()
        # Always the same response whether or not the address exists -
        # otherwise this endpoint becomes a user-enumeration oracle.
        if user is not None:
            token = secrets.token_urlsafe(32)
            db.session.add(PasswordReset(
                user_id=user.id, token=token,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=RESET_TOKEN_EXPIRY_MINUTES),
            ))
            db.session.commit()
            reset_url = url_for("auth.reset_password", token=token, _external=True)
            sender = current_app.extensions["email_sender"]
            sender.send(
                to=email,
                subject="Reset your Glassbox password",
                body=f"Click the link below to reset your password (expires in "
                     f"{RESET_TOKEN_EXPIRY_MINUTES} minutes):\n\n{reset_url}",
            )
        flash("If that email has an account, a reset link has been sent - check the server console.", "info")
        return redirect(url_for("auth.login"))

    return render_template("forgot_password.html", form=form)


@auth.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def reset_password(token):
    pr = PasswordReset.query.filter_by(token=token).first()
    now = datetime.now(timezone.utc)
    expires_at = pr.expires_at.replace(tzinfo=timezone.utc) if pr and pr.expires_at.tzinfo is None else (pr.expires_at if pr else None)
    valid = pr is not None and pr.used_at is None and expires_at is not None and expires_at > now

    if not valid:
        flash("This reset link is invalid or has expired. Request a new one.", "error")
        return redirect(url_for("auth.forgot_password"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        pr.user.password_hash = generate_password_hash(form.password.data)
        pr.used_at = now
        db.session.commit()
        flash("Password updated. Log in with your new password.", "info")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html", form=form, token=token)
