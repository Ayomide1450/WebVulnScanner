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
from flask_login import login_required, login_user, logout_user
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
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember me")


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
    turning the post-login redirect into an open redirect."""
    next_url = request.args.get("next")
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
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
            subject="Verify your WebVulnScanner email",
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


@auth.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()
        if user is None or not check_password_hash(user.password_hash, form.password.data):
            flash("Invalid email or password.", "error")
            return render_template("login.html", form=form)

        login_user(user, remember=form.remember.data)
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
                subject="Reset your WebVulnScanner password",
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
