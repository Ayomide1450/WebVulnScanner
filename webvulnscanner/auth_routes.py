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
from datetime import datetime, timezone

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import login_required, login_user, logout_user
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired, Email, Length, Optional

from webvulnscanner.extensions import db, limiter
from webvulnscanner.models import Organization, Plan, Role, User

auth = Blueprint("auth", __name__)


class SignupForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    org_name = StringField("Organization name (optional)", validators=[Optional()])


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])


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
    form = SignupForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
            return render_template("signup.html", form=form)

        org = None
        role = Role.MEMBER
        org_name = (form.org_name.data or "").strip()
        if org_name:
            org = Organization(name=org_name, plan=Plan.FREE)
            db.session.add(org)
            db.session.flush()  # populate org.id before the user row references it
            role = Role.ORG_ADMIN

        verify_token = secrets.token_urlsafe(32)
        user = User(
            email=email,
            password_hash=generate_password_hash(form.password.data),
            org_id=org.id if org else None,
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

    return render_template("signup.html", form=form)


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

        login_user(user)
        return redirect(_safe_next())

    return render_template("login.html", form=form)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
