"""
Blueprint `assessment`: /assessment/request - the "Request Expert
Assessment" CTA (Phase 15, CTA-01..04).

A human-fulfilled lead-capture form, not another automated check: a user
who wants a manual/authenticated engagement beyond what the self-serve
platform offers submits company/domain/contact details here, and the
request lands in the platform-admin queue (`admin_routes.py`) for a human
to follow up on. Deliberately login-required (unlike a public marketing
contact form) so every request is attributable to a real account/org, the
same attribution convention every other write in this app already follows.

CSRF comes from Flask-WTF (`{{ form.hidden_tag() }}` in the template,
matching every other authenticated form in the app), and the route is
rate-limited the same way `/signup` is (`extensions.limiter`) since it's
an unauthenticated-adjacent write path an abusive account could otherwise
hammer to spam the admin queue.
"""
from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from wtforms import IntegerField, SelectField, StringField, TextAreaField
from wtforms.validators import DataRequired, Email, NumberRange, Optional

from glassbox.extensions import db, limiter
from glassbox.models import AssessmentRequest, AssessmentType

assessment = Blueprint("assessment", __name__, url_prefix="/assessment")


class AssessmentRequestForm(FlaskForm):
    company_name = StringField("Company name", validators=[DataRequired()])
    domain = StringField("Primary domain", validators=[DataRequired()])
    contact_name = StringField("Contact name", validators=[DataRequired()])
    contact_email = StringField("Contact email", validators=[DataRequired(), Email()])
    contact_phone = StringField("Contact phone", validators=[Optional()])
    assessment_type = SelectField(
        "Assessment type",
        choices=[(t.name, t.value) for t in AssessmentType],
        validators=[DataRequired()],
    )
    scope = TextAreaField("Scope", validators=[Optional()])
    auth_requirements = TextAreaField("Authentication requirements", validators=[Optional()])
    domain_count = IntegerField("Number of domains", validators=[Optional(), NumberRange(min=1)])
    timeline = StringField("Desired timeline", validators=[Optional()])
    notes = TextAreaField("Additional notes", validators=[Optional()])


@assessment.route("/request", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per hour")
def request_assessment():
    form = AssessmentRequestForm()
    if form.validate_on_submit():
        req = AssessmentRequest(
            org_id=current_user.org_id,
            requested_by_id=current_user.id,
            company_name=form.company_name.data.strip(),
            domain=form.domain.data.strip(),
            contact_name=form.contact_name.data.strip(),
            contact_email=form.contact_email.data.strip(),
            contact_phone=(form.contact_phone.data or "").strip() or None,
            assessment_type=AssessmentType[form.assessment_type.data],
            scope=(form.scope.data or "").strip() or None,
            auth_requirements=(form.auth_requirements.data or "").strip() or None,
            domain_count=form.domain_count.data,
            timeline=(form.timeline.data or "").strip() or None,
            notes=(form.notes.data or "").strip() or None,
        )
        db.session.add(req)
        db.session.commit()
        flash("Your assessment request has been submitted. Our team will reach out shortly.", "success")
        return redirect(url_for("scan.dashboard"))

    return render_template("assessment_request.html", form=form)
