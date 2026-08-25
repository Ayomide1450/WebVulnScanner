"""
Blueprint `webhooks`: /webhooks (+ add/delete/toggle/test/deliveries).

Phase 19 (WEBH-*): the management UI for the outbound-webhook surface
implemented in `webvulnscanner/webhooks.py` - that module owns delivery
and signing; this file owns CRUD, scoping, and validation.

Scope model (mirrors `_scoped_asset_query()`'s dual rule):

- A user WITH an org manages ORG webhooks - but only as ORG_ADMIN, the
  same authority boundary as invites/domains (an integration that receives
  every scan result for the org is exactly as sensitive as those). Members
  can still open /webhooks; they get an explanation and an empty list
  rather than a 404, since the nav link is visible to everyone and "where
  did that go?" is a worse answer than a plain sentence.
- A SOLO user (`org_id` None) manages their own personal webhooks, which
  only ever receive scans they ran themselves.

Every mutating route re-checks ownership server-side (404-not-403
convention) - the template hiding an action button is never the guard.
"""
import secrets

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from wtforms import SelectField, StringField
from wtforms.validators import DataRequired, Length, Optional

from webvulnscanner.audit import log_org_event
from webvulnscanner.extensions import db, limiter
from webvulnscanner.models import OutboundWebhook, Role, WebhookDelivery
from webvulnscanner.webhooks import (
    redact_webhook_url,
    send_test_ping,
    validate_webhook_url,
)

webhooks_bp = Blueprint("webhooks", __name__)


class AddWebhookForm(FlaskForm):
    label = StringField("Label", validators=[DataRequired(), Length(max=120)])
    url = StringField("Webhook URL", validators=[Optional(), Length(max=2048)])
    # Phase 25 (INTG-02): payload wrapping format — "default" (raw Glassbox
    # JSON, works for Slack/generic receivers) or "splunk_hec" (wraps in
    # {"event": ..., "sourcetype": "glassbox:scan"} for Splunk HEC ingestion).
    payload_format = SelectField("Payload Format", choices=[
        ("default", "Glassbox JSON (default)"),
        ("splunk_hec", "Splunk HEC"),
    ], default="default")


def _scoped_webhook_or_404(webhook_id):
    """Loads the webhook and enforces manage-authority: org webhooks are
    manageable by their org's ORG_ADMIN only, solo webhooks by their creator
    only. 404 (not 403), matching every other cross-scope access in the
    app - the endpoint's existence isn't information for non-holders."""
    w = OutboundWebhook.query.get_or_404(webhook_id)
    if w.org_id is not None:
        if current_user.org_id != w.org_id or current_user.role != Role.ORG_ADMIN:
            abort(404)
    else:
        if w.created_by_user_id != current_user.id:
            abort(404)
    return w


@webhooks_bp.route("/webhooks")
@login_required
def index():
    """List the caller's scope's webhooks + recent deliveries, with the add
    form. ?created=<id> (set by a successful add) re-displays that webhook's
    signing secret ONE page-render at a time - it is shown nowhere before or
    after, so a receiver can verify signatures without Glassbox ever being
    able to re-reveal the secret on demand."""
    form = AddWebhookForm()
    new_webhook = None
    created_id = request.args.get("created", type=int)
    if created_id:
        candidate = OutboundWebhook.query.get(created_id)
        if candidate is not None:
            if candidate.org_id is not None:
                if candidate.org_id == current_user.org_id and current_user.role == Role.ORG_ADMIN:
                    new_webhook = candidate
            elif candidate.created_by_user_id == current_user.id:
                new_webhook = candidate

    if current_user.org_id is not None and current_user.role == Role.ORG_ADMIN:
        rows = (OutboundWebhook.query.filter_by(org_id=current_user.org_id)
                .order_by(OutboundWebhook.created_at.desc()).all())
        member_note = False
    elif current_user.org_id is not None:
        # Org member without admin rights: no list (nothing here is theirs),
        # just the explanation.
        rows, member_note = [], True
    else:
        rows = (OutboundWebhook.query.filter_by(
                    org_id=None, created_by_user_id=current_user.id)
                .order_by(OutboundWebhook.created_at.desc()).all())
        member_note = False

    visible_ids = [w.id for w in rows]
    deliveries = ([], [])
    if visible_ids:
        deliveries = (
            (WebhookDelivery.query.filter(WebhookDelivery.webhook_id.in_(visible_ids))
             .order_by(WebhookDelivery.created_at.desc()).limit(15).all()),
            {w.id: w.label for w in rows},
        )

    return render_template(
        "webhooks.html", form=form, webhooks=rows, member_note=member_note,
        deliveries=deliveries[0], labels_by_id=deliveries[1],
        new_webhook=new_webhook, redact=redact_webhook_url,
    )


@webhooks_bp.route("/webhooks/add", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def add():
    """Create a webhook. The URL goes through validate_webhook_url()'s HTTPS +
    SSRF gate BEFORE any row exists (same fail-closed shape as the scan-target
    flow); the signing secret is generated server-side and shown once via the
    redirect target."""
    form = AddWebhookForm()
    if not form.validate_on_submit():
        flash("A label and webhook URL are required.", "error")
        return redirect(url_for("webhooks.index"))

    error = validate_webhook_url((form.url.data or "").strip())
    if error is not None:
        flash(error, "error")
        return redirect(url_for("webhooks.index"))

    w = OutboundWebhook(
        org_id=current_user.org_id,  # None for solo users - personal webhook
        created_by_user_id=current_user.id,
        label=(form.label.data or "").strip(),
        url=(form.url.data or "").strip(),
        secret=secrets.token_hex(32),
        payload_format=form.payload_format.data or "default",
    )
    db.session.add(w)
    log_org_event("webhook_created", detail=f"Webhook \"{w.label}\" created")
    db.session.commit()
    return redirect(url_for("webhooks.index", created=w.id))


@webhooks_bp.route("/webhooks/<int:webhook_id>/delete", methods=["POST"])
@login_required
def delete_webhook(webhook_id):
    """Removes the webhook. Its WebhookDelivery rows keep their FK values but
    are left orphaned by design (append-only history convention - same reason
    OrgAuditEvent outlives its DomainVerification); they simply stop
    appearing once their webhook_id no longer resolves to a listed row."""
    w = _scoped_webhook_or_404(webhook_id)
    label = w.label
    log_org_event("webhook_deleted", detail=f"Webhook \"{label}\" deleted")
    db.session.delete(w)
    db.session.commit()
    flash(f"Webhook \"{w.label}\" deleted.", "info")
    return redirect(url_for("webhooks.index"))


@webhooks_bp.route("/webhooks/<int:webhook_id>/toggle", methods=["POST"])
@login_required
def toggle_webhook(webhook_id):
    """Pause/resume without losing the stored URL/secret - a temporarily
    noisy channel shouldn't force re-registering (and re-verifying) it."""
    w = _scoped_webhook_or_404(webhook_id)
    w.is_active = not w.is_active
    action = "resumed" if w.is_active else "paused"
    log_org_event("webhook_toggled", detail=f"Webhook \"{w.label}\" {action}")
    db.session.commit()
    flash(
        f"Webhook \"{w.label}\" {'resumed' if w.is_active else 'paused'}.",
        "info",
    )
    return redirect(url_for("webhooks.index"))


@webhooks_bp.route("/webhooks/<int:webhook_id>/test", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def test_webhook(webhook_id):
    """Fires send_test_ping() synchronously - the caller is waiting on this
    exact button, and one bounded POST (5s timeout) is the point."""
    w = _scoped_webhook_or_404(webhook_id)
    ok, error = send_test_ping(w)
    if ok:
        flash(f"Test ping to \"{w.label}\" delivered.", "info")
    else:
        flash(f"Test ping to \"{w.label}\" failed: {error}", "error")
    return redirect(url_for("webhooks.index"))


@webhooks_bp.route("/webhooks/<int:webhook_id>/deliveries")
@login_required
def deliveries(webhook_id):
    """Recent attempts for one webhook, newest first - the debugging view
    for "is my Slack integration actually working?"."""
    w = _scoped_webhook_or_404(webhook_id)
    rows = (WebhookDelivery.query.filter_by(webhook_id=w.id)
            .order_by(WebhookDelivery.created_at.desc()).limit(25).all())
    return render_template(
        "webhook_deliveries.html", webhook=w, deliveries=rows, redact=redact_webhook_url,
    )
