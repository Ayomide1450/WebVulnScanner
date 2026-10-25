"""
Blueprint `billing`: /account/billing + invoice create/verify.

Invoice creation and verification are `@org_admin_required` (a billing
decision for the whole org), while viewing the billing page just requires
being logged in - any member can see their org's current plan/subscription
status and pending invoices.
"""
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from glassbox import billing
from glassbox.audit import log_org_event
from glassbox.decorators import org_admin_required
from glassbox.extensions import limiter
from glassbox.models import CryptoInvoice, InvoiceStatus, Plan

billing_bp = Blueprint("billing", __name__, url_prefix="/account/billing")

TOKEN_SYMBOLS = ("USDT", "USDC")


@billing_bp.route("", methods=["GET"])
@login_required
def view():
    org = current_user.organization
    subscription = org.subscription if org else None
    pending_invoices = (
        CryptoInvoice.query.filter_by(org_id=current_user.org_id, status=InvoiceStatus.PENDING)
        .order_by(CryptoInvoice.created_at.desc())
        .all()
        if current_user.org_id
        else []
    )
    return render_template(
        "billing.html",
        org=org,
        subscription=subscription,
        pending_invoices=pending_invoices,
        plan_prices=billing.PLAN_USD_PRICE,
        plan_annual_prices=billing.PLAN_ANNUAL_USD_PRICE,
        token_symbols=TOKEN_SYMBOLS,
        upgradable_plans=(Plan.PAID, Plan.ORG_VERIFIED),
        # Surfaced on each pending-invoice card (Phase 10 live-verification
        # feedback, 08-20) so a payer can double-check the token contract
        # before sending - the address alone doesn't tell them which token/
        # chain they're paying with, and self-custody crypto sent to the
        # wrong contract is unrecoverable. Read-only display value, not
        # used for verification (verify_invoice() already resolves this
        # itself from the invoice's own token_symbol).
        token_contracts={
            "USDT": current_app.config.get("USDT_CONTRACT_ADDRESS", ""),
            "USDC": current_app.config.get("USDC_CONTRACT_ADDRESS", ""),
        },
    )


@billing_bp.route("/invoice", methods=["POST"])
@login_required
@org_admin_required
@limiter.limit("10 per hour")
def create_invoice():
    target_plan_raw = request.form.get("target_plan")
    token_symbol = request.form.get("token_symbol")
    billing_cycle = request.form.get("billing_cycle", "monthly")

    try:
        target_plan = Plan(target_plan_raw)
    except ValueError:
        flash("Unknown plan selected.", "error")
        return redirect(url_for("billing.view"))

    if target_plan not in billing.PLAN_USD_PRICE:
        flash("That plan is not purchasable.", "error")
        return redirect(url_for("billing.view"))

    if token_symbol not in TOKEN_SYMBOLS:
        flash("Unsupported payment token.", "error")
        return redirect(url_for("billing.view"))

    if billing_cycle not in billing.BILLING_CYCLES:
        flash("Choose a monthly or annual billing cycle.", "error")
        return redirect(url_for("billing.view"))

    try:
        inv = billing.create_invoice(current_user.org_id, target_plan, token_symbol, billing_cycle)
    except RuntimeError as e:
        flash(str(e), "error")
        return redirect(url_for("billing.view"))

    log_org_event("invoice_created", detail=f"{target_plan.value} plan invoice ({billing_cycle})")
    flash(
        f"Invoice created ({billing_cycle} billing): send exactly {inv.expected_amount} {inv.token_symbol} "
        f"to {inv.receiving_address} before it expires.",
        "info",
    )
    return redirect(url_for("billing.view"))


@billing_bp.route("/invoice/<int:invoice_id>/verify", methods=["POST"])
@login_required
@org_admin_required
@limiter.limit("30 per hour")
def verify_invoice_route(invoice_id):
    inv = CryptoInvoice.query.get(invoice_id)
    if inv is None:
        abort(404)
    if inv.org_id != current_user.org_id:
        abort(403)

    paid = billing.verify_invoice(inv)
    if paid:
        log_org_event("invoice_verified", detail=f"Payment for {inv.target_plan.value} plan confirmed")
        flash(f"Payment confirmed - {inv.target_plan.value} plan is now active.", "info")
    else:
        flash("Payment not found yet (or invoice expired). Try again once the transfer confirms.", "error")
    return redirect(url_for("billing.view"))
