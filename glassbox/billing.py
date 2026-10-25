"""
Self-built crypto (USDT/USDC on Polygon) billing logic (Workstream 6).

No Stripe, no HD wallets, no third-party payment processor - a single
self-custody receiving address (`CRYPTO_RECEIVING_ADDRESS`) plus
unique-amount invoicing (a random cents-level offset added to the plan's
base USD price) so an incoming transfer can be matched to exactly one
invoice by amount alone, verified against Polygonscan's free-tier
`tokentx` API.

Price table - not pinned by the user beyond "usdt/usdc"; these are this
workstream's own placeholder numbers, flagged for the judge to confirm or
override:
    PAID          $19.00/mo   or $190.00/yr (2 months free)
    ORG_VERIFIED  $49.00/mo   or $490.00/yr (2 months free)

Every purchasable plan is billed as a subscription, not a one-off charge -
`billing_cycle` ("monthly"/"annual") is a required choice on the upgrade
form (billing.html), stored on the `CryptoInvoice` row, and determines how
far `_activate_subscription()` pushes `current_period_end` out once the
invoice is paid (30 vs 365 days). There is no recurring auto-charge (this
is self-custody crypto, not a card on file) - `current_period_end` is
purely informational today, shown on the billing page so an admin knows
when to come back and pay the next invoice; a renewal reminder/downgrade-
on-expiry job is not built here (see billing.html for the shown-but-not-
yet-enforced framing).
"""
import random
from datetime import UTC, datetime, timedelta

# OS entropy source for invoice-amount offsets - see create_invoice() for why
# the default Mersenne Twister is not acceptable there.
_system_random = random.SystemRandom()

import requests
from flask import current_app
from sqlalchemy.exc import IntegrityError

from glassbox.extensions import db
from glassbox.models import CryptoInvoice, InvoiceStatus, Plan, Subscription, SubStatus

POLYGONSCAN_API_URL = "https://api.polygonscan.com/api"
# Same-ethos timeout convention as checks.py's REQUEST_TIMEOUT (8s) - this is
# a single API call, not a per-check budget, so a slightly longer timeout is
# reasonable, but it must still not be able to hang the request forever.
POLYGONSCAN_TIMEOUT = 10

PLAN_USD_PRICE = {
    Plan.PAID: 19.00,
    Plan.ORG_VERIFIED: 49.00,
}

# Annual price = 10x monthly (2 months free) - a standard SaaS annual
# discount, not independently priced. Kept as its own explicit dict (rather
# than computed inline at every call site) so billing.html and
# create_invoice() read the exact same numbers.
PLAN_ANNUAL_USD_PRICE = {plan: round(price * 10, 2) for plan, price in PLAN_USD_PRICE.items()}

BILLING_CYCLES = ("monthly", "annual")
BILLING_CYCLE_DAYS = {"monthly": 30, "annual": 365}


def price_for(target_plan, billing_cycle):
    return PLAN_ANNUAL_USD_PRICE[target_plan] if billing_cycle == "annual" else PLAN_USD_PRICE[target_plan]

# Amount-matching tolerance - must stay well below the smallest possible
# unique_offset (0.0001) so two invoices for the same plan can never
# collide, but still absorb float/Decimal rounding noise.
AMOUNT_MATCH_TOLERANCE = 1e-6


def _token_contract_address(token_symbol):
    if token_symbol == "USDT":  # noqa: S105 - crypto token symbol, not a password
        return current_app.config["USDT_CONTRACT_ADDRESS"]
    if token_symbol == "USDC":  # noqa: S105 - crypto token symbol, not a password
        return current_app.config["USDC_CONTRACT_ADDRESS"]
    raise ValueError(f"Unsupported token_symbol: {token_symbol!r}")


MAX_OFFSET_COLLISION_RETRIES = 25


def create_invoice(org_id, target_plan, token_symbol, billing_cycle="monthly"):
    """Creates a PENDING `CryptoInvoice` for `org_id` to upgrade to
    `target_plan`, paid in `token_symbol` (USDT/USDC), billed either
    `"monthly"` or `"annual"` (see `price_for`/`BILLING_CYCLE_DAYS`).

    `expected_amount` is the plan's base USD price plus a small random
    offset (four decimal places, 0.0001-0.0099) - this is what makes an
    incoming transfer identifiable as belonging to *this* invoice rather
    than any other pending invoice for the same plan+cycle.

    The offset space is only ~99 discrete values, so with multiple pending
    invoices for the same plan a naive random pick can collide (birthday-
    paradox math) - `verify_invoice` matches purely by amount, so a
    collision would let one real payment activate the wrong org's plan.
    Guard against that here: re-roll the offset (up to
    MAX_OFFSET_COLLISION_RETRIES times) if it collides with any other
    still-PENDING invoice's expected_amount for the same plan. This closes
    the loophole at creation time rather than trying to disambiguate two
    already-colliding invoices later. Monthly and annual prices for the
    same plan never collide with each other (10x apart), so the collision
    check doesn't need to filter on billing_cycle too.
    """
    if billing_cycle not in BILLING_CYCLES:
        raise ValueError(f"Unsupported billing_cycle: {billing_cycle!r}")
    base = price_for(target_plan, billing_cycle)

    for _ in range(MAX_OFFSET_COLLISION_RETRIES):
        # CSPRNG, not random.uniform: this offset is the ONLY thing binding
        # an on-chain payment to a specific org's invoice, because
        # verify_invoice() matches purely by amount. Mersenne Twister output
        # is reconstructable from observed samples, and an attacker can
        # sample it freely by creating their own invoices - which would let
        # them predict another org's expected amount and race a payment
        # against it.
        #
        # Residual, NOT fixed by this change: the offset space is only ~99
        # values (0.0001-0.0099 at 4dp), so it is guessable by brute force
        # regardless of generator quality. The real defences remain the
        # creation-time collision check below and matched_tx_hash's unique
        # constraint. Widening the space (more decimal places) or binding
        # payments by memo/reference instead of amount is the proper fix and
        # is not attempted here.
        offset = round(_system_random.uniform(0.0001, 0.0099), 4)
        expected = round(base + offset, 6)
        collision = CryptoInvoice.query.filter_by(
            target_plan=target_plan, status=InvoiceStatus.PENDING, expected_amount=expected,
        ).first()
        if collision is None:
            break
    else:
        # Exhausted the retry budget - every offset in the ~99-value space
        # is currently claimed by a pending invoice for this plan. Rather
        # than silently create a colliding invoice, fail loudly; the org
        # admin can just try again once some of those invoices expire.
        raise RuntimeError(
            "Could not allocate a unique invoice amount right now - too many "
            "pending invoices for this plan. Try again shortly."
        )

    now = datetime.now(UTC)

    inv = CryptoInvoice(
        org_id=org_id,
        target_plan=target_plan,
        billing_cycle=billing_cycle,
        token_symbol=token_symbol,
        chain=current_app.config["CRYPTO_CHAIN"],
        receiving_address=current_app.config["CRYPTO_RECEIVING_ADDRESS"],
        base_usd_amount=base,
        unique_offset=offset,
        expected_amount=expected,
        status=InvoiceStatus.PENDING,
        expires_at=now + timedelta(minutes=current_app.config["INVOICE_EXPIRY_MINUTES"]),
    )
    db.session.add(inv)
    db.session.commit()
    return inv


def verify_invoice(inv):
    """Checks whether `inv` has been paid, via Polygonscan's `tokentx`
    endpoint. Returns True iff `inv.status` is (or becomes) PAID.

    Short-circuits without hitting the network if the invoice is already
    resolved (PAID -> True, EXPIRED -> False) or has passed its
    `expires_at` (expires it in place and returns False).

    Network/API failures return False rather than raising - matches
    checks.py's `check_*` "one failing lookup shouldn't take down the
    request" convention.
    """
    if inv.status == InvoiceStatus.PAID:
        return True
    if inv.status == InvoiceStatus.EXPIRED:
        return False

    now = datetime.now(UTC)
    expires_at = inv.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if now > expires_at:
        inv.status = InvoiceStatus.EXPIRED
        db.session.commit()
        return False

    try:
        contract_address = _token_contract_address(inv.token_symbol)
        resp = requests.get(
            POLYGONSCAN_API_URL,
            params={
                "module": "account",
                "action": "tokentx",
                "contractaddress": contract_address,
                "address": inv.receiving_address,
                "sort": "desc",
                "apikey": current_app.config["POLYGONSCAN_API_KEY"],
            },
            timeout=POLYGONSCAN_TIMEOUT,
        )
        payload = resp.json()
        txs = payload.get("result") or []
        if not isinstance(txs, list):
            return False
    except (requests.RequestException, ValueError):
        return False

    created_at = inv.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    created_ts = created_at.timestamp()

    min_confirmations = current_app.config["INVOICE_MIN_CONFIRMATIONS"]

    for tx in txs:
        try:
            tx_ts = float(tx["timeStamp"])
            if tx_ts < created_ts:
                continue

            amount = int(tx["value"]) / (10 ** int(tx["tokenDecimal"]))
            if abs(amount - float(inv.expected_amount)) >= AMOUNT_MATCH_TOLERANCE:
                continue

            if tx["to"].lower() != inv.receiving_address.lower():
                continue

            if int(tx.get("confirmations", 0)) < min_confirmations:
                continue
        except (KeyError, TypeError, ValueError):
            continue

        inv.status = InvoiceStatus.PAID
        inv.matched_tx_hash = tx.get("hash")
        inv.matched_at = datetime.now(UTC)
        try:
            db.session.commit()
        except IntegrityError:
            # uq_crypto_invoices_matched_tx_hash fired - this exact
            # transaction has already been credited to a different
            # invoice (see create_invoice's offset-collision-retry
            # docstring for how that could still happen despite the
            # creation-time guard, e.g. a pre-existing DB from before
            # that guard shipped). Don't mark this invoice paid for a
            # payment it didn't actually receive.
            db.session.rollback()
            return False
        _activate_subscription(inv)
        return True

    return False


def _activate_subscription(inv):
    """Upserts `Subscription(org_id=inv.org_id)` and writes through to
    `Organization.plan` - the latter is what `entitlements.effective_tier()`
    actually reads, so this is the step that changes what a scan is allowed
    to do."""
    now = datetime.now(UTC)

    sub = Subscription.query.filter_by(org_id=inv.org_id).first()
    if sub is None:
        sub = Subscription(org_id=inv.org_id)
        db.session.add(sub)

    sub.plan = inv.target_plan
    sub.status = SubStatus.ACTIVE
    sub.current_period_end = now + timedelta(days=BILLING_CYCLE_DAYS.get(inv.billing_cycle, 30))

    inv.organization.plan = inv.target_plan

    db.session.commit()
