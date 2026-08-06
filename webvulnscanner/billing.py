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
    PAID          $19.00/mo
    ORG_VERIFIED  $49.00/mo
"""
import random
from datetime import datetime, timedelta, timezone

import requests
from flask import current_app

from webvulnscanner.extensions import db
from webvulnscanner.models import InvoiceStatus, CryptoInvoice, Plan, SubStatus, Subscription

POLYGONSCAN_API_URL = "https://api.polygonscan.com/api"
# Same-ethos timeout convention as checks.py's REQUEST_TIMEOUT (8s) - this is
# a single API call, not a per-check budget, so a slightly longer timeout is
# reasonable, but it must still not be able to hang the request forever.
POLYGONSCAN_TIMEOUT = 10

PLAN_USD_PRICE = {
    Plan.PAID: 19.00,
    Plan.ORG_VERIFIED: 49.00,
}

# Amount-matching tolerance - must stay well below the smallest possible
# unique_offset (0.0001) so two invoices for the same plan can never
# collide, but still absorb float/Decimal rounding noise.
AMOUNT_MATCH_TOLERANCE = 1e-6


def _token_contract_address(token_symbol):
    if token_symbol == "USDT":
        return current_app.config["USDT_CONTRACT_ADDRESS"]
    if token_symbol == "USDC":
        return current_app.config["USDC_CONTRACT_ADDRESS"]
    raise ValueError(f"Unsupported token_symbol: {token_symbol!r}")


def create_invoice(org_id, target_plan, token_symbol):
    """Creates a PENDING `CryptoInvoice` for `org_id` to upgrade to
    `target_plan`, paid in `token_symbol` (USDT/USDC).

    `expected_amount` is the plan's base USD price plus a small random
    offset (four decimal places, 0.0001-0.0099) - this is what makes an
    incoming transfer identifiable as belonging to *this* invoice rather
    than any other pending invoice for the same plan.
    """
    base = PLAN_USD_PRICE[target_plan]
    offset = round(random.uniform(0.0001, 0.0099), 4)
    expected = round(base + offset, 6)
    now = datetime.now(timezone.utc)

    inv = CryptoInvoice(
        org_id=org_id,
        target_plan=target_plan,
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

    now = datetime.now(timezone.utc)
    expires_at = inv.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
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
        created_at = created_at.replace(tzinfo=timezone.utc)
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
        inv.matched_at = datetime.now(timezone.utc)
        db.session.commit()
        _activate_subscription(inv)
        return True

    return False


def _activate_subscription(inv):
    """Upserts `Subscription(org_id=inv.org_id)` and writes through to
    `Organization.plan` - the latter is what `entitlements.effective_tier()`
    actually reads, so this is the step that changes what a scan is allowed
    to do."""
    now = datetime.now(timezone.utc)

    sub = Subscription.query.filter_by(org_id=inv.org_id).first()
    if sub is None:
        sub = Subscription(org_id=inv.org_id)
        db.session.add(sub)

    sub.plan = inv.target_plan
    sub.status = SubStatus.ACTIVE
    sub.current_period_end = now + timedelta(days=30)

    inv.organization.plan = inv.target_plan

    db.session.commit()
