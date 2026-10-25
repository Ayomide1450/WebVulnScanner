"""Tests for glassbox/billing.py's pure logic - the invoice-amount-
collision retry in create_invoice(), and verify_invoice()'s status
transitions / Polygonscan-response matching. Previously untested (see
handoff.md's "known limitations" list) despite create_invoice()'s
collision-retry loop and verify_invoice()'s IntegrityError handling being
exactly the kind of logic a route-rendering test (test_billing_routes.py)
can't exercise - a real payment landing on the wrong org's plan is a
billing-correctness bug, not a cosmetic one.

Uses the `app`/`db` fixtures from conftest.py directly, without nesting a
second `with app.app_context():` inside the test body - the `db` fixture
already holds one open for the life of the test. Nesting a second one here
opened a second SQLite connection while the first transaction was still
open, deadlocking every test with "database is locked" the first time this
file was written - see handoff.md's "nested app_context()" pitfall entry.
"""
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from glassbox import billing
from glassbox.extensions import db as _db
from glassbox.models import CryptoInvoice, InvoiceStatus, Plan, Subscription, SubStatus
from tests.conftest import make_org


def _make_invoice(org, plan=Plan.PAID, token_symbol="USDT", status=InvoiceStatus.PENDING,
                   expected_amount=19.005, expires_in_minutes=60, created_minutes_ago=0,
                   billing_cycle="monthly"):
    now = datetime.now(UTC)
    inv = CryptoInvoice(
        org_id=org.id,
        target_plan=plan,
        billing_cycle=billing_cycle,
        token_symbol=token_symbol,
        chain="polygon",
        receiving_address="0xReceivingAddress",
        base_usd_amount=billing.PLAN_USD_PRICE[plan],
        unique_offset=round(expected_amount - billing.PLAN_USD_PRICE[plan], 4),
        expected_amount=expected_amount,
        status=status,
        expires_at=now + timedelta(minutes=expires_in_minutes),
        created_at=now - timedelta(minutes=created_minutes_ago),
    )
    _db.session.add(inv)
    _db.session.flush()
    return inv


# --------------------------------------------------------------------------
# create_invoice() - offset-collision retry
# --------------------------------------------------------------------------

def test_create_invoice_sets_expected_amount_above_base_price(app, db):
    org = make_org()
    inv = billing.create_invoice(org.id, Plan.PAID, "USDT")
    assert float(inv.expected_amount) > billing.PLAN_USD_PRICE[Plan.PAID]
    assert float(inv.expected_amount) < billing.PLAN_USD_PRICE[Plan.PAID] + 0.01
    assert inv.status == InvoiceStatus.PENDING


def test_create_invoice_annual_cycle_prices_at_10x_monthly(app, db):
    org = make_org()
    inv = billing.create_invoice(org.id, Plan.PAID, "USDT", billing_cycle="annual")
    assert inv.billing_cycle == "annual"
    assert float(inv.base_usd_amount) == billing.PLAN_ANNUAL_USD_PRICE[Plan.PAID]
    assert float(inv.base_usd_amount) == billing.PLAN_USD_PRICE[Plan.PAID] * 10


def test_create_invoice_rejects_unknown_billing_cycle(app, db):
    org = make_org()
    with pytest.raises(ValueError):
        billing.create_invoice(org.id, Plan.PAID, "USDT", billing_cycle="weekly")


def test_create_invoice_retries_on_amount_collision_then_succeeds(app, db):
    # First roll collides with an existing PENDING invoice for the same
    # plan; the retry loop must re-roll and land on a free amount instead
    # of creating a second invoice with the same expected_amount (which
    # would make verify_invoice's amount-only matching ambiguous).
    org = make_org()
    existing = _make_invoice(org, plan=Plan.PAID, expected_amount=19.0050)
    _db.session.commit()

    offsets = iter([0.0050, 0.0071])  # first collides (0.0050), second is free
    with patch.object(billing._system_random, "uniform", side_effect=lambda a, b: next(offsets)):
        inv = billing.create_invoice(org.id, Plan.PAID, "USDT")

    assert float(inv.expected_amount) != float(existing.expected_amount)
    assert float(inv.expected_amount) == pytest.approx(19.0071, abs=1e-6)


def test_create_invoice_ignores_collisions_with_non_pending_invoices(app, db):
    # A PAID or EXPIRED invoice's amount is no longer "claimed" - only
    # PENDING invoices should count as a collision.
    org = make_org()
    _make_invoice(org, plan=Plan.PAID, expected_amount=19.0050, status=InvoiceStatus.PAID)
    _db.session.commit()

    with patch.object(billing._system_random, "uniform", return_value=0.0050):
        inv = billing.create_invoice(org.id, Plan.PAID, "USDT")

    assert float(inv.expected_amount) == pytest.approx(19.0050, abs=1e-6)


def test_create_invoice_raises_after_exhausting_retry_budget(app, db):
    # Every roll collides - create_invoice must fail loudly rather than
    # silently create a second invoice with an already-claimed amount
    # (verify_invoice matches purely by amount, so that would let one real
    # payment activate the wrong org's plan).
    org = make_org()
    _make_invoice(org, plan=Plan.PAID, expected_amount=19.0050)
    _db.session.commit()

    with patch.object(billing._system_random, "uniform", return_value=0.0050):
        with pytest.raises(RuntimeError, match="Could not allocate a unique invoice amount"):
            billing.create_invoice(org.id, Plan.PAID, "USDT")


# --------------------------------------------------------------------------
# verify_invoice() - status short-circuits
# --------------------------------------------------------------------------

def test_verify_invoice_already_paid_short_circuits_true_without_network(app, db):
    org = make_org()
    inv = _make_invoice(org, status=InvoiceStatus.PAID)
    _db.session.commit()
    with patch("glassbox.billing.requests.get") as mock_get:
        assert billing.verify_invoice(inv) is True
        mock_get.assert_not_called()


def test_verify_invoice_already_expired_short_circuits_false_without_network(app, db):
    org = make_org()
    inv = _make_invoice(org, status=InvoiceStatus.EXPIRED)
    _db.session.commit()
    with patch("glassbox.billing.requests.get") as mock_get:
        assert billing.verify_invoice(inv) is False
        mock_get.assert_not_called()


def test_verify_invoice_past_expiry_flips_to_expired(app, db):
    org = make_org()
    inv = _make_invoice(org, expires_in_minutes=-5)  # already past expiry
    _db.session.commit()
    with patch("glassbox.billing.requests.get") as mock_get:
        assert billing.verify_invoice(inv) is False
        mock_get.assert_not_called()
    assert inv.status == InvoiceStatus.EXPIRED


# --------------------------------------------------------------------------
# verify_invoice() - Polygonscan response matching
# --------------------------------------------------------------------------

def _tx(amount_units, decimals=6, to="0xReceivingAddress", confirmations=10, ts=None, tx_hash="0xhash1"):
    if ts is None:
        # +2s, not "now": verify_invoice's int(tx["timeStamp"]) truncates to
        # whole seconds while inv.created_at.timestamp() keeps its
        # fractional part - a same-second "now" default can truncate to
        # *before* created_at's more precise value and get skipped by the
        # "must be after creation" check, which is what a real on-chain tx
        # (whole-second timestamps) landing shortly after invoice creation
        # would never have to worry about.
        ts = datetime.now(UTC).timestamp() + 2
    return {
        "timeStamp": str(int(ts)),
        "value": str(int(amount_units * (10 ** decimals))),
        "tokenDecimal": str(decimals),
        "to": to,
        "confirmations": str(confirmations),
        "hash": tx_hash,
    }


def test_verify_invoice_matches_and_activates_subscription(app, db):
    org = make_org(plan=Plan.FREE)
    inv = _make_invoice(org, plan=Plan.PAID, expected_amount=19.0050)
    _db.session.commit()

    matching_tx = _tx(19.0050)
    mock_resp = type("R", (), {"json": lambda self: {"result": [matching_tx]}})()
    with patch("glassbox.billing.requests.get", return_value=mock_resp):
        assert billing.verify_invoice(inv) is True

    assert inv.status == InvoiceStatus.PAID
    assert inv.matched_tx_hash == "0xhash1"
    sub = Subscription.query.filter_by(org_id=org.id).first()
    assert sub is not None
    assert sub.status == SubStatus.ACTIVE
    assert sub.plan == Plan.PAID
    assert org.plan == Plan.PAID  # entitlements.effective_tier() reads this, not Subscription


def test_verify_invoice_activates_annual_period_end_365_days(app, db):
    org = make_org(plan=Plan.FREE)
    inv = _make_invoice(org, plan=Plan.PAID, expected_amount=190.005, billing_cycle="annual")
    _db.session.commit()

    matching_tx = _tx(190.005)
    mock_resp = type("R", (), {"json": lambda self: {"result": [matching_tx]}})()
    with patch("glassbox.billing.requests.get", return_value=mock_resp):
        assert billing.verify_invoice(inv) is True

    sub = Subscription.query.filter_by(org_id=org.id).first()
    period_end = sub.current_period_end
    if period_end.tzinfo is None:
        period_end = period_end.replace(tzinfo=UTC)
    delta = period_end - datetime.now(UTC)
    assert 360 < delta.days <= 365  # ~365 days out, not the monthly 30


def test_verify_invoice_ignores_tx_below_min_confirmations(app, db):
    org = make_org()
    inv = _make_invoice(org, expected_amount=19.0050)
    _db.session.commit()

    low_conf_tx = _tx(19.0050, confirmations=1)  # below default INVOICE_MIN_CONFIRMATIONS=5
    mock_resp = type("R", (), {"json": lambda self: {"result": [low_conf_tx]}})()
    with patch("glassbox.billing.requests.get", return_value=mock_resp):
        assert billing.verify_invoice(inv) is False
    assert inv.status == InvoiceStatus.PENDING


def test_verify_invoice_ignores_tx_with_wrong_amount(app, db):
    org = make_org()
    inv = _make_invoice(org, expected_amount=19.0050)
    _db.session.commit()

    wrong_amount_tx = _tx(19.0099)
    mock_resp = type("R", (), {"json": lambda self: {"result": [wrong_amount_tx]}})()
    with patch("glassbox.billing.requests.get", return_value=mock_resp):
        assert billing.verify_invoice(inv) is False
    assert inv.status == InvoiceStatus.PENDING


def test_verify_invoice_ignores_tx_before_invoice_created(app, db):
    org = make_org()
    inv = _make_invoice(org, expected_amount=19.0050, created_minutes_ago=0)
    _db.session.commit()

    old_ts = (datetime.now(UTC) - timedelta(days=1)).timestamp()
    old_tx = _tx(19.0050, ts=old_ts)
    mock_resp = type("R", (), {"json": lambda self: {"result": [old_tx]}})()
    with patch("glassbox.billing.requests.get", return_value=mock_resp):
        assert billing.verify_invoice(inv) is False
    assert inv.status == InvoiceStatus.PENDING


def test_verify_invoice_network_failure_returns_false_not_raise(app, db):
    org = make_org()
    inv = _make_invoice(org, expected_amount=19.0050)
    _db.session.commit()

    import requests as requests_module
    with patch("glassbox.billing.requests.get", side_effect=requests_module.RequestException("boom")):
        assert billing.verify_invoice(inv) is False
    assert inv.status == InvoiceStatus.PENDING


def test_verify_invoice_malformed_json_returns_false_not_raise(app, db):
    org = make_org()
    inv = _make_invoice(org, expected_amount=19.0050)
    _db.session.commit()

    mock_resp = type("R", (), {"json": lambda self: (_ for _ in ()).throw(ValueError("bad json"))})()
    with patch("glassbox.billing.requests.get", return_value=mock_resp):
        assert billing.verify_invoice(inv) is False


def test_verify_invoice_double_match_on_matched_tx_hash_returns_false(app, db):
    # uq_crypto_invoices_matched_tx_hash (defense in depth alongside
    # create_invoice's offset-collision retry) - if the same on-chain tx
    # hash somehow already matched a *different* invoice, this invoice must
    # not also be marked paid for a payment it didn't receive.
    org = make_org()
    other_org = make_org(name="Other Org")
    already_matched = _make_invoice(
        other_org, expected_amount=49.0012, plan=Plan.ORG_VERIFIED, status=InvoiceStatus.PAID,
    )
    already_matched.matched_tx_hash = "0xduplicate"
    already_matched.matched_at = datetime.now(UTC)
    _db.session.commit()

    inv = _make_invoice(org, expected_amount=19.0050)
    _db.session.commit()

    dup_tx = _tx(19.0050, tx_hash="0xduplicate")
    mock_resp = type("R", (), {"json": lambda self: {"result": [dup_tx]}})()
    with patch("glassbox.billing.requests.get", return_value=mock_resp):
        assert billing.verify_invoice(inv) is False
    assert inv.status == InvoiceStatus.PENDING
