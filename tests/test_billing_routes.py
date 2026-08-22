"""
Route-level tests for `webvulnscanner/billing_routes.py`.

Originally just the two tests proving `/account/billing`'s pending-invoice
payment card renders. Extended in Phase 8 (SEC-09, 08-03-PLAN.md) to cover
the highest-value untested surface in the app after authorization itself:
whether an ORG_ADMIN session identity is actually checked against an
invoice's `org_id` before the route lets it verify a payment, replay one,
or tamper with `create_invoice`'s form values. `billing.py`'s own
unit-level logic (offset-collision retry, `matched_tx_hash` double-match
rejection) is already covered by `tests/test_billing.py` and is
deliberately NOT re-tested here - see the scoping-assumption lock at the
bottom of this module, which fails loudly if that assumption ever stops
being true.

Every test that can reach `billing.verify_invoice` patches
`webvulnscanner.billing.requests.get` (the module-local reference, not the
global `requests` package) rather than mocking `billing.verify_invoice`
itself - several assertions below depend on the *call count* of that patch
to prove whether the route reached the network at all, which only works if
the real function body still runs against a stubbed network call.
"""
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from webvulnscanner import billing
from webvulnscanner.models import (
    CryptoInvoice,
    InvoiceStatus,
    Organization,
    Plan,
    Role,
    Subscription,
)
from tests.conftest import login, make_org, make_user

DEFAULT_RECEIVING_ADDRESS = "0xABCDEF0123456789ABCDEF0123456789ABCDEF01"


def make_pending_invoice(
    org,
    target_plan=Plan.PAID,
    token_symbol="USDT",
    status=InvoiceStatus.PENDING,
    receiving_address=DEFAULT_RECEIVING_ADDRESS,
    matched_tx_hash=None,
    matched_at=None,
):
    inv = CryptoInvoice(
        org_id=org.id,
        target_plan=target_plan,
        token_symbol=token_symbol,
        chain="polygon",
        receiving_address=receiving_address,
        base_usd_amount=Decimal("19.00"),
        unique_offset=Decimal("0.000123"),
        expected_amount=Decimal("19.000123"),
        status=status,
        matched_tx_hash=matched_tx_hash,
        matched_at=matched_at,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    from webvulnscanner.extensions import db

    db.session.add(inv)
    db.session.flush()
    return inv


def _polygonscan_response(txs=None):
    """A minimal stand-in for `requests.Response` carrying only the
    `.json()` method `billing.verify_invoice` actually calls."""
    return type("R", (), {"json": lambda self: {"result": txs or []}})()


# --------------------------------------------------------------------------
# GET /account/billing - payment card rendering (pre-existing coverage)
# --------------------------------------------------------------------------

def test_pending_invoice_renders_as_a_payment_card_with_copy_button(client, db):
    # Viewing /account/billing only requires login (any member, not just an
    # org admin - creating/verifying invoices is the org-admin-only part),
    # so the default make_user() role is enough here.
    org = make_org()
    make_user("payer@example.com", org=org)
    inv = make_pending_invoice(org)
    db.session.commit()

    login(client, "payer@example.com")
    resp = client.get("/account/billing")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'class="invoice-card"' in body
    assert f'id="addr-{inv.id}"' in body
    assert "0xABCDEF0123456789ABCDEF0123456789ABCDEF01" in body
    assert "Copy" in body


def test_no_pending_invoices_still_shows_empty_state(client, db):
    org = make_org()
    make_user("nopay@example.com", org=org)
    db.session.commit()

    login(client, "nopay@example.com")
    resp = client.get("/account/billing")

    assert resp.status_code == 200
    assert "No pending invoices." in resp.get_data(as_text=True)


# --------------------------------------------------------------------------
# Cross-org invoice verification (SEC-09, T-08-13) - Task 1
#
# billing_routes.verify_invoice_route:95's `inv.org_id != current_user.org_id:
# abort(403)` is the only thing standing between an incrementing invoice ID
# and another org's plan activation. Read alongside billing.py, the guard is
# already present and correctly ordered ahead of the `billing.verify_invoice`
# call - this section closes a *proof* gap (D-02), not a vulnerability.
# --------------------------------------------------------------------------

def test_cross_org_verify_is_refused_and_makes_no_changes(client, db):
    org_a = make_org(name="Org A")
    org_b = make_org(name="Org B")
    make_user("admina@example.com", org=org_a, role=Role.ORG_ADMIN)
    make_user("adminb@example.com", org=org_b, role=Role.ORG_ADMIN)
    inv = make_pending_invoice(org_b)
    db.session.commit()

    inv_id = inv.id
    org_b_id = org_b.id
    pre_status = inv.status
    pre_matched_tx_hash = inv.matched_tx_hash
    pre_matched_at = inv.matched_at
    pre_plan = org_b.plan

    login(client, "admina@example.com")

    with patch("webvulnscanner.billing.requests.get") as mock_get:
        resp = client.post(f"/account/billing/invoice/{inv_id}/verify")

    assert resp.status_code == 403
    mock_get.assert_not_called()

    db.session.expire_all()
    refreshed_inv = CryptoInvoice.query.get(inv_id)
    assert refreshed_inv.status == pre_status == InvoiceStatus.PENDING
    assert pre_matched_tx_hash is None
    assert refreshed_inv.matched_tx_hash is None
    assert pre_matched_at is None
    assert refreshed_inv.matched_at is None

    refreshed_org_b = Organization.query.get(org_b_id)
    assert refreshed_org_b.plan == pre_plan == Plan.FREE
    assert Subscription.query.filter_by(org_id=org_b_id).count() == 0


def test_verify_nonexistent_invoice_returns_404(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()

    login(client, "admin@example.com")
    resp = client.post("/account/billing/invoice/999999/verify")

    assert resp.status_code == 404


def test_owning_org_admin_can_reach_verify_invoice(client, db):
    # Positive control: the guard must not refuse the org that actually owns
    # the invoice. billing.verify_invoice's own return value doesn't matter
    # here (an empty tx list is a legitimate "not paid yet" outcome) - what
    # matters is that the route reaches billing.verify_invoice at all
    # (call_count == 1) and redirects back to the billing view.
    org = make_org()
    make_user("owner@example.com", org=org, role=Role.ORG_ADMIN)
    inv = make_pending_invoice(org)
    db.session.commit()

    login(client, "owner@example.com")

    with patch("webvulnscanner.billing.requests.get", return_value=_polygonscan_response()) as mock_get:
        resp = client.post(f"/account/billing/invoice/{inv.id}/verify")

    assert resp.status_code == 302
    assert mock_get.call_count == 1


def test_plain_member_cannot_verify_but_can_still_view_billing(client, db):
    # The view/act split is deliberate: any member can see the billing page,
    # but only an ORG_ADMIN can create or verify invoices.
    # decorators.org_admin_required aborts 403 for a non-ORG_ADMIN.
    org = make_org()
    make_user("member@example.com", org=org, role=Role.MEMBER)
    inv = make_pending_invoice(org)
    db.session.commit()

    login(client, "member@example.com")

    resp = client.post(f"/account/billing/invoice/{inv.id}/verify")
    assert resp.status_code == 403

    resp2 = client.get("/account/billing")
    assert resp2.status_code == 200


# --------------------------------------------------------------------------
# Replay safety (SEC-09, T-08-14) - Task 2
#
# The route flashes a SUCCESS message whenever billing.verify_invoice
# returns True, including the PAID short-circuit - so a replayed POST looks
# successful to the user. The guarantee under test is that nothing actually
# changes, not that the user sees a failure.
# --------------------------------------------------------------------------

def test_replaying_verify_on_a_paid_invoice_changes_nothing(client, db):
    # Seeded via billing._activate_subscription itself (rather than
    # hand-building a Subscription row) so this test exercises the exact
    # upsert a real prior payment would have run, instead of a hand-rolled
    # approximation of it - see 08-03-SUMMARY.md for why this was chosen
    # over directly constructing the Subscription/Organization.plan state.
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    inv = make_pending_invoice(
        org, status=InvoiceStatus.PAID, matched_tx_hash="0xexistingpayment",
        matched_at=datetime.now(timezone.utc),
    )
    db.session.commit()
    billing._activate_subscription(inv)
    db.session.commit()

    inv_id = inv.id
    org_id = org.id
    sub = Subscription.query.filter_by(org_id=org_id).first()
    pre_period_end = sub.current_period_end
    pre_sub_status = sub.status
    pre_sub_plan = sub.plan
    pre_org_plan = org.plan
    pre_matched_tx_hash = inv.matched_tx_hash

    login(client, "admin@example.com")

    with patch("webvulnscanner.billing.requests.get") as mock_get:
        resp = client.post(f"/account/billing/invoice/{inv_id}/verify")

    assert resp.status_code == 302
    mock_get.assert_not_called()  # PAID short-circuits before any network call

    db.session.expire_all()
    refreshed_inv = CryptoInvoice.query.get(inv_id)
    refreshed_sub = Subscription.query.filter_by(org_id=org_id).first()
    refreshed_org = Organization.query.get(org_id)

    assert refreshed_inv.matched_tx_hash == pre_matched_tx_hash
    assert refreshed_sub.current_period_end == pre_period_end
    assert refreshed_sub.status == pre_sub_status
    assert refreshed_sub.plan == pre_sub_plan
    assert refreshed_org.plan == pre_org_plan


# --------------------------------------------------------------------------
# Value tampering / org injection (SEC-09, T-08-15 / T-08-16) - Task 2
# --------------------------------------------------------------------------

def _login_as_org_admin(client, db, email="admin@example.com", org=None):
    org = org or make_org()
    make_user(email, org=org, role=Role.ORG_ADMIN)
    db.session.commit()
    login(client, email)
    return org


def test_create_invoice_rejects_unknown_plan_value(client, db):
    _login_as_org_admin(client, db)
    resp = client.post(
        "/account/billing/invoice",
        data={"target_plan": "not_a_real_plan", "token_symbol": "USDT", "billing_cycle": "monthly"},
    )
    assert resp.status_code == 302
    assert CryptoInvoice.query.count() == 0


def test_create_invoice_rejects_plan_not_purchasable(client, db):
    # Plan.FREE is a real Plan enum member (so it survives the Plan(...)
    # constructor) but is deliberately absent from billing.PLAN_USD_PRICE -
    # it must be rejected by the second gate, not the first.
    _login_as_org_admin(client, db)
    resp = client.post(
        "/account/billing/invoice",
        data={"target_plan": Plan.FREE.value, "token_symbol": "USDT", "billing_cycle": "monthly"},
    )
    assert resp.status_code == 302
    assert CryptoInvoice.query.count() == 0


def test_create_invoice_rejects_unsupported_token_symbol(client, db):
    _login_as_org_admin(client, db)
    resp = client.post(
        "/account/billing/invoice",
        data={"target_plan": Plan.PAID.value, "token_symbol": "BTC", "billing_cycle": "monthly"},
    )
    assert resp.status_code == 302
    assert CryptoInvoice.query.count() == 0


def test_create_invoice_rejects_invalid_billing_cycle(client, db):
    _login_as_org_admin(client, db)
    resp = client.post(
        "/account/billing/invoice",
        data={"target_plan": Plan.PAID.value, "token_symbol": "USDT", "billing_cycle": "weekly"},
    )
    assert resp.status_code == 302
    assert CryptoInvoice.query.count() == 0


def test_create_invoice_happy_path_derives_expected_amount_from_price_table(client, db):
    org = _login_as_org_admin(client, db)
    resp = client.post(
        "/account/billing/invoice",
        data={"target_plan": Plan.PAID.value, "token_symbol": "USDT", "billing_cycle": "monthly"},
    )
    assert resp.status_code == 302
    assert CryptoInvoice.query.count() == 1

    inv = CryptoInvoice.query.first()
    assert inv.org_id == org.id
    base_price = billing.PLAN_USD_PRICE[Plan.PAID]
    # expected_amount = base price + a 0.0001-0.0099 unique_offset (see
    # billing.create_invoice's docstring) - assert against that derived
    # range, not a hardcoded literal.
    assert base_price < float(inv.expected_amount) < base_price + 0.01


def test_create_invoice_ignores_injected_org_id_form_field(client, db):
    org = _login_as_org_admin(client, db)
    other_org = make_org(name="Other Org")
    db.session.commit()

    resp = client.post(
        "/account/billing/invoice",
        data={
            "target_plan": Plan.PAID.value,
            "token_symbol": "USDT",
            "billing_cycle": "monthly",
            "org_id": str(other_org.id),
        },
    )
    assert resp.status_code == 302
    assert CryptoInvoice.query.count() == 1

    inv = CryptoInvoice.query.first()
    assert inv.org_id == org.id
    assert inv.org_id != other_org.id


# --------------------------------------------------------------------------
# Cross-org listing scope (SEC-09, T-08-17) - Task 2
# --------------------------------------------------------------------------

def test_billing_view_never_renders_another_orgs_pending_invoice(client, db):
    org_a = make_org(name="Org A")
    org_b = make_org(name="Org B")
    make_user("membera@example.com", org=org_a, role=Role.MEMBER)
    make_user("memberb@example.com", org=org_b, role=Role.MEMBER)
    make_pending_invoice(org_a, receiving_address="0xORGADEADBEEFDEADBEEFDEADBEEFDEADBEEF0A")
    inv_b = make_pending_invoice(org_b, receiving_address="0xORGBDEADBEEFDEADBEEFDEADBEEFDEADBEEF0B")
    db.session.commit()

    login(client, "membera@example.com")
    resp = client.get("/account/billing")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert inv_b.receiving_address not in body
    assert f'id="addr-{inv_b.id}"' not in body


# --------------------------------------------------------------------------
# Scoping-assumption lock (SEC-09, T-08-19) - Task 2
#
# This plan deliberately does not re-test billing.py's unit-level logic
# (offset-collision retry, matched_tx_hash double-match rejection) because
# tests/test_billing.py already covers it. That's only a safe scoping
# decision as long as those two tests keep existing - this lock fails
# loudly the moment either one is deleted or renamed.
# --------------------------------------------------------------------------

def test_test_billing_still_covers_the_two_unit_tests_this_plan_relies_on():
    source = (Path(__file__).resolve().parent / "test_billing.py").read_text(encoding="utf-8")
    assert "def test_create_invoice_raises_after_exhausting_retry_budget(" in source
    assert "def test_verify_invoice_double_match_on_matched_tx_hash_returns_false(" in source
