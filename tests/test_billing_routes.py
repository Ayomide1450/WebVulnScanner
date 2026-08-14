"""Tests for templates/billing.html's pending-invoice payment card."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from webvulnscanner.models import CryptoInvoice, InvoiceStatus, Plan
from tests.conftest import login, make_org, make_user


def make_pending_invoice(org, target_plan=Plan.PAID, token_symbol="USDT"):
    inv = CryptoInvoice(
        org_id=org.id,
        target_plan=target_plan,
        token_symbol=token_symbol,
        chain="polygon",
        receiving_address="0xABCDEF0123456789ABCDEF0123456789ABCDEF01",
        base_usd_amount=Decimal("19.00"),
        unique_offset=Decimal("0.000123"),
        expected_amount=Decimal("19.000123"),
        status=InvoiceStatus.PENDING,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    from webvulnscanner.extensions import db

    db.session.add(inv)
    db.session.flush()
    return inv


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
    user = make_user("nopay@example.com", org=org)
    db.session.commit()

    login(client, "nopay@example.com")
    resp = client.get("/account/billing")

    assert resp.status_code == 200
    assert "No pending invoices." in resp.get_data(as_text=True)
