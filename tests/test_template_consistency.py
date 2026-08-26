"""Rendered-HTML assertions for HARD-05's reuse-only visual consistency
pass across dashboard.html, org_admin.html, billing.html and
scan_report.html.

This module owns HARD-05's observable assertions: the four in-scope
templates now apply classes that already existed in base.html (the shared
`.btn.primary` treatment, the `.hud-grid` texture, `.status-pill .dot` +
`.glow-pulse`, and one new `#icon-warning` sprite symbol) to spots that
were previously using older, pre-`base.html`-promotion styling. Per D-10
this is a reuse-only pass, so these tests check that already-existing
classes now appear on the four pages, rather than checking for any new
CSS declaration.

What these tests cannot answer - does the `.hud-grid` texture read well
behind the score gauge, does the state dot crowd the pill label at phone
width - is explicitly out of scope here and is settled at this plan's
human-verification checkpoint instead (04-UI-SPEC.md's one backstop row).
"""
from webvulnscanner.models import ScanStatus

from tests.conftest import login, make_org, make_scan, make_user
from tests.test_billing_routes import make_pending_invoice


# --------------------------------------------------------------------------
# dashboard.html
# --------------------------------------------------------------------------

def test_dashboard_new_scan_cta_uses_shared_primary_button(client, db):
    import pathlib

    org = make_org()
    make_user("cta@example.com", org=org)
    db.session.commit()

    login(client, "cta@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'class="btn primary"' in body
    # dashboard.html's own local style block no longer defines a gradient
    # button rule - base.html itself legitimately uses linear-gradient
    # elsewhere (.card, .score-card), so this is checked against the page's
    # own source, not the fully-rendered response.
    template_source = pathlib.Path("templates/dashboard.html").read_text(encoding="utf-8")
    assert 'linear-gradient' not in template_source


def test_dashboard_latest_scan_card_is_present(client, db):
    org = make_org()
    user = make_user("anchor@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    scan.risk_score = 80
    db.session.commit()

    login(client, "anchor@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'class="card"' in body


def test_dashboard_running_scan_status_pill_has_pulsing_dot(client, db):
    org = make_org()
    user = make_user("running@example.com", org=org)
    make_scan(user, org=org, status=ScanStatus.RUNNING)
    db.session.commit()

    login(client, "running@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'class="status-pill running"><span class="dot glow-pulse">' in body


def test_dashboard_completed_scan_status_pill_has_no_dot(client, db):
    org = make_org()
    user = make_user("completed@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    scan.risk_score = 90
    db.session.commit()

    login(client, "completed@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'dot glow-pulse' not in body


def test_dashboard_no_scans_shows_unchanged_empty_state(client, db):
    org = make_org()
    make_user("empty@example.com", org=org)
    db.session.commit()

    login(client, "empty@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No scans yet." in body
    assert 'dot glow-pulse' not in body
    assert 'class="card hud-grid"' not in body  # hud-grid removed in redesign


def test_dashboard_existing_queued_pill_class_string_unbroken(client, db):
    """Regression lock for tests/test_scan_routes.py's
    test_dashboard_scan_status_renders_as_a_pill - the nested dot markup
    must not disturb the pill's own class expression."""
    org = make_org()
    user = make_user("queuedpill@example.com", org=org)
    make_scan(user, org=org)  # default status is ScanStatus.QUEUED
    db.session.commit()

    login(client, "queuedpill@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    assert 'class="status-pill queued"' in resp.get_data(as_text=True)


# --------------------------------------------------------------------------
# org_admin.html
# --------------------------------------------------------------------------

def _make_admin(org, email="orgadmin@example.com"):
    from webvulnscanner.models import Role

    return make_user(email, org=org, role=Role.ORG_ADMIN, verified=True)


def test_org_admin_scan_history_card_is_present(client, db):
    org = make_org()
    admin = _make_admin(org)
    make_scan(admin, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()

    login(client, "orgadmin@example.com")
    resp = client.get("/org/admin")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'class="card"' in body


def test_org_admin_running_scan_row_has_pulsing_dot(client, db):
    org = make_org()
    admin = _make_admin(org)
    make_scan(admin, org=org, status=ScanStatus.RUNNING)
    db.session.commit()

    login(client, "orgadmin@example.com")
    resp = client.get("/org/admin")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'class="status-pill running"><span class="dot glow-pulse">' in body


def test_org_admin_completed_scan_row_has_no_dot(client, db):
    org = make_org()
    admin = _make_admin(org)
    make_scan(admin, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()

    login(client, "orgadmin@example.com")
    resp = client.get("/org/admin")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'dot glow-pulse' not in body


def test_org_admin_invite_button_uses_shared_primary_button(client, db):
    org = make_org()
    _make_admin(org)
    db.session.commit()

    login(client, "orgadmin@example.com")
    resp = client.get("/org/admin")

    assert resp.status_code == 200
    assert 'class="btn primary"' in resp.get_data(as_text=True)


def test_org_admin_members_and_domains_pills_unchanged(client, db):
    org = make_org()
    _make_admin(org)
    db.session.commit()

    login(client, "orgadmin@example.com")
    resp = client.get("/org/admin")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'class="pill pass"' in body


# --------------------------------------------------------------------------
# billing.html
# --------------------------------------------------------------------------

def test_billing_current_plan_card_is_present(client, db):
    org = make_org()
    make_user("billed@example.com", org=org)
    db.session.commit()

    login(client, "billed@example.com")
    resp = client.get("/account/billing")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'class="card"' in body


def test_billing_action_buttons_use_shared_primary_button(client, db):
    org = make_org()
    make_user("actions@example.com", org=org)
    make_pending_invoice(org)
    db.session.commit()

    login(client, "actions@example.com")
    resp = client.get("/account/billing")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert body.count('btn primary') == 2
    assert 'class="btn primary verify-btn"' in body


def test_billing_pending_invoice_shows_awaiting_payment_pill(client, db):
    org = make_org()
    make_user("pending@example.com", org=org)
    make_pending_invoice(org)
    db.session.commit()

    login(client, "pending@example.com")
    resp = client.get("/account/billing")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'Awaiting payment' in body
    assert 'status-pill running' in body


def test_billing_no_pending_invoices_shows_unchanged_empty_state(client, db):
    org = make_org()
    make_user("nopending@example.com", org=org)
    db.session.commit()

    login(client, "nopending@example.com")
    resp = client.get("/account/billing")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No pending invoices." in body
    assert "Awaiting payment" not in body


def test_billing_no_org_warning_uses_sprite_icon_not_emoji(client, db):
    make_user("noorg@example.com", org=None)
    db.session.commit()

    login(client, "noorg@example.com")
    resp = client.get("/account/billing")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert '#icon-warning' in body
    assert '&#9888' not in body
    assert '⚠' not in body


def test_admin_form_partial_uses_canonical_button_treatment():
    """Phase 6 (DESIGN-03) supersedes the Phase-4 (HARD-05) lock this test used to enforce -
    _admin_form_styles.html's bare gradient button{} override was itself divergent-component drift
    Phase 6 exists to consolidate. This now asserts the partial matches the same solid-accent,
    var(--accent)-based button treatment the other two form partials carry, with no gradient
    anywhere in the file."""
    import pathlib

    partial = pathlib.Path("templates/_admin_form_styles.html").read_text(encoding="utf-8")
    assert "linear-gradient" not in partial
    assert "background: var(--accent)" in partial


# --------------------------------------------------------------------------
# scan_report.html
# --------------------------------------------------------------------------

def test_scan_report_no_longer_duplicates_table_rule(client, db):
    """table/th/td and h1/h2.section are all canonical in base.html (Phase 4 promoted the table rule;
    Phase 6's 06-01/06-04 promoted h1/h2.section) - scan_report.html should define none of them
    locally."""
    import pathlib

    text = pathlib.Path("templates/scan_report.html").read_text(encoding="utf-8")
    assert "border-collapse" not in text
    assert "h2.section {" not in text
