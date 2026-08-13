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


def test_dashboard_latest_scan_card_is_the_one_textured_anchor(client, db):
    org = make_org()
    user = make_user("anchor@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    scan.risk_score = 80
    db.session.commit()

    login(client, "anchor@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert body.count('class="card hud-grid"') == 1


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
    assert 'class="card hud-grid"' not in body


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
