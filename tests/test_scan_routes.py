"""Tests for webvulnscanner/scan_routes.py's dashboard() view."""
from tests.conftest import login, make_org, make_scan, make_user


def test_dashboard_single_scored_scan_renders_flat_reference_line(client, db):
    """Regression test for the single-point sparkline bug: with exactly one
    scored scan, the SVG used to render one bare <circle> with no
    <polyline> at all (SVG polylines need >=2 points) - an unlabeled
    floating dot. It should now render a flat 2-point reference line plus a
    text label."""
    org = make_org()
    user = make_user("solo@example.com", org=org)
    scan = make_scan(user, org=org)
    scan.risk_score = 42
    db.session.commit()

    login(client, "solo@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    sh = 70
    y = round(sh - (42 / 100 * sh), 1)
    assert f'<polyline points="0,{y} 560,{y}"' in body
    assert "only scan so far" in body


def test_dashboard_multiple_scored_scans_render_a_trend_polyline(client, db):
    org = make_org()
    user = make_user("trend@example.com", org=org)
    for score in (30, 70):
        s = make_scan(user, org=org)
        s.risk_score = score
    db.session.commit()

    login(client, "trend@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "only scan so far" not in body
    assert body.count("<circle cx=") >= 2


def test_dashboard_no_scored_scans_shows_not_enough_data_message(client, db):
    org = make_org()
    user = make_user("empty@example.com", org=org)
    make_scan(user, org=org)  # risk_score stays None (still queued)
    db.session.commit()

    login(client, "empty@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    assert "Not enough completed scans yet for a trend line." in resp.get_data(as_text=True)
