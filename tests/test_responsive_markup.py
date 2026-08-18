"""Rendered-HTML and source-level markup assertions for RESP-03's
dual-markup table/card contract (D-01) and the base.html CSS surface it
depends on.

This module owns RESP-03's markup-presence half: it asserts that a table
which has been converted to the dual-markup pattern renders BOTH a semantic
`<table>` (desktop) and a curated `.mobile-record-cards` list (mobile) from
the same collection, in the same order, inside the same conditional - and
that base.html carries every CSS class/media-query wave 2's five parallel
plans will reference. What it cannot answer - what actually happens at a
given viewport width in a real browser, whether text truncates instead of
overflowing, what the Tab order looks like - this repo has no
browser-driving tool, so that half is explicitly deferred to this plan's
`checkpoint:human-verify` task instead.

Selectors: `-k table_cards` picks the dual-markup presence tests (this
plan's Task 1); `-k base_css_surface` picks the base.html CSS-surface
regression lock (this plan's Task 2) - a wave-2 executor can run that one
selection alone to confirm base.html hasn't drifted before touching any of
its five parallel plans.
"""
from webvulnscanner.models import ScanStatus

from tests.conftest import login, make_org, make_scan, make_user


# --------------------------------------------------------------------------
# dashboard.html Scan History - dual-markup table/card presence (Task 1)
# --------------------------------------------------------------------------

def test_dashboard_table_cards_both_blocks_present_for_one_scan(client, db):
    org = make_org()
    user = make_user("cards1@example.com", org=org)
    make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()

    login(client, "cards1@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'class="table-scroll desktop-table"' in body
    assert "<thead>" in body and "</thead>" in body
    assert "<tbody>" in body and "</tbody>" in body
    assert 'class="mobile-record-cards"' in body


def test_dashboard_table_cards_th_cells_live_inside_thead(client, db):
    org = make_org()
    user = make_user("cards2@example.com", org=org)
    make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()

    login(client, "cards2@example.com")
    resp = client.get("/dashboard")

    body = resp.get_data(as_text=True)
    thead_start = body.index("<thead>")
    thead_end = body.index("</thead>")
    thead_block = body[thead_start:thead_end]
    assert "<th>" in thead_block


def test_dashboard_table_cards_counts_match_two_scans(client, db):
    org = make_org()
    user = make_user("cards3@example.com", org=org)
    make_scan(user, org=org, target_url="https://one.example.com", status=ScanStatus.COMPLETED)
    make_scan(user, org=org, target_url="https://two.example.com", status=ScanStatus.COMPLETED)
    db.session.commit()

    login(client, "cards3@example.com")
    resp = client.get("/dashboard")

    body = resp.get_data(as_text=True)
    assert body.count('class="card record-card"') == 2
    # Data rows only - the <thead> row's <tr> is excluded from this count
    # because it's outside <tbody>.
    tbody_start = body.index("<tbody>")
    tbody_end = body.index("</tbody>")
    tbody_block = body[tbody_start:tbody_end]
    assert tbody_block.count("<tr>") == 2


def test_dashboard_table_cards_card_contains_target_status_and_link(client, db):
    org = make_org()
    user = make_user("cards4@example.com", org=org)
    scan = make_scan(user, org=org, target_url="https://target.example.org", status=ScanStatus.COMPLETED)
    db.session.commit()

    login(client, "cards4@example.com")
    resp = client.get("/dashboard")

    body = resp.get_data(as_text=True)
    li_start = body.index('class="card record-card"')
    li_end = body.index("</li>", li_start)
    card_block = body[li_start:li_end]
    assert "https://target.example.org" in card_block
    assert 'class="status-pill completed"' in card_block
    assert f"/scan/{scan.id}" in card_block


def test_dashboard_table_cards_zero_scans_no_cards_or_rows_one_empty_state(client, db):
    org = make_org()
    make_user("cardsempty@example.com", org=org)
    db.session.commit()

    login(client, "cardsempty@example.com")
    resp = client.get("/dashboard")

    body = resp.get_data(as_text=True)
    # Scoped to the actual card/row markup, not the bare substring - the
    # embedded <style> block's own comment prose (e.g. "mobile-record-cards
    # block") legitimately contains "record-card" as a substring on every
    # page, scans or not.
    assert 'class="card record-card"' not in body
    assert "<tbody>" not in body
    # Scoped to the class attribute itself, not the bare substring - the
    # embedded <style> block defines `.empty-state {` and `.empty-state
    # .icon {` on every page regardless of scan count.
    assert body.count('class="empty-state"') == 1


# --------------------------------------------------------------------------
# base.html CSS-surface regression lock (Task 2) - source-level, so a
# wave-2 executor can confirm base.html hasn't drifted with a single
# `-k base_css_surface` selection before touching any of its five parallel
# plans, instead of five plans each independently discovering a missing
# class.
# --------------------------------------------------------------------------

def test_base_css_surface_record_card_classes_present():
    import pathlib

    text = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
    for cls in (
        ".mobile-record-cards",
        ".record-card {",
        ".record-card-top {",
        ".record-card-id {",
        ".record-card-meta {",
        ".record-card-details {",
        ".record-card-details summary {",
        ".record-card-action {",
        ".record-card-action form {",
        ".desktop-table",
    ):
        assert cls in text, f"missing {cls!r} in base.html"
    assert "@media (max-width: 430px)" in text
    assert "--bp-card: 430px;" in text


def test_base_css_surface_gauge_stroke_classes_present():
    import pathlib

    text = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
    assert ".gauge-fg.pass { stroke: var(--pass); }" in text
    assert ".gauge-fg.medium { stroke: var(--medium); }" in text
    assert ".gauge-fg.high { stroke: var(--high); }" in text
    assert ".gauge-fg.critical { stroke: var(--critical); }" in text
    # The pre-existing base rule must still be present, unaltered - the four
    # new rules are additive, not a replacement.
    assert (
        ".gauge-fg { fill:none; stroke-width: 10; stroke-linecap: round; "
        "transition: stroke-dashoffset 1s ease; filter: drop-shadow(0 0 6px currentColor); }"
    ) in text


def test_base_css_surface_icon_btn_promoted_and_touch_target_floor():
    import pathlib

    text = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
    assert ".icon-btn { min-width: 44px; min-height: 44px;" in text
    assert ".icon-btn .icon { width: 18px; height: 18px; }" in text


def test_base_css_surface_btn_block_and_focus_visible_unchanged():
    import pathlib

    text = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
    assert ".btn.block { width: 100%; justify-content: center; }" in text
    assert (
        ":focus-visible { outline: 2px solid var(--ring); outline-offset: 2px; "
        "border-radius: 4px; }"
    ) in text


def test_base_css_surface_card_and_table_rules_unchanged():
    import pathlib

    text = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
    assert (
        ".card { background: linear-gradient(180deg, var(--panel), var(--panel2)); "
        "border: 1px solid var(--border); border-radius: var(--radius-md); "
        "padding: 22px; margin-bottom: 18px; }"
    ) in text
    assert (
        "th, td { text-align:left; padding: 7px 8px; border-bottom: 1px solid "
        "var(--border); vertical-align: top; }"
    ) in text
