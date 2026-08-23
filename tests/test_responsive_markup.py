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

`-k phase_gate` (added by 07-07, the phase-gate plan) is a third, later
section, written only after every one of this phase's nine table
conversions had already landed. Its job is not to prove Phase 7's own work
correct - the `table_cards`/`base_css_surface` tests above, and each wave-2/
wave-3 plan's own test module, already do that - but to catch a *future*
phase silently undoing it: someone converting a tenth table without
updating the intended six-template scope, someone re-adding a page-local
`.card`/`.btn`/`table, th, td` override that Phase 6 spent an entire phase
removing, someone editing scan_progress.html's two already-shipped
breakpoints while "just passing through". Like every lock in this module,
these are source-level - this repo has no browser-driving tool, so the
*live* behaviour they stand in for (the table/card swap actually rendering
correctly, the scan-progress feed actually being usable at 320px) is
recorded as a human observation in 07-07-SUMMARY.md instead of re-derived
here.
"""
import pathlib
import re

import pytest

from webvulnscanner.models import ScanStatus

from tests.conftest import login, make_org, make_scan, make_user

TEMPLATES_DIR = pathlib.Path("templates")


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


# --------------------------------------------------------------------------
# Phase-gate locks (07-07) - written after every table conversion in the
# phase had already landed. These catch a *future* phase silently undoing
# Phase 7's outcome; they are not re-proving this phase's own work (the
# tests above, and each wave-2/wave-3 plan's own module, already do that).
# All source-level, for the same no-browser-driving-tool reason every other
# lock in this module is.
# --------------------------------------------------------------------------

from tests.test_report_table_semantics import _strip_comments  # noqa: E402

_EXPECTED_CARD_CONVERSION_TEMPLATES = {
    "dashboard.html",
    "org_admin.html",
    "api_tokens.html",
    "assets.html",
    "asset_detail.html",
    "org_verify_domain.html",
    # Phase 19: the two webhook pages follow the same dual-markup contract
    # (desktop <table> + curated .mobile-record-cards list) from birth.
    "webhooks.html",
    "webhook_deliveries.html",
}

# The single canonical selectors Phase 6 consolidated onto base.html. A
# template other than base.html declaring one of these as a standalone rule
# (not as part of a compound selector, e.g. ".scan-type-grid .card") is a
# regression - Phase 6 spent an entire phase removing exactly this class of
# duplication.
_CANONICAL_SELECTORS = {".card", ".btn", "table, th, td"}

# Documented, pre-Phase-7 exception. `_scan_form_styles.html`'s
# `.card { margin-top: 20px; }` was added in commit a567fb4 (2026-08-08),
# nine days before Phase 6's canon landed in base.html (06-01, 2026-08-17),
# and Phase 6's own audit (06-01-PLAN.md: "the local .card {...} override
# ... is deleted entirely") left this narrower line in place - it sets
# `margin-top`, a property base.html's own `.card` rule never declares at
# all, so it is additive spacing rather than a redefinition of `.card`'s
# shape (background/border/border-radius/padding/margin-bottom, all still
# owned exclusively by base.html). The file's own inline comment records
# this as deliberate. Treated here as the one intentional, pre-existing
# exception rather than a Phase-7-introduced regression - confirmed by
# `git log -S` against both `a567fb4` and the 06-01 commit before adding
# this allowlist entry.
_ALLOWED_BARE_SELECTOR_EXCEPTIONS = {
    ("_scan_form_styles.html", ".card"),
}


def _card_conversion_scope():
    found = set()
    for path in sorted(TEMPLATES_DIR.glob("*.html")):
        if 'class="mobile-record-cards"' in path.read_text(encoding="utf-8"):
            found.add(path.name)
    return found


def _assert_card_conversion_scope_exact():
    actual = _card_conversion_scope()
    missing = _EXPECTED_CARD_CONVERSION_TEMPLATES - actual
    unexpected = actual - _EXPECTED_CARD_CONVERSION_TEMPLATES
    if missing or unexpected:
        pytest.fail(
            "card-conversion scope drifted - missing: "
            f"{sorted(missing) or 'none'}, unexpectedly present: {sorted(unexpected) or 'none'}"
        )


def _bare_selector_declarations(css_text):
    """Returns the subset of `_CANONICAL_SELECTORS` declared as a standalone
    rule (a selector-list segment, comma-split and whitespace-normalized,
    immediately followed by `{`) inside `css_text`. A selector that only
    appears as part of a compound selector (e.g. `.scan-type-grid .card`) or
    inside a `class="..."` attribute does not match - only an actual CSS
    rule-declaration shape does.

    CSS `/* ... */` comments are stripped first, in addition to whatever
    Jinja/HTML comment-stripping the caller already applied - marketing.html
    opens its `<style>` block with a `/* ... shared components (.card, .btn,
    .pill) ... */` explanatory comment naming these exact selectors in
    prose, which would otherwise register as a false-positive rule
    declaration once the comment text sits directly before the first real
    `{`."""
    css_text = re.sub(r"/\*.*?\*/", "", css_text, flags=re.DOTALL)
    found = set()
    for selector_group in re.findall(r"([^{}]+)\{", css_text):
        parts = [re.sub(r"\s+", " ", p).strip() for p in selector_group.split(",")]
        whole = ", ".join(parts)
        if whole in _CANONICAL_SELECTORS:
            found.add(whole)
        for p in parts:
            if p in _CANONICAL_SELECTORS:
                found.add(p)
    return found


def test_phase_gate_scan_progress_breakpoints_unchanged():
    """RESP-04 re-confirmation, source-level half: the two breakpoints and
    the full-width bar-track rule this plan is explicitly told not to touch
    unless the live checkpoint actually fails."""
    text = (TEMPLATES_DIR / "scan_progress.html").read_text(encoding="utf-8")
    assert "@media (min-width: 880px)" in text
    assert "@media (max-width: 480px)" in text
    assert ".bar-track { width: 100%; max-width: none; }" in text


def test_phase_gate_card_conversion_scope_is_exactly_eight_templates():
    # Was "exactly six" through Phase 18; Phase 19's two webhook pages were
    # built to the dual-markup contract from birth and join the closed set.
    _assert_card_conversion_scope_exact()
    assert len(_card_conversion_scope()) == 8


def test_phase_gate_card_conversion_scope_negative_control_scan_compare():
    """Proves the scope lock actually bites: temporarily adding a mobile
    card block to scan_compare.html (a template with no table at all, so it
    should never legitimately gain one) must fail the scope assertion,
    naming scan_compare.html specifically rather than an opaque count
    mismatch - and reverting must pass it again. Run once, then reverted -
    not left broken."""
    path = TEMPLATES_DIR / "scan_compare.html"
    original = path.read_text(encoding="utf-8")
    marker = '<div class="wrap">'
    assert marker in original, "expected wrapper marker not found in scan_compare.html"
    try:
        broken = original.replace(marker, marker + '\n<ul class="mobile-record-cards"></ul>', 1)
        assert broken != original
        path.write_text(broken, encoding="utf-8")
        with pytest.raises(pytest.fail.Exception, match="scan_compare.html"):
            _assert_card_conversion_scope_exact()
    finally:
        path.write_text(original, encoding="utf-8")
    assert path.read_text(encoding="utf-8") == original
    _assert_card_conversion_scope_exact()


def test_phase_gate_scan_report_excluded_from_card_conversion():
    text = (TEMPLATES_DIR / "scan_report.html").read_text(encoding="utf-8")
    assert 'class="mobile-record-cards"' not in text
    assert "desktop-table" not in text


def test_phase_gate_no_page_local_component_overrides():
    """No template other than base.html declares `.card {`, `.btn {` or
    `table, th, td {` as a standalone rule - Phase 6's consolidation must
    still hold after this phase's nine table conversions. Comment-stripped
    first, so a comment naming one of these selectors in prose (several
    templates in this repo carry exactly that kind of explanatory comment)
    cannot fail its own file."""
    offenders = {}
    for path in sorted(TEMPLATES_DIR.glob("*.html")):
        if path.name == "base.html":
            continue
        text = _strip_comments(path.read_text(encoding="utf-8"))
        declared = _bare_selector_declarations(text)
        declared -= {
            sel for (fname, sel) in _ALLOWED_BARE_SELECTOR_EXCEPTIONS if fname == path.name
        }
        if declared:
            offenders[path.name] = sorted(declared)
    assert not offenders, f"page-local canonical-selector override found: {offenders}"


def test_phase_gate_every_table_carries_scroll_wrapper_and_tbody():
    """Every `<table>` in every template is preceded by a `.table-scroll`
    wrapper (checked by count, since a template's own explanatory comments
    may legitimately mention the string an extra time - 07-05-SUMMARY.md
    documents this exact false-positive class for scan_report.html) and the
    template declaring it contains at least one `<tbody>`."""
    problems = {}
    for path in sorted(TEMPLATES_DIR.glob("*.html")):
        if path.name == "base.html":
            # base.html's only "<table" occurrences are prose inside its own
            # explanatory comments (documenting the D-01 convention for
            # every *other* template to follow) - it declares no table of
            # its own.
            continue
        text = path.read_text(encoding="utf-8")
        table_count = text.count("<table")
        if table_count == 0:
            continue
        scroll_count = text.count("table-scroll")
        tbody_count = text.count("<tbody")
        page_problems = []
        if scroll_count < table_count:
            page_problems.append(
                f"{table_count} <table> tag(s) but only {scroll_count} table-scroll mention(s)"
            )
        if tbody_count == 0:
            page_problems.append("no <tbody> anywhere despite having a <table>")
        if page_problems:
            problems[path.name] = page_problems
    assert not problems, f"table semantics gap: {problems}"


def test_phase_gate_billing_has_no_table_and_no_card_block():
    """RESP-03 names billing among the pages whose tables need a mobile
    strategy, but billing.html has no <table> at all - its invoices are
    already `.invoice-card` divs and its plans a `.pricing-grid`. This lock
    exists so a future "finish RESP-03" pass doesn't add a table to billing
    just so it can be converted."""
    text = (TEMPLATES_DIR / "billing.html").read_text(encoding="utf-8")
    assert "<table" not in text
    assert 'class="mobile-record-cards"' not in text
