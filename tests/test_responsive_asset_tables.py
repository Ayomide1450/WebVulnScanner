"""Rendered-HTML and source-level markup assertions for RESP-03's
dual-markup table/card contract (D-01) on the asset/token surface:
api_tokens.html's Tokens table, assets.html's Assets table, and
asset_detail.html's Scan history table.

This module owns RESP-03's markup-presence half for these three pages. The
revoke-confirm assertions exist because api_tokens.html's confirmation
dialog is wired by a `.revoke-token-form` class and a `data-token-name`
attribute picked up by a `querySelectorAll` at the bottom of the file, not
by an inline `onsubmit` handler - a card copy of the revoke form that keeps
the `<form>`, the action and the csrf_token but drops that class or
attribute would pass a casual "does the form exist" check while silently
never prompting before an irreversible token revocation on a phone. What
this module cannot answer - what the table/card swap actually looks like at
a given viewport width, whether long text truncates instead of overflowing,
what Tab order looks like, and the measured `.pill.not-checked` composited
contrast ratio - this repo has no browser-driving tool, so all of that is
explicitly deferred to this plan's `checkpoint:human-verify` task instead.

Selectors: `-k api_tokens` (api_tokens.html), `-k assets_list` (assets.html),
`-k asset_detail` (asset_detail.html).

Note: plan 07-02's `tests/test_responsive_org_tables.py` was documented as
providing a reusable rendered-body id-uniqueness helper for later plans to
import. At the time this module was written, plan 07-02 (running in a
parallel wave-2 agent) had only landed its first task and that helper did
not yet exist on disk, so this module defines its own
`_assert_no_duplicate_ids` rather than importing one that doesn't exist yet
- see 07-03-SUMMARY.md's Deviations section.
"""
import re

from webvulnscanner.models import Plan, Report, Scan, ScanStatus

from tests.conftest import login, make_api_token, make_asset, make_org, make_user


def _make_scan_with_report(db, asset, user, org, risk_score):
    """A completed base Scan plus its Report row, `data` populated directly
    (skips the on-disk-file read path entirely - `compliance_coverage()`
    reads `report.data` first) so the Compliance coverage table has at
    least one real row instead of falling back to the "not enough
    completed scans yet" empty branch."""
    s = Scan(
        asset_id=asset.id, user_id=user.id, org_id=org.id,
        target_url=asset.target_url, scan_type="base",
        status=ScanStatus.COMPLETED, risk_score=risk_score,
    )
    db.session.add(s)
    db.session.flush()
    r = Report(scan_id=s.id, json_path=f"unused_{s.id}.json", data={"findings": [], "locked_checks": []})
    db.session.add(r)
    return s


def _assert_no_duplicate_ids(body):
    ids = re.findall(r'\bid="([^"]*)"', body)
    seen = set()
    dupes = set()
    for i in ids:
        if i in seen:
            dupes.add(i)
        seen.add(i)
    assert not dupes, f"duplicate id attribute(s) found: {dupes}"


# --------------------------------------------------------------------------
# api_tokens.html - Tokens table (Task 1)
# --------------------------------------------------------------------------

def test_api_tokens_table_cards_both_blocks_present(db, client):
    org = make_org(name="Token Org 1")
    user = make_user("tok1@example.com", org=org)
    make_api_token(user, name="CI pipeline")
    db.session.commit()

    login(client, "tok1@example.com")
    resp = client.get("/tokens")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'class="table-scroll desktop-table"' in body
    assert "<thead>" in body and "</thead>" in body
    assert "<tbody>" in body and "</tbody>" in body
    assert 'class="mobile-record-cards"' in body


def test_api_tokens_active_token_revoke_form_appears_exactly_twice_with_csrf(db, client):
    org = make_org(name="Token Org 2")
    user = make_user("tok2@example.com", org=org)
    t, _raw = make_api_token(user, name="Personal script")
    db.session.commit()

    login(client, "tok2@example.com")
    resp = client.get("/tokens")

    body = resp.get_data(as_text=True)
    assert body.count('class="revoke-token-form"') == 2
    assert body.count('data-token-name="Personal script"') == 2
    revoke_path = f"/tokens/{t.id}/revoke"
    assert body.count(revoke_path) == 2

    # Each of the two forms carries a hidden csrf_token input - split on the
    # form action so we look inside each form block individually rather
    # than just counting csrf_token occurrences anywhere on the page (the
    # create-token form above also has one).
    parts = body.split(f'action="{revoke_path}"')
    assert len(parts) == 3  # 2 occurrences => 3 split parts
    for form_tail in parts[1:]:
        # csrf_token input sits right after the form's opening tag
        assert 'name="csrf_token"' in form_tail[:400]


def test_api_tokens_revoked_token_renders_no_revoke_form(db, client):
    org = make_org(name="Token Org 3")
    user = make_user("tok3@example.com", org=org)
    make_api_token(user, name="Dead token", revoked=True)
    db.session.commit()

    login(client, "tok3@example.com")
    resp = client.get("/tokens")

    body = resp.get_data(as_text=True)
    # Scoped to the class attribute itself, not the bare substring - the
    # page's own <script> block legitimately contains the literal string
    # "revoke-token-form" inside its querySelectorAll('.revoke-token-form')
    # call on every page, revoked token or not (same false-positive shape
    # 07-01-SUMMARY.md documented for "record-card").
    assert 'class="revoke-token-form"' not in body


def test_api_tokens_zero_tokens_no_cards_one_empty_state(db, client):
    org = make_org(name="Token Org 4")
    make_user("tok4@example.com", org=org)
    db.session.commit()

    login(client, "tok4@example.com")
    resp = client.get("/tokens")

    body = resp.get_data(as_text=True)
    assert 'class="card record-card"' not in body
    assert "No API tokens yet" in body
    assert body.count("No API tokens yet") == 1


def test_api_tokens_page_has_no_duplicate_ids(db, client):
    org = make_org(name="Token Org 5")
    user = make_user("tok5@example.com", org=org)
    make_api_token(user, name="One token")
    db.session.commit()

    login(client, "tok5@example.com")
    resp = client.get("/tokens")

    _assert_no_duplicate_ids(resp.get_data(as_text=True))


# --------------------------------------------------------------------------
# assets.html - Assets table (Task 1)
# --------------------------------------------------------------------------

def test_assets_list_table_cards_both_blocks_present(db, client):
    org = make_org(name="Asset Org 1")
    user = make_user("asset1@example.com", org=org)
    make_asset(org, user, name="My Asset", target_url="https://example.com")
    db.session.commit()

    login(client, "asset1@example.com")
    resp = client.get("/assets")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'class="table-scroll desktop-table"' in body
    assert "<thead>" in body and "</thead>" in body
    assert "<tbody>" in body and "</tbody>" in body
    assert 'class="mobile-record-cards"' in body


def test_assets_list_card_contains_name_target_url_and_detail_link(db, client):
    org = make_org(name="Asset Org 2")
    user = make_user("asset2@example.com", org=org)
    a = make_asset(org, user, name="Card Asset", target_url="https://card-target.example.org")
    db.session.commit()

    login(client, "asset2@example.com")
    resp = client.get("/assets")

    body = resp.get_data(as_text=True)
    ul_start = body.index('class="mobile-record-cards"')
    li_start = body.index('class="card record-card"', ul_start)
    li_end = body.index("</li>", li_start)
    card_block = body[li_start:li_end]
    assert "Card Asset" in card_block
    assert "https://card-target.example.org" in card_block
    assert f"/assets/{a.id}" in card_block


def test_assets_list_zero_assets_no_cards_one_empty_state(db, client):
    org = make_org(name="Asset Org 3")
    make_user("asset3@example.com", org=org)
    db.session.commit()

    login(client, "asset3@example.com")
    resp = client.get("/assets")

    body = resp.get_data(as_text=True)
    assert 'class="card record-card"' not in body
    assert "No assets yet" in body


def test_assets_list_page_has_no_duplicate_ids(db, client):
    org = make_org(name="Asset Org 4")
    user = make_user("asset4@example.com", org=org)
    make_asset(org, user, name="Dup Check Asset")
    db.session.commit()

    login(client, "asset4@example.com")
    resp = client.get("/assets")

    _assert_no_duplicate_ids(resp.get_data(as_text=True))


# --------------------------------------------------------------------------
# asset_detail.html - Scan history (cards) and Compliance coverage
# (table-only triage), plus the .icon-btn deduplication (Task 2)
# --------------------------------------------------------------------------

def test_asset_detail_scan_history_table_cards_both_blocks_present(db, client):
    org = make_org(plan=Plan.PAID, name="Detail Org A")
    user = make_user("detail-a@example.com", org=org)
    a = make_asset(org, user, name="Detail Asset A")
    _make_scan_with_report(db, a, user, org, risk_score=77)
    db.session.commit()

    login(client, "detail-a@example.com")
    resp = client.get(f"/assets/{a.id}")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Exactly one desktop-table wrapper on this page proves the diagnostic
    # Compliance coverage table was NOT also converted to dual markup.
    assert body.count('class="table-scroll desktop-table"') == 1
    assert body.count('class="mobile-record-cards"') == 1
    assert body.count("<thead>") == 2
    assert body.count("</thead>") == 2
    assert body.count("<tbody>") == 2
    assert body.count("</tbody>") == 2


def test_asset_detail_scan_history_card_count_matches_row_count(db, client):
    org = make_org(plan=Plan.PAID, name="Detail Org B")
    user = make_user("detail-b@example.com", org=org)
    a = make_asset(org, user, name="Detail Asset B")
    for i in range(2):
        s = Scan(
            asset_id=a.id, user_id=user.id, org_id=org.id,
            target_url=a.target_url, scan_type="base",
            status=ScanStatus.COMPLETED, risk_score=50 + i,
        )
        db.session.add(s)
    db.session.commit()

    login(client, "detail-b@example.com")
    resp = client.get(f"/assets/{a.id}")

    body = resp.get_data(as_text=True)
    assert body.count('class="card record-card"') == 2

    tbody_start = body.rindex("<tbody>")
    tbody_end = body.index("</tbody>", tbody_start)
    tbody_block = body[tbody_start:tbody_end]
    assert tbody_block.count("<tr>") == 2


def test_asset_detail_compliance_coverage_stays_a_table_with_thead_tbody(db, client):
    org = make_org(plan=Plan.PAID, name="Detail Org C")
    user = make_user("detail-c@example.com", org=org)
    a = make_asset(org, user, name="Detail Asset C")
    _make_scan_with_report(db, a, user, org, risk_score=90)
    db.session.commit()

    login(client, "detail-c@example.com")
    resp = client.get(f"/assets/{a.id}")

    body = resp.get_data(as_text=True)
    assert "OWASP Top 10 category" in body
    # Only one desktop-table wrapper exists on the page (Scan history's) -
    # the Compliance coverage table's own wrapper must not carry it.
    assert body.count('class="table-scroll desktop-table"') == 1


def test_asset_detail_aria_labels_survive(db, client):
    org = make_org(plan=Plan.PAID, name="Detail Org D")
    user = make_user("detail-d@example.com", org=org)
    a = make_asset(org, user, name="Aria Asset")
    db.session.commit()

    login(client, "detail-d@example.com")
    resp = client.get(f"/assets/{a.id}")

    body = resp.get_data(as_text=True)
    assert 'aria-label="Pause schedule for Aria Asset"' in body
    assert 'aria-label="Delete Aria Asset"' in body


def test_asset_detail_resumed_asset_shows_resume_aria_label(db, client):
    org = make_org(plan=Plan.PAID, name="Detail Org E")
    user = make_user("detail-e@example.com", org=org)
    a = make_asset(org, user, name="Paused Asset", is_paused=True)
    db.session.commit()

    login(client, "detail-e@example.com")
    resp = client.get(f"/assets/{a.id}")

    body = resp.get_data(as_text=True)
    assert 'aria-label="Resume schedule for Paused Asset"' in body


def test_asset_detail_source_no_local_icon_btn_rule(db, client):
    import pathlib

    text = pathlib.Path("templates/asset_detail.html").read_text(encoding="utf-8")
    assert ".icon-btn {" not in text
    assert ".icon-btn .icon {" not in text

    base_text = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
    assert ".icon-btn {" in base_text


def test_asset_detail_page_has_no_duplicate_ids(db, client):
    org = make_org(plan=Plan.PAID, name="Detail Org F")
    user = make_user("detail-f@example.com", org=org)
    a = make_asset(org, user, name="Dup Check Detail Asset")
    s = Scan(
        asset_id=a.id, user_id=user.id, org_id=org.id,
        target_url=a.target_url, scan_type="base",
        status=ScanStatus.COMPLETED, risk_score=65,
    )
    db.session.add(s)
    db.session.commit()

    login(client, "detail-f@example.com")
    resp = client.get(f"/assets/{a.id}")

    _assert_no_duplicate_ids(resp.get_data(as_text=True))
