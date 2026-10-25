"""Tests for 07-05's two artifacts: the accessibility-semantics retrofit of
`templates/scan_report.html`'s 23 diagnostic tables, and `templates/_gauge.html`'s
migration from hardcoded hex stroke colours to token-backed severity classes.

Table semantics (`-k thead_tbody`): all 23 tables on the scan-report page now
carry a `<tbody>`, and the 21 that open with a column-header row also carry a
`<thead>` wrapping it. The two key-value tables - TLS certificate and
DNS/email records - are handled differently on purpose: their `<th>` cells
are *row* headers labelling the value beside them, not column headers for
everything below, so they get `scope="row"` on each `<th>` and no `<thead>`
at all. This page's 23 tables deliberately stay tables rather than becoming
D-01's `.mobile-record-cards` - they are narrow diagnostic attribute dumps
with no primary action, not record lists, and the Findings section already
renders as `.finding` cards through the `finding_card` macro (untouched by
this plan). Whether any of these 23 tables actually overflows its card at
320px is settled at this plan's human-verification checkpoint, not here -
no browser-driving tool exists in this repo, and D-01's own instruction is
to audit whether such a table exists rather than assume either way.

Gauge migration (`-k gauge`): `_gauge.html`'s `.gauge-fg` circle emits a
`pass`/`medium`/`high`/`critical` class at the same >=90/>=60/>=40/below-40
thresholds it always used, instead of a hardcoded hex `stroke` attribute -
resolving against base.html's four `.gauge-fg.*` rules (added by plan
07-01). The four numeric contrast-ratio measurements against those rules'
rendered pixel colours are also settled at the human checkpoint, using a
contrast-checking tool rather than by visual similarity.
"""
import re

import pytest

from glassbox.extensions import db as _db
from glassbox.models import Report, ScanStatus
from tests.conftest import login, make_org, make_scan, make_user

SCAN_REPORT_TEMPLATE = "templates/scan_report.html"
GAUGE_TEMPLATE = "templates/_gauge.html"

_HEX_COLOR_RE = re.compile(r"#[0-9a-fA-F]{6}\b")


def _read(path):
    import pathlib

    return pathlib.Path(path).read_text(encoding="utf-8")


def _strip_comments(html):
    """Strips Jinja `{# ... #}` and HTML `<!-- ... -->` comments before
    counting tag occurrences - two of this file's own comments (recording
    the deliberate row-header exception) mention the literal string
    "<thead>" in prose, which would otherwise inflate a naive substring
    count."""
    html = re.sub(r"\{#.*?#\}", "", html, flags=re.DOTALL)
    html = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)
    return html


def _extract_block(html, start_marker, end_marker="</details>"):
    start = html.index(start_marker)
    end = html.index(end_marker, start) + len(end_marker)
    return html[start:end]


def _add_report(scan, **data_overrides):
    data = {
        "target": "https://example.com",
        "hostname": "example.com",
        "scanned_at": "2026-01-01T00:00:00Z",
        "score": 91,
        "risk_grade": "A",
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "findings": [
            {
                "category": "Headers",
                "title": "Missing CSP",
                "severity": "medium",
                "detail": "No Content-Security-Policy header present.",
                "recommendation": "Add a Content-Security-Policy header.",
                "check_name": "headers",
            },
        ],
        "locked_checks": [],
    }
    data["severity_counts"]["medium"] = 1
    data.update(data_overrides)
    r = Report(scan_id=scan.id, json_path=f"unused_{scan.id}.json", data=data)
    _db.session.add(r)
    _db.session.flush()
    return r


# --------------------------------------------------------------------------
# thead/tbody retrofit - source-level counts across all 23 tables
# --------------------------------------------------------------------------

def test_thead_tbody_all_32_tables_carry_tbody():
    html = _strip_comments(_read(SCAN_REPORT_TEMPLATE))
    assert html.count("<table") == 32
    assert html.count("<tbody") == 32


def test_thead_tbody_30_column_header_tables_carry_thead():
    html = _strip_comments(_read(SCAN_REPORT_TEMPLATE))
    assert html.count("<thead") == 30


def test_thead_tbody_table_scroll_wrapper_count_unchanged():
    # Comment-stripped: this plan's own added comment mentions ".table-scroll"
    # in prose (explaining why the wrapper stays), which would otherwise
    # inflate a naive substring count by one.
    html = _strip_comments(_read(SCAN_REPORT_TEMPLATE))
    assert html.count("table-scroll") == 32


def test_thead_tbody_no_mobile_record_cards_or_desktop_table():
    # Comment-stripped for the same reason - the added comment names
    # ".mobile-record-cards" in prose to explain why it's absent from markup.
    html = _strip_comments(_read(SCAN_REPORT_TEMPLATE))
    assert "mobile-record-cards" not in html
    assert "desktop-table" not in html


# --------------------------------------------------------------------------
# thead/tbody retrofit - the two deliberate row-header exceptions
# --------------------------------------------------------------------------

def test_thead_tbody_tls_certificate_table_is_row_header_not_thead():
    html = _read(SCAN_REPORT_TEMPLATE)
    # Comment-stripped throughout: this block's own inline comment
    # deliberately says "no <thead>" and "Each <th> carries scope=..." in
    # prose, recording the decision for a later reader - neither must be
    # mistaken for real markup by these assertions.
    block = _strip_comments(_extract_block(html, "<summary>TLS certificate"))
    assert "<thead" not in block
    # Subject/Issuer/Expires always render; Protocol/Cipher are conditional -
    # every <th> present must carry scope="row" regardless of which fire.
    ths = re.findall(r"<th\b[^>]*>", block)
    assert len(ths) >= 3
    for th in ths:
        assert 'scope="row"' in th


def test_thead_tbody_dns_email_table_is_row_header_not_thead():
    html = _read(SCAN_REPORT_TEMPLATE)
    block = _strip_comments(_extract_block(html, "<summary>DNS email security"))
    assert "<thead" not in block
    ths = re.findall(r"<th\b[^>]*>", block)
    assert len(ths) == 4  # Domain, SPF, DMARC, CAA - all unconditional
    for th in ths:
        assert 'scope="row"' in th


def test_thead_tbody_key_value_tables_account_for_all_scope_row_th_cells():
    """Every <th> in the file carries scope="row" if and only if it belongs
    to one of the two key-value tables - guards against a future column-
    header table picking up scope="row" by copy-paste mistake."""
    html = _read(SCAN_REPORT_TEMPLATE)
    tls_block = _extract_block(html, "<summary>TLS certificate")
    dns_block = _extract_block(html, "<summary>DNS email security")
    total_scope_row = html.count('scope="row"')
    tls_scope_row = tls_block.count('scope="row"')
    dns_scope_row = dns_block.count('scope="row"')
    assert total_scope_row == tls_scope_row + dns_scope_row


# --------------------------------------------------------------------------
# thead/tbody retrofit - a rendered report still shows the finding cards
# --------------------------------------------------------------------------

def test_thead_tbody_rendered_report_still_shows_finding_card_markup(client, db):
    org = make_org()
    user = make_user("report-owner@example.org", org=org)
    scan = make_scan(user, org=org, scan_type="other", status=ScanStatus.COMPLETED)
    _add_report(scan)
    db.session.commit()

    login(client, "report-owner@example.org")
    resp = client.get(f"/scan/{scan.id}/report")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'class="finding medium"' in body
    assert "Missing CSP" in body


# --------------------------------------------------------------------------
# _gauge.html - source-level assertions
# --------------------------------------------------------------------------

def test_gauge_no_six_digit_hex_colour_literal():
    text = _read(GAUGE_TEMPLATE)
    assert _HEX_COLOR_RE.search(text) is None


def test_gauge_thresholds_unchanged():
    text = _read(GAUGE_TEMPLATE)
    assert "score >= 90" in text
    assert "score >= 60" in text
    assert "score >= 40" in text


def test_gauge_id_attribute_unchanged():
    text = _read(GAUGE_TEMPLATE)
    assert 'id="{{ _gauge_id }}"' in text


def test_gauge_class_attribute_resolves_severity_name():
    text = _read(GAUGE_TEMPLATE)
    assert 'class="gauge-fg' in text
    assert 'stroke="' not in text


def test_gauge_base_html_untouched_by_this_plan():
    # This plan's own prohibition: no diff to base.html. The four
    # .gauge-fg.pass/.medium/.high/.critical rules it needs already exist
    # there from plan 07-01.
    text = _read("templates/base.html")
    assert ".gauge-fg.pass" in text
    assert ".gauge-fg.medium" in text
    assert ".gauge-fg.high" in text
    assert ".gauge-fg.critical" in text


# --------------------------------------------------------------------------
# _gauge.html - rendered score-band -> class resolution, via /dashboard's
# real include site (dashboard.html sets score/risk_grade/gauge_id from
# Scan.risk_score exactly like the other two including pages do).
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "score,expected_class",
    [
        (95, "pass"),
        (75, "medium"),
        (50, "high"),
        (20, "critical"),
    ],
)
def test_gauge_score_band_resolves_expected_class(client, db, score, expected_class):
    org = make_org(name=f"Gauge Org {score}")
    user = make_user(f"gauge-{score}@example.org", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    scan.risk_score = score
    db.session.commit()

    login(client, f"gauge-{score}@example.org")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert f'class="gauge-fg {expected_class}"' in body
    assert 'id="gaugeFgDashboard"' in body
    assert "stroke=\"#" not in body


def test_gauge_renders_on_dashboard_scan_report_and_asset_detail(client, db):
    org = make_org(name="Gauge Three Pages Org")
    user = make_user("gauge-three@example.org", org=org)
    from tests.conftest import make_asset

    asset = make_asset(org, user, name="Gauge Asset")
    from glassbox.models import Scan

    scan = Scan(
        asset_id=asset.id, user_id=user.id, org_id=org.id,
        target_url=asset.target_url, scan_type="base",
        status=ScanStatus.COMPLETED, risk_score=90,
    )
    _db.session.add(scan)
    _db.session.flush()
    scan_for_report = make_scan(user, org=org, scan_type="other", status=ScanStatus.COMPLETED)
    scan_for_report.risk_score = 90
    _add_report(scan_for_report, score=90, risk_grade="A")
    db.session.commit()

    login(client, "gauge-three@example.org")

    dashboard_resp = client.get("/dashboard")
    assert dashboard_resp.status_code == 200
    assert "gauge-fg" in dashboard_resp.get_data(as_text=True)

    report_resp = client.get(f"/scan/{scan_for_report.id}/report")
    assert report_resp.status_code == 200
    assert "gauge-fg" in report_resp.get_data(as_text=True)

    asset_resp = client.get(f"/assets/{asset.id}")
    assert asset_resp.status_code == 200
    assert "gauge-fg" in asset_resp.get_data(as_text=True)
