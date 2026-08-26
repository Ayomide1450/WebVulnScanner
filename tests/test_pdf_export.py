"""Phase 24 (PDFX-01..08): PDF export of scan reports.

Locks, in order: the shared pure writer's PDF-byte output (magic bytes,
semantic determinism, severity sorting, empty-findings graceful degrade),
the safe_filename allowlist (PDFX-07), the no-raw-check-data redaction
defence (PDFX-03), then both export surfaces: the session-web
/scan/<id>/report.pdf route (ownership guard + leak check mirroring
CSV/SARIF) and the token-authed /api/v1 twin, including the no-drift
byte-for-byte lock between the two surfaces.

WeasyPrint requires GTK3 native libraries (present on Linux CI, absent on
Windows dev machines).  Rendering tests are gated behind a module-level
``_weasy_ok`` flag — they skip with a clear message on platforms without
GTK3, but the safe_filename and template-structure tests always run.
"""

import pytest

from webvulnscanner.models import Plan, Report, Role, ScanStatus
from webvulnscanner.pdf_report import _weasyprint_available, build_pdf_report, PDF_MIMETYPE
from webvulnscanner.scan_routes import safe_filename

from tests.conftest import (
    login,
    make_api_token,
    make_asset,
    make_org,
    make_scan,
    make_user,
)


PDF_MAGIC = b"%PDF-"

PDF_LEAK_MARKER = "MARKER-24-PDF-LEAK-CHECK-9f3a01"

# Gate: all tests that actually render a PDF via WeasyPrint need GTK3.
needs_weasy = pytest.mark.skipif(
    not _weasyprint_available,
    reason="WeasyPrint requires GTK3 native libraries (not available on this platform)",
)


def _fixture_report():
    return {
        "hostname": "example.com",
        "target": "https://example.com",
        "score": 64,
        "risk_grade": "D",
        "findings": [
            {
                "check_name": "sqli_union", "category": "SQL Injection",
                "title": "/items UNION probe reflected", "severity": "critical",
                "detail": "payload echoed in column 3",
                "recommendation": "parameterize queries",
            },
            {
                "check_name": "headers", "category": "headers",
                "title": "Content-Security-Policy missing", "severity": "medium",
                "confidence": "Potential",
            },
            {
                "check_name": "headers", "category": "headers",
                "title": "Strict-Transport-Security missing", "severity": "high",
                "confidence": "Confirmed",
            },
            {
                "check_name": "tls", "title": "Certificate chain valid",
                "severity": "pass",
            },
        ],
    }


def _attach_pdf_marker_report(scan):
    report_data = {
        "hostname": "example.com",
        "target": "https://example.com",
        "findings": [
            {
                "check_name": "xss_reflected", "category": "XSS",
                "title": "Reflected XSS", "severity": "high",
                "detail": PDF_LEAK_MARKER, "recommendation": "encode output",
            },
        ],
    }
    r = Report(scan_id=scan.id, json_path="unused-for-this-test.json",
               data=report_data)
    from webvulnscanner.extensions import db as _db
    _db.session.add(r)
    _db.session.flush()
    return r


@pytest.fixture()
def scenario(db):
    org1 = make_org(name="Org One")
    org2 = make_org(name="Org Two")
    owner = make_user("owner@org1.com", org=org1, role=Role.MEMBER)
    make_user("rival-admin@org2.com", org=org2, role=Role.ORG_ADMIN)
    scan = make_scan(owner, org=org1, target_url="https://example.com")
    return {"scan": scan}


# --------------------------------------------------------------------------
# PDFX-07: safe_filename allowlist (pure helper, no Flask context needed)
# --------------------------------------------------------------------------

class TestSafeFilename:
    def test_clean_hostname_passes_through(self):
        assert safe_filename("example.com_scan42_findings.pdf") == "example.com_scan42_findings.pdf"

    def test_colon_replaced_with_underscore(self):
        assert safe_filename("localhost:5000_scan1.pdf") == "localhost_5000_scan1.pdf"

    def test_slash_stripped(self):
        result = safe_filename("https://evil.com/../../etc/passwd.pdf")
        assert "/" not in result

    def test_leading_dots_collapsed(self):
        result = safe_filename("...hidden")
        assert not result.startswith(".")

    def test_empty_string_returns_scan(self):
        assert safe_filename("") == "scan"

    def test_none_returns_scan(self):
        assert safe_filename(None) == "scan"

    def test_unicode_replaced(self):
        result = safe_filename("report_日本語.pdf")
        assert "日" not in result
        assert result.endswith(".pdf")


# --------------------------------------------------------------------------
# PDFX-01: the shared pure writer (requires GTK3)
# --------------------------------------------------------------------------

@needs_weasy
class TestBuildPdfReport:
    def test_produces_valid_pdf_bytes(self):
        pdf_bytes, filename = build_pdf_report(_fixture_report(), 42)
        assert isinstance(pdf_bytes, (bytes, bytearray))
        assert len(pdf_bytes) > 100
        assert pdf_bytes[:5] == PDF_MAGIC
        assert filename.endswith(".pdf")

    def test_deterministic_byte_for_byte(self):
        a, name_a = build_pdf_report(_fixture_report(), 42)
        b, name_b = build_pdf_report(_fixture_report(), 42)
        assert name_a == name_b
        assert a == b

    def test_findings_sorted_by_severity(self):
        """critical before high before medium before pass."""
        pdf_bytes, _ = build_pdf_report(_fixture_report(), 42)
        text = pdf_bytes.decode("latin-1", errors="replace")
        critical_pos = text.find("SQL Injection")
        high_pos = text.find("Strict-Transport-Security")
        medium_pos = text.find("Content-Security-Policy")
        pass_pos = text.find("Certificate chain valid")
        assert critical_pos < high_pos < medium_pos < pass_pos

    def test_empty_findings_degrades_gracefully(self):
        report = {"hostname": "empty.com", "target": "https://empty.com",
                  "findings": [], "score": 100, "risk_grade": "A"}
        pdf_bytes, filename = build_pdf_report(report, 99)
        assert pdf_bytes[:5] == PDF_MAGIC
        assert "99" in filename

    def test_no_raw_check_data_in_pdf(self):
        """PDFX-03 redaction defence: report blobs like sensitive_paths
        must not appear in the rendered output."""
        report = _fixture_report()
        report["sensitive_paths"] = {
            "secret_evidence": {"raw": PDF_LEAK_MARKER},
            "passwords": ["hunter2"],
        }
        pdf_bytes, _ = build_pdf_report(report, 1)
        assert PDF_LEAK_MARKER.encode() not in pdf_bytes

    def test_filename_sanitized(self):
        """PDFX-07: hostname with special chars produces a clean filename."""
        report = _fixture_report()
        report["hostname"] = "weird:host/name.com"
        _, filename = build_pdf_report(report, 5)
        assert "/" not in filename
        assert ":" not in filename

    def test_zero_score_report(self):
        report = _fixture_report()
        report["score"] = 0
        report["risk_grade"] = "F"
        pdf_bytes, _ = build_pdf_report(report, 10)
        assert pdf_bytes[:5] == PDF_MAGIC


# --------------------------------------------------------------------------
# PDFX-01: session-web route /scan/<id>/report.pdf (requires GTK3)
# --------------------------------------------------------------------------

@needs_weasy
def test_scan_report_pdf_owner_gets_valid_download(client, db):
    org = make_org()
    user = make_user("pdf-owner@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()
    _attach_pdf_marker_report(scan)
    db.session.commit()

    login(client, "pdf-owner@example.com")
    resp = client.get(f"/scan/{scan.id}/report.pdf")
    assert resp.status_code == 200
    assert resp.content_type.startswith("application/pdf")
    assert "attachment" in resp.headers["Content-Disposition"]
    assert "example.com_scan" in resp.headers["Content-Disposition"]
    assert resp.data[:5] == PDF_MAGIC


@needs_weasy
def test_scan_report_pdf_cross_org_is_404_and_leaks_no_finding_text(client, scenario, db):
    _attach_pdf_marker_report(scenario["scan"])
    db.session.commit()

    login(client, "rival-admin@org2.com")
    resp = client.get(f"/scan/{scenario['scan'].id}/report.pdf")
    assert resp.status_code == 404
    assert PDF_LEAK_MARKER.encode() not in resp.data

    login(client, "owner@org1.com")
    resp2 = client.get(f"/scan/{scenario['scan'].id}/report.pdf")
    assert resp2.status_code == 200
    assert PDF_LEAK_MARKER.encode() in resp2.data


def test_scan_report_pdf_missing_weasyprint_flashes_and_redirects_not_500(client, db, monkeypatch):
    """When WeasyPrint's native libs aren't available (this machine, or a
    misconfigured deploy), the session-web route must degrade to a flash +
    redirect back to the report - not a raw 500. Forces the failure via
    monkeypatch so this runs identically with or without GTK3 installed."""
    from webvulnscanner import scan_routes

    org = make_org()
    user = make_user("pdf-degrade@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()
    _attach_pdf_marker_report(scan)
    db.session.commit()

    def _boom(report, scan_id):
        raise RuntimeError("WeasyPrint requires GTK3 native libraries")

    monkeypatch.setattr(scan_routes, "build_pdf_report", _boom)

    login(client, "pdf-degrade@example.com")
    # follow_redirects=False: the fixture report dict here is minimal and
    # doesn't carry every key scan_report.html needs to fully render - this
    # test only needs to prove the PDF route itself redirects with a flash,
    # not that an unrelated template renders a partial fixture cleanly.
    resp = client.get(f"/scan/{scan.id}/report.pdf", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith(f"/scan/{scan.id}/report")
    with client.session_transaction() as sess:
        flashes = dict(sess.get("_flashes", []))
    assert "temporarily unavailable" in flashes.get("error", "")


def test_fetch_report_pdf_missing_weasyprint_returns_503_json(client, db, monkeypatch):
    """Token-authed API twin of the same degrade path: a scripted caller
    (cli/wvs.py, CI) needs a parseable 503 + error message, not a bare 500,
    so it can tell 'retry later / use another format' apart from a real
    server error."""
    from webvulnscanner import api_routes

    org = make_org()
    user = make_user("pdf-degrade-api@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()
    _attach_pdf_marker_report(scan)
    db.session.commit()
    _token_row, token = make_api_token(user)

    def _boom(report, scan_id):
        raise RuntimeError("WeasyPrint requires GTK3 native libraries")

    monkeypatch.setattr(api_routes, "build_pdf_report", _boom)

    resp = client.get(
        f"/api/v1/scans/{scan.id}/report.pdf",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 503
    assert "temporarily unavailable" in resp.get_json()["error"]


def test_scan_report_pdf_no_report_row_is_404(client, db):
    org = make_org()
    user = make_user("no-report-pdf@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()

    login(client, "no-report-pdf@example.com")
    resp = client.get(f"/scan/{scan.id}/report.pdf")
    assert resp.status_code == 404


# --------------------------------------------------------------------------
# PDFX-01: token-authed /api/v1 twin + no-drift lock (requires GTK3)
# --------------------------------------------------------------------------

@needs_weasy
def test_report_pdf_matches_session_route_bytes_exactly(client, db):
    org = make_org(plan=Plan.PAID)
    user = make_user("pdf-twin@example.com", org=org, role=Role.ORG_ADMIN)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.commit()
    _attach_pdf_marker_report(scan)
    db.session.commit()

    _, raw_token = make_api_token(user, name="tok")
    api_resp = client.get(
        f"/api/v1/scans/{scan.id}/report.pdf",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    login(client, "pdf-twin@example.com")
    web_resp = client.get(f"/scan/{scan.id}/report.pdf")

    assert api_resp.status_code == 200 and web_resp.status_code == 200
    assert api_resp.data == web_resp.data


def test_report_pdf_different_org_gets_404(client, db):
    org_a = make_org(plan=Plan.PAID, name="Org A")
    org_b = make_org(plan=Plan.PAID, name="Org B")
    user_a = make_user("a-pdf@example.com", org=org_a)
    user_b = make_user("b-pdf@example.com", org=org_b)
    db.session.commit()
    _, raw_token_b = make_api_token(user_b, name="b-tok")
    a = make_asset(org_a, user_a, name="Asset")
    scan = make_scan(user_a, org=org_a, status=ScanStatus.COMPLETED)
    scan.asset_id = a.id
    db.session.commit()
    _attach_pdf_marker_report(scan)
    db.session.commit()

    resp = client.get(
        f"/api/v1/scans/{scan.id}/report.pdf",
        headers={"Authorization": f"Bearer {raw_token_b}"},
    )
    assert resp.status_code == 404
    assert PDF_LEAK_MARKER.encode() not in resp.data


def test_report_pdf_soft_deleted_asset_gets_404(client, db):
    from datetime import datetime, timezone

    org = make_org(plan=Plan.PAID)
    user = make_user("deleted-asset-pdf@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()
    _, raw_token = make_api_token(user, name="tok")
    a = make_asset(org, user, name="Doomed")
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    scan.asset_id = a.id
    db.session.commit()
    _attach_pdf_marker_report(scan)
    a.deleted_at = datetime.now(timezone.utc)
    db.session.commit()

    resp = client.get(
        f"/api/v1/scans/{scan.id}/report.pdf",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------
# PDFX-04: timeout guard (smoke — no real long-running render)
# --------------------------------------------------------------------------

@needs_weasy
def test_build_pdf_report_completes_in_reasonable_time():
    import time
    start = time.monotonic()
    pdf_bytes, _ = build_pdf_report(_fixture_report(), 1)
    elapsed = time.monotonic() - start
    assert elapsed < 15, f"PDF render took {elapsed:.1f}s — exceeding 15s budget"
    assert pdf_bytes[:5] == PDF_MAGIC


# --------------------------------------------------------------------------
# PDFX-08: template has no | safe on finding fields
# --------------------------------------------------------------------------

def test_pdf_template_no_unsafe_filter():
    """Phase-8 regression lock extended: the PDF template must not use
    | safe on any finding field (category, title, detail, recommendation)."""
    from pathlib import Path
    tpl = Path("templates/pdf_report.html").read_text(encoding="utf-8")
    for field in ["f.title", "f.detail", "f.recommendation", "f.category"]:
        assert f"{field} | safe" not in tpl, f"Found '| safe' on {field} in PDF template"
