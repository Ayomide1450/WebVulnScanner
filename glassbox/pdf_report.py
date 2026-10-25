"""PDF export of one scan report (Phase 24 / PDFX-01..08).

`build_pdf_report()` is the single writer behind both export surfaces —
the session-web GET /scan/<int:scan_id>/report.pdf route and
api_routes.py's token-authed GET /api/v1/scans/<int:scan_id>/report.pdf —
so the two formats cannot drift, mirroring sarif.build_sarif_report's
role for SARIF and scan_routes.findings_csv_document's role for CSV.

Pure module: no Flask imports, plain dicts in and out.  The HTML template
is rendered via Jinja2 (the same engine the app already uses) and then
paginated to PDF by WeasyPrint.

SSRF defence (PDFX-01): the ``url_fetcher`` is constructed with
``allowed_protocols=[]`` so WeasyPrint's CSS ``url()`` / ``@font-face``
cannot fetch remote resources — only inline/embedded data is reachable.
``presentational_hints=False`` prevents WeasyPrint from interpreting
HTML attributes like ``background`` as resource loads.

Redaction defence (PDFX-03): the template renders only the
``report["findings"]`` list (Finding dicts with the standard
category/title/severity/detail/recommendation keys), never raw check-data
blobs like ``report["sensitive_paths"]``.  Finding ``detail`` fields
rendered as plain escaped text — no ``| safe`` anywhere (Phase-8
regression lock).

WeasyPrint is imported lazily — the module loads fine without the GTK3
native libraries it requires, but ``build_pdf_report`` raises a clear
``RuntimeError`` if they're missing.  This lets CI (Linux, GTK3 present)
and the Windows dev machine coexist without conditional skips everywhere.
"""


from jinja2 import Environment, FileSystemLoader

from glassbox.checks import CHECK_LABELS
from glassbox.utils import safe_filename

PDF_MIMETYPE = "application/pdf"
PDF_RENDER_TIMEOUT = 30

_weasyprint_available = False
try:
    from weasyprint import HTML as _WeasyHTML
    from weasyprint.urls import URLFetcher as _WeasyURLFetcher
    _weasyprint_available = True
except OSError:
    # Windows dev machines without GTK3 native libs — the import succeeds
    # partially but dlopen fails; module still loads for tests that only
    # touch safe_filename or template structure.
    pass

_jinja_env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=True,
)


def _ensure_weasyprint():
    if not _weasyprint_available:
        raise RuntimeError(
            "WeasyPrint requires GTK3 native libraries which are not "
            "installed on this system.  See https://doc.courtbouillon.org/"
            "weasyprint/stable/first_steps.html#installation for "
            "platform-specific instructions."
        )


def build_pdf_report(report, scan_id):
    """One report dict in -> (pdf_bytes, filename) out.

    Deterministic for identical inputs (same findings list, same scan_id):
    the template contains no timestamps or randomness.  The filename is
    sanitised through ``safe_filename()`` (PDFX-07).  Never raises on odd
    finding shapes — every field read uses .get() with defaults, matching
    the degrade-gracefully convention of the CSV and SARIF writers.
    """
    _ensure_weasyprint()

    findings = report.get("findings") or []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "pass": 5}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", ""), 6))

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    enriched = []
    for f in sorted_findings:
        enriched.append({
            "category": f.get("category", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "detail": f.get("detail", ""),
            "recommendation": f.get("recommendation", ""),
            "check_name": f.get("check_name", ""),
            "label": CHECK_LABELS.get(f.get("check_name", ""), f.get("category", "")),
        })

    # Derived, deterministic summary fields so the template can open with an
    # executive summary instead of dropping the reader straight into an
    # unranked findings dump. All of these are a pure function of the
    # findings list above - no clock, no randomness - so
    # test_deterministic_byte_for_byte still holds.
    SEVERITY_SCALE = ["critical", "high", "medium", "low", "info"]
    actionable = [s for s in SEVERITY_SCALE if severity_counts.get(s)]
    headline_severity = actionable[0] if actionable else ""

    # "Needs attention now" vs "nothing urgent" - drives the one-line verdict.
    urgent_count = severity_counts.get("critical", 0) + severity_counts.get("high", 0)

    # Group for the per-severity sections, preserving the severity-sorted
    # order within each group.
    grouped = []
    for sev in SEVERITY_SCALE + ["pass"]:
        rows = [f for f in enriched if f.get("severity") == sev]
        if rows:
            grouped.append({"severity": sev, "count": len(rows), "findings": rows})

    context = {
        "target": report.get("target", ""),
        "hostname": report.get("hostname", ""),
        "score": report.get("score", 0),
        "risk_grade": report.get("risk_grade", "N/A"),
        "findings": enriched,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "scan_id": scan_id,
        "headline_severity": headline_severity,
        "urgent_count": urgent_count,
        "actionable_count": sum(severity_counts.get(s, 0) for s in SEVERITY_SCALE),
        "pass_count": severity_counts.get("pass", 0),
        "grouped_findings": grouped,
        "severity_scale": SEVERITY_SCALE,
    }

    template = _jinja_env.get_template("pdf_report.html")
    html_string = template.render(**context)

    url_fetcher = _WeasyURLFetcher(allowed_protocols=[])
    pdf_bytes = _WeasyHTML(
        string=html_string,
        url_fetcher=url_fetcher,
        presentational_hints=False,
    ).write_pdf()

    hostname = report.get("hostname") or "scan"
    raw_name = f"{hostname}_scan{scan_id}_findings.pdf"
    filename = safe_filename(raw_name)
    return pdf_bytes, filename
