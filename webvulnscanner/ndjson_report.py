"""NDJSON (newline-delimited JSON) export of scan findings — one JSON
object per line, ingestible by any SIEM, log aggregator, or CLI pipeline
that speaks NDJSON (e.g. `jq`, Splunk HEC raw mode, Elastic Logstash).

Phase 25 (INTG-01): the portable, streaming-friendly alternative to CSV/SARIF/PDF.
Each finding serialises to a single compact JSON line — no wrapping array, no
trailing comma, no pretty-printing — so receivers can process the stream line
by line without loading the entire document.
"""
import json

from webvulnscanner.utils import safe_filename
from webvulnscanner.webhooks import _load_report


# Fields emitted per finding.  Order matters for downstream parsers that
# expect a stable key sequence (e.g. Splunk field extraction, jq pipelines).
_NDJSON_KEYS = (
    "category",
    "title",
    "severity",
    "confidence",
    "cwe",
    "owasp_category",
    "detail",
    "recommendation",
)


def findings_ndjson(report, scan_id):
    """Return (ndjson_text, filename) for `report` — the single shared
    writer behind both the session-web /scan/<id>/findings.ndjson route
    and the token-authed /api/v1 twin.

    Pure function: no Flask objects in or out, same convention as
    findings_csv_document."""
    lines = []
    for finding in report.get("findings", []):
        compact = {k: finding.get(k) for k in _NDJSON_KEYS}
        lines.append(json.dumps(compact, separators=(",", ":"), ensure_ascii=False))

    ndjson_text = "\n".join(lines)
    if ndjson_text:
        ndjson_text += "\n"  # trailing newline — POSIX text file convention

    hostname = report.get("hostname") or "scan"
    filename = safe_filename(f"{hostname.replace(':', '_')}_scan{scan_id}_findings.ndjson")
    return ndjson_text, filename
