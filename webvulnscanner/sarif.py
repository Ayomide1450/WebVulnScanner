"""SARIF 2.1.0 export of one scan report (Phase 29 / SARIF-01..02).

`build_sarif_report()` is the single writer behind both export surfaces -
the session-web GET /scan/<int:scan_id>/report.sarif route and api_routes.py's
token-authed GET /api/v1/scans/<int:scan_id>/report.sarif - so the two
formats cannot drift, mirroring scan_routes.findings_csv_document's role for
CSV. Pure module: no Flask imports, plain dicts in and out.

The output targets GitHub's native Security tab ingestion via
github/codeql-action/upload-sarif: one driver rule per unique check that
produced findings (rule id = the finding's `check_name`, falling back to its
`category` for legacy blobs), results carrying the shared severity -> level
mapping (checks.severity_to_sarif_level - SARIF-02 forbids a second copy),
CWE ids as rule tags where Phase 12 populated them, and confidence/
verification_state preserved on each result's properties for round-tripping.
"""

import json

from webvulnscanner.checks import CHECK_LABELS, severity_to_sarif_level

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "Glassbox"
TOOL_INFORMATION_URI = "https://github.com/ArktechDesigns/glassbox"


def _rule_id_for(finding):
    return str(finding.get("check_name") or finding.get("category") or "glassbox")


def _rule_label(rule_id):
    # CHECK_LABELS covers every current base-scan check name (a regression
    # test keeps it in sync); anything else - advanced/media/api-only names,
    # legacy categories - degrades to the title-cased raw id, same fallback
    # convention as the live-feed timeline.
    return CHECK_LABELS.get(rule_id, rule_id.replace("_", " ").title())


def build_sarif_report(report, scan_id):
    """One report dict in -> (sarif_document_dict, filename) out.

    Pure and deterministic: identical inputs always produce identical
    output (locked by test), including rules emitted in first-seen order
    over the already-severity-sorted findings list. Never raises on odd
    finding shapes - every field read goes through .get() with defaults,
    matching the degrade-gracefully convention of findings_csv_document.
    """
    findings = report.get("findings") or []

    rules, rule_index = [], {}
    for finding in findings:
        rid = _rule_id_for(finding)
        if rid in rule_index:
            continue
        rule_index[rid] = len(rules)
        rule = {
            "id": rid,
            "name": _rule_label(rid),
            "shortDescription": {"text": _rule_label(rid)},
        }
        cwe = finding.get("cwe")
        if cwe:
            # GitHub's Code Scanning maps `cwe:<id>` tags to its own CWE
            # advisory cross-references; keep the bare id verbatim as Phase 12
            # stored it (e.g. "CWE-79").
            rule["properties"] = {"tags": ["security", f"cwe:{cwe}"]}
        rules.append(rule)

    target = str(report.get("target") or "")
    results = []
    for finding in findings:
        message = str(finding.get("title") or "")
        detail = str(finding.get("detail") or "")
        if detail:
            message = f"{message} — {detail}"
        result = {
            "ruleId": _rule_id_for(finding),
            "ruleIndex": rule_index[_rule_id_for(finding)],
            "level": severity_to_sarif_level(finding.get("severity")),
            "message": {"text": message},
            "properties": {
                "severity": str(finding.get("severity") or ""),
                "confidence": str(finding.get("confidence") or ""),
                "title": str(finding.get("title") or ""),
            },
        }
        if target:
            # A coarse artifactLocation (the scanned origin) rather than a
            # fabricated file path/region - findings are URL-scoped, not
            # line-scoped, and GitHub renders the location link as-is.
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target},
                },
            }]
        verification_state = finding.get("verification_state")
        if verification_state:
            result["properties"]["verification_state"] = str(verification_state)
        results.append(result)

    doc = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_INFORMATION_URI,
                        "rules": rules,
                    },
                },
                "results": results,
                # automationDetails gives the upload a stable identity per
                # scan so repeated uploads of the SAME scan replace rather
                # than duplicate entries in the Security tab.
                "automationDetails": {"id": f"glassbox/scan/{scan_id}"},
            }
        ],
    }

    hostname = (
        report.get("hostname")
        or _urlparse_netloc(target)
        or "scan"
    )
    from webvulnscanner.utils import safe_filename
    filename = safe_filename(f"{str(hostname).replace(':', '_')}_scan{scan_id}.sarif")
    return doc, filename


def _urlparse_netloc(url):
    from urllib.parse import urlparse

    try:
        return urlparse(url).netloc
    except ValueError:
        return ""


def sarif_text(doc):
    """Deterministic serialization both routes serve - indent=2 so the
    artifact diffs sensibly in PRs, sort_keys off to keep rule/result order
    meaningful. Trailing newline per text-file convention."""
    return json.dumps(doc, indent=2) + "\n"
