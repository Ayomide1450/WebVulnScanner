"""
Single source of truth for the in-product API reference (Phase 22, DOCS-01).

`API_ENDPOINTS` below documents every /api/v1 route; the /docs/api page
renders straight from this structure, and tests/test_api_docs.py's
url_map-enumeration lock fails - naming the exact rule - if any /api/v1
route exists that isn't documented here, or if a documented path/method
stops existing. That is the same self-maintaining discipline
tests/test_cross_org_idor.py applies to IDOR coverage: docs that cannot
silently drift, because a code change without a spec update breaks CI.

Two more sync locks live in the same test file and pin the other two
hand-maintained artifacts on this module:

- WEBHOOK_VERIFY_SNIPPET is behaviorally executed against
  webhooks.sign_payload (same secret/body in, byte-identical signature
  verdict out) so the copy-pasteable receiver example can't drift from the
  real signing algorithm.
- CLI_SUBCOMMANDS must equal the set of `glassbox <subcommand>` lines found
  in cli/README.md, so a new CLI command forces both surfaces to move
  together.

Examples are shaped after the real serializers (_serialize_asset /
_serialize_scan_summary in api_routes.py, evaluate_gate's dict in
security_gate.py) rather than invented shapes.
"""

# ---------------------------------------------------------------------------
# Endpoint spec - one entry per Flask rule under /api/v1
# ---------------------------------------------------------------------------

_API_TOKEN_AUTH = "Bearer API token"

API_ENDPOINTS = [
    {
        "path": "/api/v1/assets",
        "methods": ["GET"],
        "group": "Assets",
        "summary": "List every Asset the caller can see (org-shared for org members, "
        "own-only for solo users), newest first, each with its latest scan summary.",
        "auth": _API_TOKEN_AUTH,
        "rate_limit": "60/minute",
        "request_example": None,
        "response_example": {
            "assets": [
                {
                    "id": 42,
                    "name": "Marketing site",
                    "target_url": "https://www.example.com",
                    "hostname": "www.example.com",
                    "cadence": "daily",
                    "schedule_scan_type": "base",
                    "is_paused": False,
                    "latest_scan": {
                        "id": 1042,
                        "status": "COMPLETED",
                        "risk_score": 88,
                        "created_at": "2026-08-24T09:15:00",
                        "completed_at": "2026-08-24T09:16:41",
                    },
                }
            ]
        },
    },
    {
        "path": "/api/v1/assets/<int:asset_id>/scans",
        "methods": ["POST"],
        "group": "Assets",
        "summary": "Trigger a scan for an existing Asset. Always returns 202 with the "
        "created scan's id/status - inspect status even on success, because an "
        "SSRF-unsafe target or insufficient tier produces a FAILED scan at creation "
        "time. Uses the exact dispatch path the scheduler itself uses.",
        "auth": _API_TOKEN_AUTH,
        "rate_limit": "30/minute",
        "request_example": None,
        "response_example": {"scan_id": 1043, "status": "QUEUED"},
    },
    {
        "path": "/api/v1/scans",
        "methods": ["GET", "POST"],
        "group": "Scans",
        "summary": "GET lists your own scans (newest first, optional ?target_url= filter, "
        "?limit= up to 100). POST launches an ad-hoc standard/base scan against "
        "target_url without creating a persistent Asset - subject to the identical "
        "SSRF/tier/authorization gates as every other launch surface. `authorized: true` "
        "is REQUIRED in the body: confirm you own the domain or have explicit permission "
        "to test it.",
        "auth": _API_TOKEN_AUTH,
        "rate_limit": "30/minute",
        "request_example": {
            "target_url": "https://www.example.com",
            "authorized": True,
        },
        "response_example": {"scan_id": 1044, "status": "QUEUED", "duplicate": False},
    },
    {
        "path": "/api/v1/scans/<int:scan_id>",
        "methods": ["GET"],
        "group": "Scans",
        "summary": "Lightweight status poll for one scan - progress counters and error "
        "message without pulling the full report. Ideal for CI wait-loops.",
        "auth": _API_TOKEN_AUTH,
        "rate_limit": "60/minute",
        "request_example": None,
        "response_example": {
            "id": 1044,
            "status": "RUNNING",
            "risk_score": None,
            "created_at": "2026-08-24T10:00:00",
            "completed_at": None,
            "progress_current": 7,
            "progress_total": 23,
            "error_message": None,
        },
    },
    {
        "path": "/api/v1/scans/<int:scan_id>/report",
        "methods": ["GET"],
        "group": "Reports",
        "summary": "Fetch a completed scan's full report as JSON - the exact document "
        "the web UI renders. 404 while the scan is still running or failed (no report "
        "yet); 500 if the stored report blob/file is unreadable.",
        "auth": _API_TOKEN_AUTH,
        "rate_limit": "60/minute",
        "request_example": None,
        "response_example": {
            "score": 88,
            "risk_grade": "B",
            "severity_counts": {"critical": 0, "high": 1, "medium": 3},
            "findings": "[ ... full Finding objects: category/title/severity/confidence/cwe/detail/recommendation ... ]",
        },
    },
    {
        "path": "/api/v1/scans/<int:scan_id>/report.csv",
        "methods": ["GET"],
        "group": "Reports",
        "summary": "The same report as CSV - byte-identical to the web UI's export.csv "
        "download (one shared writer behind both), served as an attachment.",
        "auth": _API_TOKEN_AUTH,
        "rate_limit": "60/minute",
        "request_example": None,
        "response_example": (
            "category,title,severity,confidence,detail\n"
            'headers,Strict-Transport-Security missing,medium,Potential,"..."\n'
        ),
    },
    {
        "path": "/api/v1/scans/<int:scan_id>/report.sarif",
        "methods": ["GET"],
        "group": "Reports",
        "summary": "The same report as SARIF 2.1.0 - byte-identical to the web UI's "
        "report.sarif download (one shared writer behind both). Ingestible directly by "
        "GitHub's Security tab via github/codeql-action/upload-sarif: severity maps to "
        "SARIF level (critical/high -> error, medium -> warning, low/info -> note) and "
        "CWE ids ride rule tags where known. Served as an attachment.",
        "auth": _API_TOKEN_AUTH,
        "rate_limit": "60/minute",
        "request_example": None,
        "response_example": (
            '{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Glassbox", '
            '"rules": [...]}}, "results": [{"ruleId": "headers", "level": "warning", '
            '"message": {"text": "..."}, ...}]}]}'
        ),
    },
    {
        "path": "/api/v1/scans/<int:scan_id>/compare/<int:other_id>",
        "methods": ["GET"],
        "group": "Reports",
        "summary": "Diff two completed scans of yours - the same Added/Removed/Changed/"
        "Unchanged structure the web compare page renders. Both scans are ownership-"
        "checked independently.",
        "auth": _API_TOKEN_AUTH,
        "rate_limit": "60/minute",
        "request_example": None,
        "response_example": {
            "scan_a": {"id": 1042, "status": "COMPLETED", "risk_score": 91},
            "scan_b": {"id": 1044, "status": "COMPLETED", "risk_score": 88},
            "diff": {
                "added": "[ ... findings present only in b ... ]",
                "removed": [],
                "changed": [],
                "unchanged_count": 31,
            },
        },
    },
    {
        "path": "/api/v1/scans/<int:scan_id>/gate",
        "methods": ["GET"],
        "group": "CI gate",
        "summary": "Evaluate a completed scan against a severity threshold and return a "
        "pass/fail verdict - the single server-side rule `glassbox gate` and direct HTTP "
        "CI consumers share. Optional ?fail_on= is one of: low, medium, high, critical "
        "(default high). Read-only; recomputed from the stored report on every call.",
        "auth": _API_TOKEN_AUTH,
        "rate_limit": "60/minute",
        "request_example": None,
        "response_example": {
            "verdict": "FAIL",
            "fail_on": "high",
            "blocking_count": 1,
            "scan_id": 1044,
            "scan_status": "COMPLETED",
            "target_url": "https://www.example.com",
            "score": 88,
            "risk_grade": "B",
            "severity_counts": {"critical": 0, "high": 1, "medium": 3},
        },
    },
]

# Error semantics shared by every endpoint (all errors are JSON, never HTML):
ERROR_SEMANTICS = [
    ("401", "Missing, malformed, revoked, or unknown Bearer token."),
    ("400", "Malformed request (e.g. POST /scans without target_url or authorized=true)."),
    ("404", "No such resource, or it belongs to another user/org - deliberately "
    "indistinguishable (ownership probes learn nothing)."),
    ("500", "The report row exists but its stored blob/file is unreadable."),
]

CURL_EXAMPLE = (
    "curl -H \"Authorization: Bearer $GLASSBOX_API_TOKEN\" \\\n"
    "     https://your-glassbox-host/api/v1/scans/1044/gate?fail_on=high"
)

# ---------------------------------------------------------------------------
# Webhook receiver verification snippet (DOCS-03)
# Behaviorally locked to webhooks.sign_payload by test_api_docs.py: the test
# exec()s this source and requires identical pass/fail verdicts against the
# real signer for sample inputs. Header name: X-Glassbox-Signature.
# ---------------------------------------------------------------------------

WEBHOOK_VERIFY_SNIPPET = """\
import hashlib
import hmac


def verify_signature(secret, raw_body, header_value):
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, header_value)
"""

# ---------------------------------------------------------------------------
# CLI quickstart (DOCS-04)
# Locked to cli/README.md: the set of subcommands below must equal the set of
# `glassbox <cmd>` invocation lines in that README, or the sync test fails
# naming the diff.
# ---------------------------------------------------------------------------

CLI_SUBCOMMANDS = [
    "init",
    "check",
    "assess",
    "readiness",
    "findings",
    "report",
    "gate",
    "assets",
    "scan",
    "compare",
    "verify",
]
