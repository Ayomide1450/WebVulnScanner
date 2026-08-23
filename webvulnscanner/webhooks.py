"""Outbound webhook delivery (Phase 19, WEBH-*): the push half of the
platform's continuous-validation loop.

The scheduler already fires scans on a cadence and `_run_scan_in_background`
records the result - but until now both were silent. This module completes
the loop: when a scan reaches COMPLETED, every matching active
`OutboundWebhook` receives one JSON POST describing the outcome. A team's
Slack channel (or any HTTP receiver) learns about a posture regression in
minutes instead of whenever someone next logs in.

Payload shape (one body serves two audiences):

    {
      "text": "Glassbox: assessment of example.com completed - score 87 (B),
               3 finding(s). Security gate PASSED.",     <- Slack renders this
      "event": "scan.completed",
      "scan": {"id", "target_url", "scan_type", "risk_score", "risk_grade"},
      "gate": {"fail_on", "passed", "blocking_count"} | null,
      "top_findings": [{"severity", "title"}, ...]  (max 5, most severe first)
    }

The `text` field is deliberately first-class because Slack incoming webhooks
render exactly that key; generic consumers get the same information
structured under `event`/`scan`. Slack ignores unknown keys, so ONE payload
works for both - no second integration to maintain.

Safety properties, all inherited from existing app machinery rather than
reinvented:

- Receiver URLs are validated at creation time with the SAME SSRF gate the
  scan-target flow uses (`checks.is_ssrf_safe_hostname`) - a webhook must
  not become a way to make Glassbox's servers POST at internal services or
  cloud-metadata addresses. Same documented DNS-rebinding caveat applies:
  submission-time check only.
- Every delivery is signed (`X-Glassbox-Signature: sha256=HMAC-SHA256`,
  keyed by the webhook's per-endpoint secret) so a receiver can verify the
  request genuinely came from Glassbox and wasn't replayed/forged.
- `fire_scan_webhooks()` NEVER raises - a dead receiver, expired Slack URL,
  or DNS failure degrades to a `failed` WebhookDelivery row, exactly the
  degrade-gracefully convention every check_* function follows. The scan
  that triggered it is long since committed; delivery problems can never
  corrupt or un-complete it.
"""
import hashlib
import hmac
import json
import logging
from urllib.parse import urlparse

import requests

from webvulnscanner.checks import is_ssrf_safe_hostname
from webvulnscanner.models import OutboundWebhook, WebhookDelivery
from webvulnscanner.security_gate import DEFAULT_FAIL_ON, evaluate_gate

# Bounded worst case per receiver - a webhook must never stall the scan
# thread that's delivering from it (WR-03's reasoning, applied server-side).
WEBHOOK_TIMEOUT_SECONDS = 5

# How many of the most severe findings ride along in the payload. The full
# report stays in Glassbox (and behind its auth); a channel needs the
# headline, not the whole evidence dump.
MAX_TOP_FINDINGS = 5

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def redact_webhook_url(url):
    """Display-safe form of a stored webhook URL: scheme + host + '/***'.
    The path is where receivers (Slack included) embed their credential, so
    it is never rendered back anywhere - not even for the webhook's owner."""
    parsed = urlparse(url or "")
    host = parsed.netloc or "(unknown)"
    return f"{parsed.scheme or 'https'}://{host}/***(redacted)"


def validate_webhook_url(url):
    """None if `url` is an acceptable webhook endpoint; a user-safe error
    string otherwise. Enforces HTTPS (deliveries carry findings - plaintext
    HTTP would let any network hop read them), a resolvable public hostname
    via the same `is_ssrf_safe_hostname` gate scan targets go through, and
    the model column's length limit."""
    if not url or len(url) > 2048:
        return "A webhook URL is required."
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        return "Webhook URLs must be HTTPS (e.g. https://hooks.slack.com/services/...)."
    hostname = parsed.hostname
    if not hostname or not is_ssrf_safe_hostname(hostname):
        return (
            "This endpoint resolves to a private, internal, or unreachable "
            "address and cannot be used as a webhook target."
        )
    return None


def _load_report(scan):
    """Report JSON for `scan`, or None - Report.data (Postgres) first,
    on-disk file as legacy fallback, mirroring scan_routes._load_report_json.
    Re-declared here (rather than imported) because scan_routes imports THIS
    module; keeping the dependency direction one-way avoids a cycle."""
    if scan.report is None:
        return None
    if scan.report.data is not None:
        return scan.report.data
    from webvulnscanner.scan_engine import read_report_file

    return read_report_file(scan.report.json_path)


def build_scan_payload(scan, report):
    """The POST body dict for a completed scan. Never raises even with a
    missing/unreadable report: the text line and scan block are built from
    the Scan row itself; findings/gate sections simply degrade to empty."""
    score = scan.risk_score
    grade = (report or {}).get("risk_grade") or "?"
    findings = (report or {}).get("findings") or []

    text = (
        f"Glassbox: assessment of {urlparse(scan.target_url).hostname or scan.target_url} "
        f"completed - score {score if score is not None else '?'} ({grade}), "
        f"{len(findings)} finding(s)."
    )

    # Gate verdict comes from the same evaluate_gate() the /api/v1 gate
    # endpoint and `glassbox gate` use - the blocking rule is defined once.
    gate = evaluate_gate(findings, fail_on=DEFAULT_FAIL_ON)
    if gate["passed"]:
        text += " Security gate PASSED."
    else:
        text += (
            f" Security gate FAILED - {len(gate['blocking_findings'])} blocking "
            f"finding(s) at {DEFAULT_FAIL_ON} severity or above."
        )

    top = sorted(
        findings,
        key=lambda f: _SEVERITY_RANK.get((f.get("severity") or "info").lower(), 99),
    )[:MAX_TOP_FINDINGS]

    return {
        "text": text,
        "event": "scan.completed",
        "scan": {
            "id": scan.id,
            "target_url": scan.target_url,
            "scan_type": scan.scan_type,
            "status": scan.status.value,
            "risk_score": score,
            "risk_grade": grade,
        },
        "gate": {
            "fail_on": DEFAULT_FAIL_ON,
            "passed": gate["passed"],
            "blocking_count": len(gate["blocking_findings"]),
        },
        "top_findings": [
            {"severity": f.get("severity"), "title": f.get("title")} for f in top
        ],
    }


def sign_payload(secret, body_bytes):
    """HMAC-SHA256 signature header value over the exact bytes sent."""
    digest = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _post_payload(webhook, payload):
    """The raw signed POST shared by real deliveries and the owner's
    "send test" button - returns (status, response_code, error_message)."""
    body = json.dumps(payload).encode("utf-8")
    try:
        resp = requests.post(
            webhook.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Glassbox-Event": str(payload.get("event", "scan.completed")),
                "X-Glassbox-Signature": sign_payload(webhook.secret, body),
                "User-Agent": "Glassbox-Webhook/1.0",
            },
            timeout=WEBHOOK_TIMEOUT_SECONDS,
        )
        # 2xx = delivered; anything else (including Slack's 410 Gone for a
        # removed channel) is a failed attempt worth surfacing in the UI.
        if 200 <= resp.status_code < 300:
            return "delivered", resp.status_code, None
        return "failed", resp.status_code, f"receiver returned HTTP {resp.status_code}"
    except requests.RequestException as exc:
        return "failed", None, f"delivery error: {exc}"


def deliver(webhook, scan_id):
    """One signed POST to `webhook.url` describing scan `scan_id`, plus the
    WebhookDelivery row recording how it went. Never raises."""
    from webvulnscanner.extensions import db
    from webvulnscanner.models import Scan

    try:
        scan = db.session.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"scan {scan_id} no longer exists")
        payload = build_scan_payload(scan, _load_report(scan))
        status, code, error = _post_payload(webhook, payload)
    except Exception as exc:  # noqa: BLE001 - a webhook must never break its scan
        status, code, error = "failed", None, f"unexpected delivery error: {exc}"

    try:
        db.session.add(WebhookDelivery(
            webhook_id=webhook.id, scan_id=scan_id,
            status=status, response_code=code, error_message=error,
        ))
        db.session.commit()
    except Exception:  # noqa: BLE001 - observability write, best-effort by design
        db.session.rollback()
        logging.warning("webhook delivery log write failed for webhook %s", webhook.id)


def send_test_ping(webhook):
    """Owner-triggered connectivity check from /webhooks - proves the URL is
    reachable and the secret/signature flow works before any real scan needs
    it. Records its own WebhookDelivery row (scan_id NULL) so the attempt is
    visible in the same recent-deliveries table as real traffic."""
    from webvulnscanner.extensions import db

    payload = {
        "text": "Glassbox: test ping - this endpoint is wired up correctly.",
        "event": "ping",
    }
    status, code, error = _post_payload(webhook, payload)
    try:
        db.session.add(WebhookDelivery(
            webhook_id=webhook.id, scan_id=None,
            status=status, response_code=code, error_message=error,
        ))
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
    return status == "delivered", error


def fire_scan_webhooks(scan_id):
    """Deliver scan-completed notices to every matching ACTIVE webhook.

    Matching mirrors `_scoped_asset_query()`'s dual scope rule: org webhooks
    receive scans run by that org; a solo user's personal webhook receives
    only scans they ran themselves (matched on created_by_user_id - NULL-org
    equality would cross-match different solo users). Called from
    `_run_scan_in_background`'s shared tail AFTER the terminal commit, so
    every spawn path (wizard, API, scheduler) converges here unchanged."""
    from webvulnscanner.extensions import db
    from webvulnscanner.models import Scan

    try:
        s = db.session.get(Scan, scan_id)
        if s is None:
            return
        query = OutboundWebhook.query.filter_by(is_active=True)
        if s.org_id is not None:
            query = query.filter(OutboundWebhook.org_id == s.org_id)
        else:
            query = query.filter(
                OutboundWebhook.org_id.is_(None),
                OutboundWebhook.created_by_user_id == s.user_id,
            )
        for webhook in query.all():
            deliver(webhook, scan_id)
    except Exception:  # noqa: BLE001 - notifications must never break a finished scan
        logging.exception("webhook fan-out failed for scan %s", scan_id)
