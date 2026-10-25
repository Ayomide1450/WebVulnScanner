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
import time
from urllib.parse import urlparse

import requests

from glassbox.checks import is_ssrf_safe_hostname
from glassbox.models import OutboundWebhook, WebhookDelivery
from glassbox.regressions import alertable_new
from glassbox.security_gate import DEFAULT_FAIL_ON, evaluate_gate

# Bounded worst case per receiver - a webhook must never stall the scan
# thread that's delivering from it (WR-03's reasoning, applied server-side).
WEBHOOK_TIMEOUT_SECONDS = 5

# Phase 25 (INTG-03): bounded retry — each attempt creates its own
# WebhookDelivery row so the full trail is visible in the UI.
MAX_DELIVERY_ATTEMPTS = 3

# Phase 25 (INTG-03): delay between retry attempts (seconds).  Each
# successive attempt sleeps longer: 1 s, 2 s, 4 s (exponential backoff).
_RETRY_DELAY_SECONDS = [1, 2, 4]

# How many of the most severe findings ride along in the payload. The full
# report stays in Glassbox (and behind its auth); a channel needs the
# headline, not the whole evidence dump.
MAX_TOP_FINDINGS = 5

# Phase 27 (CONT-03): distinct event header for regression alerts. Same
# receivers, same signed-delivery machinery - only X-Glassbox-Event differs.
REGRESSION_EVENT = "finding.regressed"

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
    from glassbox.scan_engine import read_report_file

    return read_report_file(scan.report.json_path)


def build_scan_payload(scan, report, event="scan.completed"):
    """The POST body dict for a completed scan. Never raises even with a
    missing/unreadable report: the text line and scan block are built from
    the Scan row itself; findings/gate sections simply degrade to empty.
    `event` defaults to the original Phase 19 event; Phase 27's regression
    alert passes its own event string through `build_regression_payload`
    (below) rather than building a second delivery path."""
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
        "event": event,
        "scan": _scan_block(scan, risk_grade=grade),
        "gate": {
            "fail_on": DEFAULT_FAIL_ON,
            "passed": gate["passed"],
            "blocking_count": len(gate["blocking_findings"]),
        },
        "top_findings": [
            {"severity": f.get("severity"), "title": f.get("title")} for f in top
        ],
    }


def _scan_block(scan, risk_grade=None):
    """The shared per-scan block of every webhook payload - one definition
    so scan.completed and finding.regressed payloads can't drift apart.
    `risk_grade` overrides the stored report's grade when the caller already
    has it in hand (build_scan_payload's `report` argument is authoritative
    for its own payload - it may be a freshly-built dict that isn't what's
    persisted)."""
    grade = risk_grade
    if grade is None and scan.report is not None and isinstance(scan.report.data, dict):
        grade = scan.report.data.get("risk_grade")
    return {
        "id": scan.id,
        "target_url": scan.target_url,
        "scan_type": scan.scan_type,
        "status": scan.status.value,
        "risk_score": scan.risk_score,
        "risk_grade": grade or "?",
        "asset_id": scan.asset_id,
    }


def build_regression_payload(scan, regressed_findings):
    """Phase 27 (CONT-03): the POST body for a `finding.regressed` alert.
    `regressed_findings` is the already-filtered list of NEW High/Critical
    findings (regressions.alertable_new's output) from the scan's stored
    report - this function never re-derives severity policy."""
    host = urlparse(scan.target_url).hostname or scan.target_url
    text = (
        f"Glassbox regression on {host}: {len(regressed_findings)} new "
        f"High/Critical finding(s) since the previous scheduled scan."
    )
    return {
        "text": text,
        "event": REGRESSION_EVENT,
        "scan": _scan_block(scan),
        "regressed_findings": [
            {
                "severity": f.get("severity"),
                "title": f.get("title"),
                "check_name": f.get("check_name"),
            }
            for f in regressed_findings
        ],
    }


def build_splunk_hec_payload(inner_payload):
    """Phase 25 (INTG-02): wrap a Glassbox scan payload in the Splunk HEC
    event envelope.  The receiver's `sourcetype` field lets Splunk auto-
    discover the JSON schema; the `event` key carries the original payload
    verbatim so no Glassbox-specific logic is lost.

    Reference: https://docs.splunk.com/en/SplunkCloud/DataSubmission/HTTPHEC/SubmitdatatoHEC
    """
    return {
        "event": inner_payload,
        "sourcetype": "glassbox:scan",
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


def _log_delivery(webhook_id, scan_id, status, code, error, attempt=1):
    """Write one WebhookDelivery row — the single place delivery outcomes
    are recorded so every call site (deliver, send_test_ping) stays in sync.
    Never raises: a failed observability write is logged and swallowed."""
    from glassbox.extensions import db

    try:
        db.session.add(WebhookDelivery(
            webhook_id=webhook_id, scan_id=scan_id,
            status=status, response_code=code, error_message=error,
            attempt_number=attempt,
        ))
        db.session.commit()
    except Exception:  # noqa: BLE001 - observability write, best-effort by design
        db.session.rollback()
        logging.warning("webhook delivery log write failed for webhook %s", webhook_id)


def deliver(webhook, scan_id, payload=None):
    """Phase 25 (INTG-03): bounded retry loop — up to MAX_DELIVERY_ATTEMPTS
    signed POSTs, each creating its own WebhookDelivery row so the full
    trail is visible in the UI.  Stops on first "delivered" (2xx) or when
    the attempt budget is exhausted.  Between attempts the thread sleeps
    (_RETRY_DELAY_SECONDS — exponential backoff, 1 s / 2 s / 4 s); this
    runs inside a ThreadPoolExecutor so it never stalls the scan tail.

    INTG-02: when ``webhook.payload_format == "splunk_hec"`` the outgoing
    body is wrapped in the Splunk HEC envelope before signing — the
    receiver's ``sourcetype`` field lets Splunk auto-discover the schema.

    `payload` overrides the default scan.completed body —
    fire_regression_webhooks passes its finding.regressed payload through
    this same delivery path so signing, headers, timeouts, and delivery
    logging stay single-sourced.

    Never raises (degrade-gracefully convention inherited from Phase 19)."""
    from glassbox.extensions import db
    from glassbox.models import Scan

    try:
        scan = db.session.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"scan {scan_id} no longer exists")
        if payload is None:
            payload = build_scan_payload(scan, _load_report(scan))
    except Exception as exc:  # noqa: BLE001 - a webhook must never break its scan
        _log_delivery(webhook.id, scan_id, "failed", None,
                       f"unexpected delivery error: {exc}", attempt=1)
        return

    final_status = "failed"
    final_code = None
    final_error = None

    for attempt in range(1, MAX_DELIVERY_ATTEMPTS + 1):
        if attempt > 1:
            delay_idx = min(attempt - 2, len(_RETRY_DELAY_SECONDS) - 1)
            time.sleep(_RETRY_DELAY_SECONDS[delay_idx])

        # INTG-02: wrap payload for Splunk HEC if configured
        if getattr(webhook, "payload_format", None) == "splunk_hec":
            wrapped = build_splunk_hec_payload(payload)
        else:
            wrapped = payload

        status, code, error = _post_payload(webhook, wrapped)
        _log_delivery(webhook.id, scan_id, status, code, error, attempt=attempt)

        if status == "delivered":
            return  # success — stop retrying

        final_status = status
        final_code = code
        final_error = error

    # Exhausted all attempts — the last _log_delivery call already recorded it.


def send_test_ping(webhook):
    """Owner-triggered connectivity check from /webhooks - proves the URL is
    reachable and the secret/signature flow works before any real scan needs
    it. Records its own WebhookDelivery row (scan_id NULL) so the attempt is
    visible in the same recent-deliveries table as real traffic."""
    from glassbox.extensions import db

    payload = {
        "text": "Glassbox: test ping - this endpoint is wired up correctly.",
        "event": "ping",
    }
    status, code, error = _post_payload(webhook, payload)
    _log_delivery(webhook.id, None, status, code, error, attempt=1)
    return status == "delivered", error


def fire_scan_webhooks(scan_id):
    """Deliver scan-completed notices to every matching ACTIVE webhook.

    Matching mirrors `_scoped_asset_query()`'s dual scope rule: org webhooks
    receive scans run by that org; a solo user's personal webhook receives
    only scans they ran themselves (matched on created_by_user_id - NULL-org
    equality would cross-match different solo users). Called from
    `_run_scan_in_background`'s shared tail AFTER the terminal commit, so
    every spawn path (wizard, API, scheduler) converges here unchanged."""
    from glassbox.extensions import db
    from glassbox.models import Scan

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


def fire_regression_webhooks(scan_id):
    """Phase 27 (CONT-03): deliver a `finding.regressed` alert to every
    matching ACTIVE webhook when the scan's stored report contains at least
    one NEW High/Critical finding since its Asset's previous scan. Reuses
    Phase 19's machinery end to end - same receiver scoping as
    fire_scan_webhooks, same signed `deliver()` (timeout, HMAC header,
    WebhookDelivery row) - so there is exactly ONE notification path with a
    different event string, never a second delivery implementation.

    Self-guarding: silently does nothing for scans without regression tags
    (manual wizard scans), scans whose only new findings are below High, or
    missing/unreadable reports. Never raises."""
    from glassbox.extensions import db
    from glassbox.models import Scan

    try:
        s = db.session.get(Scan, scan_id)
        if s is None:
            return
        report = _load_report(s)
        findings = (report or {}).get("findings") or []
        regressed = alertable_new(findings)
        if not regressed:
            return
        payload = build_regression_payload(s, regressed)
        query = OutboundWebhook.query.filter_by(is_active=True)
        if s.org_id is not None:
            query = query.filter(OutboundWebhook.org_id == s.org_id)
        else:
            query = query.filter(
                OutboundWebhook.org_id.is_(None),
                OutboundWebhook.created_by_user_id == s.user_id,
            )
        for webhook in query.all():
            deliver(webhook, scan_id, payload=payload)
    except Exception:  # noqa: BLE001 - notifications must never break a finished scan
        logging.exception("regression webhook fan-out failed for scan %s", scan_id)
