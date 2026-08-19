"""
Tests for SEC-04 (escaping), SEC-05 (SQL parameterization) and SEC-06 (report
file-path containment), covered together as one audit sweep - 08-RESEARCH.md
verified this session that the codebase is already correct on all three, so
this module's job is to convert that one-time reading into a standing,
regression-proof check rather than a recorded grep result.

Jinja2's autoescaping is on by default under Flask, and nothing in this app
disables it (`webvulnscanner/__init__.py` never sets `autoescape=False`,
replaces the Jinja environment, or registers a markup-returning filter). The
risk this module exists to catch is not today's state but a future `|safe`
filter, `Markup()` wrap, or raw-SQL string built anywhere in `webvulnscanner/`
- which is why Task 2's locks are comment-filtered source scans that run on
every suite invocation, not a one-time audit finding.

Task 1 (this section): end-to-end escaping proof. Every user- or
target-controlled string that reaches a template is proven to render
escaped, in both directions (escaped form present AND raw form absent -
asserting only absence would pass if the field silently failed to render at
all, which is a rendering bug masquerading as a security pass). A single
payload constant is defined once below and both its escaped and raw forms
are derived from it via `markupsafe.escape` (the exact function Jinja2's
autoescape calls), never retyped.
"""
from markupsafe import escape as _markupsafe_escape

from webvulnscanner.extensions import db as _db
from webvulnscanner.models import DomainVerification, Report, Role, Scan, ScanStatus, VerifyMethod

from tests.conftest import login, make_org, make_scan, make_user

# Single module-level payload: a tag (would execute if unescaped) plus an
# attribute-breaking quote (would let a partial-escaping bug still break out
# of an attribute context) - both derived-checkable in one string so a test
# would catch partial escaping, not just a totally-missing one.
PAYLOAD = "<script>alert('xss')</script>\" onmouseover=alert(1)"
ESCAPED_PAYLOAD = str(_markupsafe_escape(PAYLOAD))


def _make_report_data(finding_title=PAYLOAD, finding_detail=PAYLOAD, ai_summary=None):
    """A minimal Report.data dict satisfying every key scan_report.html reads
    for a non-base scan_type (see module docstring in the plan: scan_type is
    deliberately set to something other than 'base'/'advanced'/'media'/'api'
    on the seeded Scan row below, so the detailed-check-output sections that
    require many more report keys never render at all - only the generic
    score-card/ai-summary/findings sections, which is all this sweep needs)."""
    return {
        "target": "https://example.com",
        "hostname": "example.com",
        "scanned_at": "2026-01-01T00:00:00+00:00",
        "score": 42,
        "risk_grade": "D",
        "severity_counts": {"critical": 1},
        "findings": [
            {
                "category": "xss",
                "check_name": "xss_probe",
                "title": finding_title,
                "severity": "critical",
                "detail": finding_detail,
                "recommendation": "Escape all rendered output.",
            }
        ],
        "locked_checks": [],
        "ai_summary": ai_summary,
    }


def _seed_scan_with_report(user, org, report_data):
    """Seeds a Scan + Report row via Report.data directly (no filesystem, no
    scan execution) - scan_type='probe' is not 'base'/'advanced'/'media'/'api'
    so scan_report.html's four scan-type-gated detail sections never render,
    keeping this report dict minimal."""
    scan = make_scan(user, org=org, target_url="https://example.com",
                      scan_type="probe", status=ScanStatus.COMPLETED)
    _db.session.add(Report(scan_id=scan.id, json_path="unused.json", data=report_data))
    _db.session.commit()
    return scan


# --------------------------------------------------------------------------
# Task 1: escaping proofs. Each field's test asserts BOTH the escaped form
# present AND the raw form absent in the rendered response body.
# --------------------------------------------------------------------------


def test_finding_title_renders_escaped_on_scan_report(client, db):
    """Asserted against GET /scan/<id>/report (templates/scan_report.html's
    finding_card macro, {{ f.title }})."""
    org = make_org(name="Finding Title Escaping Org")
    user = make_user("finding-title@example.com", org=org, role=Role.MEMBER)
    scan = _seed_scan_with_report(
        user, org, _make_report_data(finding_title=PAYLOAD, finding_detail="benign detail text"))
    login(client, "finding-title@example.com")

    resp = client.get(f"/scan/{scan.id}/report")
    body = resp.get_data(as_text=True)

    assert ESCAPED_PAYLOAD in body
    assert PAYLOAD not in body


def test_finding_detail_renders_escaped_on_scan_report(client, db):
    """Asserted against GET /scan/<id>/report (templates/scan_report.html's
    finding_card macro, {{ f.detail }})."""
    org = make_org(name="Finding Detail Escaping Org")
    user = make_user("finding-detail@example.com", org=org, role=Role.MEMBER)
    scan = _seed_scan_with_report(
        user, org, _make_report_data(finding_title="benign title text", finding_detail=PAYLOAD))
    login(client, "finding-detail@example.com")

    resp = client.get(f"/scan/{scan.id}/report")
    body = resp.get_data(as_text=True)

    assert ESCAPED_PAYLOAD in body
    assert PAYLOAD not in body


def test_ai_summary_renders_escaped_on_scan_report(client, db):
    """Asserted against GET /scan/<id>/report (templates/scan_report.html,
    the AI-assisted-summary card, {{ r.ai_summary }}) - a second
    untrusted-content path into the same template, one step further removed
    (Groq's LLM output rather than the scanned site's raw HTTP response)."""
    org = make_org(name="AI Summary Escaping Org")
    user = make_user("ai-summary@example.com", org=org, role=Role.MEMBER)
    scan = _seed_scan_with_report(
        user, org,
        _make_report_data(finding_title="benign title", finding_detail="benign detail",
                           ai_summary=PAYLOAD))
    login(client, "ai-summary@example.com")

    resp = client.get(f"/scan/{scan.id}/report")
    body = resp.get_data(as_text=True)

    assert ESCAPED_PAYLOAD in body
    assert PAYLOAD not in body


def test_org_name_renders_escaped_on_org_admin(client, db):
    """Asserted against GET /org/admin (templates/org_admin.html line 26,
    {{ org.name if org else 'Organization' }}) - attacker-controlled at
    signup time, rendered to every other member of the same org."""
    org = make_org(name=PAYLOAD)
    user = make_user("org-name-admin@example.com", org=org, role=Role.ORG_ADMIN)
    login(client, "org-name-admin@example.com")

    resp = client.get("/org/admin")
    body = resp.get_data(as_text=True)

    assert ESCAPED_PAYLOAD in body
    assert PAYLOAD not in body


def test_domain_name_renders_escaped_on_org_admin(client, db):
    """Asserted against GET /org/admin (templates/org_admin.html's domain
    table, {{ dv.domain }}) - DomainVerification.domain has no format
    validator beyond DataRequired() on the add-domain form, so a malicious
    value reaching the row and then the page is the realistic path, not a
    hypothetical one."""
    org = make_org(name="Domain Name Escaping Org")
    user = make_user("domain-admin@example.com", org=org, role=Role.ORG_ADMIN)
    dv = DomainVerification(org_id=org.id, domain=PAYLOAD, method=VerifyMethod.DNS_TXT,
                             token="test-token-value")
    db.session.add(dv)
    db.session.commit()
    login(client, "domain-admin@example.com")

    resp = client.get("/org/admin")
    body = resp.get_data(as_text=True)

    assert ESCAPED_PAYLOAD in body
    assert PAYLOAD not in body


def test_flashed_error_message_renders_escaped(client, db):
    """Asserted against GET /dashboard (templates/base.html's
    get_flashed_messages() block, shared by every page that extends
    base.html). The flash is injected directly into session['_flashes'] -
    the exact structure Flask's own flash()/get_flashed_messages() read and
    write - rather than driving a specific route to produce one, since the
    escaping mechanism under test lives entirely in base.html's rendering of
    whatever message a route flashed, not in which route flashed it."""
    org = make_org(name="Flash Escaping Org")
    user = make_user("flash-user@example.com", org=org, role=Role.MEMBER)
    login(client, "flash-user@example.com")
    with client.session_transaction() as sess:
        sess["_flashes"] = [("error", PAYLOAD)]

    resp = client.get("/dashboard")
    body = resp.get_data(as_text=True)

    assert ESCAPED_PAYLOAD in body
    assert PAYLOAD not in body


def test_csv_export_contains_raw_payload_unescaped(client, db):
    """Counter-case pinning the deliberate asymmetry: CSV is not HTML, so
    GET /scan/<id>/export.csv must NOT HTML-escape the same payload the
    report page escapes. Without this test, a later contributor "fixing"
    the CSV export to match the HTML page's escaping would corrupt the
    export with nothing objecting.

    The tag substring is checked rather than the full PAYLOAD verbatim:
    Python's csv module correctly doubles PAYLOAD's own embedded `"`
    per RFC 4180 quoting when it lands in a comma-containing-safe field -
    that quote-doubling is standard CSV quoting, not HTML-escaping, and
    asserting the exact byte sequence would conflate the two. The
    security-relevant assertion is that the tag itself was never
    HTML-entity-encoded."""
    org = make_org(name="CSV Escaping Org")
    user = make_user("csv-user@example.com", org=org, role=Role.MEMBER)
    scan = _seed_scan_with_report(user, org, _make_report_data())
    login(client, "csv-user@example.com")

    resp = client.get(f"/scan/{scan.id}/export.csv")
    body = resp.get_data(as_text=True)

    assert "<script>alert('xss')</script>" in body
    assert ESCAPED_PAYLOAD not in body
    assert resp.mimetype == "text/csv"
