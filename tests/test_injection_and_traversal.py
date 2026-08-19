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
import pathlib
import re

from markupsafe import escape as _markupsafe_escape

from webvulnscanner.extensions import db as _db
from webvulnscanner.models import DomainVerification, Report, Role, Scan, ScanStatus, VerifyMethod

from tests.conftest import login, make_org, make_scan, make_user

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WEBVULNSCANNER_DIR = REPO_ROOT / "webvulnscanner"
TEMPLATES_DIR = REPO_ROOT / "templates"

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


# --------------------------------------------------------------------------
# Task 2: standing, comment-filtered source-level locks for SEC-04's
# escaping guarantee and SEC-05's SQL-parameterization guarantee. These
# convert Task 1's one-time proof (and 08-RESEARCH.md's one-time grep) into
# assertions that run on every suite invocation - a future |safe filter,
# Markup() wrap, string-template render, or raw-SQL string anywhere in this
# codebase fails the suite instead of waiting for the next manual audit.
#
# Comment filtering matters here specifically because this module's own
# prose (above and in this section) necessarily discusses the very
# constructs it forbids - an unfiltered grep-style lock could be tripped by
# its own docstring, or worse, could be satisfied by commenting out the
# forbidden construct instead of removing it.
# --------------------------------------------------------------------------


def _strip_jinja_comment_spans(text):
    """Yields (lineno, code_only_line) pairs for a Jinja template's source,
    with the contents of every {# ... #} comment block blanked out (spans
    can cross multiple lines) while preserving line numbers and any real
    code sharing a line with a comment marker - so a template's own
    commented-out discussion of |safe/autoescape can never trip the lock,
    and a real offending line is still reported at its true line number."""
    out = []
    in_comment = False
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        pieces = []
        i = 0
        while i < len(raw_line):
            if in_comment:
                end = raw_line.find("#}", i)
                if end == -1:
                    i = len(raw_line)
                else:
                    in_comment = False
                    i = end + 2
            else:
                start = raw_line.find("{#", i)
                if start == -1:
                    pieces.append(raw_line[i:])
                    i = len(raw_line)
                else:
                    pieces.append(raw_line[i:start])
                    in_comment = True
                    i = start + 2
        out.append((lineno, "".join(pieces)))
    return out


def _find_unsafe_filter_or_autoescape_off():
    """Comment-filtered scan of every template under templates/ (including
    partials) for the escaping-disabling |safe filter or an
    autoescape-disabling {% autoescape false %} block. Returns
    (path, lineno, stripped_line, mechanism) tuples."""
    hits = []
    for path in sorted(TEMPLATES_DIR.rglob("*.html")):
        for lineno, code_line in _strip_jinja_comment_spans(path.read_text(encoding="utf-8")):
            if re.search(r"\|\s*safe\b", code_line):
                hits.append((path, lineno, code_line.strip(), "|safe filter"))
            if re.search(r"\{%-?\s*autoescape\s+false\s*-?%\}", code_line):
                hits.append((path, lineno, code_line.strip(), "{% autoescape false %}"))
    return hits


def test_no_template_disables_autoescaping_or_uses_safe_filter():
    hits = _find_unsafe_filter_or_autoescape_off()
    assert not hits, "escaping-disabling construct(s) found (SEC-04 regression): " + "; ".join(
        f"{p.relative_to(REPO_ROOT).as_posix()}:{n} uses {mech} -> {line!r}"
        for p, n, line, mech in hits
    )


def _find_markup_construction_or_string_template_render():
    """Comment-filtered (full-line only, matching test_csrf_enforcement.py's
    established idiom) scan of every .py under webvulnscanner/ for
    Markup(...) construction or render_template_string(...) calls - the two
    ways a Python module (rather than a template) could reintroduce
    unescaped HTML. Returns (path, lineno, stripped_line) tuples."""
    hits = []
    for path in sorted(WEBVULNSCANNER_DIR.rglob("*.py")):
        for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if raw_line.strip().startswith("#"):
                continue
            code_part = raw_line.split("#", 1)[0]
            if re.search(r"\bMarkup\s*\(", code_part) or re.search(r"\brender_template_string\s*\(", code_part):
                hits.append((path, lineno, raw_line.strip()))
    return hits


def test_no_module_constructs_markup_or_renders_template_string():
    hits = _find_markup_construction_or_string_template_render()
    assert not hits, "markup-construction/string-template-render call(s) found (SEC-04 regression): " + "; ".join(
        f"{p.relative_to(REPO_ROOT).as_posix()}:{n} -> {line!r}" for p, n, line in hits
    )


def _find_raw_sql_execute_call_sites():
    """Comment-filtered (full-line only) scan of every .py under
    webvulnscanner/ for a direct `.execute(` call - the only shape a raw or
    string-interpolated SQL statement could enter this codebase through,
    since every ORM/Core query-builder call (Model.query.filter(...),
    select(...), update(...), etc.) never itself calls .execute() in
    application code; only db.session.execute(...) does. Returns a list of
    (module_path_posix, enclosing_function_name) tuples, the same
    module+function-keyed shape test_csrf_enforcement.py's
    test_csrf_exempt_applied_to_exactly_one_blueprint uses for its own
    exact-set lock."""
    hits = []
    for path in sorted(WEBVULNSCANNER_DIR.rglob("*.py")):
        current_function = None
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            if raw_line.strip().startswith("#"):
                continue
            code_part = raw_line.split("#", 1)[0]
            func_match = re.match(r"\s*def\s+(\w+)\s*\(", code_part)
            if func_match:
                current_function = func_match.group(1)
            if ".execute(" in code_part:
                hits.append((path.relative_to(REPO_ROOT).as_posix(), current_function))
    return hits


def test_raw_sql_execute_call_sites_are_exactly_the_two_known_ones():
    hits = _find_raw_sql_execute_call_sites()
    expected = {
        ("webvulnscanner/public_routes.py", "healthz"),
        ("webvulnscanner/scheduler.py", "_try_claim"),
    }
    assert set(hits) == expected, (
        f"raw db.session.execute() call site(s) changed (SEC-05 regression) - expected "
        f"exactly {sorted(expected)}, found {sorted(set(hits))}. A new call site needs "
        f"either becoming an ORM/Core query-builder call instead, or an explicit, "
        f"reviewed addition to this allowlist plus its own literal/bound-parameter proof."
    )


def test_healthcheck_sql_argument_is_a_literal_string_constant():
    """public_routes.healthz() is one of the two allowlisted raw-execute call
    sites - defensible only because its argument is a literal string, never
    built from a variable, f-string, or .format() call."""
    import inspect

    from webvulnscanner.public_routes import healthz

    src = inspect.getsource(healthz)
    assert re.search(r'db\.text\(\s*"SELECT 1"\s*\)', src), (
        "public_routes.healthz() no longer calls db.text() with the literal "
        "'SELECT 1' string constant - if this becomes a variable or an "
        "f-string, this allowlist entry needs re-auditing as a potential "
        "raw-SQL injection point."
    )
    assert "f\"" not in src and "f'" not in src and ".format(" not in src, (
        "public_routes.healthz() appears to build its SQL text dynamically "
        "rather than passing a literal string constant to db.text()"
    )


def test_scheduler_update_binds_values_as_parameters():
    """scheduler._try_claim() is the other allowlisted raw-execute call site
    - defensible only because it's a SQLAlchemy Core update() statement
    whose values are bound via .values(...), never formatted directly into
    a SQL string."""
    import inspect

    from webvulnscanner.scheduler import _try_claim

    src = inspect.getsource(_try_claim)
    assert re.search(r"\.values\(", src), (
        "scheduler._try_claim() no longer calls .values(...) on its Core "
        "update() statement - if values started being formatted directly "
        "into a string instead of bound via .values(), this would become a "
        "raw-SQL injection point."
    )
    assert not re.search(r"f\"|f'|%\s*\(|\.format\(", src), (
        "scheduler._try_claim() appears to format SQL text directly rather "
        "than binding parameters via SQLAlchemy Core's .values()"
    )
    assert "db.text(" not in src, (
        "scheduler._try_claim() now uses db.text() for raw SQL text instead "
        "of the Core update() statement builder - re-audit as a potential "
        "raw-SQL injection point"
    )


# Negative controls performed manually while writing this section (not
# themselves permanent tests - each forbidden construct was introduced in a
# scratch edit, the relevant test was run alone to confirm it failed naming
# the right file/line, then the edit was reverted; `git diff --stat` was
# confirmed clean afterward). Failure messages recorded verbatim in
# 08-05-SUMMARY.md.
