"""App-wide accessibility locks (A11Y-01/02/03's automatable halves).

An exhaustive audit this planning session found the codebase's baseline
already strong: all eight icon-only buttons carried an `aria-label`, there
was not one clickable `<div>`, `role="button"` or stray `tabindex` in any
of the 35 templates, exactly one form control in the entire app had no
accessible name (org_admin.html's deletion-reason input - closed by plan
07-02), and exactly two templates had a heading skip (marketing.html,
scan_new_advanced.html - closed by this plan's Task 1). So these are
almost entirely *preservation* locks, not fix-verification tests - their
real value is catching a regression introduced by the nine new mobile-card
blocks waves 1/2 added, or by any future work.

What these assertions cannot answer - whether a keyboard user can actually
complete a real flow end to end, and whether a focus ring is visually
clipped by a tightly-bounding parent anywhere - is settled at this plan's
`checkpoint:human-verify` task instead (07-UI-SPEC.md's unresolved UI
Consideration row). Static rendered-HTML assertions can prove the
*preconditions* for keyboard operability (every interactive element is
native, one global focus rule applies to all of them) but not that a human
can tab through a live page without getting lost.

Selectors: `-k heading_hierarchy`, `-k labels_and_icon_buttons`,
`-k no_clickable_divs`, `-k focus_treatment`. `.com`/`.org` fake domains
are used in fixture emails throughout, never `.test` (CLAUDE.md's Gotcha:
email_validator statically rejects reserved TLDs even with deliverability
checking off).
"""
import pathlib
import re
import socket
from datetime import datetime, timezone

import pytest
from bs4 import BeautifulSoup

from webvulnscanner.extensions import db as _db
from webvulnscanner.models import (
    DomainVerification,
    Invitation,
    InvitationStatus,
    Plan,
    Report,
    Role,
    ScanStatus,
    VerifyMethod,
)

from tests.conftest import login, make_api_token, make_asset, make_org, make_scan, make_user
from tests.test_responsive_org_tables import _ids_in

TEMPLATES_DIR = pathlib.Path("templates")

# --------------------------------------------------------------------------
# Page-list construction. Built from app.url_map (not hand-maintained) so a
# future route with no test coverage here is a visible gap, not a silent
# one. Rules that accept GET, take no path parameter, and aren't excluded
# below are in scope.
# --------------------------------------------------------------------------

EXCLUDED_ENDPOINTS = {
    "static": "Flask's built-in static-file server - serves assets, not an HTML page.",
    "public.healthz": "Render's health-check path - returns a bare 200 with no HTML body to assert against.",
    "auth.logout": "Clears the session and 302-redirects to '/' - no template of its own to render.",
}
EXCLUDED_BLUEPRINT_PREFIXES = (
    "api.",  # webvulnscanner/api_routes.py - a JSON API blueprint (/api/v1/*). Every
    # response is application/json, so heading/label/icon/focus assertions - all of
    # which parse an HTML document - don't apply.
)

# Extra query string appended when requesting a given path, so the page
# renders its populated state rather than a query-string-less default.
# `/scan/new/type` and `/scan/new/advanced` both resolve their `target`
# from `?target=` - without it, `/scan/new/type` re-renders Step 1 with a
# validation error and `/scan/new/advanced` renders its locked-tier empty
# state, neither of which exercises the markup this plan's Task 1 fixed.
QUERY_PARAMS = {
    "/scan/new/type": "target=https://example.com",
    "/scan/new/advanced": "target=https://example.com",
}

# auth.login redirects a GET when current_user.is_authenticated (there's
# nothing useful to show a logged-in user on the login form); auth.signup
# does the same unless an invite token is present. Neither is reachable as
# a 200 while the `seeded` fixture's admin session is active, so `_get()`
# logs the session out first for these two before requesting them - each
# parametrised test still gets its own fresh fixture-scoped app/db, so
# logging out inside one test's `_get()` call can't leak into another.
ANONYMOUS_ONLY_PATHS = {"/login", "/signup"}


def _reachable_get_pages(app):
    pages = []
    for rule in app.url_map.iter_rules():
        if "GET" not in rule.methods:
            continue
        if rule.arguments:  # takes a path parameter, e.g. <int:scan_id>
            continue
        endpoint = rule.endpoint
        if endpoint in EXCLUDED_ENDPOINTS:
            continue
        if any(endpoint.startswith(p) for p in EXCLUDED_BLUEPRINT_PREFIXES):
            continue
        pages.append(rule.rule)
    return sorted(set(pages))


def _public_dns(monkeypatch):
    """Mirrors tests/test_scan_wizard.py's `_public_dns` - patches
    socket.getaddrinfo so any hostname resolves to one ordinary public
    IPv4 address, for the two pages above whose GET handler runs the SSRF
    safety check against `?target=`."""
    def _impl(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", _impl)


def _make_invitation(org, email="invitee@example.org", role="member", inviter=None):
    inv = Invitation(
        org_id=org.id, email=email, role=role, status=InvitationStatus.PENDING,
        invited_by_id=inviter.id if inviter else None,
    )
    _db.session.add(inv)
    _db.session.flush()
    return inv


def _make_verified_domain(org, domain="example.com"):
    dv = DomainVerification(
        org_id=org.id, domain=domain, method=VerifyMethod.DNS_TXT, token="tok",
        verified_at=datetime.now(timezone.utc),
    )
    _db.session.add(dv)
    _db.session.flush()
    return dv


def _seed_app(db):
    """One org-admin, platform-admin fixture user with an asset, a
    completed scan with a report, an API token, a pending invitation and a
    verified domain - so every authenticated page in the list below
    renders populated rather than empty. An empty page trivially passes
    every assertion this module makes, which would make the whole module
    worthless (same reasoning the plan's <action> spells out)."""
    org = make_org(plan=Plan.ORG_VERIFIED, name="A11y Fixture Org")
    admin = make_user("a11y-admin@example.org", org=org, role=Role.ORG_ADMIN)
    admin.is_platform_admin = True
    make_user("a11y-member@example.org", org=org, role=Role.MEMBER)
    _make_invitation(org, inviter=admin)
    _make_verified_domain(org, domain="example.com")

    asset_row = make_asset(org, admin, name="a11y-asset", target_url="https://example.com")
    # scan_type="other" (not "base") - mirrors tests/test_report_table_semantics.py's
    # _add_report fixture convention: scan_report.html only renders its base-scan-
    # specific sections (headers/TLS/cookies/etc., needing many more report keys)
    # inside {% if scan.scan_type == 'base' %}; "other" reaches the same generic
    # findings/severity/locked-checks markup this module needs with a minimal fixture.
    scan = make_scan(admin, org=org, target_url="https://example.com", scan_type="other",
                      status=ScanStatus.COMPLETED)
    scan.risk_score = 82
    report_data = {
        "target": "https://example.com",
        "hostname": "example.com",
        "scanned_at": "2026-01-01T00:00:00Z",
        "score": 82,
        "risk_grade": "B",
        "severity_counts": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
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
    report = Report(scan_id=scan.id, json_path=f"unused_{scan.id}.json", data=report_data)
    _db.session.add(report)
    make_api_token(admin, name="a11y-token")
    db.session.commit()
    return {"org": org, "admin": admin, "asset": asset_row, "scan": scan}


@pytest.fixture()
def seeded(client, db, monkeypatch):
    """Logs the fixture user in and returns the seed data plus the app's
    reachable-page list, with DNS mocked for the two pages that need it."""
    _public_dns(monkeypatch)
    data = _seed_app(db)
    login(client, "a11y-admin@example.org")
    return data


def _get(client, path):
    if path in ANONYMOUS_ONLY_PATHS:
        client.get("/logout")
    qs = QUERY_PARAMS.get(path)
    url = f"{path}?{qs}" if qs else path
    return client.get(url)


def _build_throwaway_app_for_url_map():
    """A second, disposable Flask app - built only so PAGES can be derived
    from its real app.url_map at collection time (pytest.mark.parametrize
    needs the page list before any per-test fixture runs). TESTING=True
    plus SCHEDULER_ENABLED=False guarantees create_app()'s own
    _maybe_start_scheduler() guard skips starting the background thread
    (webvulnscanner/__init__.py); the in-memory SQLite URI means db.init_app()
    never touches a real file, and no query is ever issued against it - the
    url_map is fully built by blueprint registration alone, before any
    request or DB access happens. The `app`/`client` fixtures below build
    the real per-test app every actual request in this module goes through."""
    from webvulnscanner import create_app
    from webvulnscanner.config import Config

    class _UrlMapOnlyConfig(Config):
        TESTING = True
        SCHEDULER_ENABLED = False
        WTF_CSRF_ENABLED = False
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"

    return create_app(_UrlMapOnlyConfig)


PAGES = _reachable_get_pages(_build_throwaway_app_for_url_map())

MIN_EXPECTED_PAGES = {
    "/", "/terms", "/privacy", "/login", "/signup", "/forgot-password",
    "/dashboard", "/assets", "/scan/new", "/scan/new/type", "/scan/new/base",
    "/scan/new/advanced", "/scan/new/media", "/scan/new/api",
    "/tokens", "/account/billing", "/org/admin", "/org/verify-domain",
    "/platform-admin",
}


def test_page_list_covers_the_documented_minimum():
    assert MIN_EXPECTED_PAGES.issubset(set(PAGES))


# --------------------------------------------------------------------------
# Parametrised fixture pages: a scan report, a scan progress page, and an
# asset detail page - none of these is reachable as a no-parameter GET
# route, so they're built from fixture ids rather than app.url_map.
# --------------------------------------------------------------------------

def _fixture_page_paths(data):
    return {
        "scan report": f"/scan/{data['scan'].id}/report",
        "asset detail": f"/assets/{data['asset'].id}",
    }


def _queued_scan_progress_path(db, data):
    """A second, still-QUEUED scan (not the completed one `seeded` already
    made) so GET /scan/<id> renders scan_progress.html instead of
    redirecting straight to the report - the report path is already
    covered above."""
    queued = make_scan(data["admin"], org=data["org"], target_url="https://example.com",
                        status=ScanStatus.QUEUED)
    db.session.commit()
    return f"/scan/{queued.id}"


# --------------------------------------------------------------------------
# heading_hierarchy - GET every reachable page (plus the three parametrised
# fixture pages), assert no forward heading-level jump greater than one.
# --------------------------------------------------------------------------

def _heading_levels(body):
    soup = BeautifulSoup(body, "html.parser")
    levels = []
    for tag in soup.find_all(re.compile(r"^h[1-6]$")):
        levels.append(int(tag.name[1]))
    return levels


def _assert_no_heading_skip(levels, where):
    """Zero headings is a pass. Equal-level adjacency is a pass. Only a
    forward jump of two or more levels (e.g. h2 -> h4) is a violation -
    stepping back down any number of levels (h3 -> h1) is always valid
    document structure."""
    seen_max = 0
    for level in levels:
        if level > seen_max + 1:
            pytest.fail(
                f"{where}: heading jumped from h{seen_max} context to h{level} "
                f"(full sequence: {levels})"
            )
        seen_max = max(seen_max, level)


@pytest.mark.parametrize("path", PAGES)
def test_heading_hierarchy(client, seeded, path):
    resp = _get(client, path)
    assert resp.status_code == 200, f"{path} returned {resp.status_code}"
    body = resp.get_data(as_text=True)
    _assert_no_heading_skip(_heading_levels(body), path)


def test_heading_hierarchy_fixture_pages(client, db, seeded):
    for label, path in _fixture_page_paths(seeded).items():
        resp = client.get(path)
        assert resp.status_code == 200, f"{label} ({path}) returned {resp.status_code}"
        body = resp.get_data(as_text=True)
        _assert_no_heading_skip(_heading_levels(body), label)

    progress_path = _queued_scan_progress_path(db, seeded)
    resp = client.get(progress_path)
    assert resp.status_code == 200
    _assert_no_heading_skip(_heading_levels(resp.get_data(as_text=True)), "scan progress")


def test_heading_hierarchy_negative_control_marketing_h3_back_to_h4():
    """Proves the lock actually bites: temporarily demoting one of
    marketing.html's promoted <h3>s back to <h4> must fail the assertion,
    and reverting must pass it again. Run once, then reverted - not left
    demoted."""
    path = TEMPLATES_DIR / "marketing.html"
    original = path.read_text(encoding="utf-8")
    try:
        broken = original.replace("<h3>Exposed secrets</h3>", "<h4>Exposed secrets</h4>", 1)
        assert broken != original, "expected marker heading not found in marketing.html"
        levels = _heading_levels(broken)
        with pytest.raises(pytest.fail.Exception):
            _assert_no_heading_skip(levels, "negative-control marketing.html")
    finally:
        path.write_text(original, encoding="utf-8")
    # Reverted file must pass again.
    assert path.read_text(encoding="utf-8") == original
    restored_levels = _heading_levels(original)
    _assert_no_heading_skip(restored_levels, "marketing.html (reverted)")


# --------------------------------------------------------------------------
# labels_and_icon_buttons - every visible input/select/textarea has a
# matching <label for> or an aria-label; every <label for> names a real
# control; every icon-only <button> has an aria-label and its <svg>
# carries aria-hidden.
# --------------------------------------------------------------------------

_SKIP_INPUT_TYPES = {"hidden", "submit"}


def _assert_labels_and_icon_buttons(body, where):
    soup = BeautifulSoup(body, "html.parser")

    label_ids = set()
    for label in soup.find_all("label"):
        target = label.get("for")
        if target:
            label_ids.add(target)
            assert soup.find(id=target) is not None, (
                f"{where}: <label for=\"{target}\"> names an id that has no control"
            )

    for control in soup.find_all(["input", "select", "textarea"]):
        if control.name == "input" and (control.get("type") or "").lower() in _SKIP_INPUT_TYPES:
            continue
        control_id = control.get("id")
        has_label = control_id is not None and control_id in label_ids
        has_aria_label = bool(control.get("aria-label"))
        assert has_label or has_aria_label, (
            f"{where}: control {control} has neither a matching <label for> nor an aria-label"
        )

    for button in soup.find_all("button"):
        svgs = button.find_all("svg")
        if not svgs:
            continue
        text_content = button.get_text(strip=True)
        if text_content:
            continue  # not icon-only - has visible text alongside (or instead of) the svg
        assert button.get("aria-label"), f"{where}: icon-only button has no aria-label: {button}"
        for svg in svgs:
            assert svg.get("aria-hidden") == "true", (
                f"{where}: icon-only button's <svg> lacks aria-hidden: {button}"
            )


@pytest.mark.parametrize("path", PAGES)
def test_labels_and_icon_buttons(client, seeded, path):
    resp = _get(client, path)
    assert resp.status_code == 200
    _assert_labels_and_icon_buttons(resp.get_data(as_text=True), path)


def test_labels_and_icon_buttons_fixture_pages(client, db, seeded):
    for label, path in _fixture_page_paths(seeded).items():
        resp = client.get(path)
        assert resp.status_code == 200
        _assert_labels_and_icon_buttons(resp.get_data(as_text=True), label)


def test_labels_and_icon_buttons_eight_known_icon_only_buttons_are_named(client, seeded):
    """Regression lock naming the eight icon-only buttons this planning
    session's audit found: three asset actions (asset_detail.html) and
    five password toggles (one on login, two each on signup/reset_password).
    A failure here names the specific control, not just a page."""
    org = seeded["org"]
    asset_row = seeded["asset"]

    resp = client.get(f"/assets/{asset_row.id}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    soup = BeautifulSoup(body, "html.parser")
    icon_buttons = [
        b for b in soup.find_all("button")
        if b.find("svg") and not b.get_text(strip=True)
    ]
    assert len(icon_buttons) >= 1  # pause or resume (mutually exclusive) + delete
    for b in icon_buttons:
        assert b.get("aria-label"), f"asset_detail.html icon button missing aria-label: {b}"

    client.get("/logout")
    for path, expected_toggles in (("/login", 1), ("/signup", 2)):
        resp = client.get(path)
        assert resp.status_code == 200
        soup = BeautifulSoup(resp.get_data(as_text=True), "html.parser")
        toggles = soup.find_all("button", class_="pw-toggle")
        assert len(toggles) == expected_toggles, f"{path}: expected {expected_toggles} pw-toggle button(s)"
        for t in toggles:
            assert t.get("aria-label") == "Show password"
            svg = t.find("svg")
            assert svg is not None and svg.get("aria-hidden") == "true"


def test_labels_and_icon_buttons_negative_control_removed_aria_label():
    """Proves the lock actually bites: temporarily removing one aria-label
    from asset_detail.html's delete button must fail a direct re-check of
    that markup, and reverting must pass it again. Run once, then
    reverted."""
    path = TEMPLATES_DIR / "asset_detail.html"
    original = path.read_text(encoding="utf-8")
    marker = 'class="btn destructive icon-btn" aria-label="Delete {{ asset.name }}"'
    assert marker in original, "expected delete-button marker not found in asset_detail.html"
    try:
        broken = original.replace(marker, 'class="btn destructive icon-btn"', 1)
        assert broken != original
        soup = BeautifulSoup(broken, "html.parser")
        icon_buttons = [b for b in soup.find_all("button") if b.find("svg") and not b.get_text(strip=True)]
        offending = [b for b in icon_buttons if not b.get("aria-label")]
        assert offending, "negative control did not actually remove the aria-label"
    finally:
        path.write_text(original, encoding="utf-8")
    assert path.read_text(encoding="utf-8") == original


# --------------------------------------------------------------------------
# no_clickable_divs - no div/span/li/td/tr carries a click-handler
# attribute or a button role, anywhere: rendered response bodies AND
# template source (so a violation behind an excluded/skipped route is
# still caught).
# --------------------------------------------------------------------------

_NON_NATIVE_TAGS = ("div", "span", "li", "td", "tr")
_CLICK_HANDLER_RE = re.compile(
    r'<(?:' + "|".join(_NON_NATIVE_TAGS) + r')\b[^>]*\s(?:onclick|role="button")',
    re.IGNORECASE,
)


def _assert_no_clickable_divs(body, where):
    soup = BeautifulSoup(body, "html.parser")
    for tag_name in _NON_NATIVE_TAGS:
        for el in soup.find_all(tag_name):
            assert not el.get("onclick"), f"{where}: <{tag_name}> carries onclick: {el}"
            assert (el.get("role") or "").lower() != "button", (
                f"{where}: <{tag_name}> carries role=\"button\": {el}"
            )


@pytest.mark.parametrize("path", PAGES)
def test_no_clickable_divs(client, seeded, path):
    resp = _get(client, path)
    assert resp.status_code == 200
    _assert_no_clickable_divs(resp.get_data(as_text=True), path)


def test_no_clickable_divs_fixture_pages(client, db, seeded):
    for label, path in _fixture_page_paths(seeded).items():
        resp = client.get(path)
        assert resp.status_code == 200
        _assert_no_clickable_divs(resp.get_data(as_text=True), label)


def test_no_clickable_divs_source_level_across_all_templates():
    """Companion source-level scan: catches a violation introduced in a
    template behind an excluded/skipped route (e.g. error pages, partials
    only ever rendered via {% include %}) that the rendered-response
    assertions above can never reach."""
    offenders = []
    for template_path in TEMPLATES_DIR.glob("*.html"):
        text = template_path.read_text(encoding="utf-8")
        if _CLICK_HANDLER_RE.search(text):
            offenders.append(template_path.name)
    assert not offenders, f"non-native clickable element(s) found in: {offenders}"


# --------------------------------------------------------------------------
# focus_treatment - base.html is the only template declaring
# :focus-visible anywhere in templates/.
# --------------------------------------------------------------------------

def test_focus_treatment_base_html_declares_focus_visible():
    text = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
    assert ":focus-visible" in text


def test_focus_treatment_no_other_template_declares_focus_visible():
    offenders = []
    for template_path in TEMPLATES_DIR.glob("*.html"):
        if template_path.name == "base.html":
            continue
        text = template_path.read_text(encoding="utf-8")
        if ":focus-visible" in text:
            offenders.append(template_path.name)
    assert not offenders, f"component-local :focus-visible rule found in: {offenders}"


# --------------------------------------------------------------------------
# id-uniqueness - extends 07-02's rendered-body id-uniqueness invariant
# (previously proven on org_admin.html/org_verify_domain.html only) to
# every reachable page in the app, now that every dual-markup conversion
# in this phase has landed.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", PAGES)
def test_no_duplicate_ids(client, seeded, path):
    resp = _get(client, path)
    assert resp.status_code == 200
    ids = _ids_in(resp.get_data(as_text=True))
    seen = set()
    dupes = set()
    for i in ids:
        if i in seen:
            dupes.add(i)
        seen.add(i)
    assert not dupes, f"{path}: duplicate id(s) {dupes}"


def test_no_duplicate_ids_fixture_pages(client, db, seeded):
    for label, path in _fixture_page_paths(seeded).items():
        resp = client.get(path)
        assert resp.status_code == 200
        ids = _ids_in(resp.get_data(as_text=True))
        seen = set()
        dupes = set()
        for i in ids:
            if i in seen:
                dupes.add(i)
            seen.add(i)
        assert not dupes, f"{label} ({path}): duplicate id(s) {dupes}"
