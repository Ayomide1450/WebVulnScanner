"""
Live dev-server probe for Phase 8 (D-01/D-02, plan 08-07).

WHAT THIS TARGETS: this app's OWN local routes and auth boundaries only -
never a third-party host. CONTEXT.md D-01 draws this line explicitly against
CLAUDE.md's authorized-use constraint: that constraint governs scanning
*someone else's* infrastructure (`checks.py`'s scan pipelines, gated by the
`authorized*` checkboxes and `is_ssrf_safe_hostname()`), not this app testing
its own auth logic against itself. This script never submits a scan against
any external target - it only fires cross-org IDOR and CSRF-bypass attempts
at this application's own routes, over real HTTP, against a real running
`python app.py` process.

WHY THIS EXISTS ALONGSIDE THE TEST SUITE (D-02): Flask's test client shares
a process, a session interface and an import graph with the app under test -
it short-circuits the WSGI layer, real cookie handling, and real
Origin/Referer processing. Those are exactly the layers a cross-origin CSRF
attempt and a raw cross-org request actually traverse. This script
SUPPLEMENTS the automated suite, it never REPLACES it: every case below
carries the name of the Flask-test-client regression test that already
covers the same behavior (see CASES's `covering_test` field, and
tests/test_live_probe_script.py's static lock proving every one of those
named tests actually exists on disk). If this script is never run again,
the guarantee still holds through the covering tests.

OPERATOR SEQUENCE (also see 08-07-PLAN.md Task 2's checkpoint text):

  1. Seed a disposable database (creates a throwaway SQLite file under your
     OS temp directory, seeds two throwaway orgs, prints their ids/creds):

       set FLASK_SKIP_DOTENV=1
       set SESSION_COOKIE_SECURE=false
       set ALLOW_INSECURE_DEV_SECRET_KEY=true
       .venv\\Scripts\\python scripts\\live_probe_phase8.py --seed

     Confirm the printed database path is a temporary file, NOT
     webvulnscanner.db. If it is not, stop - the guardrail failed and that
     is itself a finding.

  2. In a SECOND shell, with the SAME three env vars set plus the
     SQLALCHEMY_DATABASE_URI this script just printed, start the app
     against that same disposable database:

       set FLASK_SKIP_DOTENV=1
       set SESSION_COOKIE_SECURE=false
       set ALLOW_INSECURE_DEV_SECRET_KEY=true
       set SQLALCHEMY_DATABASE_URI=<the value --seed printed>
       .venv\\Scripts\\python app.py

     Confirm it starts on http://127.0.0.1:5000 and that
     http://127.0.0.1:5000/healthz returns ok.

  3. Back in the first shell, run the probe:

       .venv\\Scripts\\python scripts\\live_probe_phase8.py --probe --base-url http://127.0.0.1:5000

  4. Read the printed per-case table (case name, route, expected outcome,
     observed status, pass/fail, covering test) and the exit code. Exit 0
     means every case behaved as expected; exit 1 lists the failing case(s)
     first.

  5. Stop the app and delete the disposable database file.

SESSION_COOKIE_SECURE=false IS REQUIRED for a plain-http local server -
session/remember cookies default to Secure, so `requests` (like a real
browser) will never send the session cookie back over plain http without
this. Without it, every single case would read as "refused" for entirely
the wrong reason (an unsent cookie, not an enforced guard) - this script
guards against that specific false pass by verifying it is actually
authenticated (verify_authenticated()) before running any case at all, and
aborting with a clear message if not.

Callable functions this module exposes (also usable directly from a REPL or
tests/test_live_probe_script.py, which locks what's checkable without a
running server): the guardrails (assert_loopback_base_url,
assert_db_uri_is_self_created, assert_flask_skip_dotenv_set), the seeder
(seed_disposable_database), and the prober (run_probe). See the __main__
guard at the bottom for the --seed/--probe CLI entry point.
"""
import argparse
import ipaddress
import json
import os
import socket
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

PROBE_DB_MARKER = "webvulnscanner_live_probe_phase8"
PROBE_PASSWORD = "ProbePhase8Pass!1"
# base.html's nav renders this exact link for every authenticated page -
# see templates/base.html's "Logout" <a> tag. Used by verify_authenticated()
# as the "definitely-logged-in" marker, distinct from a login-page redirect
# (which would never contain a link to /logout).
AUTH_MARKER_TEXT = 'href="/logout"'


class ProbeRefused(Exception):
    """Raised by a guardrail this script refuses to bypass. The __main__
    entry point catches this exactly once, prints the reason, and exits
    non-zero - never a silent pass-through past a failed guardrail."""


# ---------------------------------------------------------------------------
# Guardrails - hard refusals, never warnings (08-07-PLAN.md's explicit
# instruction). Each is a small, pure-ish function so
# tests/test_live_probe_script.py can call it directly with a synthetic bad
# value, with no running server and no real database involved.
# ---------------------------------------------------------------------------


def probe_db_path():
    """The one disposable SQLite path this script will ever create or
    accept - always inside the OS temp directory, named with an
    unambiguous marker so a human glancing at printed output immediately
    recognizes it as disposable and never mistakes it for
    webvulnscanner.db."""
    return Path(tempfile.gettempdir()) / f"{PROBE_DB_MARKER}.db"


def probe_db_uri():
    # Matches this app's own existing convention (config.py's default URI,
    # tests/conftest.py's per-test fixture) of an unmodified str(Path) -
    # SQLAlchemy's sqlite dialect accepts Windows backslash paths natively,
    # no forward-slash normalization needed.
    return f"sqlite:///{probe_db_path()}"


def probe_ids_path():
    """Where seed_disposable_database() writes the seeded org/user/object
    ids (and the raw API-token/password values a probe run needs) so a
    separate `--probe` invocation - and the separately-started `python
    app.py` process in between - can all agree on the same disposable
    world without re-seeding it."""
    return Path(tempfile.gettempdir()) / f"{PROBE_DB_MARKER}_ids.json"


def assert_loopback_base_url(base_url):
    """Refuses a non-loopback base URL. This script only ever probes the
    app's own locally-running instance - CONTEXT.md D-01 draws this line
    explicitly against CLAUDE.md's authorized-use constraint, which governs
    scanning someone else's infrastructure, not this app's own auth logic
    tested against itself. Returns the parsed hostname on success."""
    hostname = urlparse(base_url).hostname
    if not hostname:
        raise ProbeRefused(
            f"could not parse a hostname out of base URL {base_url!r} - use e.g. "
            f"http://127.0.0.1:5000"
        )
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ProbeRefused(
            f"could not resolve hostname {hostname!r}: {exc}. Refusing to probe an "
            f"unresolvable host rather than guessing what it might be."
        ) from exc
    for _family, _type, _proto, _canonname, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if not ip.is_loopback:
            raise ProbeRefused(
                f"base URL {base_url!r} resolves to {ip}, which is not a loopback "
                f"address. This script only probes the app's own locally-running "
                f"instance - never a non-local host (see this module's docstring: "
                f"CONTEXT.md D-01 draws this line explicitly against CLAUDE.md's "
                f"authorized-use constraint). Use http://127.0.0.1:5000 or "
                f"http://localhost:5000."
            )
    return hostname


def assert_db_uri_is_self_created(uri):
    """Refuses a database URI this script did not itself generate -
    compared against the exact value probe_db_uri() returns, so pointing
    this at webvulnscanner.db (by a stray env var, a copy-pasted config, or
    any other means) is structurally impossible, not merely discouraged."""
    expected = probe_db_uri()
    if uri != expected:
        raise ProbeRefused(
            f"database URI {uri!r} is not the disposable file this script creates "
            f"itself ({expected!r}). This guardrail exists because a careless run "
            f"can otherwise end up pointed at your real webvulnscanner.db - see "
            f"CLAUDE.md's FLASK_SKIP_DOTENV warning and 08-RESEARCH.md's Open "
            f"Question 2. Do not set SQLALCHEMY_DATABASE_URI yourself before "
            f"--seed; this script manages its own disposable file and prints the "
            f"exact value to use afterward."
        )


def assert_flask_skip_dotenv_set():
    """Refuses to seed unless FLASK_SKIP_DOTENV is set truthy. Without it,
    a careless run risks the surrounding tooling picking up a real .env and
    ending up pointed at a shared/real database (CLAUDE.md's documented
    worktree warning, echoed in .planning/STATE.md's Blockers/Concerns)."""
    value = os.environ.get("FLASK_SKIP_DOTENV", "").strip().lower()
    if value not in ("1", "true", "yes"):
        raise ProbeRefused(
            "FLASK_SKIP_DOTENV is not set. Set FLASK_SKIP_DOTENV=1 before running "
            "--seed - see CLAUDE.md's documented worktree warning about the Flask "
            "CLI's dotenv loading, and this module's own docstring for the full "
            "operator sequence."
        )


# ---------------------------------------------------------------------------
# Seeder - creates the disposable database, applies the schema directly
# (db.create_all(), same convention tests/conftest.py's `app` fixture uses
# for a throwaway per-run DB, not a real Alembic migration replay), and
# seeds two orgs (A/B) each with an ORG_ADMIN, a MEMBER, a scan, an asset, a
# pending invoice, a pending invitation, and an API token.
# ---------------------------------------------------------------------------


def seed_disposable_database():
    """Refuses to run (raises ProbeRefused) unless every guardrail passes:
    FLASK_SKIP_DOTENV is set, and if SQLALCHEMY_DATABASE_URI is already set
    in the environment, it must equal the disposable path this script
    itself would create. Returns the seeded-ids dict (also written to
    probe_ids_path() for a later --probe invocation to read)."""
    assert_flask_skip_dotenv_set()
    existing_uri = os.environ.get("SQLALCHEMY_DATABASE_URI")
    if existing_uri:
        assert_db_uri_is_self_created(existing_uri)

    uri = probe_db_uri()
    db_path = probe_db_path()
    if db_path.exists():
        db_path.unlink()  # always seed fresh, never append to a stale prior run

    os.environ["SQLALCHEMY_DATABASE_URI"] = uri
    os.environ.setdefault("SESSION_COOKIE_SECURE", "false")
    os.environ.setdefault("ALLOW_INSECURE_DEV_SECRET_KEY", "true")

    from webvulnscanner import create_app
    from webvulnscanner.config import Config

    class _ProbeConfig(Config):
        SQLALCHEMY_DATABASE_URI = uri
        TESTING = False
        SCHEDULER_ENABLED = False

    app = create_app(_ProbeConfig)
    with app.app_context():
        from webvulnscanner.extensions import db as _db

        _db.create_all()
        ids = _seed_two_orgs(_db)

    save_seed_ids(ids)
    return ids


def _seed_two_orgs(_db):
    import hashlib
    import secrets

    from werkzeug.security import generate_password_hash

    from webvulnscanner.models import (
        ApiToken,
        Asset,
        CryptoInvoice,
        InvoiceStatus,
        Invitation,
        InvitationStatus,
        Organization,
        Plan,
        Role,
        Scan,
        ScanStatus,
        User,
    )

    def _bundle(label):
        org = Organization(name=f"Live Probe Org {label}", plan=Plan.PAID)
        _db.session.add(org)
        _db.session.flush()

        admin = User(
            email=f"probe-admin-{label.lower()}@example.com",
            password_hash=generate_password_hash(PROBE_PASSWORD),
            org_id=org.id, role=Role.ORG_ADMIN,
            email_verified_at=datetime.now(timezone.utc),
        )
        member = User(
            email=f"probe-member-{label.lower()}@example.com",
            password_hash=generate_password_hash(PROBE_PASSWORD),
            org_id=org.id, role=Role.MEMBER,
            email_verified_at=datetime.now(timezone.utc),
        )
        _db.session.add_all([admin, member])
        _db.session.flush()

        scan = Scan(
            user_id=admin.id, org_id=org.id,
            target_url="https://example.com", scan_type="base",
            status=ScanStatus.COMPLETED,
        )
        _db.session.add(scan)
        _db.session.flush()

        asset = Asset(
            org_id=org.id, created_by_user_id=admin.id, authorized_by_user_id=admin.id,
            authorized_at=datetime.now(timezone.utc),
            name=f"Live Probe Asset {label}", target_url="https://example.com",
            hostname="example.com", cadence="daily", schedule_scan_type="base",
            next_run_at=datetime.now(timezone.utc),
        )
        _db.session.add(asset)
        _db.session.flush()

        invoice = CryptoInvoice(
            org_id=org.id, target_plan=Plan.PAID, billing_cycle="monthly",
            token_symbol="USDT", chain="polygon",
            receiving_address="0x" + ("1" if label == "A" else "2") * 40,
            base_usd_amount=29, unique_offset="0.000001", expected_amount="29.000001",
            status=InvoiceStatus.PENDING,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        _db.session.add(invoice)

        invitation = Invitation(
            org_id=org.id, email=f"probe-invitee-{label.lower()}@example.com",
            role=Role.MEMBER.value, status=InvitationStatus.PENDING,
            invited_by_id=admin.id,
        )
        _db.session.add(invitation)

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        api_token = ApiToken(user_id=admin.id, name="Live probe token", token_hash=token_hash)
        _db.session.add(api_token)

        _db.session.flush()

        return {
            "org_id": org.id, "org_name": org.name,
            "admin_id": admin.id, "admin_email": admin.email,
            "member_id": member.id, "member_email": member.email,
            "scan_id": scan.id, "asset_id": asset.id, "asset_name": asset.name,
            "invoice_id": invoice.id, "invitation_id": invitation.id,
            "api_token_id": api_token.id, "api_token_raw": raw_token,
        }

    org_a = _bundle("A")
    org_b = _bundle("B")
    _db.session.commit()
    return {"org_a": org_a, "org_b": org_b, "password": PROBE_PASSWORD}


def save_seed_ids(ids):
    probe_ids_path().write_text(json.dumps(ids, indent=2), encoding="utf-8")


def load_seed_ids():
    path = probe_ids_path()
    if not path.is_file():
        raise ProbeRefused(f"No seeded-ids file found at {path} - run with --seed first.")
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Case list - each case pairs a real HTTP request against this app's own
# routes with the name of the Flask-test-client regression test that
# already covers the same behavior (D-02's contract, checked statically by
# tests/test_live_probe_script.py so this mapping cannot rot).
#
# One cross-org IDOR case per REGISTRY family in tests/test_cross_org_idor.py
# (billing/api/api_tokens/asset/org/scan), the three CSRF token conditions
# (missing/wrong/valid) mirroring tests/test_csrf_enforcement.py's Task 1,
# and one foreign-Origin case - the single shape the Flask test client
# structurally cannot represent at all (this module's docstring, D-01).
# ---------------------------------------------------------------------------

CASES = [
    # --- Cross-org IDOR, one per REGISTRY family ---
    {
        "name": "billing_verify_invoice_cross_org",
        "family": "billing",
        "kind": "post_with_csrf",
        "path": "/account/billing/invoice/{org_b[invoice_id]}/verify",
        "csrf_source_path": "/account/billing",
        "data": {},
        "expected_status": 403,
        "covering_test": "tests/test_billing_routes.py::test_cross_org_verify_is_refused_and_makes_no_changes",
    },
    {
        "name": "api_trigger_scan_cross_org",
        "family": "api",
        "kind": "bearer_post",
        "path": "/api/v1/assets/{org_b[asset_id]}/scans",
        "data": {},
        "expected_status": 404,
        "covering_test": "tests/test_api_routes.py::test_trigger_scan_different_org_gets_404_no_scan_created",
    },
    {
        "name": "api_tokens_revoke_cross_user",
        "family": "api_tokens",
        "kind": "post_with_csrf",
        "path": "/tokens/{org_b[api_token_id]}/revoke",
        "csrf_source_path": "/tokens",
        "data": {},
        "expected_status": 404,
        "covering_test": "tests/test_api_tokens_routes.py::test_user_cannot_revoke_another_users_token",
    },
    {
        "name": "asset_detail_cross_org",
        "family": "asset",
        "kind": "get",
        "path": "/assets/{org_b[asset_id]}",
        "expected_status": 404,
        "covering_test": "tests/test_asset_routes.py::test_get_asset_detail_for_other_org_is_404",
    },
    {
        "name": "org_resend_invitation_cross_org",
        "family": "org",
        "kind": "post_with_csrf",
        "path": "/org/admin/invite/{org_b[invitation_id]}/resend",
        "csrf_source_path": "/org/admin",
        "data": {},
        "expected_status": 404,
        "covering_test": "tests/test_org_routes.py::test_cross_org_resend_invitation_is_404_and_leaves_invitation_and_audit_log_untouched",
    },
    {
        "name": "scan_detail_cross_org",
        "family": "scan",
        "kind": "get",
        "path": "/scan/{org_b[scan_id]}",
        "expected_status": 404,
        "covering_test": "tests/test_scan_ownership.py::test_admin_of_a_different_org_cannot_view_scan",
    },
    # --- CSRF token conditions (SEC-02), mirroring
    # tests/test_csrf_enforcement.py's Task 1 shape ---
    {
        "name": "csrf_missing_token_invite",
        "family": "org",
        "kind": "post_csrf_condition",
        "path": "/org/admin/invite",
        "token_condition": "missing",
        "data": {"email": "probe-csrf-missing@example.com", "role": "member"},
        "expected_status": 400,
        "covering_test": "tests/test_csrf_enforcement.py::test_invite_without_csrf_token_redirects_and_creates_no_row",
    },
    {
        "name": "csrf_wrong_token_invite",
        "family": "org",
        "kind": "post_csrf_condition",
        "path": "/org/admin/invite",
        "token_condition": "wrong",
        "csrf_source_path": "/org/admin",
        "data": {"email": "probe-csrf-wrong@example.com", "role": "member"},
        "expected_status": 400,
        "covering_test": "tests/test_csrf_enforcement.py::test_invite_with_wrong_csrf_token_redirects_and_creates_no_row",
    },
    {
        "name": "csrf_valid_token_invite",
        "family": "org",
        "kind": "post_csrf_condition",
        "path": "/org/admin/invite",
        "token_condition": "valid",
        "csrf_source_path": "/org/admin",
        "data": {"email": "probe-csrf-valid@example.com", "role": "member"},
        "expected_status": 302,
        "covering_test": "tests/test_csrf_enforcement.py::test_invite_with_valid_csrf_token_returns_302_and_creates_one_row",
    },
    # --- Foreign-Origin CSRF case - the one shape the Flask test client
    # structurally cannot produce (this module's docstring, D-01). ---
    {
        "name": "foreign_origin_valid_token_invite",
        "family": "org",
        "kind": "post_csrf_condition",
        "path": "/org/admin/invite",
        "token_condition": "valid",
        "csrf_source_path": "/org/admin",
        "data": {"email": "probe-foreign-origin@example.com", "role": "member"},
        "extra_headers": {"Origin": "https://evil.example.com"},
        "expected_status": 302,
        "covering_test": "tests/test_csrf_enforcement.py::test_invite_with_valid_csrf_token_returns_302_and_creates_one_row",
        "note": (
            "This app's CSRFProtect validates the submitted token only, not the "
            "Origin/Referer header (no WTF_CSRF_SSL_STRICT/Referer check is "
            "configured anywhere in webvulnscanner/) - a valid token from a real "
            "session is expected to succeed regardless of Origin. A real browser's "
            "own SameSite=Lax cookie policy (not this app) is what would actually "
            "withhold the session cookie on a genuine cross-site POST navigation; "
            "`requests` does not enforce SameSite, so this case's value is "
            "confirming the app itself has no independent Origin check to fall "
            "back on - see 08-07-PLAN.md's must_haves statement on this exact, "
            "previously-unverified question."
        ),
    },
]


# ---------------------------------------------------------------------------
# Prober - authenticates as Org A's admin over real HTTP, verifies the
# session is genuinely authenticated before running any case (the
# SESSION_COOKIE_SECURE false-pass trap this module's docstring describes),
# then runs every case in CASES and prints a per-case result table.
# ---------------------------------------------------------------------------


def _extract_csrf_token(html):
    soup = BeautifulSoup(html, "html.parser")
    field = soup.find("input", {"name": "csrf_token"})
    if field is None:
        return None
    return field.get("value")


def _mutate_token(token):
    # Same first-character-flip idiom as tests/test_csrf_enforcement.py's
    # _mutate_token: flipping the LAST character of an itsdangerous
    # signature is unreliable (base64 padding-bit slack can leave the
    # decoded bytes unchanged, ~1-in-16 of the time - see 08-02-SUMMARY.md).
    # Flipping the first character always corrupts the decoded payload.
    first = token[0]
    return ("0" if first != "0" else "1") + token[1:]


def login(session, base_url, email, password):
    get_resp = session.get(f"{base_url}/login")
    token = _extract_csrf_token(get_resp.text)
    if token is None:
        raise ProbeRefused(
            "Could not find a csrf_token input on GET /login - cannot log in. Is "
            "the app actually running at the given --base-url?"
        )
    return session.post(
        f"{base_url}/login",
        data={"email": email, "password": password, "csrf_token": token},
        allow_redirects=True,
    )


def verify_authenticated(session, base_url):
    """Requests a known-good authenticated route and asserts a 200 with an
    expected marker before any case runs. Session/remember cookies default
    to Secure, so against a plain-http local server `requests` never sends
    the cookie back at all unless SESSION_COOKIE_SECURE=false was set
    before `python app.py` started - without this check, every case would
    otherwise silently read as "refused" for entirely the wrong reason.
    Raises ProbeRefused with a clear, actionable message if the marker is
    absent."""
    resp = session.get(f"{base_url}/dashboard")
    if resp.status_code != 200 or AUTH_MARKER_TEXT not in resp.text:
        raise ProbeRefused(
            f"Authentication check failed: GET /dashboard returned "
            f"{resp.status_code} and did not contain the expected authenticated-"
            f"session marker ({AUTH_MARKER_TEXT!r}). This almost always means the "
            f"session cookie was never sent back by `requests` - set "
            f"SESSION_COOKIE_SECURE=false before starting `python app.py` (a "
            f"Secure cookie is never sent back over plain http). Aborting before "
            f"running any case, since every case would otherwise read as a false "
            f"'refused' rather than a real one."
        )


def _resolve_path(template, ids):
    return template.format(org_a=ids["org_a"], org_b=ids["org_b"])


def _run_get_case(session, base_url, case, ids):
    url = base_url + _resolve_path(case["path"], ids)
    resp = session.get(url, allow_redirects=False)
    marker = ids["org_b"].get("org_name")
    leaked = bool(marker and marker in resp.text)
    return resp.status_code, leaked


def _run_post_with_csrf_case(session, base_url, case, ids):
    csrf_page = session.get(base_url + case["csrf_source_path"])
    token = _extract_csrf_token(csrf_page.text)
    if token is None:
        raise ProbeRefused(
            f"Could not find a csrf_token input on {case['csrf_source_path']} - "
            f"cannot run case {case['name']!r}."
        )
    data = dict(case["data"])
    data["csrf_token"] = token
    url = base_url + _resolve_path(case["path"], ids)
    resp = session.post(url, data=data, allow_redirects=False)
    return resp.status_code, False


def _run_bearer_post_case(case, ids, base_url):
    token = ids["org_a"]["api_token_raw"]
    url = base_url + _resolve_path(case["path"], ids)
    resp = requests.post(
        url, data=case["data"], headers={"Authorization": f"Bearer {token}"},
        allow_redirects=False,
    )
    return resp.status_code, False


def _run_post_csrf_condition_case(session, base_url, case, ids):
    condition = case["token_condition"]
    data = dict(case["data"])
    if condition != "missing":
        csrf_page = session.get(base_url + case["csrf_source_path"])
        token = _extract_csrf_token(csrf_page.text)
        if token is None:
            raise ProbeRefused(f"Could not find a csrf_token input for case {case['name']!r}")
        if condition == "wrong":
            token = _mutate_token(token)
        data["csrf_token"] = token
    headers = case.get("extra_headers", {})
    url = base_url + _resolve_path(case["path"], ids)
    resp = session.post(url, data=data, headers=headers, allow_redirects=False)
    return resp.status_code, False


_RUNNERS = {
    "get": lambda session, base_url, case, ids: _run_get_case(session, base_url, case, ids),
    "post_with_csrf": lambda session, base_url, case, ids: _run_post_with_csrf_case(session, base_url, case, ids),
    "bearer_post": lambda session, base_url, case, ids: _run_bearer_post_case(case, ids, base_url),
    "post_csrf_condition": lambda session, base_url, case, ids: _run_post_csrf_condition_case(session, base_url, case, ids),
}


def run_case(session, base_url, case, ids):
    runner = _RUNNERS.get(case["kind"])
    if runner is None:
        raise ProbeRefused(f"Unknown case kind {case['kind']!r} for case {case['name']!r}")
    status, leaked = runner(session, base_url, case, ids)
    passed = (status == case["expected_status"]) and not leaked
    return {
        "name": case["name"],
        "route": case["path"],
        "expected": case["expected_status"],
        "observed": status,
        "leaked": leaked,
        "passed": passed,
        "covering_test": case["covering_test"],
        "note": case.get("note"),
    }


def run_probe(base_url):
    """Refuses a non-loopback base_url (assert_loopback_base_url), loads
    the ids seed_disposable_database() wrote, logs in as Org A's admin over
    real HTTP, verifies the session is genuinely authenticated
    (verify_authenticated - BEFORE any case runs), then runs every case in
    CASES. Returns (results, all_passed)."""
    assert_loopback_base_url(base_url)
    ids = load_seed_ids()

    session = requests.Session()
    login(session, base_url, ids["org_a"]["admin_email"], ids["password"])
    verify_authenticated(session, base_url)

    results = [run_case(session, base_url, case, ids) for case in CASES]
    all_passed = all(r["passed"] for r in results)
    return results, all_passed


def print_results_table(results):
    col_widths = (42, 48, 8, 8, 6)
    header = (
        f"{'CASE':{col_widths[0]}} {'ROUTE':{col_widths[1]}} "
        f"{'EXPECT':{col_widths[2]}} {'OBSERVED':{col_widths[3]}} "
        f"{'RESULT':{col_widths[4]}} COVERING TEST"
    )
    print(header)
    print("-" * len(header))
    failing = [r for r in results if not r["passed"]]
    passing = [r for r in results if r["passed"]]
    for r in failing + passing:
        status = "FAIL" if not r["passed"] else "PASS"
        leak_note = " [LEAKED ORG-B DATA]" if r["leaked"] else ""
        print(
            f"{r['name']:{col_widths[0]}} {r['route']:{col_widths[1]}} "
            f"{str(r['expected']):{col_widths[2]}} {str(r['observed']):{col_widths[3]}} "
            f"{status:{col_widths[4]}} {r['covering_test']}{leak_note}"
        )
    for r in results:
        if r["note"]:
            print(f"\n  NOTE ({r['name']}): {r['note']}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Live dev-server probe for Phase 8 (D-01/D-02). See this "
        "module's docstring for the full operator sequence.",
    )
    parser.add_argument("--seed", action="store_true", help="Create the disposable DB and seed two orgs")
    parser.add_argument("--probe", action="store_true", help="Run the probe cases against --base-url")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    return parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    if not args.seed and not args.probe:
        print(
            "Nothing to do - pass --seed or --probe. See this script's module "
            "docstring for the full operator sequence.",
            file=sys.stderr,
        )
        return 1

    try:
        if args.seed:
            ids = seed_disposable_database()
            print(f"Seeded disposable database at: {probe_db_path()}")
            print("Confirm this path is a TEMPORARY file, NOT webvulnscanner.db.")
            print()
            print("Start the app against this same database in a second shell")
            print("(same FLASK_SKIP_DOTENV=1 / SESSION_COOKIE_SECURE=false / ")
            print("ALLOW_INSECURE_DEV_SECRET_KEY=true env vars):")
            print(f"  set SQLALCHEMY_DATABASE_URI={probe_db_uri()}")
            print(r"  .venv\Scripts\python app.py")
            print()
            print(f"Org A admin: {ids['org_a']['admin_email']} / password: {ids['password']}")
            print(f"Org B admin: {ids['org_b']['admin_email']} / password: {ids['password']}")

        if args.probe:
            results, all_passed = run_probe(args.base_url)
            print_results_table(results)
            print()
            if all_passed:
                print(f"ALL {len(results)} CASE(S) PASSED.")
            else:
                failing = [r for r in results if not r["passed"]]
                print(f"{len(failing)} of {len(results)} CASE(S) FAILED - see table above.")
            return 0 if all_passed else 1
    except ProbeRefused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
