"""
Tests for glassbox/api_docs.py + docs_route.py (Phase 22, DOCS-01..05).

The theme of this file is that the /docs/api page cannot silently drift from
reality. Three independent locks:

- DOCS-01: every /api/v1 rule in the live url_map must appear in
  API_ENDPOINTS with exactly matching methods, AND vice versa - a new API
  endpoint without a spec entry fails this test BY NAME, as does a documented
  path whose route was renamed or deleted.
- DOCS-03: WEBHOOK_VERIFY_SNIPPET is exec()ed and behaviorally compared
  against webhooks.sign_payload for sample inputs (both directions), so the
  copy-pasteable receiver example can never disagree with the real signer.
- DOCS-04: CLI_SUBCOMMANDS must equal the set of `glassbox <cmd>` invocation
  lines in cli/README.md, so a new CLI command forces both surfaces to move.

Plus DOCS-05's page-level contract: /docs/api is login-required (302 anon,
never JSON) and renders the spec content for a logged-in user.
"""
import re
from pathlib import Path

import pytest

from glassbox.api_docs import (
    API_ENDPOINTS,
    CLI_SUBCOMMANDS,
    WEBHOOK_VERIFY_SNIPPET,
)
from glassbox.webhooks import sign_payload
from tests.conftest import login, make_org, make_user

REPO_ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------
# DOCS-01: url_map <-> spec bidirectional lock
# --------------------------------------------------------------------------

def _api_v1_rules(app):
    """Every live rule under /api/v1, excluding Flask's static endpoint."""
    return {
        rule.rule: {m for m in rule.methods if m not in ("HEAD", "OPTIONS")}
        for rule in app.url_map.iter_rules()
        if rule.rule.startswith("/api/v1") and rule.endpoint != "static"
    }


def test_every_api_v1_route_is_documented_with_matching_methods(app):
    live = _api_v1_rules(app)
    assert live, "no /api/v1 routes found - the scan itself is broken"

    spec = {ep["path"]: set(ep["methods"]) for ep in API_ENDPOINTS}

    undocumented = sorted(set(live) - set(spec))
    stale = sorted(set(spec) - set(live))
    method_drift = {
        path: {"spec": sorted(spec[path]), "live": sorted(methods)}
        for path, methods in live.items()
        if path in spec and spec[path] != methods
    }
    assert not undocumented, (
        f"/api/v1 route(s) exist but have no API_ENDPOINTS entry in "
        f"glassbox/api_docs.py - add one so /docs/api stays complete: "
        f"{undocumented}"
    )
    assert not stale, (
        f"API_ENDPOINTS document(s) path(s) that no longer exist in the "
        f"url_map - remove or update them: {stale}"
    )
    assert not method_drift, f"documented methods drifted from live routes: {method_drift}"


def test_spec_entries_have_renderable_fields():
    """Each entry carries everything api_docs.html reads - catches a typo'd
    key at test time instead of an empty cell on the rendered page."""
    for ep in API_ENDPOINTS:
        assert ep["methods"], f"{ep['path']}: no methods"
        assert all(m in ("GET", "POST", "PUT", "DELETE") for m in ep["methods"])
        for field in ("group", "summary", "auth", "rate_limit"):
            assert ep[field], f"{ep['path']}: missing {field}"


# --------------------------------------------------------------------------
# DOCS-03: webhook snippet is behaviorally identical to the real signer
# --------------------------------------------------------------------------

def _exec_snippet():
    namespace: dict = {}
    exec(WEBHOOK_VERIFY_SNIPPET, namespace)  # noqa: S102 - repo-owned constant
    return namespace["verify_signature"]


@pytest.mark.parametrize(
    "secret,body",
    [
        ("secret-a", b'{"event":"scan.completed"}'),
        ("unicode-secret-\u00e9", b"x"),
        ("k" * 64, b""),
    ],
)
def test_webhook_snippet_agrees_with_real_signer(secret, body):
    verify_snippet = _exec_snippet()

    real_header = sign_payload(secret, body)
    # Positive: the snippet accepts what the real signer produced.
    assert verify_snippet(secret, body, real_header) is True

    # Negative: tampered body / wrong secret / wrong scheme must be rejected.
    assert verify_snippet(secret, body + b"x", real_header) is False
    assert verify_snippet("other-secret", body, real_header) is False
    assert (
        verify_snippet(
            secret,
            body,
            real_header.replace("sha256=", "md5="),
        )
        is False
    )


def test_webhook_snippet_uses_constant_time_compare():
    """A receiver-side check that used == instead of hmac.compare_digest would
    be timing-leaky - the shipped snippet must model the right habit."""
    assert "compare_digest" in WEBHOOK_VERIFY_SNIPPET
    # And it must hash the raw body bytes, not a re-serialized dict.
    assert "raw_body" in WEBHOOK_VERIFY_SNIPPET


# --------------------------------------------------------------------------
# DOCS-04: CLI section stays in sync with cli/README.md
# --------------------------------------------------------------------------

def test_cli_subcommands_match_readme():
    readme = (REPO_ROOT / "cli" / "README.md").read_text(encoding="utf-8")
    # Every indented `glassbox <cmd>` invocation line in the README.
    in_readme = set(re.findall(r"^\s+glassbox\s+([a-z]+)", readme, flags=re.MULTILINE))
    assert in_readme, "no glassbox command lines found in cli/README.md - parse broken"

    in_spec = set(CLI_SUBCOMMANDS)

    missing_from_docs = sorted(in_readme - in_spec)
    phantom_in_docs = sorted(in_spec - in_readme)
    assert not missing_from_docs and not phantom_in_docs, (
        "the /docs/api CLI quickstart and cli/README.md disagree - "
        f"commands only in README: {missing_from_docs}; "
        f"commands only in the docs spec: {phantom_in_docs}. "
        "Update glassbox/api_docs.py's CLI_SUBCOMMANDS and/or the README "
        "so both surfaces move together."
    )


# --------------------------------------------------------------------------
# DOCS-05: login gate + render
# --------------------------------------------------------------------------

def test_api_docs_page_requires_login(client):
    resp = client.get("/docs/api")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_api_docs_page_renders_spec_for_logged_in_user(client, db):
    org = make_org(name="Docs Org")
    make_user("docs@example.com", org=org)
    db.session.commit()

    assert login(client, "docs@example.com").status_code == 200
    resp = client.get("/docs/api")

    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    # Every documented endpoint's path appears on the page. Flask rule
    # arguments (<int:scan_id>) are autoescaped by Jinja like any other
    # content - compare against that exact rendered form.
    for ep in API_ENDPOINTS:
        rendered_path = (
            ep["path"].replace("<", "&lt;").replace(">", "&gt;")
        )
        assert rendered_path in html, f"{ep['path']} missing from rendered docs"
    # Auth + webhook sections present, and the logged-in nav rendered.
    assert "X-Glassbox-Signature" in html
    assert "verify_signature" in html
    assert "/logout" in html


def test_nav_link_present_for_logged_in_users(client, db):
    org = make_org(name="Nav Org")
    make_user("nav@example.com", org=org)
    db.session.commit()

    assert login(client, "nav@example.com")
    base = client.get("/dashboard").get_data(as_text=True)
    assert 'href="/docs/api"' in base
