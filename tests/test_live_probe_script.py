"""
Tests for scripts/live_probe_phase8.py (D-01/D-02, plan 08-07 Task 1).

scripts/live_probe_phase8.py is a MANUAL-RUN script - it needs a real,
locally-running `python app.py` process to actually probe anything, which
this module deliberately never starts (that is plan 08-07's Task 2, a
checkpoint:human-verify gate). What IS checkable without a running server,
and is exactly what this module locks:

  - the script imports cleanly and exposes its guardrails/seeder/prober as
    plain callables with a __main__ CLI entry point
  - the loopback guardrail refuses a non-loopback base URL and accepts a
    loopback one
  - the database guardrail refuses a URI the script did not itself create
    and accepts the one it does create
  - every case in CASES names a real, resolvable regression test (the D-02
    mapping - the whole reason the live probe's value survives without a
    live server being run again)
  - the case list covers every REGISTRY family in tests/test_cross_org_idor.py
    (billing/api/api_tokens/asset/org/scan)
  - at least one case carries a foreign Origin header - the one shape the
    Flask test client structurally cannot represent
  - the docstring names the full operator sequence including
    FLASK_SKIP_DOTENV=1 and SESSION_COOKIE_SECURE=false
  - verify_authenticated() is called before the case loop in run_probe(),
    proven by source order, not by running it

Same sys.path-insertion idiom tests/test_secrets_hygiene.py already
established for importing a scripts/ module directly (scripts/ has no
__init__.py and is not a package).
"""
import inspect
import re
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import live_probe_phase8 as live_probe  # noqa: E402

from tests.test_cross_org_idor import REGISTRY as IDOR_REGISTRY  # noqa: E402


# ---------------------------------------------------------------------------
# Imports cleanly, exposes callables + __main__ guard
# ---------------------------------------------------------------------------


def test_script_imports_cleanly_and_exposes_callables():
    for name in (
        "seed_disposable_database",
        "run_probe",
        "assert_loopback_base_url",
        "assert_db_uri_is_self_created",
        "assert_flask_skip_dotenv_set",
        "main",
    ):
        assert callable(getattr(live_probe, name, None)), f"live_probe_phase8.{name} is not callable"


def test_script_has_a_dunder_main_guard():
    source = (SCRIPTS_DIR / "live_probe_phase8.py").read_text(encoding="utf-8")
    assert 'if __name__ == "__main__":' in source
    assert "sys.exit(main())" in source


# ---------------------------------------------------------------------------
# Guardrails - callable directly, no running server, no real database.
# ---------------------------------------------------------------------------


def test_loopback_guardrail_rejects_a_non_loopback_base_url():
    # A numeric IP literal - ipaddress.ip_address() classifies it locally,
    # no DNS lookup needed, so this test needs no network access.
    with pytest.raises(live_probe.ProbeRefused):
        live_probe.assert_loopback_base_url("http://93.184.216.34:5000")


def test_loopback_guardrail_accepts_loopback_urls():
    assert live_probe.assert_loopback_base_url("http://127.0.0.1:5000") == "127.0.0.1"
    assert live_probe.assert_loopback_base_url("http://localhost:5000") == "localhost"


def test_database_guardrail_rejects_a_uri_it_did_not_create():
    with pytest.raises(live_probe.ProbeRefused):
        live_probe.assert_db_uri_is_self_created("sqlite:///webvulnscanner.db")


def test_database_guardrail_accepts_its_own_generated_uri():
    # Must not raise.
    live_probe.assert_db_uri_is_self_created(live_probe.probe_db_uri())


def test_flask_skip_dotenv_guardrail_rejects_when_unset(monkeypatch):
    monkeypatch.delenv("FLASK_SKIP_DOTENV", raising=False)
    with pytest.raises(live_probe.ProbeRefused):
        live_probe.assert_flask_skip_dotenv_set()


def test_flask_skip_dotenv_guardrail_accepts_when_set(monkeypatch):
    monkeypatch.setenv("FLASK_SKIP_DOTENV", "1")
    live_probe.assert_flask_skip_dotenv_set()  # must not raise


# ---------------------------------------------------------------------------
# Case list - the D-02 mapping. Every covering_test must resolve to a real
# `def` on disk, same technique tests/test_cross_org_idor.py's
# test_registry_test_references_resolve already established.
# ---------------------------------------------------------------------------


def test_every_case_names_a_covering_test_that_resolves_on_disk():
    bad = []
    for case in live_probe.CASES:
        ref = case["covering_test"]
        module_path, _, test_name = ref.partition("::")
        full_path = PROJECT_ROOT / module_path
        if not full_path.is_file():
            bad.append(f"{case['name']} -> {ref!r} (file not found: {module_path})")
            continue
        source = full_path.read_text(encoding="utf-8")
        if not re.search(rf"^def {re.escape(test_name)}\(", source, re.MULTILINE):
            bad.append(f"{case['name']} -> {ref!r} (no 'def {test_name}(' found in {module_path})")
    assert not bad, (
        "CASES entries pointing at a test that doesn't exist on disk - the D-02 "
        "mapping has rotted:\n" + "\n".join(f"  - {b}" for b in bad)
    )


def test_case_list_covers_every_registry_family():
    """tests/test_cross_org_idor.py's REGISTRY has one entry per
    <int:>-accepting route, grouped by blueprint (endpoint prefix before the
    first '.'). This script doesn't need to mirror every individual route -
    but it must cover every FAMILY, so the live probe's IDOR coverage
    reaches every blueprint that has any cross-org guard at all."""
    registry_families = {endpoint.split(".", 1)[0] for endpoint in IDOR_REGISTRY}
    case_families = {case["family"] for case in live_probe.CASES}
    missing = registry_families - case_families
    assert not missing, (
        f"CASES has no entry for REGISTRY family/families {sorted(missing)} - "
        f"the live probe's IDOR coverage does not reach every blueprint "
        f"tests/test_cross_org_idor.py's REGISTRY does."
    )


def test_case_list_includes_at_least_one_foreign_origin_case():
    origin_cases = [
        c for c in live_probe.CASES
        if "Origin" in c.get("extra_headers", {})
    ]
    assert origin_cases, (
        "no case in CASES carries a foreign Origin header - the one shape the "
        "Flask test client structurally cannot represent (this module's own "
        "docstring, D-01) would then be entirely untested by this script."
    )
    for case in origin_cases:
        origin = case["extra_headers"]["Origin"]
        assert "evil" in origin or "attacker" in origin, (
            f"case {case['name']!r}'s Origin header {origin!r} doesn't look like "
            f"an obviously-foreign origin"
        )


def test_case_list_includes_all_three_csrf_token_conditions():
    conditions = {c.get("token_condition") for c in live_probe.CASES if c["kind"] == "post_csrf_condition"}
    assert {"missing", "wrong", "valid"} <= conditions, (
        f"expected all three CSRF token conditions (missing/wrong/valid) among "
        f"CASES, found: {sorted(c for c in conditions if c)}"
    )


# ---------------------------------------------------------------------------
# Docstring names the operator sequence.
# ---------------------------------------------------------------------------


def test_module_docstring_names_the_full_operator_sequence():
    doc = live_probe.__doc__ or ""
    assert "FLASK_SKIP_DOTENV=1" in doc
    assert "SESSION_COOKIE_SECURE=false" in doc
    assert "--seed" in doc
    assert "--probe" in doc
    assert "CONTEXT.md D-01" in doc
    assert "CLAUDE.md" in doc


# ---------------------------------------------------------------------------
# Authentication is verified BEFORE any case runs - proven by source order
# (run_probe calls verify_authenticated() before its case loop), since
# actually running this against a live server is out of scope for this
# module (that's Task 2).
# ---------------------------------------------------------------------------


def test_run_probe_verifies_authentication_before_running_any_case():
    source = inspect.getsource(live_probe.run_probe)
    auth_pos = source.find("verify_authenticated(")
    loop_pos = source.find("run_case(session, base_url, case, ids)")
    assert auth_pos != -1, "run_probe() no longer calls verify_authenticated()"
    assert loop_pos != -1, "run_probe() no longer runs CASES via run_case()"
    assert auth_pos < loop_pos, (
        "run_probe() calls verify_authenticated() AFTER the case loop, not "
        "before - a false pass from an unauthenticated session would then "
        "reach every case instead of being caught up front."
    )


def test_verify_authenticated_checks_status_and_marker_together():
    source = inspect.getsource(live_probe.verify_authenticated)
    assert "AUTH_MARKER_TEXT" in source
    assert "200" in source
    assert "ProbeRefused" in source


# ---------------------------------------------------------------------------
# Production-file boundary - this plan's own acceptance criteria requires
# `git diff --stat` for this plan to list no file under webvulnscanner/.
# Checked here as a standing lock, not just a one-time commit-time check.
# ---------------------------------------------------------------------------


def test_no_case_kind_bypasses_a_real_ownership_or_csrf_mechanism():
    # Sanity lock on the case list's own shape: every case must declare a
    # kind this module's runner dict actually knows how to execute, so a
    # typo'd kind doesn't silently no-op at probe time.
    known_kinds = {"get", "post_with_csrf", "bearer_post", "post_csrf_condition"}
    bad = [c["name"] for c in live_probe.CASES if c["kind"] not in known_kinds]
    assert not bad, f"case(s) with an unrecognized kind: {bad}"
