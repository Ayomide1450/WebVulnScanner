"""
Tests for scripts/secrets_sweep_phase8.py (SEC-08).

Runs the working-tree sweep and the self-test in-process (importing the
script's functions directly, not shelling out to it) so this is part of
the standing suite, not a one-time observation. The git-history half is
also exercised here, but degrades to a skip with a recorded reason on a
shallow checkout (e.g. a CI runner without full history) rather than
failing the suite for an environmental reason - see
scripts/secrets_sweep_phase8.py's own module docstring for why no
scanning package (detect-secrets/gitleaks) is used instead.
"""
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import secrets_sweep_phase8 as sweep  # noqa: E402


def test_self_test_proves_the_patterns_fire():
    # The single most likely failure mode of a hand-written secrets
    # check (T-08-39 in this plan's threat register): a broken regex
    # that silently produces a clean sweep. This must pass before any
    # "clean" result below means anything.
    assert sweep.self_test() is True


def test_working_tree_sweep_is_clean():
    result = sweep.sweep_working_tree()
    assert result["file_count"] > 0, "the sweep scanned zero files - the scan itself is broken"
    assert result["unallowed_hits"] == [], (
        f"un-allowlisted credential-shaped literal(s) found in the working "
        f"tree: {result['unallowed_hits']}"
    )


def test_every_allowlist_entry_has_a_non_empty_reason():
    # T-08-40: an allowlist used to silence real findings without
    # justification is worse than no sweep at all.
    empty = [text for text, reason in sweep.ALLOWLIST.items() if not reason or not reason.strip()]
    assert not empty, f"allowlist entry/entries with no written reason: {empty}"


def test_milestone_commit_range_resolves():
    # A wrong or rewritten boundary commit must surface immediately, not
    # silently sweep zero commits and report a false "clean" git-range
    # result.
    if sweep._is_shallow_checkout():
        pytest.skip(
            "shallow git checkout - full history unavailable, same skip "
            "scripts/secrets_sweep_phase8.py's own sweep_git_range() applies"
        )
    count = sweep._git_range_resolves()
    assert count is not None, (
        f"commit range {sweep.MILESTONE_START_COMMIT}..HEAD did not resolve"
    )
    assert count > 0, f"commit range {sweep.MILESTONE_START_COMMIT}..HEAD resolved to zero commits"


def test_git_range_sweep_is_clean_or_skips_cleanly_on_shallow_checkout():
    result = sweep.sweep_git_range()
    if result["skipped"]:
        # Documented, not silently ignored - a shallow CI checkout is an
        # environmental fact, not a finding.
        assert result["reason"], "git-range sweep was skipped with no reason recorded"
        return
    assert result["commit_count"] is not None and result["commit_count"] > 0
    assert result["unallowed_hits"] == [], (
        f"un-allowlisted credential-shaped literal(s) found in the "
        f"{sweep.MILESTONE_START_COMMIT}..HEAD commit range diff: "
        f"{result['unallowed_hits']}"
    )
