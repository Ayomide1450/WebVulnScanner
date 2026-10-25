"""CWE coverage lock for CHECK_CWE.

`Finding.cwe` existed as a field since v1.3 but no built-in check ever
populated it - only community_checks.py, from YAML. Three already-written
code paths therefore emitted null forever: sarif.py's `cwe:<id>` tagging
(what makes GitHub Code Scanning group and explain a finding),
ndjson_report.py's exported `cwe` column, and the `cwe` field the API
reference advertises.

Same "coverage lock over a hand-maintained map" pattern as
entitlements.FEATURE_REQUIREMENTS, checks.CHECK_LABELS and
checks.CHECK_CATEGORY: the map is only useful if it stays complete as
checks are added, and a human will forget.
"""
import re

import pytest

from glassbox.checks import CHECK_COMPLIANCE, CHECK_CWE, Finding, apply_cwe_mapping


def test_cwe_map_covers_the_same_check_name_space_as_compliance():
    """CHECK_COMPLIANCE is the authoritative check-name space; CHECK_CWE
    must cover exactly it. A check added to one and not the other is the
    drift this lock exists to catch."""
    missing = sorted(set(CHECK_COMPLIANCE) - set(CHECK_CWE))
    extra = sorted(set(CHECK_CWE) - set(CHECK_COMPLIANCE))
    assert not missing, f"checks with no CHECK_CWE entry: {missing}"
    assert not extra, f"CHECK_CWE entries for unknown checks: {extra}"


def test_every_cwe_value_is_a_wellformed_id_or_an_explicit_none():
    """A malformed ID silently breaks SARIF's `cwe:<id>` tag, and GitHub
    just drops the tag rather than erroring - so assert the shape here."""
    for check, cwe in sorted(CHECK_CWE.items()):
        if cwe is None:
            continue
        assert re.fullmatch(r"CWE-\d{1,4}", cwe), f"{check}: malformed CWE id {cwe!r}"


def test_only_deliberately_uncategorised_checks_have_no_cwe():
    """None must be a decision, not an oversight. robots_sitemap is
    informational wayfinding rather than a weakness - CHECK_COMPLIANCE
    independently calls it "Uncategorized"."""
    unmapped = {k for k, v in CHECK_CWE.items() if v is None}
    assert unmapped == {"robots_sitemap"}, (
        f"unexpected unmapped checks: {sorted(unmapped)} - either give the "
        f"check a CWE or add it here with a stated reason"
    )
    for check in unmapped:
        assert CHECK_COMPLIANCE[check]["owasp"] == "Uncategorized", (
            f"{check} has no CWE but claims a real OWASP category - "
            f"those two judgements should agree"
        )


# --------------------------------------------------------------------------
# apply_cwe_mapping behaviour
# --------------------------------------------------------------------------


def _finding(check_name, **kw):
    return Finding(
        category="test",
        title="t",
        severity="medium",
        detail="d",
        check_name=check_name,
        **kw,
    )


def test_backfills_cwe_from_check_name():
    f = _finding("sqli_login")
    assert f.cwe is None
    apply_cwe_mapping([f])
    assert f.cwe == "CWE-89"


def test_never_overwrites_an_author_supplied_cwe():
    """community_checks.py sets cwe from each YAML check's own definition.
    That value is more specific than anything a check-name map can infer,
    so it must win."""
    f = _finding("sqli_login", cwe="CWE-564")
    apply_cwe_mapping([f])
    assert f.cwe == "CWE-564"


def test_unknown_check_name_is_left_alone_not_guessed():
    f = _finding("some_future_check")
    apply_cwe_mapping([f])
    assert f.cwe is None


def test_deliberately_unmapped_check_stays_none():
    f = _finding("robots_sitemap")
    apply_cwe_mapping([f])
    assert f.cwe is None


def test_is_idempotent():
    f = _finding("idor")
    apply_cwe_mapping([f])
    apply_cwe_mapping([f])
    assert f.cwe == "CWE-639"


def test_returns_the_same_list_so_it_can_wrap_deduplicate():
    """The orchestrators call deduplicate_findings(apply_cwe_mapping(x)),
    so this must return the findings rather than None."""
    findings = [_finding("headers")]
    assert apply_cwe_mapping(findings) is findings


@pytest.mark.parametrize(
    "check,expected",
    [
        ("xss_stored", "CWE-79"),
        ("idor", "CWE-639"),
        ("open_redirect", "CWE-601"),
        ("bruteforce", "CWE-307"),
        ("path_traversal", "CWE-22"),
        ("secrets", "CWE-798"),
    ],
)
def test_spot_check_high_impact_mappings(check, expected):
    """These are the findings most likely to reach a client report or a
    GitHub Code Scanning alert, so pin them explicitly - a silent edit to
    one of these changes what a customer is told their bug *is*."""
    assert CHECK_CWE[check] == expected
