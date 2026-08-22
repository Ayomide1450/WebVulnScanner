"""v1.3 Phase 13 (SCORE-01): coverage lock for SECURITY_DOMAIN_MAP, mirroring
tests/test_compliance.py's proof pattern for the sibling CHECK_COMPLIANCE
dict - every dispatchable check_name must have a domain entry, no stale
entries for check names no longer dispatched, and every entry's value must
be one of the 11 real SECURITY_DOMAINS (never a Security Posture/Production
Readiness aggregate section, which are report-summary-only)."""
from webvulnscanner.checks import (
    SCAN_TYPE_CHECK_NAMES,
    SECURITY_DOMAIN_MAP,
    SECURITY_DOMAINS,
    SECURITY_POSTURE_SECTIONS,
    security_domain_for,
)


def test_security_domain_map_covers_every_dispatchable_check_name():
    all_names = set().union(*SCAN_TYPE_CHECK_NAMES.values())
    missing = all_names - set(SECURITY_DOMAIN_MAP)
    assert not missing, f"SECURITY_DOMAIN_MAP is missing entries for {missing}"


def test_security_domain_map_has_no_stale_keys():
    all_names = set().union(*SCAN_TYPE_CHECK_NAMES.values())
    stale = set(SECURITY_DOMAIN_MAP) - all_names
    assert not stale, f"SECURITY_DOMAIN_MAP has stale entries for check names no longer dispatched: {stale}"


def test_every_security_domain_map_value_is_a_real_domain_not_an_aggregate_section():
    for check_name, domain in SECURITY_DOMAIN_MAP.items():
        assert domain in SECURITY_DOMAINS, (
            f"{check_name!r} maps to {domain!r}, which is not one of the 11 real SECURITY_DOMAINS"
        )
        assert domain not in SECURITY_POSTURE_SECTIONS, (
            f"{check_name!r} maps to {domain!r}, an aggregate-only report section - "
            "no single check's findings should be attributed there"
        )


def test_security_domain_for_degrades_gracefully_for_unknown_check_name():
    assert security_domain_for("this_check_does_not_exist") == "Uncategorized"


def test_security_domain_for_known_check_name():
    assert security_domain_for("headers") == "Configuration"
    assert security_domain_for("idor") == "Authorization"
