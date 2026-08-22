"""v1.3 Phase 13 (SCORE-02): coverage for scan_routes.group_findings_by_domain,
mirroring test_compliance.py's group_findings_by_compliance() test shape
(same function contract, different mapping shape - see that function's own
docstring for the difference)."""
from webvulnscanner.scan_routes import group_findings_by_domain

_MAPPING = {
    "headers": "Configuration",
    "tls": "TLS",
    "cookies": "Configuration",
}


def test_group_findings_by_domain_empty_input_returns_empty_list():
    assert group_findings_by_domain([], _MAPPING) == []


def test_group_findings_by_domain_two_findings_share_a_domain():
    findings = [
        {"check_name": "headers", "title": "a"},
        {"check_name": "cookies", "title": "b"},
    ]
    out = group_findings_by_domain(findings, _MAPPING)
    assert out == [("Configuration", findings)]


def test_group_findings_by_domain_unmapped_check_name_is_uncategorized():
    findings = [{"check_name": "nope", "title": "c"}]
    out = group_findings_by_domain(findings, _MAPPING)
    assert out == [("Uncategorized", findings)]


def test_group_findings_by_domain_missing_check_name_key_is_uncategorized():
    findings = [{"title": "d"}]
    out = group_findings_by_domain(findings, _MAPPING)
    assert out == [("Uncategorized", findings)]


def test_group_findings_by_domain_uncategorized_group_is_always_last():
    mapped = {"check_name": "headers", "title": "a"}
    unmapped = {"title": "b"}
    tls_mapped = {"check_name": "tls", "title": "c"}
    out = group_findings_by_domain([unmapped, mapped, tls_mapped], _MAPPING)
    labels = [domain for domain, _ in out]
    assert labels == ["Configuration", "TLS", "Uncategorized"]


def test_group_findings_by_domain_uses_real_security_domain_map():
    """End-to-end sanity check against the actual SECURITY_DOMAIN_MAP, not
    just the small local fixture above."""
    from webvulnscanner.checks import SECURITY_DOMAIN_MAP
    findings = [
        {"check_name": "idor", "title": "IDOR finding"},
        {"check_name": "secrets", "title": "Secret finding"},
    ]
    out = group_findings_by_domain(findings, SECURITY_DOMAIN_MAP)
    labels = {domain for domain, _ in out}
    assert labels == {"Authorization", "Secrets"}
