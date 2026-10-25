"""
Tests for glassbox/entitlements.py - the single place that gates which
checks a scan is allowed to run by plan tier (Free / Paid / Org-verified),
plus the domain-ownership check that gates the intrusive checks on top of
tier alone. See CLAUDE.md's "entitlements.py" row and
`FEATURE_REQUIREMENTS`'s own docstring for why this module matters: a check
missing from FEATURE_REQUIREMENTS silently defaults to Tier.FREE (allowed
to everyone), so this is the one place a gating regression would be both
easy to introduce and easy to miss.
"""
import logging
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from glassbox.entitlements import (
    FEATURE_REQUIREMENTS,
    Tier,
    allowed_checks,
    domain_is_org_verified,
    effective_tier,
)
from glassbox.models import Plan

from tests.conftest import make_org, make_user


# --------------------------------------------------------------------------
# Tier ordering
# --------------------------------------------------------------------------

def test_tier_ordering():
    # allowed_checks()/run_scan()/run_advanced_scan() all rely on `<=`
    # comparing Tier members - if the IntEnum values ever get reordered or
    # given non-monotonic values, every gate silently breaks.
    assert Tier.FREE < Tier.PAID < Tier.ORG_VERIFIED


# --------------------------------------------------------------------------
# FEATURE_REQUIREMENTS regression coverage: every check name run_scan's
# jobs dict can dispatch must have an explicit entry, or it silently
# defaults to Tier.FREE (allowed_checks' documented fallback behavior).
# Extracted from the live source rather than hand-copied so this test
# actually catches a future jobs-dict edit that forgets to update the map.
# --------------------------------------------------------------------------

def _run_scan_job_names():
    src = Path(__file__).resolve().parent.parent / "glassbox" / "scan_engine.py"
    text = src.read_text(encoding="utf-8")
    # Slice out just the `jobs = { ... }` block inside run_scan (the first
    # occurrence - run_advanced_scan doesn't use a jobs dict, it branches
    # per check group instead).
    start = text.index("jobs = {")
    end = text.index("\n    }", start)
    block = text[start:end]
    return set(re.findall(r'"(\w+)":\s*lambda', block))


ADVANCED_SCAN_CHECK_NAMES = {"sqli_login", "bruteforce", "sqli_union", "xss_stored", "idor",
                             "auth_comparison", "mass_assignment"}
# Dispatched outside run_scan's jobs dict (see FEATURE_REQUIREMENTS's own
# comment) but still gated through the same map.
OUT_OF_JOBS_DICT_NAMES = {"headers", "cookies", "open_ports"}


def test_feature_requirements_covers_run_scan_jobs():
    used = _run_scan_job_names()
    assert used, "extraction found no job names - regex or scan_engine.py's jobs dict shape changed"
    missing = used - set(FEATURE_REQUIREMENTS)
    assert not missing, (
        f"scan_engine.run_scan can dispatch {missing} but FEATURE_REQUIREMENTS has no entry for "
        "them - they would silently default to Tier.FREE (allowed to everyone)."
    )


def test_feature_requirements_covers_advanced_and_out_of_band_checks():
    missing = (ADVANCED_SCAN_CHECK_NAMES | OUT_OF_JOBS_DICT_NAMES) - set(FEATURE_REQUIREMENTS)
    assert not missing


def test_intrusive_checks_require_org_verified_tier():
    # These are exactly the checks CLAUDE.md documents as requiring both
    # Tier.ORG_VERIFIED *and* a verified DomainVerification row - the tier
    # half of that gate lives here.
    intrusive = {"xss_sqli", "sqli_login", "bruteforce", "sqli_union", "xss_stored", "idor"}
    for name in intrusive:
        assert FEATURE_REQUIREMENTS[name] == Tier.ORG_VERIFIED, name


def test_passive_checks_are_free_tier():
    passive = {
        "headers", "cookies", "tls", "https_redirect", "sensitive_paths",
        "robots_sitemap", "dns_email", "mixed_content", "vulnerable_js", "secrets", "sri",
    }
    for name in passive:
        assert FEATURE_REQUIREMENTS[name] == Tier.FREE, name


# --------------------------------------------------------------------------
# allowed_checks()
# --------------------------------------------------------------------------

def test_allowed_checks_free_tier_only_gets_passive_checks():
    names = ["headers", "crawl", "xss_sqli"]
    allowed, locked = allowed_checks(names, Tier.FREE)
    assert allowed == ["headers"]
    assert set(locked) == {"crawl", "xss_sqli"}


def test_allowed_checks_paid_tier_unlocks_active_but_not_intrusive():
    names = ["headers", "crawl", "xss_sqli"]
    allowed, locked = allowed_checks(names, Tier.PAID)
    assert set(allowed) == {"headers", "crawl"}
    assert locked == ["xss_sqli"]


def test_allowed_checks_org_verified_unlocks_everything():
    names = ["headers", "crawl", "xss_sqli"]
    allowed, locked = allowed_checks(names, Tier.ORG_VERIFIED)
    assert set(allowed) == set(names)
    assert locked == []


def test_allowed_checks_unknown_name_defaults_to_free_and_warns(caplog):
    with caplog.at_level(logging.WARNING):
        allowed, locked = allowed_checks(["totally_made_up_check"], Tier.FREE)
    assert allowed == ["totally_made_up_check"]
    assert locked == []
    assert "no FEATURE_REQUIREMENTS entry" in caplog.text


def test_allowed_checks_preserves_order_and_empty_input():
    allowed, locked = allowed_checks([], Tier.FREE)
    assert allowed == []
    assert locked == []

    names = ["crawl", "headers", "cors"]  # PAID, FREE, PAID
    allowed, locked = allowed_checks(names, Tier.PAID)
    assert allowed == names  # order preserved, not sorted/grouped
    assert locked == []


# --------------------------------------------------------------------------
# effective_tier()
# --------------------------------------------------------------------------

def test_effective_tier_none_user_is_free():
    assert effective_tier(None) == Tier.FREE


def test_effective_tier_unauthenticated_user_is_free():
    anon = SimpleNamespace(is_authenticated=False)
    assert effective_tier(anon) == Tier.FREE


def test_effective_tier_authenticated_user_without_org_is_free():
    user = SimpleNamespace(is_authenticated=True, organization=None)
    assert effective_tier(user) == Tier.FREE


@pytest.mark.parametrize("plan,expected", [
    (Plan.FREE, Tier.FREE),
    (Plan.PAID, Tier.PAID),
    (Plan.ORG_VERIFIED, Tier.ORG_VERIFIED),
])
def test_effective_tier_maps_org_plan_to_tier(plan, expected):
    org = SimpleNamespace(plan=plan)
    user = SimpleNamespace(is_authenticated=True, organization=org)
    assert effective_tier(user) == expected


# --------------------------------------------------------------------------
# domain_is_org_verified() - needs a real DB (queries DomainVerification)
# --------------------------------------------------------------------------

def test_domain_is_org_verified_none_org_is_false(db):
    assert domain_is_org_verified(None, "https://example.com") is False


def test_domain_is_org_verified_no_row_is_false(db):
    org = make_org()
    assert domain_is_org_verified(org, "https://example.com") is False


def test_domain_is_org_verified_pending_row_is_false(db):
    from glassbox.extensions import db as _db
    from glassbox.models import DomainVerification, VerifyMethod

    org = make_org()
    _db.session.add(DomainVerification(
        org_id=org.id, domain="example.com", method=VerifyMethod.DNS_TXT,
        token="tok", verified_at=None,  # never completed verification
    ))
    _db.session.flush()
    assert domain_is_org_verified(org, "https://example.com") is False


def test_domain_is_org_verified_verified_row_is_true(db):
    from datetime import datetime, timezone

    from glassbox.extensions import db as _db
    from glassbox.models import DomainVerification, VerifyMethod

    org = make_org()
    _db.session.add(DomainVerification(
        org_id=org.id, domain="example.com", method=VerifyMethod.DNS_TXT,
        token="tok", verified_at=datetime.now(timezone.utc),
    ))
    _db.session.flush()
    assert domain_is_org_verified(org, "https://example.com") is True


def test_domain_is_org_verified_hostname_is_case_and_port_insensitive(db):
    from datetime import datetime, timezone

    from glassbox.extensions import db as _db
    from glassbox.models import DomainVerification, VerifyMethod

    org = make_org()
    _db.session.add(DomainVerification(
        org_id=org.id, domain="example.com", method=VerifyMethod.DNS_TXT,
        token="tok", verified_at=datetime.now(timezone.utc),
    ))
    _db.session.flush()
    assert domain_is_org_verified(org, "https://EXAMPLE.com:8443/some/path") is True


def test_domain_is_org_verified_does_not_leak_across_orgs(db):
    # A verified domain on org A must not make it look verified for org B -
    # this is the org-isolation half of the ORG_VERIFIED gate; without it,
    # any org could unlock another org's intrusive checks against a domain
    # they don't own just by matching hostnames.
    from datetime import datetime, timezone

    from glassbox.extensions import db as _db
    from glassbox.models import DomainVerification, VerifyMethod

    org_a = make_org(name="Org A")
    org_b = make_org(name="Org B")
    _db.session.add(DomainVerification(
        org_id=org_a.id, domain="example.com", method=VerifyMethod.DNS_TXT,
        token="tok", verified_at=datetime.now(timezone.utc),
    ))
    _db.session.flush()
    assert domain_is_org_verified(org_a, "https://example.com") is True
    assert domain_is_org_verified(org_b, "https://example.com") is False
