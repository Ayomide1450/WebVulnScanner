"""
Entitlement / tier gating for WebVulnScanner (Workstream 3).

This module is the one place allowed to bridge DB-backed concepts
(`webvulnscanner.models.Plan`, `DomainVerification`) and the tier-ordering
system used to gate checks. `webvulnscanner/checks.py` and
`webvulnscanner/scan_engine.py` have zero dependency on `webvulnscanner.models`
today and that must stay true - `models` is only imported here, and lazily
inside the functions that need it, to avoid any circular-import risk.

`Tier` (this file) and `Plan` (models.py) are deliberately kept as two
distinct concepts: `Plan` is the DB-persisted, SQLAlchemy-enum value stored
on an `Organization`; `Tier` is a plain, comparable `IntEnum` used for
`<=` gating logic. `effective_tier()` is the only place that maps one to
the other.
"""
import logging
from enum import IntEnum
from urllib.parse import urlparse


class Tier(IntEnum):
    FREE = 0
    PAID = 1
    ORG_VERIFIED = 2


# Keys MUST match run_scan's jobs-dict keys exactly, plus "headers"/"cookies"/
# "open_ports" (dispatched outside the jobs dict), the advanced-scan check
# names, and "media". Verified directly against webvulnscanner/scan_engine.py
# - note "secrets" is the correct jobs-dict key (NOT "exposed_secrets").
FEATURE_REQUIREMENTS = {
    # base scan - passive (FREE)
    "headers": Tier.FREE, "cookies": Tier.FREE, "tls": Tier.FREE,
    "https_redirect": Tier.FREE, "sensitive_paths": Tier.FREE, "robots_sitemap": Tier.FREE,
    "dns_email": Tier.FREE, "mixed_content": Tier.FREE, "vulnerable_js": Tier.FREE,
    "secrets": Tier.FREE, "sri": Tier.FREE,
    # base scan - active (PAID)
    "crawl": Tier.PAID, "open_ports": Tier.PAID, "cors": Tier.PAID,
    "http_methods": Tier.PAID, "open_redirect": Tier.PAID, "directory_listing": Tier.PAID,
    # base scan - intrusive (ORG_VERIFIED + domain-ownership check)
    "xss_sqli": Tier.ORG_VERIFIED,
    # advanced scan - all intrusive (ORG_VERIFIED + domain-ownership check)
    "sqli_login": Tier.ORG_VERIFIED, "bruteforce": Tier.ORG_VERIFIED,
    "sqli_union": Tier.ORG_VERIFIED, "xss_stored": Tier.ORG_VERIFIED, "idor": Tier.ORG_VERIFIED,
    # media scan - single call, judgment call: active multi-page crawl +
    # optional download, but no payload injection, so PAID (not ORG_VERIFIED).
    "media": Tier.PAID,
    # api scan - single call, same reasoning as media: schema/wordlist/JS-
    # discovery probing is read-only (GET requests, one read-only GraphQL
    # introspection query) with no injection payloads, so PAID not
    # ORG_VERIFIED.
    "api": Tier.PAID,
}


def effective_tier_for_org(org):
    """Maps an `Organization` (or `None`) directly to a `Tier`.

    Org-shaped entry point for callers that have an `Organization` but no
    `User` - e.g. webvulnscanner.scheduler's tick handler, which must
    recompute tier at scheduled-fire time (ASSET-07), never cached from
    registration time, and has no request/user in the loop. `effective_tier`
    below is user-shaped and delegates here after its own user-specific
    checks, so the Plan->Tier mapping is defined exactly once.
    """
    from webvulnscanner.models import Plan  # lazy import - see module docstring

    if org is None:
        return Tier.FREE

    plan_to_tier = {
        Plan.FREE: Tier.FREE,
        Plan.PAID: Tier.PAID,
        Plan.ORG_VERIFIED: Tier.ORG_VERIFIED,
    }
    return plan_to_tier.get(org.plan, Tier.FREE)


def effective_tier(user):
    """Maps an (optionally-authenticated) user to a `Tier`.

    Unauthenticated users, or users with no organization, are always FREE.
    Otherwise the user's `org.plan` (the DB-persisted `Plan` enum) is mapped
    to the matching `Tier` via `effective_tier_for_org`.
    """
    if user is None or not getattr(user, "is_authenticated", True):
        return Tier.FREE

    org = getattr(user, "organization", None)
    return effective_tier_for_org(org)


def allowed_checks(names, tier):
    """Splits `names` into `(allowed, locked)` against `FEATURE_REQUIREMENTS`
    for the given `tier`, via a single `<=` comparison per name.

    Any name missing from `FEATURE_REQUIREMENTS` defaults to `Tier.FREE`
    (i.e. allowed) and logs a warning, since a missing key means the map
    itself is out of sync with the checks it's supposed to gate.
    """
    allowed = []
    locked = []
    for name in names:
        if name not in FEATURE_REQUIREMENTS:
            logging.warning(
                "entitlements: %r has no FEATURE_REQUIREMENTS entry - "
                "defaulting to Tier.FREE (allowed). The FEATURE_REQUIREMENTS "
                "map is missing a key.",
                name,
            )
        required = FEATURE_REQUIREMENTS.get(name, Tier.FREE)
        if required <= tier:
            allowed.append(name)
        else:
            locked.append(name)
    return allowed, locked


def domain_is_org_verified(org, target_url):
    """True if `org` has a verified `DomainVerification` row for the
    hostname in `target_url`. Evaluated fresh on every call - never cached
    from verification time.
    """
    if org is None:
        return False

    from webvulnscanner.models import DomainVerification  # lazy import

    hostname = urlparse(target_url).netloc.split(":")[0].lower()
    row = DomainVerification.query.filter_by(
        org_id=org.id,
        domain=hostname,
    ).filter(DomainVerification.verified_at.isnot(None)).first()
    return row is not None
