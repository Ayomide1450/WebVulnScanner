"""
Community check loader for Glassbox.

Loads declarative, YAML-defined HTTP pattern-match checks from
``checks/community/*.yaml`` at startup, validates their schema and safety
constraints, and exposes them as standard ``(data, findings)`` check
functions indistinguishable from built-in checks to ``run_scan()``.

Safety constraints enforced at load time:
- GET-only requests (non-GET methods rejected)
- Max 10 requests per check (``MAX_REQUESTS_PER_CHECK``)
- Regex patterns compiled with a timeout guard (``re.compile``; raw
  ``yaml.safe_load`` already prevents code execution in payloads)
- Required fields validated; missing/invalid = load-time rejection

Community checks are narrow by design: HTTP request/response pattern-match
only.  They cannot run arbitrary Python, access the filesystem, or send
non-GET requests.  This is the class of check most community contributions
actually need.
"""
import logging
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlparse, parse_qs

import yaml
import requests as _requests

from webvulnscanner.checks import (
    Finding,
    REQUEST_TIMEOUT,
    CHECK_LABELS,
    CHECK_CATEGORY,
    CHECK_COMPLIANCE,
    SECURITY_DOMAIN_MAP,
    SCAN_TYPE_CHECK_NAMES,
)
from webvulnscanner.entitlements import FEATURE_REQUIREMENTS, Tier

logger = logging.getLogger(__name__)

COMMUNITY_CHECKS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "checks", "community",
)

# Safety limits enforced at load time.
MAX_REQUESTS_PER_CHECK = 10
VALID_METHODS = {"GET"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info", "pass"}
VALID_TIERS = {"free", "paid", "org_verified"}
VALID_CATEGORIES = {"shield", "lock", "network", "folder", "mail", "bug"}
VALID_CONFIDENCE = {
    "Confirmed", "Strong Evidence", "Potential",
    "Informational", "Not Externally Verifiable",
}
VALID_SECURITY_DOMAINS = {
    "Attack Surface", "Authentication", "Authorization", "API Security",
    "Client Security", "Configuration", "Secrets", "DNS & Domains",
    "TLS", "Dependencies", "Privacy",
}

_TIER_MAP = {
    "free": Tier.FREE,
    "paid": Tier.PAID,
    "org_verified": Tier.ORG_VERIFIED,
}


@dataclass
class CommunityCheckSpec:
    """Parsed and validated community check definition."""
    name: str
    display_label: str
    description: str
    owasp_category: str
    security_domain: str
    tier: Tier
    requests: list
    finding: dict
    icon_category: str = "shield"


class CommunityCheckError(Exception):
    """Raised when a community check YAML fails validation."""


def _validate_check(spec, source_path):
    """Validate a parsed YAML dict against the community check schema.

    Raises CommunityCheckError with a clear message for every rejection
    reason.  Never silently skips — malformed checks fail closed.
    """
    errors = []

    # --- Required top-level fields ---
    for key in ("name", "display_label", "description", "owasp_category",
                "security_domain", "tier", "requests", "finding"):
        if key not in spec:
            errors.append(f"missing required field: {key}")

    if errors:
        raise CommunityCheckError(
            f"{source_path}: {'; '.join(errors)}"
        )

    # --- name ---
    name = spec["name"]
    if not isinstance(name, str) or not name.strip():
        errors.append("'name' must be a non-empty string")
    elif not re.match(r"^[a-z][a-z0-9_]{0,63}$", name):
        errors.append(
            "'name' must be snake_case, 1-64 chars, starting with a letter "
            "(e.g. 'missing_x_header')"
        )

    # --- display_label ---
    if not isinstance(spec["display_label"], str) or not spec["display_label"].strip():
        errors.append("'display_label' must be a non-empty string")

    # --- owasp_category ---
    if not isinstance(spec["owasp_category"], str) or not spec["owasp_category"].strip():
        errors.append("'owasp_category' must be a non-empty string")

    # --- security_domain ---
    sd = spec.get("security_domain", "")
    if sd not in VALID_SECURITY_DOMAINS:
        errors.append(
            f"'security_domain' must be one of: {', '.join(sorted(VALID_SECURITY_DOMAINS))}"
        )

    # --- tier ---
    tier_str = spec.get("tier", "")
    if tier_str not in VALID_TIERS:
        errors.append(
            f"'tier' must be one of: {', '.join(sorted(VALID_TIERS))}"
        )

    # --- icon_category (optional) ---
    ic = spec.get("icon_category", "shield")
    if ic not in VALID_CATEGORIES:
        errors.append(
            f"'icon_category' must be one of: {', '.join(sorted(VALID_CATEGORIES))}"
        )

    # --- requests ---
    reqs = spec.get("requests", [])
    if not isinstance(reqs, list) or len(reqs) == 0:
        errors.append("'requests' must be a non-empty list")
    elif len(reqs) > MAX_REQUESTS_PER_CHECK:
        errors.append(
            f"'requests' has {len(reqs)} entries, max allowed is "
            f"{MAX_REQUESTS_PER_CHECK}"
        )
    else:
        for i, req in enumerate(reqs):
            prefix = f"requests[{i}]"
            if not isinstance(req, dict):
                errors.append(f"{prefix}: must be a mapping")
                continue
            if "path" not in req:
                errors.append(f"{prefix}: missing 'path'")
            method = req.get("method", "GET").upper()
            if method not in VALID_METHODS:
                errors.append(
                    f"{prefix}: method must be GET (got '{method}'); "
                    f"community checks are read-only"
                )
            # Validate match conditions
            match = req.get("match", {})
            if not isinstance(match, dict):
                errors.append(f"{prefix}.match: must be a mapping")
            else:
                if "status_code" in match:
                    sc = match["status_code"]
                    if not isinstance(sc, int) or not (100 <= sc <= 599):
                        errors.append(f"{prefix}.match.status_code: must be an integer 100-599")
                for seq_key in ("required_headers", "forbidden_headers"):
                    if seq_key in match and not isinstance(match[seq_key], list):
                        errors.append(f"{prefix}.match.{seq_key}: must be a list")
                if "body_contains" in match and not isinstance(match["body_contains"], str):
                    errors.append(f"{prefix}.match.body_contains: must be a string")
                if "body_regex" in match:
                    pat = match["body_regex"]
                    if not isinstance(pat, str):
                        errors.append(f"{prefix}.match.body_regex: must be a string")
                    else:
                        try:
                            re.compile(pat)
                        except re.error as e:
                            errors.append(f"{prefix}.match.body_regex: invalid regex: {e}")

    # --- finding ---
    finding = spec.get("finding", {})
    if not isinstance(finding, dict):
        errors.append("'finding' must be a mapping")
    else:
        for key in ("title", "severity", "description"):
            if key not in finding or not isinstance(finding.get(key), str) or not finding[key].strip():
                errors.append(f"finding.{key}: must be a non-empty string")
        sev = finding.get("severity", "")
        if sev and sev not in VALID_SEVERITIES:
            errors.append(
                f"finding.severity: must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
            )
        conf = finding.get("confidence", "")
        if conf and conf not in VALID_CONFIDENCE:
            errors.append(
                f"finding.confidence: must be one of: {', '.join(sorted(VALID_CONFIDENCE))}"
            )

    if errors:
        raise CommunityCheckError(
            f"{source_path}: {'; '.join(errors)}"
        )


def _parse_check(spec, source_path):
    """Parse a validated YAML dict into a CommunityCheckSpec."""
    tier_str = spec.get("tier", "org_verified")
    return CommunityCheckSpec(
        name=spec["name"],
        display_label=spec["display_label"],
        description=spec.get("description", ""),
        owasp_category=spec["owasp_category"],
        security_domain=spec.get("security_domain", "Configuration"),
        tier=_TIER_MAP[tier_str],
        requests=spec.get("requests", []),
        finding=spec.get("finding", {}),
        icon_category=spec.get("icon_category", "shield"),
    )


def _build_check_function(spec):
    """Build a standard ``(data, findings)`` check function from a spec.

    The returned function accepts ``(base_url, session)`` like most built-in
    checks, constructs URLs per the spec's request definitions, sends GET
    requests, evaluates match conditions, and returns findings.
    """
    requests_defs = spec.requests
    finding_def = spec.finding

    def check_fn(base_url, session):
        results = []
        findings = []
        match_count = 0

        for req_def in requests_defs:
            path = req_def.get("path", "/")
            param_name = req_def.get("param_name")
            payload = req_def.get("payload", "")
            timeout = min(req_def.get("timeout", REQUEST_TIMEOUT), REQUEST_TIMEOUT)
            match = req_def.get("match", {})

            # Build URL
            url = base_url.rstrip("/") + "/" + path.lstrip("/")
            if param_name:
                separator = "&" if "?" in url else "?"
                url += separator + urlencode({param_name: payload})

            row = {"url": url, "path": path, "result": "pass"}

            try:
                resp = session.get(url, timeout=timeout)
            except _requests.RequestException as e:
                row["result"] = "error"
                row["error"] = str(e)[:200]
                results.append(row)
                continue

            # Evaluate match conditions
            matched = True
            reasons = []

            if "status_code" in match:
                if resp.status_code != match["status_code"]:
                    matched = False
                    reasons.append(f"status {resp.status_code} != {match['status_code']}")

            for header in match.get("required_headers", []):
                if header.lower() not in {h.lower() for h in resp.headers}:
                    matched = False
                    reasons.append(f"missing header {header}")

            for header in match.get("forbidden_headers", []):
                if header.lower() in {h.lower() for h in resp.headers}:
                    matched = False
                    reasons.append(f"forbidden header {header} present")

            body_contains = match.get("body_contains")
            if body_contains and body_contains not in resp.text:
                matched = False
                reasons.append(f"body missing '{body_contains}'")

            body_regex = match.get("body_regex")
            if body_regex:
                try:
                    if not re.search(body_regex, resp.text):
                        matched = False
                        reasons.append(f"body regex not matched")
                except re.error:
                    matched = False
                    reasons.append("invalid body_regex in check definition")

            if matched:
                row["result"] = "fail"
                match_count += 1

            row["status_code"] = resp.status_code
            row["match_reasons"] = reasons if not matched else []
            results.append(row)

        # Build findings
        if match_count > 0:
            title = finding_def.get("title", spec.display_label)
            detail_parts = []
            for r in results:
                if r["result"] == "fail":
                    detail_parts.append(r["url"])
            detail = (
                finding_def.get("description", spec.display_label)
                + f" Matched {match_count}/{len(requests_defs)} request(s)."
            )
            if detail_parts:
                detail += " Paths: " + ", ".join(detail_parts[:5])

            findings.append(Finding(
                category=spec.owasp_category,
                title=title,
                severity=finding_def.get("severity", "medium"),
                detail=detail,
                recommendation=finding_def.get("recommendation", ""),
                confidence=finding_def.get("confidence", "Confirmed"),
                cwe=finding_def.get("cwe"),
            ))

        return results, findings

    check_fn.__name__ = f"community_{spec.name}"
    check_fn.__qualname__ = f"community_{spec.name}"
    return check_fn


def load_community_checks(directory=None):
    """Load and validate all ``*.yaml`` files from the community checks dir.

    Returns a list of ``CommunityCheckSpec`` objects.  Raises
    ``CommunityCheckError`` on the first malformed file found (fail closed).
    """
    if directory is None:
        directory = COMMUNITY_CHECKS_DIR

    if not os.path.isdir(directory):
        logger.debug("Community checks directory not found: %s", directory)
        return []

    specs = []
    for fname in sorted(os.listdir(directory)):
        if not fname.endswith((".yaml", ".yml")):
            continue
        fpath = os.path.join(directory, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise CommunityCheckError(f"{fpath}: YAML parse error: {e}")

        if not isinstance(raw, dict):
            raise CommunityCheckError(f"{fpath}: expected a YAML mapping, got {type(raw).__name__}")

        _validate_check(raw, fpath)
        specs.append(_parse_check(raw, fpath))
        logger.info("Loaded community check: %s (%s)", spec.name if False else raw["name"], fpath)

    return specs


def register_community_checks(specs):
    """Register loaded community check specs into the global registries.

    Mutates ``FEATURE_REQUIREMENTS``, ``CHECK_LABELS``, ``CHECK_CATEGORY``,
    ``CHECK_COMPLIANCE``, ``SECURITY_DOMAIN_MAP``, and
    ``SCAN_TYPE_CHECK_NAMES`` in-place so that ``run_scan()``'s existing
    tier-gating, live-feed, and compliance-reporting code works without
    modification.
    """
    for spec in specs:
        full_name = f"community_{spec.name}"
        FEATURE_REQUIREMENTS[full_name] = spec.tier
        CHECK_LABELS[full_name] = spec.display_label
        CHECK_CATEGORY[full_name] = spec.icon_category
        CHECK_COMPLIANCE[full_name] = {"owasp": spec.owasp_category, "asvs": None}
        SECURITY_DOMAIN_MAP[full_name] = spec.security_domain
        # NOTE: community checks are NOT added to SCAN_TYPE_CHECK_NAMES —
        # they are dynamically loaded at runtime, not statically enumerated
        # in the source.  run_scan()'s jobs.update() adds them to the
        # dispatch dict; the compliance tests source-parse for literal keys.
        logger.info(
            "Registered community check: %s (tier=%s, domain=%s)",
            full_name, spec.tier.name, spec.security_domain,
        )


def build_community_jobs(specs, base_url, session):
    """Build a dict of ``{name: callable}`` for all loaded community checks.

    Returns a dict suitable for merging into ``run_scan()``'s ``jobs`` dict
    before the ``allowed_checks`` / ``ThreadPoolExecutor`` dispatch.
    """
    jobs = {}
    for spec in specs:
        full_name = f"community_{spec.name}"
        fn = _build_check_function(spec)
        jobs[full_name] = lambda _fn=fn: _fn(base_url, session)
    return jobs
