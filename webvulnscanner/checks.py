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
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin, quote

import dns.resolver
import requests
from bs4 import BeautifulSoup
from PIL import Image, ExifTags

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
    "advanced": {"sqli_login", "bruteforce", "sqli_union", "xss_stored", "idor"},
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
    # media scan
    "media":             {"owasp": "A01:2021-Broken Access Control",     "asvs": "V8.3"},
    # api scan (matches run_api_scan()'s own `results` dict sub-keys, not
    # entitlements.FEATURE_REQUIREMENTS's single "api" tier-gating bucket)
    "schema":            {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V13"},
    "wordlist":          {"owasp": "A01:2021-Broken Access Control",     "asvs": "V13"},
    "js_discovery":      {"owasp": "A01:2021-Broken Access Control",     "asvs": "V13"},
}

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
]

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


def _mk_session():
    s = _SSRFSafeSession()
    s.headers.update({"User-Agent": UA})
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
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # version()/cipher() reflect whatever the server's own default
                # negotiation picked against a standard client context - this
                # never attempts to force a weaker protocol/cipher itself, it
                # only reads back what the server was willing to offer.
                tls_version = ssock.version()
                cipher = ssock.cipher()  # (name, protocol, secret_bits) or None
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
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
    - A 429 is reported as NEEDS_REVIEW ("rate limited") - the scanner
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
                                     row["detail"], row["recommendation"], confidence="Potential"))
            rows.append(row)
            continue

        if r.status_code == 429:
            retry_after = r.headers.get("Retry-After")
            if retry_after:
                row["evidence"]["retry_after"] = retry_after
            row.update(classification="needs_review", severity="info", confidence="low",
                       title="Rate limited",
                       detail="The target rate-limited the request (HTTP 429), so the scanner could not reliably "
                              "determine whether the resource exists. The scanner does not retry a rate-limited "
                              "path.",
                       recommendation="Re-run the scan later, outside of any rate-limit window, or investigate "
                                       "manually.")
            rows.append(row)
            continue

        if r.status_code >= 500:
            row.update(classification="needs_review", severity="info", confidence="low",
                       title="Server error",
                       detail=f"The server returned HTTP {r.status_code} while this path was being tested. This "
                                "is inconclusive - the scanner could not reliably determine whether the "
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
                                     row["detail"] + " " + impact, remediation, confidence="Confirmed"))
        else:
            row.update(classification="needs_review", severity="medium", confidence="low",
                       title="Reachable, not confirmed",
                       detail="The scanner detected an unusual response, but there was insufficient evidence to "
                              "confirm that the requested sensitive resource exists.",
                       recommendation="Verify the resource manually or review the production server "
                                       "configuration.")
            findings.append(Finding("Sensitive Path Exposure", f"Unconfirmed reachable path: /{path}", "medium",
                                     row["detail"], row["recommendation"], confidence="Potential"))
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
            except socket.timeout:
                pass
            if not data:
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % hostname.encode())
                    data = s.recv(256)
                except (socket.timeout, OSError):
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
                    "network/firewall settings to shrink probe-able surface.", confidence="Strong Evidence"))
            else:
                rows.append({"port": port, "status": "warn",
                             "note": f"Responded with an unbranded service banner: {snippet}"})
                findings.append(Finding(
                    "Network", f"Unbranded service responding on unexpected port {port}", "high",
                    "This does not look like your CDN/edge - it may be a real backend service exposed directly.",
                    "Firewall this port or bind the service to localhost/a private network only.", confidence="Strong Evidence"))
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


def check_http_methods(base_url, session):
    rows, findings = [], []
    try:
        r = session.request("OPTIONS", base_url + "/", timeout=REQUEST_TIMEOUT)
        rows.append({"method": "OPTIONS", "code": r.status_code, "allow": r.headers.get("Allow", "")})
    except requests.RequestException:
        pass
    for method in ("PUT", "DELETE", "TRACE", "CONNECT"):
        try:
            r = session.request(method, base_url + "/", timeout=REQUEST_TIMEOUT)
            rows.append({"method": method, "code": r.status_code, "allow": ""})
            if r.status_code not in (404, 405, 501, 400, 403, 501):
                sev = "high" if method == "TRACE" else "medium"
                findings.append(Finding("HTTP methods", f"{method} method not rejected ({r.status_code})", sev,
                                         f"Server responded {r.status_code} instead of 405/501 for {method}.",
                                         f"Disable the {method} method at the web server/edge for this route.", confidence="Confirmed"))
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
                                         "Validate redirect targets against an allowlist of internal paths.", confidence="Confirmed"))
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
                        "Always set a short-lived 'exp' claim and use refresh tokens for longer sessions.", confidence="Confirmed"))
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
            findings.append(Finding("Supply chain", f"Third-party script without SRI", "medium",
                                     f"{abs_url} is loaded from an external host with no integrity= hash.",
                                     "Add an integrity (SHA-384) and crossorigin attribute, or self-host the script.", confidence="Confirmed"))

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
                if p.netloc == origin and any(h in p.path.lower() for h in AUTH_LIKE_PATH_HINTS):
                    if abs_url not in candidates:
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


def check_xss_sqli(urls, session):
    """Reflected-XSS canary + error-based and boolean-based blind SQLi probe.
    One extra request per technique per parameter - not a full fuzzer."""
    findings = []
    tested = []
    for url in urls:
        qs = parse_qs(urlparse(url).query)
        for param in qs:
            row = {"url": url, "param": param, "xss": "pass", "sqli": "pass"}

            xss_url = _inject_param(url, param, f"\"><svg onload={XSS_MARKER}>")
            try:
                r = session.get(xss_url, timeout=REQUEST_TIMEOUT)
                if f"<svg onload={XSS_MARKER}>" in r.text:
                    row["xss"] = "fail"
                    findings.append(Finding("XSS", f"Reflected XSS in '{param}' on {url}", "critical",
                                             "Injected markup was reflected unescaped into the HTML response.",
                                             "Escape/encode all user input before rendering; verify with a CSP.", confidence="Confirmed"))
            except requests.RequestException:
                row["xss"] = "info"

            try:
                err_r = session.get(_inject_param(url, param, "'"), timeout=REQUEST_TIMEOUT)
                if any(re.search(sig, err_r.text.lower()) for sig in SQL_ERROR_SIGNATURES):
                    row["sqli"] = "fail"
                    findings.append(Finding("SQL Injection", f"DB error signature via '{param}' on {url}", "critical",
                                             "A single quote triggered a database error visible in the response.",
                                             "Use parameterized queries/ORM bindings; never string-concat user input into SQL.", confidence="Strong Evidence"))
                else:
                    true_r = session.get(_inject_param(url, param, "1' AND '1'='1"), timeout=REQUEST_TIMEOUT)
                    false_r = session.get(_inject_param(url, param, "1' AND '1'='2"), timeout=REQUEST_TIMEOUT)
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
    """Returns (direct_media_urls, embedded_video_urls). Direct URLs point
    to actual image/video files (HEAD-checkable, downloadable). Embedded
    URLs are third-party player iframes (YouTube/Vimeo/etc.) that can't be
    downloaded as a file but are still worth inventorying - a site's video
    content isn't only self-hosted <video> tags."""
    soup = BeautifulSoup(html, "html.parser")
    urls = set()

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
        if href.lower().endswith(MEDIA_FILE_EXTENSIONS):
            urls.add(urljoin(base_url + "/", a["href"]))

    embeds = set()
    for iframe in soup.find_all("iframe", src=True):
        abs_url = urljoin(base_url + "/", iframe["src"])
        host = urlparse(abs_url).netloc.lower()
        if any(domain in host for domain in VIDEO_EMBED_DOMAINS):
            embeds.add(abs_url)

    return urls, embeds


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
        return [], [], {"error": str(e)}

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

    media_urls, embeds = _extract_media_urls(base_url, home_r.text)
    for page in pages[1:]:
        try:
            r = _get_respecting_backoff(session, page, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue
        u, e = _extract_media_urls(base_url, r.text)
        media_urls |= u
        embeds |= e

    return list(media_urls)[:MAX_MEDIA_ITEMS], list(embeds)[:20], {"pages_crawled": len(pages)}


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


def check_media(session, base_url, download, max_files):
    media_urls, embed_urls, crawl_info = crawl_media(session, base_url)
    if not media_urls and not embed_urls:
        return {"media_items": [], "crawl_info": crawl_info, "downloaded_count": 0, "download_dir": None}, []

    findings = []
    items = []
    exif_checked = 0
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
        want_download = download and item["kind"] in ("image", "video") and downloaded < max_files

        if want_exif or want_download:
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

    for url in embed_urls:
        host = urlparse(url).netloc.lower()
        platform = next((d for d in VIDEO_EMBED_DOMAINS if d in host), host)
        items.append({"url": url, "kind": "embedded", "status": None, "content_type": platform,
                       "size": None, "suspicious_path": False})

    return {"media_items": items, "crawl_info": crawl_info, "downloaded_count": downloaded,
            "download_dir": os.path.relpath(download_dir, APP_DIR) if download_dir else None,
            "embedded_count": len(embed_urls)}, findings


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
    bogus_password = "not_a_real_password_123"
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
        findings.append(Finding("Auth", "SQLi login-bypass test has an unreliable baseline", "info",
                                 "The fail_text you supplied wasn't found on a known-bad login, so the "
                                 "content-comparison technique can't be trusted here (the time-based technique "
                                 "below still applies).",
                                 "Double-check the exact text shown on a failed login and re-run.", confidence="Informational"))

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
        elif marker in r.text:
            rows.append({"variant": name, "result": "partially reflected (likely encoded)"})
        else:
            rows.append({"variant": name, "result": "not reflected"})
    return {"rows": rows, "status": "not_confirmed"}, []


def check_idor(session, url_template, ids, cookie_a, cookie_b):
    """For each resource ID owned by test account A, checks it three ways:
    with account B's session (cross-account access), and with no auth at
    all (fully public exposure) - two distinct severities, since a page
    that's public-by-design isn't the same bug as one that leaks across
    accounts. Both accounts must be ones you created and control."""
    headers_b = {"Cookie": cookie_b}
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
            row["anonymous_code"] = None

        if row.get("anonymous_code") == 200:
            row["status"] = "PUBLIC"
            findings.append(Finding("IDOR", f"Resource id={rid} is readable with no authentication at all", "high",
                                     "An unauthenticated request returned HTTP 200 for a resource that presumably "
                                     "belongs to a specific account.",
                                     "Require authentication for this route, or confirm the resource is meant to be public.", confidence="Confirmed"))
        elif r_b.status_code == 200:
            row["status"] = "EXPOSED"
            findings.append(Finding("IDOR", f"Account B accessed resource id={rid} owned by account A", "high",
                                     f"HTTP {r_b.status_code} returned when account B's session requested a "
                                     "resource created by account A.",
                                     "Enforce ownership/role checks server-side on every resource lookup, "
                                     "not just in the UI.", confidence="Confirmed"))
        elif r_b.status_code in (401, 403, 404):
            row["status"] = "denied"
        else:
            row["status"] = "unexpected"
        rows.append(row)
    return {"rows": rows}, findings


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
                               f"One of the {len(passwords)} tested common passwords logged in successfully "
                               "(value withheld from this report).",
                               "Rotate that password immediately and enforce a stronger password policy / rate limiting.", confidence="Confirmed")
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
