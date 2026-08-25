# Community Check YAML Schema

This document defines the YAML format for community-contributed security
checks.  Community checks are **HTTP request/response pattern-match only** —
the safest, most common class of check a contributor would write.

## Directory structure

```
checks/
  community/
    *.yaml              ← community check definitions
    SCHEMA.md           ← this file
```

Place `.yaml` files in `checks/community/`.  They are loaded at scan
startup, validated, and merged into the same check pipeline as built-in
checks.

## Schema

```yaml
# REQUIRED — snake_case, unique, 1-64 chars starting with a letter.
# The loader prefixes "community_" to avoid name collisions with built-ins.
name: my_custom_check

# REQUIRED — human-readable label shown in the scan-progress feed and report.
display_label: My custom security check

# REQUIRED — brief description of what the check detects.
description: >
  Describes the security issue this check identifies.

# REQUIRED — OWASP Top 10:2021 category for compliance mapping.
owasp_category: A05:2021 - Security Misconfiguration

# REQUIRED — one of the 11 security domains the report groups findings into:
#   Attack Surface, Authentication, Authorization, API Security,
#   Client Security, Configuration, Secrets, DNS & Domains,
#   TLS, Dependencies, Privacy
security_domain: Configuration

# REQUIRED — minimum tier required to run this check:
#   free        → runs for all users
#   paid        → requires a paid plan
#   org_verified → requires org-verified domain ownership
tier: paid

# OPTIONAL — icon category for the live feed (default: "shield").
# One of: shield, lock, network, folder, mail, bug
icon_category: lock


# REQUIRED — list of HTTP requests to make (max 10).
# Each entry is a single GET request with optional query-parameter injection.
requests:
  - path: /                    # URL path appended to base_url
    method: GET                # ONLY GET is allowed (enforced at load time)
    param_name: q              # OPTIONAL — query parameter name
    payload: test              # OPTIONAL — value for param_name
    timeout: 8                 # OPTIONAL — per-request timeout (seconds, max 8)

    # REQUIRED — conditions that must ALL match for the request to count
    # as a finding.  At least one condition must be specified.
    match:
      status_code: 200         # OPTIONAL — exact status code match
      required_headers:        # OPTIONAL — headers that must be present
        - X-Frame-Options
      forbidden_headers:       # OPTIONAL — headers that must NOT be present
        - Server
      body_contains: "login"   # OPTIONAL — substring match in response body
      body_regex: '(?i)error' # OPTIONAL — regex match in response body


# REQUIRED — finding metadata produced when at least one request matches.
finding:
  title: "Security issue detected"       # REQUIRED — finding title
  severity: medium                        # REQUIRED — critical|high|medium|low|info|pass
  description: >                          # REQUIRED — detailed description
    What was found and why it matters.
  recommendation: >                       # OPTIONAL — remediation advice
    How to fix the issue.
  confidence: "Strong Evidence"           # OPTIONAL — defaults to "Confirmed"
  cwe: "CWE-200"                         # OPTIONAL — CWE ID if applicable
```

## Example

See `missing_x_content_type.yaml`, `server_version_disclosure.yaml`, and
`exposed_admin_panels.yaml` in this directory for working examples.

## Safety constraints

Community checks are restricted to a narrow, safe subset of HTTP probing:

| Constraint | Enforcement |
|---|---|
| GET-only requests | Load-time validation rejects non-GET methods |
| Max 10 requests per check | Load-time validation rejects longer lists |
| Same-origin only | `base_url` is the scan target; no cross-origin requests |
| Regex patterns compiled with stdlib `re` | Invalid regexes rejected at load time |
| No arbitrary Python code | YAML only — `yaml.safe_load` prevents code execution |
| No filesystem access | Check functions only receive `base_url` and `session` |
| Tier-gated | Community checks default to `org_verified` (most restrictive) |

## How it works

1. At scan startup, `community_checks.load_community_checks()` reads every
   `*.yaml` file from `checks/community/`.
2. Each file is validated against the schema above.  Malformed files cause
   a load-time error (fail closed — never silently skipped).
3. Valid checks are registered into the global registries (`FEATURE_REQUIREMENTS`,
   `CHECK_LABELS`, `CHECK_CATEGORY`, `CHECK_COMPLIANCE`, `SECURITY_DOMAIN_MAP`)
   so they flow through the same tier-gating, live-feed, and report-rendering
   code as built-in checks.
4. `build_community_jobs()` creates `(data, findings)` callables that are
   merged into `run_scan()`'s jobs dict and dispatched via the same
   `ThreadPoolExecutor` as built-in checks.
