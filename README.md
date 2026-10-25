# Glassbox

[![GitHub repo](https://img.shields.io/badge/GitHub-glassbox-blue?logo=github)](https://github.com/Ayomide1450/Glassbox)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)](https://www.python.org/)

A multi-tenant website security-checkup SaaS: sign up, create an organization,
run scans against domains you own, and track results across a dashboard with
report history and diffing. Every scan route requires a server-side-enforced
authorization checkbox before it will touch a target.

## Authorized use only

Only scan domains you own or have explicit permission to test. Every scan
form requires an authorization checkbox, enforced server-side. The most
intrusive checks (reflected/stored XSS, SQLi, IDOR, brute-force) are further
gated behind **domain-ownership verification** (DNS TXT record or
`/.well-known/` file) tied to your organization.

## Plans / entitlement tiers

| Tier | Unlocks |
|---|---|
| **Free** | Headers, cookies, TLS, HTTPS redirect, sensitive-path probing, robots/sitemap review, DNS/email security (SPF/DMARC/CAA), outdated-JS detection, exposed-secrets scan, SRI check |
| **Paid** | + same-origin crawl, open-port scan, CORS misconfiguration, dangerous HTTP methods, open-redirect probing, directory-listing exposure, media/EXIF discovery scan |
| **Org-verified** (paid + verified domain) | + reflected XSS/SQLi canaries, SQLi login-bypass, rate-limited brute-force, UNION/error/time-based SQLi, stored XSS, cross-account IDOR |
| **SSO** | SAML 2.0 single-sign-on for organizations with verified domains |

Billing is self-built crypto invoicing (USDT/USDC on Polygon, confirmed via
the Polygonscan API).

## Architecture

`app.py` is a thin factory shim; everything lives in the `glassbox/`
package as Flask blueprints:

| Module | Responsibility |
|---|---|
| `auth_routes.py` | Signup, login, logout, email verification |
| `sso_routes.py` | SAML 2.0 SSO login initiation, ACS callback, JIT provisioning |
| `org_routes.py`, `domain_verification.py` | Org admin, invites, SSO config, domain-ownership verification |
| `billing_routes.py`, `billing.py` | Crypto invoices, plan activation |
| `entitlements.py` | Maps org plan to tier, gates individual checks |
| `scan_routes.py`, `scan_engine.py`, `checks.py` | Async scan execution, live progress feed, four scan orchestrators, every individual check function |
| `regressions.py` | Continuous regression tracking — diffs findings across scheduled scans |
| `audit.py` | Append-only audit trail for security-sensitive actions |
| `pdf_report.py`, `sarif.py`, `ndjson_report.py` | Export formats (PDF, SARIF, NDJSON/Splunk HEC) |
| `ai_summary.py` | AI-assisted remediation summaries (Groq/open-source LLM) |
| `selftest.py` | Built-in detection verification engine |
| `webhooks.py` | Outbound webhook delivery with HMAC signing |
| `api_routes.py`, `api_tokens_routes.py` | REST API with token auth |
| `models.py` | SQLAlchemy models: `Organization`, `User`, `DomainVerification`, `Scan`, `ScanEvent`, `Report`, `Subscription`, `CryptoInvoice`, `SSOConfiguration` |
| `public_routes.py` | Marketing landing page |

Scans run in a background thread per request and report progress over an
event stream; results are persisted as `Report` rows so they can be diffed
via `/scan/<id>/compare/<other_id>`.

## What it checks

- HTTP to HTTPS redirect
- TLS certificate validity and expiry
- Security headers (CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy,
  Permissions-Policy, COOP/CORP) with a letter grade
- Cookie flags (Secure / HttpOnly / SameSite)
- Common sensitive file/path exposure (`.env`, `.git`, backups, etc.)
- `robots.txt` / `sitemap.xml` disclosure review
- Common ports on the resolved IP — with response-based classification, not
  just "is the TCP handshake open," so CDN edge noise isn't reported as a
  real exposed service
- CORS misconfiguration (reflected `Origin` + `Allow-Credentials: true`)
- Dangerous HTTP methods left enabled (PUT/DELETE/TRACE/CONNECT)
- Open-redirect probing on common redirect parameter names
- Directory listing exposure on common asset paths
- Mixed content (http:// resources on an https:// page)
- DNS email-security hygiene: SPF, DMARC, CAA records
- Known-outdated JS libraries referenced by name/version
- Same-origin crawl (depth 1) that discovers linked URLs with query parameters
- Reflected-XSS canary, error-based SQLi, and boolean-based blind-SQLi probes
  on every parameter found by the crawl
- Same-origin media/image crawl with EXIF/GPS leakage detection
- SQLi login-bypass, rate-limited brute-force (5-attempt cap), UNION/error/
  time-based SQLi, stored-XSS, and cross-account IDOR (opt-in, credential-driven,
  org-verified + domain-ownership required)
- API exposure: OpenAPI/Swagger/GraphQL-introspection, unauthenticated path
  wordlist, endpoints discovered from the site's own JavaScript
- Ten additional intrusive checks: SSTI, host-header injection, cache
  deception, CRLF injection, CSRF posture, subdomain takeover DNS,
  path traversal, rate-limit burst, active JWT `alg:none`, GraphQL
  argument canary

Every scan computes a weighted 0-100 risk score and saves a full report you
can revisit and diff against past runs from the dashboard.

**Forms are listed, never auto-submitted.** The crawler records `<form>`
action/method/inputs for visibility, but only sends GET requests with
query parameters during probing.

## Setup

```bash
git clone https://github.com/Ayomide1450/Glassbox.git
cd Glassbox
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env   # set SECRET_KEY at minimum
flask db upgrade
python app.py
```

Open http://127.0.0.1:5000. See `docs/env-vars.md` for every supported
variable (DB URL, crypto billing config, email mode, Cloudflare Turnstile
bot-check keys, etc.).

### Deployment

Production runs on [Fly.io](https://fly.io) (`Dockerfile`) — this app runs
each scan as a background `threading.Thread` and has an in-process scheduler,
both needing a persistent process. `render.yaml`/`Procfile` are kept as
alternatives.

Scan reports are stored in Postgres (`Report.data`), not local disk — required
for correctness on any multi-machine deployment.

### Platform administration

Cross-org operator actions live behind a separate `User.is_platform_admin`
flag, distinct from any org's own `ORG_ADMIN` role:

```bash
flask grant-platform-admin someone@example.com
```

### Environment variables

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Yes | Signs session cookies and tokens |
| `SQLALCHEMY_DATABASE_URI` | Yes | Postgres connection string |
| `GROQ_API_KEY` | No | AI remediation summaries (Paid tier+) |
| `EMAIL_MODE` | No | `console` (default), `resend` |
| `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY` | No | Cloudflare Turnstile bot check |
| `SESSION_COOKIE_SECURE` | No | Set `false` for local HTTP dev |

## Notes on accuracy

This tool caught and fixed a real false positive during development: an
early version of the port check flagged Cloudflare's edge answering on
alternate ports as "unexpected open ports," when it was actually just
Cloudflare's anycast network accepting connections network-wide. The check
now inspects the actual response and only raises a high-severity finding
when something *unbranded* responds. Treat every finding as a lead to
verify manually, not a certainty.

## What this tool intentionally does not do

- JWT/session tampering, business-logic abuse, subdomain takeover — these
  need human judgment about what "should" be allowed.
- Full CVE-level dependency scanning — run `npm audit` / `snyk test` /
  `semgrep` on your actual source repo for that.

## License

[MIT](LICENSE) &copy; 2026 Gabriel Ayomide.

You may use, modify, and distribute this software, including commercially,
provided the copyright notice and permission notice are retained. The software
is provided "as is", without warranty — see [LICENSE](LICENSE) for the full
text.

Licensing the code permissively does not loosen the operational rule above:
**only scan domains you own or have explicit written permission to test.** That
constraint is a matter of law in most jurisdictions, not of this license.
