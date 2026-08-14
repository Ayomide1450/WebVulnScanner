# WebVulnScanner

[![GitHub repo](https://img.shields.io/badge/GitHub-WebVulnScanner-blue?logo=github)](https://github.com/Ayomide1450/WebVulnScanner)

A multi-tenant website security-checkup SaaS: sign up, create an organization,
run scans against domains you own, and track results across a dashboard with
report history and diffing. Every scan route still requires a server-side-
enforced authorization checkbox before it will touch a target — that
constraint predates and survives the SaaS conversion.

## Authorized use only

Only scan domains you own or have explicit permission to test. Every scan
form requires an authorization checkbox, enforced server-side. The most
intrusive checks (reflected/stored XSS, SQLi, IDOR, brute-force) are further
gated behind **domain-ownership verification** (DNS TXT record or
`/.well-known/` file) tied to your organization — ticking a checkbox alone
isn't enough to unlock those.

## Plans / entitlement tiers

| Tier | Unlocks |
|---|---|
| **Free** | Headers, cookies, TLS, HTTPS redirect, sensitive-path probing, robots/sitemap review, DNS/email security (SPF/DMARC/CAA), outdated-JS detection, exposed-secrets scan, SRI check |
| **Paid** | + same-origin crawl, open-port scan, CORS misconfiguration, dangerous HTTP methods, open-redirect probing, directory-listing exposure, media/EXIF discovery scan |
| **Org-verified** (paid + verified domain) | + reflected XSS/SQLi canaries, SQLi login-bypass, rate-limited brute-force, UNION/error/time-based SQLi, stored XSS, cross-account IDOR |

Billing is self-built crypto invoicing (USDT/USDC on Polygon, confirmed via
the Polygonscan API) — see `webvulnscanner/billing.py`.

## Architecture

`app.py` is a thin factory shim; everything lives in the `webvulnscanner/`
package as Flask blueprints:

| Module | Responsibility |
|---|---|
| `auth_routes.py` | Signup, login, logout, email verification |
| `org_routes.py`, `domain_verification.py` | Org admin, invites, domain-ownership verification |
| `billing_routes.py`, `billing.py` | Crypto invoices, plan activation |
| `entitlements.py` | Maps org plan → `Tier`, gates individual checks |
| `scan_routes.py`, `scan_engine.py`, `checks.py` | Async scan execution (`/scan/<id>/events` for live progress), the three scan orchestrators, and every individual check function |
| `models.py` | `Organization`, `User`, `DomainVerification`, `Scan`, `Report`, `Subscription`, `CryptoInvoice` (SQLAlchemy) |
| `public_routes.py` | Marketing landing page |

Scans run in a background thread per request and report progress over an
event stream; results are persisted as `Report` rows (and still written to
`reports/` as JSON) so they can be diffed via `/scan/<id>/compare/<other_id>`.

## What it checks

- HTTP → HTTPS redirect
- TLS certificate validity and expiry
- Security headers (CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy,
  Permissions-Policy, COOP/CORP) with a letter grade
- Cookie flags (Secure / HttpOnly / SameSite)
- Common sensitive file/path exposure (`.env`, `.git`, backups, etc.)
- `robots.txt` / `sitemap.xml` disclosure review
- Common ports on the resolved IP — with response-based classification, not
  just "is the TCP handshake open," so CDN edge noise (Cloudflare/Vercel/etc.
  accepting connections on alternate ports) isn't reported as a real exposed
  service
- CORS misconfiguration (reflected `Origin` + `Allow-Credentials: true`)
- Dangerous HTTP methods left enabled (PUT/DELETE/TRACE/CONNECT)
- Open-redirect probing on common redirect parameter names
- Directory listing exposure on common asset paths
- Mixed content (http:// resources on an https:// page)
- DNS email-security hygiene: SPF, DMARC, CAA records
- A best-effort check for known-outdated JS libraries referenced by name/version
- A lightweight same-origin crawl (depth 1) that discovers linked URLs with
  query parameters automatically
- Reflected-XSS canary, error-based SQLi, and boolean-based blind-SQLi probes
  on every parameter found by the crawl (or a URL you supply)
- Same-origin media/image crawl with EXIF/GPS leakage detection and optional
  download-to-disk
- SQLi login-bypass, rate-limited brute-force (5-attempt cap), UNION/error/
  time-based SQLi, stored-XSS (proven via marker string, no cookie
  exfiltration), and cross-account IDOR — all opt-in, credential-driven, and
  gated behind Org-verified + domain-ownership proof

Every scan computes a weighted 0–100 risk score (critical/high/medium/low
findings each cost points) and saves a full report you can revisit and diff
against past runs from the dashboard.

**Forms are listed, never auto-submitted.** The crawler records `<form>`
action/method/inputs for visibility, but only ever sends GET requests with
query parameters.

## Setup

```
cd WebVulnScanner
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env   # then set SECRET_KEY at minimum
python app.py
```

Run `flask db upgrade` once (schema is Alembic-owned, not auto-created) before `python app.py`.
Then open http://127.0.0.1:5000. See `docs/env-vars.md` for every supported variable (DB URL,
crypto billing config, email mode — `EMAIL_MODE=console` by default, which just prints
verification/invite emails to stdout, Cloudflare Turnstile bot-check keys, etc.).

### Deployment

Production runs on [Fly.io](https://fly.io) (`Dockerfile` + `fly.toml`) rather than a serverless
platform — this app runs each scan as a background `threading.Thread` and has an in-process
scheduler, both of which need a persistent process, not scale-to-zero. `render.yaml`/`Procfile`
are kept for Render as an alternative. See `docs/env-vars.md`'s "Deploying on Fly.io" section for
the full secret list.

Scan reports are stored in Postgres (`Report.data`), not local disk — required for correctness on
any multi-machine deployment, since local disk is per-machine and isn't shared.

### Platform administration

A small set of cross-org operator actions (currently: approving/rejecting a domain-deletion
request) live behind a separate `User.is_platform_admin` flag, distinct from any org's own
`ORG_ADMIN` role. Nothing in the app can grant this flag — only:

```
flask grant-platform-admin someone@example.com
```

Granted accounts get a "Platform Admin" nav link to `/platform-admin`.

`SECRET_KEY` is required — the app refuses to start without it (it signs
session cookies, the remember-me cookie, and org-invite tokens). For local
development only, set `ALLOW_INSECURE_DEV_SECRET_KEY=true` instead. Session
cookies also default to `Secure` (HTTPS-only); set `SESSION_COOKIE_SECURE=false`
if you're testing locally over plain `http://`.

AI-assisted remediation summaries (Paid tier and above) need `GROQ_API_KEY`
set to a free Groq API key (https://console.groq.com) — without it, scans
still run and reports still generate, they just skip that section.
`GROQ_MODEL` defaults to `llama-3.1-8b-instant`.

## Notes on accuracy

This tool caught and fixed a real false positive during development: an
early version of the port check flagged Cloudflare's edge answering on
alternate ports (8080/8443) as "unexpected open ports," when it was actually
just Cloudflare's anycast network accepting connections network-wide, not an
exposed origin service. The check now inspects the actual response and only
raises a high-severity finding when something *unbranded* (not your CDN)
responds. Treat every finding as a lead to verify manually, not a certainty.

## What this tool intentionally does not do

- JWT/session tampering, business-logic abuse, subdomain takeover — these
  need human judgment about what "should" be allowed. See the "Advanced
  Manual Attack-Simulation Techniques" section of the companion PDF guide
  (`Website_Security_Testing_Guide.pdf`).
- Full CVE-level dependency scanning — run `npm audit` / `snyk test` /
  `semgrep` on your actual source repo for that (also covered in the PDF).
