# WebVulnScanner

A local web app for checking your own website's security posture. Runs only
on your machine (`localhost:5000`) — it is not deployed anywhere and has no
way to be used against a target you didn't type in yourself.

## Authorized use only

Only scan domains you own or have explicit permission to test. The tool
requires you to tick an authorization checkbox before every scan; this is
enforced server-side, not just in the UI.

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
  query parameters automatically, so you don't have to hand-supply every page
- Reflected-XSS canary, error-based SQLi, and boolean-based blind-SQLi probes
  on every parameter found by the crawl (or a URL you supply), one to three
  non-destructive requests per parameter

Every scan computes a weighted 0–100 risk score (critical/high/medium/low
findings each cost points) and saves the full report as a timestamped JSON
file in `reports/` so you can diff results between runs.

**Forms are listed, never auto-submitted.** The crawler records `<form>`
action/method/inputs for visibility, but only ever sends GET requests with
query parameters — it will not submit a real login, signup, or contact form
on your site.

## Setup

```
cd WebVulnScanner
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000 in your browser.

## Notes on accuracy

This tool caught and fixed a real false positive during development: an
early version of the port check flagged Cloudflare's edge answering on
alternate ports (8080/8443) as "unexpected open ports," when it was actually
just Cloudflare's anycast network accepting connections network-wide, not an
exposed origin service. The check now inspects the actual response and only
raises a high-severity finding when something *unbranded* (not your CDN)
responds — a genuine signal worth investigating. Treat every finding as a
lead to verify manually, not a certainty — that's true of any scanner,
including expensive commercial ones.

## What this tool intentionally does not do

- IDOR / broken access control across roles, JWT/session tampering, business
  logic abuse, brute-force/lockout testing, subdomain takeover, or anything
  requiring an authenticated session — these need human judgment about what
  "should" be allowed. See the "Advanced Manual Attack-Simulation Techniques"
  section of the companion PDF guide (`Website_Security_Testing_Guide.pdf`).
- Full CVE-level dependency scanning — run `npm audit` / `snyk test` /
  `semgrep` on your actual source repo for that (also covered in the PDF).
