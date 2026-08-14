# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary: security engineers and security-minded teams evaluating and running checks against
infrastructure they own or are authorized to test. They expect tooling that fits how security
engineers actually work — not a general "is my website safe" consumer checkup, though the app is
currently also usable by solo devs/small teams in that lighter mode.

## Product Purpose

A multi-tenant website security-checkup SaaS ("Autonomous Security Validation Platform"): sign
up, create an organization, run scans against domains you own, and track results across a
dashboard with report history and diffing. Scans run passive → active → intrusive, gated by plan
tier and, for the most intrusive checks, by verified domain ownership.

## Positioning

Not a bug-bounty marketplace — no external hackers, everything stays between the org and the
platform. Positioned as an "Autonomous Security Validation Platform": rule-based detection
engine (SSRF-guarded, authorization-enforced) with an AI layer that explains/prioritizes findings
rather than generating them. Currently strongest as a one-shot passive/light-active recon engine
with genuinely good safety engineering; the product's known competitive gap versus tools like
Nuclei/Trivy/Semgrep is the lack of continuous/scheduled scanning, an asset inventory, and an
API/CLI-first workflow — acknowledged in project history as future direction, not yet built.

## Operating Context

- Every scan route requires a server-side-enforced authorization checkbox before touching a
  target — a hard rule that predates and survives the SaaS conversion.
- The most intrusive checks (reflected/stored XSS, SQLi, IDOR, brute-force) are further gated
  behind domain-ownership verification (DNS TXT record or `/.well-known/` file) tied to the
  organization.
- Scans run async in a background thread with live progress over an event stream
  (`/scan/<id>/events`); results persist as `Report` rows and are diffable
  (`/scan/<id>/compare/<other_id>`).
- Billing is self-built crypto invoicing (USDT/USDC on Polygon via the Polygonscan API) — locked
  as the current model; not under active reconsideration despite an open strategic discussion
  about self-hostable/open-core alternatives.

## Capabilities and Constraints

- Tiers: Free (headers, cookies, TLS, HTTPS redirect, sensitive-path probing, robots/sitemap,
  DNS/email security, outdated-JS, exposed-secrets, SRI), Paid (+ same-origin crawl, open-port
  scan, CORS misconfig, dangerous HTTP methods, open-redirect, directory-listing exposure,
  media/EXIF discovery), Org-verified (+ reflected XSS/SQLi canaries, SQLi login-bypass,
  rate-limited brute-force, UNION/error/time-based SQLi, stored XSS, cross-account IDOR).
- Detection is 100% rule-based; an AI layer (Groq/Llama 3.1 8B Instant) only explains and
  prioritizes existing findings for Paid+ tier — it never generates findings itself, and its
  prompt is injection-hardened against scanned-site response content.
- No migrations system: `models.py` uses `db.create_all()` only. Adding a column to an existing
  table won't apply to a live DB — schema changes require a new table.
- Explicitly undecided / open per project history, not to be treated as settled: whether a
  plugin/check system, API/CLI, compliance-framework mapping (OWASP ASVS/Top 10/PCI-DSS), or
  self-hostable/open-core model get built. These are acknowledged gaps, not commitments.

## Brand Commitments

- Name: WebVulnScanner.
- Existing dark OLED design system already implemented in `templates/base.html`:
  `--bg:#020617`, `--accent:#22c55e` (green), Fira Sans/Code typography. Marketing hero uses a
  terminal-boot animation + typewriter headline with deliberately honest copy (no inflated
  claims).

## Evidence on Hand

- Working templates for marketing, auth, dashboard, org admin, domain verification, billing,
  scan flows (new/advanced/media/API), scan progress/report/compare, and legal pages — see
  `templates/`.
- `README.md` and `handoff.md` document architecture, check inventory, and project history in
  detail; treat as authoritative supporting context alongside this file.
- No customer testimonials, case studies, press, or third-party proof assets exist — future work
  must not fabricate them.

## Product Principles

- Authorization and safety engineering (server-enforced checkboxes, SSRF guard,
  domain-verification gating) are non-negotiable and must never be weakened for UX convenience.
- Detection stays rule-based and auditable; AI assists interpretation, never invents findings.
- Copy and claims stay honest — no inflated security-marketing language.
- Build for how security engineers actually evaluate tooling, even while the product currently
  also serves lighter consumer use.
- Billing/tier/org-account SaaS shape is a locked constraint for design work, not a variable to
  redesign around.
