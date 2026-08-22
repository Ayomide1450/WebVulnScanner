# Glassbox Rebrand — Design Spec

**Status:** Approved for planning. Implementation deliberately deferred until v1.1
(Phases 6-9 on the current WebVulnScanner identity) closes — see "Sequencing" below.

## 1. Product identity

- **Name:** Glassbox
- **Tagline:** "External exposure, made visible."
- **Category:** Continuous external security validation platform — explicitly not a
  "vulnerability scanner." Never use "scanner" as the product concept in user-facing text.
- **Product promise:** Make external security easy to see and act on.
- **Core loop:** Discover → Understand → Validate → Remediate → Verify → Monitor
- **Visual identity:** Unchanged. Keep the OLED-dark palette + green accent and every
  design token/component Phase 6 (Design System Consistency) already consolidated onto
  `base.html`. This is a naming/positioning/IA rebrand, not a visual-design rebrand —
  Glassbox inherits Phase 6's work rather than redoing it.

### Audience framing (unchanged from original brief, already well-scoped)

- **Developers** — fast triage, exact location of an issue, actionable remediation,
  fix verification, workflow integration.
- **Security engineers** — attack-surface visibility, evidence review, posture-over-time
  comparison, risk management.
- **Businesses** — posture summary, asset monitoring, meaningful alerts, professional
  reports, demonstrable improvement over time.

## 2. Sequencing (locked decision)

Planning and spec work happens now. Implementation starts only after the current v1.1
milestone (Phase 6 Design System Consistency → Phase 7 Responsive & Accessibility →
Phase 8 Security Re-Audit & Hardening → Phase 9 SEO/Performance/UX States) closes.
Rationale: rebranding an app that hasn't had its accessibility/security-audit pass yet
means redoing rebrand copy/QA against a moving target. Glassbox becomes its own
milestone once v1.1 ships.

## 3. Information architecture

### Top-level navigation (replaces current Dashboard/Assets/New Scan/Billing/API
Tokens/Organization/Platform Admin)

1. **Security Posture** → `/dashboard` (reframed)
2. **Attack Surface** → `/assets` (reframed — describe assets by external exposure,
   not by their scan list)
3. **Assessments** → existing scan-creation workflow (`/scan/new*`); primary CTA verb
   changes from "New Scan"/"Run Scan" to **"Run Assessment"**
4. **Findings** → new aggregate view (see §4) — read-only, built from existing data
5. **Security History** → promotes the existing `/scan/<id>/compare/<other_id>` feature
   from a report-page-only link to a first-class nav destination
6. **Organization** → unchanged structurally, terminology pass only
7. **Billing** → unchanged structurally, terminology pass only

API Tokens and Platform Admin stay reachable (likely folded under Organization/an
overflow menu — exact placement is an implementation-time UI decision, not a spec
decision) but are not part of the primary seven-item nav.

### 4. Findings — aggregate view (new route, no new database model)

`/findings` queries the caller's accessible `Report` rows using the exact same
ownership/org scoping `_check_ownership()` already enforces elsewhere in
`scan_routes.py`, parses each `report.json`'s findings list, and flattens them into one
filterable table computed server-side, per-request. No new table, no migration —
findings remain stored exactly as they are today (inside each scan's `Report.json`
blob), this view just reads across many of them at once instead of one at a time.

**Filters:** severity, confidence, asset, assessment (scan). Applied as query params to
the in-memory flattened list before render — same pattern the app already uses for
report data, not a new persistence layer.

**Confidence labels** (new, derived — not stored):
- Confirmed
- Strong Evidence
- Potential
- Informational
- Not Externally Verifiable

Confidence is derived per-finding from a new lookup table mapping each check's
category/detail pattern to one of the five tiers (e.g. a live XSS proof-of-execution →
Confirmed; a 403-blocked path probe → Potential; a passive header/cookie observation →
Informational). This follows the same "derived, not persisted" convention
`checks.CHECK_LABELS`/`checks.CHECK_CATEGORY` already establish for check metadata.

**Severity and confidence stay separate axes** — a finding keeps its existing
severity (critical/high/medium/low/info/pass) unchanged, and confidence is layered on
top as an independent second dimension. Neither replaces the other.

### 5. Explicitly out of scope this milestone

- No `Finding` database model, no fix-status tracking (open/fixed/verified/regressed),
  no cross-scan finding-identity matching. "Verify" continues to mean "re-run an
  assessment and check the finding is gone," not a tracked DB state.
- No Alerts/notifications system (new risk / new asset / regression) — this is the
  natural next feature once a real `Finding` model exists, but is not part of Glassbox
  v1.
- No visual/component redesign — Phase 6 already owns design-token consistency.
- No route, class, or internal-identifier renames. `scan_type`, the `Scan` model,
  `run_scan()`/`run_advanced_scan()`/`run_media_scan()`/`run_api_scan()`,
  `checks.py` function names, and every DB column stay exactly as-is. These are
  internal contracts, not user-facing language — renaming them is unnecessary risk for
  a positioning change and would touch migrations for no user-visible benefit.
- No changes to `authorized`/`authorized_adv`/`authorized_media`/`authorized_api`
  gating, `entitlements.py`, or `checks.is_ssrf_safe_hostname()` — CLAUDE.md's standing
  constraint against weakening these applies unchanged under the new brand.

## 6. Terminology map

Applied as a copy/IA pass across templates and route-facing strings — **not** a blind
find-and-replace. Internal/technical identifiers (Python names, route paths, DB
columns, template filenames) are unaffected unless explicitly listed.

| Old (user-facing) | New (user-facing) |
|---|---|
| WebVulnScanner (brand name, everywhere) | Glassbox |
| New Scan / Run Scan (button/CTA copy) | Run Assessment |
| Scan History | Security History |
| Scan Results / Scan Report (page heading) | Findings |
| "Scanner" as the product noun | Assessment Engine (copy only — never a class/route rename) |
| Scan (as a UI-facing noun, e.g. "your scans") | Assessment |
| Dashboard (nav label) | Security Posture |
| Assets (nav label) | Attack Surface |

Identifiers that do **not** change: `scan_type` field/param name, `Scan` model name,
`ScanStatus`, `ScanEvent`, every `run_*_scan()` function name, `checks.py` function
names, template filenames (`scan_new_base.html` etc. stay as filenames — only their
rendered copy changes), route paths (`/scan/new`, `/scan/<id>` etc. stay as URLs to
avoid breaking bookmarks/links — a redirect/vanity-URL layer is a possible future nice-
to-have, not part of this spec).

## 7. Rework surface (page/file inventory)

Every template in `templates/` gets at minimum a copy/terminology pass. Templates with
structural IA changes are called out; everything else is copy-only.

**Structural changes:**
- `base.html` — nav bar rewrite (7-item nav above), brand name/logo text, footer copy
- `dashboard.html` → reframed as Security Posture (header copy, stat-tile labels)
- `assets.html`, `asset_detail.html` → reframed as Attack Surface (exposure-first
  framing, not scan-list-first)
- `scan_new.html`, `scan_new_type.html`, `scan_new_base.html`, `scan_new_media.html`,
  `scan_new_api.html`, `scan_new_advanced.html` → "Run Assessment" CTA language
  throughout, "Assessments" as the section name
- `scan_report.html` → reframed as a Findings detail view; confidence label rendered
  alongside severity per finding
- `scan_compare.html` → promoted, reframed as Security History
- New: `findings.html` (or equivalent) + its route in `scan_routes.py` (or a new
  `findings_routes.py` blueprint, implementation's call) for the aggregate view

**Copy-only pass:** `marketing.html`, `login.html`, `signup.html`,
`forgot_password.html`, `reset_password.html`, `verify_email.html`, `terms.html`,
`privacy.html`, `billing.html`, `org_admin.html`, `org_verify_domain.html`,
`platform_admin.html`, `api_tokens.html`, `404.html`, `429.html`, `500.html`.

**Non-template surfaces:**
- `README.md` — full rewrite under the new identity (name, description, problem
  statement, target users, core capabilities, architecture, security model, domain
  ownership verification, assessment engine, reporting, dev setup, env vars, testing,
  deployment, project structure). No leftover "WebVulnScanner"/"website scanner"
  framing.
- Page `<title>`/Open Graph metadata, favicon references
- Email templates (verify-email, password-reset, org-invite) — brand name + tone pass
- `SCAN_TYPE_CARDS` blurbs and other user-facing string constants in `scan_routes.py`
- Error messages, flash messages, empty-state copy app-wide

## 8. Final repository-wide check (part of implementation, not this spec)

Once implemented: search the full repo for `WebVulnScanner`/`webvulnscanner`/`scanner`
and triage every hit — legitimate internal/technical uses (Python package name,
`.venv` paths, git history, code comments describing internal mechanics) are left
alone; user-facing strings are not. Full test suite, and a repeat of this session's
visual walkthrough (desktop + the mobile-viewport pass that didn't happen yet) against
the renamed app before considering the milestone closed.
