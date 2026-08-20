# WebVulnScanner

## What This Is

A multi-tenant Flask SaaS ("Autonomous Security Validation Platform") for security engineers and
security-minded teams: sign up, create an organization, run rule-based vulnerability scans
(passive → active → intrusive) against domains you own, and track results across a dashboard with
report history and diffing. Detection is 100% rule-based; an AI layer (Groq) only explains and
prioritizes findings, never generates them. As of v1.1, the app also meets a "production ready"
bar across UI/UX, accessibility, responsiveness, security, and SEO — not just feature-complete.

## Core Value

Security engineers can trust WebVulnScanner to run safe, authorization-gated, non-destructive
scans against their own infrastructure and get findings they can act on — without it ever
weakening its safety guarantees to become a general attack tool.

## Business Context

- **Customer**: Security engineers and security-minded teams evaluating/running checks against
  infrastructure they own; also usable by solo devs/small teams in a lighter mode.
- **Revenue model**: Self-built crypto invoicing (USDT/USDC on Polygon via the Polygonscan API),
  tiered plans (Free / Paid / Org-verified).
- **Success metric**: *Inferred/proposed, not explicitly confirmed by the user* — the product
  supports a real continuous-scanning workflow (assets registered once, monitored over time) as
  opposed to only one-shot, human-triggered scans. Revisit and confirm with the user once Phase 1
  ships.
- **Strategy notes**: Ranked gap analysis from a prior session (originally captured in
  `handoff.md`'s "Strategic direction" section, not present as a file in this worktree — summary
  carried forward into this document's Context section below) informs this milestone's phase
  sequencing.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

- ✓ Passive/active/intrusive scan tiers (Free/Paid/Org-verified) with `entitlements.py` gating
- ✓ Server-enforced authorization checkbox + SSRF-safe-hostname guard on every scan submission
- ✓ Domain-ownership verification (DNS TXT / `.well-known`) gating the most intrusive checks
- ✓ Async scan execution with live SSE progress feed (base scans)
- ✓ AI-assisted remediation summaries (Groq, Paid+) that explain/prioritize but never generate findings
- ✓ API exposure scan + media/HLS/DASH stream discovery (`/scan-api`) — shipped 2026-08-05
- ✓ Terms/Privacy pages, site footer, Postgres connection-pooling fix, visual polish pass,
  keep-alive heartbeat — shipped 2026-08-07
- ✓ Alembic/Flask-Migrate schema migrations, replacing the old `db.create_all()`-only approach

### Validated (v1.0, shipped 2026-08-13)

- ✓ Persistent asset inventory + continuous/scheduled scanning (`Asset` model, in-process scheduler)
- ✓ API/CLI-first programmatic workflow (`ApiToken`, `/api/v1/*`, `cli/wvs.py`)
- ✓ Compliance-framework mapping (OWASP Top 10) on findings and reports
- ✓ Production hardening (multi-worker-safe rate limiting via `RATELIMIT_STORAGE_URI`, orchestrator
  test coverage for all 4 scan types, invite-flow completion)
- ✓ Fly.io production deploy, platform-admin panel (cross-org visibility, domain-deletion
  separation-of-duties), DB-backed report storage (`Report.data`), cross-org domain-scan block,
  Cloudflare Turnstile on signup, billing monthly/annual cycles

### Validated (v1.1, shipped 2026-08-20)

- ✓ New Scan flow redesigned as a guided Select Domain → Select Type → Confirm Authorization →
  Start Scan wizard, including an "Advanced" Smart Setup deviation (D-02a) beyond the original spec
- ✓ One canonical design-system token layer (typography/spacing/component/container) in `base.html`,
  fanned out across every template — no local drift left unconsolidated
- ✓ Full responsive + accessibility audit and fixes (320px–1280px, keyboard/AT operability, heading
  hierarchy, WCAG AA contrast) with standing regression locks (`tests/test_accessibility.py`)
- ✓ Full security re-audit across the v1.0-added API/scheduler/admin surfaces: cross-org IDOR
  enumeration lock, CSRF enforcement proof, `_SSRFSafeSession` redirect-hop guard (SEC-03, the
  phase's one real vulnerability fix), injection/traversal sweep, open-redirect/error-leakage/
  secrets-sweep coverage — closed with a real-process HTTP probe, not just the test client
- ✓ SEO (dynamic robots.txt/sitemap.xml, meta/OG/Twitter tags, favicons), a data-size-independent
  N+1 audit (none found) plus real pagination on every unbounded list, and closed empty/submitting/
  duplicate-scan/timeout UX states

## Current Milestone: v1.2 Live Verification Closeout

**Goal:** Actually run the `checkpoint:human-verify` gates deferred at v1.1 close (phases 5, 6, 7,
9 — responsive four-width sweep, keyboard/AT operability, WCAG AA contrast, live scan-progress
feed re-check, and end-to-end UX flow confirmation) against the real Fly deployment, and fix any
real defect found. No new feature scope — this closes debt v1.1 explicitly carried forward rather
than compounding it further.

### Active

- [ ] Four-width responsive sweep (320px/375px/768px/1280px) of every page against
      `https://webvulnscanner.fly.dev`, per 07-07-PLAN.md's original checklist
- [ ] Keyboard-only operability walkthrough (every interactive element reachable/operable, visible
      focus state)
- [ ] WCAG AA contrast confirmation with a real contrast-checking tool (not just the token math)
- [ ] Live scan-progress feed (SSE) re-confirmation at all four widths against a real running scan
- [ ] End-to-end confirmation that Phase 5's New Scan wizard and Phase 9's UX states (empty/
      submitting/duplicate-scan/timeout) actually behave correctly in a live browser
- [ ] Fix any real defect found during the above (scoped to what the sweep surfaces — not a
      redesign)

### Out of Scope

<!-- Explicit boundaries. Includes reasoning to prevent re-adding. -->

- Plugin/third-party check-extensibility system — acknowledged gap (ranked #2 in the prior
  session's gap analysis) but deprioritized this milestone: no concrete requirement or user
  request to build it now, and the recommendation given previously was to build continuous
  scanning + asset inventory first since it's the harder-to-defer, highest-leverage gap. Revisit
  next milestone.
- Self-hostable/open-core deployment model — billing/SaaS shape is locked (see Key Decisions);
  explicitly not under reconsideration this milestone.
- Replacing crypto-invoice billing with a different payment model — locked, not a variable to
  redesign around.

## Context

- **Stack**: Python 3.12 / Flask app-factory pattern, blueprints for `auth`/`org`/`billing_bp`/
  `scan`/`public`/`asset`/`api_v1`/`admin` (grew during v1.0), SQLAlchemy models, Alembic-managed
  migrations, deployed to **Fly.io** (a real always-on VM — chosen over Render specifically because
  it matches this app's `threading.Thread`-per-scan + in-process scheduler model; `Dockerfile`/
  `fly.toml` committed) with a partial/limited Vercel alternate target that does not support the
  scan-execution/SSE routes as-is.
- **Current scan model is one-shot**: a user submits a target URL per scan, a `Scan` row is
  created, a daemon background thread runs the orchestrator, and a `Report` row is saved. There is
  no persistent "Asset" entity that outlives a single scan — this is the specific gap this
  milestone's Phase 1 addresses.
- **Prior strategic direction** (ranked gap analysis vs. tools like Nuclei/Trivy/Semgrep,
  discussed but not committed): (1) no continuous/scheduled scanning + asset inventory — the
  single biggest gap, requires a new persistent-asset data model instead of one-off `Scan` rows;
  (2) no plugin/check architecture; (3) not API/CLI-first; (4) no compliance/framework mapping
  (OWASP ASVS/Top 10/PCI-DSS); (5) trust/self-hostable/open-core question (deprioritized — billing
  shape is locked, see Key Decisions). The recommendation given at the time: don't try to
  out-feature Nessus/Qualys — lean into existing differentiation (SSRF/authorization rigor, live
  feed, AI-assisted triage) and build continuous scanning + asset inventory first, since API/CLI
  and compliance-mapping become materially easier to justify once an asset actually persists
  across scans.
- **Known, documented, accepted residual gaps** (not regressions, not silently discovered):
  `checks.is_ssrf_safe_hostname()` is a submission-time check only — no DNS-rebinding protection;
  Flask-Limiter's in-memory rate limiting is not multi-worker-safe (latent today under
  `--workers 1`, addressed in Phase 4); the SSE progress-feed polling loop has no per-scan
  timeout, which is fine on Render's long-lived-connection model but incompatible with serverless.
- **Codebase evidence changes the starting condition assumed by the prior gap analysis**:
  `README.md` and an earlier draft of this project's own product doc both still describe schema
  changes as requiring `db.create_all()`-only workarounds ("add a new table instead of altering
  one"). That's now stale — the codebase has since adopted Alembic/Flask-Migrate
  (`migrations/`, confirmed via `CLAUDE.md` and `webvulnscanner/__init__.py`). A new `Asset` table
  (and any schema evolution it needs later) is a normal `flask db migrate` operation, not the
  workaround-requiring situation the original gap analysis implicitly assumed. This makes Phase 1
  more straightforward than it would have looked a few sessions ago.
- **Two SPECs already shipped** before this milestone (context only, not open work): API exposure
  scan + media/HLS/DASH stream discovery (2026-08-05), and page-completion/visual-polish
  (2026-08-07, legal pages, footer, connection-pooling fix, keep-alive heartbeat). Their
  constraints (GET-only probing, SPA-response guards, reuse-existing-design-system) exemplify the
  house conventions this milestone's new work should also follow.

## Constraints

- **Tech stack**: Flask/Python 3.12, no runtime change this milestone — new work extends the
  existing app-factory/blueprint pattern, the `checks.py` → `scan_engine.py` → `entitlements.py`
  layering, and the now-Alembic-migrated SQLAlchemy schema.
- **Safety-critical code is frozen**: never weaken or remove the `authorized*` server-side
  checkboxes, `entitlements.py` tier/domain-verification gating, or
  `checks.is_ssrf_safe_hostname()`. Every new scan-trigger path added this milestone (scheduled
  scans, API-triggered scans) must route through the same gates as manual web-UI scan submission —
  no shortcut path that bypasses authorization/SSRF/tier checks.
- **Billing/SaaS shape locked**: crypto-invoice billing (USDT/USDC on Polygon) and the
  Free/Paid/Org-verified tier model are locked per prior product decision; do not propose
  replacing them as part of any phase in this milestone.
- **Deployment target**: Render (gunicorn, single worker today), not Vercel. New background or
  scheduled-execution work must fit a threaded-gunicorn deployment without requiring a
  re-architecture to serverless.
- **Test coverage gap on 3 of 4 orchestrators**: `run_advanced_scan`/`run_media_scan`/
  `run_api_scan` have no dedicated tests today (only `run_scan` does, via
  `tests/test_scan_events.py`). Work that builds on these orchestrators (e.g. scheduled scans)
  should not further widen this gap — closing it is addressed directly in Phase 4.
- **Detection stays rule-based**: the AI layer (Groq) only explains/prioritizes existing findings;
  it must never generate or auto-remediate findings.
- **No formatter/linter/CI style gate** exists in the repo beyond `pytest` — match existing
  hand-written style conventions (see `.planning/codebase/CONVENTIONS.md`) rather than introducing
  new tooling as part of feature work.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Billing/SaaS/org-tier shape stays as-is (crypto invoicing, Free/Paid/Org-verified tiers) | User confirmed this is locked for this milestone; self-hostable/open-core remains an explicitly deprioritized, undecided question | ✓ Locked, held through v1.1 |
| Phase 1 = persistent asset inventory + continuous/scheduled scanning | Ranked gap analysis identifies this as the single biggest competitive gap and the dependency that makes API/CLI (Phase 2) and compliance-mapping (Phase 3) meaningfully easier to justify and build | ✓ Good — v1.0 shipped |
| Plugin/check-extensibility system (ranked gap #2) deferred out of v1 | No concrete requirement or user request for it this milestone; recommendation prioritized continuous scanning + API/CLI + compliance-mapping ahead of it | — Pending (still deferred, revisit for v1.2) |
| Production Hardening (Phase 4) scoped to include multi-worker rate-limiting, orchestrator/org-route test coverage, and remaining visual-polish debt from `.planning/codebase/CONCERNS.md` | Milestone goal is explicitly "production ready" — these are the concrete, evidence-backed gaps between current state and that bar, not speculative work | ✓ Good — v1.0 shipped |
| v1.1 phase order: New Scan redesign (5) → Design System (6) → Responsive/A11y (7) → Security (8) → SEO/Perf/UX States (9) | Each phase builds on a stable surface rather than auditing work about to change underneath it (design-system before responsive audit, redesign before both) | ✓ Good — zero rework needed across phase boundaries |
| SEC-03's redirect guard implemented via `_mk_session()` overriding `get_redirect_target()`, not `resolve_redirects()` | An earlier attempt at `resolve_redirects()` was tested against a real local-server harness and found not to work — that loop sends a hop before yielding it for inspection, too late to block | ✓ Good — proven against a real HTTP server, not just the test client |
| Phase 9 executed leanly (4 PLAN.md written directly, no researcher/planner/checker subagent cascade) | User flagged the standard multi-agent flow as too token-heavy for a phase this scoped; explicit request for a straight-through continuation | ✓ Good — zero merge conflicts across all 4 plans, 802 tests passing |
| Phases 5/6/7/9's live-verification human-checkpoints closed via override, not answered | Explicit user instruction not to block milestone progress on unanswered human checkpoints; all underlying implementation is done and test-covered | ⚠️ Revisit — schedule an actual live-browser pass early in v1.2 to close this out for real |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-08-20 — milestone v1.2 (Live Verification Closeout) started*
