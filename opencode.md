# opencode.md — Session Memory

> Living memory file for this repo. **Update it at the end of every working
> session** (and whenever a meaningful change lands): what was done, what
> changed, what's next. Read it first when starting a new session.

---

## Project

**Glassbox** (v1.3+; formerly WebVulnScanner — Python package `webvulnscanner/`
and DB unchanged). Multi-tenant Flask **security platform**. **NEVER call it a
"scanner"** (user's explicit instruction) — it is a security-assessment /
expertise platform for **cybersecurity experts, security engineers, vibe
coders, and DevOps** teams: it turns website security posture into professional,
workflow-integrated output (scored reports, AI remediation, CI/CD gate
verdicts). Accounts, orgs, crypto-invoice billing, tiered entitlements
(Free / Paid / Org-verified) gate which checks a scan may run. Intrusive
checks additionally require server-verified domain ownership.

Audience lens to apply to every feature decision:
- **Security engineers/experts**: rigorous, evidence-backed findings, no
  false-positive noise, verifiable methodology.
- **DevOps**: machine-consumable API + CLI (`glassbox`), pass/fail gates for
  pipelines, deployable (Render/Fly), health checks, rate-limit backends.
- **Vibe coders**: plain-English AI summaries, guided scan pages, clear
  next-step recommendations.

## Goal

A professional security-assessment platform: four scan pipelines (base /
advanced / media / api), tier gating, live scan progress feed, AI remediation
summaries, platform admin tooling, and a CLI + REST API surface so findings
plug directly into engineering workflows (CI/CD gates, dashboards) —
deployable, tested (pytest on every push), and safe by design.

## Non-negotiable safety constraints (never weaken)

- `authorized*` server-side checkbox checks in all scan routes.
- `entitlements.py` tier + domain-verification gating before intrusive checks.
- `checks.is_ssrf_safe_hostname()` SSRF guard before any Scan row is created.
- Same-origin depth-1 crawler; forms never auto-submitted; bruteforce capped
  at 5 attempts; secrets redacted in reports; marker-only stored-XSS proof.
- AI summary prompt keeps findings framed as data-to-summarize (injection bound).

## State snapshot (last updated: 2026-08-22)

- Branch work is on top of `f27fbb4` "wip(18): Glassbox CLI (Phase 18)".
- Tests run via `pytest` (fresh Flask app per test, SQLite under tmp_path).

### Done (recent history)

- Phase 16 — Platform Admin user/org management (`feat(16)`).
- Phase 18 (wip commit) — Glassbox CLI (`cli/wvs.py`) + API additions.
- Various fix(10) UI/UX passes: nav links, CSRF error page, invoice payment
  instructions, dark-theme select dropdowns.
- Docs: v1.4 scope for Phases 16–18.

### In progress (uncommitted at memory creation)

- New module `webvulnscanner/security_gate.py` — CI/CD-style pass/fail gate
  over a completed scan's findings (`evaluate_gate(findings, fail_on)`,
  default threshold `high`; deliberately NOT persistence-backed — pure
  function of the stored Report JSON).
- New test `tests/test_security_gate.py`.
- `webvulnscanner/api_routes.py` — new `/api/v1/scans/<id>/gate` endpoint
  delegating to the gate module (single source of truth so CLI and direct
  HTTP consumers can't drift).
- `cli/wvs.py` — `glassbox gate` command calling that endpoint.
- Test updates: `tests/test_cli.py`, `tests/test_cross_org_idor.py`.

### Full-product audit (2026-08-22, user asked "is it sophisticated enough?")

The codebase has grown far past CLAUDE.md's description. Verified surface:

- **Engine**: 30 checks in checks.py; 4 orchestrators all emitting
  `readiness_verdict` + `check_coverage_pct`; scoring + grade; findings carry
  severity AND confidence; scan diffing (compare); AI summaries.
- **Continuous validation (PRODUCT.md's old gap — now built)**:
  asset inventory (`asset_routes.py`: create/schedule/pause/resume/delete,
  `templates/assets*.html`) + `scheduler.py` fixed-interval scheduler with
  cadence presets.
- **DevOps surface**: REST API under `/api/v1` (assets, scans, report,
  compare, gate) authenticated by revocable API tokens
  (`api_tokens_routes.py` + `api_tokens.html` UI); click-based `glassbox`
  CLI: login/logout/init/check/assess/readiness/gate/findings/verify/
  compare/report/assets/scan start — `gate` returns CI-friendly exit codes.
- **Human-led tier**: `assessment_routes.py` + `assessment_request.html`
  ("Request Expert Assessment" CTA on dashboard).
- **Platform admin suite**: admin_routes.py + 6 platform_admin_*.html.
- **Maturity signals**: 52 test files / ~766 tests, 9 Alembic migrations,
  GitHub Actions CI, Render/Fly/Vercel/Docker deploy configs, legal pages.

Verified gaps for a pro audience (grep-confirmed absent):
1. ~~Positioning language~~ → **FIXED** (see "Done since audit").
2. No PDF/report export (JSON only).
3. No integrations: webhooks, Slack, GitHub, SIEM — none exist.
4. No audit-log model.
5. No SSO/SAML.
6. No developer-facing API docs page/template.
7. PRODUCT.md is stale (claims no-migrations constraint that Alembic
   replaced; still named WebVulnScanner).

## STAGING-FIRST POLICY (user directive, 2026-08-22 — standing rule)

**All work ships to STAGING from now on. Production only after staging runs
error-free.** Concretely, every change follows this pipeline:

1. Work on `develop` → verify (`pytest` at minimum) → commit.
2. Deploy/verify on **staging** (glassboxsec-staging.fly.dev) — local
   `fly deploy -a glassboxsec-staging --config fly.staging.toml` while
   Actions billing is down.
3. Only when staging shows NO errors does a change get promoted: merge
   develop → master and `fly deploy -a glassboxsec` (production).
Never skip step 2 for anything user-facing or schema-touching. Prod pushes
are deliberate release events, not defaults.

### Branch/environment model (set up 2026-08-22 — THE NEW WORKFLOW)

```
develop ──push──► glassboxsec-staging.fly.dev (own Postgres)   ← ALL daily work here
master  ──push──► glassboxsec.fly.dev (prod DB)                ← release-only, push deliberately
```

- Local repo now ON `develop`. develop was merged up to master's tip
  (merge commit c921811) + infra commit ef8fd86, pushed to origin.
  The security-gate WIP + scanner purge are UNCOMMITTED in this working tree.
- **Staging**: Fly app `glassboxsec-staging` + Postgres cluster
  `glassboxsec-db-staging` (attached via DATABASE_URL secret), fresh
  SECRET_KEY, EMAIL_MODE=console (cannot send real email). Live and
  healthz-200 verified; migrations ran on its own DB.
  Deploy cmd: `fly deploy -a glassboxsec-staging --config fly.staging.toml`
- **Prod**: `glassboxsec` untouched, still running OLD origin/master code
  (local master was 50 commits ahead of origin/master — never pushed).
- `.github/workflows/fly-deploy.yml` is branch-wired: develop→staging job,
  master/main→production job. **GitHub Actions billing BLOCKED until next
  month (user confirmed 2026-08-22)** — ALL Actions runs fail instantly.
  Until billing returns, EVERYTHING deploys locally via fly CLI:
    staging: `fly deploy -a glassboxsec-staging --config fly.staging.toml`
    prod release: `fly deploy -a glassboxsec` (after merge develop→master)
  `git push origin <branch>` still works normally (backup only; its deploy
  step no-ops into failure). Do NOT treat a push as a deploy this month.
  Note: prod's database is NOT a Fly Postgres (`fly postgres list` shows
  only glassboxsec-db-staging) — prod uses an external Postgres behind its
  SQLALCHEMY_DATABASE_URI secret; never touch that secret.
- config.py now falls back SQLALCHEMY_DATABASE_URI → DATABASE_URL → sqlite
  (prod secret keeps precedence; standard var name works for attached DBs).

### Done since audit

- **"Scanner" purge complete (2026-08-22)** — zero occurrences left in
  templates/source outside the `webvulnscanner` package name and opaque test
  fixture URLs (`scanner.example.com`, `scanner@example.com`). Changed:
  marketing.html `<title>`/meta/OG/Twitter ×6 → "Glassbox - Autonomous
  Security Validation for AppSec Teams" + assessments wording; eyebrow
  line 163 → "Autonomous Security Validation Platform";
  assessment_request.html → "self-serve platform"; checks.py report texts
  ("the scanner could not/detected/never uploads" → assessment/Glassbox);
  docstrings/comments in checks.py, assessment_routes.py, scan_routes.py,
  test_sensitive_paths.py, test_secrets_hygiene.py.
- Verified: targeted pytest (test_sensitive_paths + template_consistency +
  secrets_hygiene) = 38 passed. NOTE: full suite is slow (~64s/38 tests
  ≈ 20 min total) — the earlier full-run timeout was slowness, not a hang.

### What's next (candidate queue)

1. GitHub Actions billing returns next month (user confirmed) — re-verify
   the branch-wired auto-deploys fire once it does. Until then all deploys
   are local fly CLI commands (see above).
2. Finish + verify the security-gate WIP: run `pytest`, review diff, commit
   to develop (staging deploys it on next push/deploy), then release to
   master when satisfied.
3. Refresh stale docs (PRODUCT.md still says WebVulnScanner/no-migrations;
   README/CLAUDE.md predate assets/scheduler/API/CLI/admin modules).
4. Decide remaining Phase 18 scope vs. opening Phase 19.
5. Sophistication roadmap candidates (pro audience): report PDF export,
   webhook/Slack notifications, audit log, API docs page.
6. Housekeeping: `dev-server-*.log` files and `instance/` are untracked
   clutter candidates (check .gitignore covers them).

## Conventions to honor while working here

- Checks return `(data, findings)`; never let a check raise past itself
  (wrap network calls in `try/except requests.RequestException`).
- New base-scan check ⇒ add `FEATURE_REQUIREMENTS` entry (entitlements.py),
  register in `run_scan()`'s jobs dict (or call directly), add to
  `CHECK_LABELS` + `CHECK_CATEGORY`, render in `scan_report.html`.
- Schema changes go through Alembic (`flask db migrate` → review → upgrade);
  `db.create_all()` no longer runs automatically.
- Frontend: reuse `base.html` design tokens/components/motion primitives;
  no emoji icons (inline SVG sprite only); no bare element selectors added
  to `base.html` (keep form styles in the `_scan_form_styles` /
  `_admin_form_styles` partial pattern).
- Scoring stays centralized in `scan_engine._score_report()` (regression
  test locks this).
- Only commit when explicitly asked. Never commit secrets.

## How to update this file

After each session or landed change:

1. Move items from "In progress" → "Done" with one-line summaries.
2. Refresh the state snapshot line (date + HEAD commit).
3. Re-prioritize "What's next".
4. Add any newly learned gotcha to "Conventions".
