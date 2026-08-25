# opencode.md — Session Memory

> Living memory file for this repo. **Update it at the end of every working
> session** (and whenever a meaningful change lands): what was done, what
> changed, what's next. Read it first when starting a new session.

## Operating model (added 2026-08-24 — read before starting any new phase)

This project now runs a two-role loop: **Claude** (via Claude Code, working alongside the user
in `handoff.md`) acts as senior UX/UI engineer, senior full-stack developer, senior product
engineer, and DevOps reviewer — reviewing what you (opencode) ship, verifying it live via
browser automation against real staging, scoping and prioritizing what's next, and writing the
roadmap/requirement entries you should build against. **You (opencode) are the build arm** —
you write the code, run the tests, and ship to staging per the STAGING-FIRST POLICY.

**Rules for this loop to work without drift:**

1. **Build exactly what's scoped in `.planning/ROADMAP.md`/`REQUIREMENTS.md`** — don't
   silently reprioritize or invent scope Claude/the user hasn't reviewed. If you think the
   scoped order is wrong, say so in `opencode.md`'s "What's next" section rather than
   reordering unilaterally (this has happened before — see Phase 22-26 sequencing, which
   Claude's review flagged as needing a swap; the roadmap now reflects the corrected order).
2. **No mistake goes unrecorded.** Every test failure you had to fix, every bug a human/
   reviewer caught that you didn't catch yourself, every revert, every "shipped" claim that
   turned out wrong — log it in `opencodefailure.md` the same session, using that file's entry
   format. This is not optional and not a blocker to shipping; log and move on.
3. **Full suite green + targeted live-fire verification before any "shipped to staging"
   claim** in this file. A claim here gets spot-checked live via browser automation — don't
   write "verified" unless you actually ran the verification, not just the test suite.
4. **UX matters as much as correctness.** A check that works but ships behind confusing
   copy, a dev-tool-sounding page, or a standalone route nobody discovers is not done — see
   the Phase 21.1 entry below for a concrete example of exactly this being caught after the
   fact and having to be reworked.
5. Everything else in "Conventions to honor while working here" (below) still applies
   unchanged.

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

## State snapshot (last updated: 2026-08-25, post Phase 30 decision)

- Branch `develop`, HEAD **f215d92** "fix(27.1): severity-aware chart point colors +
  gridlines + score labels", pushed to origin.
- **Phase 27.1 SHIPPED TO STAGING** (f215d92) — chart legibility fix: points colored
  by severity (pass/medium/high/critical), score labels on each point, y-axis
  gridlines. Asset detail chart fully redesigned from bare sparkline.
- **Phase 28 SHIPPED TO STAGING** (bbad7b0) — community check plugin architecture:
  YAML-defined checks from checks/community/*.yaml, schema validation, registry
  integration, ThreadPoolExecutor dispatch. 41 tests, 1089 passed full suite.
- **Phase 30 DECISION DOC COMPLETE** (.planning/PHASE30-OPEN-CORE-DECISION.md) —
  GO decision: AGPL-3.0 open-core, deferred to v2 for execution. No code change.
- v1.7 is now COMPLETE (Phases 27, 27.1, 28, 29, 30 all shipped/documented).
- Phases 21.1/22/27 remain v13/v14-live-fire-verified. NOT yet promoted to
  production — awaiting user's staging verification per the STAGING-FIRST POLICY
  (now covers 17–22 + 21.1 + 27 + 27.1 + 28 + 29).
- Tests run via `pytest` (fresh Flask app per test, SQLite under tmp_path).
  Full suite is ~12 min / **1089 tests**; use targeted runs during development.

### Done (recent history)

- Phase 29 — SARIF 2.1.0 export (`feat(29)` d6981c3, staging v15):
  `webvulnscanner/sarif.py` shared writer behind BOTH surfaces (session-web
  /scan/<id>/report.sarif + token-authed /api/v1 twin, byte-identical, same
  ownership guards as CSV — IDOR REGISTRY += both); severity→level mapping
  lives once in checks.severity_to_sarif_level(); vendored official SARIF
  schema + jsonschema (dev-only) for fixture-based validation; "Export SARIF"
  link on the report page; api_docs entry (url_map drift lock updated itself).
  SARIF-03 = user-side upload-sarif run, pending (Actions billing).
- Phase 27 — Continuous regression tracking for asset scans (`feat(27)`
  4e5947e): `regressions.py` pure deterministic diff; background-tail
  tagging of stored reports (asset-linked scans only); finding.regressed
  signed webhook (new High/Critical only, reuses Phase 19 machinery);
  regression timeline on the Asset detail page. CONT-01..04 complete.
- Phase 16 — Platform Admin user/org management (`feat(16)`).
- Phase 18 (wip commit) — Glassbox CLI (`cli/wvs.py`) + API additions.
- Various fix(10) UI/UX passes: nav links, CSRF error page, invoice payment
  instructions, dark-theme select dropdowns.
- Docs: v1.4 scope for Phases 16–18.

### Phase 18 close-out (SHIPPED TO STAGING 2026-08-23, commit 9405e81)

**Phase 18 close-out (COMPLETE, committed 9405e81, shipped to staging):**
- `webvulnscanner/api_routes.py` — new GET `/api/v1/scans/<int:scan_id>/report.csv`
  (token-authed CSV export; ownership branches + WR-01/WR-02 error semantics cloned
  verbatim from fetch_report).
- `webvulnscanner/scan_routes.py` — CSV writer extracted to shared pure helper
  `findings_csv_document(report, scan_id)`; web export.csv route now calls it too
  (single writer behind both surfaces — byte-identical output proven by test).
- `cli/wvs.py` — `glassbox report --csv` flag hitting the new endpoint.
- `cli/pyproject.toml` (new) — installable package; `pip install ./cli` provides a
  real `glassbox` console script (wheel build + entry_points.txt verified).
- Tests: test_api_routes.py (+7 report.csv tests), test_cli.py (+2 --csv tests),
  test_cross_org_idor.py REGISTRY += api.fetch_report_csv.
- Planning docs updated: ROADMAP Phase 18 → ✅ Complete 2026-08-23; REQUIREMENTS.md
  CLI-01..03 → [x] with the "no new endpoints" deviation documented in place.

### Phase 19 decision (user-confirmed 2026-08-23)

**Phase 19 = Webhooks/Slack integrations** (outbound webhook on scan completion,
Slack-compatible payload). Builds on the gate endpoint.

Also user-directed: **stale docs (PRODUCT.md/README/CLAUDE.md) are OFF-LIMITS for the
assistant** — the user will review/update them personally. Do not edit them.

### Phase 19 implementation (SHIPPED TO STAGING 2026-08-23, commit 001dfa6)

**Why it matters**: closes the continuous-validation loop — scheduled scans
fire on a cadence, but results previously reached a team only when someone
logged in. Webhooks push each completed scan's outcome to where the team
already watches (Slack incoming webhook or any HTTP receiver), minutes after
it happens; HMAC signing lets receivers verify it came from Glassbox.

Built (wizard/API/scheduler all converge on `_run_scan_in_background`'s
shared tail — confirmed scheduler imports `_spawn_scan_thread` from
scan_routes):

- `models.py`: `OutboundWebhook` + `WebhookDelivery` (scan_id NULLABLE for
  test pings). Migration `c3f8a91d2e47`, down_revision='1da1e657ca46' —
  **run `flask db upgrade` on deploy**.
- `webvulnscanner/webhooks.py` — engine: `validate_webhook_url` (HTTPS +
  `is_ssrf_safe_hostname`, same SSRF gate as scan targets),
  `redact_webhook_url` (never render stored URLs — Slack URLs embed creds),
  `build_scan_payload` (Slack-first `text` + structured event/scan/gate/
  top_findings ≤5, gate via single-source `evaluate_gate`),
  `sign_payload`/`_post_payload` (X-Glassbox-Signature sha256=HMAC over
  exact bytes, 5s timeout), `deliver` (never raises, records row),
  `send_test_ping` (scanless ping), `fire_scan_webhooks` (org→org_id,
  solo→created_by_user_id never NULL-org equality, active only).
- `scan_routes.py`: hook after terminal COMPLETED commit.
- `webhook_routes.py` blueprint `/webhooks`: index (?created=<id> secret-
  shown-once; member_note for org MEMBERs), POST /add (20/hour), POST
  /<id>/delete|toggle|test (test 10/hour), GET /<id>/deliveries.
  `_scoped_webhook_or_404`: org webhook → that org's ORG_ADMIN, solo →
  creator, else 404. Registered in `__init__.py`.
- `templates/webhooks.html` + `webhook_deliveries.html`: dual-markup
  contract from birth (desktop table + .mobile-record-cards); page-scoped
  styles per api_tokens.html discipline; `base.html` gained a "Webhooks"
  nav link after API Tokens.
- Tests: `tests/test_webhooks.py` (+23); IDOR REGISTRY += 4 webhooks
  endpoints; live_probe_phase8.py += webhooks family case + webhook in the
  probe bundle; tripwire locks updated deliberately:
  `_EXPECTED_SAFE_REFERRER_CALL_SITES` 303→307 (blueprint registration
  shifted __init__.py), card-conversion scope six→eight templates.
- Docs: ROADMAP Phase 19 ✅ Complete + progress row; REQUIREMENTS
  WEBH-01..07 all [x], traceability 49/49.
- Full suite: **940 passed / 0 failed**. Staging verified: healthz 200,
  webhook routes live (login-gated), migration c3f8a91d2e47 applied
  (Dockerfile CMD runs `flask db upgrade` on every machine start — no
  release_command needed).
- Commit 001dfa6 pushed to origin; awaiting user staging verification for
  production promotion (merge develop → master, `fly deploy -a glassboxsec`).
- Follow-up fix 2a161fe: CLI credential prompt gave ZERO visual feedback on
  Windows (hide_input=True) — real first-run user thought the program froze.
  `_prompt_secret()` in cli/wvs.py now echoes '*' per keystroke/pasted char
  (msvcrt path when stdin is a console; piped input/tests keep click's
  hidden prompt), backspace erases visibly, Ctrl+C works. v1.0.1.
- Onboarding follow-up d40f126 (deployed to staging, healthz 200): (a)
  interactive login/init now prints where to create a token before
  prompting; (b) new cli/README.md quickstart incl. the "glassbox not
  recognized" venv gotcha; (c) api_tokens.html reveal panel shows
  `pip install ./cli` + `glassbox init --api-url {{ request.url_root }}`
  hint (host-aware, works staging AND prod). 43 CLI/api-token/markup
  tests green.
- PHASE 17 COMPLETE (2026-08-23): DEPTH-01 signed off "A AND B" — decision
  record .planning/PHASE17-DEPTH-DECISION.md. checks.py: REFLECTED_XSS_VARIANTS
  (4 marker-only shapes), context-aware boolean-blind pairs (numeric vs quote),
  SQL_ERROR_SIGNATURES=14, MAX_PROBE_REQUESTS_PER_URL=12, crawl_depth2_param_urls
  (MAX_CRAWL_PAGES=15, same-origin/robots/HTML-only, GET-only) wired in
  scan_engine.run_scan for org_verified_for_domain only, merged behind hop-1,
  probe list still capped [:10]. tests/test_phase17_coverage.py = 20 locks
  (registry minimums, budget arithmetic, caps, robots/cross-origin skips,
  run_scan merge-order + gating). Full suite 960 passed. ROADMAP P17 ✅,
  REQUIREMENTS DEPTH-01..03 [x], traceability Complete.

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
3. ~~No integrations: webhooks, Slack, GitHub, SIEM — none exist~~ →
   webhooks + Slack **BUILT in Phase 19 (2026-08-23)**; GitHub/SIEM still open.
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

### Repo-hygiene decisions (recorded 2026-08-24)

- `.lure_deploy/` (Dockerfile + fly.toml + lure_app.py) stays IN-TREE
  permanently as the reusable live-fire verification fixture for the ten
  intrusive checks: `selftest.py` proves detection logic in-process on
  loopback, while the deployed lure proves network-path behavior end-to-end
  against real staging infrastructure — complementary, both worth keeping.
  The fly app `glassbox-lure` is ephemeral ops state, not a fixture: redeploy
  on demand from `.lure_deploy/`, destroy when done.
- Root-level `lure_app.py` DELETED (was a byte-identical duplicate of
  `.lure_deploy/lure_app.py`, which is the copy the Dockerfile builds from).
- `srv_files/` DELETED from the tree — it only ever held a 47-byte
  manual.pdf stub that lure_app.py auto-regenerates at startup when missing,
  and nothing in-tree references the path. Both `srv_files/` and
  `.lure_deploy/srv_files/` are now gitignored so local runs don't re-track it.

### Done since audit

- **CLI onboarding + masked token prompt SHIPPED TO STAGING (2026-08-23,
  2a161fe/be5bcc5/d40f126/c7678f2)** — cli v1.0.1: `_prompt_secret()`
  (msvcrt `*`-per-char masked input on Windows console when stdin isatty,
  click hidden-prompt fallback for piped/CI), first-run guidance before the
  token prompt, new cli/README.md, API Tokens page reveal-panel hint
  (`pip install ./cli`, `glassbox init --api-url {{ request.url_root... }}`
  + `.muted-cli-hint`). Client-only — no server deploy needed for 2a161fe;
  d40f126 (template hint) deployed, healthz 200.
- **Phase 17 crawl depth/variants SHIPPED TO STAGING (2026-08-23, b099a8a)**
  - user approved "A AND B" (.planning/PHASE17-DEPTH-DECISION.md): 4
    reflected-XSS marker variants, context-aware boolean-blind SQLi pairs,
    MAX_PROBE_REQUESTS_PER_URL=12, 2 new SQL error signatures (=14),
    `crawl_depth2_param_urls()` (MAX_CRAWL_PAGES=15) wired into run_scan()
    gated on org-verified target; hop-1 priority merge capped [:10].
    tests/test_phase17_coverage.py (20 locks). Full suite **960 passed**.
    Deployed staging, healthz 200.
- **Phase 20 Intrusive Coverage Expansion COMPLETE, SHIPPED TO STAGING
  (2026-08-23, c2727f9 + 3ee435c)** — ten new
  base-scan checks in checks.py: ssti, host_header, cache_deception,
  crlf, csrf_posture (PAID tier); path_traversal, rate_limit,
  jwt_active, graphql_deep, subdomain_takeover (ORG_VERIFIED).
  Safety contracts: computed-result-only SSTI proof, own-token-only JWT
  forgery with garbage-signature control requirement, GET-only rate-limit
  burst (RATE_LIMIT_BURST=15) against auth paths only, zero-network CSRF
  posture from crawled forms, DNS-only takeover fingerprints via existing
  dns.resolver dep, read-only GraphQL queries. Wired: entitlements
  FEATURE_REQUIREMENTS, CHECK_LABELS/CHECK_CATEGORY, scan_engine jobs dict
  ×10, scan_report.html ten sections (all tables .table-scroll-wrapped per
  D-01). Registry locks updated: CHECK_COMPLIANCE + SECURITY_DOMAIN_MAP
  (+10 each), test_report_table_semantics counts 23→32 tables/tbody,
  21→30 thead, 32 scroll wrappers; A05_BASE_CHECK_NAMES fixture extended
  (host_header/cache_deception/subdomain_takeover are owasp-A05 too);
  removed two `'&mdash;'|safe` violations caught by the autoescape lock.
    tests/test_phase20_checks.py (28→29 locks). Full suite **989 passed /
    0 failed**. NOTE: one transient org_invite tampered-signature failure
   during a long run near UTC midnight — ROOT-CAUSED & CLOSED same day
   (itsdangerous unpadded b64url; test now truncates — see Phase 21 below).
   No recurrence in any subsequent full-suite run; no longer being watched.
- **Phase 20 LIVE-FIRE VERIFIED ON STAGING (2026-08-23, 3ee435c)** — user asked "how do
  I know these work"; drove end-to-end on staging via CLI. Staging account
  arktechdesigns@gmail.com / Review Org was plan=free → flipped to
  ORG_VERIFIED + seeded DomainVerification rows (nextlevelhub.xyz,
  www.nextlevelhub.xyz, glassbox-lure.fly.dev) via fly ssh console +
  base64-encoded python one-liners (PS quoting: outer double quotes, inner
  singles, blob as bare argv token — SFTP put does NOT land where console
  looks). Scan progression proved tier gating: scan1 free=16 locked,
  scan3 org-verified+hostname-match=0 locked. Deployed lure app
  (lure_app.py → fly app `glassbox-lure`, .lure_deploy/ has its Dockerfile+
  fly.toml; destroy when done). Lure scan: ALL FOUR positive detections
  fired with Confirmed confidence — ssti critical (6776), path_traversal
  critical (real /etc/passwd read), jwt_active critical (alg:none accepted,
  garbage control 401), graphql_deep medium introspection + low field-
  suggestions; honest negatives elsewhere. **Bug caught & fixed**: jar
  eviction in check_jwt_active — session jar's genuine token rode along on
  every replay so the garbage-signature CONTROL could never differ;
  now evicts per-variant, restores after, wire-level regression test
  asserts exactly one auth_token cookie leaves the process.
- **OPS GOTCHA**: never rewrite repo files via PS Get-Content|Set-Content —
  it ANSI-mangles non-ASCII and adds a UTF-8 BOM that breaks ast-parsing
  tests (fixed by git checkout + Edit tool re-apply). Stray BOMs in md files
  strip via [System.IO.File]::WriteAllText with UTF8Encoding($false).
- **Phase 21 Built-in Detection Self-Test SHIPPED TO STAGING (2026-08-23,
  2886b1e)** — user
  asked why lures need a separate URL; Option B chosen: selftest.py spins an
  ephemeral 127.0.0.1-only ThreadingHTTPServer lure (SSTI/traversal-decoy-
  passwd/JWT alg:none/GraphQL introspection/tokenless POST form + throttled
  /login), runs all ten Phase-20 checks in-process via real crawl_same_
  origin, compares to EXPECTATIONS matrix (5 must-fire incl. severity
  floors, 5 must-stay-silent). No Scan row, no report file, SSRF guard
  untouched (target generated internally, never user input). Route POST
  /selftest (login, CSRF form, limiter 30/hour) renders pass/fail matrix;
  dashboard button added; blueprint registration shifted __init__.py's
  _safe_referrer line-lock 307→311. Gotchas fixed during build: (1) naive
  query parsing missed URL-encoded payloads — parse_qs everywhere;
  (2) module-level login-hit counter broke run-to-run determinism — state
  moved onto server instance. **org_invite flake ROOT-CAUSED**: itsdangerous
  emits UNPADDED b64url — last char can carry <6 significant bits so the
  test's char-flip ('a'<->'b') was intermittently a NO-OP decode (7 of 60
   sig lengths lossless, alignment shifts with timestamp); test now truncates
   instead. Full suite **1001 passed**. Deployed to staging (release v11):
   re-checked 2026-08-24 — /healthz 200, POST /selftest live behind login
   (302 unauthenticated, no 404). Production promotion pending per the
   STAGING-FIRST POLICY.

- **Phase 22 SHIPPED TO STAGING (2026-08-24, commit 5314b0c)** — split into
  its own commit from the shared working tree (intermediate post-22 snapshot
  reconstructed for __init__.py + test_auth_flows.py tripwire 315; verified
  boot-clean in a throwaway `git worktree` at that exact tree, 56 passed).
- **Phase 21.1 Detection-Verification UX Fold-In SHIPPED TO STAGING
  (2026-08-24, commit d124485)** — UXFT-01..04 all [x] with implementation
  notes in REQUIREMENTS.md; ROADMAP row Complete 2026-08-24. Full suite
  **1016 passed / 0 failed** (18:38) on the final tree; fly deploy → staging
  release v13; live-fire: /healthz 200, /selftest 404 (dead route confirmed),
  /docs/api 302 auth gate. Badge-on-report rendering is suite-verified only
  (needs an authenticated scan to see live). Production promotion still
  user-gated.
- **Phase 22 In-Product API Documentation BUILT (2026-08-24, v1.6 first
  phase)** — why: Phases 2/18/19 shipped a full token-authed REST surface +
  CLI + signed webhooks discoverable only by reading source; /docs/api makes
  it integrable in one sitting and can't drift. `webvulnscanner/api_docs.py`
  = single-source spec (API_ENDPOINTS ×8 routes, error-semantics table,
  curl example); `docs_route.py` blueprint GET /docs/api (@login_required);
  templates/api_docs.html (base.html tokens only, endpoint overview table +
  mobile-record-cards from birth). Three drift locks in
  tests/test_api_docs.py (10 tests): (1) url_map↔spec bidirectional incl.
  method-drift check — a new /api/v1 route fails CI BY NAME until documented;
  (2) WEBHOOK_VERIFY_SNIPPET exec()ed and behaviorally compared both
  directions against webhooks.sign_payload (tamper/wrong-secret/wrong-scheme
  negatives); (3) CLI_SUBCOMMANDS set == cli/README.md's `glassbox <cmd>`
  lines with named-diff failure. Tripwires updated deliberately: _safe_
  referrer call-site lock 311→315 (__init__ registration), card-conversion
  scope eight→nine (api_docs.html), test renamed exactly_eight→exactly_
   nine_templates. Full suite **1015 passed / 0 failed** (18 min). NOT yet
   committed/deployed.

- **Phase 21 selftest SURFACE REDESIGN BUILT (2026-08-24, user direction —
  same uncommitted tree as Phase 22)** — why: the standalone /selftest page +
  dashboard button read as "another scanner: which domain does THIS one hit?"
  — the exact confusion the loopback design exists to avoid. User's framing:
  the self-test is "the gun works"; a scan verdict is about "is your house
  locked" — those must not look like two parallel products. Changes: (a)
  `selftest.py` gained `detection_verification()` (runs the matrix once per
  worker process, threading.Lock-guarded cache; errors return None and are
  NOT cached — next scan retries) + `verification_summary()` (compact
  {passed, confirmed, total, duration_ms, failed[]} badge dict) +
  `reset_detection_verification_cache()` test hook; engine itself UNTOUCHED.
  (b) `run_scan()` calls verification_summary() at the very END of the
  pipeline (after scoring, so the live feed isn't delayed on a worker's first
  scan) and attaches `report["detection_verified"]` only when present — an
  unavailable verification omits the badge, never fails the scan.
  (c) DELETED: `webvulnscanner/selftest_routes.py`, `templates/selftest.html`,
  dashboard.html's "Detection Self-Test" button, __init__ registration
  (_safe_referrer tripwire back 315→311 with history note). (d)
  scan_report.html renders a quiet `.pill.pass` "Engine verified · N/10
  detections confirmed" beside the score + muted note "Verified against
  Glassbox's internal check target — not your site."; drift → `pill medium`
  naming the failed checks; absent key → nothing rendered.
  (e) tests/test_selftest.py: route tests replaced by /selftest-returns-404
  regression lock, cache-semantics tests (compute-once via identity assert,
  error-not-cached), summary-shape exact-equality test, and structural locks
  (source-parse precedent) tying run_scan ordering (scoring < summary call <
  attach) + template to the key. REQUIREMENTS ST-04 got the CLI-02-style
  dated SUPERSEDED note; ST-06 annotated. Targeted suites green (223 across
  selftest/api_docs/auth_flows/template_consistency/accessibility/responsive_
  markup); FULL suite pending at entry-writing time.


- **Email-verification gate on login SHIPPED TO STAGING (2026-08-22,
  bb7d5d0)** — reversed the old documented "unverified email does not
  block login" decision: login() now refuses unverified accounts (flash +
  resend option rendered via `resend_email` template var); new POST
  /resend-verification (5/hour, anti-enumeration neutral flash, mints a
  token for legacy tokenless rows). login.html gained the resend details
  block. 7 new tests; source-parse locks updated for shifted line numbers
  (_safe_next now line 94; _safe_next call sites 165/311/354). Full suite
  **904 passed / 0 failed**; deployed to staging (healthz 200).
- **Security-gate feature SHIPPED TO STAGING (2026-08-22, pipeline steps 1–2
  done)** — full suite 897 passed / 0 failed; committed to develop as
  b87c15d (feat(18): security_gate.py + /api/v1/scans/<id>/gate + `glassbox
  gate` CLI + tests) and 21880f2 (scanner-wording purge + opencode.md +
  .dockerignore); pushed; deployed locally to staging (new image rev),
  healthz 200, gate endpoint live (401 unauthenticated = auth guard OK).
  **NOT yet promoted to production** — awaiting user's staging verification
  per the STAGING-FIRST POLICY.

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

0. ~~Turnstile on staging~~ → **FIXED (2026-08-22)**: user supplied their
   Cloudflare widget keys; set as TURNSTILE_SITE_KEY/TURNSTILE_SECRET_KEY
   secrets on glassboxsec-staging. Verified: widget renders on /signup with
   the correct sitekey + script tag; server-side siteverify now ACTIVE on
   staging.
0b. **Staging email is console-mode BY DESIGN** (user hit this when testing
   resend: links only appear in fly logs, no inbox delivery). Fix = user
   supplies RESEND_API_KEY + RESEND_FROM_EMAIL (prod's Fly secrets are
   write-only, local .env doesn't have them), then:
   `fly secrets set -a glassboxsec-staging EMAIL_MODE=resend RESEND_API_KEY=re_… RESEND_FROM_EMAIL=…`
   Domain already Resend-verified via prod use; free tier covers staging.
   Pending user action as of 2026-08-22.

1. GitHub Actions billing returns next month (user confirmed) — re-verify
   the branch-wired auto-deploys fire once it does. Until then all deploys
   are local fly CLI commands (see above).
2. ~~Finish + verify the security-gate WIP~~ → shipped to staging (b87c15d,
   see "Done since audit"). ~~Phase 18 close-out~~ → complete 2026-08-23
   (CSV API + `glassbox report --csv` + cli/pyproject.toml packaging);
   **uncommitted** — commit to develop, then deploy to staging per the
   STAGING-FIRST POLICY.
3. ~~Refresh stale docs~~ → USER-OWNED now (explicit instruction 2026-08-23):
   the user reviews/updates PRODUCT.md/README/CLAUDE.md personally; the
   assistant must not edit them.
4. ~~Decide Phase 18 vs 19~~ → decided 2026-08-23: Phase 18 closed; Phase 19 =
   Webhooks/Slack integrations. ~~Phase 19 build~~ → SHIPPED TO STAGING
   2026-08-23 (commit 001dfa6, suite green, migration applied). Next:
   user verifies staging, then production promotion.
5. ~~Sophistication roadmap candidates~~ → **v1.6 SCOPED (2026-08-24)**: Phases 22–26
   in .planning/ROADMAP.md + REQUIREMENTS.md (24 requirements, all Planned):
   22 in-product API docs page, 23 audit log, 24 report PDF export,
   25 pipeline integrations (GitHub Actions/SIEM), 26 SSO/SAML (spike-first with
   explicit NO-GO escape hatch). Start at Phase 22 whenever user says go.

   **v1.7 SCOPED (2026-08-24, from the "what makes this world-class" strategic review)**:
   ~~Phase 21.1~~ → **DONE + SHIPPED TO STAGING (d124485, see Done)**.
   ~~Phase 27 (Continuous Regression Tracking)~~ → **DONE + SHIPPED TO STAGING
   (4e5947e, release v14; CONT-01..04 complete; regression timeline is
   suite-verified, live browser walkthrough still pending user-side)**.
   User-set build order for the rest: Phase 29 (SARIF export, targets GitHub's Security tab)
   → Phase 28 (Check Extensibility — a narrow
   YAML-based community-check loader, HTTP pattern-match only, same tier-gating as built-ins)
   → Phase 30 (self-hostable/open-core
   decision spike — doc only, GO or NO-GO both valid).
   **USER-SET ORDER (2026-08-24 instruction): 27 → 29 → 28 → 30** — matches the earlier
   recommendation (27 and 29 before 28/30); build exactly to each phase's ROADMAP success
   criteria, no added or dropped scope.
   ~~Phase 27~~ DONE, ~~Phase 29~~ DONE (d6981c3, staging v15; SARIF-03 upload-sarif
   verification pending user-side). **NEXT: Phase 28 (Check Extensibility)** — then 30.
   Also scoped-but-unbuilt: Phase 27.1 chart legibility (CHARTUX-01..04; needs the
   `dataviz` skill per its own criterion 5) — slot it whenever the user says go.
6. Housekeeping: `dev-server-*.log` files and `instance/` are untracked
   clutter candidates (check .gitignore covers them). Also: staging DB still
   has a dangling DomainVerification row for glassbox-lure.fly.dev (lure app
   destroyed 2026-08-24, confirmed via fly apps list) — harmless, delete the
   row next time you're in the staging org-admin page. Note: Fly shows
   glassboxsec-staging as "suspended" between requests — that's normal
   machine-idling, it auto-resumes on traffic.
7. Phase 17 (Expanded Check Coverage) is still v1.4's only open phase:
   DEPTH-01 needs an explicit signed crawl-depth decision; DEPTH-02/03 are
   payload-variant work. Decide whether it stays in v1.4 or moves to a
   later milestone.

## Conventions to honor while working here

- **Always explain the "why"** (standing user directive, 2026-08-23): whenever
  building or changing anything, state the reason behind the work and how it
  helps the website/product — in plain language, before or alongside the
  implementation, not after the fact.
- **Live-fire verification runs must log "confirmed via fresh process"**:
  state that the target was a freshly deployed/restarted process (and that no
  stale dev server or nested `app_context()` participated), so a verification
  can't silently validate old code — see handoff.md's duplicate-server and
  nested-context gotchas.
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
