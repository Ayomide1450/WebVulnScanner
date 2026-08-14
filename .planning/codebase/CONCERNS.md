# Codebase Concerns

**Analysis Date:** 2026-08-10

## Tech Debt

**Stale "no migrations" comments left in `models.py` after the migrations track landed:**
- Issue: `CLAUDE.md` (lines 37-43) documents that the project moved from `db.create_all()`-only
  schema management to Alembic via Flask-Migrate (`migrations/`, one baseline revision:
  `migrations/versions/4621b1837a3f_baseline_schema.py`). However, `models.py` still carries
  docstrings written under the old constraint: `PasswordReset` (`webvulnscanner/models.py:103-107`)
  says it's "its own table rather than a column on User... added after the app already had a live
  database, and `db.create_all()` can only create new tables, never ALTER an existing one," and
  `ScanEvent` (`webvulnscanner/models.py:168-173`) repeats the same "db.create_all() only creates
  new tables" reasoning.
- Files: `webvulnscanner/models.py:103-107`, `webvulnscanner/models.py:168-173`
- Impact: A future contributor reading these docstrings could conclude that ALTERing an existing
  table is still unsafe/impossible, and add an unnecessary new table instead of a proper Alembic
  migration for what should now be a normal `flask db migrate` column addition.
- Fix approach: Update both docstrings to note the historical reason those tables were split out
  (in case that shape is still preferred for other reasons) but remove/qualify the now-incorrect
  claim that schema changes require a new table — point instead to `CLAUDE.md`'s "Database
  migrations" section.

**README.md and PRODUCT.md are out of sync with the current migrations-based schema model:**
- Issue: `README.md:100-101` states "SQLite tables are created automatically on first run
  (`webvulnscanner.db`)" — no mention of `flask db upgrade`. `PRODUCT.md:57-58` states "No
  migrations system: `models.py` uses `db.create_all()` only. Adding a column to an existing
  table won't apply to a live DB — schema changes require a new table." Both directly contradict
  `CLAUDE.md:37-43`'s documented Alembic/Flask-Migrate setup and `webvulnscanner/__init__.py:119`'s
  comment that schema is intentionally *not* created implicitly via `db.create_all()` anymore.
- Files: `README.md:100-101`, `PRODUCT.md:57-58`, contradicted by `CLAUDE.md:37-43` and
  `webvulnscanner/__init__.py:119`
- Impact: A new developer following README setup steps will not run `flask db upgrade` and will
  hit a database with no tables (SQLite) or fail entirely (Postgres, where `create_all()` is
  never called at all per `__init__.py:119`).
- Fix approach: Update the README "Setup" section to include `flask db upgrade` after
  `copy .env.example .env`, and correct/remove the PRODUCT.md "No migrations system" line (or
  mark it explicitly superseded, since PRODUCT.md is meant to capture current product truth).

**README architecture table understates the module count and check-orchestrator count:**
- Issue: `README.md:36-44`'s architecture table omits `ai_summary.py` entirely and describes
  `scan_routes.py`/`scan_engine.py`/`checks.py` as running "the three scan orchestrators," while
  `CLAUDE.md:107-108` and `docs/vercel-migration.md:42-43` both confirm there are now four
  (`run_scan`/`run_advanced_scan`/`run_media_scan`/`run_api_scan`). The `models.py` row also omits
  `ScanEvent`, which is a real table (`webvulnscanner/models.py:168-190`).
- Files: `README.md:36-44` vs `webvulnscanner/scan_engine.py`, `webvulnscanner/models.py`
- Impact: Low — cosmetic/doc-accuracy only, but compounds the migrations doc-drift above as a
  sign README isn't kept current with `CLAUDE.md`/code changes.
- Fix approach: Sync the README architecture table with `CLAUDE.md`'s module table the next time
  either is touched.

**Scoring logic duplicated across all four scan orchestrators:**
- Issue: `CLAUDE.md:192-198` documents that the 100-minus-severity-weights → letter-grade →
  `severity_counts` scoring block "is duplicated four times in `scan_engine.py` (`run_scan`,
  `run_media_scan`, `run_advanced_scan`, `run_api_scan`) rather than shared."
- Files: `webvulnscanner/scan_engine.py` (all four orchestrator functions)
- Impact: Any change to the scoring formula (severity weights, grade thresholds) must be applied
  in four places by hand; a partial update silently produces inconsistent grading between scan
  types.
- Fix approach: Extract a shared `_score_report(findings) -> (risk_score, grade, severity_counts)`
  helper and call it from all four orchestrators.

**Media/API scan progress pages lack the live per-check feed that base scans have:**
- Issue: `CLAUDE.md:164-168` states `run_advanced_scan`/`run_media_scan`/`run_api_scan` have no
  `progress_cb` parameter at all — their scan-progress pages "degrade to the plain
  bar/status-line-only view," and extending the live feed to them is explicitly called out as
  "a deferred, separate piece of work."
- Files: `webvulnscanner/scan_engine.py` (three orchestrators), `templates/scan_progress.html`
- Impact: User-facing inconsistency — three of four scan types give substantially worse
  real-time feedback than the base scan.
- Fix approach: Give each remaining orchestrator the same `jobs`-dict + `ThreadPoolExecutor` +
  `progress_cb` shape `run_scan()` already has, per `CLAUDE.md`'s own note.

**Two dashboard/admin templates still use emoji instead of the SVG icon convention:**
- Issue: `CLAUDE.md:284-286` explicitly calls out that the app should "never use emoji as icons
  (inline SVG only, one pre-existing exception in `billing.html`/`org_verify_domain.html`'s
  empty-state `.warn-box` not yet cleaned up)."
- Files: `templates/billing.html`, `templates/org_verify_domain.html`
- Impact: Cosmetic inconsistency with the rest of the design system; low risk but flagged in
  project docs as a known deviation.
- Fix approach: Replace the emoji in both empty-state `.warn-box` blocks with the standard
  `.icon`/`<symbol>` SVG pattern used elsewhere.

**Frontend redesign left incomplete on several pages:**
- Issue: `CLAUDE.md:310-312` notes the `scan_progress.html` "SOC" motion/texture primitives
  (`.glow-pulse`, `.hud-grid`, `.telemetry-dot`, etc.) are "available for future redesign phases"
  and that "dashboard/billing/org-admin/scan_report visual passes are still open."
- Files: `templates/dashboard.html`, `templates/billing.html`, `templates/org_admin.html`,
  `templates/scan_report.html`
- Impact: Visual inconsistency between the redesigned scan-progress experience and the rest of
  the app's older styling.
- Fix approach: Apply the same motion/texture primitives from `base.html` to the remaining pages
  in a dedicated visual pass, per `CLAUDE.md`'s own note.

## Known Bugs

Not detected — no open bug reports, `TODO`/`FIXME`/`HACK`/`XXX` markers exist anywhere in
`webvulnscanner/`, `templates/`, `tests/`, or `scripts/` (verified via repo-wide grep). All
caveats found are pre-documented design limitations (see other sections) rather than acknowledged
bugs.

## Security Considerations

**SSRF guard is submission-time only, does not protect against DNS rebinding:**
- Risk: `CLAUDE.md:231-235` and `webvulnscanner/scan_routes.py` document that
  `checks.is_ssrf_safe_hostname()` resolves the target hostname once at scan-submission time and
  rejects private/loopback/link-local/reserved/multicast addresses, but "it does not pin the
  resolved IP for the actual scan request, so it does not protect against DNS rebinding."
- Files: `webvulnscanner/checks.py` (`is_ssrf_safe_hostname`), `webvulnscanner/scan_routes.py`
  (call sites in every `new_scan_*` route)
- Current mitigation: Submission-time hostname-class rejection; `tests/test_ssrf_guard.py`
  covers the address-class matrix via mocked `socket.getaddrinfo`.
- Recommendations: Per the docstring's own caveat, pin the resolved IP for the duration of the
  actual scan request (e.g. via a custom `requests` transport/adapter) if DNS-rebinding coverage
  is ever required — currently explicitly out of scope, not a regression.

**In-memory rate limiting is not multi-worker-safe:**
- Risk: `CLAUDE.md:242-245` and `webvulnscanner/extensions.py:24-28` both flag that
  `flask_limiter.Limiter`'s in-memory storage is "fine for the current single dev-server-process
  reality, not multi-worker-safe." `Procfile`/`render.yaml` currently run gunicorn with
  `--workers 1 --threads 4`, so the limitation is latent, not currently triggered — but any future
  scale-out to multiple gunicorn workers (or a serverless deploy where each invocation is a fresh
  process) silently breaks `/login` (10/min), `/signup` (5/hour), and invoice
  create/verify (10/hour, 30/hour) rate limits, since counters wouldn't be shared across
  processes.
- Files: `webvulnscanner/extensions.py:24-29`, `Procfile`, `render.yaml`
- Current mitigation: Single-worker deployment keeps counters process-global; documented as a
  known constraint in code comments.
- Recommendations: Switch `Limiter`'s `storage_uri` to a shared backend (e.g. Redis) before ever
  increasing `--workers` beyond 1, per the extensions.py comment's own instruction.

**AI remediation summaries pass scanned-site response content into an LLM prompt:**
- Risk: `CLAUDE.md:266-272` notes that finding `detail`/`title` text can contain content drawn
  directly from the scanned site's own HTTP responses (header values, secret snippets, probe
  output) — not fully trusted input, even for an authorized target.
- Files: `webvulnscanner/ai_summary.py` (`SYSTEM_PROMPT`, `generate_remediation_summary`)
- Current mitigation: `SYSTEM_PROMPT` frames all finding data as data-to-summarize inside
  `<findings>` delimiters, never as instructions to follow; the model's output is read-only
  report text with no tool-use attached, bounding a successful prompt injection to "a wrong
  sentence in a report."
- Recommendations: None additional documented; preserve this framing if `SYSTEM_PROMPT` is ever
  changed, per `CLAUDE.md`'s explicit instruction.

## Performance Bottlenecks

Not detected as an active complaint in project docs — the closest documented performance/latency
constraint is the SSE progress-feed polling loop (`scan_events()` in `scan_routes.py`), which
`docs/vercel-migration.md:19-22` describes as "an indefinite polling loop" that `sleep(0.5)`s and
re-queries the DB "with no upper bound tied to a single scan's duration." This is a scaling/
platform-compatibility concern (see "Scaling Limits" below) more than a measured performance
bottleneck in the current single-worker deployment.

## Fragile Areas

**Background scan threads share the request-thread's SQLite connection pool:**
- Files: `webvulnscanner/scan_routes.py:82-90` (`_run_scan_in_background`), `webvulnscanner/config.py:55-72`
- Why fragile: Each submitted scan spawns a daemon `threading.Thread` that writes `Scan`/
  `ScanEvent`/`Report` rows through the same SQLite connection pool as the HTTP request thread
  that spawned it — `scan_routes.py:87-89` documents this explicitly requires
  `SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"check_same_thread": False}}`, which
  `config.py:71-72` only applies when the DB URI starts with `sqlite`. On Postgres this is a
  non-issue (connections are per-thread via the pool), but on SQLite it's a documented,
  intentional relaxation of SQLite's default thread-safety guard.
- Safe modification: Do not remove `check_same_thread: False` for SQLite without re-architecting
  background scan execution; do not assume `Scan`/`ScanEvent` writes from the background thread
  are visible to a `db` session opened in a different context without a fresh
  `app.app_context()` — `tests/test_scan_events.py`'s module docstring (referenced from
  `CLAUDE.md:73-77`) documents that holding an outer app context open while calling
  `_run_scan_in_background` causes "its otherwise-successful commits to read back stale through
  that same session," which is why that test module uses short-lived
  `with app.app_context():` blocks per call instead of a shared `db` fixture.
- Test coverage: `tests/test_scan_events.py` covers this specific commit-visibility interaction
  for base scans; no equivalent test exists for `run_advanced_scan`/`run_media_scan`/
  `run_api_scan` (see "Test Coverage Gaps" below).

**Scan execution model is fundamentally incompatible with serverless deployment:**
- Files: `docs/vercel-migration.md` (whole document), `api/index.py`, `vercel.json`,
  `webvulnscanner/scan_routes.py`, `webvulnscanner/scan_engine.py`
- Why fragile: `docs/vercel-migration.md:9-27` documents three specific incompatibilities: (1)
  scans run on a raw daemon `threading.Thread` spawned from the request handler that keeps
  running after the HTTP response returns — a serverless function is frozen/torn down once it
  returns, killing a scan mid-flight (a scan "routinely makes 30+ outbound HTTP requests"); (2)
  the SSE feed (`scan_events()`) is an unbounded `sleep(0.5)`-and-poll loop with no timeout, far
  exceeding Vercel's 10s/60s/300s function execution caps; (3) `scan_engine.save_report()` writes
  to local `reports/`/`downloads/` disk, which does not persist on Vercel's ephemeral `/tmp`.
  `vercel.json`'s own comment and `api/index.py`'s docstring both state outright that "deploying
  this as-is means those routes remain unreliable on Vercel specifically."
- Safe modification: Do not deploy scan-execution routes to Vercel without first building the
  "queue/worker split" `docs/vercel-migration.md` describes as a follow-up project. The
  auth/billing/dashboard/report-rendering routes are confirmed safe for Vercel as-is
  (`docs/vercel-migration.md:33-40`).
- Test coverage: No test coverage targets serverless-specific failure modes (expected, since the
  app is currently deployed via Render/gunicorn per `render.yaml`/`Procfile`, not Vercel).

**Crypto invoice amount-collision handling is probabilistic, not exhaustively verified:**
- Files: `webvulnscanner/billing.py` (`create_invoice()`, `MAX_OFFSET_COLLISION_RETRIES`),
  `webvulnscanner/models.py` (`CryptoInvoice.matched_tx_hash` unique constraint)
- Why fragile: `CLAUDE.md:246-250` documents that `create_invoice()` re-rolls its random
  amount-offset "up to `MAX_OFFSET_COLLISION_RETRIES` times" if it collides with another
  `PENDING` invoice's `expected_amount` for the same plan, since `verify_invoice()` "matches
  purely by amount." A collision that survives all retries (extremely unlikely but not
  impossible under enough concurrent pending invoices for the same plan) could let one real
  payment activate the wrong org's plan; the DB-level unique constraint on `matched_tx_hash` is
  defense in depth against the same transaction being matched twice, not against two different
  pending invoices ending up with the same expected amount.
- Safe modification: Preserve both the retry loop and the `matched_tx_hash` unique constraint
  together; do not relax the retry cap without understanding the amount-matching design in
  `billing.py`.
- Test coverage: `tests/test_billing.py` (259 lines) exercises billing flows; verify it includes
  a collision-retry-exhaustion case before treating this as fully covered.

## Scaling Limits

**SSE progress feed is an unbounded polling loop with no per-scan timeout:**
- Current capacity: Works within the current single-worker, threaded-gunicorn deployment
  (`Procfile`: `gunicorn app:app --workers 1 --threads 4 --timeout 120`) where a long-lived
  connection is tolerable.
- Limit: `docs/vercel-migration.md:19-22` documents `scan_events()` as `sleep(0.5)`-and-poll
  "in a `while` loop until the scan reaches `COMPLETED`/`FAILED`, with no upper bound tied to a
  single scan's duration" — incompatible with any platform enforcing hard per-request execution
  caps (serverless, some reverse-proxy timeout configs).
- Scaling path: Documented in `docs/vercel-migration.md` as needing "a bounded-request redesign"
  (e.g. client-side polling with a max-duration cutoff) if the app is ever deployed to a
  platform with hard execution-time limits.

**Rate limiting counters do not survive a multi-worker or multi-process scale-out:**
- Current capacity: Correct under the current `--workers 1` gunicorn configuration.
- Limit: See "In-memory rate limiting is not multi-worker-safe" above — counters are
  process-local, so scaling workers/processes silently multiplies the effective rate limit
  (or resets it per-process on serverless).
- Scaling path: `webvulnscanner/extensions.py:28` states directly: "Switch `storage_uri` to a
  shared backend (e.g. Redis) if that changes."

## Dependencies at Risk

Not detected — no deprecated/end-of-life dependency warnings, pinned-vulnerable-version notes, or
migration-away plans are documented in `requirements.txt`, `requirements-dev.txt`, `CLAUDE.md`,
`README.md`, or `PRODUCT.md`.

## Missing Critical Features

These are documented, acknowledged product gaps rather than accidental omissions — cited from
`PRODUCT.md`:

**No continuous/scheduled scanning or asset inventory:**
- Problem: `PRODUCT.md:29-31` states the product's "known competitive gap versus tools like
  Nuclei/Trivy/Semgrep is the lack of continuous/scheduled scanning, an asset inventory, and an
  API/CLI-first workflow — acknowledged in project history as future direction, not yet built."
- Blocks: Recurring/automated monitoring use cases; the product is currently one-shot,
  human-triggered scanning only.

**No API/CLI-first workflow:**
- Problem: Same citation as above (`PRODUCT.md:29-31`) — the app is web-UI-only today.
- Blocks: Programmatic/CI-integrated usage of the scanner.

**No plugin/check-extensibility system:**
- Problem: `PRODUCT.md:59-61` lists "whether a plugin/check system... get[s] built" as
  "Explicitly undecided / open per project history, not to be treated as settled... These are
  acknowledged gaps, not commitments."
- Blocks: Third-party or user-authored custom checks; every check currently lives as a hardcoded
  function in `webvulnscanner/checks.py`.

**No compliance-framework mapping:**
- Problem: `PRODUCT.md:60` lists "compliance-framework mapping (OWASP ASVS/Top 10/PCI-DSS)" as
  the same category of undecided/open gap.
- Blocks: Using scan findings directly for compliance-audit evidence or reporting.

**No self-hostable/open-core model:**
- Problem: `PRODUCT.md:43-45` states billing is "self-built crypto invoicing... locked as the
  current model; not under active reconsideration despite an open strategic discussion about
  self-hostable/open-core alternatives," and `PRODUCT.md:61` repeats self-hosting as an
  explicitly undecided/open gap.
- Blocks: Self-hosted or open-source deployment paths for users who don't want the hosted
  crypto-billed SaaS model.

## Test Coverage Gaps

**No dedicated tests for three of the four scan orchestrators:**
- What's not tested: `tests/` has no `test_scan_engine.py` or equivalent module exercising
  `run_advanced_scan`, `run_media_scan`, or `run_api_scan` directly (confirmed via grep — the
  only references to these function names in `tests/` are comments in
  `tests/test_entitlements.py:35` and `:53` about tier-gating behavior, not orchestrator-level
  tests). By contrast, `run_scan()` (base scans) has dedicated coverage in
  `tests/test_scan_events.py` (338 lines) for its `progress_cb` call sequence, `ScanEvent`
  writes, and SSE serialization.
- Files: `webvulnscanner/scan_engine.py` (`run_advanced_scan`, `run_media_scan`, `run_api_scan`)
- Risk: Regressions in the advanced/media/api scan pipelines — e.g. the duplicated scoring logic
  described above, or scan-status/error-handling behavior — would not be caught by the test
  suite; only entitlement-gating around them is verified.
- Priority: Medium — these are Org-verified/Paid-tier-gated, lower-traffic paths than the base
  scan, but they include the most sensitive checks (SQLi login-bypass, brute-force, stored XSS,
  IDOR).

**Thin coverage on org routes relative to other blueprints:**
- What's not tested: `tests/test_org_routes.py` is 15 lines covering a single scenario (member
  verification pill rendering on `/org/admin`). By comparison, `auth_routes.py` has 414 lines of
  tests (`tests/test_auth_flows.py`) and billing has 259 + 58 lines
  (`tests/test_billing.py`/`tests/test_billing_routes.py`).
- Files: `webvulnscanner/org_routes.py` (193 lines), `webvulnscanner/domain_verification.py`
  (120 lines)
- Risk: Org invite flows, member-role changes, and domain-verification submission/status logic
  in `org_routes.py`/`domain_verification.py` have no visible regression coverage beyond the one
  rendering test.
- Priority: Medium — domain verification directly gates the most intrusive checks
  (`entitlements.domain_is_org_verified`), so a regression here has security-relevant blast
  radius even though it isn't itself an intrusive check.

**No test coverage for the checked-in Vercel entrypoint's documented failure mode:**
- What's not tested: `api/index.py`/`vercel.json` exist in the repo and are wired to deploy the
  full Flask app, but `docs/vercel-migration.md` itself states the scan-execution routes are
  "unreliable on Vercel specifically" as currently implemented. No test asserts or documents
  this boundary in an automated way (e.g. skip-marking or flagging scan routes as
  platform-incompatible) — it is prose-only in `docs/vercel-migration.md`.
- Files: `api/index.py`, `vercel.json`, `docs/vercel-migration.md`
- Risk: Low direct risk (this is a known, documented limitation, not a silent bug), but a
  contributor deploying to Vercel without reading `docs/vercel-migration.md` first has no
  automated guardrail catching the mismatch.
- Priority: Low.

---

*Concerns audit: 2026-08-10*
