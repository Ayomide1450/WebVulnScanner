# Phase 8: Security Re-Audit & Hardening - Context

**Gathered:** 2026-08-18
**Status:** Ready for planning

<domain>
## Phase Boundary

Every route, form, redirect target, and file-serving path across the app — including the API
tokens, scheduler, asset routes, and platform-admin panel added in v1.0 — is verified
server-side to enforce the same ownership, CSRF, SSRF, injection, and information-disclosure
guarantees the product already promises, with any gap found closed and covered by a regression
test. This phase **verifies and closes gaps; it does not redesign** `authorized*`,
`entitlements.py`, `checks.is_ssrf_safe_hostname()`, or `billing.py`'s verification logic — those
stay frozen per CLAUDE.md.

Ten requirements (SEC-01..SEC-10) map to five success criteria in ROADMAP.md: cross-org
IDOR across every ID-accepting route (incl. `/api/v1/*`), CSRF on every state-changing route,
SSRF redirect-following, XSS/SQLi/path-traversal sweeps, and open-redirect/secrets/billing-replay/
error-leakage checks.

</domain>

<decisions>
## Implementation Decisions

### Verification depth
- **D-01:** Beyond code-review and Flask-test-client integration tests (matching the existing
  `_check_ownership` test pattern across all four call sites), this phase also runs a live
  dev-server probe pass: start `python app.py` locally with two seeded test orgs/users, and fire
  real HTTP requests at the running instance to attempt cross-org IDOR/CSRF bypass, not just
  simulate it through the test client. This targets the app's **own** local routes/auth
  boundaries — it is not an external-domain scan and does not touch `checks.py`'s scan pipelines
  or CLAUDE.md's authorized-use constraint (which governs scanning *someone else's* infrastructure,
  not testing this app's own auth logic against itself).
- **D-02:** The live probe pass is a verification step, not a replacement for the automated
  regression-test suite — every finding (live-probed or code-reviewed) still needs a
  Flask-test-client regression test added so the guarantee survives without a live server running.

### Handling a live finding
- **D-03:** If a genuinely live, exploitable gap is found (not just a missing test), fix it
  immediately within this phase — matching the roadmap goal's "with any gap found closed" — and
  record it plainly in the plan's summary (what the gap was, the exact route/function, the fix,
  and the regression test that now locks it). No pause for sign-off before shipping the fix,
  consistent with this project's established pattern this session of moving fast on
  low-ambiguity, high-confidence fixes. — **Reversibility:** reversible — a security fix inside an
  existing route handler is a targeted code change, not a schema/contract change.

### Priority ordering
- **D-04:** Sequence work by blast radius, not ROADMAP.md's listed order: **SEC-01 (cross-org
  IDOR) and SEC-02 (CSRF) first**, since a hit on either is a full authorization bypass across
  the whole multi-tenant model; **SEC-09 (billing replay/tampering/cross-org invoice access)
  second**, since a hit there is direct financial impact; then SEC-03 (SSRF redirects), SEC-04/05/06
  (XSS/SQLi/path-traversal), SEC-07 (open redirect), SEC-08 (secrets sweep), SEC-10
  (error-leakage) in roughly that order. If the phase is interrupted mid-way (a real risk per
  this session's history of transient API/rate-limit failures), the highest-risk gaps are the
  ones already known.

### Adjacent thin-test coverage
- **D-05:** While auditing `org_routes.py`/`domain_verification.py` (CSRF/ownership) and the three
  under-tested scan orchestrators (`run_advanced_scan`/`run_media_scan`/`run_api_scan` — see
  `.planning/codebase/CONCERNS.md`'s "thin coverage" findings), backfill the baseline regression
  tests those files are already missing, as a natural byproduct of the audit rather than a
  separately scoped task. Do not expand this into a general test-coverage initiative beyond what
  auditing these specific files for the five success criteria already requires touching.

### Claude's Discretion
- Whether SEC-01..SEC-10 become one large plan or several parallel-wave plans is a planning-time
  call (gsd-planner's job), not decided here — the priority ordering (D-04) constrains sequencing
  within whatever plan structure the planner chooses, it does not mandate the plan count.
- The live-probe pass's exact tooling (a standalone `requests`-based Python script under a
  scratch/temp location, `curl` invocations, or pytest's own test client against a `live_server`
  fixture) is left to the planner/researcher to pick based on what's idiomatic for this repo's
  existing test infra (`tests/conftest.py`).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Frozen surfaces (do not weaken or redesign)
- `glassbox/entitlements.py` — tier/domain-verification gating; `FEATURE_REQUIREMENTS`
- `glassbox/checks.py` `is_ssrf_safe_hostname()` — submission-time-only SSRF guard; see its
  docstring for what it does and does not protect against (no DNS-rebinding pinning — accepted
  residual gap, explicitly out of scope, see REQUIREMENTS.md Out of Scope table)
- `glassbox/billing.py` — invoice creation/verification, `MAX_OFFSET_COLLISION_RETRIES`
  collision-retry logic
- `authorized` / `authorized_adv` / `authorized_media` / `authorized_api` checkbox checks
  (wherever enforced server-side across `scan_routes.py`)

### Existing security patterns to extend, not replace
- `glassbox/scan_routes.py` `_check_ownership` — the existing IDOR guard, already tested
  "across all four call sites" per CLAUDE.md; the pattern SEC-01's new coverage should match
- `glassbox/auth_routes.py` `_safe_next()` — the existing open-redirect guard for
  login/forgot-password; SEC-07 extends this same pattern to invite/logout/next-param paths
- `extensions.limiter` (Flask-Limiter) rate-limiting on `/login`, `/signup`, invoice create/verify
  — relevant context for SEC-02 (CSRF) and SEC-09 (billing) audits
- `templates/404.html`/`429.html`/`500.html` — already render inside the app's own theme instead
  of Flask's raw default error page; SEC-10 confirms they (and 400/401/403) leak nothing further
  in production mode

### Requirements & scope
- `.planning/REQUIREMENTS.md` §Security & Hardening (SEC-01..SEC-10) and §Out of Scope
  (DNS-rebinding pinning explicitly excluded — do not reopen)
- `.planning/ROADMAP.md` §Phase 8 — the five success criteria this phase's plans must satisfy
- `.planning/codebase/CONCERNS.md` — "Thin coverage on advanced/media/api orchestrators" and
  "Thin coverage on org routes" sections, source for D-05's backfill scope
- `CLAUDE.md` — authorized-use constraint (governs scanning external targets, distinct from D-01's
  self-testing probe pass), frozen-surface list, testing commands

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `_check_ownership` (scan_routes.py) — existing per-scan IDOR guard pattern; SEC-01's new
  coverage for asset/domain/invoice/token/org/user routes should follow the same shape
  (server-side org-membership check before returning data, tested at every call site)
- `_safe_next()` (auth_routes.py) — existing origin-restricted redirect guard; SEC-07 extends the
  identical pattern rather than inventing a new one
- `tests/conftest.py` — per-test fresh Flask app against its own on-disk SQLite file; CSRF and
  rate-limiting disabled by default (note: SEC-02's CSRF audit will need a test variant with CSRF
  re-enabled, mirroring how `tests/test_auth_flows.py` already re-enables `RATELIMIT_ENABLED` for
  one dedicated 429 test)

### Established Patterns
- Every `check_*` function returns `(data, findings)` and never raises past itself — not directly
  relevant to Phase 8's route-security audit, but establishes this codebase's general
  fail-safe-degrade convention (mirrored in `ai_summary.py`'s never-raises contract)
- `billing.create_invoice()` re-rolls its amount-offset on collision, with a DB-level unique
  constraint on `matched_tx_hash` as defense in depth — the existing model SEC-09 verifies still
  holds and extends if a gap is found

### Integration Points
- `/api/v1/*` surface is explicitly named in SEC-01 — confirm which blueprint(s) register it
  during research, since it's not named elsewhere in this CONTEXT and needs its own ownership-check
  audit pass distinct from the HTML routes

</code_context>

<specifics>
## Specific Ideas

No specific implementation examples given beyond the four decisions above — this phase is
audit-and-close-gaps against an already-fully-specified success-criteria list, not open design
space.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope. (DNS-rebinding-proof SSRF pinning remains explicitly
out of scope per REQUIREMENTS.md, not re-raised here.)

</deferred>

---

*Phase: 8-security-re-audit-hardening*
*Context gathered: 2026-08-18*
