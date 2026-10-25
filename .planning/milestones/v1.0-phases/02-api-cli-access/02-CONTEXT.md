# Phase 2: API & CLI Access - Context

**Gathered:** 2026-08-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Security engineers can manage assets and trigger/retrieve scans programmatically instead of only
through the web UI — API tokens (separate from session-cookie auth), REST endpoints to list
assets/status, trigger scans, and fetch reports as JSON, and a CLI wrapper over that API.
Requirements: API-01 through API-06 (see REQUIREMENTS.md). Depends on Phase 1 (Asset model,
`entitlements.py` tier gating, `is_ssrf_safe_hostname()`, `_spawn_scan_thread` — all reused
unchanged, not re-architected).

</domain>

<decisions>
## Implementation Decisions

Discussion focused on the token authentication mechanism — the area with the most implementation
leverage and the one every other API-01..06 requirement depends on. The other candidate areas
(API route design/versioning, CLI distribution & auth, rate-limit/tier-gate consistency) were
surfaced but not selected for deep-dive; user confirmed readiness to proceed with research +
planner discretion on those, grounded in existing codebase conventions (see Claude's Discretion
below).

### Token Storage & Verification

- **D-01:** Tokens are hash-only: a random secret is generated and shown to the user exactly once
  at creation time; only its hash (not a prefix-split scheme) is persisted, looked up via an
  indexed hash-column query at request time. No plaintext secret is ever stored or logged. —
  **Reversibility:** costly — **rationale:** moving to a prefix+secret split scheme later (e.g.
  for secret-scanning integration) would require a new column, a token-format change, and
  invalidating/reissuing all existing tokens — not a data migration in the destructive sense, but
  a real breaking change for anyone already using a token.

### Token Scope

- **D-02:** A token is user-scoped — it acts as the specific user who created it and inherits
  that user's exact existing role/permissions (admin vs. member, org membership). No new
  authorization model is introduced; every existing authorization check (ownership,
  `entitlements.py` tier gating, `_check_asset_access`) applies unchanged to a token-authenticated
  request exactly as it would to that user's session-authenticated request. — **Reversibility:**
  one-way — **rationale:** switching to org-scoped tokens with independent roles later would be a
  genuine breaking change to the token's authorization semantics — existing tokens' behavior would
  change or need reissuing, and every route that assumes "the token IS a user" would need
  reworking. This is a foundational decision for how every subsequent API route authorizes
  requests — **do not build routes that assume org-scoped tokens are coming**; build for
  user-scoped semantics as the durable model, not a placeholder.

### Revocation

- **D-03:** Revocation is soft: a `revoked_at` timestamp is set, not a row deletion — mirroring
  Phase 1's `Asset.deleted_at` soft-delete convention. A revoked token fails auth immediately but
  its row (and any audit/usage history attached to it) persists. — **Reversibility:** reversible —
  switching to hard-delete later is a straightforward behavior change, no data-shape migration
  required beyond dropping the soft-delete check.

### Token Count

- **D-04:** A user can hold multiple concurrent, independently-revocable named tokens (e.g. one
  for a CI pipeline, one for a personal script) — not a single-token-per-user model. Requires a
  `name`/label field per token for identification in the token-management UI. — **Reversibility:**
  reversible — collapsing to single-token-per-user later is a UI/validation constraint change, not
  a data-model rewrite (the schema already supports multiple rows per user).

### Token Creation Authority (resolved post-research)

- **D-05:** Any authenticated org member can self-service generate/revoke their own API token —
  not gated to `Role.ORG_ADMIN`. This resolves a tension the researcher flagged between
  REQUIREMENTS.md's API-01 literal text ("org admin can generate...tokens") and D-02's
  user-scoped model: API-01 is reinterpreted as "any user acting within their org," matching
  D-02's premise that a token simply acts as the user who created it — there is no separate
  admin-gated token-issuance authority to build. — **Reversibility:** reversible — adding an
  admin-only restriction later is a single added authorization check on the create-token route,
  not a data-model or existing-token-semantics change.

### Ownership-Check Mismatch (flagged by research, scoped to this phase)

The researcher found a pre-existing Phase 1 gap: `scan_routes._check_ownership` attributes
Asset-fired Scans to `asset.created_by_user_id`, which disagrees with `asset_routes.
_check_asset_access`'s org-shared ownership model. API-04 (fetch report via API) would inherit
this gap unless addressed. Left to planner discretion whether to fix it narrowly (route API-04's
report-fetch through `_check_asset_access(scan.asset)` instead of the mismatched
`_check_ownership`) or flag it as a cross-cutting fix for a later phase — the narrow, in-scope fix
is preferred since it's directly in this phase's new code path and low-risk, but do not expand
this into an app-wide `_check_ownership` refactor (out of scope for this phase).

### Claude's Discretion

The following areas were surfaced as gray areas but not deep-dived; researcher/planner have
discretion to resolve them using existing codebase conventions and the locked decisions above as
constraints:

- **API route design & versioning** — exact URL prefix/blueprint structure (e.g. `/api/v1/...`),
  JSON response/error envelope shape, and pagination approach for the asset-list endpoint (API-02).
  Must be consistent with this project's existing blueprint-per-feature convention (Phase 1's
  `asset` blueprint, `auth_routes.py`, `org_routes.py`, etc.).
- **CLI distribution & authentication** — how the CLI tool (API-06) ships (installable
  console-script entry point vs. a single downloadable script) and how it authenticates locally
  (token in a config file vs. environment variable vs. CLI flag). Must accept a user-scoped token
  (per D-02) and use it exactly as the web UI's session would for authorization purposes.
- **Rate-limit & tier-gate consistency** — how API endpoints reuse Flask-Limiter and
  `entitlements.py` so token-authenticated access cannot bypass what the web UI and Phase 1's
  scheduler already enforce (API-05). Must mirror Phase 1's fire-time tier re-check pattern
  (`entitlements.effective_tier_for_org`/`allowed_checks`) — tier is checked fresh per request,
  never cached on the token.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & product context
- `.planning/REQUIREMENTS.md` §"API & CLI Access (API)" — API-01 through API-06, the full locked
  requirement list for this phase.
- `.planning/PROJECT.md` §"Constraints" — safety-critical-code-frozen rule (authorization,
  SSRF, entitlements gating must apply identically on every new scan-trigger path, including
  API-triggered scans per API-03).
- `.planning/ROADMAP.md` §"Phase 2" — goal and success criteria this phase is accountable to.

### Phase 1 foundation (this phase builds directly on top of, does not re-architect)
- `.planning/phases/01-asset-inventory-continuous-scanning/01-01-SUMMARY.md`,
  `01-02-SUMMARY.md` — what Phase 1 actually built: `Asset` model, `asset` blueprint
  (`/assets`, `/assets/new`, `/assets/<id>`, schedule/pause/resume/delete routes),
  `scheduler.py`'s fire-time tier re-check pattern (`entitlements.effective_tier_for_org`),
  `_check_asset_access`'s solo-user-vs-org 404-not-403 ownership convention.
- `.planning/phases/01-asset-inventory-continuous-scanning/01-VERIFICATION.md` — confirms the
  Asset/scheduler foundation this phase's endpoints will expose is real and tested (172/172,
  independently verified).

### Codebase map
- `.planning/codebase/ARCHITECTURE.md` — blueprint-per-feature convention, existing
  authentication (Flask-Login session-based) this phase adds a second auth path alongside.
- `.planning/codebase/CONVENTIONS.md` — naming/error-handling/docstring conventions new
  `api_routes.py` and CLI code should match.
- `.planning/codebase/STACK.md` — confirms Flask-Limiter and no existing token-auth library in
  `requirements.txt` — a token scheme is new to this codebase, not a pre-existing pattern to copy.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `entitlements.effective_tier_for_org(org)` (`glassbox/entitlements.py`, added in Phase 1)
  — org-shaped tier lookup already extracted for the scheduler; the API layer should call this
  same helper rather than re-deriving tier from a session-bound `current_user`.
- `_check_asset_access` (`glassbox/asset_routes.py`, Phase 1) — the 404-not-403
  ownership-check convention (including the solo-user `org_id IS NULL` IDOR fix) — API routes
  reading/mutating an Asset must reuse this exact function, not re-implement ownership checks.
- `is_ssrf_safe_hostname()` (`checks.py`) — reuse directly for API-03 (triggering a scan via API
  must enforce the same SSRF gate as the web UI and scheduler).
- Flask-Limiter (`glassbox/extensions.py`) — existing rate-limiter instance; new API
  endpoints should register limits through it rather than introducing a second rate-limiting
  mechanism.

### Established Patterns
- Blueprint-per-feature: each major capability gets its own routes module (`auth_routes.py`,
  `org_routes.py`, `asset_routes.py`, …) registered in `glassbox/__init__.py`'s
  `create_app()`. A new `api_routes.py` (and a separate CLI module/package) should follow this
  same registration pattern.
- Fire-time / request-time re-checking, never cached: Phase 1 established that tier and SSRF
  safety must be re-verified at the moment of action (scheduler fire), not trusted from
  registration time. This phase's API-triggered scans (API-03) must follow the identical
  principle — re-check tier and SSRF safety per request, not per token.
- Soft-delete/soft-disable over hard delete: `Asset.deleted_at` (Phase 1) established the house
  convention this phase's `revoked_at` (D-03) follows.

### Integration Points
- New token model needs a foreign key to `User` (not `Organization` — tokens are user-scoped per
  D-02) and a `name` field (per D-04).
- New `api_routes.py` blueprint will call into the same `scan_engine`/`checks`/`entitlements`
  layer Phase 1's `asset_routes.py` and `scheduler.py` already call — no parallel scan-execution
  path should be introduced for API-triggered scans (API-03/API-04).
- CLI tool is a new, separate piece of distributable code (not a Flask blueprint) that talks to
  the API layer as an HTTP client — its own module/package location is left to planner discretion.

</code_context>

<specifics>
## Specific Ideas

No bespoke visual or behavioral references beyond the four locked token-auth decisions above —
all four were accepted as the recommended option during discussion (hash-only token storage,
user-scoped tokens inheriting existing permissions exactly, soft-disable revocation matching
Phase 1's Asset convention, and multiple named tokens per user).

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope. No scope-creep suggestions came up during this
session; the three areas left to Claude's Discretion above are within-phase implementation
ambiguity, not new capabilities.

</deferred>

---

*Phase: 2-API & CLI Access*
*Context gathered: 2026-08-10*
