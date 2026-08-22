# Phase 5: New Scan Flow Redesign - Context

**Gathered:** 2026-08-15
**Status:** Ready for planning

<domain>
## Phase Boundary

Replace today's 4 disconnected single-form `scan_new_*.html` pages (plus the `scan_new.html`
chooser) with one guided Select Domain → Select Type → Confirm Authorization → Start Scan flow.
Covers target selection (verified-domain dropdown + free-text fallback), plain-language scan-type
availability labeling, tier/verification-aware "Upgrade to Unlock" CTAs, and closing the
View-Report reachability gap for scan types without a live progress feed. Does not touch scan
execution logic, `checks.py`, `entitlements.py`'s gating rules, or `is_ssrf_safe_hostname()` —
this phase is presentation/flow only, routing through the exact same
`_launch_base_scan()`/`_unsafe_target_error()`/tier-check gates that already exist.

</domain>

<decisions>
## Implementation Decisions

### Domain-picker data source
- **D-01:** The "Select Verified Domain" dropdown lists only the user's org's verified
  `DomainVerification` records (`verified_at IS NOT NULL`, `org_id` scoped) — not `Asset` records,
  which may not be domain-verified. Free-text target entry remains an equally-visible parallel
  input alongside the dropdown, not hidden behind an "Other" toggle, since unclaimed/one-off
  targets are a first-class, explicitly-required use case (SCANUX-02).

### Wizard scope — which scan types get the guided flow
- **D-02:** All 4 scan types (base/advanced/media/api) go through the same
  Select Domain → Select Type → Confirm Authorization → Start Scan shell. Choosing "Advanced" as
  the type routes into its existing credentialed form (login URL, session cookie, test-account
  fields) to collect the fields the wizard's generic domain-picker step can't — reuses
  `scan_new_advanced.html`'s existing form logic rather than building new credential-collection UI.
  — **Reversibility:** costly — reworking this later to a fully unified dynamic form would mean
  redoing the routing between the generic wizard shell and Advanced's dedicated form.

### Upgrade-to-Unlock behavior
- **D-03:** The CTA is context-aware: it links to `/billing` when the actual blocking gate is
  tier/plan, and links to `org.verify_domain_view` when the actual blocking gate is
  domain-verification (e.g., Advanced's checks need `Tier.ORG_VERIFIED` **and** a verified domain
  for the exact target — a plan upgrade alone wouldn't unlock it). Reuses the same
  `can_run_paid`/`can_run_org_verified`/`can_run_media`/`can_run_api` flags `_tier_flags()` already
  computes plus a per-target `domain_is_org_verified()` check to decide which destination applies.

### Wizard scope — Advanced's intake form (supersedes D-02's "as-is" clause)
- **D-02a (2026-08-17):** D-02's decision that Advanced routes into its own dedicated Step-3 form
  still stands. What's superseded is the *shape* of that form: it no longer starts with all 16 raw
  credential fields exposed. Instead it opens as **URL-first** (one target field + the
  `authorized_adv` checkbox), and only after authorization is confirmed does the page call
  `POST /scan/new/advanced/detect` (new route) to auto-crawl the target and pre-fill the
  login-bypass group's `login_url`/`login_user_field`/`login_pass_field` where a login form can be
  found (`checks.detect_login_form()`). All four check groups render as collapsed
  `<details>` cards with plain-language, non-jargon headings and field-level micro-copy (how to get
  a session cookie from DevTools, etc.); the login group auto-expands when detection finds a match.
  Field **names** (`login_url`, `login_user_field`, ... all 16) are unchanged — `_parse_advanced_form`,
  the four `has_*_group` predicates, and every server-side gate are byte-identical to before this
  change; only the template's presentation and one new read-only detection endpoint were added.
  — **Reversibility:** moderate — the detect endpoint and progressive-disclosure markup can be
  removed without touching engine/gating code, but the plain-language copy would need rewriting
  back to the old technical labels.
- Rationale: 05-02-PLAN.md's original acceptance criteria (`grep -c "request.form.get('" ... 16`,
  full field-by-field redisplay) were written for the raw-form shape and needed updating to match;
  the field-repopulation *behavior* they were protecting (never silently blank a validation-error
  redisplay) is preserved and still tested in `tests/test_scan_wizard.py`.

### Post-launch / View Report reachability
- **D-04:** Extend the existing auto-redirect-on-completion behavior to scan types that don't have
  a live SSE feed. Base scans already redirect `scan_detail` → `scan_report` via the SSE `status
  === 'completed'` handler in `scan_progress.html`. Advanced/media/api's progress page (the
  "plain bar/status-line-only view" `CLAUDE.md` already documents) currently has no polling at
  all — add a lightweight interval poll against `scan_detail`'s existing COMPLETED-redirect logic
  (or a small dedicated status endpoint) so those three scan types get the same
  "lands on the report automatically once done" behavior as base scans, closing the real gap
  rather than treating SCANUX-05 as already satisfied.

### Claude's Discretion
- Exact wizard mechanics (separate page-per-step with server-side state vs. one page with
  progressive JS-revealed sections) — implementation approach, not a user-facing vision decision.
  Follow the codebase's existing convention (GET+POST per route, minimal/no JS framework, forms
  posting directly) rather than introducing new client-side state machinery.
- Exact wording/copy for the plain-language availability labels (Included / Requires Verified
  Domain / Requires Paid Plan) beyond what SCANUX-03 already specifies verbatim.
- Whether the poll interval in D-04 reuses the existing `/scan/<id>/events` SSE endpoint (even
  though advanced/media/api don't emit `ScanEvent` rows, the endpoint still reports `status`) or a
  new lightweight status-only endpoint — pick whichever avoids duplicating query logic.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Existing scan-launch flow (being replaced/extended)
- `templates/scan_new.html` — current 4-card chooser landing page
- `templates/scan_new_base.html` — current base-scan form (bulk-target textarea, tier hints)
- `templates/scan_new_advanced.html`, `templates/scan_new_media.html`, `templates/scan_new_api.html`
  — current per-type forms; Advanced's credential fields are the ones D-02 says stay as-is
- `templates/_scan_form_styles.html` — shared CSS partial across all 5 scan_new_* templates
- `webvulnscanner/scan_routes.py` — `new_scan()` (line ~367), `new_scan_base()` (~420),
  `new_scan_advanced()` (~490), `new_scan_media()` (~554), `new_scan_api()` (~604),
  `_tier_flags()` (~312), `_unsafe_target_error()` (~323), `_launch_base_scan()` (~376),
  `scan_detail()` (~648) — the COMPLETED-redirect logic D-04 extends
- `webvulnscanner/models.py` — `DomainVerification` (line 133, org-scoped verified-domain records
  D-01's dropdown queries), `Asset` (line 165, explicitly NOT the D-01 data source)
- `webvulnscanner/entitlements.py` — `Tier` enum, `FEATURE_REQUIREMENTS`,
  `domain_is_org_verified()` — the functions D-03's context-aware CTA branches on

### Design system this phase must build within (not redesign — that's Phase 6)
- `templates/base.html` — `.btn`/`.card`/`.pill`/`.badge` canonical components; do not invent new
  ones here even though this phase ships new templates — Phase 6 (Design System Consistency) is
  sequenced right after this phase specifically so it only has to audit these new pages once, in
  final form

No external ADR/SPEC docs exist for this phase — requirements fully captured in
`.planning/REQUIREMENTS.md`'s SCANUX-01..05 plus the decisions above.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `_tier_flags(tier)` (scan_routes.py) already computes `can_run_paid`/`can_run_org_verified`/
  `can_run_media`/`can_run_api` — the exact booleans the new "Included / Requires Verified Domain /
  Requires Paid Plan" labels need per scan type.
- `_unsafe_target_error()` and `_launch_base_scan()` already centralize the SSRF/ownership/
  cross-org-domain gate — the wizard's Confirm/Start step must call into these unchanged, not
  reimplement validation.
- `domain_is_org_verified(org, url)` (entitlements.py) — exactly the check D-03's context-aware CTA
  needs to distinguish "needs a plan upgrade" from "needs domain verification".

### Established Patterns
- Every existing scan_new_* route follows GET-renders-form / POST-validates-and-launches with
  `request.form.get('target', '')` repopulation on validation error (note: CLAUDE.md's bug history
  flags a past regression here — `scan_new_base.html` once read `request.args` instead of
  `request.form` on error, silently clearing user input; don't reintroduce that class of bug in
  any new step).
- `authorized`/`authorized_adv`/`authorized_media`/`authorized_api` checkboxes are server-side
  `required` form fields checked in the POST handler, never trusted from client state alone — the
  new Confirm Authorization step must submit one of these same checkbox fields, not a new
  client-only confirmation.

### Integration Points
- `scan_detail()`'s existing COMPLETED → redirect-to-report logic is the mechanism D-04 extends
  for advanced/media/api, not a new mechanism.
- The dashboard's empty-state / "New scan" CTA and `base.html`'s nav link both point at the stable
  `/scan/new` URL (`scan.new_scan`) — keep this endpoint name/URL stable per `new_scan()`'s own
  docstring even as its template changes.

</code_context>

<specifics>
## Specific Ideas

No further specific UI references beyond what's already locked in D-01..D-04 and REQUIREMENTS.md's
SCANUX-01..05 wording (exact labels: "Standard Scan", "Included" / "Requires Verified Domain" /
"Requires Paid Plan", "Upgrade to Unlock").

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

### Process note (not phase-scoped, carried forward as a standing practice)
The user asked that `handoff.md` be kept updated at every stage of this milestone, not just at
session end — this is a working-memory doc (gitignored, not part of `.planning/`) that prior
sessions repeatedly flagged as *should update continuously* but didn't. Applies to every phase in
this milestone, not just Phase 5.

</deferred>

---

*Phase: 5-new-scan-flow-redesign*
*Context gathered: 2026-08-15*
