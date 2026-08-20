# Phase 9: SEO, Performance & UX States - Context

**Gathered:** 2026-08-19
**Status:** Ready for planning

<domain>
## Phase Boundary

Public marketing/legal pages (marketing home, terms, privacy) become correctly discoverable and
indexable while every authenticated app route stays out of search surfaces entirely; dashboard/
org-admin list queries and unbounded lists (scan history, asset list, org members, findings) don't
degrade as data grows; and every page communicates its loading/empty/error condition clearly
instead of going blank or stalling silently (SEO-01..04, PERF-01..02, STATE-01..03). Depends on
Phase 6's canonical component set (empty-state/alert/card/pill patterns) per ROADMAP.md.

This phase closes the v1.1 milestone. No phase in this milestone proposes changing the billing/
SaaS shape, the Fly.io deployment model, or the rule-based-only detection convention — none of
that is touched here either.

</domain>

<decisions>
## Implementation Decisions

### SEO delivery mechanism
- **D-01:** `robots.txt` and `sitemap.xml` are served by dynamic Flask routes that build their
  content from the app's own `url_map` at request time, not static files — so the Disallow list
  can't silently drift from reality as new authenticated routes are added later. Same discipline
  Phase 8's route-enumeration locks already established in this codebase (`tests/test_cross_org_idor.py`'s
  registry, the SEC-01 inventory table). — **Reversibility:** reversible — a route can always be
  swapped for a static file later with no data migration.

### SEO scope
- **D-02:** Beyond ROADMAP's minimum (title, meta description, canonical URL, Open Graph on
  marketing/terms/privacy; none of these on authenticated pages) — also add Twitter Card tags
  (`twitter:card`, `twitter:title`, `twitter:description`, `twitter:image`) reusing the same OG
  values, no new data to generate. **Explicitly not adding**: JSON-LD structured data — deferred,
  not this phase.

### Pagination
- **D-03:** Numbered-page pagination (`?page=N`, Prev/1 2 3/Next controls) for unbounded lists —
  scan history, asset list, org members, findings — not "load more"/infinite-scroll (avoids new JS
  plumbing in a server-rendered Jinja app) and not a bare cap-with-link (the capped list still needs
  its own pagination eventually, so build it once). Default page size: **20 per page**.
  — **Reversibility:** costly — once templates/routes assume page-N query params and offset/limit
  queries, switching to a different pagination shape (cursor-based, load-more) touches every
  converted route and template again, not just a config value.

### Empty/loading/submitting states
- **D-04:** Extract a shared `_empty_state.html` partial (icon/title/message/CTA-slot API, same
  convention as `_scan_form_styles.html`/`_admin_form_styles.html`) rather than copy-pasting
  `dashboard.html`'s or `asset_detail.html`'s existing one-off empty-state markup to every other
  list. Both existing instances get migrated onto the new partial too, so there is exactly one
  empty-state implementation app-wide, not three. — **Reversibility:** reversible — a partial's
  internals can change without touching call sites, that's the point of extracting it now.
- **D-05:** Extend the auth-forms submitting-state pattern (disabled button + loading indicator) to
  **all** of: the four scan-launch forms (base/advanced/media/api — the clearest case, each has a
  multi-second round-trip before redirecting to the progress page), org-admin forms (invite,
  domain add/verify, schedule updates), billing forms (create/verify invoice), and account/settings
  forms (API token create/revoke, profile/password changes). App-wide, not scoped to just the
  highest-value forms.

### Scan-state gaps (failed / timed-out / duplicate-concurrent)
- **D-06:** Real gap found during discussion, not assumed: **no duplicate-concurrent-scan guard
  exists today** (two scans against the same target+user can run simultaneously with no check at
  all — `grep` for "duplicate"/"concurrent"/"already running" across `scan_routes.py` found
  nothing), and **no scan-level wall-clock timeout exists** (only per-HTTP-request timeouts inside
  individual `check_*` functions in `checks.py` — a hung scan has no outer bound and would run
  indefinitely). A `ScanStatus.FAILED` state does already exist but isn't currently surfaced with a
  specific reason.

  **Decision: full scope.** This phase adds both guards, not just messaging for what already
  exists:
  1. A duplicate-concurrent-scan check — refuse or redirect a new scan submission if a `RUNNING`
     scan already exists for the same target+user, following the app's existing ownership-check
     conventions (`_check_ownership`-style pattern) rather than inventing a new one.
  2. A scan-level wall-clock timeout that marks a stuck scan `FAILED` with a specific, recorded
     reason instead of running forever.
  3. All three conditions (failed, timed-out, duplicate) then get distinct, specific messages in
     the UI — not a single generic "scan failed" catch-all.

  This is real new backend behavior (route logic + a timeout mechanism), not just a template pass —
  research/planning should treat it as such, sized accordingly. — **Reversibility:** reversible for
  the duplicate-scan check (a route-level guard, easy to relax later); **costly** for the timeout
  mechanism if it ends up woven into `run_scan()`'s internals rather than wrapping the outer
  `threading.Thread` dispatch — planner should prefer wrapping the existing
  `_run_scan_in_background`/thread-dispatch layer over threading a timeout through each of the four
  orchestrators individually, to keep this reversible and to avoid touching `scan_engine.py`'s four
  orchestrator bodies (which Phase 8's `test_scan_engine.py` source-locks already assert acquire
  their session a specific way — don't disturb those locks incidentally).

### Claude's Discretion
- Exact pixel/spacing values for pagination controls and the empty-state partial's layout — Phase 6
  already established the canonical spacing/typography scale; use it, don't invent new values.
- Exact wording of the failed/timed-out/duplicate/empty-state messages — plain-language, matching
  the tone of this codebase's existing scan-wizard copy pass (Phase 5).
- Where exactly the scan-level timeout value lives (a new config constant vs. reusing an existing
  one) and its default duration — research should look at what's typical for this app's scan sizes
  before picking a number.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Design system (Phase 6/7 — reuse, don't reinvent)
- `templates/base.html` — canonical typography/spacing tokens, `.card`/`.btn`/`.pill`/`.badge`/
  `.warn-box`/`.error-box`/`.info-box` component styles, `.table-scroll` wrapper, `.status-pill`
  with `.dot`/`.glow-pulse` states — the empty-state partial and pagination controls must draw from
  these, not introduce new component styles.
- `.planning/phases/06-design-system-consistency/06-CONTEXT.md` — the typography/spacing/container
  decisions this phase's UI work must stay consistent with.
- `.planning/phases/07-responsive-accessibility-compliance/07-CONTEXT.md` — the mobile stacked-card
  data strategy (D-01) already applied to tables; pagination controls and the empty-state partial
  need to work at the same 320px-and-up range this phase already proved out.

### Security frozen surfaces (Phase 8 — do not touch)
- `.planning/phases/08-security-re-audit-hardening/08-VERIFICATION.md` — confirms `entitlements.py`,
  `checks.is_ssrf_safe_hostname()`'s body, `billing.py`, and `authorized*` checkbox handling are
  frozen; the duplicate-scan/timeout work in D-06 must not touch any of these.
- `tests/test_scan_engine.py` — the per-orchestrator `_mk_session()` source-parsing lock added in
  Phase 8 (08-04). A scan-level timeout mechanism must not be implemented by editing the four
  orchestrator function bodies in a way that could trip this lock incidentally.

### Project-level
- `CLAUDE.md` — "Adding a new base-scan check" / "Architecture" sections for how `scan_routes.py`/
  `scan_engine.py`/`checks.py` are laid out; the authorized-use constraint (irrelevant to this
  phase's app-internal-only scope, but confirms D-06's guards target the app's own scan-dispatch
  logic, not an external scan target).
- `.planning/REQUIREMENTS.md` §SEO/PERF/STATE — literal wording of SEO-01..04, PERF-01..02,
  STATE-01..03.
- `.planning/ROADMAP.md` §Phase 9 — the 5 success criteria this phase's plans must satisfy.

No other external specs/ADRs apply — requirements fully captured in decisions above.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `templates/dashboard.html`, `templates/asset_detail.html` — existing one-off empty-state markup;
  source material for the new `_empty_state.html` partial (D-04), not to be left as-is once the
  partial exists.
- Auth pages (login/signup/forgot/reset) — existing submitting-state pattern (disabled button +
  loading indicator) to extend per D-05.
- `webvulnscanner/org_routes.py` — already has `.limit(50)`/`.limit(30)` query caps on some listing
  queries (invite/member lists) — a partial precedent for D-03's pagination work, though not
  full page-N pagination.
- `webvulnscanner/scan_routes.py:1111` — `.limit(MAX_LIFECYCLE_SCANS)` on a scan-history query —
  another existing cap to potentially convert to real pagination.
- Phase 8's `_check_ownership`/`_check_asset_access` pattern in `scan_routes.py`/`asset_routes.py`
  — the shape D-06's duplicate-concurrent-scan guard should follow for consistency.

### Established Patterns
- `templates/_scan_form_styles.html`, `templates/_admin_form_styles.html` — the existing
  shared-partial convention (unscoped element selectors that would leak if promoted into
  `base.html` directly) that `_empty_state.html` should follow.
- `webvulnscanner/scan_routes.py`'s `_run_scan_in_background` — the shared background-thread
  dispatch tail all four scan types already go through; the natural wrapping point for D-06's
  scan-level timeout rather than threading it through `scan_engine.py`'s four orchestrators.

### Integration Points
- `webvulnscanner/public_routes.py` — currently only serves `/` (marketing); `robots.txt`/
  `sitemap.xml` routes (D-01) belong here, generated from `app.url_map`.
- `templates/base.html`'s `{% block title %}`/head area — currently has only a generic `<title>`;
  the meta description/canonical/OG/Twitter Card tags (D-02) need a template block structure that
  public pages fill in and authenticated pages leave empty.

</code_context>

<specifics>
## Specific Ideas

No particular visual references given beyond "reuse what Phase 6 already established" — this phase
is explicitly about consistency and closing real gaps, not introducing a new visual direction.

</specifics>

<deferred>
## Deferred Ideas

- JSON-LD structured data (Organization/SoftwareApplication schema markup) — explicitly deferred
  per D-02, not this phase.
- Cursor-based/infinite-scroll pagination — explicitly rejected in favor of numbered pages (D-03),
  noted here only so a future phase doesn't have to re-litigate why numbered pages were chosen.

### Reviewed Todos (not folded)
None — no pending todos matched this phase's scope at discussion time.

</deferred>

---

*Phase: 9-SEO, Performance & UX States*
*Context gathered: 2026-08-19*
