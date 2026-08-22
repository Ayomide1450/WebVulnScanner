# Phase 7: Responsive & Accessibility Compliance - Research

**Researched:** 2026-08-18
**Domain:** Responsive CSS (mobile-first breakpoints, table→card conversion) and WCAG 2.1 AA
accessibility (semantic HTML, ARIA naming, keyboard operability, color contrast) applied to an
existing, already-consolidated Flask/Jinja2 server-rendered design system.
**Confidence:** HIGH (all findings grounded in a direct read of every in-scope template and
`base.html` this session, plus verified WCAG 2.1 success-criterion text)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Mobile data-table strategy**
- **D-01:** Hybrid responsive data strategy, not a blanket approach. Explicitly rejected: making
  horizontal-scroll the default mobile solution for every table (the CLAUDE.md-documented
  existing scroll-container precedent from commit `a567fb4` is NOT to be extended app-wide by
  default in this phase).

  **Mobile (≤~430px):** dashboard, org-admin, billing, findings/scan-report tables all become
  **stacked cards**, not scrolled tables. Each card shows only:
  - Primary identifier/title
  - Severity/status
  - Most important metadata
  - Key value
  - Primary action
  - Secondary details only when genuinely useful (not every column blindly copied in)

  Cards link to a full record/detail view rather than cramming every column onto the card —
  preserve information hierarchy, don't just reflow the table.

  **Desktop:** keep proper semantic `<table>`s where tabular comparison is genuinely useful —
  clear column hierarchy, sticky headers where appropriate, sort/filter controls, sensible
  column widths, row hover/focus states, good density without overcrowding.

  **Horizontal scroll is the exception, not the default** — reserve it only for data that
  genuinely needs many columns and doesn't represent well as cards (if any such table exists;
  audit during planning rather than assuming one does).

  Mobile quality bar at 320–430px: no accidental page overflow, no tiny text, no compressed
  columns, no clipped content, ~44px+ touch targets, most important info visible immediately,
  actions easy to reach, long values wrap/truncate intelligently, details expand progressively.
  Priority order for what a mobile card surfaces: **Understand → Act → View details** — not
  "preserve the desktop table structure at a smaller size."

  — **Reversibility:** partially reversible. The stacked-card markup is new per-table (not a
  small CSS-only change like Phase 6's token work) — swapping strategy later means rewriting
  that markup again, not just adjusting a token. Worth getting right per-table during planning
  rather than treating as a mechanical global find/replace.

### Claude's Discretion

Other Phase 7 success criteria (keyboard/AT operability, heading hierarchy, WCAG AA contrast
including severity-colored text/badges) are left to the researcher/planner to handle against the
roadmap's existing success criteria — no additional user decisions were requested or given for
those this session.

### Deferred Ideas (OUT OF SCOPE)

None raised this session — discussion was scoped to the one gray area (mobile table strategy)
the user chose to weigh in on.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|--------------------|
| RESP-01 | Every page renders without horizontal scroll, clipped text, or overlapping elements at 320/375/768/1280px, verified live | Environment Availability names the live-browser verification tool; Validation Architecture maps this to a `checkpoint:human-verify` gate per page family, matching Phase 6's established gate pattern |
| RESP-02 | Auth pages and org setup pages have a polished, non-cramped mobile layout with the product name correctly positioned relative to the form | Common Pitfalls (Pitfall 5) identifies the actual page set (`.auth-wrap` pages vs. `org_verify_domain.html`'s `.wrap`) and flags the ambiguity as Open Question 1 rather than guessing a fix |
| RESP-03 | Dashboard/org-admin/billing/scan-report tables use a deliberate mobile strategy, not silent overflow clipping | Architecture Patterns 1-3 (dual-markup table→card conversion, `<thead>`/`<tbody>` retrofit, `scan_report.html`'s diagnostic-vs-record-list triage) are the concrete implementation path for D-01 |
| RESP-04 | The live scan-progress feed remains legible/usable at mobile widths, re-confirmed not assumed | Summary and Code Examples document the two `@media` breakpoints (`min-width:880px`, `max-width:480px`) already shipped in `scan_progress.html`, reframing this requirement as a re-confirmation task, not new build work |
| A11Y-01 | Every form input has an associated `<label>`; every icon-only control has an accessible name | Don't Hand-Roll documents the already-correct `aria-label`/`<label for>` patterns to extend; ripgrep audit this session found labels already well-formed across all 35 templates, narrowing the actual remaining work |
| A11Y-02 | Heading hierarchy is sequential, non-skipping on every major template | Common Pitfalls (Pitfall 4) names the two confirmed, concrete violations (`marketing.html`, `scan_new_advanced.html`) found via an exhaustive heading-tag grep this session |
| A11Y-03 | All interactive elements are keyboard-reachable/operable with a visible focus state | Don't Hand-Roll confirms the global `:focus-visible` ring already exists in `base.html`; a codebase-wide `onclick`/`role="button"`/`tabindex` grep this session found zero clickable-`<div>` violations, narrowing A11Y-03 to a confirmation walkthrough |
| A11Y-04 | Text/UI-element color contrast meets WCAG AA, including severity-colored finding text/badges | Common Pitfalls (Pitfalls 1-3) present hand-computed WCAG luminance math showing the token palette already passes, and scope the real remaining risk to two specific opacity/hardcoded-color cases |
</phase_requirements>

## Summary

This phase is a verify-and-fix pass, not new visual design — Phase 6 already gave every template
one canonical token set (`base.html`: 11-role typography, `--space-*`/`--radius-*`/`--container-*`
tokens, `.btn`/`.pill`/`.status-pill`/`.card`/`.warn-box` component canon) and every check this
phase performs must build on that cascade, never reintroduce a local override. The codebase is
vanilla server-rendered HTML/CSS with no build step, no JS framework, and no component library —
so "responsive" and "accessible" here mean hand-authored `@media` queries and semantic markup
fixes across ~35 templates, not a library swap.

Three concrete, verified gaps drive most of the phase's work. First, `base.html`'s data tables
(`dashboard.html`, `org_admin.html`, `api_tokens.html`, `assets.html`, `asset_detail.html`,
`org_verify_domain.html`) are plain `<table>` markup with **no `<thead>`/`<tbody>`**, wrapped only
in the pre-existing `.table-scroll` horizontal-scroll class from commit `a567fb4` — exactly the
default-scroll pattern D-01 rejects as the mobile answer for these "record list" tables. Second,
`marketing.html` and `scan_new_advanced.html` both have **verified heading-hierarchy skips**
(`<h2>`→`<h4>` with no `<h3>` in between, in two places on the marketing page; `<h4>` appearing
*before* any `<h2>`/`<h3>` on the advanced-scan page) — concrete, fixable A11Y-02 violations, not
a hypothetical audit target. Third, `scan_progress.html` already has two mobile breakpoints
(`min-width:880px` for the two-column grid, `max-width:480px` for the log header) from a prior
session — RESP-04 is a **re-confirm**, not a from-scratch build, and research here should save the
planner from re-doing work that's already shipped.

Manually computing WCAG relative luminance for every severity/status color token
(`--critical`/`--high`/`--medium`/`--low`/`--info`/`--accent`/`--telemetry`) against both
`--bg` (#020617) and `--panel` (#0b1220) shows **every text-color token already clears 4.5:1**
(the tightest case, `--muted` #8b96ad on `--panel`, computes to ~6.3:1) — the OLED-dark palette
Phase 6 formalized was already contrast-safe for AA normal text. The genuine risk areas are
narrower: `.btn:disabled`/`.pill.not-checked`'s `opacity:.5`/`.65` treatments (opacity blending
toward the page background can silently drop a passing color below 4.5:1), and the four
hardcoded (non-token) gauge-stroke colors in `_gauge.html` that were never audited by Phase 6.
Both should get a scripted/tool-confirmed check rather than an assumption either way.

**Primary recommendation:** Treat this phase as five parallelizable audit-and-fix tracks — (1) the
D-01 stacked-card conversion for the ~6 "record list" tables (`<thead>`/`<tbody>` addition +
dual-markup card block, CSS `display` swap at the breakpoint, one new mobile-card partial pattern
per table family), (2) the two verified heading-skip fixes plus a systematic scan of every other
template for the same class of bug, (3) a `<label for>`/icon-button accessible-name sweep (the
codebase's existing precedent — `aria-label` on every `.pw-toggle`/`.icon-btn` — is already good;
extend it, don't reinvent it), (4) a keyboard-walkthrough + `:focus-visible` audit (the ring
already exists globally in `base.html`, so this is confirmation, not new CSS), and (5) a
contrast-tool-confirmed pass over the two genuine risk areas (disabled-opacity states, hardcoded
gauge colors) rather than the whole palette, which the math above already clears.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Responsive breakpoints (media queries) | Browser / Client (CSS) | — | Pure CSS `@media` rules evaluated client-side; no server involvement beyond serving the same HTML/CSS to every viewport |
| Stacked-card vs. table markup (D-01) | Frontend Server (SSR, Jinja2) | Browser / Client (CSS `display` swap) | Jinja renders both the `<table>` and the card markup into the same response; CSS decides which is visible at a given viewport — this is a Flask/Jinja SSR app, there is no client-side hydration tier |
| Heading hierarchy / semantic HTML | Frontend Server (SSR, Jinja2) | — | Heading tags are baked into the rendered template; no client-side DOM manipulation changes them |
| Keyboard operability / `:focus-visible` | Browser / Client (CSS + native HTML semantics) | — | Native `<button>`/`<a>`/`<input>`/`<select>` are keyboard-operable by default; `:focus-visible` is a CSS pseudo-class already defined globally in `base.html` |
| Color contrast (WCAG AA) | Browser / Client (CSS custom properties) | — | All color decisions are CSS custom properties in `base.html`; no server-side color logic exists |
| Icon-only control accessible names | Frontend Server (SSR, Jinja2 `aria-label`) | — | `aria-label` values are rendered server-side (e.g. `aria-label="Delete {{ asset.name }}"` in `asset_detail.html`) — this pattern is already established and should be extended, not replaced |

No API/Backend or Database/Storage tier work exists in this phase's scope — CLAUDE.md explicitly
excludes touching `authorized*` checkbox logic, `entitlements.py`, and
`checks.is_ssrf_safe_hostname()`; this phase is templates/CSS/markup only.

## Standard Stack

### Core

No new libraries, packages, or build tooling are introduced by this phase — `06-UI-SPEC.md`
confirms (and this session's own read of `base.html` confirms again) there is no `package.json`,
no `components.json`, no Tailwind config, no npm/shadcn in this repo. Responsive/accessible
behavior is implemented entirely in hand-authored CSS inside `<style>` blocks (`base.html` +
the shared `_*_form_styles.html`/`_legal_styles.html` partials) and Jinja2 template markup.

| Standard | Version | Purpose | Why Standard |
|----------|---------|---------|---------------|
| WCAG | 2.1 Level AA | The compliance target named explicitly in A11Y-01..04 and RESP success criteria | Industry baseline for web accessibility; matches the requirement text verbatim |
| CSS Media Queries (`@media`) | CSS3 (Level 4 range syntax not required) | Breakpoint implementation | Already the app's only responsive mechanism (`base.html` line 253, `dashboard.html`/`billing.html`/`marketing.html`/`platform_admin.html`/`scan_progress.html` all already use `min-width`/`max-width` `@media` rules) |
| Native HTML5 semantics (`<button>`, `<label for>`, `<thead>`/`<tbody>`, heading levels) | HTML Living Standard | Keyboard operability, screen-reader table/label association | No ARIA-widget reinvention needed for anything in scope — every interactive element in this codebase is already a real `<button>`/`<a>`/`<input>`, not a `<div>` (confirmed by this session's `onclick`/`role="button"`/`tabindex` grep across all templates: zero clickable-`<div>` hits found) |

### Supporting (manual verification tools, not installed dependencies)

| Tool | Purpose | When to Use |
|------|---------|-------------|
| Browser DevTools responsive/device-toolbar mode (Chrome/Firefox/Edge, all pre-installed, no install step) | Live 320/375/768/1280px viewport checks (RESP-01 success criterion) | Every `checkpoint:human-verify` task this phase creates |
| WebAIM Contrast Checker (webaim.org/resources/contrastchecker, free, no signup) or a browser's built-in DevTools contrast inspector (Chrome/Firefox color picker shows live contrast ratio) | A11Y-04's "confirmed with a contrast-checking tool" requirement | Verifying the two genuine risk areas below (disabled-opacity states, `_gauge.html`'s hardcoded stroke colors) — the rest of the token palette is already computed safe in this research, see Common Pitfalls |
| axe DevTools browser extension (free tier) — optional, not required | Broader automated a11y scan as a supplementary sanity check | Optional; not a substitute for the manual keyboard walkthrough A11Y-03 requires |

**Installation:** None — no `npm install`/`pip install` step for this phase's actual deliverable.
`beautifulsoup4` is already a project dependency (`requirements.txt` line 3) and is available if
the planner wants a Wave-0 test helper that parses rendered HTML for `<label for>`/heading-tag
assertions (see Validation Architecture below) — no new package needed.

**Version verification:** N/A — no packages to verify against a registry this phase.

## Package Legitimacy Audit

**Not applicable.** This phase installs zero external packages (confirmed: no new `pip`/`npm`
dependency is required by any of RESP-01..04/A11Y-01..04 — all work is CSS/Jinja2 markup against
the existing `beautifulsoup4`/Flask/pytest stack already in `requirements.txt`/
`requirements-dev.txt`). The Package Legitimacy Gate protocol is skipped per its own "whenever
this phase installs external packages" trigger condition.

## Architecture Patterns

### System Architecture Diagram

```
Browser request (any viewport width)
        |
        v
Flask route (scan_routes.py / org_routes.py / etc. -- UNCHANGED this phase)
        |
        v
Jinja2 template render (templates/*.html)
        |
        +--> base.html cascade: typography/spacing/radius/container tokens (Phase 6, frozen)
        |
        +--> Page template renders BOTH:
        |      (a) semantic <table> markup (desktop-shaped, kept for narrow-viewport
        |          horizontal-scroll exception cases only)
        |      (b) mobile stacked-card markup (D-01: primary identifier, severity/status,
        |          key value, primary action -- curated subset, not all columns)
        |
        v
Single HTML response ships to the browser (no client-side hydration --
this is plain server-rendered HTML, not a React/Vue SPA)
        |
        v
CSS @media query at the client decides which of (a)/(b) is display:block
vs display:none for the current viewport width
        |
        v
Keyboard/AT user tabs through native <button>/<a>/<input> elements --
:focus-visible ring (already global in base.html) shows current position
```

### Recommended Project Structure

No new directories. Within `templates/`, the existing convention already separates shared,
unscoped-selector CSS into `_*_form_styles.html`/`_legal_styles.html` partials specifically
because those selectors (`label`, `input`, `button`) would otherwise leak into every other form.
**Follow the same discipline for any new table→card partial**: if a stacked-card treatment ends
up shared verbatim across 2+ tables (e.g. the "Target/Type/Status/Score/Created" shape used by
both `dashboard.html`'s Scan History table and `asset_detail.html`'s Scan history table), extract
it into a new `_scan_history_card.html`-style partial rather than duplicating the card markup
inline in both templates — matching the precedent `_gauge.html` already set for the shared
score-gauge widget.

### Pattern 1: Dual-markup table→card conversion (D-01's chosen strategy)

**What:** Render two markup blocks for the same data — the existing semantic `<table>` (desktop)
and a new curated card list (mobile) — and let a CSS `@media` query show exactly one at a time.

**When to use:** Every "record list" table named in D-01: `dashboard.html`'s Scan History table,
`org_admin.html`'s Members/Pending Invitations/Verified domains/Scan History tables,
`api_tokens.html`'s tokens table, `assets.html`'s assets table, `asset_detail.html`'s Scan history
table, `org_verify_domain.html`'s domains table.

**Why dual-markup instead of the CSS-only `data-label::before` reflow trick:** D-01 explicitly
requires the mobile card to show a *curated subset* (primary identifier → severity/status → key
value → primary action, "not every column blindly copied in") and to link out to a full detail
view rather than cramming every column onto the card. A CSS-only relabeling trick (hide `<thead>`,
inject the column name via `td::before { content: attr(data-label) }`) can only reflow the *same*
columns — it cannot drop columns, reorder them, or add a "view details" link that isn't already a
cell. Since the content itself differs, not just its layout, two Jinja blocks are the correct
implementation, matching what the phase's own research question suggested as the best fit for
this codebase's existing per-partial CSS pattern.

**Example (illustrative Jinja/CSS shape, not literal current code):**
```html
<!-- Desktop: existing semantic table, wrapped in .table-scroll as today -->
<div class="table-scroll desktop-table">
  <table>
    <thead><tr><th>Target</th><th>Type</th><th>Status</th><th>Score</th><th>Created</th><th></th></tr></thead>
    <tbody>
      {% for s in scans %}
      <tr>
        <td><code>{{ s.target_url }}</code></td>
        <td>{{ scan_type_labels.get(s.scan_type, s.scan_type|title) }}</td>
        <td>{{ latest_status_pill(s.status.value) }}</td>
        <td>{{ s.risk_score if s.risk_score is not none else '-' }}</td>
        <td>{{ s.created_at.strftime('%b %d, %Y %H:%M') }}</td>
        <td><a class="row-link" href="{{ url_for('scan.scan_detail', scan_id=s.id) }}">View &rarr;</a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<!-- Mobile: curated card list, hidden by default, shown only under the breakpoint -->
<ul class="mobile-record-cards">
  {% for s in scans %}
  <li class="card record-card">
    <div class="record-card-top">
      <code class="record-card-id">{{ s.target_url }}</code>
      {{ latest_status_pill(s.status.value) }}
    </div>
    <div class="record-card-meta">{{ s.risk_score if s.risk_score is not none else '-' }} / 100 &middot; {{ s.created_at.strftime('%b %d') }}</div>
    <a class="btn secondary block" href="{{ url_for('scan.scan_detail', scan_id=s.id) }}">View &rarr;</a>
  </li>
  {% endfor %}
</ul>
```
```css
/* Desktop-first; mobile shows the curated card instead of the table below ~430px,
   matching D-01's "Mobile (<=~430px)" threshold. */
.mobile-record-cards { display: none; }
@media (max-width: 430px) {
  .desktop-table { display: none; }
  .mobile-record-cards { display: flex; flex-direction: column; gap: var(--space-3); list-style: none; margin: 0; padding: 0; }
}
```
`[VERIFIED: templates/dashboard.html:306-327]` — the exact table this pattern targets:
```
<h2 class="section">Scan History</h2>
<div class="card">
  {% if scans %}
  <div class="table-scroll">
  <table>
    <tr><th>Target</th><th>Type</th><th>Status</th><th>Security Score</th><th>Created</th><th></th></tr>
    {% for s in scans %}
    <tr>
      <td><code>{{ s.target_url }}</code></td>
      <td>{{ scan_type_labels.get(s.scan_type, s.scan_type|title) }}</td>
      <td>{{ latest_status_pill(s.status.value) }}</td>
      <td>{{ s.risk_score if s.risk_score is not none else '-' }}</td>
      <td>{{ s.created_at.strftime('%b %d, %Y %H:%M') }}</td>
      <td><a class="row-link" href="{{ url_for('scan.scan_detail', scan_id=s.id) }}">View &rarr;</a></td>
    </tr>
    {% endfor %}
  </table>
  </div>
  {% else %}
  <div class="empty-state">No scans yet. ...</div>
  {% endif %}
</div>
```

### Pattern 2: `<thead>`/`<tbody>` retrofit (accessibility + a prerequisite for Pattern 1)

**What:** Every table currently found in this codebase renders as bare `<table><tr><th>...`
with no `<thead>`/`<tbody>` wrapper — confirmed by this session's grep of `scan_report.html`,
`dashboard.html`, `org_admin.html`, `api_tokens.html`, `assets.html`, `asset_detail.html`,
`org_verify_domain.html` (20+ `<table>` occurrences, zero `<thead>`/`<tbody>` hits across all of
them). `[VERIFIED: templates/dashboard.html:311]` — `<tr><th>Target</th><th>Type</th>...` with no
enclosing `<thead>`, immediately followed by data `<tr>`s with no `<tbody>`.

**When to use:** Every table touched by this phase (whether it gets the D-01 card treatment or
stays a table). Adding `<thead>`/`<tbody>` is a zero-risk, purely-additive semantic fix — it does
not change `base.html`'s `table, th, td { ... }` CSS selector behavior (both selectors still
match) and materially improves screen-reader table navigation (JAWS/NVDA/VoiceOver's
table-navigation commands rely on `<thead>` to identify column headers when a user jumps to a
later row). Bundle this into whichever task touches each table's markup rather than opening a
separate pass — it's a one-line wrap, not new layout work.

### Pattern 3: Curated-vs-diagnostic table triage for `scan_report.html`

**What:** `scan_report.html` is architecturally different from the other four D-01 pages — it
contains **20+ separate `<table>` elements** (Security headers, Cookies, TLS, Exposed secrets,
JWT tokens, SRI, Open ports, HTTP methods, Open redirects, Directory listing, DNS/email records,
Vulnerable JS, Crawled forms, XSS/SQLi probe results, SQLi login-bypass/time-based rows,
Brute-force attempts, SQLi UNION variants, IDOR resource rows, Media items, API-exposure paths x3)
`[VERIFIED: templates/scan_report.html:231-796, table tag positions confirmed via grep this
session]`, almost all nested inside collapsed `<details>` accordions and already wrapped in
`.table-scroll`. These are **diagnostic/attribute dumps** (2-7 narrow columns of raw check
output), not the "record list with a primary action" shape D-01 describes (identifier + severity
+ status + key value + primary action, linking to a detail view). The page's actual *Findings*
section — the part a user reads first — already renders as `.finding` cards, not a table
(`[VERIFIED: templates/scan_report.html:118-129]`, the `finding_card` macro emits a `<div
class="finding {{ f.severity }}">`, never a `<tr>`).

**When to use:** Do not blanket-convert all 20+ diagnostic tables to D-01's stacked-card shape —
that is out of proportion to what D-01 asks for and risks losing at-a-glance tabular comparison
that a security engineer actually wants for e.g. the headers-grade table. Treat these as
candidates for D-01's own named exception ("horizontal scroll is the last-resort exception... for
data that genuinely needs many columns and doesn't represent well as cards") — audit each one
during planning for whether its content genuinely needs stacked-card treatment (e.g. the
"attempts"/media-items tables that behave more like a record list) vs. whether it should simply
keep `.table-scroll` + gain `<thead>`/`<tbody>` per Pattern 2 and be confirmed not to overflow the
card at 320px (D-01's own "audit whether any such table actually exists — don't assume one does"
instruction, applied literally: this phase already found the tables that instruction warns about).

### Anti-Patterns to Avoid

- **CSS-only `td::before { content: attr(data-label) }` reflow for the D-01 tables:** produces
  the *same* columns relabeled, not the curated subset D-01 requires. Only appropriate for the
  diagnostic tables in Pattern 3 if a planner decides one of those needs a lighter-weight fix than
  full card conversion — never for the primary record-list tables.
- **Reintroducing a page-local `<style>` override of `.card`/`.btn`/`table, th, td`:** Phase 6
  spent 4 plans consolidating these into `base.html`; any new mobile-card CSS must extend the
  existing `.card` class (`background: linear-gradient(...); border-radius: var(--radius-md);`)
  rather than redefining card shape locally.
  `[VERIFIED: templates/base.html:165]` — `.card { background: linear-gradient(180deg, var(--panel), var(--panel2)); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 22px; margin-bottom: 18px; }`
- **Replacing a `<form method="POST">` + `<button type="submit">` destructive action with a
  `<div onclick>` or bare JS `href` during card-layout rework:** every destructive action in this
  codebase (asset delete, token revoke, domain deletion request) is a real CSRF-protected form
  submission with a `confirm()` dialog — this pattern must survive the D-01 markup rework
  unchanged; converting it to a JS-only click handler would both break CSRF protection and betray
  A11Y-03 (a `<div>` is not natively keyboard-operable).
- **Snapping icon-only-button touch targets down to the compact `.verify-btn`/`.revoke-btn`
  13px/6px-12px-padding treatment inside a new mobile card:** that treatment is well below the
  ~44px touch target D-01 itself specifies as the mobile quality bar. `asset_detail.html` already
  established the correct pattern — `.icon-btn { min-width: 44px; min-height: 44px; ...}` — reuse
  that class for any new icon-only mobile-card action, not the admin-table compact button.
  `[VERIFIED: templates/asset_detail.html:43]`

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|--------------|-----|
| Focus-visible ring | A custom `:focus` outline per component | `base.html`'s existing global `:focus-visible { outline: 2px solid var(--ring); outline-offset: 2px; border-radius: 4px; }` (line 68) | Already defined once, globally, using the `--ring` token (= `--accent`) — every native interactive element inherits it for free; a component-local override would fragment the one consistent focus treatment Phase 6/pre-Phase-6 already established |
| Password-visibility toggle accessible-name updates | A new pattern | The existing `.pw-toggle` JS (`login.html`/`signup.html`/`reset_password.html`) which already does `btn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password')` on click | Already correct and dynamic — don't touch, and use as the reference pattern for any other icon-only toggle needing a state-dependent accessible name |
| Icon-only button accessible names | A new ad hoc convention | `aria-label="<verb> <specific target>"` on the `<button>` itself, matching `asset_detail.html`'s `aria-label="Delete {{ asset.name }}"` / `aria-label="Pause schedule for {{ asset.name }}"` | Already-proven, Jinja-interpolated, screen-reader-correct pattern in this exact codebase — extend it verbatim rather than inventing `aria-labelledby`/visually-hidden-span alternatives for the same problem |
| Contrast-ratio math | A custom JS contrast calculator | WebAIM Contrast Checker or browser DevTools' built-in contrast inspector | One-off manual verification task, not a runtime feature — no reason to ship contrast-calculation code in the app itself |
| Destructive-action confirmation | A custom modal/dialog component | The existing `confirm()` + `.btn.destructive` pattern (`asset_detail.html`, `api_tokens.html`) | CLAUDE.md's Copywriting Contract explicitly names this as the established, to-be-extended pattern — not to be redesigned this phase |

**Key insight:** almost everything this phase needs (focus ring, icon-button naming, destructive
confirmation) already exists correctly somewhere in the codebase from Phase 1/2/6 work — the job
is *auditing for consistency and extending coverage*, not designing new interaction patterns.

## Common Pitfalls

### Pitfall 1: Assuming the whole severity/status color palette needs a contrast fix

**What goes wrong:** Treating A11Y-04 as "redesign the color tokens" when the tokens are already
compliant.
**Why it happens:** The phase description explicitly calls out "including severity-colored
finding text/badges" as a thing to check, which reads like a known problem.
**How to avoid:** This session computed WCAG relative luminance for every severity/status/accent
text-color token (`--critical` #f87171, `--high` #fb923c, `--medium` #fbbf24, `--low` #60a5fa,
`--info`/`--muted` #8b96ad, `--accent`/`--pass` #22c55e, `--telemetry` #38bdf8) against both
`--bg` (#020617) and `--panel` (#0b1220) `[VERIFIED: templates/base.html:16-19,25 for the exact
hex values used in this calculation]`. Every one clears 4.5:1 — the tightest case (`--muted` on
`--panel`) computes to ~6.3:1, and most clear 7-9:1. `.btn.primary`'s inverted case (`#041007`
text on `var(--accent)` background) also clears ~8.5:1. **Do not budget planner time to redesign
the palette** — instead spend the A11Y-04 budget on the two areas this math does *not* cover:
**Warning signs:** A plan task titled "redesign severity colors for contrast" is almost certainly
solving an already-solved problem; redirect that task to the two items below instead.

### Pitfall 2: `opacity` states silently failing contrast even though the base color passes

**What goes wrong:** `.btn:disabled { opacity: .5; }` `[VERIFIED: templates/base.html:81]` and
`.pill.not-checked { opacity: .65; ... }` `[VERIFIED: templates/asset_detail.html:24]` both blend
an otherwise-passing text color toward whatever sits behind it, which can drop effective contrast
below 4.5:1 depending on the background — opacity blending isn't captured by a single token's
"does this color pass" check, since the result depends on the composite, not the token alone.
**Why it happens:** Contrast audits often check the CSS custom property values, not the rendered,
opacity-composited result.
**How to avoid:** Verify these two specific opacity states with a live contrast-checking tool
(screenshot the rendered disabled button / not-checked pill, sample the actual pixel color) rather
than computing from the token value alone.
**Warning signs:** Any `opacity` value under 1 applied to text or a text-containing element is a
contrast-audit blind spot until it's checked in its rendered, composited state.

### Pitfall 3: `_gauge.html`'s hardcoded stroke colors were never brought into the token system

**What goes wrong:** Assuming every color in the app already went through Phase 6's token
consolidation.
**Why it happens:** Phase 6's scope was typography/spacing/radius/container tokens and component
canon — it didn't audit every hardcoded color literal.
**How to avoid:** `_gauge.html`'s SVG stroke color is a 4-way hardcoded hex ternary — `stroke=
"{{ '#34d399' if score >= 90 else ('#fbbf24' if score >= 60 else ('#fb923c' if score >= 40 else
'#fb7185')) }}"` `[VERIFIED: templates/_gauge.html:23]` — none of these four hex values
(`#34d399`, `#fbbf24`, `#fb923c`, `#fb7185`) match `base.html`'s `--pass`/`--medium`/`--high`/
`--critical` tokens exactly (they're close but not identical: e.g. `#fb7185` vs. `--critical`
`#f87171`). This is decorative (the gauge always pairs the color with a plain-text number/grade,
so it's not the only way the information is conveyed — WCAG doesn't require decorative-only color
to hit text contrast), but it should still get a tool-confirmed check against the `--panel`/
`--bg` gradient it renders on, since it was never verified by any prior phase.
**Warning signs:** Any `stroke=`/`fill=`/inline `color:` literal that doesn't reference a
`var(--*)` token is a candidate this class of gap — a quick `grep -rn '#[0-9a-fA-F]\{6\}'
templates/` during planning will surface any others.

### Pitfall 4: Heading-hierarchy skips already exist and are easy to miss on a skim

**What goes wrong:** Assuming "no heading skips found yet" because a quick skim of a page reads
top-to-bottom sensibly, without checking the actual tag sequence.
**Why it happens:** Visual size doesn't always match tag level in this codebase (e.g.
`06-UI-SPEC.md` documents `.tier-card h3` being deliberately sized like an H2 for visual
prominence) — a page can *look* hierarchical while its tags skip a level.
**How to avoid:** This session grepped every `<h1>`-`<h6>` tag across all 35 templates and found
two confirmed skips: `marketing.html` goes `<h2>What WebVulnScanner checks</h2>` directly to
`<h4>Exposed secrets</h4>` (and 10 sibling `<h4>`s) with no `<h3>` in between
`[VERIFIED: templates/marketing.html:191,198]`, and again `<h2>How it works</h2>` directly to
`<h4>Enter your domain</h4>` `[VERIFIED: templates/marketing.html:310,316]`.
`scan_new_advanced.html` has four `<h4>` elements (accordion group labels, e.g. `<h4>Can someone
log in as another user without the password?</h4>`) appearing *before* the page's only `<h2>`
(the locked-state availability heading, later in the same file) — `[VERIFIED:
templates/scan_new_advanced.html:31,81,110,127,152,185]`, `h1` at line 31 then `h4` at line 81 is
the actual document order, confirmed by reading the file this session. Every other template
audited (`dashboard.html`, `org_admin.html`, `billing.html`, `asset_detail.html`, `assets.html`,
`api_tokens.html`, `org_verify_domain.html`, `platform_admin.html`, `scan_compare.html`,
`scan_progress.html`, `scan_report.html`, `terms.html`, `privacy.html`, all auth pages, error
pages) uses strictly sequential `h1`→`h2`(→`h3` where present) with no skip.
**Warning signs:** Any `<h4>` (or deeper) used purely for visual size rather than document
structure is a skip candidate — check its actual position relative to the nearest preceding
`<h2>`/`<h3>`, not just its font size.

### Pitfall 5: Assuming `org_verify_domain.html` is an "auth-pattern" page for RESP-02

**What goes wrong:** Applying the `.auth-wrap`/`--container-auth` (440px, centered) treatment to
`org_verify_domain.html` because RESP-02 groups it with "org setup pages."
**Why it happens:** RESP-02's phrasing ("org setup pages (create org, add domain, verify domain)")
reads as one uniform page family alongside the five true auth pages.
**How to avoid:** This session confirmed there is no separate "create org" page at all — org
creation happens via the optional `org_name` field on `signup.html`
(`[VERIFIED: templates/signup.html:46-50]`, "Give your organization a name to create it and
become its admin. Leave blank to sign up solo."), which already uses `.auth-wrap`. **Add/verify
domain, however, is `org_verify_domain.html`, which uses `.wrap`/`--container-app` (1040px), not
`.auth-wrap`** `[VERIFIED: templates/org_verify_domain.html:7]` — it's structurally an
app-shell page (form card + a data table below it), matching `org_admin.html`'s pattern, not the
five narrow centered auth-card pages. Apply RESP-02's "product name correctly positioned relative
to the form" check specifically to the five `.auth-wrap` pages (`login`/`signup`/
`forgot_password`/`reset_password`/`verify_email`) where the topnav-brand-to-form relationship is
the actual open question (see Open Questions below); audit `org_verify_domain.html`'s mobile
layout under RESP-03's table-strategy lens instead (it has exactly the "record list" domains
table D-01 targets).
**Warning signs:** A plan task that applies `--container-auth` styling to `org_verify_domain.html`
is solving the wrong container-width mismatch.

## Code Examples

### Existing global focus-visible ring (already correct, do not duplicate)
```css
/* Source: templates/base.html:68 -- verified this session */
:focus-visible { outline: 2px solid var(--ring); outline-offset: 2px; border-radius: 4px; }
```

### Existing icon-only accessible-name pattern (already correct, extend verbatim)
```html
<!-- Source: templates/asset_detail.html:62,69,76 -- verified this session -->
<button type="submit" class="btn secondary icon-btn" aria-label="Resume schedule for {{ asset.name }}">
  <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#icon-play"/></svg>
</button>
```

### Existing dynamic aria-label pattern for a toggle button (already correct, extend verbatim)
```javascript
// Source: templates/login.html (bottom <script>) -- verified this session
document.querySelectorAll('.pw-toggle').forEach(function (btn) {
  btn.addEventListener('click', function () {
    var input = document.getElementById(btn.dataset.toggleFor);
    var showing = input.type === 'text';
    input.type = showing ? 'password' : 'text';
    btn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
  });
});
```

### Existing partial two-column-to-stacked responsive pattern (RESP-04 precedent to confirm, not rebuild)
```css
/* Source: templates/scan_progress.html:38-39,50-54 -- verified this session */
.soc-grid { display:grid; grid-template-columns: 1fr; gap: 18px; margin-top: 18px; }
@media (min-width: 880px) { .soc-grid { grid-template-columns: minmax(0, 2fr) minmax(240px, 1fr); align-items:start; } }
...
@media (max-width: 480px) {
  .soc-log-header { flex-direction: column; align-items: flex-start; }
  .bar-track { width: 100%; max-width: none; }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|-------------------|---------------|--------|
| Horizontal-scroll-by-default for any table that might overflow (`.table-scroll`, commit `a567fb4`) | Deliberate per-table strategy: stacked cards for record-list tables, scroll reserved for genuinely-many-column diagnostic tables | This phase (D-01, 07-CONTEXT.md) | `.table-scroll` stays for the `scan_report.html` diagnostic-table family (Pattern 3 above) but is no longer the default answer for dashboard/org-admin/billing/api-tokens/assets record-list tables |
| Ad hoc/no `aria-label` on icon-only controls | Consistent `aria-label="<verb> <target>"` server-rendered pattern | Phase 1/2 (asset_detail.html, api_tokens.html precedent already exists) | This phase extends existing good coverage rather than establishing it from zero |

**Deprecated/outdated:** None specific to this phase — no library upgrades or API changes are in
scope; this is a markup/CSS audit against a stable, already-modernized token system.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|----------------|
| A1 | RESP-02's "product name correctly positioned relative to the form" most likely refers to the topnav-brand-to-auth-card vertical spacing/redundant-CTA relationship on the five `.auth-wrap` pages, not a literal brand-inside-the-card requirement | Common Pitfalls (Pitfall 5), Open Questions | If the actual intended meaning is different (e.g. wanting the brand *inside* the auth card, not just the topnav), the planner should treat this as an open design question for `/gsd-discuss-phase` or resolve it during the phase's own visual checkpoint, not assume this research's reading is correct |
| A2 | The two heading-skip violations found (`marketing.html`, `scan_new_advanced.html`) are the *only* skips in the app — based on an exhaustive grep of every `<h1>`-`<h6>` this session, not a sampling | Common Pitfalls (Pitfall 4) | Low risk — the grep was exhaustive (all 35 templates, all heading tags), but a planner should still spot-check headings introduced by any template this research didn't quote in full |
| A3 | `_gauge.html`'s hardcoded stroke colors likely still pass AA contrast against the panel gradient (visually similar hue/lightness to the verified token equivalents) but were not individually computed this session | Common Pitfalls (Pitfall 3) | If one of the four hex values is meaningfully darker/lower-contrast than estimated, a tool-confirmed check would catch it before the planner assumes it's fine by similarity alone |

## Open Questions

1. **What exactly does "product name correctly positioned relative to the form" mean for RESP-02?**
   - What we know: The five `.auth-wrap` pages already have a functioning topnav brand-link
     above a centered, `--container-auth` (440px)-wide card. At narrow widths the topnav
     collapses to a stacked brand-then-nav-links column (`@media (max-width: 640px)` in
     `base.html`), and the card below it starts with `padding-top: var(--space-7)` (48px). The
     login/signup pages also show the nav's own "Login"/"Sign up" links alongside the in-card
     "swap" link (e.g. login shows both a nav "Sign up" CTA and a bottom-of-card "Don't have an
     account? Sign up" link) — mild redundancy on a short mobile viewport.
   - What's unclear: Whether the intended fix is (a) tightening the vertical gap between brand
     and card, (b) something about the brand icon/text sizing at narrow widths, (c) the CTA
     redundancy between topnav and in-card swap link, or (d) something not identifiable from
     static template reading alone (would require an actual rendered screenshot at 320-375px to
     see, which this research phase did not produce).
   - Recommendation: The planner should schedule a `checkpoint:human-verify` early in this
     phase's plan — before committing to a specific CSS fix — that screenshots the five auth
     pages at 320/375px so the actual visual gap (not a guess) drives the fix. Don't guess-fix
     this one blind.

2. **Which of `scan_report.html`'s 20+ diagnostic tables, if any, should get full D-01 card
   treatment vs. stay `.table-scroll`?**
   - What we know: Most are narrow (2-4 columns), already collapsed inside `<details>`
     accordions, and read as attribute dumps rather than record lists. A few (media items table,
     bruteforce-attempts table) have more of a "row = one thing that happened" record shape that
     might benefit from cards.
   - What's unclear: Without live-rendering each at 320px, it's not certain which ones actually
     overflow their card at that width (D-01's own instruction: "audit whether any such table
     actually exists — don't assume one does").
   - Recommendation: Have the planner allocate one task specifically to render/screenshot (or
     `grep`-measure likely content width of) each of `scan_report.html`'s tables at the smallest
     breakpoint before deciding the card-vs-scroll split, rather than deciding it from static
     template reading alone.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|-------------|-----------|---------|----------|
| A browser with responsive/device-toolbar dev tools (Chrome/Firefox/Edge) | RESP-01..04 live viewport checks, keyboard walkthrough (A11Y-03) | Assume ✓ (standard on any dev machine) | n/a | None needed — this is a standard, universally-available tool |
| A contrast-ratio checking tool (WebAIM web tool or browser DevTools color picker) | A11Y-04 | Assume ✓ (WebAIM is a free public web page, no install; DevTools ship with every major browser) | n/a | None needed |
| Local Flask dev server (`python app.py`) | Rendering pages to check live, same setup Phase 6 already used | ✓ (documented in CLAUDE.md's Commands section, already proven working this milestone) | n/a | None needed |

No missing dependencies — this phase requires no new tool, service, or package installation.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest (already configured; `tests/conftest.py` builds a fresh Flask app per test) `[VERIFIED: requirements-dev.txt:2]` |
| Config file | none — standard pytest discovery, matching every existing test file's convention |
| Quick run command | `python -m pytest tests/test_template_consistency.py -q` |
| Full suite command | `python -m pytest -q` |

The existing pattern this phase should follow (`tests/test_template_consistency.py`, read this
session) asserts against **rendered HTML strings** (`client.get(...).get_data(as_text=True)`) or
raw template source (`pathlib.Path("templates/x.html").read_text(...)`) via substring/`in` checks
— not a browser-driving tool (no Selenium/Playwright is installed or configured in this repo).
This means automated coverage for this phase is necessarily limited to what a static-HTML
assertion can prove; the live-viewport and color-contrast criteria remain human-verified.

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|---------------------|-------------|
| RESP-01 | No horizontal scroll/clipping/overlap at 320/375/768/1280px on every page | manual (live browser) | n/a — `checkpoint:human-verify` per page family | ❌ Wave 0 N/A (not automatable) |
| RESP-02 | Auth/org-setup pages have a polished, non-cramped mobile layout | manual (live browser, per Open Question 1) | n/a — `checkpoint:human-verify` | ❌ Wave 0 N/A |
| RESP-03 | Record-list tables use the D-01 stacked-card strategy, not silent overflow | unit (markup presence) + manual (visual) | `pytest tests/test_responsive_markup.py -k table_cards -x` (new file) for markup presence; `checkpoint:human-verify` for the actual 320px rendered result | ❌ Wave 0 — new test file needed |
| RESP-04 | Live scan-progress feed remains legible/usable at mobile widths | manual (re-confirm, per this research's Summary) | n/a — `checkpoint:human-verify`, but scope it as a *re-confirmation* against `scan_progress.html`'s already-shipped 880px/480px breakpoints, not new work | ❌ Wave 0 N/A |
| A11Y-01 | Every form input has an associated `<label>`; every icon-only control has an accessible name | unit (rendered-HTML assertion) | `pytest tests/test_accessibility.py -k labels_and_icon_buttons -x` (new file) | ❌ Wave 0 — new test file needed |
| A11Y-02 | Heading hierarchy is sequential, non-skipping on every major template | unit (template-source tag-order assertion) | `pytest tests/test_accessibility.py -k heading_hierarchy -x` (new file) | ❌ Wave 0 — new test file needed |
| A11Y-03 | All interactive elements are keyboard-reachable/operable with a visible focus state | manual (keyboard-only walkthrough) + unit (no `onclick`-on-`<div>`/no missing `tabindex` regression) | `pytest tests/test_accessibility.py -k no_clickable_divs -x` (new file) for the regression lock; `checkpoint:human-verify` for the actual keyboard walkthrough | ❌ Wave 0 — new test file needed |
| A11Y-04 | Text/UI-element contrast meets WCAG AA, including severity colors | manual (contrast-tool-confirmed, scoped per Pitfall 1/2/3 above) | n/a for the two genuine risk areas — `checkpoint:human-verify`; optionally a scripted luminance-check unit test could assert the token hex values algebraically (this research's own computation, turned into a regression lock) | ❌ Wave 0 optional — a `test_contrast_tokens.py` regression lock is a nice-to-have, not required |

### Sampling Rate

- **Per task commit:** `python -m pytest tests/test_accessibility.py tests/test_template_consistency.py -q` (once the new file exists)
- **Per wave merge:** `python -m pytest -q` (full suite, matching every Phase 6 plan's convention)
- **Phase gate:** Full suite green before `/gsd-verify-work`, plus every `checkpoint:human-verify` task confirmed — matching Phase 6's established gate pattern exactly (`06-01`..`06-04`-SUMMARY.md all show Task N = `checkpoint:human-verify`, gate=blocking, requirements not marked complete until confirmed).

### Wave 0 Gaps

- [ ] `tests/test_accessibility.py` — new file; covers A11Y-01 (label/aria-label presence), A11Y-02
      (heading tag order per template), A11Y-03 (regression lock: no `onclick` attribute on a
      `<div>`, matching this session's confirmed-clean baseline so a future regression is caught)
- [ ] `tests/test_responsive_markup.py` — new file (or extend `test_template_consistency.py`);
      covers RESP-03's markup-presence half (both `<table>` and mobile-card block exist in the
      rendered response for each D-01 table)
- [ ] No framework install needed — pytest + `beautifulsoup4` (if the planner wants DOM-based
      assertions instead of substring matching) are both already in the dependency set.

## Security Domain

This phase touches only templates/CSS/markup and explicitly must not modify `authorized*`
checkbox logic, `entitlements.py` gating, or `checks.is_ssrf_safe_hostname()` per CLAUDE.md. No
new authentication, session, input-validation, or cryptography surface is introduced.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|----------------|---------|--------------------|
| V2 Authentication | No | Unchanged this phase — auth forms get responsive/label fixes only, no logic change |
| V3 Session Management | No | Unchanged |
| V4 Access Control | No | Unchanged — `_check_ownership`/entitlement gating out of scope per CLAUDE.md |
| V5 Input Validation | No | Forms keep their existing Flask-WTF validators; only `<label>` association and layout change |
| V6 Cryptography | No | Not touched |
| V11 Business Logic / UI (informal — "don't let a UI rework silently drop a security control") | Yes | Preserve every existing CSRF-protected `<form>` + `confirm()` destructive-action pattern verbatim when converting table rows to mobile cards (see Anti-Patterns above) |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|-----------------------|
| A markup rework accidentally converts a CSRF-protected `<form>` submit into a bare `<a href>`/`<div onclick>` GET-style action while restyling a table row into a mobile card | Tampering / Elevation of Privilege (CSRF) | Keep every destructive/state-changing action as a real `<form method="POST">` with its existing `csrf_token` hidden field when moving it into card markup — verified this session that every current destructive action (asset delete, token revoke, domain deletion request, invitation revoke) already follows this pattern; the risk is only in *not* preserving it during the D-01 rework |
| An `aria-label`/visible-text change during a11y fixes accidentally exposes sensitive data (e.g. a full API token value) in an attribute that ends up in page source differently than before | Information Disclosure | Not a realistic risk here — `api_tokens.html`'s `aria-label="Your new API token for {{ new_token_name }}"` already only references the token *name*, not its value; preserve that convention for any new `aria-label` this phase adds |

## Sources

### Primary (HIGH confidence — read directly this session)
- `templates/base.html` — design tokens, existing `:focus-visible`, existing `@media` breakpoint, table/severity CSS
- `templates/dashboard.html`, `org_admin.html`, `billing.html`, `api_tokens.html`, `assets.html`,
  `asset_detail.html`, `org_verify_domain.html`, `scan_report.html`, `scan_progress.html`,
  `login.html`, `signup.html`, `reset_password.html`, `scan_new_type.html`,
  `_scan_wizard_stepper.html`, `_gauge.html`, `_auth_form_styles.html`, `_admin_form_styles.html`,
  `_scan_form_styles.html` — full reads this session
- `.planning/phases/07-responsive-accessibility-compliance/07-CONTEXT.md` — locked D-01 decision
- `.planning/phases/06-design-system-consistency/06-UI-SPEC.md`, `06-01`..`06-04-SUMMARY.md` — the
  design-system baseline this phase builds against
- `.planning/REQUIREMENTS.md`, `.planning/STATE.md` — requirement text, milestone/deployment context
- `CLAUDE.md` — project constraints (see below)
- Ripgrep searches this session across all `templates/*.html` for `@media`, `<h[1-6]`,
  `onclick|role="button"|tabindex`, `<label`, `<button type="button"`, `aria-label` — exhaustive,
  not sampled

### Secondary (MEDIUM confidence)
- [W3C: Understanding Success Criterion 1.4.3 Contrast (Minimum)](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html) — confirms 4.5:1 normal text / 3:1 large text thresholds
- [Deque University: 1.4.11 Non-Text Contrast (AA)](https://dequeuniversity.com/resources/wcag2.1/1.4.11-non-text-contrast) — confirms 3:1 threshold for UI components/graphical objects
- [WebAIM: Contrast and Color Accessibility](https://webaim.org/articles/contrast/) — practical contrast-checking guidance

### Tertiary (LOW confidence — general pattern background only, not load-bearing for any specific claim in this document)
- General web search results on responsive-table-to-card CSS conventions (data-label trick vs.
  dual-markup) — used only to confirm the dual-markup recommendation is a recognized pattern, not
  as the source of any specific fact about this codebase

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new packages, entire "stack" is the already-verified existing codebase
- Architecture (table→card pattern): HIGH — grounded in direct reads of every named template and CLAUDE.md's own architecture doc
- Pitfalls: HIGH — every pitfall in this document is backed by a direct grep/read this session, not inference
- Contrast math: MEDIUM — computed by hand from verified hex values using the standard WCAG relative-luminance formula; recommend a tool-based spot-check (per Common Pitfalls) rather than treating this document's arithmetic as the final word

**Research date:** 2026-08-18
**Valid until:** No expiry driver — this research is grounded in the current state of a private
codebase, not a fast-moving external library; valid until the next phase that materially changes
these templates (i.e., effectively until Phase 7 itself lands)
