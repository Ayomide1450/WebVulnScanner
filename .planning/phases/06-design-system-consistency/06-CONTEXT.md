# Phase 6: Design System Consistency - Context

**Gathered:** 2026-08-17
**Status:** Ready for planning

<domain>
## Phase Boundary

Every template in the app — marketing/legal pages, auth pages, and the full logged-in app
(dashboard, all four scan-launch pages, scan progress/report/compare, billing, org admin,
platform admin, assets) — draws from one documented typography scale, one spacing scale, and
one canonical style per shared component (buttons, inputs/selects/textareas, cards, tables,
badges/pills, alert/warn/error/info boxes), with purpose-consistent container max-widths and
no local drift left unconsolidated (DESIGN-01..04). Framed by the user as a full
"production-grade cybersecurity SaaS" quality bar, not a cosmetic pass — see D-01 below.

</domain>

<decisions>
## Implementation Decisions

### Depth of the typography/consistency pass
- **D-01:** Not strict deduplication only. The user explicitly asked for thorough,
  professional/world-class execution ("don't do a lazy job, be thorough" / "professional work
  world class") — Claude has latitude to adjust specific font sizes, weights, and line-heights
  where the current values read as cramped, inconsistent, or below a production SaaS bar, not
  just collapse the ~30 near-duplicate `font-size` values (13px/13.5px/14px/14.5px etc. found
  scattered across 220 declarations) onto the nearest existing value. The existing OLED-dark
  "evolved operator console" palette/motion language (`--bg`/`--accent`/`--telemetry`,
  `.glow-pulse`/`.hud-grid`) is the established identity and is NOT being replaced — this is a
  refinement/consolidation of an existing world, not a rebrand. — **Reversibility:** reversible
  — scale values live in `base.html` custom properties; adjusting them again later only requires
  changing the token definitions, not every call site, since DESIGN-01/03 already require every
  template to reference the scale rather than hardcode.

### Container/content max-width strategy
- **D-02:** Purpose-based width categories, not one universal width. At minimum: a narrow width
  for single-column forms (auth pages, the four scan-launch pages) and a wider width for
  data-dense views (dashboard, scan report/compare, org admin, platform admin, asset list/
  detail). Exact pixel values are Claude's discretion during planning/UI-spec — pick values that
  read as intentional and professional, not simply "keep whatever's already there." Executed to
  a "world class" bar per the user's explicit answer, not the minimum viable consistency fix.

### Page scope
- **D-03:** Every template gets audited, no exceptions — marketing (`marketing.html`), legal
  (`terms.html`/`privacy.html`), auth (`login.html`/`signup.html`/`forgot_password.html`/
  `reset_password.html`/`verify_email.html`), and the full logged-in app. Matches ROADMAP.md's
  "every template" wording and the user's explicit "entire website, not just the login page"
  framing that triggered this phase.

### Claude's Discretion
- Exact typography scale values (Display/H1-H4/Body/Small/Caption/Label/Button/Nav) and exact
  spacing-scale extensions beyond the existing `--space-1..7` (4/8/12/16/24/32/48px) tokens.
- Exact container max-width pixel values per category (D-02).
- Priority/ordering of which templates get touched first within the phase.
- Whether existing arbitrary values (e.g. `22px`, `26px` font-sizes found in the audit) become
  new scale steps or get snapped to the nearest existing step — judgment call per instance,
  guided by "does this read as intentional" rather than a mechanical nearest-neighbor snap.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Design system baseline (what already exists, to extend not replace)
- `templates/base.html` — the existing token set: OLED-dark palette (`--bg`/`--panel`/`--text`/
  `--accent`/`--telemetry`/severity colors), `--radius`/`--radius-lg`, `--space-1..7` spacing
  scale (already defined but not yet universally adopted — DESIGN-02's actual gap), `.card`/
  `.btn`/`.pill`/`.badge`/`.status-pill` canonical component shapes, the icon sprite, and the
  `.glow-pulse`/`.hud-grid`/`.telemetry-dot` motion primitives Phase 4 established as the
  "evolved operator console" motion language — reuse these, do not invent parallel ones.
- `CLAUDE.md` "Frontend design system" section — documents which components are already
  consolidated vs. which still have known local overrides (the two documented emoji-icon
  exceptions in `org_verify_domain.html`, the Phase-4-closed `billing.html` warn-box exception).

### Shared per-page-family CSS partials (already-established consolidation pattern to extend)
- `templates/_scan_form_styles.html` — shared by the four `scan_new_*.html` + `scan_new_type.html`
  + `scan_new.html` (just extended this session with `textarea` styling — see 06-DISCUSSION-LOG.md
  for the session that surfaced this exact class of drift).
- `templates/_admin_form_styles.html` — shared by `billing.html`/`org_admin.html`/
  `org_verify_domain.html`.
- `templates/_auth_form_styles.html`, `templates/_legal_styles.html`, `templates/_gauge.html` —
  other existing shared partials; same pattern (element selectors scoped to a partial rather than
  promoted into `base.html` to avoid leaking into unrelated forms) should be followed for any new
  consolidation, not broken.

### Requirements
- `.planning/REQUIREMENTS.md` DESIGN-01..04 (lines ~122-133) — full requirement text.
- `.planning/ROADMAP.md` Phase 6 section (lines ~263-291) — goal, success criteria, sequencing
  rationale (why Phase 6 follows Phase 5 and precedes Phase 7).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `--space-1` through `--space-7` (4/8/12/16/24/32/48px) already exist in `base.html` as CSS
  custom properties but are inconsistently adopted — many templates still hardcode arbitrary
  pixel margins/padding instead of referencing the scale. DESIGN-02's actual work is adoption,
  not invention.
- `.card`/`.btn`/`.pill`/`.badge`/`.status-pill`/`.warn-box`/`.error-box`/`.info-box` already
  exist as canonical component classes in `base.html` per CLAUDE.md's own documentation — the
  audit's job is finding and consolidating the templates that still locally override these
  rather than reusing them, not creating new component classes from scratch.

### Established Patterns
- Per-page-family shared CSS partials (`_scan_form_styles.html`, `_admin_form_styles.html`, etc.)
  are the existing, deliberate pattern for element-selector-scoped styles (`label`, `input[type=
  text]`, `button`) that would leak into unrelated forms if promoted to `base.html` directly -
  documented explicitly in CLAUDE.md's "Frontend design system" section. Any new shared styling
  discovered during this phase's audit should follow this same scoping discipline, not bypass it
  by adding bare element selectors to `base.html`.
- A real, freshly-discovered instance of typography drift this session: `_scan_form_styles.html`
  historically styled `input[type=text], select` but never `textarea`, so Chrome's default
  monospace UA stylesheet made one form control visually mismatch its siblings on the same page.
  This is the exact class of bug DESIGN-01/03 exists to catch systematically across every
  template, not just fix one instance at a time when a user happens to notice it.

### Integration Points
- Every template extends `base.html` (`{% extends "base.html" %}`) and most either use a shared
  partial's `{% include %}` or carry local `<style>` blocks in their own `{% block head %}` -
  the audit needs to walk both the shared partials and each template's local style block to find
  drift in either place.

</code_context>

<specifics>
## Specific Ideas

No further specific visual references beyond D-01/D-02/D-03 above and the "production-grade
cybersecurity SaaS" quality bar stated in the triggering request. The existing OLED-dark
"evolved operator console" identity (established across Phases 2-4, documented in CLAUDE.md) is
the visual language to refine, not replace.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope. (Responsive/accessibility fixes at specific
viewport widths are explicitly Phase 7's job, sequenced after this phase per ROADMAP.md's own
stated rationale, not scope creep to fold in here.)

</deferred>

---

*Phase: 6-design-system-consistency*
*Context gathered: 2026-08-17*
