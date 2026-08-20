# Phase 7: Responsive & Accessibility Compliance - Context

**Gathered:** 2026-08-18
**Status:** Ready for planning

<domain>
## Phase Boundary

Every page renders correctly at mobile-through-desktop widths (320px–1280px, no horizontal
scroll/clipping/overlap) and is fully operable by keyboard and assistive technology, built
against the canonical component set Phase 6 established (RESP-01..04, A11Y-01..04). This is a
verify-and-fix pass against an already-consolidated design system, not a new visual redesign —
Phase 6's tokens/components are the starting point.

</domain>

<decisions>
## Implementation Decisions

### Mobile data-table strategy
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

</decisions>

<deferred>
## Deferred Ideas

None raised this session — discussion was scoped to the one gray area (mobile table strategy)
the user chose to weigh in on. Other Phase 7 success criteria (keyboard/AT operability, heading
hierarchy, WCAG AA contrast including severity-colored text/badges) are left to the researcher/
planner to handle against the roadmap's existing success criteria — no additional user decisions
were requested or given for those this session.

</deferred>

<next_steps>
## Next Steps

Ready for `/gsd-plan-phase 7` (or the researcher step if the planner wants prior art on
stacked-card/responsive-table patterns first). No other phase-7-specific gray areas were
raised — proceed with the roadmap's stated success criteria plus D-01 above.

</next_steps>
