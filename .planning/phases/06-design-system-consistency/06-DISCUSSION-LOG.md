# Phase 6: Design System Consistency - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-17
**Phase:** 6-design-system-consistency
**Areas discussed:** Typography scope, Container widths, Page scope

---

## Typography scope

| Option | Description | Selected |
|--------|-------------|----------|
| Strict consistency only | Snap ~30 near-duplicate font-size values into a documented scale, keep the existing OLED-dark look exactly as-is. | |
| Consistency + a quality pass | Same consolidation, but also willing to adjust specific sizes/weights/line-heights where they read as cramped or below a "production-grade SaaS" feel. | ✓ (implied) |

**User's choice:** "dont do a lady work be thorough" (free text, not one of the two options
verbatim — read as "don't do a lazy job, be thorough").
**Notes:** Interpreted as authorizing the more thorough option (quality pass, not just dedup),
combined with the third answer's explicit "professional work world class" — the user wants a
genuine quality bar, not a mechanical consistency-only pass. Captured as D-01 in CONTEXT.md.

---

## Container widths

| Option | Description | Selected |
|--------|-------------|----------|
| A small set of purpose-based widths | One width for narrow forms, one for wide data views - consistent within each category. | ✓ (implied) |
| One single max-width everywhere | Every page uses the exact same container width. | |

**User's choice:** "professional work world class" (free text).
**Notes:** Read together with the typography answer as the same underlying instruction: do this
properly, to a professional standard, rather than picking the minimum-effort option on either
question. Purpose-based widths (the Recommended option) captured as D-02, executed to a high
bar rather than a token pass.

---

## Page scope

| Option | Description | Selected |
|--------|-------------|----------|
| Everything, no exceptions | Marketing, auth, and the full logged-in app all get audited. | ✓ |
| Logged-in app only | Focus on dashboard/scans/billing/org-admin/reports; defer marketing/auth. | |

**User's choice:** Everything, no exceptions.
**Notes:** Matches the user's original framing ("not just the login page") that triggered this
phase discussion. Captured as D-03.

---

## Claude's Discretion

- Exact typography scale values and spacing-scale extensions beyond `--space-1..7`.
- Exact container max-width pixel values per purpose category.
- Priority/ordering of which templates get touched first.
- Whether individual arbitrary values become new scale steps or snap to an existing one.

## Deferred Ideas

None — discussion stayed within phase scope. Responsive/accessibility work at specific viewport
widths is Phase 7, already sequenced to follow this phase per ROADMAP.md.
