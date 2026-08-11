# Phase 3: Compliance & Framework Reporting - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-11
**Phase:** 3-Compliance & Framework Reporting
**Areas discussed:** Framework scope

---

## Framework scope

| Option | Description | Selected |
|--------|-------------|----------|
| OWASP Top 10 only | Simpler: 10 fixed categories | |
| ASVS only | More granular, audit-grade, heavier to maintain | |
| Both (Top 10 + ASVS) | Each check maps to both | |

**User's first answer (free text):** "GO WITH THE BEST PRACTICES TO ENSURE THIS WEBSITE SERVES
THE USERS AND DELIVER SECURITY CHECK/SERVICES TO COMPANIES AND SOLO DEVELOPER ESPECIALLY VIBE
CODERS" — did not pick a literal option, asked for a best-practice recommendation serving both a
company/audit audience and a solo/vibe-coder audience.

**Follow-up proposal:** OWASP Top 10 required on every mapped check (recognizable, quick-glance,
fits vibe-coder audience) + ASVS control ID optional, added only where it adds real audit value
(fits company/audit audience). Not every check needs an ASVS ID.

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, Top 10 required + ASVS optional | Matches COMP-01's "and/or" wording | ✓ |
| Top 10 only, skip ASVS entirely this phase | Simpler scope, defer ASVS | |

**User's choice:** "Yes, Top 10 required + ASVS optional"

---

## Coverage (asked alongside Framework scope, not separately selected as an area)

| Option | Description | Selected |
|--------|-------------|----------|
| All checks, all 4 scan types | Full COMP-04 sync convention from day one | ✓ |
| Base scan checks only, others deferred | Smaller footprint, others get "unmapped" fallback | |

**User's choice:** "All checks, all 4 scan types"

## Unmapped findings (asked alongside Framework scope, not separately selected as an area)

| Option | Description | Selected |
|--------|-------------|----------|
| Explicit 'Uncategorized' bucket | Own group in UI, matches CHECK_CATEGORY's fallback pattern | ✓ |
| Omit from compliance view entirely | Only checks with a real mapping appear | |

**User's choice:** "Explicit 'Uncategorized' bucket"

---

## Claude's Discretion

- Report grouping/filter UX on `scan_report.html` (new tab vs. toggle vs. inline badges) — area
  was identified but not selected for discussion; left to planner/UI-SPEC.
- Per-Asset compliance summary placement and "currently failing" semantics — area was identified
  but not selected for discussion; left to planner/UI-SPEC.
- Mapping data source/maintenance mechanics (exact dict shape, regression-test implementation) —
  area was identified but not selected for discussion; left to planner.

## Deferred Ideas

None — discussion stayed within phase scope.
