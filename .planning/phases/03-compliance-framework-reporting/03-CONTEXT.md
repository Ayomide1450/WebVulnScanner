# Phase 3: Compliance & Framework Reporting - Context

**Gathered:** 2026-08-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Security teams can see scan findings mapped to recognized compliance frameworks (OWASP Top 10,
optionally ASVS) for audit and reporting purposes, not just a flat severity list. Covers: tagging
findings with their framework category, a compliance-grouped/filterable view on scan reports, and
a per-Asset compliance-coverage summary across scan history.

</domain>

<decisions>
## Implementation Decisions

### Framework scope
- **D-01:** OWASP Top 10 category is the required/primary mapping for every check that gets
  mapped. ASVS control ID is an optional secondary tag, added only where it adds real audit value
  (not mandatory per check). Satisfies COMP-01's "OWASP Top 10 (and/or ASVS)" wording while
  keeping the mapping-authoring burden proportionate. — **Reversibility:** costly — adding ASVS
  later is additive (no breaking change), but retrofitting it onto checks shipped without it means
  re-touching every check's mapping entry a second time.
- **D-02:** Rationale for this split: the target audience spans both companies needing audit-grade
  detail and solo/vibe-coder users who need a quick, recognizable label. OWASP Top 10 is the
  broadly-recognized layer; ASVS is the audit-grade layer, added opportunistically.

### Coverage
- **D-03:** All checks across all 4 scan types (base/advanced/media/api) get a mapping entry in
  this phase — not just base-scan checks. Follows the same all-checks convention already
  established by `CHECK_LABELS`/`CHECK_CATEGORY` in `checks.py`.

### Unmapped findings
- **D-04:** Checks/findings that don't map cleanly to any OWASP/ASVS category (info-only, pass
  findings, etc.) get an explicit "Uncategorized" bucket in the compliance view rather than being
  silently dropped — mirrors `CHECK_CATEGORY`'s existing `"shield"` icon fallback pattern.

### Claude's Discretion
- Report grouping/filter UX (new tab vs. toggle vs. inline badges on scan_report.html) — not
  discussed, left to planner/UI-SPEC judgment.
- Per-Asset compliance summary placement (new page vs. a section on `asset_detail.html`) and
  exact "currently failing" semantics (most-recent-scan-only vs. any-scan-in-history) — not
  discussed, left to planner/UI-SPEC judgment. Planner should pick the interpretation consistent
  with how `asset_detail.html` already presents scan history (Phase 1), and document the choice
  explicitly since it's user-visible.
- Exact mapping data structure (new dict in `checks.py`, e.g. `CHECK_COMPLIANCE`, following the
  `CHECK_LABELS`/`CHECK_CATEGORY` key-set convention) and how COMP-04's coverage-regression-test
  requirement gets implemented — technical detail, left to planner.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Existing coverage-convention precedent (COMP-04's explicit reference point)
- `webvulnscanner/checks.py` — `CHECK_LABELS` (~line 61) and `CHECK_CATEGORY` (~line 79) dicts,
  and their "keep this dict in sync" comment — the pattern any new compliance-mapping dict and its
  regression test should mirror.
- `webvulnscanner/checks.py` — `Finding` dataclass (~line 146): `category`, `severity` fields —
  where a compliance tag would attach or be looked up from.
- `tests/test_scan_events.py` — existing regression test that checks `CHECK_LABELS`/
  `CHECK_CATEGORY` cover every check name `run_scan()`'s jobs dict can dispatch; the pattern
  COMP-04 wants replicated for the new compliance mapping.

### Project-level
- `.planning/REQUIREMENTS.md` — COMP-01..04 full text.
- `.planning/ROADMAP.md` §Phase 3 — goal and success criteria.
- `CLAUDE.md` — scan orchestrator / check-function conventions (`(data, findings)` return shape,
  `FEATURE_REQUIREMENTS` tier-gating pattern) that a compliance-mapping addition must respect.

No other external specs — requirements fully captured in decisions above.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `CHECK_LABELS` / `CHECK_CATEGORY` dicts in `checks.py` — direct structural precedent for the new
  compliance-mapping dict (same key set: check names dispatched by the 4 orchestrators).
- `templates/base.html`'s `.pill`/`.badge` component convention — likely reusable for rendering
  OWASP Top 10 category tags on `scan_report.html` without inventing new CSS.

### Established Patterns
- Every new "per-check" lookup table in this codebase (`CHECK_LABELS`, `CHECK_CATEGORY`,
  `FEATURE_REQUIREMENTS`) ships with a regression test asserting it covers every check name a
  `jobs` dict can dispatch — a missing entry degrades gracefully (title-cased fallback / `Tier.FREE`
  default) rather than breaking, but is still test-covered. COMP-04 explicitly asks for this same
  convention.

### Integration Points
- `scan_report.html` — where the compliance-grouped/filterable view attaches (COMP-02).
- `asset_detail.html` (built in Phase 1) — most likely home for the per-Asset compliance-coverage
  summary (COMP-03), pending planner's UI-SPEC decision (see Claude's Discretion above).

</code_context>

<specifics>
## Specific Ideas

No specific UI mockups or exact wording requested — user's guidance was to follow security
best-practice framework conventions (OWASP Top 10 as the recognizable layer, ASVS as the
audit-grade layer) suited to a dual audience of companies and solo/vibe-coder developers.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope. (Only "Framework scope" was selected for discussion;
the other 3 identified gray areas — report grouping/filter UX, per-Asset summary placement,
mapping data maintenance — were explicitly left to planner discretion, not deferred to a future
phase.)

</deferred>

---

*Phase: 3-Compliance & Framework Reporting*
*Context gathered: 2026-08-11*
