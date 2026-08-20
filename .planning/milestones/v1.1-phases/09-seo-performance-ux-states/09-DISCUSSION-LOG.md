# Phase 9: SEO, Performance & UX States - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-19
**Phase:** 9-SEO, Performance & UX States
**Areas discussed:** SEO metadata & discoverability, Performance fix scope, Empty/loading state pattern, Failed/timeout/duplicate-scan messaging

---

## SEO metadata & discoverability

**Q1: How should robots.txt/sitemap.xml be generated?**

| Option | Description | Selected |
|--------|-------------|----------|
| Dynamic Flask routes | Generated from `app.url_map` at request time, can't drift from reality | ✓ |
| Static files | Hand-maintained files, simpler but can go stale | |

**Q2: Beyond ROADMAP's minimum (title/meta description/canonical/OG) — add anything else?**

| Option | Description | Selected |
|--------|-------------|----------|
| Nothing more | Exactly ROADMAP's scope | |
| Twitter Card tags | Reuses existing OG values, cheap addition | ✓ |
| JSON-LD structured data | More setup, more claims | |

**User's choice:** Dynamic routes for robots.txt/sitemap.xml; add Twitter Card tags reusing OG values; explicitly no JSON-LD.
**Notes:** User specified the exact four Twitter Card tags to add (`twitter:card`, `twitter:title`, `twitter:description`, `twitter:image`) and explicitly excluded JSON-LD by name.

---

## Performance fix scope

**Q1: What pagination UI pattern for unbounded lists?**

| Option | Description | Selected |
|--------|-------------|----------|
| Numbered pages | Prev/1 2 3/Next, query-param driven | ✓ |
| "Load more" button | Inline fetch-based append | |
| Simple cap + "view all" link | Least new UI, defers the real problem | |

**Q2: Default page/cap size?**

| Option | Description | Selected |
|--------|-------------|----------|
| 20 per page | Common admin/dashboard default | ✓ |
| 25 per page | Matches existing org_routes.py limits | |
| 50 per page | Fewer page changes for power users | |

**User's choice:** Numbered pages, 20 per page.
**Notes:** None beyond the selection.

---

## Empty/loading state pattern

**Q1: Extend existing empty-state pattern app-wide, or design a fresh canonical one?**

| Option | Description | Selected |
|--------|-------------|----------|
| Extend existing pattern as-is | Reuse dashboard.html/asset_detail.html's treatment verbatim | |
| Refine into a shared partial first | Extract `_empty_state.html` with a title/message/CTA-slot API | ✓ |

**Q2: Extend the auth-forms submitting-state pattern to which other forms?**

| Option | Description | Selected |
|--------|-------------|----------|
| All 4 scan-launch forms | base/advanced/media/api | ✓ |
| Org-admin forms | Invite, domain add/verify, schedule updates | ✓ |
| Billing forms | Create/verify invoice | ✓ |
| Account/settings forms | API token create/revoke, profile/password | ✓ |

**User's choice:** Shared `_empty_state.html` partial; submitting-state extended to all four categories (app-wide).
**Notes:** User selected all four submitting-state options rather than a subset.

---

## Failed/timeout/duplicate-scan messaging

**Q1: A codebase check before asking found no duplicate-concurrent-scan guard and no scan-level timeout exist today. How far should Phase 9 go?**

| Option | Description | Selected |
|--------|-------------|----------|
| Full scope: add both guards + messaging | Real new backend behavior — duplicate-scan check, scan-level timeout, distinct messages for all three states | ✓ |
| Messaging only, gaps stay open | Just improve existing FAILED-state rendering, note the gaps as out of scope | |
| Split: timeout yes, duplicate deferred | Fix the more common failure mode now, defer the lower-risk edge case | |

**User's choice:** Full scope — both guards plus messaging.
**Notes:** This was flagged as a real, previously-undocumented gap discovered via a codebase grep during discussion (no match for "duplicate"/"concurrent"/"already running" in scan_routes.py, no scan-level timeout anywhere outside per-HTTP-request timeouts in checks.py), not assumed going in.

---

## Claude's Discretion

- Exact pixel/spacing values for pagination controls and the empty-state partial's layout (use Phase 6's existing scale).
- Exact wording of failed/timed-out/duplicate/empty-state messages (plain-language, matching Phase 5's scan-wizard copy tone).
- Where the scan-level timeout value lives and its default duration (research to determine a sensible number).

## Deferred Ideas

- JSON-LD structured data — explicitly deferred, not this phase.
- Cursor-based/infinite-scroll pagination — explicitly rejected in favor of numbered pages.
