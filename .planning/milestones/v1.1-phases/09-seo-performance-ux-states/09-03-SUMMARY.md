---
phase: 09-seo-performance-ux-states
plan: 03
subsystem: performance
tags: [pagination, n+1-audit, dashboard, org-admin, assets, scan-report]
dependency-graph:
  requires: ["09-02", "09-04"]
  provides: ["templates/_pagination.html", "tests/test_query_counts.py", "tests/test_pagination.py"]
  affects:
    - glassbox/scan_routes.py
    - glassbox/asset_routes.py
    - glassbox/org_routes.py
    - templates/dashboard.html
    - templates/assets.html
    - templates/org_admin.html
    - templates/scan_report.html
tech-stack:
  added: []
  patterns:
    - "Flask-SQLAlchemy 3.1 Query.paginate(page=, per_page=, error_out=False) for every real DB-backed list"
    - "sqlalchemy.event.listen(engine, 'before_cursor_execute', ...) as a reusable query-counting test helper"
key-files:
  created:
    - templates/_pagination.html
    - tests/test_query_counts.py
    - tests/test_pagination.py
  modified:
    - glassbox/scan_routes.py
    - glassbox/asset_routes.py
    - glassbox/org_routes.py
    - templates/dashboard.html
    - templates/assets.html
    - templates/org_admin.html
    - templates/scan_report.html
decisions:
  - "PERF-01 audit found no N+1 in dashboard()/org.admin() - no production fix needed, only proved it executably"
  - "dashboard()'s all_scans (full, unbounded) stays separate from scan_history (paginated) so trend/stat sections never shrink to the current page"
  - "org.admin()'s members_page queries User directly (not org_obj.users) since a loaded relationship list can't be paginated at the DB layer; member_count is a separate .count()"
  - "scan_report()'s compliance-grouped view is deliberately left unpaginated - explicit scope boundary, not an oversight"
metrics:
  duration: "~2.5 hours"
  completed: 2026-08-20
status: complete
actuals:
  tokens: 41000
  tasks: 3
  commits: 2
---

# Phase 9 Plan 3: PERF-01 N+1 Audit + PERF-02 Pagination Summary

Proved dashboard()/org.admin() have no per-row N+1 query pattern (data-size-independent query
count at 3 vs 15 rows), then added real DB-level pagination at 20/page to all four D-03 lists
(dashboard scan history, asset list, org members, a scan report's severity-grouped findings) via
one new shared `pagination_nav()` partial.

## What was built

**`templates/_pagination.html`** - the single `pagination_nav(page, total_pages)` macro used
app-wide, matching 09-UI-SPEC.md's D-03 spec exactly: desktop (Prev / numbered pages / Next) and
mobile (Prev / "Page N of M" / Next) markup both always present in the DOM, a
`@media (max-width: 430px)` rule selects one (same `--bp-card` breakpoint `base.html`'s
`.desktop-table`/`.mobile-record-cards` dual-markup already uses). The numbered-page row is
omitted entirely when `total_pages <= 1`; Prev/Next always render, `aria-disabled="true"` +
`tabindex="-1"` at either boundary (both at once on a single-page list).

**Task 1 (PERF-01 audit, `tests/test_query_counts.py`)** - a reusable `count_queries()` context
manager (SQLAlchemy `before_cursor_execute` event listener, registered/removed per-test via
try/finally) proves `GET /dashboard` and `GET /org/admin` issue the identical query count at 3
rows vs 15 rows of their respective collections. **No production fix was needed** - both routes
were already correct (`dashboard()` only touches plain `Scan` columns per row; `org.admin()`'s
scans/audit_events queries were already `joinedload()`'d, and its members loop reads only plain
`User` columns). Query counts observed (after normalizing SQLAlchemy's session identity-map cache
state - see Deviations below): dashboard = 3 queries at both 3 and 15 scans; org-admin = 7 queries
at both 3 and 15 rows/collection.

**Task 2 (PERF-02, three real `.paginate()` queries)**:
- `scan_routes.dashboard()`: `scan_history` is a new, separate paginated query
  (`Scan.query.filter_by(...).paginate(page=page, per_page=20, error_out=False)`) feeding only the
  Scan History table. `all_scans` (the original unbounded query, renamed) still feeds
  `latest`/`target_trends`/`completed_count` and the Security Score Over Time chart unchanged - none
  of those shrink to the current page.
- `asset_routes.list_assets()`: `_scoped_asset_query()` paginated directly - no stat depends on the
  full list here, simpler than dashboard's case.
- `org_routes.admin()`: `members_page` queries `User.query.filter_by(org_id=org_obj.id)` directly
  (not `org_obj.users`, which is an already-loaded relationship list, not a `Query`, and can't be
  paginated at the DB layer) and paginates it; `member_count` is a separate, unbounded `.count()`
  so the "Members · N" stat is unaffected by which page is being viewed.

**Task 3 (PERF-02, `scan_routes.scan_report()`)**: the severity-grouped (default) findings view is
paginated at 20/page via a plain Python slice (the findings list is already fully loaded in-memory
from the report's JSON blob, not a DB `Query` - "pagination" here means bounding what's rendered).
The compliance-grouped view (`?group=compliance`) is **deliberately left unpaginated** - its
different grouping semantics (by OWASP category, not a flat sorted list) are out of this plan's
explicit scope, proven by a dedicated test (`test_scan_report_compliance_view_ignores_pagination`)
rather than left implicit.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Test-methodology bug, not a production bug] Cache-warmth artifact in the PERF-01
query-count test**
- **Found during:** Task 1, first honest run of `tests/test_query_counts.py`
- **Issue:** An unnormalized first pass measured the "3 rows" phase right after `login()`'s own
  follow-redirect GET had already warmed Flask-SQLAlchemy's scoped session identity map, then
  measured the "15 rows" phase right after a fresh `db.session.commit()` had expired every cached
  object. This reported 1 query at 3 scans vs 3 at 15 (dashboard), and 6 vs 7 (org-admin) - which
  looks exactly like an N+1, but the confound was SQLAlchemy session cache state, not row count: a
  cache-warm request skips a lazy-relationship `SELECT` whose result is already in the identity
  map; a cache-cold request right after a commit does not.
- **Fix:** Added `db.session.expire_all()` immediately before each `count_queries()` measurement in
  both tests, forcing an explicit cold state each time so the comparison isolates row count as the
  only variable. Confirmed by hand (throwaway debug scripts, since removed) that both routes report
  a *constant* query count across 3 vs 15 rows once cache warmth stops confounding the measurement.
- **Files modified:** `tests/test_query_counts.py`
- **Commit:** `f80f47d`

Or, for the pagination task: no further deviations - Tasks 2 and 3 were implemented exactly as
written in the plan's `<action>` blocks.

## Known Issues (pre-existing, out of scope)

`tests/test_org_invite.py::test_decode_invite_token_rejects_tampered_signature` fails
deterministically on current `master` (confirmed in isolation, and confirmed the diff between
this plan's commits and `master` touches neither `tests/test_org_invite.py` nor
`generate_invite_token`/`decode_invite_token` in `org_routes.py` at all). This is unrelated to
PERF-01/PERF-02 and out of this plan's scope per the scope-boundary rule (pre-existing failures in
unrelated files are not auto-fixed) - logged here rather than fixed. Full-suite result: **801
passed, 1 failed (this pre-existing, unrelated test)**.

## Self-Check

- `templates/_pagination.html` - FOUND
- `tests/test_query_counts.py` - FOUND
- `tests/test_pagination.py` - FOUND
- Commit `f80f47d` (Task 1) - FOUND in `git log`
- Commit `543c050` (Tasks 2+3) - FOUND in `git log`
- `.venv\Scripts\python -m pytest tests/test_query_counts.py tests/test_pagination.py -q` - 11
  passed (2 + 9)
- `.venv\Scripts\python -m pytest -q` (full suite) - 801 passed, 1 failed (pre-existing/unrelated,
  see Known Issues)

## Self-Check: PASSED
