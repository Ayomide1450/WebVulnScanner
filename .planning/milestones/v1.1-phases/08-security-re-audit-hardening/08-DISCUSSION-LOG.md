# Phase 8: Security Re-Audit & Hardening - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-18
**Phase:** 8-security-re-audit-hardening
**Areas discussed:** Live-probe depth, Handling a real finding, Priority ordering, Adjacent thin-test coverage

---

## Live-probe depth

| Option | Description | Selected |
|--------|-------------|----------|
| Code-review + regression tests only | Match the existing `_check_ownership` test pattern: audit route code, write/extend Flask test-client integration tests. No live server. | |
| Add a live dev-server probe pass | Also run `app.py` locally and fire real HTTP requests against a running instance with two seeded orgs, in addition to test-client coverage. | ✓ |

**User's choice:** Add a live dev-server probe pass.
**Notes:** Targets the app's own local auth boundaries, not an external-domain scan — distinct from CLAUDE.md's authorized-use constraint on scanning someone else's infrastructure. Recorded as D-01/D-02 in CONTEXT.md; the live pass supplements the regression-test suite, it doesn't replace it.

---

## Handling a real finding

| Option | Description | Selected |
|--------|-------------|----------|
| Fix immediately within the phase | Matches the roadmap goal ("with any gap found closed"). Fix, add a regression test, record plainly — no pause for sign-off. | ✓ |
| Pause and ask before fixing anything above medium severity | Any critical/high-severity live finding stops for explicit go-ahead before shipping the fix. | |

**User's choice:** Fix immediately within the phase (recommended option).
**Notes:** Consistent with this session's established fast-moving pattern. Recorded as D-03.

---

## Priority ordering

| Option | Description | Selected |
|--------|-------------|----------|
| Highest blast-radius first | IDOR (SEC-01), CSRF (SEC-02), billing replay (SEC-09) audited/closed first. | ✓ |
| Roadmap listing order | SEC-01 through SEC-10 in ROADMAP.md's listed order. | |

**User's choice:** Highest blast-radius first (recommended option).
**Notes:** Recorded as D-04 with the full ordering rationale (auth bypass and financial impact first, so an interruption still leaves the riskiest gaps known).

---

## Adjacent thin-test coverage

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, as a natural byproduct | Backfill CONCERNS.md's flagged gaps (org_routes.py, domain_verification.py, run_advanced_scan/run_media_scan/run_api_scan) while auditing those same files. | ✓ |
| No, stay strictly scoped | Only add tests directly proving one of the 5 success criteria. | |

**User's choice:** Yes, as a natural byproduct (recommended option).
**Notes:** Recorded as D-05, explicitly bounded to not become a general test-coverage initiative.

---

## Claude's Discretion

- Whether SEC-01..SEC-10 become one large plan or several parallel-wave plans (planner's call; priority ordering constrains sequencing, not plan count).
- The live-probe pass's exact tooling (standalone script, curl, or a pytest `live_server` fixture) — left to research/planning to match this repo's existing test infra.

## Deferred Ideas

None — discussion stayed within phase scope. DNS-rebinding-proof SSRF pinning remains explicitly out of scope per REQUIREMENTS.md and was not re-raised.
