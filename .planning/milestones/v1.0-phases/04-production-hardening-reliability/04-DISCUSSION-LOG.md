# Phase 4: Production Hardening & Reliability - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-13
**Phase:** 4-production-hardening-reliability
**Areas discussed:** Orchestrator test coverage, Org-flow test coverage & the invite gap, Visual-consistency pass

---

## Orchestrator test coverage (HARD-02)

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, lock in safety constraints too | Regression-test MAX_BRUTEFORCE_ATTEMPTS/stored-XSS marker-only proof/no auto-submit alongside status/error handling | ✓ |
| Literal scope only | Just status transitions and error handling | |

**User's choice:** Yes, lock in safety constraints too.
**Notes:** These orchestrators carry the app's most sensitive checks (SQLi login-bypass, brute-force, stored XSS, IDOR).

| Option | Description | Selected |
|--------|-------------|----------|
| Fully mocked, like run_scan | Stub check functions, no real HTTP | ✓ |
| Some real network calls | Exercise real checks against a live test target | |

**User's choice:** Fully mocked, like run_scan.

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, intentional — advanced stays manual-only | Test run_advanced_scan via direct invocation only | ✓ |
| Should be schedulable too | Bigger design question, likely its own follow-up | |

**User's choice:** Yes, intentional — advanced stays manual-only.
**Notes:** Confirmed via `scheduler.py`'s `_fire()` — no `"advanced"` branch exists; advanced scans need per-run credentials that don't fit unattended scheduling.

---

## Org-flow test coverage & the invite gap (HARD-03)

| Option | Description | Selected |
|--------|-------------|----------|
| Finish the invite flow | Wire /signup to consume ?invite=<token>, assign org+role, test end-to-end | ✓ |
| Also add a standalone role-change route | Most literal reading of HARD-03, but a new admin capability | |
| Test-and-document only | Pin today's behavior, log the gap, no new logic | |

**User's choice:** Finish the invite flow.
**Notes:** Found live during discussion: `org_routes.py`'s `invite()` generates a token that `/signup` never reads — the invite email's own body text admits this ("signup does not yet consume the invite token automatically"). There is also no route anywhere to change an existing member's role.

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, bind email into the token | generate_invite_token(org_id, role, email); signup locks/validates the email | ✓ |
| No, leave it org+role only | Matches today's behavior, leaked-link gap stays open | |

**User's choice:** Yes, bind email into the token.
**Notes:** `generate_invite_token`/`decode_invite_token` currently don't bind the invitee's email — a leaked/forwarded invite link could let anyone join at the granted role.

---

## Visual-consistency pass (HARD-05)

| Option | Description | Selected |
|--------|-------------|----------|
| Reuse existing tokens/primitives only | Apply base.html's existing primitives to the 4 pages, no new components | ✓ |
| Fuller redesign moment | New patterns, bigger scope | |

**User's choice:** Reuse existing tokens/primitives only.

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, run /gsd-ui-phase 4 | Consistent with Phase 2/3 precedent | ✓ |
| No, fold directly into planning | Lighter-weight | |

**User's choice:** Yes, run /gsd-ui-phase 4.

---

## Claude's Discretion

- **HARD-01 (multi-worker rate limiting)** — not selected for live discussion. Disclosed default
  (Redis via the existing `RATELIMIT_STORAGE_URI` config value, proven with a `fakeredis`-backed
  test rather than a real Redis service container) was presented in the pre-context summary; user
  proceeded to "ready for context" without objection or override.
- Exact new-test file organization for HARD-02/HARD-03 left to the planner, per `TESTING.md`'s
  existing "one file per feature area" convention.

## Deferred Ideas

- A fuller HARD-05 redesign moment (new visual patterns beyond `base.html`'s existing set) —
  explicitly declined for this phase; candidate for its own future visual-redesign phase.
- A standalone member role-change route (for changing role after someone has already joined, not
  just at invite time) — explicitly declined for this phase as a new admin capability outside
  "hardening"; candidate for a future requirement.
- Making `run_advanced_scan` schedulable (would need a design for storing/reusing test
  credentials for unattended runs) — explicitly declined as out of scope for Phase 4.
