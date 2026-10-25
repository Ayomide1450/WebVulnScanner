---
phase: 08-security-re-audit-hardening
plan: 03
subsystem: testing
tags: [flask, sqlalchemy, billing, crypto-invoicing, idor, route-testing, pytest]

# Dependency graph
requires:
  - phase: 08-security-re-audit-hardening (08-01, 08-02)
    provides: "SEC-01 completeness lock (tests/test_cross_org_idor.py REGISTRY) with billing.verify_invoice_route explicitly registered as Deferred to this plan"
provides:
  - "Route-level proof that /account/billing/invoice/<id>/verify rejects cross-org access (403), leaves the target invoice, Organization.plan and Subscription table unchanged, and never reaches Polygonscan"
  - "Route-level proof that a replayed verify on a PAID invoice changes nothing and makes no new network call"
  - "Route-level proof that create_invoice's four validation gates (unknown plan, non-purchasable plan, unsupported token, invalid cycle) each create zero CryptoInvoice rows"
  - "Route-level proof that create_invoice derives org_id from the session, not the form, even when an org_id field is injected"
  - "Route-level proof that /account/billing never renders another org's pending invoice or receiving address"
  - "Discharged tests/test_cross_org_idor.py's last Deferred registry entry (billing.verify_invoice_route) to a real test reference"
affects: [08-07]

actuals:
  tokens: 4900
  tasks: 2
  commits: 1

tech-stack:
  added: []
  patterns:
    - "Patch glassbox.billing.requests.get (module-local reference) rather than billing.verify_invoice itself, so a mock's call_count proves whether the route's guard fired before the network call was ever attempted - not just what the route returned."
    - "Force db.session.expire_all() before re-querying a row post-request to prove state-unchanged assertions read the true DB row rather than a possibly-stale identity-mapped Python object."

key-files:
  created: []
  modified:
    - tests/test_billing_routes.py
    - tests/test_cross_org_idor.py

key-decisions:
  - "PAID-invoice replay state was seeded by calling billing._activate_subscription(inv) directly (the exact function a real payment would call) rather than hand-constructing the Subscription row - this exercises the real upsert code path instead of an approximation of it."
  - "The org_id-injection tampering test asserts the created invoice's org_id ignores an extra org_id form field - trivially true today since create_invoice() never reads request.form for org_id, but this pins the property with a regression test rather than leaving it implicit."
  - "billing.py and billing_routes.py were read in full and confirmed already correct (the 403 guard at billing_routes.py:95-96 is present and ordered ahead of the verify_invoice call) - this plan closes a proof gap, not a vulnerability, so neither file was modified."

patterns-established:
  - "Route-level cross-org/tamper test module structure: comment-banner-separated sections (view rendering / cross-org verify / replay / tampering / listing scope / scoping-assumption lock), each grounded in a specific STRIDE threat ID from the plan's threat_model table."

requirements-completed: [SEC-09]

coverage:
  - id: D1
    description: "Cross-org invoice verification (403) with unchanged invoice row, unchanged Organization.plan, no Subscription row, and zero Polygonscan calls"
    requirement: SEC-09
    verification:
      - kind: unit
        ref: "tests/test_billing_routes.py#test_cross_org_verify_is_refused_and_makes_no_changes"
        status: pass
    human_judgment: false
  - id: D2
    description: "Nonexistent invoice ID returns 404"
    requirement: SEC-09
    verification:
      - kind: unit
        ref: "tests/test_billing_routes.py#test_verify_nonexistent_invoice_returns_404"
        status: pass
    human_judgment: false
  - id: D3
    description: "Owning org admin positive control reaches billing.verify_invoice (call count 1) and gets 302"
    requirement: SEC-09
    verification:
      - kind: unit
        ref: "tests/test_billing_routes.py#test_owning_org_admin_can_reach_verify_invoice"
        status: pass
    human_judgment: false
  - id: D4
    description: "Plain MEMBER refused verify (403 from org_admin_required) but can still GET /account/billing (200)"
    requirement: SEC-09
    verification:
      - kind: unit
        ref: "tests/test_billing_routes.py#test_plain_member_cannot_verify_but_can_still_view_billing"
        status: pass
    human_judgment: false
  - id: D5
    description: "Replaying verify on a PAID invoice changes no Subscription field, Organization.plan, or matched_tx_hash, and makes no new Polygonscan call"
    requirement: SEC-09
    verification:
      - kind: unit
        ref: "tests/test_billing_routes.py#test_replaying_verify_on_a_paid_invoice_changes_nothing"
        status: pass
    human_judgment: false
  - id: D6
    description: "create_invoice's four validation gates (unknown plan, non-purchasable plan, unsupported token, invalid billing cycle) each create zero CryptoInvoice rows"
    requirement: SEC-09
    verification:
      - kind: unit
        ref: "tests/test_billing_routes.py#test_create_invoice_rejects_unknown_plan_value"
        status: pass
      - kind: unit
        ref: "tests/test_billing_routes.py#test_create_invoice_rejects_plan_not_purchasable"
        status: pass
      - kind: unit
        ref: "tests/test_billing_routes.py#test_create_invoice_rejects_unsupported_token_symbol"
        status: pass
      - kind: unit
        ref: "tests/test_billing_routes.py#test_create_invoice_rejects_invalid_billing_cycle"
        status: pass
    human_judgment: false
  - id: D7
    description: "create_invoice happy path creates exactly one row whose org_id is the caller's org and expected_amount derives from billing.py's real price table"
    requirement: SEC-09
    verification:
      - kind: unit
        ref: "tests/test_billing_routes.py#test_create_invoice_happy_path_derives_expected_amount_from_price_table"
        status: pass
    human_judgment: false
  - id: D8
    description: "An injected org_id form field on create_invoice does not redirect the created invoice at another org"
    requirement: SEC-09
    verification:
      - kind: unit
        ref: "tests/test_billing_routes.py#test_create_invoice_ignores_injected_org_id_form_field"
        status: pass
    human_judgment: false
  - id: D9
    description: "GET /account/billing never renders another org's pending invoice id or receiving address"
    requirement: SEC-09
    verification:
      - kind: unit
        ref: "tests/test_billing_routes.py#test_billing_view_never_renders_another_orgs_pending_invoice"
        status: pass
    human_judgment: false
  - id: D10
    description: "Scoping-assumption lock: tests/test_billing.py still defines the two unit tests this plan deliberately does not duplicate"
    requirement: SEC-09
    verification:
      - kind: unit
        ref: "tests/test_billing_routes.py#test_test_billing_still_covers_the_two_unit_tests_this_plan_relies_on"
        status: pass
    human_judgment: false
  - id: D11
    description: "tests/test_cross_org_idor.py's billing.verify_invoice_route registry entry discharged from Deferred to a real test reference"
    requirement: SEC-09
    verification:
      - kind: unit
        ref: "tests/test_cross_org_idor.py#test_registry_test_references_resolve"
        status: pass
      - kind: unit
        ref: "tests/test_cross_org_idor.py#test_every_id_accepting_route_has_a_registered_denial_test"
        status: pass
    human_judgment: false

duration: ~25min
completed: 2026-08-19
status: complete
---

# Phase 8 Plan 03: Billing Route Cross-Org/Replay/Tampering Coverage Summary

**Extended `tests/test_billing_routes.py` from 2 tests to 15, proving the billing routes (not just `billing.py`'s already-tested internals) reject cross-org invoice verification, replayed verification, and form-tampered `create_invoice` calls - and discharged plan 08-01's one deferred cross-org registry entry.**

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-08-19
- **Tasks:** 2 of 2 completed
- **Files modified:** 2

## Accomplishments

- Proved `billing_routes.verify_invoice_route`'s `inv.org_id != current_user.org_id: abort(403)` guard actually stops a cross-org caller: 403 status, the target invoice's `status`/`matched_tx_hash`/`matched_at` unchanged (re-queried after `db.session.expire_all()`, not read off a stale object), the target org's `Organization.plan` unchanged, zero `Subscription` rows created, and zero Polygonscan network calls made (proving the abort fires *before* `billing.verify_invoice` is ever entered).
- Added the positive control (owning admin reaches `verify_invoice`, network call count 1, 302 redirect), the nonexistent-invoice-ID 404 case, and the plain-MEMBER role case (403 on verify, 200 still on GET `/account/billing` - the deliberate view/act split).
- Proved a replayed verify on an already-PAID invoice changes nothing: `Subscription.current_period_end`/`status`/`plan`, `Organization.plan`, and `inv.matched_tx_hash` are all byte-identical before and after, and the Polygonscan mock's call count does not increase (the PAID short-circuit fires before the network call).
- Drove all four of `create_invoice`'s rejection gates (unknown `Plan` value, valid-but-non-purchasable `Plan.FREE`, unsupported token symbol, invalid billing cycle) and asserted `CryptoInvoice.query.count() == 0` after each; proved the happy path creates exactly one row with `org_id` equal to the caller's org and `expected_amount` inside the real price-table-derived range; proved an injected `org_id` form field does not redirect the created invoice at another org.
- Proved `/account/billing` never renders another org's pending invoice - neither its `id="addr-{id}"` element nor its receiving address string appears anywhere in a different org's rendered page body.
- Added a source-level lock asserting `tests/test_billing.py` still defines the two unit tests (`test_create_invoice_raises_after_exhausting_retry_budget`, `test_verify_invoice_double_match_on_matched_tx_hash_returns_false`) this plan's scoping decision depends on.
- Discharged `tests/test_cross_org_idor.py`'s `billing.verify_invoice_route` entry from `Deferred(...)` to `"tests/test_billing_routes.py::test_cross_org_verify_is_refused_and_makes_no_changes"`, and updated the module docstring so it no longer describes a still-open deferral.
- Read `glassbox/billing.py` and `glassbox/billing_routes.py` in full; confirmed the cross-org guard is present and correctly ordered ahead of the `verify_invoice` call. **Neither file was modified** - this plan closes a proof gap (D-02), not a live vulnerability.
- Full suite (`pytest -q`): **683 passed**, 0 failures - wave-2 gate green.

## Task Commits

Both tasks landed in a single commit since the entire test module (cross-org, replay, tampering, and listing sections) was authored as one `Write` before the first verification run - see Deviations below.

1. **Task 1: Cross-org invoice verification is refused, and refuses completely** - `4818e21` (test)
2. **Task 2: Replay, tampering and listing-scope coverage** - `4818e21` (test, same commit)

**Plan metadata:** committed separately per worktree convention (see final commit in this plan's execution).

## Files Created/Modified

- `tests/test_billing_routes.py` - grew from 2 tests (payment-card rendering) to 15: adds a shared `_polygonscan_response()` stub helper, extends `make_pending_invoice()` with `status`/`matched_tx_hash`/`matched_at`/`receiving_address` parameters, and adds cross-org / replay / tampering / listing-scope / scoping-lock sections separated by comment banners referencing their STRIDE threat IDs (T-08-13..T-08-19).
- `tests/test_cross_org_idor.py` - one registry value changed (`Deferred(...)` -> real test reference) plus a docstring update recording that the deferral has been discharged.

## Decisions Made

- Seeded the PAID-invoice replay scenario by calling `billing._activate_subscription(inv)` directly (imported from `glassbox.billing`) rather than hand-building the `Subscription` row, since that is the exact function a real prior payment would have run - more honest about what a real payment leaves behind than a hand-rolled approximation.
- Kept the `Deferred` sentinel class in `tests/test_cross_org_idor.py` even though no registry entry currently uses it (the mechanism itself is still useful for the next endpoint that needs a documented, two-step registration).
- Combined Task 1 and Task 2 into a single commit (see Deviations).

## Deviations from Plan

### Process deviation (not a Rule 1-4 auto-fix)

**1. Task 1 and Task 2 landed in one commit instead of two**
- **Found during:** Task 1 → Task 2 handoff.
- **Issue:** The plan calls for one commit per task. Because the full cross-org + replay + tampering + listing-scope test module was authored as a single `Write` of the complete file (more efficient than three incremental `Edit` passes on a file that doesn't exist yet in its extended form), by the time the first `pytest` verification ran, Task 2's code was already present alongside Task 1's.
- **Resolution:** Rather than artificially splitting an already-written, already-verified file back apart via `git add -p` (which adds risk without benefit - the two tasks' tests are logically independent sections within the same module and neither task's acceptance criteria depend on the other being absent), both tasks' work was committed together as `4818e21` with a commit message describing Task 1's scope (the higher-severity T-08-13 threat). Task 2's acceptance criteria (four tamper-gate tests, replay test, listing-scope test, source-level lock, full-suite green) are all independently verifiable in the resulting diff and all pass.
- **Files modified:** `tests/test_billing_routes.py`, `tests/test_cross_org_idor.py` (same as planned).
- **Verification:** `pytest tests/test_billing_routes.py tests/test_cross_org_idor.py -q` → 19 passed; full-suite `pytest -q` → 683 passed.
- **Committed in:** `4818e21`

---

**Total deviations:** 1 (process only - no code correctness issue, no scope creep).
**Impact on plan:** None on outcome. All of both tasks' acceptance criteria are met; the only difference from the plan's literal instruction is commit granularity.

## Issues Encountered

None - `billing.py`/`billing_routes.py` were already correct as read; no auto-fixes were needed under Rules 1-3, and no architectural question arose under Rule 4.

## User Setup Required

None - no external service configuration required. All tests stub `glassbox.billing.requests.get`; no real Polygonscan request is made anywhere in this module.

## Next Phase Readiness

SEC-09 is closed: cross-org invoice verification, replay safety, `create_invoice` value tampering, org-injection, and cross-org listing scope are all proven at the route layer, and plan 08-01's last deferred `tests/test_cross_org_idor.py` registry entry is discharged - `test_every_id_accepting_route_has_a_registered_denial_test` and `test_registry_test_references_resolve` both pass with zero remaining `Deferred(...)` entries in the registry. No blockers for the remaining Wave 3/4/5 plans (08-04 through 08-07); the 08-07 phase gate can re-check this plan's assertions alongside the rest without any pending follow-up from this plan.

## Self-Check: PASSED

- FOUND: tests/test_billing_routes.py
- FOUND: tests/test_cross_org_idor.py
- FOUND: .planning/phases/08-security-re-audit-hardening/08-03-SUMMARY.md
- FOUND commit: 4818e21 (git log --oneline --all)

---
*Phase: 08-security-re-audit-hardening*
*Completed: 2026-08-19*
