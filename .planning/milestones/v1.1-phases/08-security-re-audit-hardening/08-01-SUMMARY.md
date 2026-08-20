---
phase: 08-security-re-audit-hardening
plan: 01
subsystem: testing
tags: [idor, access-control, sec-01, flask, sqlalchemy, url_map, pytest]

# Dependency graph
requires:
  - phase: 08-security-re-audit-hardening
    provides: 08-RESEARCH.md's per-route audit of every ID-accepting route's ownership guard
provides:
  - "tests/test_cross_org_idor.py: an executable, self-maintaining lock proving every <int:>-accepting Flask route has a named cross-org/cross-user denial test"
  - "Cross-org denial coverage for org invitation resend/revoke, scan CSV export, and asset schedule update - the three routes 08-RESEARCH.md flagged as guarded-but-untested"
  - "A recorded, executable route-inventory of all 21 ID-accepting endpoints in webvulnscanner/, their guard mechanism, and their covering test"
affects: [08-03 (SEC-09, billing.verify_invoice_route), 08-07 (phase gate re-check of the one deferred registry entry)]

# Actuals (#2632)
actuals:
  tokens: 5500
  tasks: 3
  commits: 3

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "url_map enumeration lock: a module-level registry dict (endpoint -> covering test) cross-checked bidirectionally against app.url_map.iter_rules() at test time, mirroring test_entitlements.py's FEATURE_REQUIREMENTS-coverage test and test_scan_events.py's CHECK_LABELS sync test"
    - "Deferred(reason) / RoleGated(test_ref, note) registry sentinels - typed exceptions to the 'every entry must resolve to a real test' rule, so an intentional gap is explicit and named rather than silently absent"

key-files:
  created:
    - tests/test_cross_org_idor.py
  modified:
    - tests/test_org_routes.py
    - tests/test_scan_ownership.py
    - tests/test_asset_routes.py

key-decisions:
  - "org_routes.py:335 (resend_invitation) and :353 (revoke_invitation) already carried the `inv.org_id != current_user.org_id: abort(404)` guard at both call sites before this plan ran - this plan closes a proof gap (D-02), not a vulnerability. No production file was modified."
  - "The non-admin-member case (a MEMBER, not ORG_ADMIN, POSTing resend/revoke) is refused with 403 by org_admin_required (decorators.py), not the 404 IDOR guard - confirmed by reading the decorator rather than assumed."
  - "The two platform-admin domain-deletion routes (org.approve_domain_deletion / org.reject_domain_deletion) are registered in the enumeration lock as RoleGated, not as ordinary org-scoped entries - they are cross-org BY DESIGN (platform_admin_required, not an org_id comparison), so an org-scoping denial test for them would assert the wrong thing. Their registered test instead proves the role gate: the requesting org admin cannot also approve their own request (403)."
  - "billing.verify_invoice_route is the one ID-accepting route left as Deferred in the registry - explicitly transferred to plan 08-03 (SEC-09) per the threat register's T-08-05 (disposition: transfer), not silently omitted. Re-checked at the 08-07 phase gate."

patterns-established:
  - "Any future route registered with an <int:...> path converter must be added to tests/test_cross_org_idor.py's REGISTRY or the enumeration test fails, naming the exact rule string."

requirements-completed: [SEC-01]

coverage:
  - id: D1
    description: "Cross-org resend/revoke of an org invitation both 404 with no side effect (Invitation row and OrgAuditEvent unchanged); owning admin positive control proves the 404 isn't a fixture bug; non-admin member gets 403 from org_admin_required."
    requirement: "SEC-01"
    verification:
      - kind: unit
        ref: "tests/test_org_routes.py#test_cross_org_resend_invitation_is_404_and_leaves_invitation_and_audit_log_untouched"
        status: pass
      - kind: unit
        ref: "tests/test_org_routes.py#test_cross_org_revoke_invitation_is_404_and_leaves_invitation_and_audit_log_untouched"
        status: pass
      - kind: unit
        ref: "tests/test_org_routes.py#test_owning_org_admin_can_still_resend_the_same_invitation"
        status: pass
      - kind: unit
        ref: "tests/test_org_routes.py#test_owning_org_admin_can_still_revoke_the_same_invitation"
        status: pass
      - kind: unit
        ref: "tests/test_org_routes.py#test_non_admin_member_cannot_resend_or_revoke_invitation"
        status: pass
    human_judgment: false
  - id: D2
    description: "url_map enumeration lock: every <int:>-accepting route has a registered cross-org/cross-user denial test; the lock fails loudly (naming the rule) for an unregistered new route or a stale registry entry; the app's HTTP method set is proven to be a subset of GET/HEAD/OPTIONS/POST."
    requirement: "SEC-01"
    verification:
      - kind: unit
        ref: "tests/test_cross_org_idor.py#test_every_id_accepting_route_has_a_registered_denial_test"
        status: pass
      - kind: unit
        ref: "tests/test_cross_org_idor.py#test_registry_has_no_stale_entries"
        status: pass
      - kind: unit
        ref: "tests/test_cross_org_idor.py#test_registered_method_set_is_get_head_options_post_only"
        status: pass
      - kind: unit
        ref: "tests/test_cross_org_idor.py#test_registry_test_references_resolve"
        status: pass
    human_judgment: false
  - id: D3
    description: "scan.scan_report_csv (CSV findings export) and asset.update_schedule are closed: cross-org CSV export 404s and leaks no finding text; asset schedule update 404s cross-org and does not mutate cadence/schedule_scan_type."
    requirement: "SEC-01"
    verification:
      - kind: unit
        ref: "tests/test_scan_ownership.py#test_scan_report_csv_cross_org_is_404_and_leaks_no_finding_text"
        status: pass
      - kind: unit
        ref: "tests/test_asset_routes.py#test_schedule_cross_org_is_404_and_does_not_mutate_cadence_or_scan_type"
        status: pass
    human_judgment: false

duration: 55min
completed: 2026-08-19
status: complete
---

# Phase 8 Plan 01: SEC-01 Cross-Org IDOR Completeness Lock Summary

**A self-maintaining `url_map` enumeration test (`tests/test_cross_org_idor.py`) now fails, naming the exact rule string, if any future `<int:>`-accepting Flask route ships without a registered cross-org denial test - closing SEC-01 with 11 new tests and zero production-file changes.**

## Performance

- **Duration:** 55 min
- **Started:** 2026-08-19T06:58:00Z
- **Completed:** 2026-08-19T07:53:00Z
- **Tasks:** 3
- **Files modified:** 4 (1 created, 3 extended)

## Accomplishments

- Closed the two genuinely-uncovered guarded-but-untested routes 08-RESEARCH.md flagged: org invitation resend/revoke now have executable cross-org denial proof (404 + no side effect) plus an owning-admin positive control and the non-admin-member 403 case.
- Built `tests/test_cross_org_idor.py`, the completeness lock: a `REGISTRY` dict mapping all 21 `<int:>`-accepting endpoints in `app.url_map` to their covering test, with bidirectional enumeration tests (missing-entry and stale-entry), a method-subset assertion (proves no PUT/DELETE route exists anywhere in the app), and a resolution check that every referenced test actually exists on disk.
- Performed and reverted both required negative controls: a throwaway `/tmp-idor-probe/<int:x>` route made the enumeration test fail naming that literal rule string; a renamed registry key (`scan.scan_status_TMP_RENAMED_PROBE`) made the reverse-direction test fail. Both reverted; `git diff --stat` for `webvulnscanner/scan_routes.py` came back empty after the revert.
- Closed the two remaining registry gaps: `scan.scan_report_csv` (cross-org 404 + a seeded marker string proven absent from the response body, with an owner-side 200 positive control) and `asset.update_schedule` (cross-org 404 + re-read of the Asset row proving `cadence`/`schedule_scan_type` are unchanged).
- Full suite: 657 passed, 0 failed (baseline 646 + 11 new tests), confirmed twice - once before this plan's changes (retroactive precondition confirmation) and once after all three tasks.

## Task Commits

Each task was committed atomically:

1. **Task 1: End-to-end cross-org IDOR proof for the org-invitation family** - `2f93e3d` (test)
2. **Task 2: url_map enumeration lock** - `ea225d3` (test)
3. **Task 3: Close the two remaining uncovered ID-accepting routes** - `17ea150` (test)

**Plan metadata:** (this commit, docs: complete plan)

_No TDD RED/GREEN/REFACTOR cycle - all three tasks are `tdd="true"` in the plan's frontmatter but this plan is entirely test-authoring against already-correct production code (D-02), so there is no separate "implementation" commit to pair with a test commit; each task's single `test(...)` commit both proves and locks the existing guard._

## Files Created/Modified

- `tests/test_cross_org_idor.py` - New. The SEC-01 completeness lock: `REGISTRY` (endpoint -> covering test / `Deferred` / `RoleGated`), `test_every_id_accepting_route_has_a_registered_denial_test`, `test_registry_has_no_stale_entries`, `test_registered_method_set_is_get_head_options_post_only`, `test_registry_test_references_resolve`.
- `tests/test_org_routes.py` - Added a cross-org invitation section: cross-org resend/revoke denial + no-side-effect, owning-admin positive controls (split into two tests to keep each assertion block focused), and the non-admin-member 403 case. +5 tests (11 -> 16).
- `tests/test_scan_ownership.py` - Added `scan.scan_report_csv` cross-org denial test with a seeded-marker leak check and owner-side positive control. +2 tests.
- `tests/test_asset_routes.py` - Added `asset.update_schedule` cross-org denial test with a no-mutation re-read assertion. +1 test.

## Route Inventory (SEC-01 completeness)

All 21 `<int:>`-accepting rules in `app.url_map`, built programmatically via `create_app(TestConfig).url_map.iter_rules()` (not transcribed from the plan):

| Endpoint | Rule | Guard | Covering test |
|---|---|---|---|
| billing.verify_invoice_route | /account/billing/invoice/\<int:invoice_id\>/verify | inline org_id, abort(403) | **Deferred** - plan 08-03 (SEC-09), threat register T-08-05 |
| api.trigger_scan | /api/v1/assets/\<int:asset_id\>/scans | `_check_asset_access` | test_api_routes.py::test_trigger_scan_different_org_gets_404_no_scan_created |
| api.scan_status | /api/v1/scans/\<int:scan_id\> | `_check_asset_access` or `_check_ownership` | test_api_routes.py::test_scan_status_different_org_gets_404 |
| api.fetch_report | /api/v1/scans/\<int:scan_id\>/report | `_check_asset_access` or `_check_ownership` | test_api_routes.py::test_fetch_report_different_org_gets_404 |
| api_tokens.revoke_token | /tokens/\<int:token_id\>/revoke | `t.user_id != current_user.id` | test_api_tokens_routes.py::test_user_cannot_revoke_another_users_token |
| asset.asset_detail | /assets/\<int:asset_id\> | `_check_asset_access` | test_asset_routes.py::test_get_asset_detail_for_other_org_is_404 |
| asset.delete_asset | /assets/\<int:asset_id\>/delete | `_check_asset_access` | test_asset_routes.py::test_pause_resume_delete_all_three_404_for_non_owning_org |
| asset.pause_asset | /assets/\<int:asset_id\>/pause | `_check_asset_access` | test_asset_routes.py::test_pause_resume_delete_all_three_404_for_non_owning_org |
| asset.resume_asset | /assets/\<int:asset_id\>/resume | `_check_asset_access` | test_asset_routes.py::test_pause_resume_delete_all_three_404_for_non_owning_org |
| asset.update_schedule | /assets/\<int:asset_id\>/schedule | `_check_asset_access` | test_asset_routes.py::test_schedule_cross_org_is_404_and_does_not_mutate_cadence_or_scan_type **(this plan)** |
| org.approve_domain_deletion | /org/admin/domain/\<int:domain_id\>/deletion/approve | `platform_admin_required` (role, not org) | test_org_routes.py::test_org_admin_cannot_approve_their_own_deletion_request |
| org.reject_domain_deletion | /org/admin/domain/\<int:domain_id\>/deletion/reject | `platform_admin_required` (role, not org) | test_org_routes.py::test_org_admin_cannot_approve_their_own_deletion_request |
| org.request_domain_deletion | /org/admin/domain/\<int:domain_id\>/request-deletion | inline org_id, abort(404) | test_org_routes.py::test_domain_deletion_actions_are_org_scoped |
| org.resend_invitation | /org/admin/invite/\<int:invitation_id\>/resend | inline org_id, abort(404) | test_org_routes.py::test_cross_org_resend_invitation_is_404_and_leaves_invitation_and_audit_log_untouched **(this plan)** |
| org.revoke_invitation | /org/admin/invite/\<int:invitation_id\>/revoke | inline org_id, abort(404) | test_org_routes.py::test_cross_org_revoke_invitation_is_404_and_leaves_invitation_and_audit_log_untouched **(this plan)** |
| scan.scan_compare | /scan/\<int:scan_id\>/compare/\<int:other_id\> | `_check_ownership` (both scans) | test_scan_ownership.py::test_scan_compare_checks_both_scans_not_just_the_first |
| scan.scan_detail | /scan/\<int:scan_id\> | `_check_ownership` | test_scan_ownership.py::test_admin_of_a_different_org_cannot_view_scan |
| scan.scan_events | /scan/\<int:scan_id\>/events | `_check_ownership` | test_scan_ownership.py::test_scan_events_denies_cross_org_access |
| scan.scan_report | /scan/\<int:scan_id\>/report | `_check_ownership` | test_scan_ownership.py::test_scan_report_and_scan_compare_enforce_ownership_too |
| scan.scan_report_csv | /scan/\<int:scan_id\>/export.csv | `_check_ownership` | test_scan_ownership.py::test_scan_report_csv_cross_org_is_404_and_leaks_no_finding_text **(this plan)** |
| scan.scan_status | /scan/\<int:scan_id\>/status | `_check_ownership` | test_scan_status.py::test_status_different_org_gets_404 |

**Platform-admin deletion routes, explicitly:** `org.approve_domain_deletion` / `org.reject_domain_deletion` are cross-org **by design** - a platform admin reviews every org's deletion requests, so the correct (and only correct) guard is `platform_admin_required`, a role check, not an `org_id` comparison. Writing an org-scoping denial test for these two would assert something false about the intended behavior. They're registered in `test_cross_org_idor.py`'s `REGISTRY` as `RoleGated(test_ref, note)`, a distinct sentinel from a plain string entry, so the reasoning is recorded in the registry itself (not just this summary) and the resolution check still requires their `test_ref` to point at a real test.

**Method-set assertion:** `app.url_map`'s full method set is `{GET, HEAD, OPTIONS, POST}` - no PUT or DELETE route exists anywhere in `webvulnscanner/`. Asserted directly in `test_registered_method_set_is_get_head_options_post_only`, confirming 08-RESEARCH.md's Pitfall 1 finding and the plan's `must_haves` statement that SEC-01's "GET/POST/PUT/DELETE" wording is a generic checklist, not a description of this app's actual routing.

## Negative Controls (performed and reverted, verbatim)

**Control 1 - unregistered route.** Temporarily added to `webvulnscanner/scan_routes.py`:
```python
@scan.route("/tmp-idor-probe/<int:x>")
@login_required
def _tmp_idor_probe(x):
    return "probe"
```
Running `test_every_id_accepting_route_has_a_registered_denial_test` failed with:
```
AssertionError: The following <int:>-accepting route(s) in app.url_map have no entry in tests/test_cross_org_idor.py's REGISTRY. Add one mapping the endpoint to 'tests/test_x.py::test_name' (a real cross-org/cross-user denial test), or to Deferred(reason)/RoleGated(test_ref, note) if the coverage is intentionally owned elsewhere or the endpoint is cross-org by design:
  - rule='/tmp-idor-probe/<int:x>' endpoint='scan._tmp_idor_probe'
assert not [<Rule '/tmp-idor-probe/<x>' (HEAD, OPTIONS, GET) -> scan._tmp_idor_probe>]
```
Reverted. `git diff --stat -- webvulnscanner/scan_routes.py` came back empty after the revert (confirmed clean).

**Control 2 - stale registry entry.** Temporarily renamed the `scan.scan_status` key in `REGISTRY` to `scan.scan_status_TMP_RENAMED_PROBE`. Running `test_registry_has_no_stale_entries` failed with:
```
AssertionError: REGISTRY (tests/test_cross_org_idor.py) names endpoint(s) that no longer exist in app.url_map - the registry itself has rotted and needs updating: scan.scan_status_TMP_RENAMED_PROBE
assert not ['scan.scan_status_TMP_RENAMED_PROBE']
```
Reverted. Full `test_cross_org_idor.py` module re-run green (4 passed) after the revert.

## Decisions Made

- **org_routes.py's invitation guard was already correct.** `resend_invitation` (line 335) and `revoke_invitation` (line 353) both carry `if inv.org_id != current_user.org_id: abort(404)` before this plan ran. This plan closes the proof gap (D-02) - a code-review finding still needs a Flask-test-client regression test - not a vulnerability. No file under `webvulnscanner/` was modified.
- **The non-admin-member status code is 403, not 404.** `org_admin_required` (`decorators.py`) aborts 403 for an authenticated non-ORG_ADMIN before the route body (and its 404 IDOR guard) ever runs. Confirmed by reading the decorator rather than assuming the convention used elsewhere in the same file.
- **Platform-admin deletion routes are cross-org by design, not a coverage gap.** Recorded as a `RoleGated` registry entry rather than either silently skipping them or writing a nonsensical org-scoping test.
- **billing.verify_invoice_route stays Deferred, not silently dropped.** It's named in the registry with an explicit reason (owned by plan 08-03/SEC-09, threat register T-08-05) so the enumeration lock can't be satisfied by quietly deleting the entry.

## Deviations from Plan

None - plan executed exactly as written. No production file under `webvulnscanner/` was touched; `git diff --stat` across the whole plan (`git diff --stat 1dbd56c..17ea150`) lists only files under `tests/`.

## Issues Encountered

None. The `.venv` used by the orchestrator's main checkout is not present inside this worktree (worktrees share git history but not untracked directories) - tests were run by invoking the main checkout's `.venv/Scripts/python.exe` with the worktree as the working directory, which correctly imports the worktree's own `webvulnscanner`/`tests` packages (confirmed via `sys.path` behavior and cross-checked against the actual `app.url_map` inventory). No code or config change was needed to make this work; noted here only because a future agent hitting the same "No module named pytest" error in a fresh worktree should look for the sibling checkout's `.venv` rather than assume one needs to be created.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SEC-01 is closed: every `<int:>`-accepting route in the app has a named, executable cross-org/cross-user denial test except `billing.verify_invoice_route`, which is explicitly transferred to plan 08-03 (SEC-09) and will be re-checked at the 08-07 phase gate.
- The `tests/test_cross_org_idor.py` enumeration lock is now live for the rest of Phase 8 (and beyond) - any plan in this phase (or later) that adds a new `<int:>`-accepting route will get an immediate, specific test failure if it doesn't also add a REGISTRY entry.
- No blockers for 08-02 (this plan's wave-1 sibling) or subsequent waves.

---
*Phase: 08-security-re-audit-hardening*
*Completed: 2026-08-19*

## Self-Check: PASSED

- FOUND: tests/test_cross_org_idor.py
- FOUND: tests/test_org_routes.py
- FOUND: tests/test_scan_ownership.py
- FOUND: tests/test_asset_routes.py
- FOUND: .planning/phases/08-security-re-audit-hardening/08-01-SUMMARY.md
- FOUND commit: 2f93e3d
- FOUND commit: ea225d3
- FOUND commit: 17ea150
