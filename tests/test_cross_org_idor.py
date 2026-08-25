"""
SEC-01 completeness lock (08-01, Task 2).

Ownership guards in this app live per-blueprint in exactly three shapes:
`scan_routes._check_ownership` (owner-or-org-admin), `asset_routes._check_asset_access`
(org-shared, with an explicit solo-user branch), and a handful of inline
`x.org_id != current_user.org_id: abort(404)` / `x.user_id != current_user.id: abort(404)`
comparisons (org_routes.py, api_tokens_routes.py). 08-RESEARCH.md read every route that
accepts an `<int:...>` object ID this session and found all three shapes already correctly
applied - so this module does NOT re-test any individual route's guard; every per-route
denial test already lives in its own module (test_org_routes.py, test_scan_ownership.py,
test_asset_routes.py, test_api_routes.py, test_api_tokens_routes.py, test_scan_status.py,
test_domain_verification.py).

What this module actually does is make SEC-01's *completeness* claim executable, the same
way `test_entitlements.py::test_feature_requirements_covers_run_scan_jobs` makes
`entitlements.FEATURE_REQUIREMENTS`'s coverage of `run_scan`'s jobs dict executable, and the
same way `test_scan_events.py` locks `checks.CHECK_LABELS` against `run_scan`'s jobs dict:
build the REGISTRY below from the live `app.url_map`, not from a hand-copied list of today's
routes (a hand-copied list would silently go stale the day someone adds a new ID-accepting
route and forgets a test). `test_every_id_accepting_route_has_a_registered_denial_test` fails,
naming the exact rule string, the moment a `<int:>`-accepting endpoint has no entry here;
`test_registry_has_no_stale_entries` fails in the other direction if an entry names an
endpoint that no longer exists. Together they're the only mechanism in this phase that makes
SEC-01 survive the next route somebody adds without reading this file first.

Two registry value shapes are NOT plain test references:

- `Deferred(reason)` marks an endpoint whose cross-org coverage is intentionally owned
  elsewhere rather than silently missing - it still has to be *named* here, just not resolved
  to a test yet. No entry currently uses this shape: `billing.verify_invoice_route` was the
  one Deferred entry (owned by plan 08-03/SEC-09 per the phase's threat register, T-08-05,
  disposition "transfer") and has since been discharged to a real test reference
  (`tests/test_billing_routes.py::test_cross_org_verify_is_refused_and_makes_no_changes`); the
  class is kept for the next endpoint that needs the same two-step registration.
- `RoleGated(test_ref, note)` marks an endpoint that is cross-org BY DESIGN: the two
  platform-admin domain-deletion routes (`approve_domain_deletion`/`reject_domain_deletion`)
  are guarded by `platform_admin_required`, a role gate, not an org_id comparison - a platform
  admin reviews every org's requests, so an org-scoping denial test for these two would assert
  the wrong thing. Their registered test proves the role gate instead
  (`test_org_admin_cannot_approve_their_own_deletion_request`).
"""
import re
from pathlib import Path

from tests.conftest import TestConfig
from webvulnscanner import create_app

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# The only HTTP verbs this app has ever registered a route with. No PUT or
# DELETE route exists anywhere in webvulnscanner/ - every mutation is a POST
# to an action-suffixed path (08-RESEARCH.md Pitfall 1). SEC-01's literal
# "GET/POST/PUT/DELETE" wording is a generic REST checklist, not a
# description of this app's actual routing - this assertion is the
# executable form of that finding.
ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}


class Deferred:
    """Registry sentinel: this endpoint's cross-org coverage is intentionally
    owned by a different, named plan rather than missing by omission. Exempt
    from the test-reference resolution check (there is no test to resolve
    yet), but still required to be present as a REGISTRY key so the
    enumeration test doesn't flag it as unregistered."""

    def __init__(self, reason):
        self.reason = reason

    def __repr__(self):
        return f"Deferred({self.reason!r})"


class RoleGated:
    """Registry sentinel: this endpoint is deliberately cross-org because its
    guard is a role check (e.g. platform_admin_required), not an org_id
    comparison - an org-scoping denial test would be testing the wrong
    thing. `test_ref` still resolves like a plain string entry; `note`
    records why, so the reasoning lives in the registry itself rather than
    only in this module's docstring."""

    def __init__(self, test_ref, note):
        self.test_ref = test_ref
        self.note = note

    def __repr__(self):
        return f"RoleGated({self.test_ref!r}, ...)"


# endpoint -> "tests/test_x.py::test_name" | Deferred(reason) | RoleGated(test_ref, note)
#
# Built from the real `app.url_map` (see _id_accepting_rules below), cross-checked against
# 08-01-PLAN.md's Task 2 route-inventory table.
REGISTRY = {
    "billing.verify_invoice_route": "tests/test_billing_routes.py::test_cross_org_verify_is_refused_and_makes_no_changes",
    "api.trigger_scan": "tests/test_api_routes.py::test_trigger_scan_different_org_gets_404_no_scan_created",
    "api.scans_compare": "tests/test_api_routes.py::test_scans_compare_cross_org_is_404",
    "api.scan_status": "tests/test_api_routes.py::test_scan_status_different_org_gets_404",
    "api.fetch_report": "tests/test_api_routes.py::test_fetch_report_different_org_gets_404",
    # fetch_report_csv (Phase 18 close-out) clones fetch_report's ownership
    # branches verbatim, so its registry entry mirrors this one.
    "api.fetch_report_csv": "tests/test_api_routes.py::test_report_csv_different_org_gets_404",
    # scans_gate shares fetch_report's two ownership branches; this entry names the
    # asset-linked cross-org denial - the manual-scan branch is additionally covered by
    # tests/test_security_gate.py::test_manual_scan_non_owner_member_gets_404.
    "api.scans_gate": "tests/test_security_gate.py::test_cross_org_asset_linked_scan_gets_404",
    "api_tokens.revoke_token": "tests/test_api_tokens_routes.py::test_user_cannot_revoke_another_users_token",
    # Phase 19 webhook management: all four id-accepting routes share
    # _scoped_webhook_or_404's dual scope rule (org webhooks -> that org's
    # ORG_ADMIN, solo webhooks -> creator only); each denial test below
    # covers all four actions so the registry entries point at the same pair.
    "webhooks.delete_webhook": "tests/test_webhooks.py::test_all_four_webhook_actions_are_404_for_a_solo_non_owner",
    "webhooks.toggle_webhook": "tests/test_webhooks.py::test_all_four_webhook_actions_are_404_for_a_solo_non_owner",
    "webhooks.test_webhook": "tests/test_webhooks.py::test_all_four_webhook_actions_are_404_for_another_orgs_admin",
    "webhooks.deliveries": "tests/test_webhooks.py::test_all_four_webhook_actions_are_404_for_another_orgs_admin",
    "asset.asset_detail": "tests/test_asset_routes.py::test_get_asset_detail_for_other_org_is_404",
    "asset.delete_asset": "tests/test_asset_routes.py::test_pause_resume_delete_all_three_404_for_non_owning_org",
    "asset.pause_asset": "tests/test_asset_routes.py::test_pause_resume_delete_all_three_404_for_non_owning_org",
    "asset.resume_asset": "tests/test_asset_routes.py::test_pause_resume_delete_all_three_404_for_non_owning_org",
    "asset.update_schedule": "tests/test_asset_routes.py::test_schedule_cross_org_is_404_and_does_not_mutate_cadence_or_scan_type",
    "admin.user_detail": RoleGated(
        "tests/test_admin_routes.py::test_all_six_user_org_detail_and_suspend_routes_require_platform_admin",
        "Cross-org BY DESIGN (Phase 16): platform_admin_required is a role gate - a platform "
        "admin reviews every org's users, not just their own - not an org_id comparison.",
    ),
    "admin.org_detail": RoleGated(
        "tests/test_admin_routes.py::test_all_six_user_org_detail_and_suspend_routes_require_platform_admin",
        "Same platform_admin_required role gate as admin.user_detail above.",
    ),
    "admin.suspend_user": RoleGated(
        "tests/test_admin_routes.py::test_all_six_user_org_detail_and_suspend_routes_require_platform_admin",
        "Same platform_admin_required role gate as admin.user_detail above.",
    ),
    "admin.unsuspend_user": RoleGated(
        "tests/test_admin_routes.py::test_all_six_user_org_detail_and_suspend_routes_require_platform_admin",
        "Same platform_admin_required role gate as admin.user_detail above.",
    ),
    "admin.suspend_org": RoleGated(
        "tests/test_admin_routes.py::test_all_six_user_org_detail_and_suspend_routes_require_platform_admin",
        "Same platform_admin_required role gate as admin.user_detail above.",
    ),
    "admin.unsuspend_org": RoleGated(
        "tests/test_admin_routes.py::test_all_six_user_org_detail_and_suspend_routes_require_platform_admin",
        "Same platform_admin_required role gate as admin.user_detail above.",
    ),
    "org.approve_domain_deletion": RoleGated(
        "tests/test_org_routes.py::test_org_admin_cannot_approve_their_own_deletion_request",
        "Cross-org BY DESIGN: platform_admin_required is a role gate (a platform admin reviews "
        "every org's requests), not an org_id comparison - an org-scoping test would assert "
        "the wrong thing about this route. The registered test instead proves the role gate: "
        "the org admin who filed the request cannot also approve it (403).",
    ),
    "org.reject_domain_deletion": RoleGated(
        "tests/test_org_routes.py::test_org_admin_cannot_approve_their_own_deletion_request",
        "Same platform_admin_required role gate as approve_domain_deletion above (identical "
        "decorator, identical reasoning) - deliberately no separate org-scoping test for this "
        "endpoint either.",
    ),
    "org.request_domain_deletion": "tests/test_org_routes.py::test_domain_deletion_actions_are_org_scoped",
    "org.resend_invitation": "tests/test_org_routes.py::test_cross_org_resend_invitation_is_404_and_leaves_invitation_and_audit_log_untouched",
    "org.revoke_invitation": "tests/test_org_routes.py::test_cross_org_revoke_invitation_is_404_and_leaves_invitation_and_audit_log_untouched",
    "scan.scan_compare": "tests/test_scan_ownership.py::test_scan_compare_checks_both_scans_not_just_the_first",
    "scan.scan_detail": "tests/test_scan_ownership.py::test_admin_of_a_different_org_cannot_view_scan",
    "scan.scan_events": "tests/test_scan_ownership.py::test_scan_events_denies_cross_org_access",
    "scan.scan_report": "tests/test_scan_ownership.py::test_scan_report_and_scan_compare_enforce_ownership_too",
    "scan.scan_report_csv": "tests/test_scan_ownership.py::test_scan_report_csv_cross_org_is_404_and_leaks_no_finding_text",
    # fetch_report_sarif (Phase 29) clones fetch_report/fetch_report_csv's
    # ownership branches verbatim; its denial tests live alongside the rest
    # of the SARIF suite.
    "api.fetch_report_sarif": "tests/test_sarif_export.py::test_report_sarif_different_org_gets_404",
    "scan.scan_report_sarif": "tests/test_sarif_export.py::test_scan_report_sarif_cross_org_is_404_and_leaks_no_finding_text",
    # fetch_report_pdf (Phase 24) clones the same ownership branches;
    # denial tests live alongside the rest of the PDF suite.
    "api.fetch_report_pdf": "tests/test_pdf_export.py::test_report_pdf_different_org_gets_404",
    "scan.scan_report_pdf": "tests/test_pdf_export.py::test_scan_report_pdf_cross_org_is_404_and_leaks_no_finding_text",
    # fetch_report_ndjson (Phase 25) clones the same ownership branches;
    # denial tests live alongside the rest of the NDJSON suite.
    "api.fetch_report_ndjson": "tests/test_ndjson_export.py::test_report_ndjson_different_org_gets_404",
    "scan.scan_report_ndjson": "tests/test_ndjson_export.py::test_scan_report_ndjson_cross_org_is_404_and_leaks_no_finding_text",
    "org.audit_log": "tests/test_audit_log.py::test_audit_log_cross_org_is_404",
    "scan.scan_status": "tests/test_scan_status.py::test_status_different_org_gets_404",
}


def _url_map():
    # Built fresh from the real app each call (not memoized at import time) -
    # this is what lets the negative control (temporarily registering a
    # throwaway route) actually change what this test sees.
    app = create_app(TestConfig)
    return app.url_map


def _id_accepting_rules():
    return [r for r in _url_map().iter_rules() if "<int:" in r.rule]


def _test_ref(value):
    """Returns the resolvable 'module::name' string for a registry value, or
    None if the value is a Deferred sentinel (nothing to resolve yet)."""
    if isinstance(value, Deferred):
        return None
    if isinstance(value, RoleGated):
        return value.test_ref
    return value


def test_every_id_accepting_route_has_a_registered_denial_test():
    rules = _id_accepting_rules()
    missing = [r for r in rules if r.endpoint not in REGISTRY]
    assert not missing, (
        "The following <int:>-accepting route(s) in app.url_map have no entry in "
        "tests/test_cross_org_idor.py's REGISTRY. Add one mapping the endpoint to "
        "'tests/test_x.py::test_name' (a real cross-org/cross-user denial test), or to "
        "Deferred(reason)/RoleGated(test_ref, note) if the coverage is intentionally owned "
        "elsewhere or the endpoint is cross-org by design:\n" +
        "\n".join(f"  - rule={r.rule!r} endpoint={r.endpoint!r}" for r in missing)
    )


def test_registry_has_no_stale_entries():
    live_endpoints = {r.endpoint for r in _url_map().iter_rules()}
    stale = sorted(ep for ep in REGISTRY if ep not in live_endpoints)
    assert not stale, (
        "REGISTRY (tests/test_cross_org_idor.py) names endpoint(s) that no longer exist in "
        "app.url_map - the registry itself has rotted and needs updating: " + ", ".join(stale)
    )


def test_registered_method_set_is_get_head_options_post_only():
    methods = set()
    for r in _url_map().iter_rules():
        methods |= r.methods
    unexpected = methods - ALLOWED_METHODS
    assert not unexpected, (
        f"app.url_map now registers {sorted(unexpected)} - this app has never had a PUT or "
        "DELETE verb route (every mutation is a POST to an action-suffixed path, per "
        "08-RESEARCH.md Pitfall 1 and 08-01-PLAN.md's must_haves). A new verb here means "
        "SEC-01's routing assumptions need a fresh look, not just a REGISTRY update."
    )


def test_registry_test_references_resolve():
    bad = []
    for endpoint, value in REGISTRY.items():
        ref = _test_ref(value)
        if ref is None:
            continue
        module_path, _, test_name = ref.partition("::")
        full_path = PROJECT_ROOT / module_path
        if not full_path.is_file():
            bad.append(f"{endpoint} -> {ref!r} (file not found: {module_path})")
            continue
        source = full_path.read_text(encoding="utf-8")
        if not re.search(rf"^def {re.escape(test_name)}\(", source, re.MULTILINE):
            bad.append(f"{endpoint} -> {ref!r} (no 'def {test_name}(' found in {module_path})")
    assert not bad, (
        "REGISTRY entries pointing at a test that doesn't exist on disk - the same rot as a "
        "stale endpoint, just in the other direction:\n" + "\n".join(f"  - {b}" for b in bad)
    )
