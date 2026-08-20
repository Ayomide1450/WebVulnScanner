"""
Rendering coverage for STATE-01 (empty states) and STATE-02 (submitting
states), 09-02-PLAN.md.

Task 1: templates/_empty_state.html's shared macro + dashboard.html's and
assets.html's migration onto it (both existing instances, verbatim copy
preserved) - see 09-UI-SPEC.md's "New Component Specifications" section for
the macro's exact signature/structure/visual spec this module locks.

Task 2 (extends this module): org_admin.html / org_verify_domain.html /
billing.html / api_tokens.html's new adoption of the same macro across
seven call sites.

Task 3 (extends this module): submitting-state (disabled + text-swap)
regression locks for the six forms that already had the full pattern
before this plan (login/signup/the four scan-launch forms), plus presence
tests for the twelve forms this plan closes the disable-only or
no-indicator-at-all gap on.
"""
from webvulnscanner.models import Report, Role, ScanStatus

from tests.conftest import login, make_org, make_scan, make_user


# --------------------------------------------------------------------------
# Task 1: _empty_state.html partial + dashboard.html / assets.html migration
# --------------------------------------------------------------------------

def test_dashboard_no_scans_empty_state_uses_shared_macro(client, db):
    """dashboard.html's scan-history empty state - migrated verbatim copy,
    now rendered through the shared macro's .empty-state container."""
    org = make_org()
    make_user("noscans@example.com", org=org)
    db.session.commit()

    login(client, "noscans@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No scans yet." in body
    assert "Run your first scan" in body
    assert 'class="empty-state"' in body


def test_dashboard_no_findings_empty_state_uses_shared_macro(client, db):
    """dashboard.html's no-findings ('all clear') empty state - migrated
    verbatim copy, still the one --accent-colored icon instance."""
    org = make_org()
    user = make_user("nofindings@example.com", org=org)
    scan = make_scan(user, org=org, status=ScanStatus.COMPLETED)
    db.session.add(Report(scan_id=scan.id, json_path=f"unused_{scan.id}.json",
                           data={"findings": [], "severity_counts": {}}))
    db.session.commit()

    login(client, "nofindings@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No security issues found" in body
    assert "Your latest scan did not detect any actionable vulnerabilities." in body
    assert 'class="empty-state"' in body


def test_assets_empty_state_uses_shared_macro(client, db):
    """assets.html's empty state - migrated verbatim copy (title/body/CTA
    split), now rendered through the shared macro."""
    org = make_org()
    make_user("noassets@example.com", org=org)
    db.session.commit()

    login(client, "noassets@example.com")
    resp = client.get("/assets")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No assets yet." in body
    assert (
        "Register a domain as an Asset to scan it automatically on a schedule, "
        "instead of resubmitting it by hand."
    ) in body
    assert "Add your first Asset" in body
    assert 'class="empty-state"' in body


def test_dashboard_local_empty_state_css_rule_removed():
    """dashboard.html's local .empty-state/.empty-state .icon CSS rules are
    now owned exclusively by _empty_state.html's own <style> block - a
    duplicate local rule here would drift from the shared partial silently."""
    import pathlib

    text = pathlib.Path("templates/dashboard.html").read_text(encoding="utf-8")
    assert ".empty-state {" not in text
    assert ".empty-state .icon {" not in text


# --------------------------------------------------------------------------
# Task 2: org_admin.html / org_verify_domain.html / billing.html /
# api_tokens.html adoption of the shared macro
# --------------------------------------------------------------------------

def _make_org_admin(email="orgadmin2@example.com"):
    """An ORG_ADMIN user with no org attached (org=None) - org_admin_required
    only checks the role, not org membership (webvulnscanner/decorators.py),
    so this is a real, reachable state: it's what drives every one of
    org_admin.html's/org_verify_domain.html's four/one bare-collection
    branches to their empty-state simultaneously (current_user.organization
    is None -> members/domains/scans/audit_events all resolve to []),
    without needing an org that itself has zero members (impossible - the
    admin viewing the page is always a member of their own org)."""
    return make_user(email, org=None, role=Role.ORG_ADMIN, verified=True)


def test_org_admin_no_members_empty_state_uses_shared_macro(client, db):
    _make_org_admin()
    db.session.commit()

    login(client, "orgadmin2@example.com")
    resp = client.get("/org/admin")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No members." in body
    assert 'class="empty-state"' in body


def test_org_admin_no_domains_empty_state_keeps_add_one_cta(client, db):
    _make_org_admin()
    db.session.commit()

    login(client, "orgadmin2@example.com")
    resp = client.get("/org/admin")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No domains added yet." in body
    assert "Add one" in body
    assert 'href="/org/verify-domain"' in body
    assert 'class="empty-state"' in body


def test_org_admin_no_scans_empty_state_uses_shared_macro(client, db):
    _make_org_admin()
    db.session.commit()

    login(client, "orgadmin2@example.com")
    resp = client.get("/org/admin")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No scans recorded for this org yet." in body
    assert 'class="empty-state"' in body


def test_org_admin_no_activity_empty_state_uses_shared_macro(client, db):
    _make_org_admin()
    db.session.commit()

    login(client, "orgadmin2@example.com")
    resp = client.get("/org/admin")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No organization activity recorded yet." in body
    assert 'class="empty-state"' in body


def test_org_verify_domain_no_domains_empty_state_uses_shared_macro(client, db):
    _make_org_admin()
    db.session.commit()

    login(client, "orgadmin2@example.com")
    resp = client.get("/org/verify-domain")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No domains added yet." in body
    assert 'class="empty-state"' in body


def test_org_verify_domain_empty_state_not_wrapped_in_warn_box(client, db):
    """Regression lock closing the CLAUDE.md-documented '.warn-box as
    empty-state' exception - the converted block must be a plain
    _empty_state.html call, not still living inside .warn-box."""
    _make_org_admin()
    db.session.commit()

    login(client, "orgadmin2@example.com")
    resp = client.get("/org/verify-domain")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No domains added yet." in body
    # base.html's/other pages' CSS always defines the .warn-box rule
    # (loaded on every page regardless), so the regression lock checks for
    # the rendered *element* class attribute, not the CSS selector text.
    assert 'class="warn-box"' not in body


def test_billing_no_pending_invoices_uses_shared_macro(client, db):
    org = make_org()
    make_user("billingempty@example.com", org=org)
    db.session.commit()

    login(client, "billingempty@example.com")
    resp = client.get("/account/billing")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No pending invoices." in body
    assert 'class="empty-state"' in body


def test_api_tokens_no_tokens_empty_state_keeps_existing_cta(client, db):
    org = make_org()
    make_user("notokens@example.com", org=org)
    db.session.commit()

    login(client, "notokens@example.com")
    resp = client.get("/tokens")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "No API tokens yet" in body
    assert "Generate a token to authenticate CLI and API requests as yourself." in body
    assert 'href="#create-token-form"' in body
    assert "Generate your first token" in body
    assert 'class="empty-state"' in body
