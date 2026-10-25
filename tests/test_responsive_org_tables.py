"""Rendered-HTML assertions for RESP-03/A11Y-01's org-surface half:
org_admin.html's four record tables (Members, Pending Invitations, Verified
domains, Scan History) and org_verify_domain.html's Domains table.

This module owns the markup-presence half of D-01's dual-markup table/card
conversion for these five tables - what the cards actually LOOK like at
320px (wrapping, overlap, tap-target comfort) is settled at this plan's
`checkpoint:human-verify` task instead, same convention
`tests/test_responsive_markup.py` (plan 07-01) already established.

These five tables carry every destructive, CSRF-protected POST action in
the org surface: resend invitation, revoke invitation, request domain
deletion, verify domain. The CSRF-preservation assertions below exist
because a careless table-row-to-card rework is exactly how a protected POST
silently becomes a bare link - each destructive action path is asserted to
appear exactly twice in the rendered body (once per markup block), with a
hidden csrf_token input inside each occurrence's own form.

Use `-k org_admin` to select org_admin.html's tests, `-k verify_domain` to
select org_verify_domain.html's. `.com`/`.org` fake domains are used in
fixture emails throughout, never `.test` (CLAUDE.md's Gotcha:
email_validator statically rejects reserved TLDs even with deliverability
checking off).
"""
import re
from datetime import UTC, datetime

from glassbox.extensions import db as _db
from glassbox.models import (
    DomainVerification,
    Invitation,
    InvitationStatus,
    Role,
    ScanStatus,
    VerifyMethod,
)
from tests.conftest import login, make_org, make_scan, make_user


def _ids_in(body):
    """Reusable id-uniqueness helper: parses every id="..." value out of a
    rendered HTML body. Both the desktop-table block and the mobile-card
    block are always in the DOM simultaneously (the @media rule only
    toggles `display`), so a duplicate id here is invalid HTML and would
    silently mis-bind a future `<label for>` to whichever control the
    parser saw first - plans 07-03/07-05 should import this rather than
    re-implementing it."""
    return re.findall(r'id="([^"]*)"', body)


def _make_domain(org, domain="example.com", verified=True, method=VerifyMethod.DNS_TXT):
    dv = DomainVerification(org_id=org.id, domain=domain, method=method, token="tok")
    if verified:
        dv.verified_at = datetime.now(UTC)
    _db.session.add(dv)
    _db.session.flush()
    return dv


def _make_invitation(org, email="invitee@example.com", role="member", inviter=None):
    inv = Invitation(
        org_id=org.id, email=email, role=role, status=InvitationStatus.PENDING,
        invited_by_id=inviter.id if inviter else None,
    )
    _db.session.add(inv)
    _db.session.flush()
    return inv


# --------------------------------------------------------------------------
# org_admin.html - dual-markup presence, one populated org with all four
# tables non-empty
# --------------------------------------------------------------------------

def _seed_full_org_admin(db):
    org = make_org()
    admin = make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    make_user("member@example.org", org=org, role=Role.MEMBER)
    _make_invitation(org, email="invitee@example.org", inviter=admin)
    dv = _make_domain(org, domain="example.com", verified=False)
    make_scan(admin, org=org, target_url="https://example.com", status=ScanStatus.COMPLETED)
    db.session.commit()
    return org, admin, dv


def test_org_admin_renders_four_dual_markup_tables(client, db):
    _seed_full_org_admin(db)
    login(client, "admin@example.com")
    resp = client.get("/org/admin")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert body.count('class="table-scroll desktop-table"') == 4
    assert body.count('<ul class="mobile-record-cards">') == 4
    assert body.count("<thead>") == 4
    assert body.count("<tbody>") == 4


def test_org_admin_card_counts_match_row_counts(client, db):
    org = make_org()
    admin = make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    make_user("m1@example.org", org=org, role=Role.MEMBER)
    make_user("m2@example.org", org=org, role=Role.MEMBER)
    db.session.commit()

    login(client, "admin@example.com")
    resp = client.get("/org/admin")
    body = resp.get_data(as_text=True)

    # Members table: admin + m1 + m2 = 3 rows/cards.
    assert body.count('class="card record-card"') >= 3


def test_org_admin_revoke_invitation_csrf_preserved_in_both_blocks(client, db):
    org, admin, _dv = _seed_full_org_admin(db)
    inv = Invitation.query.filter_by(org_id=org.id).first()

    login(client, "admin@example.com")
    resp = client.get("/org/admin")
    body = resp.get_data(as_text=True)

    revoke_url = f"/org/admin/invite/{inv.id}/revoke"
    resend_url = f"/org/admin/invite/{inv.id}/resend"
    assert body.count(revoke_url) == 2
    assert body.count(resend_url) == 2

    # Each form containing the revoke action also carries a hidden csrf_token.
    for form in re.findall(r"<form[^>]*>.*?</form>", body, flags=re.DOTALL):
        if revoke_url in form or resend_url in form:
            assert 'name="csrf_token"' in form


def test_org_admin_request_domain_deletion_csrf_and_aria_label(client, db):
    org, admin, dv = _seed_full_org_admin(db)

    login(client, "admin@example.com")
    resp = client.get("/org/admin")
    body = resp.get_data(as_text=True)

    deletion_url = f"/org/admin/domain/{dv.id}/request-deletion"
    assert body.count(deletion_url) == 2

    for form in re.findall(r"<form[^>]*>.*?</form>", body, flags=re.DOTALL):
        if deletion_url in form:
            assert 'name="csrf_token"' in form
            assert "aria-label=" in form
            assert 'name="reason"' in form

    assert body.count("aria-label=") >= 2
    # Every reason input specifically carries an aria-label.
    for reason_input in re.findall(r'<input[^>]*name="reason"[^>]*>', body):
        assert "aria-label=" in reason_input


def test_org_admin_no_duplicate_ids(client, db):
    _seed_full_org_admin(db)
    login(client, "admin@example.com")
    resp = client.get("/org/admin")
    body = resp.get_data(as_text=True)

    ids = _ids_in(body)
    assert len(ids) == len(set(ids)), f"Duplicate id(s) found: {[i for i in ids if ids.count(i) > 1]}"


def test_org_admin_zero_records_shows_no_cards_and_single_empty_messages(client, db):
    org = make_org()
    make_user("solo@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()

    login(client, "solo@example.com")
    resp = client.get("/org/admin")
    body = resp.get_data(as_text=True)

    # Members table is non-empty (the admin themselves is a member), but
    # Pending Invitations / Verified domains / Scan History are empty.
    assert body.count("No pending invitations.") == 1
    assert body.count("No domains added yet.") == 1
    assert body.count("No scans recorded for this org yet.") == 1


def test_org_admin_card_present(client, db):
    _seed_full_org_admin(db)
    login(client, "admin@example.com")
    resp = client.get("/org/admin")
    body = resp.get_data(as_text=True)

    assert 'class="card"' in body


# --------------------------------------------------------------------------
# org_verify_domain.html - dual-markup presence + progressive disclosure
# --------------------------------------------------------------------------

def test_verify_domain_renders_dual_markup_with_details_disclosure(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    _make_domain(org, domain="example.com", verified=False)
    db.session.commit()

    login(client, "admin@example.com")
    resp = client.get("/org/verify-domain")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert body.count('class="table-scroll desktop-table"') == 1
    assert body.count('<ul class="mobile-record-cards">') == 1
    assert body.count("<thead>") == 1
    assert body.count("<tbody>") == 1
    assert '<details class="record-card-details">' in body
    assert "<summary>How to prove ownership</summary>" in body


def test_verify_domain_form_csrf_preserved_in_both_blocks(client, db):
    import pathlib

    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    dv = _make_domain(org, domain="example.com", verified=False)
    db.session.commit()

    login(client, "admin@example.com")
    resp = client.get("/org/verify-domain")
    body = resp.get_data(as_text=True)

    assert body.count(f'name="domain_id" value="{dv.id}"') == 2
    assert body.count('name="action" value="verify"') == 2

    # `add_form.csrf_token` (a WTForms field, unlike org_admin.html's raw
    # `{{ csrf_token() }}` input) only renders a value when WTF_CSRF_ENABLED
    # is true - the test suite runs with it disabled (conftest.TestConfig),
    # so this asserts CSRF-field presence against the template SOURCE
    # (where both markup blocks must carry the field) rather than the
    # rendered body.
    template_source = pathlib.Path("templates/org_verify_domain.html").read_text(encoding="utf-8")
    assert template_source.count("{{ add_form.csrf_token }}") == 2


def test_verify_domain_no_duplicate_ids(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    _make_domain(org, domain="example.com", verified=False)
    _make_domain(org, domain="example.org", verified=True, method=VerifyMethod.WELL_KNOWN)
    db.session.commit()

    login(client, "admin@example.com")
    resp = client.get("/org/verify-domain")
    body = resp.get_data(as_text=True)

    ids = _ids_in(body)
    assert len(ids) == len(set(ids)), f"Duplicate id(s) found: {[i for i in ids if ids.count(i) > 1]}"


def test_verify_domain_uses_wrap_not_auth_wrap(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()

    login(client, "admin@example.com")
    resp = client.get("/org/verify-domain")
    body = resp.get_data(as_text=True)

    assert 'class="wrap"' in body
    assert "auth-wrap" not in body


def test_verify_domain_zero_records_shows_no_cards_and_one_warn_box(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN)
    db.session.commit()

    login(client, "admin@example.com")
    resp = client.get("/org/verify-domain")
    body = resp.get_data(as_text=True)

    # Phase 9 (09-02) migrated this page's empty state from the old
    # standalone .warn-box markup to the shared _empty_state.html partial
    # (closing the CLAUDE.md-documented exception) - assert the new
    # component instead of the retired one.
    assert body.count('class="empty-state"') == 1
    assert 'class="warn-box"' not in body
    # Scoped to the real markup class, not a bare substring - base.html's
    # own embedded <style> block contains the prose/selector substring
    # "record-card" on every page regardless of whether any card renders
    # (07-01-SUMMARY.md's Rule 1 fix documents this exact false positive).
    assert 'class="card record-card"' not in body
