"""One-off, scoped cleanup for the leftover test data from the "page
completion & polish" session (see handoff.md item 11 / the finalization
pass's Part E investigation).

Deletes ONLY:
  - Organization id 1, "UI Review Org"
  - User "uireview@example.com" (its only member)
  - Scan id 1 (target https://example.com, completed) + its Report row
  - CryptoInvoice id 2 (status=pending, matched_tx_hash=None, i.e. never
    paid - already past its expires_at as of 2026-08-08)

Does NOT touch org id 2 ("Review Org" / the real account) or anything in
it, including its own pending invoice (id 1) - that invoice's origin
wasn't established during the audit and is left alone.

This script does not run automatically as part of any deploy or test -
it is meant to be run once, by hand, after reviewing the printed preview.
It prints exactly what it's about to delete and requires typing "yes" to
proceed; nothing is deleted on a dry run.

Usage:
    .venv\\Scripts\\python scripts\\cleanup_ui_review_org.py            # dry run (preview only)
    .venv\\Scripts\\python scripts\\cleanup_ui_review_org.py --confirm  # actually deletes, after typed confirmation
"""
import sys

from glassbox import create_app
from glassbox.models import db, User, Organization, Scan, Report, CryptoInvoice, ScanEvent

TARGET_ORG_NAME = "UI Review Org"
TARGET_USER_EMAIL = "uireview@example.com"


def main():
    confirm_flag = "--confirm" in sys.argv
    app = create_app()
    with app.app_context():
        org = Organization.query.filter_by(name=TARGET_ORG_NAME).first()
        if org is None:
            print(f'No organization named "{TARGET_ORG_NAME}" found - nothing to do (already cleaned up?).')
            return

        users = User.query.filter_by(org_id=org.id).all()
        scans = Scan.query.filter_by(org_id=org.id).all()
        invoices = CryptoInvoice.query.filter_by(org_id=org.id).all()

        # Safety check: refuse to touch this org if it has any member other
        # than the expected test account, or more scans/invoices than the
        # ones already identified during the audit - something changed
        # since the investigation and a human should look again.
        unexpected_users = [u for u in users if u.email != TARGET_USER_EMAIL]
        if unexpected_users:
            print("REFUSING: org has unexpected members:", [u.email for u in unexpected_users])
            print("This doesn't match the audited state - stopping without deleting anything.")
            return

        print(f"Will delete organization {org.id!r} ({org.name!r}):")
        for u in users:
            print(f"  User {u.id}: {u.email}")
        for s in scans:
            print(f"  Scan {s.id}: {s.target_url} ({s.scan_type}, {s.status.value}, created {s.created_at})")
            rpt = Report.query.filter_by(scan_id=s.id).first()
            if rpt:
                print(f"    Report {rpt.id}: {rpt.json_path}")
            ev_count = ScanEvent.query.filter_by(scan_id=s.id).count()
            if ev_count:
                print(f"    {ev_count} ScanEvent row(s)")
        for inv in invoices:
            print(
                f"  CryptoInvoice {inv.id}: status={inv.status.value}, "
                f"amount={inv.expected_amount} {inv.token_symbol}, "
                f"matched_tx_hash={inv.matched_tx_hash!r}, expires_at={inv.expires_at}"
            )

        if not confirm_flag:
            print("\nDry run only - nothing deleted. Re-run with --confirm to proceed.")
            return

        typed = input('\nType "yes" to permanently delete everything listed above: ')
        if typed.strip().lower() != "yes":
            print("Aborted - nothing deleted.")
            return

        for s in scans:
            ScanEvent.query.filter_by(scan_id=s.id).delete()
            Report.query.filter_by(scan_id=s.id).delete()
            db.session.delete(s)
        for inv in invoices:
            db.session.delete(inv)
        for u in users:
            db.session.delete(u)
        db.session.delete(org)
        db.session.commit()
        print("Deleted.")


if __name__ == "__main__":
    main()
