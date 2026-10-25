"""One-off local dev script: elevate a user's org to the full-access
(Org-verified) plan and mark their real, repeatedly-scanned domain as
verified, so every scan type (including Advanced) is unlocked for local
testing.

Mirrors scripts/cleanup_ui_review_org.py's pattern of a scoped, explicit
admin script rather than a route or CLI command that could be discovered/
abused - there is no UI path to this (org.plan is normally only set via a
real crypto-invoice payment in billing.py's verify_invoice()).

Usage (from repo root, with .venv active):
    .venv\\Scripts\\python.exe scripts\\grant_full_access.py <email> [--domain example.com]

Run with no --domain to only elevate the plan (Paid + Org-verified checks
unlock immediately); pass --domain to also mark that hostname as verified
for this org so Advanced's per-target domain_is_org_verified() check passes
too - Advanced's intrusive checks need BOTH the plan tier AND a verified
domain for the specific target being scanned.
"""
import argparse
import sys

from glassbox import create_app
from glassbox.extensions import db
from glassbox.models import DomainVerification, Plan, User, VerifyMethod, _utcnow


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("email")
    parser.add_argument("--domain", default=None, help="hostname to mark verified for this org")
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        user = User.query.filter_by(email=args.email.strip().lower()).first()
        if user is None:
            print(f"No user found with email {args.email!r}", file=sys.stderr)
            sys.exit(1)
        if user.organization is None:
            print(f"User {args.email!r} has no organization - cannot set org plan", file=sys.stderr)
            sys.exit(1)

        org = user.organization
        before = org.plan
        org.plan = Plan.ORG_VERIFIED
        db.session.commit()
        print(f"Organization {org.name!r} (id={org.id}) plan: {before} -> {org.plan}")

        if args.domain:
            hostname = args.domain.strip().lower()
            existing = DomainVerification.query.filter_by(org_id=org.id, domain=hostname).first()
            if existing is not None:
                existing.verified_at = _utcnow()
                print(f"Updated existing DomainVerification row for {hostname!r} -> verified")
            else:
                row = DomainVerification(
                    org_id=org.id,
                    domain=hostname,
                    method=VerifyMethod.DNS_TXT,
                    token="local-dev-grant-full-access",
                    verified_at=_utcnow(),
                )
                db.session.add(row)
                print(f"Added verified DomainVerification row for {hostname!r}")
            db.session.commit()

        print("Done.")


if __name__ == "__main__":
    main()
