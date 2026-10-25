"""
PERF-01's audit tool: proves `/dashboard` and `/org/admin` issue the SAME
number of SQL queries whether the signed-in user/org has 3 rows or 15 rows
of the data those pages render - a data-size-independent count is what
rules out a per-row N+1 query, not merely asserting some fixed small count
that could coincidentally hold at one data size.

`count_queries()` (this module's own reusable helper, not a new dependency
- `sqlalchemy` is already imported everywhere in this codebase) wraps a
block of code and counts every SQL statement executed against `db.engine`
during it, via a `sqlalchemy.event.listen(engine, "before_cursor_execute",
...)` callback. The listener is registered/removed in a try/finally so it
never leaks into a later test even if the wrapped code raises.

09-03-PLAN.md's Task 1 is an audit-and-prove task, not an assume-and-fix
one: `glassbox/scan_routes.py`'s `dashboard()` query only ever touches
plain `Scan` columns per row (no relationship traversal), and
`glassbox/org_routes.py`'s `admin()` scans/audit_events queries are
already eager-loaded (`joinedload(Scan.user)`, `joinedload(Scan.report)`,
`joinedload(OrgAuditEvent.actor)`) while its members loop reads only plain
`User` columns. Both tests below pass against the CURRENT code with zero
production changes - this file exists to prove that executably, the same
"grep found nothing, here's the proof" rigor 09-CONTEXT.md's D-06
duplicate-scan finding already established for this codebase. No fix was
needed for either route; if a future change to `dashboard()` or `admin()`
ever introduces a per-row query, these two tests catch it by failing.

**A real finding surfaced while writing this test, worth documenting**: an
UNNORMALIZED first pass at this test (measuring the "3 rows" phase right
after `login()`'s own follow-redirect GET had already warmed the SQLAlchemy
session's identity map, then measuring "15 rows" right after a fresh
`db.session.commit()` had expired every cached object) reported 1 query at
3 scans vs 3 at 15, and 6 vs 7 for org-admin - which LOOKS like an N+1 but
is a test-methodology artifact, not a production bug: Flask-SQLAlchemy's
scoped session's identity map, not row count, was what differed between the
two measurements (a cache-warm request skips a lazy-relationship SELECT
whose result is already loaded; a cache-cold request right after a commit
does not). Both routes below are measured from an explicitly *cold* state
each time (`db.session.expire_all()` right before every `count_queries()`
block) so the comparison is apples-to-apples on cache state, isolating row
count as the only variable - confirmed by hand that both routes report a
CONSTANT query count (3 for dashboard, 7 for org-admin) across 3 vs 15 rows
once cache warmth stops confounding the measurement.
"""
from contextlib import contextmanager

from sqlalchemy import event

from tests.conftest import login, make_org, make_scan, make_user
from glassbox.extensions import db
from glassbox.models import OrgAuditEvent, Role, ScanStatus


@contextmanager
def count_queries():
    """Counts every SQL statement executed against `db.engine` for the
    duration of the `with` block.

        with count_queries() as counter:
            client.get("/dashboard")
        assert counter.count == N

    Registers a `before_cursor_execute` listener on `db.engine` and removes
    it in `finally`, so a test using this can never leak a listener into a
    later, unrelated test - even if the code inside the `with` block raises.
    """
    class _Counter:
        count = 0

    counter = _Counter()

    def _before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        counter.count += 1

    event.listen(db.engine, "before_cursor_execute", _before_cursor_execute)
    try:
        yield counter
    finally:
        event.remove(db.engine, "before_cursor_execute", _before_cursor_execute)


def test_dashboard_query_count_independent_of_scan_count(client, db):
    """3 scans vs 15 scans for the same user must issue the identical
    number of queries when requesting GET /dashboard - proves dashboard()
    has no per-row N+1 (e.g. a relationship accessed inside the scans loop)."""
    org = make_org()
    user = make_user("dash-perf@example.com", org=org)
    for i in range(3):
        s = make_scan(user, org=org, target_url=f"https://target{i}.example.com",
                       status=ScanStatus.COMPLETED)
        s.risk_score = 70 + i
    db.session.commit()

    login(client, "dash-perf@example.com")

    # Force a cold SQLAlchemy identity map before EACH measurement (see
    # module docstring) - without this, the "3 scans" measurement would be
    # cache-warm (from login()'s own follow-redirect GET) while the "15
    # scans" measurement would be cache-cold (right after the commit
    # below), confounding row count with cache state.
    db.session.expire_all()
    with count_queries() as counter_small:
        resp = client.get("/dashboard")
        assert resp.status_code == 200
    count_small = counter_small.count

    for i in range(12):
        s = make_scan(user, org=org, target_url=f"https://target{i + 3}.example.com",
                       status=ScanStatus.COMPLETED)
        s.risk_score = 50 + i
    db.session.commit()

    db.session.expire_all()
    with count_queries() as counter_large:
        resp = client.get("/dashboard")
        assert resp.status_code == 200
    count_large = counter_large.count

    assert count_small == count_large, (
        f"dashboard() issued {count_small} queries at 3 scans but {count_large} "
        "queries at 15 scans - this indicates a per-row N+1 query"
    )


def test_org_admin_query_count_independent_of_row_count(client, db):
    """3 members/3 org-scoped scans/3 audit events vs 15 of each for the
    same org must issue the identical number of queries when requesting
    GET /org/admin - proves admin() has no per-row N+1 across any of its
    three collections (members, scans, audit_events)."""
    org = make_org()
    admin_user = make_user("orgadmin-perf@example.com", org=org, role=Role.ORG_ADMIN)
    for i in range(3):
        make_user(f"member{i}@example.com", org=org)
        make_scan(admin_user, org=org, target_url=f"https://t{i}.example.com",
                   status=ScanStatus.COMPLETED)
        db.session.add(OrgAuditEvent(
            org_id=org.id, actor_id=admin_user.id, event_type="member_invited", detail=f"m{i}",
        ))
    db.session.commit()

    login(client, "orgadmin-perf@example.com")

    # Same cold-state normalization as the dashboard test above, and for
    # the same reason (see module docstring).
    db.session.expire_all()
    with count_queries() as counter_small:
        resp = client.get("/org/admin")
        assert resp.status_code == 200
    count_small = counter_small.count

    for i in range(12):
        make_user(f"member{i + 3}@example.com", org=org)
        make_scan(admin_user, org=org, target_url=f"https://t{i + 3}.example.com",
                   status=ScanStatus.COMPLETED)
        db.session.add(OrgAuditEvent(
            org_id=org.id, actor_id=admin_user.id, event_type="member_invited", detail=f"m{i + 3}",
        ))
    db.session.commit()

    db.session.expire_all()
    with count_queries() as counter_large:
        resp = client.get("/org/admin")
        assert resp.status_code == 200
    count_large = counter_large.count

    assert count_small == count_large, (
        f"org.admin() issued {count_small} queries at 3 rows/collection but "
        f"{count_large} queries at 15 - this indicates a per-row N+1 query"
    )
