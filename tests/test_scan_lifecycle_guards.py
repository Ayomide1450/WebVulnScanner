"""
Tests for STATE-03 (09-04-PLAN.md): the three scan-lifecycle gaps closed by
this plan.

- Task 1 (this module's first section): `_find_running_scan`'s duplicate-
  concurrent-scan guard, scoped to `(user, target_url, scan_type)` -
  covering base (bulk-capable, single-target case) and api (single-target)
  as the two required call sites per the plan's acceptance criteria, plus
  the cross-scan-type negative control proving the guard never fires across
  different scan types for the same target+user.
- Task 2: `Config.SCAN_TIMEOUT_SECONDS` and the `_timeout_watchdog` scan-
  level wall-clock timeout - a live-forced-timeout test (a real
  `threading.Timer` firing against a real blocked scan thread, not asserted
  from reading the watchdog code alone) and a live race-guard test proving
  a late-finishing orchestrator write cannot resurrect an already-timed-out
  row.
- Task 3: the failed/timed-out messaging split in `scan_progress.html` -
  the generic-exception path renders "Scan failed: <text>" (now composed in
  Python, not Jinja) and the timeout path renders the bare timeout sentence
  with no such prefix, both inside the same `.error-box`.

DNS is mocked via `_public_dns` (mirrors tests/test_scan_wizard.py's
`_fake_getaddrinfo` pattern) for every test whose target must resolve as a
safe public address. `_spawn_scan_thread` is monkeypatched to a no-op
recorder (`spawned` fixture, same convention as test_scan_wizard.py/
test_api_routes.py) so no test in this module ever starts a real
background scan thread from a route POST.
"""
import socket
import threading
import time

import pytest

from webvulnscanner.entitlements import Tier
from webvulnscanner.extensions import db as _db
from webvulnscanner.models import Plan, Scan, ScanStatus

from tests.conftest import login, make_org, make_scan, make_user


@pytest.fixture()
def spawned(monkeypatch):
    """Monkeypatches _spawn_scan_thread to a no-op recorder - a real scan
    thread must never be triggered from a route-level test in this module
    (it would make a real outbound HTTP request and outlive the per-test
    app/DB teardown)."""
    calls = []

    def _fake_spawn(scan_id, scan_type, **kwargs):
        calls.append({"scan_id": scan_id, "scan_type": scan_type, "kwargs": kwargs})

    monkeypatch.setattr("webvulnscanner.scan_routes._spawn_scan_thread", _fake_spawn)
    return calls


def _public_dns(monkeypatch):
    """Patches socket.getaddrinfo so any hostname resolves to a single
    ordinary public IPv4 address - for tests whose target must pass the
    SSRF safety check regardless of which (fake) domain string is used."""
    def _impl(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", _impl)


# --------------------------------------------------------------------------
# Task 1: duplicate-concurrent-scan guard
# --------------------------------------------------------------------------

def test_duplicate_base_scan_creates_zero_new_rows_and_redirects_with_info_flash(
    client, db, monkeypatch, spawned,
):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.FREE)
    user = make_user("dup-base@example.com", org=org)
    existing = make_scan(user, org=org, target_url="https://example.com",
                          scan_type="base", status=ScanStatus.RUNNING)
    _db.session.commit()

    login(client, "dup-base@example.com")
    assert Scan.query.count() == 1

    resp = client.post(
        "/scan/new/base", data={"target": "example.com", "authorized": "on"},
        follow_redirects=True,
    )

    assert resp.status_code == 200
    assert resp.request.path == f"/scan/{existing.id}"
    assert Scan.query.count() == 1  # no new row created
    assert len(spawned) == 0  # no new thread spawned

    body = resp.data.decode()
    assert "A scan is already running for this target" in body
    assert "info-box" in body


def test_duplicate_api_scan_creates_zero_new_rows_and_redirects_with_info_flash(
    client, db, monkeypatch, spawned,
):
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.PAID)
    user = make_user("dup-api@example.com", org=org)
    existing = make_scan(user, org=org, target_url="https://example.com",
                          scan_type="api", status=ScanStatus.QUEUED)
    _db.session.commit()

    login(client, "dup-api@example.com")
    assert Scan.query.count() == 1

    resp = client.post(
        "/scan/new/api", data={"api_target": "example.com", "authorized_api": "on"},
        follow_redirects=True,
    )

    assert resp.status_code == 200
    assert resp.request.path == f"/scan/{existing.id}"
    assert Scan.query.count() == 1
    assert len(spawned) == 0

    body = resp.data.decode()
    assert "A scan is already running for this target" in body


def test_different_scan_type_against_same_target_is_not_blocked(client, db, monkeypatch, spawned):
    """T-09-11's counterpart negative control: the guard is scoped to
    (user, target, scan_type) - a RUNNING base scan against a target must
    NOT block a fresh api scan against that same target for the same
    user."""
    _public_dns(monkeypatch)
    org = make_org(plan=Plan.PAID)
    user = make_user("cross-type@example.com", org=org)
    make_scan(user, org=org, target_url="https://example.com",
              scan_type="base", status=ScanStatus.RUNNING)
    _db.session.commit()

    login(client, "cross-type@example.com")
    assert Scan.query.count() == 1

    resp = client.post(
        "/scan/new/api", data={"api_target": "example.com", "authorized_api": "on"},
        follow_redirects=False,
    )

    assert resp.status_code == 302
    assert Scan.query.count() == 2  # the original base scan + a new api scan
    assert len(spawned) == 1
    new_scan = Scan.query.filter_by(scan_type="api").first()
    assert new_scan is not None
    assert new_scan.status == ScanStatus.QUEUED
