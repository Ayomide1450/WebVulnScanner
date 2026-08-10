"""
Tests for webvulnscanner/scheduler.py - the in-process daemon-thread
scheduler for recurring Asset scans (Phase 1, ASSET-04/07/08).

`_spawn_scan_thread` is monkeypatched to a no-op recorder in every test
here so no real background thread or network call ever happens from the
suite - matching the existing project convention documented in
tests/test_ssrf_guard.py's module docstring ("a real scan thread must
never be triggered from a test").
"""
import socket
from datetime import datetime, timedelta, timezone

import pytest

from webvulnscanner.models import Asset, Plan, Scan, ScanStatus

from tests.conftest import make_asset, make_org, make_user


@pytest.fixture()
def spawned(monkeypatch):
    """Records every _spawn_scan_thread call scheduler.py makes, as a
    no-op - never spawns a real thread."""
    calls = []

    def _fake_spawn(scan_id, scan_type, **kwargs):
        calls.append({"scan_id": scan_id, "scan_type": scan_type, "kwargs": kwargs})

    monkeypatch.setattr("webvulnscanner.scheduler._spawn_scan_thread", _fake_spawn)
    return calls


def _past(minutes=5):
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def _as_aware(dt):
    """SQLite (unlike Postgres) doesn't preserve tzinfo on round-trip
    through a DateTime(timezone=True) column - a value read back after a
    commit comes back naive even though it was written tz-aware. Test-only
    normalization so assertions can safely compare against a fresh
    tz-aware datetime.now(timezone.utc)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# --------------------------------------------------------------------------
# ASSET-04: _tick fires a due Asset, creating exactly one Scan row linked
# via asset_id.
# --------------------------------------------------------------------------

def test_tick_fires_due_asset_and_creates_one_scan(app, db, spawned):
    org = make_org(plan=Plan.FREE)
    user = make_user("owner@example.com", org=org)
    a = make_asset(org, user, schedule_scan_type="base", next_run_at=_past())
    db.session.commit()

    from webvulnscanner.scheduler import _tick

    _tick(app)

    scans = Scan.query.filter_by(asset_id=a.id).all()
    assert len(scans) == 1
    assert scans[0].status == ScanStatus.QUEUED
    assert scans[0].asset_id == a.id
    assert len(spawned) == 1
    assert spawned[0]["scan_type"] == "base"


def test_tick_advances_next_run_at_by_cadence(app, db, spawned):
    org = make_org(plan=Plan.FREE)
    user = make_user("owner2@example.com", org=org)
    before = _past()
    a = make_asset(org, user, cadence="daily", next_run_at=before)
    db.session.commit()

    from webvulnscanner.scheduler import _tick

    _tick(app)

    refreshed = Asset.query.get(a.id)
    assert _as_aware(refreshed.next_run_at) > datetime.now(timezone.utc)


def test_tick_does_not_fire_a_not_yet_due_asset(app, db, spawned):
    org = make_org(plan=Plan.FREE)
    user = make_user("owner3@example.com", org=org)
    make_asset(org, user, next_run_at=datetime.now(timezone.utc) + timedelta(days=1))
    db.session.commit()

    from webvulnscanner.scheduler import _tick

    _tick(app)

    assert Scan.query.count() == 0
    assert len(spawned) == 0


def test_tick_does_not_fire_a_paused_asset(app, db, spawned):
    org = make_org(plan=Plan.FREE)
    user = make_user("owner4@example.com", org=org)
    make_asset(org, user, next_run_at=_past(), is_paused=True)
    db.session.commit()

    from webvulnscanner.scheduler import _tick

    _tick(app)

    assert Scan.query.count() == 0
    assert len(spawned) == 0


def test_tick_does_not_fire_a_soft_deleted_asset(app, db, spawned):
    org = make_org(plan=Plan.FREE)
    user = make_user("owner5@example.com", org=org)
    make_asset(org, user, next_run_at=_past(), deleted_at=datetime.now(timezone.utc))
    db.session.commit()

    from webvulnscanner.scheduler import _tick

    _tick(app)

    assert Scan.query.count() == 0
    assert len(spawned) == 0


# --------------------------------------------------------------------------
# ASSET-08: claim-guard race - two concurrent claim attempts on the same
# due Asset, only one wins.
# --------------------------------------------------------------------------

def test_try_claim_second_call_loses_the_race(app, db):
    org = make_org(plan=Plan.FREE)
    user = make_user("racer@example.com", org=org)
    a = make_asset(org, user, next_run_at=_past())
    db.session.commit()

    from webvulnscanner.scheduler import CADENCE_INTERVALS, _try_claim

    now = datetime.now(timezone.utc)
    next_run_at = now + CADENCE_INTERVALS[a.cadence]

    first = _try_claim(a.id, now, next_run_at)
    second = _try_claim(a.id, now, next_run_at)

    assert first is True
    assert second is False


def test_tick_never_double_fires_the_same_asset_in_one_tick(app, db, spawned):
    # A single _tick() call only ever claims each due Asset once (one pass
    # over the candidate list) - this pins that a normal tick, not just
    # _try_claim in isolation, produces exactly one Scan per due Asset.
    org = make_org(plan=Plan.FREE)
    user = make_user("racer2@example.com", org=org)
    a = make_asset(org, user, next_run_at=_past())
    db.session.commit()

    from webvulnscanner.scheduler import _tick

    _tick(app)
    _tick(app)  # second tick immediately after - Asset is no longer due

    assert Scan.query.filter_by(asset_id=a.id).count() == 1


# --------------------------------------------------------------------------
# ASSET-07: tier-gating for media/api schedule types - Free-tier never
# runs; upgrade is respected at the Asset's next fire.
# --------------------------------------------------------------------------

def test_free_tier_media_schedule_fails_without_spawning(app, db, spawned):
    org = make_org(plan=Plan.FREE)
    user = make_user("free-media@example.com", org=org)
    a = make_asset(org, user, schedule_scan_type="media", next_run_at=_past())
    db.session.commit()

    from webvulnscanner.scheduler import _tick

    _tick(app)

    scans = Scan.query.filter_by(asset_id=a.id).all()
    assert len(scans) == 1
    assert scans[0].status == ScanStatus.FAILED
    assert "higher plan" in scans[0].error_message
    assert len(spawned) == 0


def test_free_tier_api_schedule_fails_without_spawning(app, db, spawned):
    org = make_org(plan=Plan.FREE)
    user = make_user("free-api@example.com", org=org)
    a = make_asset(org, user, schedule_scan_type="api", next_run_at=_past())
    db.session.commit()

    from webvulnscanner.scheduler import _tick

    _tick(app)

    scans = Scan.query.filter_by(asset_id=a.id).all()
    assert len(scans) == 1
    assert scans[0].status == ScanStatus.FAILED
    assert len(spawned) == 0


def test_tier_upgrade_is_respected_at_next_fire_not_retroactively(app, db, spawned):
    org = make_org(plan=Plan.FREE)
    user = make_user("upgrade@example.com", org=org)
    a = make_asset(org, user, schedule_scan_type="media", next_run_at=_past())
    db.session.commit()

    from webvulnscanner.scheduler import _tick

    _tick(app)  # first fire: still Free tier, fails

    first_scans = Scan.query.filter_by(asset_id=a.id).all()
    assert len(first_scans) == 1
    assert first_scans[0].status == ScanStatus.FAILED
    assert len(spawned) == 0

    # Upgrade the org, then force the Asset due again (simulating its next
    # cadence tick) - the same Asset should now fire for real. Also clear
    # locked_until: in production the claim lease (5 minutes) naturally
    # expires long before the Asset's next real cadence tick; this test
    # compresses that elapsed time, so the lease must be cleared explicitly
    # to simulate it having expired.
    org.plan = Plan.PAID
    db.session.commit()
    a.next_run_at = _past()
    a.locked_until = None
    db.session.commit()

    _tick(app)

    second_scans = (
        Scan.query.filter_by(asset_id=a.id).order_by(Scan.id.desc()).all()
    )
    assert second_scans[0].status == ScanStatus.QUEUED
    assert len(spawned) == 1


# --------------------------------------------------------------------------
# Fire-time SSRF re-check (RESEARCH.md Pitfall 5) - a scheduled fire
# re-checks SSRF safety, not just at registration.
# --------------------------------------------------------------------------

def test_fire_time_ssrf_failure_produces_failed_scan_without_spawning(app, db, spawned, monkeypatch):
    org = make_org(plan=Plan.PAID)
    user = make_user("ssrf@example.com", org=org)
    a = make_asset(org, user, target_url="https://attacker-controlled.example",
                    schedule_scan_type="base", next_run_at=_past())
    db.session.commit()

    def _fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    from webvulnscanner.scheduler import _tick

    _tick(app)

    scans = Scan.query.filter_by(asset_id=a.id).all()
    assert len(scans) == 1
    assert scans[0].status == ScanStatus.FAILED
    assert "private" in scans[0].error_message.lower() or "internal" in scans[0].error_message.lower()
    assert len(spawned) == 0


def test_fire_time_ssrf_failure_does_not_pause_or_change_schedule(app, db, spawned, monkeypatch):
    # D-04: a failed scheduled scan never pauses or otherwise changes the
    # Asset's schedule state beyond what the claim already advanced.
    org = make_org(plan=Plan.PAID)
    user = make_user("ssrf2@example.com", org=org)
    a = make_asset(org, user, target_url="https://attacker-controlled2.example",
                    schedule_scan_type="base", next_run_at=_past())
    db.session.commit()

    def _fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    from webvulnscanner.scheduler import _tick

    _tick(app)

    refreshed = Asset.query.get(a.id)
    assert refreshed.is_paused is False
    assert _as_aware(refreshed.next_run_at) > datetime.now(timezone.utc)
