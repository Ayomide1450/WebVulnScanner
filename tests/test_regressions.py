"""Phase 27 (CONT-01..04): continuous regression tracking.

Locks, in order: the pure diff (classify_regressions - matching rule,
no-baseline semantics, determinism, alert threshold), its wiring into
_run_scan_in_background's shared tail (tags land IN the stored Report.data;
manual scans and baseline fires stay untagged), the finding.regressed webhook
(same signed-delivery machinery, distinct event header, High/Critical-only),
and the asset detail page's regression timeline rendering. Network is always
stubbed; the diff itself never touches it by construction."""

import hashlib
import hmac as hmac_mod
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import webvulnscanner.scan_routes as scan_routes_mod
import webvulnscanner.webhooks as webhook_engine
from webvulnscanner.entitlements import Tier
from webvulnscanner.extensions import db as _db
from webvulnscanner.models import OutboundWebhook, Report, Scan, ScanStatus, WebhookDelivery
from webvulnscanner.regressions import (
    alertable_new,
    classify_regressions,
    finding_key,
)

from tests.conftest import login, make_asset, make_org, make_scan, make_user


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _report(findings, score=70, grade="C"):
    return {"score": score, "risk_grade": grade, "findings": findings}


def _f(check_name, title, severity="medium", **extra):
    d = {"check_name": check_name, "title": title, "severity": severity}
    d.update(extra)
    return d


def _seed_completed(app, asset, user, org, findings, created_at,
                    scan_type="base", score=70):
    """A COMPLETED Scan + Report row exactly as the background tail would
    leave them (Report.data carries the blob - no disk file involved).
    Must be called INSIDE an app context - pushing a second, nested one
    here would mint a second SQLAlchemy session/connection and deadlock
    the on-disk SQLite file (see conftest's fixture docstring)."""
    s = make_scan(user, org=org, scan_type=scan_type,
                  status=ScanStatus.COMPLETED)
    s.asset_id = asset.id
    s.created_at = created_at
    s.completed_at = created_at
    s.risk_score = score
    _db.session.add(Report(scan_id=s.id, json_path="unused.json",
                           data=_report(findings, score)))
    _db.session.commit()
    return s.id


# --------------------------------------------------------------------------
# CONT-04: the pure diff
# --------------------------------------------------------------------------

def test_classify_new_recurring_resolved():
    prev = _report([_f("xss_sqli", "/search reflected", "high"),
                    _f("open_ports", "3306 exposed")])
    curr = _report([_f("open_ports", "3306 exposed"),
                    _f("sqli_union", "/items union", "critical")])
    tagged, summary = classify_regressions(prev, curr)

    tags = {finding_key(f): f["regression"] for f in tagged}
    assert tags == {
        ("open_ports", "3306 exposed"): "recurring",
        ("sqli_union", "/items union"): "new",
    }
    assert summary["new"] == 1 and summary["recurring"] == 1
    assert summary["resolved"] == [
        {"check_name": "xss_sqli", "title": "/search reflected",
         "severity": "high"},
    ]


def test_matching_ignores_order_and_detail_drift():
    prev = _report([_f("tls", "Weak cipher", "medium", detail="old detail")])
    # Same check+title, different severity/detail, different list position.
    curr = _report([_f("headers", "Unrelated new thing", "low"),
                    _f("tls", "Weak cipher", "high", detail="new detail")])
    tagged, summary = classify_regressions(prev, curr)
    tls_row = [f for f in tagged if f["check_name"] == "tls"][0]
    assert tls_row["regression"] == "recurring"
    assert tls_row["severity"] == "high"  # current severity preserved
    assert summary["recurring"] == 1 and summary["new"] == 1
    assert summary["resolved"] == []


def test_legacy_findings_match_on_category_when_check_name_missing():
    prev = _report([{"category": "TLS", "title": "Weak cipher"}])
    curr = _report([_f("tls", "Weak cipher")])  # modern dict, same issue
    tagged, _summary = classify_regressions(prev, curr)
    assert tagged[0]["regression"] == "recurring"


def test_no_baseline_leaves_findings_untagged_and_summary_none():
    curr = _report([_f("a", "A"), _f("b", "B")])
    for prev_report in (None, {}, {"findings": None}, {"score": 5}):
        tagged, summary = classify_regressions(prev_report, curr)
        assert all("regression" not in f for f in tagged)
        assert len(tagged) == 2
        assert summary is None


def test_previous_with_zero_findings_makes_everything_new():
    prev, curr = _report([]), _report([_f("a", "A", "high")])
    tagged, summary = classify_regressions(prev, curr)
    assert [f["regression"] for f in tagged] == ["new"]
    assert summary["new"] == 1


def test_classify_is_deterministic():
    prev = _report([_f("c", "gone", "low"), _f("d", "also gone", "info")])
    curr = _report([_f("a", "A", "high"), _f("b", "B"), _f("c", "C")])
    first = classify_regressions(prev, curr)
    second = classify_regressions(prev, curr)
    assert first == second
    # resolved snapshots are sorted by (check_name, title), not list order:
    names = [r["check_name"] for r in first[1]["resolved"]]
    assert names == sorted(names)


def test_alertable_new_threshold_high_critical_only():
    tagged = [
        _f("a", "brand new critical", "critical", regression="new"),
        _f("b", "brand new high", "high", regression="new"),
        _f("c", "brand new medium", "medium", regression="new"),
        _f("d", "still here critical", "critical", regression="recurring"),
        _f("e", "plain high, no tag", "high"),
    ]
    alerted = alertable_new(tagged)
    assert {f["title"] for f in alerted} == {"brand new critical",
                                             "brand new high"}


# --------------------------------------------------------------------------
# CONT-01: wiring into the shared background tail
# --------------------------------------------------------------------------

def test_scheduled_fire_tags_regressions_in_stored_report(app, monkeypatch):

    monkeypatch.setattr(scan_routes_mod, "save_report",
                        lambda report, prefix, hostname: "stubbed.json")

    def fake_run_scan(base_url, manual_test_url, tier, org_verified,
                      progress_cb=None):
        return _report([
            _f("open_ports", "3306 exposed"),
            _f("sqli_union", "/items union", "critical"),
        ], score=64)

    monkeypatch.setattr(scan_routes_mod, "run_scan", fake_run_scan)

    with app.app_context():
        org = make_org()
        user = make_user("asset-owner@example.com", org=org)
        asset = make_asset(org, user, target_url="https://example.com")
        now = datetime.now(timezone.utc)
        _seed_completed(app, asset, user, org,
                        [_f("xss_sqli", "/search reflected", "high"),
                         _f("open_ports", "3306 exposed")],
                        created_at=now - timedelta(days=1))
        queued = make_scan(user, org=org, status=ScanStatus.QUEUED)
        queued.asset_id = asset.id
        queued.created_at = now
        _db.session.commit()
        queued_id = queued.id

    scan_routes_mod._run_scan_in_background(
        app, queued_id, "base", base_url="https://example.com",
        manual_test_url=None, tier=Tier.FREE, org_verified=False,
    )

    with app.app_context():
        stored = Scan.query.get(queued_id).report.data
        tags = {(f["check_name"], f["title"]): f.get("regression")
                for f in stored["findings"]}
        assert tags == {
            ("open_ports", "3306 exposed"): "recurring",
            ("sqli_union", "/items union"): "new",
        }
        reg = stored["regression"]
        assert reg["new"] == 1 and reg["recurring"] == 1
        assert reg["resolved"] == [
            {"check_name": "xss_sqli", "title": "/search reflected",
             "severity": "high"},
        ]


def test_manual_wizard_scan_gets_no_regression_keys(app, monkeypatch):
    monkeypatch.setattr(scan_routes_mod, "save_report",
                        lambda report, prefix, hostname: "stubbed.json")
    monkeypatch.setattr(
        scan_routes_mod, "run_scan",
        lambda *a, **k: _report([_f("a", "A", "high")], score=90))

    with app.app_context():
        user = make_user("wizard@example.com")
        queued = make_scan(user, status=ScanStatus.QUEUED)  # no asset_id
        _db.session.commit()
        queued_id = queued.id

    scan_routes_mod._run_scan_in_background(
        app, queued_id, "base", base_url="https://example.com",
        manual_test_url=None, tier=Tier.FREE, org_verified=False,
    )

    with app.app_context():
        stored = Scan.query.get(queued_id).report.data
        assert "regression" not in stored
        assert all("regression" not in f for f in stored["findings"])


def test_baseline_fire_for_new_asset_stays_untagged(app, monkeypatch):
    monkeypatch.setattr(scan_routes_mod, "save_report",
                        lambda report, prefix, hostname: "stubbed.json")
    monkeypatch.setattr(
        scan_routes_mod, "run_scan",
        lambda *a, **k: _report([_f("a", "A", "high")], score=88))

    with app.app_context():
        org = make_org()
        user = make_user("first-fire@example.com", org=org)
        asset = make_asset(org, user)
        queued = make_scan(user, org=org, status=ScanStatus.QUEUED)
        queued.asset_id = asset.id
        _db.session.commit()
        queued_id = queued.id

    scan_routes_mod._run_scan_in_background(
        app, queued_id, "base", base_url="https://example.com",
        manual_test_url=None, tier=Tier.FREE, org_verified=False,
    )

    with app.app_context():
        stored = Scan.query.get(queued_id).report.data
        assert "regression" not in stored
        assert all("regression" not in f for f in stored["findings"])


def test_scan_type_change_does_not_diff_across_types(app, monkeypatch):
    """A media fire must not be diffed against a base predecessor just
    because they share an Asset - different pipelines produce incomparable
    finding sets, so the same-type filter makes this a baseline fire."""
    monkeypatch.setattr(scan_routes_mod, "save_report",
                        lambda report, prefix, hostname: "stubbed.json")
    monkeypatch.setattr(
        scan_routes_mod, "run_media_scan",
        lambda *a, **k: {"hostname": "example.com", **_report(
            [_f("media_check", "exif gps", "low")], score=80)})

    with app.app_context():
        org = make_org()
        user = make_user("mixed-types@example.com", org=org)
        asset = make_asset(org, user)
        now = datetime.now(timezone.utc)
        _seed_completed(app, asset, user, org, [_f("base_check", "B")],
                        created_at=now, scan_type="base")
        queued = make_scan(user, org=org, scan_type="media",
                           status=ScanStatus.QUEUED)
        queued.asset_id = asset.id
        queued.created_at = now
        _db.session.commit()
        queued_id = queued.id

    scan_routes_mod._run_scan_in_background(
        app, queued_id, "media", base_url="https://example.com",
        download=False, max_files=20, tier=Tier.FREE,
    )

    with app.app_context():
        stored = Scan.query.get(queued_id).report.data
        assert "regression" not in stored
        assert all("regression" not in f for f in stored["findings"])


# --------------------------------------------------------------------------
# CONT-03: finding.regressed via Phase 19's delivery machinery
# --------------------------------------------------------------------------

def _capture_posts(monkeypatch):
    calls = []

    def fake_post(url, data=None, headers=None, timeout=None):
        calls.append({"url": url, "data": data, "headers": headers})
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(webhook_engine.requests, "post", fake_post)
    return calls


def test_regression_event_delivered_signed_with_only_alertable_findings(app, db, monkeypatch):

    with app.app_context():
        org = make_org()
        user = make_user("reg-webhook@example.com", org=org)
        asset = make_asset(org, user)
        s = make_scan(user, org=org, status=ScanStatus.COMPLETED)
        s.asset_id = asset.id
        s.created_at = datetime.now(timezone.utc)
        s.risk_score = 40
        _db.session.add(Report(scan_id=s.id, json_path="unused.json", data=_report(
            [_f("sqli_union", "/items union", "critical", regression="new"),
             _f("cors", "loose cors", "low", regression="new"),
             _f("ports", "22 open", regression="recurring")])))
        w = OutboundWebhook(created_by_user_id=user.id, org_id=org.id,
                            label="ops", url="https://hooks.slack.com/services/A/B/C",
                            secret="4" * 64)
        _db.session.add(w)
        _db.session.commit()
        scan_id, secret = s.id, w.secret

    calls = _capture_posts(monkeypatch)
    with app.app_context():
        webhook_engine.fire_regression_webhooks(scan_id)

    assert len(calls) == 1
    body = json.loads(calls[0]["data"])
    assert body["event"] == "finding.regressed"
    assert [f["title"] for f in body["regressed_findings"]] == ["/items union"]
    expected_sig = "sha256=" + hmac_mod.new(
        secret.encode(), calls[0]["data"], hashlib.sha256
    ).hexdigest()
    assert calls[0]["headers"]["X-Glassbox-Signature"] == expected_sig
    assert calls[0]["headers"]["X-Glassbox-Event"] == "finding.regressed"

    with app.app_context():
        rows = WebhookDelivery.query.all()
        assert len(rows) == 1 and rows[0].status == "delivered"


def test_no_regression_event_without_new_high_critical(app, db, monkeypatch):

    with app.app_context():
        org = make_org()
        user = make_user("quiet@example.com", org=org)
        s = make_scan(user, org=org, status=ScanStatus.COMPLETED)
        s.created_at = datetime.now(timezone.utc)
        _db.session.add(Report(scan_id=s.id, json_path="u.json", data=_report(
            [_f("m", "med new", "medium", regression="new"),
             _f("r", "recurring crit", "critical", regression="recurring")])))
        _db.session.add(OutboundWebhook(
            created_by_user_id=user.id, org_id=org.id, label="quiet",
            url="https://hooks.slack.com/services/X/Y/Z", secret="k"))
        _db.session.commit()
        scan_id = s.id

    calls = _capture_posts(monkeypatch)
    with app.app_context():
        webhook_engine.fire_regression_webhooks(scan_id)

    assert calls == []
    with app.app_context():
        assert WebhookDelivery.query.count() == 0


def test_manual_scan_fires_no_regression_event(app, db, monkeypatch):

    with app.app_context():
        user = make_user("plain@example.com")
        s = make_scan(user, status=ScanStatus.COMPLETED)
        s.created_at = datetime.now(timezone.utc)
        _db.session.add(Report(scan_id=s.id, json_path="u.json", data=_report(
            [_f("a", "A", "critical")])))  # no regression tags at all
        _db.session.add(OutboundWebhook(
            created_by_user_id=user.id, org_id=None, label="solo",
            url="https://hooks.slack.com/services/S/O/L", secret="k"))
        _db.session.commit()
        scan_id = s.id

    calls = _capture_posts(monkeypatch)
    with app.app_context():
        webhook_engine.fire_regression_webhooks(scan_id)

    assert calls == []


# --------------------------------------------------------------------------
# CONT-02: asset detail page timeline
# --------------------------------------------------------------------------

def test_asset_detail_renders_regression_timeline(client, app, db):
    with app.app_context():
        org = make_org()
        user = make_user("timeline-viewer@example.com", org=org)
        asset = make_asset(org, user, name="Timeline Asset")
        now = datetime.now(timezone.utc)
        _seed_completed(app, asset, user, org,
                        [_f("xss", "/q reflected", "high")],
                        created_at=now - timedelta(days=1))
        newer = make_scan(user, org=org, status=ScanStatus.COMPLETED)
        newer.asset_id = asset.id
        newer.created_at = now
        newer.completed_at = now
        newer.risk_score = 66
        report = _report(
            [_f("ports", "3306 exposed", "high", regression="new"),
             _f("headers", "missing csp", "low", regression="recurring")],
            score=66)
        report["regression"] = {
            "new": 1, "recurring": 1,
            "resolved": [{"check_name": "xss", "title": "/q reflected",
                          "severity": "high"}],
        }
        _db.session.add(Report(scan_id=newer.id, json_path="unused.json",
                               data=report))
        _db.session.commit()
        asset_id = asset.id

    login(client, "timeline-viewer@example.com")
    resp = client.get(f"/assets/{asset_id}")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Regression timeline" in html
    assert "1 new" in html and "1 recurring" in html and "1 resolved" in html
    assert "3306 exposed" in html          # new finding title listed
    assert "/q reflected" in html          # resolved snapshot listed
    assert "No regressions tracked yet" not in html


def test_asset_detail_without_diffable_history_shows_empty_state(client, app, db):
    """One completed scan = history exists (section renders) but no
    predecessor to diff against -> reg_timeline is empty -> the muted
    empty-state card explains what will appear once a second scan lands."""
    from datetime import datetime, timedelta, timezone

    with app.app_context():
        org = make_org()
        user = make_user("empty-timeline@example.com", org=org)
        asset = make_asset(org, user, name="Empty Timeline Asset")
        _seed_completed(app, asset, user, org, [_f("a", "A")],
                        created_at=datetime.now(timezone.utc) - timedelta(days=1))
        _db.session.commit()
        asset_id = asset.id

    login(client, "empty-timeline@example.com")
    resp = client.get(f"/assets/{asset_id}")
    assert resp.status_code == 200
    assert b"No regressions tracked yet" in resp.data


def test_asset_detail_zero_scans_omits_timeline_section(client, app, db):
    """A brand-new Asset has no history at all - the page already says the
    first scheduled scan is coming, so the regression section stays out of
    the way rather than stacking two empty-state cards."""
    with app.app_context():
        org = make_org()
        user = make_user("brand-new-asset@example.com", org=org)
        asset = make_asset(org, user, name="Brand New Asset")
        _db.session.commit()
        asset_id = asset.id

    login(client, "brand-new-asset@example.com")
    resp = client.get(f"/assets/{asset_id}")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Regression timeline" not in html
    assert "hasn't been scanned yet" in html
