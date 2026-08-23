"""Phase 19 (WEBH-*): outbound-webhook tests.

Two layers, matching the module split:

- Engine (`webvulnscanner/webhooks.py`): URL validation (HTTPS + SSRF),
  payload construction, HMAC signing, delivery recording, the
  never-raises contract around dead receivers, and scope matching -
  org webhooks fire for their org's scans, solo webhooks only for
  scans their creator ran.
- Routes (`webvulnscanner/webhook_routes.py`): creation validation,
  secret-shown-once reveal, member/admin visibility, and the 404-not-403
  cross-scope denials registered in tests/test_cross_org_idor.py's
  REGISTRY.

Network is always stubbed (`requests.post` replaced on the webhooks module)
- no test ever performs a real POST - and `socket.getaddrinfo` follows the
repo-wide `_fake_getaddrinfo_public/_private` idiom from test_asset_routes.py.
"""
import hashlib
import hmac as hmac_mod
import json
import socket

import pytest
import requests as requests_lib

import webvulnscanner.webhooks as webhook_engine
from webvulnscanner.extensions import db as _db
from webvulnscanner.models import OutboundWebhook, Plan, Role, ScanStatus, WebhookDelivery
from webvulnscanner.scan_engine import save_report

from tests.conftest import login, make_org, make_scan, make_user


# --------------------------------------------------------------------------
# Shared fakes (test_asset_routes.py idioms)
# --------------------------------------------------------------------------

def _fake_getaddrinfo_public(*a, **k):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]


def _fake_getaddrinfo_private(*a, **k):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]


class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


def _persist_report(app, scan, score, grade, findings):
    """Writes the report JSON + Report row a real scan tail would have
    written (save_report only writes the file; the caller links the row)."""
    from urllib.parse import urlparse

    from webvulnscanner.models import Report

    fname = save_report({
        "target": scan.target_url, "score": score,
        "grade": grade, "findings": findings,
    }, "test_webhook", urlparse(scan.target_url).hostname)
    _db.session.add(Report(scan_id=scan.id, json_path=fname))
    _db.session.commit()


def _make_webhook(user_id, org_id=None, label="Hook", is_active=True,
                  url="https://r.example/hook", secret="42" * 32):
    w = OutboundWebhook(created_by_user_id=user_id, org_id=org_id, label=label,
                        url=url, secret=secret, is_active=is_active)
    _db.session.add(w)
    _db.session.flush()  # assign w.id before callers reference it
    return w


# --------------------------------------------------------------------------
# Engine: validate_webhook_url / redact_webhook_url
# --------------------------------------------------------------------------

def test_http_url_is_rejected():
    err = webhook_engine.validate_webhook_url("http://hooks.slack.com/services/x")
    assert err is not None and "HTTPS" in err


def test_unresolvable_private_hostname_is_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo_private)
    err = webhook_engine.validate_webhook_url("https://internal.corp.example.com/hook")
    assert err is not None and "private" in err.lower()


def test_valid_https_url_passes(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo_public)
    assert webhook_engine.validate_webhook_url(
        "https://hooks.slack.com/services/T00/B00/XXXXXXXX"
    ) is None


def test_redact_hides_path_and_query():
    shown = webhook_engine.redact_webhook_url(
        "https://hooks.slack.com/services/TOKEN/SECRET/PATHS?q=1"
    )
    assert "TOKEN" not in shown and "SECRET" not in shown and "PATHS" not in shown
    assert shown.startswith("https://hooks.slack.com/")


# --------------------------------------------------------------------------
# Engine: payload construction + signing
# --------------------------------------------------------------------------

def test_build_payload_contains_text_gate_and_top_findings(app, db):
    with app.app_context():
        u = make_user("solo@example.com")
        s = make_scan(u, status=ScanStatus.COMPLETED)
        s.risk_score = 55
        _db.session.commit()
        findings = [
            {"severity": "high", "title": "Open admin panel"},
            {"severity": "low", "title": "Minor header gap"},
            {"severity": "critical", "title": "SQL injection"},
            {"severity": "medium", "title": "Cookie flags"},
            {"severity": "info", "title": "Server banner"},
            {"severity": "pass", "title": "HSTS ok"},
            {"severity": "low", "title": "Sixth finding"},
        ]
        _persist_report(app, s, 55, "C", findings)

        payload = webhook_engine.build_scan_payload(s, webhook_engine._load_report(s))

        assert payload["event"] == "scan.completed"
        assert payload["scan"]["id"] == s.id
        assert payload["scan"]["risk_score"] == 55
        # text is Slack-first: host, score, finding count, verdict
        assert "example.com" in payload["text"] and "score 55" in payload["text"]
        assert "FAILED" in payload["text"]  # fail_on=high: the critical blocks
        assert payload["gate"]["passed"] is False
        assert payload["gate"]["blocking_count"] == 2  # critical + high
        # top_findings: severity-sorted, capped at MAX_TOP_FINDINGS(5)
        titles = [f["title"] for f in payload["top_findings"]]
        assert len(titles) == 5
        assert titles[0] == "SQL injection"


def test_signature_is_a_verifiable_hmac_sha256():
    secret = "ab" * 32
    body = b'{"hello":"world"}'
    sig = webhook_engine.sign_payload(secret, body)
    expected = hmac_mod.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert sig == f"sha256={expected}"


# --------------------------------------------------------------------------
# Engine: deliver() records outcomes and NEVER raises
# --------------------------------------------------------------------------

def test_deliver_success_records_delivery_row_and_signs_exact_bytes(app, db, monkeypatch):
    with app.app_context():
        u = make_user("solo@example.com")
        s = make_scan(u, status=ScanStatus.COMPLETED)
        w = _make_webhook(u.id, label="Slack", url="https://hooks.slack.com/services/A/B/C")
        _db.session.commit()

        captured = {}

        def fake_post(url, data=None, headers=None, timeout=None):
            captured.update(url=url, headers=headers, body=data)
            return _FakeResponse(200)

        monkeypatch.setattr(webhook_engine.requests, "post", fake_post)
        webhook_engine.deliver(w, s.id)

        row = WebhookDelivery.query.one()
        assert row.status == "delivered" and row.response_code == 200
        assert row.scan_id == s.id
        # The exact bytes signed are the exact bytes sent
        assert captured["headers"]["X-Glassbox-Signature"] == (
            f"sha256={hmac_mod.new(w.secret.encode(), captured['body'], hashlib.sha256).hexdigest()}"
        )
        assert captured["headers"]["Content-Type"] == "application/json"


def test_deliver_dead_receiver_records_failure_and_does_not_raise(app, db, monkeypatch):
    with app.app_context():
        u = make_user("solo@example.com")
        s = make_scan(u, status=ScanStatus.COMPLETED)
        w = _make_webhook(u.id, label="Dead", url="https://down.example.com/hook")
        _db.session.commit()

        def boom(*a, **k):
            raise requests_lib.exceptions.ConnectionError("refused")

        monkeypatch.setattr(webhook_engine.requests, "post", boom)
        webhook_engine.deliver(w, s.id)  # must not raise

        row = WebhookDelivery.query.one()
        assert row.status == "failed" and row.response_code is None
        assert "delivery error" in row.error_message


def test_deliver_non_2xx_counts_as_failed(app, db, monkeypatch):
    with app.app_context():
        u = make_user("solo@example.com")
        s = make_scan(u, status=ScanStatus.COMPLETED)
        w = _make_webhook(u.id, label="Gone", url="https://hooks.slack.com/services/X/Y/Z")
        _db.session.commit()

        monkeypatch.setattr(webhook_engine.requests, "post",
                            lambda *a, **k: _FakeResponse(410))
        webhook_engine.deliver(w, s.id)

        row = WebhookDelivery.query.one()
        assert row.status == "failed" and row.response_code == 410


def test_send_test_ping_records_scanless_delivery(app, db, monkeypatch):
    with app.app_context():
        u = make_user("solo@example.com")
        w = _make_webhook(u.id, label="Ping target", url="https://receiver.example.com/hook")
        _db.session.commit()

        bodies = []

        def fake_post(url, data=None, headers=None, timeout=None):
            bodies.append(json.loads(data.decode("utf-8")))
            return _FakeResponse(200)

        monkeypatch.setattr(webhook_engine.requests, "post", fake_post)
        ok, err = webhook_engine.send_test_ping(w)

        assert ok is True and err is None
        row = WebhookDelivery.query.one()
        assert row.scan_id is None and row.status == "delivered"
        assert bodies[0]["event"] == "ping"


# --------------------------------------------------------------------------
# Engine: fire_scan_webhooks scope matching
# --------------------------------------------------------------------------

def test_fire_matches_org_scope_and_skips_paused_and_foreign(app, db, monkeypatch):
    with app.app_context():
        org_a = make_org(plan=Plan.PAID, name="Org A")
        org_b = make_org(plan=Plan.PAID, name="Org B")
        ua = make_user("a-admin@example.com", org=org_a, role=Role.ORG_ADMIN)
        ub = make_user("b-admin@example.com", org=org_b, role=Role.ORG_ADMIN)
        s = make_scan(ua, org=org_a, status=ScanStatus.COMPLETED)

        hit = _make_webhook(ua.id, org_id=org_a.id, label="A slack", url="https://r.example/a", secret="1" * 64)
        _make_webhook(ua.id, org_id=org_a.id, label="A paused", url="https://r.example/p", secret="2" * 64, is_active=False)
        _make_webhook(ub.id, org_id=org_b.id, label="B slack", url="https://r.example/b", secret="3" * 64)
        _db.session.commit()

        called = []
        monkeypatch.setattr(webhook_engine, "deliver", lambda w, sid: called.append(w.id))
        webhook_engine.fire_scan_webhooks(s.id)
        assert called == [hit.id]


def test_fire_solo_scope_only_reaches_the_creator(app, db, monkeypatch):
    with app.app_context():
        mine = make_user("mine@example.com")
        other = make_user("other@example.com")  # also solo (no org)
        s = make_scan(mine, status=ScanStatus.COMPLETED)

        my_hook = _make_webhook(mine.id, label="Mine", url="https://r.example/mine", secret="4" * 64)
        _make_webhook(other.id, label="Other", url="https://r.example/other", secret="5" * 64)
        _db.session.commit()

        called = []
        monkeypatch.setattr(webhook_engine, "deliver", lambda w, sid: called.append(w.id))
        webhook_engine.fire_scan_webhooks(s.id)
        # created_by_user_id matching (not NULL-org equality): only my own hook fires
        assert called == [my_hook.id]


def test_fire_never_raises_even_if_deliver_explodes(app, db, monkeypatch):
    with app.app_context():
        u = make_user("solo@example.com")
        s = make_scan(u, status=ScanStatus.COMPLETED)
        _make_webhook(u.id, label="X", secret="6" * 64)
        _db.session.commit()

        monkeypatch.setattr(webhook_engine, "deliver",
                            lambda w, sid: (_ for _ in ()).throw(RuntimeError("boom")))
        webhook_engine.fire_scan_webhooks(s.id)  # swallowed by design


# --------------------------------------------------------------------------
# Routes: /webhooks CRUD + scoping
# --------------------------------------------------------------------------

@pytest.fixture()
def solo_client(db, client):
    make_user("solo@example.com")
    login(client, "solo@example.com")
    return client


@pytest.fixture()
def org_ctx(db, client):
    org = make_org(plan=Plan.PAID, name="Hook Org")
    make_user("hookadmin@example.com", org=org, role=Role.ORG_ADMIN)
    login(client, "hookadmin@example.com")
    return client, org


def test_add_route_rejects_http_and_creates_nothing(solo_client, db, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo_public)
    resp = solo_client.post("/webhooks/add",
                            data={"label": "L", "url": "http://x.example/h"})
    assert resp.status_code == 302
    assert OutboundWebhook.query.count() == 0


def test_solo_add_creates_personal_webhook_and_shows_secret_once(solo_client, db, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo_public)
    resp = solo_client.post("/webhooks/add", follow_redirects=False,
                            data={"label": "My Slack", "url": "https://r.example/mine"})
    assert resp.status_code == 302
    w = OutboundWebhook.query.one()
    assert w.org_id is None and w.label == "My Slack"

    # ?created=<id> reveals the secret...
    revealed = solo_client.get(f"/webhooks?created={w.id}")
    assert w.secret.encode() in revealed.data
    # ...but a plain revisit does not
    plain = solo_client.get("/webhooks")
    assert w.secret.encode() not in plain.data


def test_org_admin_add_creates_org_scoped_webhook(org_ctx, db, monkeypatch):
    c, org = org_ctx
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo_public)
    resp = c.post("/webhooks/add", follow_redirects=False,
                  data={"label": "Team Slack", "url": "https://r.example/team"})
    assert resp.status_code == 302
    w = OutboundWebhook.query.one()
    assert w.org_id == org.id


def test_org_member_gets_explanation_and_no_list(db, client):
    org = make_org(plan=Plan.PAID, name="Hook Org")
    make_user("hookadmin@example.com", org=org, role=Role.ORG_ADMIN)
    make_user("member@example.com", org=org, role=Role.MEMBER)
    login(client, "member@example.com")
    html = client.get("/webhooks").data
    # member_note branch: page renders (200), no create form, no table rows
    assert b"organization-admin feature" in html
    assert b"/webhooks/add" not in html


def test_toggle_pauses_and_resumes(org_ctx, db):
    c, org = org_ctx
    from tests.conftest import make_user as _mu
    u = _mu("toggler@example.com", org=org, role=Role.ORG_ADMIN)
    w = _make_webhook(u.id, org_id=org.id, label="T")
    _db.session.commit()

    c.post(f"/webhooks/{w.id}/toggle")
    assert OutboundWebhook.query.get(w.id).is_active is False
    c.post(f"/webhooks/{w.id}/toggle")
    assert OutboundWebhook.query.get(w.id).is_active is True


def test_test_ping_route_fires_and_redirects(solo_client, db, monkeypatch):
    from tests.conftest import make_user as _mu
    real_u = _mu("pinger@example.com")
    w = _make_webhook(real_u.id, label="P")
    _db.session.commit()

    monkeypatch.setattr(webhook_engine.requests, "post",
                        lambda *a, **k: _FakeResponse(200))
    login(solo_client, "pinger@example.com")  # ensure session is the owner
    resp = solo_client.post(f"/webhooks/{w.id}/test", follow_redirects=False)
    assert resp.status_code == 302
    row = WebhookDelivery.query.one()
    assert row.status == "delivered" and row.scan_id is None


def test_deliveries_page_lists_attempts_and_links_scans(solo_client, db, monkeypatch):
    from tests.conftest import make_user as _mu
    real_u = _mu("viewer@example.com")
    s = make_scan(real_u, status=ScanStatus.COMPLETED)
    w = _make_webhook(real_u.id, label="V")
    _db.session.add(WebhookDelivery(webhook_id=w.id, scan_id=s.id,
                                    status="delivered", response_code=200))
    _db.session.commit()

    login(solo_client, "viewer@example.com")
    html = solo_client.get(f"/webhooks/{w.id}/deliveries").data
    assert f"Scan #{s.id}".encode() in html
    assert b"Delivered" in html


# --------------------------------------------------------------------------
# Cross-scope denials (registered in test_cross_org_idor.py's REGISTRY)
# --------------------------------------------------------------------------

def test_all_four_webhook_actions_are_404_for_a_solo_non_owner(db, client):
    """The IDOR-registry denial: another SOLO user must get 404 - not 403 -
    on every id-accepting webhook route for a webhook that isn't theirs."""
    owner = make_user("owner@example.com")
    w = _make_webhook(owner.id, label="Secret hook")
    _db.session.commit()

    make_user("intruder@example.com")
    login(client, "intruder@example.com")

    assert client.post(f"/webhooks/{w.id}/delete").status_code == 404
    assert client.post(f"/webhooks/{w.id}/toggle").status_code == 404
    assert client.post(f"/webhooks/{w.id}/test").status_code == 404
    assert client.get(f"/webhooks/{w.id}/deliveries").status_code == 404
    # ...and the ?created reveal must not leak another user's secret either
    assert w.secret.encode() not in client.get(f"/webhooks?created={w.id}").data


def test_all_four_webhook_actions_are_404_for_another_orgs_admin(db, client):
    """Org scoping: an ORG_ADMIN of a DIFFERENT org gets 404 too."""
    org_a = make_org(plan=Plan.PAID, name="Org A")
    owner = make_user("a-owner@example.com", org=org_a, role=Role.ORG_ADMIN)
    w = _make_webhook(owner.id, org_id=org_a.id, label="A hook",
                      url="https://r.example/a", secret="7" * 64)
    _db.session.commit()

    org_b = make_org(plan=Plan.PAID, name="Org B")
    make_user("b-admin@example.com", org=org_b, role=Role.ORG_ADMIN)
    login(client, "b-admin@example.com")

    assert client.post(f"/webhooks/{w.id}/delete").status_code == 404
    assert client.post(f"/webhooks/{w.id}/toggle").status_code == 404
    assert client.post(f"/webhooks/{w.id}/test").status_code == 404
    assert client.get(f"/webhooks/{w.id}/deliveries").status_code == 404


def test_org_member_cannot_manage_their_own_orgs_webhook(db, client):
    """Admin-only management inside the org: a MEMBER of the SAME org also
    gets 404 on mutating routes (the index page hides the form; this proves
    hiding it wasn't the guard)."""
    org = make_org(plan=Plan.PAID, name="Same Org")
    admin = make_user("same-admin@example.com", org=org, role=Role.ORG_ADMIN)
    w = _make_webhook(admin.id, org_id=org.id, label="S",
                      url="https://r.example/s", secret="8" * 64)
    _db.session.commit()

    make_user("same-member@example.com", org=org, role=Role.MEMBER)
    login(client, "same-member@example.com")

    assert client.post(f"/webhooks/{w.id}/delete").status_code == 404
    assert client.post(f"/webhooks/{w.id}/toggle").status_code == 404
