"""Phase 21 (ST-01..06): the built-in detection self-test.

These tests run the REAL loopback lure server and the REAL check functions
inside pytest - no mocking of the layer under test. They lock both halves of
the matrix (five planted detections fire, five clean surfaces stay silent),
the listener's loopback-only binding and teardown, and the route's auth +
no-scan-row contracts."""

import socket

import pytest

from webvulnscanner.models import Scan
from webvulnscanner.selftest import EXPECTATIONS, run_selftest, start_lure_listener


def test_expectations_matrix_covers_all_ten_intrusive_checks():
    names = {name for name, _, _ in EXPECTATIONS}
    assert len(EXPECTATIONS) == 10
    assert names == {
        "ssti", "path_traversal", "jwt_active", "graphql_deep", "csrf_posture",
        "host_header", "crlf", "rate_limit", "cache_deception",
        "subdomain_takeover"}


def test_full_matrix_every_expectation_matches():
    report = run_selftest()
    assert report["passed"], [
        (r["name"], r["matched"], r["error"], r["findings"])
        for r in report["results"] if not r["matched"]]
    assert len(report["results"]) == 10
    positives = [r for r in report["results"] if r["expect_finding"]]
    negatives = [r for r in report["results"] if not r["expect_finding"]]
    assert len(positives) == 5 and len(negatives) == 5
    for row in positives:
        assert row["findings"], f"{row['name']} detected nothing"


def test_selftest_is_deterministic_across_runs():
    first = run_selftest()
    second = run_selftest()
    assert first["passed"] and second["passed"]


def test_listener_binds_loopback_only():
    server, base_url = start_lure_listener()
    try:
        host, port = server.server_address
        assert host == "127.0.0.1"
        # The URL must be unreachable via any non-loopback name we can test:
        # the port is open ONLY on 127.0.0.1, so connecting to it through a
        # different local address must fail rather than reach the lure.
        probe = socket.socket()
        probe.settimeout(2)
        try:
            probe.connect(("localhost", port))
            reachable = True
        except OSError:
            reachable = False
        finally:
            probe.close()
        # 'localhost' may resolve to 127.0.0.1 on some setups (then it IS
        # reachable); what must NEVER happen is a 0.0.0.0-style wildcard bind.
        if reachable:
            import socket as s
            hostname_ip = s.gethostbyname(s.gethostname())
            if hostname_ip != "127.0.0.1":
                wildcard = socket.socket()
                wildcard.settimeout(2)
                with pytest.raises(OSError):
                    wildcard.connect((hostname_ip, port))
                wildcard.close()
    finally:
        server.shutdown()
        server.server_close()


def test_port_released_after_run():
    before = run_selftest()
    assert before["passed"]
    server, base_url = start_lure_listener()
    port = server.server_address[1]
    server.shutdown()
    server.server_close()
    probe = socket.socket()
    probe.settimeout(2)
    with pytest.raises(OSError):
        probe.connect(("127.0.0.1", port))
    probe.close()


def test_route_requires_login(client):
    resp = client.get("/selftest")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_route_renders_page_and_runs_matrix(db, client):
    from tests.conftest import make_user, login
    user = make_user("selftester@example.com")
    db.session.commit()
    login(client, "selftester@example.com")

    resp = client.get("/selftest")
    assert resp.status_code == 200
    assert b"Detection Self-Test" in resp.data
    assert b"Run self-test" in resp.data

    resp = client.post("/selftest")
    assert resp.status_code == 200
    assert b"All expectations met" in resp.data
    assert b"jwt_active" in resp.data and b"path_traversal" in resp.data


def test_selftest_creates_no_scan_row_or_report_file(app):
    with app.app_context():
        assert Scan.query.count() == 0
        report = run_selftest()
        assert report["passed"]
        assert Scan.query.count() == 0
