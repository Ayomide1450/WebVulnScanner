"""Tests for cli/wvs.py - a pure HTTP client over /api/v1/*, no Flask app
under test here at all. Mocks requests.get/requests.post at the
cli.wvs.requests.get/.post call sites; never touches the real ~/.wvs/
directory (CONFIG_PATH is monkeypatched to a tmp_path location per test)."""
import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from cli import wvs


class _FakeResponse:
    def __init__(self, status_code, json_body=None, text=""):
        self.status_code = status_code
        self._json_body = json_body
        self.text = text if json_body is None else json.dumps(json_body)

    def json(self):
        if self._json_body is None:
            raise ValueError("no JSON body")
        return self._json_body


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    """Redirects cli.wvs.CONFIG_PATH to a tmp_path location so tests never
    touch the real ~/.glassbox/config.json. Also points the legacy
    fallback path (~/.wvs/config.json) at a tmp_path location that never
    exists, so _load_config's legacy-path fallback can't pick up a real
    local dev machine's old wvs login during a test run."""
    config_path = tmp_path / ".glassbox" / "config.json"
    monkeypatch.setattr(wvs, "CONFIG_PATH", config_path)
    monkeypatch.setattr(wvs, "_LEGACY_CONFIG_PATH", tmp_path / "no-such-legacy-dir" / "config.json")
    return config_path


# --- login ---


def test_login_success_writes_config(runner, isolated_config):
    with patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(200, json_body={"assets": []})
        result = runner.invoke(
            wvs.cli,
            ["login", "--token", "sekrit", "--api-url", "http://example.test"],
        )

    assert result.exit_code == 0
    assert "Logged in." in result.output
    assert isolated_config.exists()
    saved = json.loads(isolated_config.read_text())
    assert saved == {"token": "sekrit", "api_url": "http://example.test"}


def test_login_without_api_url_reuses_previously_saved_api_url(runner, isolated_config):
    # WR-04 regression: re-running `wvs login` without --api-url must not
    # silently reset a previously-saved custom api_url back to
    # DEFAULT_API_URL - it should reuse the stored config's api_url, same
    # precedence _resolve_api_url() already uses for every other command.
    isolated_config.parent.mkdir(parents=True, exist_ok=True)
    isolated_config.write_text(
        json.dumps({"token": "old-token", "api_url": "https://scanner.example.com"})
    )
    with patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(200, json_body={"assets": []})
        result = runner.invoke(wvs.cli, ["login", "--token", "new-token"])

    assert result.exit_code == 0
    assert mock_get.call_args[0][0] == "https://scanner.example.com/api/v1/assets"
    saved = json.loads(isolated_config.read_text())
    assert saved == {"token": "new-token", "api_url": "https://scanner.example.com"}


def test_login_failure_writes_no_config(runner, isolated_config):
    with patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(
            401, json_body={"error": "missing or invalid API token"}
        )
        result = runner.invoke(
            wvs.cli,
            ["login", "--token", "bad-token", "--api-url", "http://example.test"],
        )

    assert result.exit_code != 0
    assert "missing or invalid API token" in result.output
    assert not isolated_config.exists()


# --- assets list ---


def test_assets_list_after_login_prints_assets(runner, isolated_config):
    fake_assets = {
        "assets": [
            {
                "name": "example.com",
                "target_url": "https://example.com",
                "latest_scan": {"status": "completed", "risk_score": 87},
            },
            {
                "name": "no-scans-yet.com",
                "target_url": "https://no-scans-yet.com",
                "latest_scan": None,
            },
        ]
    }
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(200, json_body=fake_assets)
        result = runner.invoke(wvs.cli, ["assets", "list"])

    assert result.exit_code == 0
    assert "example.com" in result.output
    assert "completed" in result.output
    assert "no scans yet" in result.output


def test_assets_list_no_token_anywhere_exits_nonzero_no_request(runner, isolated_config):
    with patch.object(wvs.requests, "get") as mock_get:
        result = runner.invoke(wvs.cli, ["assets", "list"])

    assert result.exit_code != 0
    assert "glassbox login" in result.output
    mock_get.assert_not_called()


def test_assets_list_explicit_flags_override_config(runner, isolated_config):
    fake_assets = {"assets": []}
    with patch.object(
        wvs, "_load_config", return_value={"token": "stale", "api_url": "http://stale.test"}
    ), patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(200, json_body=fake_assets)
        result = runner.invoke(
            wvs.cli,
            ["assets", "list", "--token", "fresh", "--api-url", "http://fresh.test"],
        )

    assert result.exit_code == 0
    _, kwargs = mock_get.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer fresh"
    assert mock_get.call_args[0][0] == "http://fresh.test/api/v1/assets"


# --- scan start ---


def test_scan_start_success_prints_scan_id_status(runner, isolated_config):
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "post") as mock_post:
        mock_post.return_value = _FakeResponse(
            202, json_body={"scan_id": 42, "status": "queued"}
        )
        result = runner.invoke(wvs.cli, ["scan", "start", "7"])

    assert result.exit_code == 0
    assert "Scan 42 started (status: queued)." in result.output
    assert mock_post.call_args[0][0] == "http://example.test/api/v1/assets/7/scans"


def test_scan_start_error_exits_nonzero_no_traceback(runner, isolated_config):
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "post") as mock_post:
        mock_post.return_value = _FakeResponse(404, json_body={"error": "not found"})
        result = runner.invoke(wvs.cli, ["scan", "start", "999"])

    assert result.exit_code != 0
    assert "not found" in result.output
    assert "Traceback" not in result.output


# --- report (Phase 18: `glassbox report <scan-id>`, replaces the old
# `report get <scan-id>` subcommand shape) ---


def test_report_success_pretty_prints_json(runner, isolated_config):
    fake_report = {"score": 91, "grade": "A", "findings": []}
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(200, json_body=fake_report)
        result = runner.invoke(wvs.cli, ["report", "42"])

    assert result.exit_code == 0
    assert json.loads(result.output) == fake_report
    assert mock_get.call_args[0][0] == "http://example.test/api/v1/scans/42/report"


def test_report_error_exits_nonzero_no_traceback(runner, isolated_config):
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(404, json_body={"error": "report not available"})
        result = runner.invoke(wvs.cli, ["report", "42"])

    assert result.exit_code != 0
    assert "report not available" in result.output
    assert "Traceback" not in result.output


def test_report_csv_prints_server_csv_verbatim(runner, isolated_config):
    # CLI-02's CSV half: --csv hits the token-authed report.csv endpoint and
    # streams its body verbatim - no client-side re-rendering that could
    # drift from the server's single shared CSV writer.
    server_csv = 'category,title,severity,owasp_category,detail,recommendation\r\nHeaders,Missing CSP,medium,A05,No CSP.,Add one.\r\n'
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(200, text=server_csv)
        result = runner.invoke(wvs.cli, ["report", "42", "--csv"])

    assert result.exit_code == 0
    assert mock_get.call_args[0][0] == "http://example.test/api/v1/scans/42/report.csv"
    assert mock_get.call_args.kwargs["headers"]["Authorization"] == "Bearer sekrit"
    assert result.output == server_csv


def test_report_csv_error_exits_nonzero_no_traceback(runner, isolated_config):
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(404, json_body={"error": "report not available"})
        result = runner.invoke(wvs.cli, ["report", "42", "--csv"])

    assert result.exit_code != 0
    assert "report not available" in result.output
    assert "Traceback" not in result.output


# --- WR-03: every HTTP call site passes timeout= ---


def test_login_passes_request_timeout(runner, isolated_config):
    with patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(200, json_body={"assets": []})
        runner.invoke(
            wvs.cli, ["login", "--token", "sekrit", "--api-url", "http://example.test"],
        )

    assert mock_get.call_args.kwargs["timeout"] == wvs.REQUEST_TIMEOUT_SECONDS


def test_assets_list_passes_request_timeout(runner, isolated_config):
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(200, json_body={"assets": []})
        runner.invoke(wvs.cli, ["assets", "list"])

    assert mock_get.call_args.kwargs["timeout"] == wvs.REQUEST_TIMEOUT_SECONDS


def test_scan_start_passes_request_timeout(runner, isolated_config):
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "post") as mock_post:
        mock_post.return_value = _FakeResponse(202, json_body={"scan_id": 1, "status": "queued"})
        runner.invoke(wvs.cli, ["scan", "start", "7"])

    assert mock_post.call_args.kwargs["timeout"] == wvs.REQUEST_TIMEOUT_SECONDS


def test_report_passes_request_timeout(runner, isolated_config):
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(200, json_body={"score": 1})
        runner.invoke(wvs.cli, ["report", "42"])

    assert mock_get.call_args.kwargs["timeout"] == wvs.REQUEST_TIMEOUT_SECONDS


# --- gate (server-side Security Gate: the command polls the assessment to
# completion, then asks GET /api/v1/scans/<id>/gate?fail_on=<sev> for the
# verdict instead of filtering findings locally - see cli/wvs.py's gate
# docstring) ---


def _gate_mocks(gate_body):
    """Returns (post_mock_config, get_side_effect) for the two HTTP calls
    `glassbox gate` makes after launch: the completion poll, then the gate
    endpoint itself. POST returns scan 42 queued; GET first reports it
    completed (so _launch_and_wait returns without sleeping), then yields
    gate_body."""
    post_resp = _FakeResponse(202, json_body={"scan_id": 42, "status": "queued", "duplicate": False})
    poll_resp = _FakeResponse(200, json_body={"id": 42, "status": "completed"})
    gate_resp = _FakeResponse(200, json_body=gate_body)
    return [post_resp], [poll_resp, gate_resp]


def test_gate_passed_exits_zero_and_hits_server_endpoint(runner, isolated_config):
    body = {"passed": True, "fail_on": "high", "blocking_findings": [], "blocking_count": 0,
            "scan_id": 42, "scan_status": "completed", "score": 95}
    posts, gets = _gate_mocks(body)
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "post", return_value=posts[0]), \
       patch.object(wvs.requests, "get", side_effect=gets) as mock_get:
        result = runner.invoke(wvs.cli, ["gate", "https://example.com"])

    assert result.exit_code == 0
    assert "Security Gate Passed" in result.output
    # The verdict came from the server endpoint with the default threshold.
    assert mock_get.call_args_list[-1][0][0] == "http://example.test/api/v1/scans/42/gate?fail_on=high"


def test_gate_failed_exits_one_and_counts_blocking_severities(runner, isolated_config):
    blocking = [
        {"category": "SQL Injection", "title": "Login bypass", "severity": "critical", "detail": "x"},
        {"category": "Headers", "title": "Missing CSP", "severity": "high", "detail": "y"},
    ]
    body = {"passed": False, "fail_on": "high", "blocking_findings": blocking, "blocking_count": 2,
            "scan_id": 42, "score": 40}
    posts, gets = _gate_mocks(body)
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "post", return_value=posts[0]), \
       patch.object(wvs.requests, "get", side_effect=gets):
        result = runner.invoke(wvs.cli, ["gate", "https://example.com"])

    assert result.exit_code == 1
    assert "Security Gate Failed" in result.output
    assert "1 critical" in result.output
    assert "1 high" in result.output


def test_gate_json_outputs_server_verdict_and_passes_fail_on_flag(runner, isolated_config):
    # A high-only finding set passes a critical threshold - the server's
    # own verdict body is echoed verbatim and its "passed" drives the exit
    # code, not any client-side recomputation.
    body = {"passed": True, "fail_on": "critical", "blocking_findings": [], "blocking_count": 0,
            "scan_id": 42, "score": 80}
    posts, gets = _gate_mocks(body)
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "post", return_value=posts[0]), \
       patch.object(wvs.requests, "get", side_effect=gets) as mock_get:
        result = runner.invoke(
            wvs.cli, ["gate", "https://example.com", "--json", "--fail-on", "critical"],
        )

    # A high-only finding set passes a critical threshold - exit 0 - and the
    # machine output is the server's own verdict body verbatim.
    assert result.exit_code == 0
    assert json.loads(result.output) == body
    assert mock_get.call_args_list[-1][0][0] == "http://example.test/api/v1/scans/42/gate?fail_on=critical"


def test_gate_endpoint_error_surfaces_clean_message_no_traceback(runner, isolated_config):
    post_resp = _FakeResponse(202, json_body={"scan_id": 42, "status": "queued", "duplicate": False})
    poll_resp = _FakeResponse(200, json_body={"id": 42, "status": "completed"})
    error_resp = _FakeResponse(500, json_body={"error": "report file is unavailable"})
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "post", return_value=post_resp), \
       patch.object(wvs.requests, "get", side_effect=[poll_resp, error_resp]):
        result = runner.invoke(wvs.cli, ["gate", "https://example.com"])

    assert result.exit_code != 0
    assert "report file is unavailable" in result.output
    assert "Traceback" not in result.output
