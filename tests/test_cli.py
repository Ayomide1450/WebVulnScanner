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
    touch the real ~/.wvs/config.json."""
    config_path = tmp_path / ".wvs" / "config.json"
    monkeypatch.setattr(wvs, "CONFIG_PATH", config_path)
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
    assert "wvs login" in result.output
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


# --- report get ---


def test_report_get_success_pretty_prints_json(runner, isolated_config):
    fake_report = {"score": 91, "grade": "A", "findings": []}
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(200, json_body=fake_report)
        result = runner.invoke(wvs.cli, ["report", "get", "42"])

    assert result.exit_code == 0
    assert json.loads(result.output) == fake_report
    assert mock_get.call_args[0][0] == "http://example.test/api/v1/scans/42/report"


def test_report_get_error_exits_nonzero_no_traceback(runner, isolated_config):
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(404, json_body={"error": "report not available"})
        result = runner.invoke(wvs.cli, ["report", "get", "42"])

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


def test_report_get_passes_request_timeout(runner, isolated_config):
    with patch.object(
        wvs, "_load_config", return_value={"token": "sekrit", "api_url": "http://example.test"}
    ), patch.object(wvs.requests, "get") as mock_get:
        mock_get.return_value = _FakeResponse(200, json_body={"score": 1})
        runner.invoke(wvs.cli, ["report", "get", "42"])

    assert mock_get.call_args.kwargs["timeout"] == wvs.REQUEST_TIMEOUT_SECONDS
