"""wvs - thin CLI client for WebVulnScanner's /api/v1 surface. Talks only to
the HTTP API, never imports Flask or webvulnscanner directly.

Commands:
    wvs login                    - authenticate and persist a token locally
    wvs assets list               - list the caller's scoped Assets
    wvs scan start <asset-id>     - trigger a scan against an Asset
    wvs report get <scan-id>      - fetch a scan's structured JSON report

Token/API-URL resolution precedence for every command: an explicit CLI flag,
then the WVS_API_TOKEN/WVS_API_URL environment variable (both handled
natively by click's envvar= support), then the locally-stored config file
written by `wvs login` (~/.wvs/config.json) - never silently falling back to
an unauthenticated request.
"""
import json
import os
import pathlib

import click
import requests

DEFAULT_API_URL = "http://127.0.0.1:5000"
CONFIG_PATH = pathlib.Path.home() / ".wvs" / "config.json"
# WR-03: every requests.get/requests.post call below passes timeout= this
# value - without it, an unresponsive server, dropped connection, or
# misconfigured --api-url makes any wvs command hang indefinitely, which is
# a real problem for a tool meant to be piped/redirected by CI tooling (CI
# pipelines need bounded-time failures, not indefinite hangs).
# requests.Timeout is already a subclass of requests.RequestException, so
# the existing `except requests.RequestException` blocks below already
# catch it, but only once timeout= is actually supplied.
REQUEST_TIMEOUT_SECONDS = 15


def _load_config():
    """Returns the parsed JSON dict from CONFIG_PATH, or {} if the file
    doesn't exist or fails to parse - a missing/corrupt config is
    equivalent to "not logged in yet", not a crash."""
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_config(data):
    """Writes data as JSON to CONFIG_PATH, creating its parent directory if
    needed, then best-effort chmod 0600 (POSIX only - never crashes the
    command if chmod isn't supported, e.g. on Windows)."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f)
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def _resolve_token(cli_token):
    """Precedence: cli_token (already flag-or-envvar resolved by click's own
    envvar= support) > stored config file value. Raises a clean
    ClickException (never an unhandled exception) if nothing resolves."""
    if cli_token:
        return cli_token
    token = _load_config().get("token")
    if token:
        return token
    raise click.ClickException(
        "No API token found - run `wvs login` first, or pass --token / set "
        "WVS_API_TOKEN."
    )


def _resolve_api_url(cli_url):
    """Precedence: cli_url (flag-or-envvar) > stored config file value >
    DEFAULT_API_URL."""
    if cli_url:
        return cli_url
    return _load_config().get("api_url") or DEFAULT_API_URL


def _raise_for_error_response(resp):
    """Parses the API's JSON error envelope ({"error": "..."}) and raises a
    clean click.ClickException - never lets a non-2xx response or a network
    error surface as an unhandled Python traceback."""
    try:
        message = resp.json().get("error", resp.text)
    except ValueError:
        message = resp.text
    raise click.ClickException(message)


@click.group()
def cli():
    """wvs - thin CLI client for WebVulnScanner's /api/v1 surface. Talks
    only to the HTTP API, never imports Flask or webvulnscanner directly."""


@cli.command("login")
@click.option("--token", envvar="WVS_API_TOKEN", default=None)
@click.option("--api-url", envvar="WVS_API_URL", default=None)
def login(token, api_url):
    """Validate a token against the live API and persist it locally on
    success only."""
    if not token:
        token = click.prompt("API token", hide_input=True)
    if not api_url:
        # WR-04: fall back to a previously-saved api_url (same precedence
        # _resolve_api_url() already uses for every other command) before
        # DEFAULT_API_URL - otherwise a plain `wvs login` re-run (e.g. to
        # rotate an expiring token) silently overwrites a previously
        # configured custom --api-url with http://127.0.0.1:5000.
        api_url = _load_config().get("api_url") or DEFAULT_API_URL

    try:
        resp = requests.get(
            f"{api_url}/api/v1/assets",
            headers={"Authorization": f"Bearer {token}"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise click.ClickException(f"Could not reach {api_url}: {exc}") from exc

    if resp.status_code == 200:
        _save_config({"token": token, "api_url": api_url})
        click.echo("Logged in.")
        return

    try:
        message = resp.json().get("error", resp.text)
    except ValueError:
        message = resp.text
    raise click.ClickException(f"Login failed: {message}")


@cli.group()
def assets():
    """Manage/list Assets."""


@assets.command("list")
@click.option("--token", envvar="WVS_API_TOKEN", default=None)
@click.option("--api-url", envvar="WVS_API_URL", default=None)
def assets_list(token, api_url):
    """Print the caller's scoped Assets and each one's latest scan
    status."""
    token = _resolve_token(token)
    api_url = _resolve_api_url(api_url)

    try:
        resp = requests.get(
            f"{api_url}/api/v1/assets",
            headers={"Authorization": f"Bearer {token}"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise click.ClickException(f"Could not reach {api_url}: {exc}") from exc

    if resp.status_code != 200:
        _raise_for_error_response(resp)
        return

    for a in resp.json()["assets"]:
        latest = a.get("latest_scan")
        if latest is None:
            status = "no scans yet"
        else:
            status = f"{latest['status']} (risk_score={latest['risk_score']})"
        click.echo(f"{a['name']} ({a['target_url']}) - {status}")


@cli.group()
def scan():
    """Trigger and inspect scans."""


@scan.command("start")
@click.argument("asset_id", type=int)
@click.option("--token", envvar="WVS_API_TOKEN", default=None)
@click.option("--api-url", envvar="WVS_API_URL", default=None)
def scan_start(asset_id, token, api_url):
    """Trigger a scan against an existing Asset and print the created
    scan's id/status."""
    token = _resolve_token(token)
    api_url = _resolve_api_url(api_url)

    try:
        resp = requests.post(
            f"{api_url}/api/v1/assets/{asset_id}/scans",
            headers={"Authorization": f"Bearer {token}"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise click.ClickException(f"Could not reach {api_url}: {exc}") from exc

    if resp.status_code != 202:
        _raise_for_error_response(resp)
        return

    body = resp.json()
    click.echo(f"Scan {body['scan_id']} started (status: {body['status']}).")


@cli.group()
def report():
    """Fetch scan reports."""


@report.command("get")
@click.argument("scan_id", type=int)
@click.option("--token", envvar="WVS_API_TOKEN", default=None)
@click.option("--api-url", envvar="WVS_API_URL", default=None)
def report_get(scan_id, token, api_url):
    """Fetch and pretty-print a scan's structured JSON report to stdout -
    meant to be piped/redirected by CI tooling."""
    token = _resolve_token(token)
    api_url = _resolve_api_url(api_url)

    try:
        resp = requests.get(
            f"{api_url}/api/v1/scans/{scan_id}/report",
            headers={"Authorization": f"Bearer {token}"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise click.ClickException(f"Could not reach {api_url}: {exc}") from exc

    if resp.status_code != 200:
        _raise_for_error_response(resp)
        return

    click.echo(json.dumps(resp.json(), indent=2))


if __name__ == "__main__":
    cli()
