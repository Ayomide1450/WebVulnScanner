"""glassbox - the Glassbox CLI. A security control plane for developers and
security engineers, not a fake terminal: every command below is a thin
client over Glassbox's existing /api/v1 HTTP surface (api_routes.py) and
its existing engine (scan_engine.py/scan_routes.py) - this module never
imports Flask or webvulnscanner directly, and never executes arbitrary
code of any kind. It talks to a server; it does not become one.

Workflow this CLI is built around:

    Build -> Check -> Assess -> Gate -> Deploy -> Verify

    glassbox check .                      local, no server call - secrets
                                           left in source before you commit
    glassbox assess <url>                 launch a full assessment
    glassbox readiness <url>              is this target production-ready?
    glassbox gate <url> --fail-on high    CI/CD security gate, real exit codes
    glassbox verify <url>                 re-assess + diff against the last run
    glassbox compare <id> <id>            diff two specific assessments
    glassbox findings                     list findings from the latest assessment
    glassbox report                       export a full assessment report
    glassbox login / logout               credential management

Commands:
    glassbox init                 - interactive first-time setup (token + defaults)
    glassbox login                 - authenticate and persist a token locally
    glassbox logout                - forget the locally stored token
    glassbox check <path>          - local, offline check for hardcoded secrets (no server call)
    glassbox assess <url>          - launch a new assessment and wait for it to finish
    glassbox readiness <url>       - print the production-readiness verdict for a target
    glassbox gate <url>            - assess + enforce a severity threshold; exit 1 on failure
    glassbox findings [<url>]      - list findings from the latest (or given) assessment
    glassbox verify <url>          - assess again and diff against the previous assessment
    glassbox compare <id> <id>     - diff two specific assessment ids
    glassbox report [<url>]        - fetch/export a full assessment report (JSON, or --csv)

    Lower-level (unchanged, still supported):
    glassbox assets list           - list the caller's scoped Assets
    glassbox scan start <asset-id> - trigger a scan against an existing Asset
    glassbox report get <scan-id>  - fetch one scan's structured JSON report

Token/API-URL resolution precedence for every command: an explicit CLI flag,
then the GLASSBOX_API_TOKEN/GLASSBOX_API_URL environment variable (both
handled natively by click's envvar= support), then the locally-stored
config file written by `glassbox login`/`glassbox init`
(~/.glassbox/config.json) - never silently falling back to an
unauthenticated request. The legacy WVS_API_TOKEN/WVS_API_URL env vars
still work too, checked after the GLASSBOX_ ones, so an existing CI
pipeline configured before this rename doesn't break.

Authorization: every assessment-launching command (assess/gate/verify)
requires the same explicit "I own or am authorized to test this domain"
confirmation the web UI's checkbox requires - passed as `authorized: true`
in the API request body (see api_routes.py's POST /api/v1/scans docstring).
There is no flag to skip this. Destructive/unauthorized testing is refused
by the server regardless of what this client sends (checks.
is_ssrf_safe_hostname, entitlements.py's tier/domain-verification gates)
- this client cannot bypass those, only trigger the same checks a browser
would.
"""
import json
import os
import pathlib
import re
import sys
import time

import click
import requests

DEFAULT_API_URL = "http://127.0.0.1:5000"
CONFIG_DIR = pathlib.Path.home() / ".glassbox"
CONFIG_PATH = CONFIG_DIR / "config.json"
_LEGACY_CONFIG_PATH = pathlib.Path.home() / ".wvs" / "config.json"
# WR-03 (Phase 2): every requests.get/requests.post call below passes
# timeout= this value - without it, an unresponsive server, dropped
# connection, or misconfigured --api-url makes any command hang
# indefinitely, which is a real problem for a tool meant to be piped/
# redirected by CI tooling (CI pipelines need bounded-time failures, not
# indefinite hangs). requests.Timeout is already a subclass of
# requests.RequestException, so the existing `except requests.
# RequestException` blocks below already catch it.
REQUEST_TIMEOUT_SECONDS = 15

# How long `assess`/`gate`/`verify` will poll a running scan before giving
# up and exiting non-zero with a clear timeout message, rather than hanging
# forever - a CI job needs a bounded worst case. Base scans in this app
# typically finish in well under a minute; 10 minutes covers a slow/large
# target with real margin without risking a false "stuck" report on a
# merely-busy one.
POLL_TIMEOUT_SECONDS = 600
POLL_INTERVAL_SECONDS = 3

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Local, standalone secret-pattern list for `glassbox check` (offline, no
# server call) - intentionally NOT imported from checks.py's
# check_exposed_secrets: that function is tightly coupled to a live HTTP
# response (requests.Session, response text/headers) and this module's own
# docstring is explicit that it never imports Flask/webvulnscanner - a CLI
# a developer runs against their own local source tree is a genuinely
# different code path (files on disk, not an HTTP response), not a
# duplication of the same check running twice.
_SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Generic API Key", re.compile(r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")),
    ("Generic Secret Assignment", re.compile(r"(?i)(secret|password|passwd|token)['\"]?\s*[:=]\s*['\"][^'\"\s]{8,}['\"]")),
    ("Stripe Key", re.compile(r"sk_(live|test)_[0-9A-Za-z]{16,}")),
]
# Directories never worth descending into for a local secrets sweep - not
# source, or so large/generated that scanning them is pure noise.
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".mypy_cache", ".pytest_cache"}
_MAX_FILE_BYTES = 2_000_000  # skip anything unusually large (binaries, bundles) rather than read it whole


def _load_config():
    """Returns the parsed JSON dict from CONFIG_PATH, or {} if the file
    doesn't exist or fails to parse - a missing/corrupt config is
    equivalent to "not logged in yet", not a crash. Falls back to the
    pre-rename ~/.wvs/config.json (read-only) so an existing local login
    survives the rename without forcing a re-login."""
    for path in (CONFIG_PATH, _LEGACY_CONFIG_PATH):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            continue
    return {}


def _save_config(data):
    """Writes data as JSON to CONFIG_PATH, creating its parent directory if
    needed, then best-effort chmod 0600 (POSIX only - never crashes the
    command if chmod isn't supported, e.g. on Windows)."""
    # Derived from CONFIG_PATH.parent (not the CONFIG_DIR constant) so a
    # test/caller that monkeypatches CONFIG_PATH alone (tests/test_cli.py's
    # isolated_config fixture) still gets a consistent, existing parent dir
    # - matches the original single-variable design rather than requiring
    # every such fixture to patch two constants in sync.
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
        "Not logged in - run `glassbox login` first, or pass --token / set "
        "GLASSBOX_API_TOKEN."
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


def _request(method, api_url, path, token, **kwargs):
    """One shared HTTP call path for every command below - always sets the
    Authorization header and REQUEST_TIMEOUT_SECONDS, always converts a
    network failure into a clean ClickException rather than a raw
    traceback. Dispatches to requests.get/requests.post explicitly (never
    the generic requests.request) so tests/test_cli.py's existing
    `patch.object(wvs.requests, "get"/"post")` mocking idiom keeps working
    unchanged for every command, old and new."""
    fn = {"GET": requests.get, "POST": requests.post}[method]
    try:
        return fn(
            f"{api_url}{path}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=REQUEST_TIMEOUT_SECONDS,
            **kwargs,
        )
    except requests.RequestException as exc:
        raise click.ClickException(f"Could not reach {api_url}: {exc}") from exc


_shared_token_option = click.option("--token", envvar=["GLASSBOX_API_TOKEN", "WVS_API_TOKEN"], default=None)
_shared_url_option = click.option("--api-url", envvar=["GLASSBOX_API_URL", "WVS_API_URL"], default=None)


def _prompt_secret(prompt_text):
    """Reads a credential with VISUAL FEEDBACK - one '*' echoed per typed
    or pasted character, backspace erases one '*'.

    Why not just click.prompt(hide_input=True)? On Windows terminals that
    mode shows literally nothing while you type or paste (no chars, no
    dots, no cursor movement), which reads as a frozen program - a real
    first-run user reported exactly that. This helper keeps the secret off
    the screen while still proving input is being received.

    The raw-console path runs only when stdin IS an interactive console
    (msvcrt.getwch talks to the terminal directly and would bypass/ignore
    piped input); scripts, CI, and test runners get the standard hidden
    click.prompt fallback. Non-Windows keeps click's getpass-based prompt,
    which already behaves acceptably there."""
    if os.name == "nt":
        import msvcrt

        try:
            if sys.stdin.isatty():
                click.echo(f"{prompt_text} (input hidden - shown as *): ", nl=False)
                buf = []
                while True:
                    ch = msvcrt.getwch()
                    if ch in ("\r", "\n"):
                        click.echo()
                        return "".join(buf)
                    if ch == "\x08":  # Backspace
                        if buf:
                            buf.pop()
                            click.echo("\b \b", nl=False)
                        continue
                    if ch in ("\x00", "\xe0"):  # Arrow/F-key prefix - eat next code
                        msvcrt.getwch()
                        continue
                    if ch == "\x03":  # Ctrl+C (getwch does NOT raise for it)
                        raise KeyboardInterrupt
                    if ch >= " ":  # Ignore other control codes
                        buf.append(ch)
                        click.echo("*", nl=False)
        except OSError:
            pass  # Not a real console after all - fall through to click.
    return click.prompt(prompt_text, hide_input=True)


@click.group()
def cli():
    """glassbox - a security control plane for developers and security
    engineers. Talks only to Glassbox's own HTTP API; never imports Flask/
    webvulnscanner, never executes arbitrary code."""


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------

@cli.command("login")
@_shared_token_option
@_shared_url_option
def login(token, api_url):
    """Validate a token against the live API and persist it locally on
    success only."""
    if not token:
        # First-run guidance: the single most common failure is not knowing
        # where a token comes from. Say it here, at the moment it's needed,
        # instead of assuming the user found the docs.
        click.echo("Don't have a token yet? Create one in the web app:")
        click.echo("  Log in  ->  API Tokens (top nav)  ->  Generate Token.")
        click.echo("Paste it below - each character shows as *.")
        token = _prompt_secret("API token")
    if not api_url:
        # Fall back to a previously-saved api_url before DEFAULT_API_URL -
        # otherwise a plain `glassbox login` re-run (e.g. to rotate an
        # expiring token) silently overwrites a previously configured
        # custom --api-url.
        api_url = _load_config().get("api_url") or DEFAULT_API_URL

    resp = _request("GET", api_url, "/api/v1/assets", token)
    if resp.status_code == 200:
        _save_config({"token": token, "api_url": api_url})
        click.echo("Logged in.")
        return
    _raise_for_error_response(resp)


@cli.command("logout")
def logout():
    """Forget the locally stored token (does not revoke it server-side -
    use the web UI's API Tokens page, or `glassbox` has no revoke command
    yet, to actually invalidate it)."""
    if CONFIG_PATH.exists():
        CONFIG_PATH.unlink()
        click.echo("Logged out.")
    else:
        click.echo("Not logged in.")


@cli.command("init")
@_shared_token_option
@_shared_url_option
def init(token, api_url):
    """Interactive first-time setup: same as `login`, worded for a
    developer's first run. Kept as a separate command (rather than an
    alias) since `init` is the conventional entry point in this class of
    tool and a distinct name is easier to document as "start here"."""
    click.echo("Welcome to Glassbox. Let's connect your account.")
    ctx = click.get_current_context()
    ctx.invoke(login, token=token, api_url=api_url)


# --------------------------------------------------------------------------
# glassbox check . - LOCAL, offline, no server call. Distinct in kind from
# every other command: this looks at files on disk, not a live HTTP
# target, and never talks to the API at all.
# --------------------------------------------------------------------------

@cli.command("check")
@click.argument("path", type=click.Path(exists=True, file_okay=True, dir_okay=True), default=".")
@click.option("--json", "as_json", is_flag=True, default=False)
def check(path, as_json):
    """Locally scan PATH for hardcoded secrets before you commit/deploy -
    entirely offline, no server call, no target URL. Exit 1 if anything is
    found, 0 if clean - meant to run in a pre-commit hook or CI step ahead
    of `glassbox gate`."""
    root = pathlib.Path(path)
    files = [root] if root.is_file() else [
        p for p in root.rglob("*")
        if p.is_file() and not any(part in _SKIP_DIRS for part in p.parts)
    ]

    findings = []
    for f in files:
        try:
            if f.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for name, pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append({"file": str(f), "line": line_no, "rule": name})

    if as_json:
        click.echo(json.dumps({"findings": findings, "clean": not findings}, indent=2))
    else:
        if not findings:
            click.echo(click.style("✓ No hardcoded secrets found.", fg="green"))
        else:
            click.echo(click.style(f"✗ {len(findings)} potential secret(s) found:", fg="red"))
            for f in findings:
                click.echo(f"  {f['file']}:{f['line']} - {f['rule']}")

    sys.exit(1 if findings else 0)


# --------------------------------------------------------------------------
# Shared assess/wait/report machinery - assess, gate, and verify all launch
# a scan and wait for it; findings/readiness/report all need "the latest
# scan for this URL" when a scan id isn't given explicitly. One
# implementation each, reused by every command below.
# --------------------------------------------------------------------------

def _launch_and_wait(api_url, token, target_url, quiet=False):
    """POSTs /api/v1/scans, then polls GET /api/v1/scans/<id> until it
    reaches COMPLETED or FAILED (or POLL_TIMEOUT_SECONDS elapses). Returns
    the final scan-status dict. Raises ClickException on launch failure,
    timeout, or a FAILED terminal status (with the scan's error_message if
    one was recorded)."""
    resp = _request(
        "POST", api_url, "/api/v1/scans", token,
        json={"target_url": target_url, "authorized": True},
    )
    if resp.status_code != 202:
        _raise_for_error_response(resp)
    body = resp.json()
    scan_id = body["scan_id"]
    if body.get("duplicate") and not quiet:
        click.echo(f"An assessment for {target_url} is already running (scan {scan_id}) - watching it.")
    elif not quiet:
        click.echo(f"Assessment started for {target_url} (scan {scan_id})...")

    deadline = time.monotonic() + POLL_TIMEOUT_SECONDS
    last_status = body.get("status")
    while time.monotonic() < deadline:
        status_resp = _request("GET", api_url, f"/api/v1/scans/{scan_id}", token)
        if status_resp.status_code != 200:
            _raise_for_error_response(status_resp)
        status_body = status_resp.json()
        status = status_body["status"]
        if status != last_status and not quiet:
            click.echo(f"  status: {status}")
            last_status = status
        if status == "completed":
            return status_body
        if status == "failed":
            reason = status_body.get("error_message") or "no error detail recorded"
            raise click.ClickException(f"Assessment failed: {reason}")
        time.sleep(POLL_INTERVAL_SECONDS)

    raise click.ClickException(
        f"Timed out after {POLL_TIMEOUT_SECONDS}s waiting for scan {scan_id} to finish - "
        f"check `glassbox report {scan_id}` later."
    )


def _latest_scan_for(api_url, token, target_url, before_scan_id=None):
    """Resolves "the most recent completed scan for target_url" via
    GET /api/v1/scans?target_url=... - used by findings/readiness/report
    when a scan id isn't given explicitly, and by verify to find what to
    diff a fresh assessment against. `before_scan_id` excludes that id
    (verify's own just-launched scan) so it finds the PREVIOUS run, not the
    one that just started."""
    resp = _request("GET", api_url, f"/api/v1/scans?target_url={target_url}&limit=10", token)
    if resp.status_code != 200:
        _raise_for_error_response(resp)
    for s in resp.json()["scans"]:
        if s["status"] == "completed" and s["id"] != before_scan_id:
            return s
    return None


def _fetch_report(api_url, token, scan_id):
    resp = _request("GET", api_url, f"/api/v1/scans/{scan_id}/report", token)
    if resp.status_code != 200:
        _raise_for_error_response(resp)
    return resp.json()


def _resolve_target_scan_id(api_url, token, target):
    """`target` is either a bare integer (an explicit scan id) or a URL
    (resolved to its latest completed scan) - the shape `findings`/
    `readiness`/`report` all accept as their optional argument."""
    if target is None:
        raise click.ClickException("Specify a target URL or scan id - or run `glassbox assess <url>` first.")
    try:
        return int(target)
    except ValueError:
        pass
    s = _latest_scan_for(api_url, token, target)
    if s is None:
        raise click.ClickException(f"No completed assessment found for {target} - run `glassbox assess {target}` first.")
    return s["id"]


def _print_findings(findings, severity_filter=None, confidence_filter=None):
    shown = findings
    if severity_filter:
        shown = [f for f in shown if f.get("severity") == severity_filter]
    if confidence_filter:
        shown = [f for f in shown if (f.get("confidence") or "").lower() == confidence_filter.lower()]
    if not shown:
        click.echo("No findings match.")
        return
    for f in shown:
        click.echo(f"[{f.get('severity', '?').upper()}] {f.get('category', '')}: {f.get('title', '')}")
        if f.get("detail"):
            click.echo(f"    {f['detail']}")
        if f.get("recommendation"):
            click.echo(f"    Fix: {f['recommendation']}")


# --------------------------------------------------------------------------
# assess / readiness / gate / verify / compare / findings / report
# --------------------------------------------------------------------------

@cli.command("assess")
@click.argument("url")
@click.option("--json", "as_json", is_flag=True, default=False)
@click.option("--quiet", is_flag=True, default=False)
@_shared_token_option
@_shared_url_option
def assess(url, as_json, quiet, token, api_url):
    """Launch a new assessment against URL and wait for it to finish."""
    token = _resolve_token(token)
    api_url = _resolve_api_url(api_url)
    status = _launch_and_wait(api_url, token, url, quiet=quiet or as_json)
    report = _fetch_report(api_url, token, status["id"])

    if as_json:
        click.echo(json.dumps(report, indent=2))
        return

    click.echo(f"\nScore: {report.get('score')}/100 (grade {report.get('risk_grade')})")
    counts = report.get("severity_counts", {})
    click.echo("Findings: " + ", ".join(f"{sev}={counts.get(sev, 0)}" for sev in SEVERITY_ORDER))
    if report.get("readiness_verdict"):
        click.echo(f"Readiness: {report['readiness_verdict']}")


@cli.command("readiness")
@click.argument("url")
@click.option("--json", "as_json", is_flag=True, default=False)
@_shared_token_option
@_shared_url_option
def readiness(url, as_json, token, api_url):
    """Print the production-readiness verdict for URL's most recent
    completed assessment (does not launch a new one - use `assess` or
    `gate` for that)."""
    token = _resolve_token(token)
    api_url = _resolve_api_url(api_url)
    scan_id = _resolve_target_scan_id(api_url, token, url)
    report = _fetch_report(api_url, token, scan_id)

    if as_json:
        click.echo(json.dumps({
            "readiness_verdict": report.get("readiness_verdict"),
            "check_coverage_pct": report.get("check_coverage_pct"),
            "readiness_reasons": report.get("readiness_reasons", []),
            "score": report.get("score"),
        }, indent=2))
        return

    click.echo(f"Readiness: {report.get('readiness_verdict', 'unknown')}")
    if report.get("check_coverage_pct") is not None:
        click.echo(f"Coverage: {report['check_coverage_pct']}% of applicable checks ran")
    for reason in report.get("readiness_reasons", []):
        click.echo(f"  - {reason}")


@cli.command("gate")
@click.argument("url")
@click.option("--fail-on", type=click.Choice(SEVERITY_ORDER), default="high", show_default=True,
              help="Fail (exit 1) if any finding at or above this severity is present.")
@click.option("--json", "as_json", is_flag=True, default=False)
@click.option("--quiet", is_flag=True, default=False)
@click.option("--verbose", is_flag=True, default=False)
@_shared_token_option
@_shared_url_option
def gate(url, fail_on, as_json, quiet, verbose, token, api_url):
    """CI/CD security gate: assess URL, then fail (exit 1) if any finding
    at or above --fail-on severity is present. Designed for a build
    pipeline: reliable exit codes, --json for machine consumption, --quiet
    to suppress the human-readable narration.

    The threshold evaluation itself happens SERVER-side - this command
    polls the assessment to completion, then asks
    GET /api/v1/scans/<id>/gate?fail_on=<severity> for the verdict rather
    than filtering findings locally, so the blocking rule is the exact same
    one a direct HTTP consumer gets (webvulnscanner/security_gate.py -
    defined once, never drifting between client and server)."""
    token = _resolve_token(token)
    api_url = _resolve_api_url(api_url)
    status = _launch_and_wait(api_url, token, url, quiet=quiet or as_json)

    resp = _request(
        "GET", api_url, f"/api/v1/scans/{status['id']}/gate?fail_on={fail_on}", token,
    )
    if resp.status_code != 200:
        _raise_for_error_response(resp)
    body = resp.json()
    passed = body["passed"]
    blocking = body["blocking_findings"]

    if as_json:
        click.echo(json.dumps(body, indent=2))
        sys.exit(0 if passed else 1)

    if not quiet:
        if passed:
            click.echo(click.style("✓ Security Gate Passed", fg="green"))
        else:
            click.echo(click.style("✗ Security Gate Failed", fg="red"))
            by_sev = {}
            for f in blocking:
                by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            click.echo("  " + ", ".join(f"{n} {sev}" for sev, n in by_sev.items()) + " finding(s) detected")
            if verbose:
                _print_findings(blocking)
    click.echo(f"Exit code: {0 if passed else 1}")
    sys.exit(0 if passed else 1)


@cli.command("findings")
@click.argument("url", required=False, default=None)
@click.option("--severity", type=click.Choice(SEVERITY_ORDER), default=None)
@click.option("--confidence", default=None)
@click.option("--json", "as_json", is_flag=True, default=False)
@_shared_token_option
@_shared_url_option
def findings(url, severity, confidence, as_json, token, api_url):
    """List findings from URL's (or a bare scan id's) latest completed
    assessment. Does not launch a new one."""
    token = _resolve_token(token)
    api_url = _resolve_api_url(api_url)
    scan_id = _resolve_target_scan_id(api_url, token, url)
    report = _fetch_report(api_url, token, scan_id)
    all_findings = report.get("findings", [])

    if as_json:
        shown = all_findings
        if severity:
            shown = [f for f in shown if f.get("severity") == severity]
        if confidence:
            shown = [f for f in shown if (f.get("confidence") or "").lower() == confidence.lower()]
        click.echo(json.dumps(shown, indent=2))
        return

    _print_findings(all_findings, severity, confidence)


@cli.command("verify")
@click.argument("url")
@click.option("--json", "as_json", is_flag=True, default=False)
@click.option("--quiet", is_flag=True, default=False)
@_shared_token_option
@_shared_url_option
def verify(url, as_json, quiet, token, api_url):
    """Run a new assessment against URL and diff it against the previous
    one - the "did my fix actually work, and did I break anything else"
    command. Prints Fixed/New/Regressed/Unchanged, same categories the
    web UI's compare page uses (diff_reports())."""
    token = _resolve_token(token)
    api_url = _resolve_api_url(api_url)

    previous = _latest_scan_for(api_url, token, url)
    status = _launch_and_wait(api_url, token, url, quiet=quiet or as_json)

    if previous is None:
        if not as_json:
            click.echo("No previous assessment to compare against - this is the first one for this target.")
        report = _fetch_report(api_url, token, status["id"])
        if as_json:
            click.echo(json.dumps({"first_assessment": True, "report": report}, indent=2))
        return

    resp = _request("GET", api_url, f"/api/v1/scans/{previous['id']}/compare/{status['id']}", token)
    if resp.status_code != 200:
        _raise_for_error_response(resp)
    diff = resp.json()["diff"]
    _print_compare(diff, as_json)


@cli.command("compare")
@click.argument("scan_id_a", type=int)
@click.argument("scan_id_b", type=int)
@click.option("--json", "as_json", is_flag=True, default=False)
@_shared_token_option
@_shared_url_option
def compare(scan_id_a, scan_id_b, as_json, token, api_url):
    """Diff two specific assessment ids directly."""
    token = _resolve_token(token)
    api_url = _resolve_api_url(api_url)
    resp = _request("GET", api_url, f"/api/v1/scans/{scan_id_a}/compare/{scan_id_b}", token)
    if resp.status_code != 200:
        _raise_for_error_response(resp)
    diff = resp.json()["diff"]
    _print_compare(diff, as_json)


def _print_compare(diff, as_json):
    if as_json:
        click.echo(json.dumps(diff, indent=2))
        return
    click.echo(f"Fixed:      {len(diff.get('removed', []))}")
    click.echo(f"New:        {len(diff.get('added', []))}")
    click.echo(f"Regressed:  {len(diff.get('changed', []))}")
    click.echo(f"Unchanged:  {diff.get('unchanged_count', 0)}")
    click.echo(f"Score delta: {diff.get('score_delta', 0):+d}")
    if diff.get("added"):
        click.echo("\nNew findings:")
        _print_findings(diff["added"])
    if diff.get("changed"):
        click.echo("\nRegressed findings:")
        for c in diff["changed"]:
            after = c["after"]
            click.echo(f"[{after.get('severity', '?').upper()}] {after.get('category', '')}: {after.get('title', '')}")


@cli.command("report")
@click.argument("url", required=False, default=None)
@click.option("--json", "as_json", is_flag=True, default=True)
@click.option("--csv", "as_csv", is_flag=True, default=False,
              help="Export the findings as CSV instead of JSON (served by "
                   "GET /api/v1/scans/<id>/report.csv).")
@_shared_token_option
@_shared_url_option
def report_cmd(url, as_json, as_csv, token, api_url):
    """Fetch/export URL's (or a bare scan id's) latest completed
    assessment report as JSON (default) or --csv, for piping/redirecting.
    CSV comes from the server's single shared writer
    (scan_routes.findings_csv_document), so it is byte-identical to the
    web UI's /scan/<id>/export.csv download."""
    token = _resolve_token(token)
    api_url = _resolve_api_url(api_url)
    scan_id = _resolve_target_scan_id(api_url, token, url)
    if as_csv:
        resp = _request("GET", api_url, f"/api/v1/scans/{scan_id}/report.csv", token)
        if resp.status_code != 200:
            _raise_for_error_response(resp)
        click.echo(resp.text, nl=False)
        return
    report = _fetch_report(api_url, token, scan_id)
    click.echo(json.dumps(report, indent=2))


# --------------------------------------------------------------------------
# Lower-level commands (unchanged from the original wvs CLI) - Asset-based
# scan management, kept for callers already using an Asset (scheduled/
# recurring targets) rather than the ad-hoc-URL commands above.
# --------------------------------------------------------------------------

@cli.group()
def assets():
    """Manage/list Assets."""


@assets.command("list")
@_shared_token_option
@_shared_url_option
def assets_list(token, api_url):
    """Print the caller's scoped Assets and each one's latest scan
    status."""
    token = _resolve_token(token)
    api_url = _resolve_api_url(api_url)
    resp = _request("GET", api_url, "/api/v1/assets", token)
    if resp.status_code != 200:
        _raise_for_error_response(resp)

    for a in resp.json()["assets"]:
        latest = a.get("latest_scan")
        if latest is None:
            status = "no scans yet"
        else:
            status = f"{latest['status']} (risk_score={latest['risk_score']})"
        click.echo(f"{a['name']} ({a['target_url']}) - {status}")


@cli.group()
def scan():
    """Trigger and inspect scans against an existing Asset."""


@scan.command("start")
@click.argument("asset_id", type=int)
@_shared_token_option
@_shared_url_option
def scan_start(asset_id, token, api_url):
    """Trigger a scan against an existing Asset and print the created
    scan's id/status."""
    token = _resolve_token(token)
    api_url = _resolve_api_url(api_url)
    resp = _request("POST", api_url, f"/api/v1/assets/{asset_id}/scans", token)
    if resp.status_code != 202:
        _raise_for_error_response(resp)
    body = resp.json()
    click.echo(f"Scan {body['scan_id']} started (status: {body['status']}).")


if __name__ == "__main__":
    cli()
