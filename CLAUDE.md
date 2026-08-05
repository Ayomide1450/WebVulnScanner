# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

WebVulnScanner is a local, single-user Flask app for checking your own website's security
posture. It runs only on `localhost:5000`, is never deployed anywhere, and every scan route
requires a server-side-enforced authorization checkbox before it will touch a target. See
README.md for the full list of checks and the documented false-positive fix (CDN edge ports
being misreported as exposed services) — that history matters when touching `check_open_ports`.

**Only ever test against domains the user owns or has explicit permission to test.** Do not
weaken or remove the `authorized` / `authorized_adv` / `authorized_media` server-side checks.

## Commands

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000. There is no build step, linter, or test suite configured in
this repo — it's a single Flask process with server-rendered Jinja templates.

## Architecture

Everything lives in one file, `app.py` (~1550 lines), plus four Jinja templates in
`templates/`. There is no database; every scan writes a timestamped JSON report to `reports/`
and (for media scans with download enabled) files to `downloads/`.

### Three independent scan pipelines

The app exposes three unrelated scan flows, each with its own route, orchestrator function,
report shape, and results template. They don't share state — a target is re-fetched from
scratch in each:

| Route | Orchestrator | Template | Purpose |
|---|---|---|---|
| `POST /scan` | `run_scan()` | `results.html` | Passive/recon checks: headers, TLS, cookies, ports, CORS, secrets, crawl-then-probe XSS/SQLi, etc. |
| `POST /scan-advanced` | `run_advanced_scan()` | `advanced_results.html` | Opt-in, form-field-driven checks needing credentials/session cookies: SQLi login bypass, stored XSS, IDOR across two test accounts, brute-force. Each check group only runs if its required form fields are all present. |
| `POST /scan-media` | `run_media_scan()` | `media_results.html` | Same-origin media crawl (images/video), EXIF/GPS leakage, suspicious-path detection, optional download-to-disk. |

### Check function convention

Every individual check is a plain function that returns `(data, findings)`:
- `data` is whatever raw/structured info the results template needs to render (rows, dicts).
- `findings` is a `list[Finding]` — a dataclass with `category`, `title`, `severity`
  (`critical|high|medium|low|info|pass`), `detail`, `recommendation`.

`run_scan()` fans most checks out concurrently via a `ThreadPoolExecutor` (see the `jobs` dict),
then runs `check_open_ports` separately since it does its own internal threading per-port.
When adding a new check, follow this `(data, findings)` return convention and never let a check
raise past its own function — network calls should be wrapped in
`try/except requests.RequestException` so one failing check doesn't kill the whole scan.

### Scoring

All three orchestrators independently: start at 100, subtract `SEVERITY_WEIGHT[finding.severity]`
per finding, clamp to `[0, 100]`, then map the score to a letter grade (`A`–`F`) and tally
`severity_counts`. This scoring block is duplicated three times (`run_scan`,
`run_media_scan`, `run_advanced_scan`) rather than shared — keep that in mind if changing the
formula, it needs updating in all three places.

### Adding a new base-scan check

1. Write `check_foo(...) -> (data, findings)` near the other checks in the relevant section
   (headers/cookies/network checks are grouped near the top; media checks and advanced/
   authenticated checks each have their own labeled section with a comment banner).
2. Register it in the `jobs` dict inside `run_scan()` if it can run concurrently and only needs
   `base_url`/`session`/`hostname`/`home_html`; call it directly afterward (like
   `check_open_ports`) if it needs its own threading or must run after the crawl.
2. Add its `data` to the returned report dict in `run_scan()`.
3. Render it in `templates/results.html`.

### Safety constraints baked into the design

- The crawler (`crawl_same_origin`, `crawl_media`) is same-origin only and depth-1.
- Forms are enumerated (action/method/inputs) for display but **never auto-submitted** — only
  GET requests with query parameters are sent during probing.
- `check_bruteforce` is hard-capped at `MAX_BRUTEFORCE_ATTEMPTS` (5) and stops on first success.
- Secrets found by `check_exposed_secrets` are redacted (`_redact_secret`) before being put in
  the report — the report file itself must not become a second leak of the credential.
- `check_xss_stored` proves execution via a marker string; it explicitly does not exfiltrate
  cookies even though it notes that'd be the trivial next step.
- Time-based blind SQLi checks (`TIME_BLIND_DELAY = 4`) are used sparingly and stop after the
  first confirmed hit rather than probing every DB engine once one succeeds.

Preserve these constraints when modifying the corresponding checks — they're what keeps this a
non-destructive, authorized-use-only tool rather than a general attack script.
