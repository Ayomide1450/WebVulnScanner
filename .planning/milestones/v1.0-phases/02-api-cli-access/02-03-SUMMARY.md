---
phase: 02-api-cli-access
plan: 03
subsystem: cli
tags: [click, requests, http-client, cli]

requires:
  - phase: 02-api-cli-access
    provides: "02-01/02-02's full /api/v1/* surface - GET /assets, POST /assets/<id>/scans, GET /scans/<id>/report, Bearer-token auth"
provides:
  - "cli/wvs.py - standalone, pure-HTTP-client CLI (login, assets list, scan start, report get)"
  - "requirements.txt - click as an explicit direct dependency"
affects: []

actuals:
  tokens: 3413
  tasks: 2
  commits: 2

tech-stack:
  added: [click]
  patterns:
    - "Token/API-URL resolution precedence: CLI flag > env var (click's native envvar= support) > locally-stored ~/.wvs/config.json > DEFAULT_API_URL (api_url only) - never silently unauthenticated"
    - "Every requests.* call site wrapped in try/except-and-raise-click.ClickException - non-2xx responses and network errors both become a clean, nonzero-exit CLI error, never a raw traceback"
    - "Config file never touched during tests - CONFIG_PATH monkeypatched to a tmp_path location per test, no real ~/.wvs/ read/write in the suite"

key-files:
  created:
    - cli/__init__.py
    - cli/wvs.py
    - tests/test_cli.py
  modified:
    - requirements.txt
    - .planning/REQUIREMENTS.md

key-decisions:
  - "cli/ is a standalone top-level package, sibling to glassbox/, not nested inside it - matches 02-RESEARCH.md's Recommended Project Structure and Architectural Responsibility Map (Client tier: HTTP only, never imports Flask/glassbox)"
  - "Plain executable script (python cli/wvs.py ...), no pyproject.toml console-script entry point - this repo has no packaging infrastructure today, per 02-RESEARCH.md's Alternatives Considered"
  - "login has its own token/api-url resolution (prompts if unresolved) rather than reusing _resolve_token/_resolve_api_url, since falling back to stale stored config during a fresh login attempt would defeat the point of logging in"

patterns-established:
  - "CLI-as-pure-HTTP-client boundary: zero Flask/glassbox import anywhere in cli/wvs.py, verified by the full pytest suite staying green with no import-time side effects"

requirements-completed: [API-06]

coverage:
  - id: D1
    description: "wvs login validates a token against the live GET /api/v1/assets endpoint and, on success, persists it locally so subsequent commands don't require repeating --token every time"
    requirement: "API-06"
    verification:
      - kind: unit
        ref: "tests/test_cli.py#test_login_success_writes_config"
        status: pass
      - kind: unit
        ref: "tests/test_cli.py#test_login_failure_writes_no_config"
        status: pass
    human_judgment: false
  - id: D2
    description: "wvs assets list prints the caller's scoped Assets and each one's latest scan status without opening a browser"
    requirement: "API-06"
    verification:
      - kind: unit
        ref: "tests/test_cli.py#test_assets_list_after_login_prints_assets"
        status: pass
    human_judgment: false
  - id: D3
    description: "wvs scan start <asset-id> triggers a scan via POST /api/v1/assets/<id>/scans and prints the created scan's id/status"
    requirement: "API-06"
    verification:
      - kind: unit
        ref: "tests/test_cli.py#test_scan_start_success_prints_scan_id_status"
        status: pass
    human_judgment: false
  - id: D4
    description: "wvs report get <scan-id> fetches and prints the structured JSON report via GET /api/v1/scans/<id>/report"
    requirement: "API-06"
    verification:
      - kind: unit
        ref: "tests/test_cli.py#test_report_get_success_pretty_prints_json"
        status: pass
    human_judgment: false
  - id: D5
    description: "Every command resolves its token/API URL with the same precedence: explicit CLI flag, then WVS_API_TOKEN/WVS_API_URL env var, then the locally-stored config file - never silently falling back to no auth"
    requirement: "API-06"
    verification:
      - kind: unit
        ref: "tests/test_cli.py#test_assets_list_explicit_flags_override_config"
        status: pass
      - kind: unit
        ref: "tests/test_cli.py#test_assets_list_no_token_anywhere_exits_nonzero_no_request"
        status: pass
    human_judgment: false
  - id: D6
    description: "The CLI is a pure HTTP client (imports only click/requests/stdlib) with zero Flask or glassbox package imports, matching 02-RESEARCH.md's Architectural Responsibility Map"
    requirement: "API-06"
    verification:
      - kind: unit
        ref: "grep -c 'import glassbox\\|from glassbox\\|import flask\\|from flask' cli/wvs.py -> 0 matches (manual code inspection, not an automated test assertion)"
        status: pass
    human_judgment: true
    rationale: "The zero-import constraint was verified by reading cli/wvs.py's import block directly (click, requests, json, os, pathlib only) rather than a dedicated automated grep-assertion test - flagging as human-judgment since no test enforces this invariant going forward."
  - id: D7
    description: "A non-2xx API response (401/403/404/429/5xx) produces a clear, non-traceback CLI error message and a nonzero exit code, never an unhandled Python exception"
    requirement: "API-06"
    verification:
      - kind: unit
        ref: "tests/test_cli.py#test_login_failure_writes_no_config"
        status: pass
      - kind: unit
        ref: "tests/test_cli.py#test_scan_start_error_exits_nonzero_no_traceback"
        status: pass
      - kind: unit
        ref: "tests/test_cli.py#test_report_get_error_exits_nonzero_no_traceback"
        status: pass
    human_judgment: false

duration: 10min
completed: 2026-08-11
status: complete
---

# Phase 2 Plan 3: CLI Summary

**Thin, standalone `cli/wvs.py` HTTP client over `/api/v1/*` - `login`, `assets list`, `scan start`, `report get` - closing the final Phase 2 requirement (API-06) with zero Flask/glassbox import**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-08-11T09:55 (prior commit `af5bc11`, orchestrator's STATE/ROADMAP sync)
- **Completed:** 2026-08-11T10:04:06+01:00
- **Tasks:** 2
- **Files modified:** 4 (`cli/__init__.py`, `cli/wvs.py`, `requirements.txt`, `tests/test_cli.py`)

## Accomplishments
- `cli/__init__.py` / `cli/wvs.py`: a standalone, sibling-to-`glassbox/` package shipping a `click`-based CLI (`login`, `assets list`, `scan start`, `report get`) that is a pure HTTP client over `/api/v1/*` — imports only `click`, `requests`, and stdlib
- `wvs login` validates a token against the live `GET /api/v1/assets` and persists `{"token", "api_url"}` to `~/.wvs/config.json` only on a 200 response; writes nothing on failure
- Token/API-URL resolution precedence enforced identically across every command: CLI flag > `WVS_API_TOKEN`/`WVS_API_URL` env var (via click's native `envvar=`) > stored config > `DEFAULT_API_URL` (URL only) — a missing token raises a clean `click.ClickException` telling the user to run `wvs login` first, never a silent unauthenticated request
- `wvs assets list` / `wvs scan start <id>` / `wvs report get <id>` each wrap their `requests.*` call in the same try/except-and-raise-`ClickException` shape, so a non-2xx response or network error always produces a clean, nonzero-exit message — never a raw Python traceback
- `requirements.txt`: `click` added as an explicit direct dependency (previously only resolved transitively via Flask)
- `tests/test_cli.py`: 9 new tests, all mocked-HTTP (`unittest.mock.patch` on `cli.wvs.requests.get`/`.post`), `CONFIG_PATH` monkeypatched to `tmp_path` per test — no live server dependency, no real `~/.wvs/` touched
- Full suite: 208/208 passing (199 pre-existing + 9 new)

## Task Commits

Each task was committed atomically:

1. **Task 1: CLI foundation - config resolution, login, assets list** - `9d28985` (feat)
2. **Task 2: CLI scan trigger + report fetch** - `c66e21e` (feat)

**Plan metadata:** this SUMMARY.md (committed separately per execute-plan.md's final-commit step)

## Files Created/Modified
- `cli/__init__.py` - package marker for the standalone `cli/` package (new)
- `cli/wvs.py` - click entrypoint: `login`, `assets list`, `scan start`, `report get` (new)
- `requirements.txt` - adds `click`
- `tests/test_cli.py` - 9 new tests: 2 login, 3 assets list, 2 scan start, 2 report get (new)
- `.planning/REQUIREMENTS.md` - API-06 marked complete (checkbox + traceability table)

## Decisions Made
No new architectural decisions beyond what 02-RESEARCH.md already locked - the plan's action text was followed exactly:
- `cli/` is a standalone top-level package (sibling of `glassbox/`), a plain executable script with no `pyproject.toml` console-script entry point, per 02-RESEARCH.md's Alternatives Considered (this repo has no packaging infrastructure today).
- `login`'s own token/api-url resolution intentionally does **not** reuse `_resolve_token`/`_resolve_api_url` (which fall back to stored config) — falling back to a stale stored token during a fresh login attempt would defeat the purpose of logging in; `login` prompts (`click.prompt(hide_input=True)`) if the token is still unresolved after flag/env, and falls back straight to `DEFAULT_API_URL` for the URL without prompting, exactly as the plan specified.

## Deviations from Plan

None — plan executed exactly as written. Both tasks' `<action>` and `<verify>` sections were followed verbatim; no Rule 1-4 auto-fixes were needed.

## Issues Encountered
None. Both tasks' `<verify>` commands passed on first implementation; the full suite (`pytest`, run via the sibling checkout's venv since this worktree has no local `.venv`) was green (208/208) after Task 2 with no regressions to any of the 199 pre-existing tests.

## User Setup Required
None — no external service configuration required (no new env vars; `click` was already resolved transitively via Flask, so no new install footprint).

## Next Phase Readiness
API-01 through API-06 are all complete — this was the final plan in Phase 2 (api-cli-access). A security engineer can now generate/revoke a token from the web UI, then authenticate, list assets, trigger a scan, and fetch a report entirely from the command line via `python cli/wvs.py login|assets list|scan start|report get`, with no browser required at any step after initial token creation.

---
*Phase: 02-api-cli-access*
*Completed: 2026-08-11*

## Self-Check: PASSED

All created/modified files (`cli/__init__.py`, `cli/wvs.py`, `requirements.txt`, `tests/test_cli.py`,
`.planning/REQUIREMENTS.md`, this SUMMARY.md) exist on disk. Both task commits (`9d28985`, `c66e21e`)
are present in `git log`.
