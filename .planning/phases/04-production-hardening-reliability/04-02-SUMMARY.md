---
phase: 04-production-hardening-reliability
plan: 02
subsystem: infra
tags: [flask-limiter, redis, fakeredis, rate-limiting, gunicorn, testing]

requires:
  - phase: 04-production-hardening-reliability
    provides: "04-01's scan_engine.py hardening (shared scoring helper, orchestrator test coverage) — no direct dependency, sibling wave-1 plan"
provides:
  - "A proof that RATELIMIT_STORAGE_URI actually shares rate-limit counters across independent Flask-Limiter instances, simulating >1 gunicorn worker"
  - "redis production dependency, fakeredis + lupa test-only dependencies"
  - "Boot-time log line naming the active rate-limit storage backend (scheme only)"
  - "Corrected extensions.py comment describing the real storage-backend mechanism"
affects: [deployment, production-readiness, HARD-01]

actuals:
  tokens: 3270
  tasks: 2
  commits: 2

tech-stack:
  added: [redis, fakeredis, lupa]
  patterns:
    - "Two independently-constructed Limiter+Flask-app pairs, never routed through create_app()/webvulnscanner.extensions.limiter, used to simulate separate gunicorn worker processes in a unit test"
    - "monkeypatch redis.from_url (not any flask_limiter/limits API) as the sole client-injection point for fakeredis"
    - "Boot-time log line prints only a config value's URI scheme, never the full value, when the value may carry credentials"

key-files:
  created:
    - tests/test_ratelimit_storage.py
  modified:
    - requirements.txt
    - requirements-dev.txt
    - webvulnscanner/extensions.py
    - webvulnscanner/__init__.py
    - .planning/phases/04-production-hardening-reliability/04-RESEARCH.md

key-decisions:
  - "Added lupa (bare, unpinned) to requirements-dev.txt mid-execution, verified via a human package-legitimacy checkpoint — fakeredis's EVAL/EVALSHA support (which limits' RedisStorage.incr() calls unconditionally, for every rate-limit check regardless of window strategy) requires it, and there was no way to prove the real Flask-Limiter/limits code path with fakeredis without it"
  - "No fallback-to-memory path added for an unreachable Redis URL — Flask-Limiter's existing loud boot failure is preserved intentionally (T-04-07)"
  - "Boot log logs the storage URI's scheme only, never the full URI, since a redis:// URL routinely carries a password (T-04-06)"

patterns-established:
  - "Package-legitimacy checkpoint protocol: when a blocking issue is only fixable by adding a new, previously-unplanned dependency, stop and get explicit human verification before installing, even under an otherwise-autonomous plan"

requirements-completed: [HARD-01]

coverage:
  - id: D1
    description: "Two independently-constructed Limiter instances sharing a redis:// storage_uri (fakeredis-backed) observe the same counter — proves RATELIMIT_STORAGE_URI actually enables cross-worker-safe rate limiting"
    requirement: "HARD-01"
    verification:
      - kind: unit
        ref: "tests/test_ratelimit_storage.py::test_two_independent_limiters_share_a_counter_via_fakeredis"
        status: pass
    human_judgment: false
  - id: D2
    description: "Negative control: two Limiter instances with the in-memory default do NOT share a counter, guarding against the shared-Limiter-object false-pass"
    requirement: "HARD-01"
    verification:
      - kind: unit
        ref: "tests/test_ratelimit_storage.py::test_two_independent_limiters_do_not_share_a_counter_with_in_memory_storage"
        status: pass
    human_judgment: false
  - id: D3
    description: "Config.RATELIMIT_STORAGE_URI is the exact key Flask-Limiter reads (pinned against flask_limiter.constants.ConfigVars.STORAGE_URI, not a hardcoded string) and defaults to empty string when unset"
    requirement: "HARD-01"
    verification:
      - kind: unit
        ref: "tests/test_ratelimit_storage.py::test_flask_limiter_reads_the_exact_config_key_the_app_writes"
        status: pass
      - kind: unit
        ref: "tests/test_ratelimit_storage.py::test_ratelimit_storage_uri_defaults_to_empty_string"
        status: pass
    human_judgment: false
  - id: D4
    description: "Mutation proof: the positive shared-counter test genuinely fails (200 instead of 429) when pointed at memory:// instead of the fakeredis-backed redis:// URI, and passes again when reverted"
    requirement: "HARD-01"
    verification:
      - kind: manual_procedural
        ref: "Manually edited storage_uri to memory:// in test_two_independent_limiters_share_a_counter_via_fakeredis, ran pytest, observed AssertionError: assert 200 == 429, then reverted and reran (see Deviations section for full transcript)"
        status: pass
    human_judgment: false
  - id: D5
    description: "Boot-time log line names the active rate-limit storage backend's scheme (redis:// or in-memory) without ever printing the full URI/password"
    requirement: "HARD-01"
    verification:
      - kind: manual_procedural
        ref: "Ran create_app() locally with RATELIMIT_STORAGE_URI=redis://:secretpass@localhost:6379/0 and INFO logging enabled; observed 'Rate limiting: using redis:// storage backend (shared across workers)' with no password in the output"
        status: pass
    human_judgment: false

duration: ~15min (this session's continuation; prior cut-off session's duration not tracked)
completed: 2026-08-13
status: complete
---

# Phase 04 Plan 02: Multi-worker rate-limit storage proof Summary

**Proved `RATELIMIT_STORAGE_URI` genuinely shares rate-limit counters across independent Flask-Limiter instances via a fakeredis-backed test (no Redis server, no Docker), shipped `redis`/`fakeredis`/`lupa` as the supporting dependencies, and made the active storage backend observable at boot without ever logging a credential.**

## Performance

- **Duration:** ~15min (continuation of a session cut off by a prior session limit; original session's duration not tracked)
- **Started:** 2026-08-13 (continuation)
- **Completed:** 2026-08-13T19:15:53+01:00
- **Tasks:** 2/2 completed
- **Files modified:** 6 (1 new test file, 4 modified source/config files, 1 modified research doc)

## Accomplishments
- Landed the two-Limiter fakeredis shared-counter proof (`tests/test_ratelimit_storage.py`), its in-memory negative control, and the `Config.RATELIMIT_STORAGE_URI` vs `flask_limiter.constants.ConfigVars.STORAGE_URI` wiring assertion — all passing, with the required mutation proof run and recorded.
- Discovered and resolved a real gap in the plan's research: `limits`' `RedisStorage.incr()` calls a registered Lua script unconditionally on every rate-limit check (not just for moving/sliding-window strategies), which `fakeredis` only supports via its optional `lupa` extra. Added `lupa` to `requirements-dev.txt` after an explicit human package-legitimacy checkpoint.
- Rewrote `extensions.py`'s stale "fine for single dev-server-process reality" comment on the `limiter` singleton to describe the real, now-proven mechanism.
- Added a boot-time `logging.info` line in `create_app()` naming the active rate-limit storage backend (URI scheme only — never the full URI, which may carry a Redis password).
- Full suite green at 296 passed both before and after Task 2 (up from the plan's stated 260-test baseline, reflecting tests added by 04-01 and this plan).

## Task Commits

Each task was committed atomically:

1. **Task 1: End-to-end "two workers, one shared counter"** - `81494ea` (test)
2. **Task 2: Make the backend in use observable, correct the stale comment** - `6174413` (docs+feat)

**Plan metadata:** commit pending (this SUMMARY + STATE/ROADMAP update)

## Files Created/Modified
- `tests/test_ratelimit_storage.py` - New: the two-Limiter fakeredis shared-counter proof, in-memory negative control, and config-key wiring assertions (HARD-01)
- `requirements.txt` - Added `redis` (bare, unpinned) — production dependency for a Render deploy with `RATELIMIT_STORAGE_URI` set
- `requirements-dev.txt` - Added `fakeredis` and `lupa` (bare, unpinned) — test-only, never needed at runtime
- `webvulnscanner/extensions.py` - Replaced the stale in-memory-only `limiter` comment with the real, proven storage-backend mechanism
- `webvulnscanner/__init__.py` - Added a boot-time log line after `limiter.init_app(app)` naming the storage backend's scheme
- `.planning/phases/04-production-hardening-reliability/04-RESEARCH.md` - Recorded `lupa` in the Standard Stack and Package Legitimacy Audit tables (deviation from the original research, discovered during execution)

## Decisions Made
- **Added `lupa` as a new, previously-unplanned dependency mid-execution.** `limits`' `RedisStorage.incr()` (the method Flask-Limiter calls on every rate-limited request) always executes via a registered Lua script, regardless of fixed/moving/sliding-window strategy — confirmed by reading `limits/storage/redis.py`. `fakeredis` 2.37.0 only implements `EVAL`/`EVALSHA`/`SCRIPT` when `lupa` is importable (`fakeredis/commands_mixins/scripting_mixin.py` does an unconditional `import lupa`); without it every rate-limited request against a fakeredis-backed client raises `redis.exceptions.ResponseError: unknown command 'evalsha'`. There was no way to satisfy the plan's must-haves (a real end-to-end proof through actual Flask-Limiter + actual `limits` code, monkeypatched only at `redis.from_url`) without this package. Per the plan's own T-04-SC threat-register row ("Any additional package an executor introduces invalidates this row and must re-run the Package Legitimacy Gate first"), execution paused for an explicit human-verify checkpoint before installing. Approved; `lupa` is a 15+-year-old package maintained by a well-known Cython core contributor (`scoder`/Stefan Behnel), and is fakeredis's own documented extra for this exact purpose.
- **No startup connectivity check or memory-fallback added**, per the plan's explicit instruction — an unreachable/misconfigured Redis URL must fail loudly at boot rather than silently downgrading to private per-worker counters.
- **Boot log prints scheme only**, never the full `RATELIMIT_STORAGE_URI` value, to avoid leaking a Redis password into logs.

## Deviations from Plan

### Auto-fixed / Escalated Issues

**1. [Rule 3 exclusion → human-verify checkpoint] `fakeredis` requires the `lupa` extra for Lua-script support that `limits`' Redis storage depends on unconditionally**
- **Found during:** Task 1, first run of `pytest tests/test_ratelimit_storage.py -x -q`
- **Issue:** The already-written test (from the prior cut-off session) failed with `redis.exceptions.ResponseError: unknown command 'evalsha'` on the very first rate-limited request. Root cause: `limits.storage.redis.RedisStorage.incr()` always calls a registered Lua script (`SCRIPT_INCR_EXPIRE`) for atomic increment+expire, for every strategy — not an implementation detail 04-RESEARCH.md's Pattern 1/Pitfall 2 sections anticipated. `fakeredis` 2.37.0 only supports `EVAL`/`EVALSHA` when its `lupa` extra is installed.
- **Fix:** Per deviation Rule 3's explicit package-install exclusion, execution paused and returned a `checkpoint:human-verify` (gate `blocking-human`) documenting the root cause, confirming `lupa`'s legitimacy (PyPI, 15+ years, `github.com/scoder/lupa`, fakeredis's own documented extra), and proposing to add it to `requirements-dev.txt`. The coordinator verified and approved. `lupa` was then installed and added to `requirements-dev.txt`; `04-RESEARCH.md`'s Standard Stack and Package Legitimacy Audit tables were updated to record it.
- **Files modified:** `requirements-dev.txt`, `.planning/phases/04-production-hardening-reliability/04-RESEARCH.md`
- **Verification:** `pytest tests/test_ratelimit_storage.py -x -q` — 4 passed (previously 1 failed). Full suite (`pytest -q`) — 296 passed both after Task 1 and after Task 2.
- **Committed in:** `81494ea` (Task 1 commit — `lupa` install and research-doc update bundled with the test file's own commit, since the checkpoint blocked Task 1's own completion)

**2. [Verification-only] Plan's Task 1 acceptance-criteria string check is stricter than its own required docstring content**
- **Found during:** Running Task 1's literal acceptance-criteria check: `assert 'webvulnscanner.extensions' not in t and 'create_app' not in t`
- **Issue:** The check failed because the test module's docstring — which the plan's own Task 1 action step 4 explicitly requires to explain *why* `webvulnscanner.extensions.limiter` and `create_app()` are deliberately not used — necessarily contains those two substrings as prose, not as actual imports/calls.
- **Fix:** No code change. Verified the true intent (no actual `import` of `webvulnscanner.extensions`, no actual `create_app()` call) via an AST-based check instead of a substring search — both are absent from real code, confirming the test only ever mentions them in comments/docstring, matching the plan's `must_haves` truth #5 in spirit.
- **Files modified:** None — verification-only finding, no fix required.
- **Committed in:** N/A (no code change)

---

**Total deviations:** 2 (1 escalated to a human-verify checkpoint and resolved with coordinator approval; 1 verification-methodology note with no code impact).
**Impact on plan:** The `lupa` addition was necessary for the plan's own must-haves to be satisfiable at all — not scope creep, a genuine gap in pre-execution research now closed and documented. No change to the plan's actual deliverables, threat model, or scope.

## Issues Encountered
None beyond the two items above.

## User Setup Required
None - no external service configuration required. (Provisioning an actual Redis instance and setting `RATELIMIT_STORAGE_URI` on Render, and raising gunicorn's `--workers` count, remain deliberate future operator decisions outside this plan's scope, per 04-RESEARCH.md's State of the Art section. Plan 04-05's documentation-reconciliation task should record: the `RATELIMIT_STORAGE_URI` env var, that its value is a `redis://[:password]@host:port[/db]` URL, that it must be set *before* raising the worker count above 1, and that leaving it unset preserves today's single-worker behavior unchanged.)

## Next Phase Readiness
HARD-01 is complete and proven. `render.yaml`, `Procfile`, and `.env.example` are untouched — no deployment behavior changed. The app is now safe to run behind >1 gunicorn worker *once* an operator provisions Redis and sets `RATELIMIT_STORAGE_URI` (a separate, later step). No blockers for subsequent phase-04 plans.

---
*Phase: 04-production-hardening-reliability*
*Completed: 2026-08-13*
