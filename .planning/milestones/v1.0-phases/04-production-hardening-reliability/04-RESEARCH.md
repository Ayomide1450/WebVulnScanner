# Phase 4: Production Hardening & Reliability - Research

**Researched:** 2026-08-13
**Domain:** Multi-worker rate-limit storage (Flask-Limiter/`limits`/Redis), orchestrator test
coverage (mocked-network Flask/pytest pattern), Flask-WTF/itsdangerous invite-token flow, scoring
dedup (pure-function extraction), reuse-only CSS/template consistency pass.
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**HARD-01: Multi-worker rate limiting (not discussed live — see Claude's Discretion)**
- **D-01:** Wire `Limiter`'s `storage_uri` to Redis via the already-present `RATELIMIT_STORAGE_URI`
  config value (currently read into `app.config` but not exercised by any test). Prove
  multi-worker-safety with a test that instantiates two separate `Limiter`/app instances against
  the same fake shared backend and confirms they share a counter — use an in-process fake
  (e.g. `fakeredis`) rather than a real Redis service container, to keep this repo's
  zero-external-service CI convention (`.github/workflows/tests.yml` currently needs no service
  containers, no `.env`) intact. Add `redis`/`fakeredis` to `requirements.txt`/
  `requirements-dev.txt` respectively.

**HARD-02: Orchestrator test coverage**
- **D-02:** New tests for `run_advanced_scan`/`run_media_scan`/`run_api_scan` go beyond the
  literal "status transitions and error handling" wording to also regression-lock each
  orchestrator's safety constraints (e.g. `MAX_BRUTEFORCE_ATTEMPTS` cap, stored-XSS marker-only
  proof with no cookie exfiltration, no form auto-submission) — these are the most sensitive
  checks in the app per `CONCERNS.md`'s own priority note, and losing regression coverage on the
  safety caps specifically would be worse than losing it on plain status-transition logic.
- **D-03:** All three orchestrators' tests are fully mocked — stub check functions, no real
  network calls — matching `run_scan`'s existing convention in `tests/test_scan_events.py` and
  `TESTING.md`'s documented pattern. No precedent in this suite for hitting a live test target.
- **D-04:** `run_advanced_scan` has no scheduler-triggered path to test — confirmed via
  `webvulnscanner/scheduler.py`'s `_fire()`, which only branches on `"base"`/`"media"`/`"api"`;
  there is no `"advanced"` branch, and `Asset`'s schedule model has no field for stored
  credentials. This is intentional, not a bug to fix — test `run_advanced_scan` via direct
  invocation only. `run_media_scan`/`run_api_scan` need both direct-invocation tests and
  scheduler-fired tests (extending `tests/test_scheduler.py`'s pattern, which today only exercises
  the `"base"` branch per Phase 1).

**HARD-03: Org-flow test coverage & the invite/role-change gap**
- **D-05:** Real, previously-undocumented gap found during discussion: `org_routes.py`'s
  `invite()` generates a signed token via `generate_invite_token(org_id, role)` and emails a
  link to `/signup?invite=<token>`, but `/signup` (`auth_routes.py`) never reads the `invite`
  query param at all — `decode_invite_token` is defined and never called anywhere in the
  codebase. There is also no route anywhere to change an existing member's role.
- **D-06:** Finish the invite flow as part of this phase: `/signup` gains an invite-mode branch
  that decodes the token, joins the token's `org_id` at the token's `role` (skipping/hiding the
  "create a new org" field in that mode), and is what HARD-03's "role-change... test coverage"
  is understood to mean — role *assignment* via invite, end-to-end tested. **No standalone
  route for changing an already-existing member's role gets built.**
- **D-07:** While finishing the invite flow, also close a real security gap found alongside it:
  `generate_invite_token`/`decode_invite_token` don't bind the invitee's email, so a
  leaked/forwarded invite link could be used by anyone to join the org at the granted role.
  Change the signature to `generate_invite_token(org_id, role, email)`; signup's invite-mode
  pre-fills/locks the email field and rejects a mismatch at decode time.
- **D-08:** Domain-verification flow (`org_routes.py`'s `verify_domain_view` +
  `domain_verification.py`) needs test coverage too per HARD-03's literal wording — the flow
  already exists and works, it's just untested; no discussion needed on scope here.

**HARD-04: Shared scoring helper**
- **D-09:** Not discussed live — `.planning/codebase/CONCERNS.md` already fully specifies the fix
  approach (extract `_score_report(findings) -> (risk_score, grade, severity_counts)` and call it
  from all four orchestrators in `scan_engine.py`). Treat this as settled.

**HARD-05: Visual consistency pass**
- **D-10:** Reuse-only scope — apply `base.html`'s already-built primitives (`.glow-pulse`,
  `.hud-grid`, `--telemetry`/`--telemetry2`, `.table-scroll`, `.status-pill`, etc.) to
  `dashboard.html`/`billing.html`/`org_admin.html`/`scan_report.html`. No new components or
  visual patterns get invented here.
- **D-11:** Run a dedicated `/gsd-ui-phase 4` UI-SPEC before planning, consistent with the
  precedent set by Phase 2/3 — already done; see `04-UI-SPEC.md`.

### Claude's Discretion
- HARD-01 (multi-worker rate limiting) was not selected for live discussion. D-01 above is the
  disclosed default the user saw and did not override before choosing "ready for context" — not
  a directly-confirmed decision, so research/planning should treat the Redis+fakeredis approach
  as a strong default rather than an immovable lock, and flag it back if research surfaces a
  reason to prefer something else. **Research finding: no reason surfaced to deviate — Redis is
  the only backend `limits`/Flask-Limiter documents as production-grade, and no Redis instance is
  already provisioned anywhere in this repo (no `docker-compose.yml`, no `render.yaml` Redis
  resource). Proceed with D-01 as specified.**
- Exact new-test file organization for HARD-02/HARD-03 (one file per orchestrator/flow vs.
  consolidated) is left to the planner — follow `TESTING.md`'s existing "one file per feature
  area" convention unless there's a good reason to deviate.

### Deferred Ideas (OUT OF SCOPE)
- A fuller HARD-05 redesign moment (new visual patterns beyond what `base.html` already has) —
  explicitly declined for this phase in favor of reuse-only scope (D-10).
- A standalone member role-change route (changing an existing member's role after they've
  already joined) — explicitly declined for this phase (D-06) as a new admin capability.
- Making `run_advanced_scan` schedulable — explicitly declined (D-04), bigger design question.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| HARD-01 | Rate limits enforce correctly under >1 gunicorn worker (shared backend) | Standard Stack (redis/fakeredis versions), Architecture Patterns §HARD-01, Common Pitfalls §1-2, Code Examples §1 |
| HARD-02 | `run_advanced_scan`/`run_media_scan`/`run_api_scan` get automated test coverage | Architecture Patterns §HARD-02, Common Pitfalls §3-5, Code Examples §2-4 |
| HARD-03 | Org invite / role-change / domain-verification flows get test coverage | Architecture Patterns §HARD-03, Common Pitfalls §6-8, Code Examples §5-6 |
| HARD-04 | Scoring logic deduplicated into one shared helper used by all 4 orchestrators | Architecture Patterns §HARD-04 (identity verification), Code Examples §7 |
| HARD-05 | Dashboard/billing/org-admin/scan_report visually match the design system | Architecture Patterns §HARD-05 (UI-SPEC cross-check), all verified against live template state |
</phase_requirements>

## Summary

This phase is almost entirely "how," not "what" — every locked decision already names the exact
files, functions, and fix approach. Research here is confirmatory: verifying current code state
matches what CONTEXT.md/UI-SPEC.md assumed, surfacing exact signatures/line numbers the planner
needs, and flagging pitfalls the decisions didn't anticipate.

Four pitfalls surfaced that CONTEXT.md/UI-SPEC.md did not fully anticipate: (1) **the
`webvulnscanner.extensions.limiter` object is a process-wide singleton** reused via
`.init_app()` across every `create_app()` call in the test suite (confirmed in
`tests/test_auth_flows.py`'s existing rate-limit test) — a HARD-01 test built around that
singleton would not actually prove cross-*process* (i.e., cross-worker) sharing, it would prove
the trivial fact that one Python object shares its own field; the test must construct two
genuinely independent `flask_limiter.Limiter` objects. (2) **`limits`' `RedisStorage` calls
`redis.from_url(uri, **options)` internally** (confirmed from `limits`' source) — the monkeypatch
target for fakeredis is `redis.from_url` (or the `redis.Redis` class used by it), not something
Flask-Limiter itself exposes; flask-limiter's own upstream test suite does not use fakeredis at
all (it uses Docker), so this pattern has no in-repo or upstream precedent to copy verbatim. (3)
**All four orchestrators' scoring blocks are verified byte-for-byte identical** except for the
local variable name holding the findings list (`findings` vs `all_findings`) — HARD-04's
extraction is a pure mechanical refactor with zero behavioral edge cases to reconcile, but the
duplicated `findings_sorted = sorted(...)` line immediately after the block is *also* identical
across all four and is a natural candidate to fold into the same helper (CONCERNS.md's suggested
signature omits it). (4) **`decode_invite_token` has zero call sites today** and
`generate_invite_token` has exactly one (`org_routes.py:177`) — the D-07 signature change to
3 args is unambiguously safe, confirmed via full-repo grep, not just CONTEXT.md's claim.

**Primary recommendation:** Follow every locked decision as-is; no deviations found. Build the
HARD-01 test as a standalone two-Limiter-instance unit test (bypassing the app-factory singleton
entirely) using a shared `fakeredis.FakeServer()` and a `redis.from_url` monkeypatch. Extract
`_score_report(findings)` to return `(score, risk_grade, severity_counts, findings_sorted)` — one
more value than CONCERNS.md's suggested 3-tuple, since the sort is duplicated identically too.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Rate-limit counter storage (HARD-01) | Database/Storage (Redis) | API/Backend (Flask-Limiter config) | Counters must survive across worker processes — only a shared out-of-process store satisfies that; the Flask app only supplies the URI |
| Orchestrator test coverage (HARD-02) | API/Backend (`scan_engine.py`) | — | Pure Python function tests, no client/browser tier involved |
| Invite-token flow (HARD-03) | API/Backend (`auth_routes.py`/`org_routes.py`) | Browser/Client (signup.html form) | Token generation/validation is server-side; the browser only renders a pre-filled, locked email field |
| Scoring dedup (HARD-04) | API/Backend (`scan_engine.py`) | — | Pure computation, no persistence or client concern |
| Visual consistency (HARD-05) | Frontend Server / Browser (Jinja templates + CSS) | — | Server-rendered HTML/CSS only, no JS framework in this repo |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `redis` | 8.1.0 [VERIFIED: PyPI registry] | Real Redis client; `limits`' `RedisStorage` calls `redis.from_url()` internally | Only client `limits`/Flask-Limiter's Redis backend depends on |
| `fakeredis` | 2.37.0 [VERIFIED: PyPI registry] | In-process fake Redis server for the multi-worker-sharing test, no Docker/service container needed | Documented, maintained drop-in for `redis-py`'s client API (`FakeStrictRedis`, shared `FakeServer`) — matches this repo's zero-external-service CI convention |
| `Flask-Limiter` | already in `requirements.txt` (unpinned; latest is 4.1.1 [VERIFIED: PyPI registry]) | Rate limiting extension already wired in `extensions.py` | No change — already the app's rate-limit layer |
| `limits` | transitive dep of Flask-Limiter (latest 5.8.0 [VERIFIED: PyPI registry]) | Backend storage abstraction Flask-Limiter delegates to; owns the `redis://` scheme → `RedisStorage` → `redis.from_url()` chain | Not a direct dependency to add — documented here because its internals determine the exact monkeypatch target for the fakeredis test |
| `lupa` | 2.8 [VERIFIED: PyPI registry] | Lua-Python bridge; `fakeredis`'s optional extra (`fakeredis[lupa]`) that backs its `EVAL`/`EVALSHA`/`SCRIPT` command support | **Discovered during execution, not anticipated pre-plan-time**: `limits`' `RedisStorage.incr()` calls a registered Lua script (`SCRIPT_INCR_EXPIRE`) unconditionally for every rate-limit check regardless of strategy (fixed/moving/sliding window) — confirmed by reading `limits/storage/redis.py`. `fakeredis` 2.37.0 raises `unknown command 'evalsha'` for every rate-limited request without it, since `fakeredis/commands_mixins/scripting_mixin.py` does an unconditional `import lupa` guarding all scripting commands. Required, not optional, for this plan's fakeredis-backed proof to run at all. |

### Supporting
None — HARD-02/03/04/05 need no new packages, only new test/template code using what's already
installed (`pytest`, Flask-WTF, itsdangerous, Jinja2).

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Redis (`RATELIMIT_STORAGE_URI=redis://...`) | Memcached (`memcached://...`) | `limits` supports it, but Redis is the only backend already referenced in `config.py`'s comments/`CONCERNS.md`'s own recommendation ("Switch storage_uri to a shared backend (e.g. Redis)") — no reason to introduce a second backend choice not already anticipated by the codebase |
| `fakeredis` in-process fake | `pytest-docker` + real Redis container | Rejected explicitly by D-01 to preserve the zero-service-container CI convention (`.github/workflows/tests.yml` currently needs no service containers, no `.env`) |

**Installation:**
```bash
pip install redis fakeredis
```
Add `redis` to `requirements.txt` (production dependency — Render deploy needs it once
`RATELIMIT_STORAGE_URI` is set to a real Redis URL) and `fakeredis` to `requirements-dev.txt`
only (test-only, never needed at runtime).

**Version verification:** `pip index versions redis` → `8.1.0` (latest); `pip index versions
fakeredis` → `2.37.0` (latest); `pip index versions flask-limiter` → `4.1.1`; `pip index versions
limits` → `5.8.0`. All confirmed live against PyPI on 2026-08-13. `requirements.txt` pins no
version numbers for any existing package (e.g. `flask`, `Flask-Limiter` are bare names) — follow
that exact repo convention: add `redis` and `fakeredis` as bare, unpinned names, not `==x.y.z`
pins, to match every other line in both requirements files.

## Package Legitimacy Audit

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|-------------|---------|-------------|
| `redis` | PyPI | 10+ years (redis-py, the canonical Python Redis client) | very high (top-500 PyPI package) | github.com/redis/redis-py | OK | Approved |
| `fakeredis` | PyPI | 10+ years, actively maintained (2.37.0 released recently per PyPI index) | high, widely used in test suites | github.com/cunla/fakeredis-py | OK | Approved |
| `lupa` | PyPI | 15+ years (releases since ~2010, latest 2.8), maintained by Stefan Behnel (`scoder`, a long-standing Cython core contributor) | high, widely used wherever Python code embeds a Lua interpreter (fakeredis's own documented scripting extra) | github.com/scoder/lupa | OK | Approved — added mid-execution via a human-verified package-legitimacy checkpoint (see 04-02-SUMMARY.md deviations) after discovering `fakeredis` requires it for `EVAL`/`EVALSHA` support that `limits`' `RedisStorage.incr()` depends on unconditionally |

**Packages removed due to [SLOP] verdict:** none.
**Packages flagged as suspicious [SUS]:** none. Both packages are long-established, canonical
choices for their stated purpose (`redis` is *the* Python Redis client; `fakeredis` is *the*
standard in-memory Redis test double) — no ambiguity, no cross-ecosystem confusion risk (neither
name collides with an unrelated package on another registry in a way relevant here), no
postinstall-script concern (`pip show`/registry metadata for both are pure-Python/C-extension
libraries with no documented postinstall network calls).

## Architecture Patterns

### System Architecture Diagram (HARD-01's new shared-storage path)

```
gunicorn --workers N
   │
   ├── worker process 1 ── webvulnscanner.extensions.limiter (singleton IN THIS PROCESS)
   │        │                         │
   │        │                 storage_uri = RATELIMIT_STORAGE_URI (redis://...)
   │        │                         │
   ├── worker process 2 ── webvulnscanner.extensions.limiter (a DIFFERENT singleton object,
   │        │                         │                        fresh Python import in this
   │        │                         │                        process)
   │        │                         ▼
   │        │              ┌─────────────────────┐
   └── worker process N ──▶│   Redis (shared)     │◀── both workers' counters live here,
                            │   INCR/EXPIRE per     │    not in either process's memory
                            │   rate-limit key       │
                            └─────────────────────┘
```
Each gunicorn worker is a separate OS process with its own fresh import of
`webvulnscanner.extensions`, hence its own `Limiter` Python object — the property under test is
that two *independent* `Limiter` objects pointed at the same `storage_uri` observe the same
counter, not that one shared Python object does (trivially true and not what production needs
proven).

### Recommended Test File Organization
```
tests/
├── test_ratelimit_storage.py     # HARD-01: new file — two-Limiter fakeredis sharing test
├── test_scan_engine.py            # HARD-02: new file — run_advanced_scan/run_media_scan/run_api_scan direct-invocation tests
├── test_scheduler.py              # HARD-02: EXTEND existing file — add "media"/"api" scheduler-fire cases
├── test_org_routes.py             # HARD-03: EXTEND existing 15-line file — invite/signup/domain-verification coverage
│                                     (or split into test_org_invite.py + test_domain_verification.py if it grows
│                                     past ~150 lines — TESTING.md's "one file per feature area" convention leaves
│                                     this to planner discretion, matching CONTEXT.md's explicit discretion note)
```
One new top-level test file per net-new feature area (`test_ratelimit_storage.py`,
`test_scan_engine.py`), extending existing files where the feature area already has one
(`test_scheduler.py`, `test_org_routes.py`) — matches `TESTING.md`'s documented convention.

### Pattern 1 (HARD-01): Two independent `Limiter` instances sharing a fakeredis backend
**What:** A standalone test that never touches `webvulnscanner.extensions.limiter` or
`create_app()` — it builds two bare `flask.Flask` + `flask_limiter.Limiter` mini-apps in-test,
both configured with the same `storage_uri`, with `redis.from_url` monkeypatched process-wide to
route to a shared `fakeredis.FakeServer()`.
**When to use:** Exactly this one test — proving the storage *layer* is shared is a generic
property of `limits`' Redis backend, independent of this app's routes/blueprints.
**Example (illustrative shape — plan should adapt to final test file location):**
```python
# Source: derived from limits' RedisStorage.__init__ (confirmed via source read:
# "self.storage = self.dependency.from_url(uri, **options)" where self.dependency
# is the `redis` module for a "redis://" URI) + fakeredis's documented FakeServer
# sharing pattern (fakeredis.readthedocs.io).
import fakeredis
import redis
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


def test_two_limiter_instances_share_counters_via_fakeredis(monkeypatch):
    shared_server = fakeredis.FakeServer()
    monkeypatch.setattr(
        redis, "from_url",
        lambda *a, **k: fakeredis.FakeStrictRedis(server=shared_server),
    )

    def make_app():
        app = Flask(__name__)
        limiter = Limiter(
            key_func=get_remote_address,
            storage_uri="redis://localhost:6379",  # never actually dialed - redis.from_url is patched
            app=app,
        )

        @app.route("/probe")
        @limiter.limit("3 per minute")
        def probe():
            return "ok"

        return app.test_client()

    client_a = make_app()  # simulates gunicorn worker 1
    client_b = make_app()  # simulates gunicorn worker 2 - a SEPARATE Limiter object

    statuses = [client_a.get("/probe").status_code for _ in range(3)]
    assert all(s == 200 for s in statuses)

    # The 4th request, from a DIFFERENT Limiter instance (different "worker"),
    # is still rate-limited - proves the counter lives in the shared fake
    # Redis backend, not in either Limiter object's own memory.
    assert client_b.get("/probe").status_code == 429
```
Both `flask.test_client()` calls use `127.0.0.1` as `get_remote_address`'s key, so this
demonstrates the shared-counter property correctly without needing a real network client.

### Pattern 2 (HARD-02): Direct-invocation orchestrator test, mirroring `_stub_all_checks`
**What:** Monkeypatch every `check_*` function `run_advanced_scan`/`run_media_scan`/
`run_api_scan` import into `scan_engine`'s namespace (same binding-location caveat
`test_scan_events.py`'s docstring already documents — patch `scan_engine.check_x`, not
`checks.check_x`, since `scan_engine.py` does `from webvulnscanner.checks import check_x`).
**When to use:** All three new orchestrator test files/sections.
**Example:**
```python
# Source: mirrors tests/test_scan_events.py's _stub_all_checks pattern (verified read
# 2026-08-13), adapted for run_media_scan's single check_media call.
from webvulnscanner import scan_engine


def test_run_media_scan_returns_completed_shape(monkeypatch):
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: object())
    monkeypatch.setattr(
        scan_engine, "check_media",
        lambda session, base_url, download, max_files: (
            {"images": [], "videos": []}, [],
        ),
    )
    report = scan_engine.run_media_scan("https://example.com", download=False, max_files=20)
    assert report["score"] == 100
    assert report["risk_grade"] == "A"
    assert report["media"] == {"images": [], "videos": []}
```

### Pattern 3 (HARD-02, safety-constraint regression lock): bruteforce cap
**What:** Assert `run_advanced_scan` never calls the stubbed `check_bruteforce` with more than
`MAX_BRUTEFORCE_ATTEMPTS` passwords, and that a stubbed "succeeded" result short-circuits (no
further calls) — regression-locking the safety cap at the orchestrator's call-site level, since
`checks.check_bruteforce` (`webvulnscanner/checks.py:1562-1596`) itself already enforces the cap
internally and D-03 says the check function is stubbed out entirely for these tests (never
executed for real), so the orchestrator-level test cannot re-verify the check's own internal
slicing — it can only verify `run_advanced_scan` passes through whatever the (mocked) check
returns without adding its own separate attempt loop.
**When to use:** `test_scan_engine.py`'s `run_advanced_scan` bruteforce-group tests.
**Example:**
```python
# Source: read webvulnscanner/checks.py:1562-1596 and webvulnscanner/scan_engine.py:193-202
# this session - the orchestrator calls check_bruteforce exactly once per invocation with
# advanced["bruteforce_passwords"] passed through unmodified (the cap itself lives inside
# check_bruteforce, not in run_advanced_scan - see check_bruteforce's own docstring:
# "Hard-capped at MAX_BRUTEFORCE_ATTEMPTS, stops immediately on first success").
def test_run_advanced_scan_calls_bruteforce_exactly_once_with_unmodified_password_list(monkeypatch):
    from webvulnscanner import scan_engine
    from webvulnscanner.entitlements import Tier

    calls = []

    def _fake_bruteforce(session, url, user_field, pass_field, username, passwords, fail_text):
        calls.append(passwords)
        return {"attempts": [], "cap": 5, "rate_limited": False}, []

    monkeypatch.setattr(scan_engine, "check_bruteforce", _fake_bruteforce)
    monkeypatch.setattr(scan_engine, "check_sqli_login", lambda *a, **k: ({}, []))
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: object())

    advanced = {
        "login_url": "https://example.com/login", "user_field": "user", "pass_field": "pass",
        "fail_text": "invalid", "bruteforce_username": "admin",
        "bruteforce_passwords": ["a", "b", "c", "d", "e", "f", "g"],  # 7 passwords, over the cap
        "sqli_union_url": "", "sqli_union_param": "",
        "stored_xss_submit_url": "", "stored_xss_field": "", "stored_xss_view_url": "", "stored_xss_cookie": "",
        "idor_url_template": "", "idor_ids": [], "idor_cookie_a": "", "idor_cookie_b": "",
    }
    scan_engine.run_advanced_scan(advanced, Tier.ORG_VERIFIED, True)

    assert len(calls) == 1  # called exactly once, not once per password
    # run_advanced_scan itself does not slice the list - it's the mocked check_bruteforce's
    # own job (in production) to cap at 5; asserting the orchestrator passes the full list
    # through is what regression-locks "the cap lives in checks.py, not duplicated here".
    assert calls[0] == advanced["bruteforce_passwords"]
```
**Note for the planner:** because D-03 mocks check functions entirely, the *actual*
`MAX_BRUTEFORCE_ATTEMPTS` slicing behavior (`passwords[:MAX_BRUTEFORCE_ATTEMPTS]`) is only
testable by calling `checks.check_bruteforce` directly (not through the orchestrator) with a
mocked `_timed_request`/`session.post` — that test belongs in a `checks.py`-focused test module
if one doesn't already assert it, not in the new orchestrator test file. Grep confirmed no
existing test asserts this cap directly; flag as a possible pre-existing gap for the planner to
fold into `test_scan_engine.py` as a `checks.check_bruteforce`-level unit test alongside the
orchestrator-level ones, if not already covered elsewhere in the suite.

### Pattern 4 (HARD-02, scheduler-fired coverage): extend `test_scheduler.py`
**What:** Add `media`/`api` cases mirroring the existing `test_free_tier_media_schedule_fails_
without_spawning` / `test_tier_upgrade_is_respected_at_next_fire_not_retroactively` shape, but for
a *successful* (tier-allowed) fire — the existing tests only cover the tier-denial path for
media/api; none currently assert a successful scheduler-fired media/api scan reaches
`_spawn_scan_thread` with the right `scan_type`/kwargs (`webvulnscanner/scheduler.py:124-132`).
**When to use:** `tests/test_scheduler.py`, using the existing `spawned` fixture (records
`_spawn_scan_thread` calls as no-ops — confirmed at `tests/test_scheduler.py:21-31`).
**Example:**
```python
# Source: mirrors tests/test_scheduler.py's existing test_tick_fires_due_asset_and_creates_one_scan
# shape (read this session), extended to assert kwargs for the "media"/"api" branches specifically.
def test_paid_tier_media_schedule_spawns_with_download_false(app, db, spawned):
    from webvulnscanner.models import Plan
    from tests.conftest import make_asset, make_org, make_user
    from webvulnscanner.scheduler import _tick

    org = make_org(plan=Plan.PAID)
    user = make_user("paid-media@example.com", org=org)
    a = make_asset(org, user, schedule_scan_type="media", next_run_at=_past())
    db.session.commit()

    _tick(app)

    assert len(spawned) == 1
    assert spawned[0]["scan_type"] == "media"
    # download defaults False for unattended scheduled fires (scheduler.py:124-129,
    # "the more conservative default for a run nobody is watching").
    assert spawned[0]["kwargs"]["download"] is False
```

### Pattern 5 (HARD-03): invite-mode signup route test
**What:** POST to `/signup?invite=<token>` and assert the created user lands in the token's
`org_id` at the token's `role`, the email field is locked to the invited address (mismatch
rejected), and an expired/tampered token degrades to the existing non-invite signup path (not a
500).
**When to use:** New tests in `tests/test_org_routes.py` (or a split-out
`tests/test_org_invite.py`), plus a `generate_invite_token`/`decode_invite_token` unit test
covering the new 3-arg signature and the email-mismatch rejection.
**Example (illustrative — exact route-branch shape is the planner's/executor's call, not
prescribed here beyond D-06/D-07's contract):**
```python
# Source: derived from org_routes.py's existing generate_invite_token/decode_invite_token
# (read this session, webvulnscanner/org_routes.py:63-79) plus D-06/D-07's contract.
def test_generate_and_decode_invite_token_round_trips_with_email():
    from webvulnscanner.org_routes import decode_invite_token, generate_invite_token

    token = generate_invite_token(org_id=5, role="member", email="invitee@example.com")
    decoded = decode_invite_token(token, expected_email="invitee@example.com")
    assert decoded == {"org_id": 5, "role": "member", "email": "invitee@example.com"}


def test_decode_invite_token_rejects_email_mismatch():
    from webvulnscanner.org_routes import decode_invite_token, generate_invite_token

    token = generate_invite_token(org_id=5, role="member", email="invitee@example.com")
    # Signed-up email differs from the invited email - must be rejected, not silently accepted.
    assert decode_invite_token(token, expected_email="attacker@example.com") is None
```
**Design-space note (not a locked decision — the planner/executor decides the exact function
signature):** two reasonable shapes exist for the email check: (a) `decode_invite_token(token,
expected_email)` returning `None` on mismatch (matches its existing `None`-on-failure
convention), or (b) `decode_invite_token(token)` returning the dict unconditionally and letting
`signup()` compare `decoded["email"]` itself. Either satisfies D-07; (a) keeps the security check
co-located with the other token-validity checks (signature/expiry) rather than splitting it
across two call sites.

### Pattern 6 (HARD-03): domain-verification flow test
**What:** Cover `verify_domain_view`'s `action=add`/`action=verify` POST branches and
`domain_verification.py`'s `generate_verification`/`verify_domain` (mocking `dns.resolver.resolve`
and `requests.get`, matching `tests/test_ssrf_guard.py`'s established mocked-network convention
for this kind of DNS/HTTP-dependent check).
**When to use:** New tests added to `tests/test_org_routes.py` (D-08's scope — already-working
flow, just untested).
**Example:**
```python
# Source: derived from domain_verification.py's own _verify_dns_txt/_verify_well_known
# (read this session, webvulnscanner/domain_verification.py:73-99) and the existing
# mocked-DNS convention already proven in tests/test_ssrf_guard.py.
def test_verify_domain_dns_txt_success(db, monkeypatch):
    from webvulnscanner.domain_verification import generate_verification, txt_record_value, verify_domain
    from webvulnscanner.models import VerifyMethod
    from tests.conftest import make_org

    org = make_org()
    dv = generate_verification(org.id, "example.com", VerifyMethod.DNS_TXT)

    class _FakeAnswer:
        def __init__(self, value):
            self.strings = [value.encode()]

    monkeypatch.setattr(
        "dns.resolver.resolve",
        lambda domain, rtype, lifetime=None: [_FakeAnswer(txt_record_value(dv))],
    )

    assert verify_domain(dv) is True
    assert dv.verified_at is not None
```

### Pattern 7 (HARD-04): `_score_report` extraction
**What:** A pure function taking a findings list and returning everything the four orchestrators'
scoring blocks currently compute inline — confirmed byte-for-byte identical across all four
(`webvulnscanner/scan_engine.py` lines 72-82, 129-139, 243-254, 427-438, read this session) except
for the local variable name holding the findings list.
**Example:**
```python
# Source: mechanical extraction of the verbatim-identical block repeated at
# webvulnscanner/scan_engine.py:72-82 (run_media_scan), :129-139 (run_api_scan),
# :243-254 (run_advanced_scan), :427-438 (run_scan) - read this session.
def _score_report(findings):
    """Shared by all four orchestrators (HARD-04). Returns (score, risk_grade,
    severity_counts, findings_sorted) - folds in the findings_sorted computation
    too, since that line is ALSO duplicated identically in all four call sites
    immediately after the score/grade/severity_counts block, not just the three
    values CONCERNS.md's note names."""
    score = 100
    for f in findings:
        score -= SEVERITY_WEIGHT.get(f.severity, 0)
    score = max(0, min(100, score))
    risk_grade = ("A" if score >= 90 else "B" if score >= 75 else
                  "C" if score >= 60 else "D" if score >= 40 else "F")

    severity_counts = {s: 0 for s in SEVERITY_WEIGHT}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
    return score, risk_grade, severity_counts, findings_sorted
```
Each orchestrator's call site becomes a one-line replacement, e.g. in `run_media_scan`:
```python
score, risk_grade, severity_counts, findings_sorted = _score_report(findings)
```
(and `_score_report(all_findings)` in the other three, matching each function's existing local
variable name — the extraction changes nothing about which variable is passed in, only removes
the duplicated body).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Cross-process shared rate-limit counters | A custom Redis client wrapper or a bespoke shared-counter table in Postgres/SQLite | `RATELIMIT_STORAGE_URI` + Flask-Limiter's existing `limits`-library-backed `storage_uri` mechanism (already wired, zero new plumbing) | `limits` already implements the correct atomic INCR/EXPIRE Lua-script-backed sliding/fixed-window logic for Redis; a hand-rolled version would need to re-solve race conditions Flask-Limiter's dependency already solves |
| Simulating a real Redis server in tests | A hand-written fake with a `dict`-backed `INCR`/`EXPIRE`/`TTL` mock | `fakeredis.FakeServer()` + `FakeStrictRedis(server=...)` | `fakeredis` implements the actual Redis command semantics (including TTL/expiry edge cases `limits` depends on) — a hand-rolled dict mock risks silently diverging from real Redis behavior on exactly the edge case (window expiry) the test needs to be trustworthy about |
| Invite-token signing | A custom HMAC scheme | `itsdangerous.URLSafeTimedSerializer` (already used by `generate_invite_token`/`decode_invite_token`) | Already the app's established token pattern (also used for password-reset tokens); D-07 only adds a field to the signed payload, not a new signing mechanism |

**Key insight:** every "don't hand-roll" item in this phase is really "don't hand-roll what's
already wired in" — HARD-01 through HARD-04 are all about finishing/testing/deduplicating
existing plumbing, not introducing new mechanisms.

## Common Pitfalls

### Pitfall 1: Testing HARD-01 against the `webvulnscanner.extensions.limiter` singleton proves nothing about multi-worker safety
**What goes wrong:** A test that calls `create_app()` twice and points both apps'
`RATELIMIT_STORAGE_URI` at the same fakeredis URL will *appear* to pass even with the current
in-memory default, because both `create_app()` calls in the test suite reuse the exact same
`webvulnscanner.extensions.limiter` module-level singleton object (confirmed: `tests/
test_auth_flows.py`'s `test_login_rate_limit_is_enforced` already documents this: "Limiter's
in-memory storage is a process-wide singleton shared across every test app instance"). Counters
would already be shared via the shared Python object, storage backend irrelevant.
**Why it happens:** `extensions.py`'s `limiter = Limiter(key_func=get_remote_address)` is
constructed once at import time, and `create_app()` calls `limiter.init_app(app)` on that same
object for every app built in the process — this is a deliberate, documented pattern for this
app's own runtime (one process per gunicorn worker → one `Limiter` per process), but it means
the *test suite's* multiple `create_app()` calls don't simulate multiple worker processes at all.
**How to avoid:** Build the HARD-01 test as two standalone `flask.Flask` + fresh
`flask_limiter.Limiter(...)` instances (see Pattern 1 above), never importing
`webvulnscanner.extensions.limiter`. This is a deliberate departure from "test through the real
app," justified because the property under test (storage-layer sharing) is generic to `limits`'
Redis backend, not specific to this app's routes.
**Warning signs:** A HARD-01 test that passes even when `storage_uri` is left at the in-memory
default — that's the tell that the test accidentally proved the singleton-sharing property
instead of the storage-sharing property.

### Pitfall 2: The fakeredis monkeypatch target is `redis.from_url`, not a Flask-Limiter API
**What goes wrong:** Patching something inside `flask_limiter` (e.g. `flask_limiter.Limiter`
itself, or a nonexistent `storage_uri` override hook) does nothing, because the actual Redis
client construction happens two layers down, inside `limits`' `RedisStorage.__init__`, via
`self.dependency.from_url(uri, **options)` where `self.dependency` is the `redis` module itself
for a `redis://`-scheme URI (confirmed via reading `limits`' `RedisStorage` source this session).
**Why it happens:** Flask-Limiter delegates all storage-backend logic to the `limits` library;
neither package exposes a documented dependency-injection point for a fake client — there is no
official fakeredis integration for either package (flask-limiter's own upstream test suite uses
a real Dockerized Redis, not fakeredis, confirmed by reading its `tests/conftest.py`).
**How to avoid:** `monkeypatch.setattr(redis, "from_url", lambda *a, **k:
fakeredis.FakeStrictRedis(server=shared_server))` before constructing either `Limiter` instance.
Scope the monkeypatch narrowly (function-level, via pytest's `monkeypatch` fixture, auto-reverted
after the test) since it globally intercepts every `redis.from_url` call for the test's duration.
**Warning signs:** `ConnectionRefusedError`/`redis.exceptions.ConnectionError` when running the
HARD-01 test — means the patch didn't take effect before `Limiter.init_app()`/construction ran
(the storage object is typically built eagerly at `Limiter(...)`/`init_app()` time, so the patch
must be in place *before* either `Limiter` object is constructed, not just before requests hit
it).

### Pitfall 3: SQLite background-thread commit-visibility gotcha applies to the new orchestrator tests too
**What goes wrong:** `CONCERNS.md`'s "Fragile Areas" section documents that
`_run_scan_in_background`'s writes, when called synchronously with an outer `app.app_context()`
already held open (e.g. via the `db` fixture), read back stale through that same session —
`tests/test_scan_events.py`'s existing base-scan test avoids this by using short-lived
`with app.app_context():` blocks instead of the shared `db` fixture. The same hazard applies
verbatim to any new HARD-02 test that calls `_run_scan_in_background` for `"media"`/`"api"`/
`"advanced"` scan types (not just `"base"`).
**Why it happens:** Flask-SQLAlchemy's scoped session caches identity-mapped objects per
context; a background-thread-style call made while an outer context/session is already open
reads the outer session's (stale) cache instead of the just-committed row.
**How to avoid:** If HARD-02's new tests exercise `_run_scan_in_background` directly (as opposed
to calling `run_advanced_scan`/`run_media_scan`/`run_api_scan` directly, which is what D-03/D-02
primarily call for), mirror `test_scan_events.py`'s exact pattern: short-lived
`with app.app_context():` blocks around each phase (setup / invoke / assert), never the `db`
fixture held open across the call. If the new tests stay at the orchestrator-function level
(`scan_engine.run_media_scan(...)` directly, no DB/`Scan` row involved at all) — the likely
majority case per D-02/D-03's wording — this pitfall doesn't apply; it only matters if/when a
test also exercises `scan_routes._run_scan_in_background`'s DB-writing wrapper for the new scan
types (recommended as a smaller, targeted addition per orchestrator, not required by D-02's
core ask).
**Warning signs:** A test asserting `Scan.status == COMPLETED` intermittently reads `RUNNING` or
a stale `QUEUED` value.

### Pitfall 4: `check_bruteforce`'s `time.sleep(1.0)` between attempts means it must be mocked, never called for real, in orchestrator tests
**What goes wrong:** `checks.check_bruteforce` (`webvulnscanner/checks.py:1562-1596`) sleeps 1
full second between each password attempt (`time.sleep(1.0)`, line 1587) — a real (unmocked)
call in a test with even 3-5 passwords would make the test suite measurably slower and flaky
under CI load. D-03 already mandates full mocking for exactly this class of reason.
**Why it happens:** The sleep is a deliberate production behavior (spaces out brute-force
attempts to look less like an automated flood) — a check function detail, not a test artifact.
**How to avoid:** Always monkeypatch `scan_engine.check_bruteforce` (and every other check
function `run_advanced_scan`/`run_media_scan`/`run_api_scan` call) at the `scan_engine` module
namespace, per Pattern 2/3 above — never invoke the real `checks.check_bruteforce` from an
orchestrator-level test.
**Warning signs:** A new test in `test_scan_engine.py` taking multiple real seconds to run.

### Pitfall 5: `run_advanced_scan`'s `locked` list entries depend on tier/domain gating evaluated per-group, independently
**What goes wrong:** A test asserting "when tier is below ORG_VERIFIED, everything lands in
`locked`" must check each check-group's `locked.append(...)` call individually
(`webvulnscanner/scan_engine.py:190-241`) — `sqli_login`/`bruteforce`/`sqli_union`/`xss_stored`/
`idor` are five *independent* `elif has_group_fields:` branches, each appending its own name only
if that group's *specific* required fields are present (a group with no fields filled in never
appears in `locked` at all, matching the docstring's own note: "in practice: below that tier...
every group lands in `locked` regardless of form-field completeness" — only true for groups whose
fields ARE filled in).
**Why it happens:** The gating logic mirrors form-completeness per-group before it mirrors tier —
an incomplete form group is silently skipped entirely (never runs, never locks), which is easy
to misassert as "locked" if a test doesn't fill in that group's required fields.
**How to avoid:** For an "everything locked below tier" test, fill in every group's required
fields (matching `_parse_advanced_form`'s full field list, `webvulnscanner/scan_routes.py:
209-227`) and assert all 5 check names appear in `report["locked_checks"]`; for an "empty form
groups are silently skipped, not locked" test, leave fields empty and assert `locked_checks == []`
and `ran == []`.
**Warning signs:** A false-positive-passing test that only fills in one group's fields and
therefore only ever exercises one of the five lock branches.

### Pitfall 6: `decode_invite_token`'s current zero call sites means its behavior is currently unverified by any test
**What goes wrong:** Because `decode_invite_token` (`org_routes.py:73-79`) has never been called
in production code (confirmed via full-repo grep, zero non-definition matches), there is no
existing regression coverage proving its `BadSignature`/`SignatureExpired` exception handling
actually works end-to-end — the D-07 signature change (adding `email`) is landing on genuinely
untested ground, not a well-worn path.
**Why it happens:** The function was written ahead of its consumer (the plan explicitly deferred
consuming it — see `org_routes.py`'s original module docstring, since edited by D-06/D-07's
scope), so it never got exercised by anything, tests included.
**How to avoid:** Write the round-trip test (Pattern 5 above) AND explicit expired-token and
tampered-token tests before wiring the signup route to depend on it — don't assume the existing
`decode_invite_token` body is correct just because it was already in the codebase; verify it
fresh as part of this phase's work.
**Warning signs:** A signup-route test using a real, freshly-generated token passes, but there's
no test using a token whose signature has been altered by a single character — that gap would
mean CSRF/token-forgery resistance for invites is unverified.

### Pitfall 7: `InviteForm`'s `email` field (already `Email()`-validated) needs to also flow into `generate_invite_token`'s new 3rd argument
**What goes wrong:** `org_routes.py`'s `invite()` route (line 165-193) already collects
`form.email.data` for sending the invite email, but currently does NOT pass it into
`generate_invite_token(current_user.org_id, role)` (2-arg call today, line 177) — a planner
implementing D-07 must remember to add `form.email.data.strip().lower()` as the third argument at
this exact call site (the only call site — confirmed via grep), not just change the function
signature.
**Why it happens:** The email is already being lowercased/stripped for the `sender.send(to=...)`
call two lines below (line 182: `form.email.data.strip().lower()`) — easy to reuse that
normalized value for the token too, but equally easy to forget since it's a separate line.
**How to avoid:** Normalize the email once (`invitee_email = form.email.data.strip().lower()`)
and use that single variable for both `generate_invite_token(..., invitee_email)` and
`sender.send(to=invitee_email, ...)` — avoids the two call sites silently normalizing
differently.
**Warning signs:** A signup test using a differently-cased invited email
(`Invitee@Example.com` vs `invitee@example.com`) failing the email-match check at decode time.

### Pitfall 8: `signup.html`'s current form has no email-locking affordance — template changes are required, not just route changes
**What goes wrong:** `templates/signup.html` (read this session) renders a single unconditional
form with an editable `form.email` field and an `org_name` field with the hint "create it and
become its admin... Leave blank to sign up solo" — neither branch of D-06's invite-mode UX
(pre-filled/locked email, hidden org-name field) exists in the template today. A planner/executor
who only edits `auth_routes.py`'s `signup()` view without touching the template will not actually
deliver the pre-filled/locked-email behavior D-06/D-07 specify.
**Why it happens:** The template was built before the invite flow existed at all (its current
form is generic signup-only).
**How to avoid:** Plan an explicit template-change task: `signup.html` needs either (a) a
Jinja conditional block keyed on an `invite_mode`/`invite_email` context variable the view passes
in, disabling/pre-filling the email input and hiding the org-name field+hint when present, or
(b) a small dedicated `SignupForm` subclass/variant for invite mode. Either way this is a
template task, not purely a Python-route task — CONTEXT.md's "template changes needed in
templates/signup.html" line item is correct and load-bearing.
**Warning signs:** Planner scopes HARD-03's invite-flow work as "one task, auth_routes.py only" —
should be at least two tasks (route logic + template change), given the confirmed template gap.

## Code Examples

See Architecture Patterns §1-7 above — all seven code examples are sourced from files read this
session (`webvulnscanner/scan_engine.py`, `webvulnscanner/checks.py`, `webvulnscanner/
org_routes.py`, `webvulnscanner/domain_verification.py`, `webvulnscanner/scheduler.py`,
`tests/test_scan_events.py`, `tests/test_scheduler.py`) plus `limits`/`fakeredis` upstream source
confirmed via WebFetch this session, not fabricated from training-data assumption.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| In-memory-only rate-limit storage (fine for `--workers 1`) | `RATELIMIT_STORAGE_URI`-driven Redis storage, opt-in via env var | This phase (HARD-01) | Enables safely raising `--workers` beyond 1 in `Procfile`/`render.yaml` later — that raise itself is explicitly NOT part of this phase's scope (deployment config change is a separate, later decision) |
| Scoring logic hand-duplicated 4x | Single `_score_report()` helper | This phase (HARD-04) | Future scoring-formula changes (severity weights, grade thresholds) touch one function instead of four |

**Deprecated/outdated:** None — this phase closes gaps in already-current patterns, it does not
retire anything.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `_score_report`'s return signature should be `(score, risk_grade, severity_counts, findings_sorted)` — a 4-tuple, not CONCERNS.md's suggested 3-tuple — because `findings_sorted`'s computation is also verbatim-duplicated across all four call sites | Architecture Patterns §Pattern 7 | Low — this is a mechanical refactor design choice, not a behavioral risk either way; if the planner prefers the literal 3-tuple from CONCERNS.md, the `findings_sorted` line just stays inline at each of the 4 call sites instead of folding in, no functional difference |
| A2 | The email-mismatch check in `decode_invite_token` should take an `expected_email` parameter and return `None` on mismatch (Pattern 5's "Design-space note") rather than the caller comparing emails itself | Architecture Patterns §Pattern 5 | Low — CONTEXT.md's D-07 only locks the *outcome* (mismatch is rejected), not this exact function signature; either shape satisfies the requirement, planner/executor is free to choose |
| A3 | No Redis instance is already provisioned anywhere in this project's infra (Render/Neon) that HARD-01 could point at instead of requiring the user to provision one later | User Constraints §Claude's Discretion | Low-medium — verified via repo grep (no `render.yaml` Redis resource block, no `docker-compose.yml`), but this is a claim about infrastructure outside the repo's own files; if wrong, the planner/user still just sets `RATELIMIT_STORAGE_URI` to whatever Redis URL exists — no code changes needed either way, this only affects a deployment-config decision explicitly out of this phase's scope |

## Open Questions

1. **Should the new `_run_scan_in_background`-level tests (DB-writing wrapper) be added for
   `media`/`api`/`advanced`, beyond direct orchestrator-function tests?**
   - What we know: D-02/D-03 focus on `run_advanced_scan`/`run_media_scan`/`run_api_scan`
     themselves ("status transitions and error handling" — the orchestrator functions' own
     return-shape/error behavior). `_run_scan_in_background` is a separate wrapper in
     `scan_routes.py` that these orchestrators feed into.
   - What's unclear: Whether "status transitions" in HARD-02's wording refers to the `Scan.status`
     DB column (only touched by `_run_scan_in_background`, not by the orchestrators themselves,
     which are pure functions with no DB writes) or to the orchestrators' own internal
     branching/grading logic.
   - Recommendation: Cover both, proportionally — orchestrator-level tests are the primary,
     required deliverable (matches D-02/D-03's literal function names); one targeted
     `_run_scan_in_background`-level test per new scan type (mirroring `test_scan_events.py`'s
     existing base-scan one, using the short-lived-app-context pattern from Pitfall 3) closes the
     DB-status-transition gap cheaply without over-scoping.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `redis` (PyPI package) | HARD-01 production rate-limit storage | ✗ (not installed in this worktree's Python env — no `.venv` present) | not installed; latest is 8.1.0 | Install via `pip install -r requirements.txt` after adding the line — no fallback needed, this is a standard pure-Python package |
| `fakeredis` (PyPI package) | HARD-01 test | ✗ (not installed) | not installed; latest is 2.37.0 | Same — install via `requirements-dev.txt` |
| Real Redis server | HARD-01 production runtime (NOT tests) | Not checked / not applicable to this dev environment | n/a | Not needed for this phase's work — `RATELIMIT_STORAGE_URI` stays unset in dev/test; a real Redis instance is a deployment-time (Render) concern outside this phase's scope, same as D-01 frames it |

**Missing dependencies with no fallback:** none — both `redis`/`fakeredis` are simple `pip
install` additions with no environment prerequisites (no compiled extensions requiring system
libraries beyond what any other `requirements.txt` entry needs).

**Missing dependencies with fallback:** none needed.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest (via `pytest.ini`, `testpaths = tests`) [VERIFIED: TESTING.md + tests/conftest.py read this session] |
| Config file | `pytest.ini` (repo root) |
| Quick run command | `pytest tests/test_ratelimit_storage.py -v` (or the specific new file) |
| Full suite command | `pytest -v` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| HARD-01 | Two independent Limiter instances share a counter via fakeredis-backed `storage_uri` | unit | `pytest tests/test_ratelimit_storage.py -x` | ❌ Wave 0 |
| HARD-02 | `run_advanced_scan`/`run_media_scan`/`run_api_scan` status/error/safety-cap behavior | unit | `pytest tests/test_scan_engine.py -x` | ❌ Wave 0 |
| HARD-02 | `media`/`api` scheduler-fired dispatch | unit | `pytest tests/test_scheduler.py -x` | ✅ (extend existing file) |
| HARD-03 | Invite-mode signup, token email-binding, domain-verification flow | unit/route | `pytest tests/test_org_routes.py -x` | ✅ (extend existing 15-line file) |
| HARD-04 | `_score_report` returns identical values to the pre-extraction inline blocks | unit | `pytest tests/test_scan_engine.py -k score -x` | ❌ Wave 0 (can live in the same new file as HARD-02's tests) |
| HARD-05 | Visual pass — no automated test (presentation-only, per UI-SPEC's "UI Considerations": every state category already ✅ covered, no new error/loading paths introduced) | manual/visual | n/a — verified via `/gsd-ui-review` or manual UAT, not pytest | n/a |

### Sampling Rate
- **Per task commit:** run the specific new/extended test file (`pytest tests/test_X.py -v`)
- **Per wave merge:** `pytest -v` (full suite)
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `tests/test_ratelimit_storage.py` — new file, covers HARD-01 (no existing fixture/pattern
      to extend — this is a genuinely new test shape not sharing `conftest.py`'s `app`/`client`/
      `db` fixtures, since it deliberately bypasses the app factory per Pitfall 1)
- [ ] `tests/test_scan_engine.py` — new file, covers HARD-02 (orchestrator-level) and HARD-04
      (scoring-helper-level)
- [ ] Framework install: `pip install redis fakeredis` (or add to requirements files and
      `pip install -r requirements-dev.txt`) — required before `test_ratelimit_storage.py` can
      even be collected by pytest (a bare `import fakeredis` at module level will `ModuleNotFoundError`
      otherwise)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | yes | Session-cookie auth via Flask-Login (unchanged this phase) — invite-mode signup still goes through the same `generate_password_hash`/`User` creation path, just pre-fills org/role from a verified token instead of the form |
| V3 Session Management | no | Not touched this phase |
| V4 Access Control | yes | Invite-token binding (D-07) is fundamentally an access-control fix — closes a "leaked link grants org membership to anyone" gap. `org_admin_required`/`login_required` decorators (already in place on `/org/admin/invite`) are unchanged |
| V5 Input Validation | yes | `InviteForm`'s existing `Email()`/`DataRequired()` WTForms validators (unchanged); the new email-match check at decode time is itself an input-validation control, not a new library — reuses `itsdangerous`'s existing signed-payload mechanism |
| V6 Cryptography | yes | `itsdangerous.URLSafeTimedSerializer` (HMAC-signed, using `SECRET_KEY`) — already the app's established token-signing mechanism (also used for password-reset), never hand-roll a new signing approach for the email-bound token |
| V13 API and Web Service | n/a | Rate-limit backend change (HARD-01) affects `/login`/`/signup`/invoice/API-token endpoints' *availability* of correct limiting, not their input/output contract |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| Rate-limit bypass via multi-worker counter fragmentation (HARD-01's own subject) | Denial of Service (bypass, not amplification) | Shared Redis-backed `storage_uri` — this phase's entire HARD-01 deliverable |
| Invite-link forwarding/leaking → unauthorized org join at a granted role (D-07's own subject) | Elevation of Privilege | Email-bound, signed, time-limited (`itsdangerous`, 7-day `INVITE_MAX_AGE_SECONDS`) invite tokens — this phase's HARD-03 deliverable |
| Token tampering (bit-flip on the signed invite payload) | Tampering | `itsdangerous`'s HMAC signature already rejects any tampered payload via `BadSignature` (existing mechanism, unchanged by D-07 — only the payload's *field set* changes) |

## Sources

### Primary (HIGH confidence)
- `webvulnscanner/scan_engine.py` (read in full, 492 lines) — all four orchestrators' scoring
  blocks confirmed byte-for-byte identical except variable naming; `run_advanced_scan`'s
  per-group locked-check branching
- `webvulnscanner/checks.py` (targeted reads, lines 1482-1596) — `check_xss_stored`,
  `check_idor`, `check_bruteforce`, `MAX_BRUTEFORCE_ATTEMPTS = 5` (line 44)
- `webvulnscanner/org_routes.py` (read in full) — `generate_invite_token`/`decode_invite_token`
  current 2-arg signature and sole call site (line 177)
- `webvulnscanner/auth_routes.py` (read in full) — `signup()`'s current unconditional-form shape
- `webvulnscanner/domain_verification.py` (read in full) — `verify_domain`/`_verify_dns_txt`/
  `_verify_well_known` mocking surface
- `webvulnscanner/scheduler.py` (read in full) — `_fire()`'s `"base"`/`"media"`/`"api"` branches,
  confirmed no `"advanced"` branch (grounds D-04)
- `webvulnscanner/scan_routes.py` (read in full) — `_run_scan_in_background`, `_spawn_scan_thread`
- `webvulnscanner/extensions.py`, `webvulnscanner/config.py` (read in full) — `RATELIMIT_STORAGE_URI`
  already wired, `limiter` singleton construction
- `tests/test_scan_events.py`, `tests/test_scheduler.py`, `tests/test_org_routes.py`,
  `tests/conftest.py`, `tests/test_auth_flows.py` (lines 375-415), `tests/test_config.py` (lines
  90-98) — all read in full or targeted, establish existing test patterns/fixtures/singleton
  gotcha
- `templates/signup.html`, `templates/dashboard.html`, `templates/org_admin.html`,
  `templates/billing.html`, `templates/scan_report.html`, `templates/base.html` (targeted greps
  and reads) — confirmed current markup state matches every claim in `04-UI-SPEC.md`
- `pip index versions redis/fakeredis/flask-limiter/limits` [VERIFIED: PyPI registry, run this
  session, 2026-08-13] — 8.1.0 / 2.37.0 / 4.1.1 / 5.8.0 respectively

### Secondary (MEDIUM confidence)
- `limits`' `RedisStorage.__init__` source, fetched via WebFetch from
  `raw.githubusercontent.com/alisaifee/limits/master/limits/storage/redis.py` this session —
  confirms `self.dependency.from_url(uri, **options)` as the exact construction call [CITED:
  github.com/alisaifee/limits]
- `fakeredis.readthedocs.io` — `FakeServer()` sharing pattern, `FakeStrictRedis.from_url()`
  [CITED: fakeredis.readthedocs.io]
- `limits.readthedocs.io/en/latest/storage.html` — confirms no official fakeredis-injection
  pattern is documented; connection-pool injection is the only documented DI point [CITED:
  limits.readthedocs.io]

### Tertiary (LOW confidence)
- flask-limiter's own `tests/conftest.py` (WebFetch summary, not a full read) — confirms upstream
  tests use Docker, not fakeredis, for Redis-backed tests; used here only to establish "no
  official precedent exists," not as a positive pattern to copy

## Metadata

**Confidence breakdown:**
- Standard stack (redis/fakeredis versions, package legitimacy): HIGH — versions verified live
  against PyPI registry this session, both packages are long-established canonical choices
- Architecture (HARD-01 test shape, HARD-04 extraction, invite-token flow): HIGH — every claim
  traces to a specific file/line read this session, not training-data assumption; the one
  genuinely novel piece (fakeredis + `limits`' `RedisStorage`) is corroborated by reading `limits`'
  own source, not just training memory
- Pitfalls: HIGH — all 8 pitfalls are grounded in specific confirmed code facts (singleton
  construction, `time.sleep(1.0)`, zero call sites, template gap), not speculative

**Research date:** 2026-08-13
**Valid until:** 30 days (stable-domain phase — no fast-moving library surface involved beyond
routine PyPI version drift, which the planner should re-check with `pip index versions` if this
phase is executed materially later than the research date)
