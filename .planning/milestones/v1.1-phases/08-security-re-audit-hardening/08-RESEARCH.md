# Phase 8: Security Re-Audit & Hardening - Research

**Researched:** 2026-08-18
**Domain:** Application-security regression audit (IDOR, CSRF, SSRF, XSS, SQLi, path-traversal,
open-redirect, secrets, billing-replay, error-leakage) across an existing Flask multi-tenant app
**Confidence:** HIGH

## Summary

This phase is **not greenfield security design** — it is a route-by-route verification pass
against a codebase that, on inspection, already implements the large majority of what SEC-01
through SEC-10 ask for. Reading every ID-accepting route in `scan_routes.py`, `asset_routes.py`,
`api_routes.py`, `api_tokens_routes.py`, `org_routes.py`, and `billing_routes.py` this session
confirms a consistent, already-tested `_check_ownership`/`_check_asset_access`/inline-`org_id`
pattern is applied almost everywhere an object ID is accepted. CSRF is enforced app-wide via a
single `CSRFProtect()` instance (`glassbox/extensions.py:19`, `csrf.init_app(app)` at
`glassbox/__init__.py:98`), and every template carrying a POST form was confirmed (this
session, via grep) to emit a `csrf_token` field. Jinja2 autoescaping is on everywhere by Flask
default (`render_template` never disables it; zero `|safe` filters exist in `templates/`, zero
`Markup(...)`/`render_template_string(...)` calls exist in `glassbox/`). No raw/string-
interpolated SQL exists — the only two non-ORM-builder DB calls in the codebase are
`db.session.execute(db.text("SELECT 1"))` (a static healthcheck string,
`glassbox/public_routes.py:37`) and a parameterized SQLAlchemy Core `update()` in
`glassbox/scheduler.py:46`. No route accepts a raw filesystem path from the user at all —
report/CSV downloads resolve their on-disk file via a DB-stored filename generated server-side
(`scan_engine.save_report()`), never from a request parameter.

The one **genuine, confirmed-open gap** this session's read of `checks.py`/`scan_engine.py`
surfaces is **SEC-03**: `is_ssrf_safe_hostname()` is called once at scan-submission time
(`scan_routes._unsafe_target_error`), but the actual `requests.Session()` object every check
function shares (`checks._mk_session()`, called once per orchestrator in `scan_engine.py`) is a
plain, unmodified `requests.Session()` with no per-hop redirect-hostname re-validation. Since the
large majority of `session.get(...)` calls in `checks.py` either omit `allow_redirects` (requests'
default is `True`) or pass it explicitly, `requests` will silently follow a 30x redirect straight
into a private/loopback/link-local/metadata address with zero re-check — this is the exact,
concrete mechanism SEC-03's success criterion names. The fix is a single, well-scoped change:
subclass `requests.Session` (or override `resolve_redirects`) in `_mk_session()` so every redirect
hop is validated through `is_ssrf_safe_hostname()` before it's followed — see Code Examples below.

A second real finding, this time a **test-coverage gap rather than a live vulnerability**: no test
in the suite re-enables `WTF_CSRF_ENABLED` to prove CSRF actually rejects a token-less POST (every
existing CSRF-adjacent test only asserts the `csrf_token` field is *present in rendered HTML*, not
that the server *enforces* it) — the same class of gap the `RATELIMIT_ENABLED`-re-enabled test
(`tests/test_auth_flows.py:483` `test_login_rate_limit_is_enforced`) already fixed for rate
limiting, and the exact pattern to copy for CSRF. A third, smaller gap: `tests/test_billing_routes.py`
is only 58 lines/2 tests and has no route-level cross-org/replay coverage for
`create_invoice`/`verify_invoice_route`, even though the underlying `billing.py` unit logic
(collision-retry-exhaustion, double-tx-hash-match) is already well tested in `tests/test_billing.py`.
A fourth, narrower gap: `org_routes.py`'s `resend_invitation`/`revoke_invitation` have no
cross-org test (only `request_domain_deletion` does, via
`test_domain_deletion_actions_are_org_scoped`) — the code already 404s correctly
(`inv.org_id != current_user.org_id: abort(404)`), it's untested.

**Note on CONCERNS.md staleness:** `.planning/codebase/CONCERNS.md` is dated 2026-08-10 and its
"thin coverage" claims about `org_routes.py`/`domain_verification.py`/the three scan orchestrators
predate Phase 4 (HARD-02/HARD-03), which already built substantial coverage
(`tests/test_scan_engine.py` is 549 lines covering `run_advanced_scan`/`run_media_scan`/
`run_api_scan`; `tests/test_org_routes.py` is 222 lines; `tests/test_domain_verification.py` is
268 lines, already including a cross-org rejection test). D-05's "backfill" scope per this
research is much narrower than CONCERNS.md implies — see the Phase Requirements table.

**Primary recommendation:** Treat this phase as five closable checklists, not an open design
problem — SEC-03's redirect guard is the one code fix that must ship; SEC-02's CSRF-enforcement
test and SEC-09's route-level billing tests are the two test-backfill items; everything else is
confirm-and-lock-with-a-regression-test on already-correct code.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Cross-org IDOR guards (SEC-01) | API/Backend (route layer) | — | Ownership checks live in each blueprint's route function, before any query result reaches a template/JSON response |
| CSRF protection (SEC-02) | API/Backend (Flask-WTF middleware) | Browser (hidden form field) | `CSRFProtect` validates server-side; the token itself is emitted into the HTML form by the template tier |
| SSRF/redirect-following (SEC-03) | API/Backend (outbound HTTP client in `checks.py`) | — | The scan engine's own outbound `requests.Session` is the only place a redirect can be silently followed |
| XSS prevention (SEC-04) | API/Backend (Jinja2 autoescape) | Browser (CSP header, out of this phase's scope) | Escaping happens at template-render time server-side |
| SQLi prevention (SEC-05) | Database/Storage (SQLAlchemy query builder) | — | Parameterization is enforced at the ORM/Core layer, not app logic |
| Path-traversal / file-serving (SEC-06) | API/Backend (route + filename resolution) | Database/Storage (filename stored server-side) | No route accepts a raw path; the DB row is the only path source |
| Open redirect (SEC-07) | API/Backend (`_safe_next()`) | — | Single, already-centralized guard in `auth_routes.py` |
| Secrets sweep (SEC-08) | Source control / CI | — | Not a runtime-tier concern; a repo-history/grep audit |
| Billing replay/tampering (SEC-09) | API/Backend (`billing_routes.py`/`billing.py`) | Database/Storage (`matched_tx_hash` unique constraint) | Both the app-logic collision-retry and the DB constraint jointly own this guarantee |
| Error-leakage (SEC-10) | API/Backend (Flask error handlers + `DEBUG` config) | — | `app.debug`/`DEBUG` config gates whether Werkzeug's debugger or a generic page renders |

## Standard Stack

No new libraries are required for this phase — every mechanism SEC-01..SEC-10 needs already
exists in `requirements.txt`/`requirements-dev.txt`.

### Core (already in use, no version change needed)
| Library | Installed Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Flask-WTF | 1.3.0 [VERIFIED: `.venv` `pip show`, this session] | `CSRFProtect`, form validation | Already the app's CSRF mechanism (`glassbox/extensions.py:19`) |
| requests | 2.34.2 [VERIFIED: `.venv` `pip show`, this session] | Outbound HTTP client for all scan checks | `Session.resolve_redirects()` override is the standard idiomatic way to intercept per-hop redirects in this library — stable API across 2.x |
| pytest | 9.1.1 [VERIFIED: `.venv` `pip show`, this session] | Regression-test framework | Already the project's only test runner |

### Supporting
| Library | Purpose | When to Use |
|---------|---------|-------------|
| `dns.resolver` (dnspython) | Already used by `checks.is_ssrf_safe_hostname` (via `socket.getaddrinfo`, not dnspython directly) and `domain_verification.py` | No new usage needed this phase |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Overriding `requests.Session.resolve_redirects` for SEC-03 | A `response` hook (`session.hooks["response"]`) | A response hook fires *after* a response is received but does not by itself prevent `requests` from following the next redirect — `resolve_redirects` override is the only point that can veto a hop before it's fetched. Rejected. |
| Overriding `requests.Session.resolve_redirects` | A custom `requests.adapters.HTTPAdapter.send()` override | Adapter-level interception happens per-connection, below the redirect-resolution loop — would require reimplementing redirect-loop logic instead of hooking into it. More code, same result. Rejected. |
| `pytest-flask`'s `live_server` fixture for D-01's live probe pass | A standalone `requests`-based Python script | `pytest-flask` is not in `requirements-dev.txt` and would be a new dependency added mid-audit-phase; the project's existing test infra (`tests/conftest.py`) has no `live_server` precedent. A standalone script (e.g. `scripts/live_probe_phase8.py`, run manually against `python app.py`) matches D-02's "verification step, not a replacement for the regression suite" framing and needs zero new dependencies. **Recommended.** |
| Manual/`git log -p`+grep secrets sweep for SEC-08 | Installing `detect-secrets`/`gitleaks` | Neither tool is installed in this environment or listed in `requirements-dev.txt`; installing a new scanning tool mid-phase would need its own legitimacy verification per the Package Legitimacy Gate. A scoped `git log -p 00ae203..HEAD` (the v1.1-milestone-kickoff commit [VERIFIED: `git log --oneline`, this session — commit `00ae203 docs: start milestone v1.1 Production Audit, Hardening & Redesign`]) plus targeted grep patterns covers the requirement's literal "added this milestone" scope without a new tool. |

**Installation:** None required.

## Package Legitimacy Audit

Not applicable — this phase installs no new external packages.

## Architecture Patterns

### System Architecture Diagram

```
                 ┌─────────────────────────────────────────────────────────┐
                 │                    Browser / CLI / curl                  │
                 └───────────────┬───────────────────────┬──────────────────┘
                                  │ session cookie          │ Bearer token
                                  ▼                         ▼
                 ┌─────────────────────────┐   ┌─────────────────────────────┐
                 │  Cookie-authenticated    │   │  /api/v1/* (api_routes.py)   │
                 │  HTML routes             │   │  api_login_required          │
                 │  (@login_required)       │   │  (request_loader, path-scoped│
                 │                          │   │   to /api/v1/* only)         │
                 └───────────┬──────────────┘   └──────────────┬───────────────┘
                              │                                   │
                              ▼                                   ▼
        ┌──────────────────────────────────────────────────────────────────┐
        │        Ownership/CSRF gate (per blueprint, before any query)      │
        │  _check_ownership() (scan_routes)  _check_asset_access() (asset)  │
        │  inline org_id==current_user.org_id (org_routes/billing_routes)   │
        │  t.user_id==current_user.id (api_tokens_routes)                   │
        │  CSRFProtect (global, all POST/PUT/PATCH/DELETE, csrf.exempt(api))│
        └───────────────────────────┬────────────────────────────────────────┘
                                     │ authorized
                                     ▼
        ┌──────────────────────────────────────────────────────────────────┐
        │  Scan submission gate: normalize_target() -> is_ssrf_safe_        │
        │  hostname() -> domain_is_org_verified()/entitlements gate         │
        │  (scan_routes._unsafe_target_error, asset_routes.new_asset)       │
        └───────────────────────────┬────────────────────────────────────────┘
                                     │ Scan row created, background thread spawned
                                     ▼
        ┌──────────────────────────────────────────────────────────────────┐
        │  scan_engine.py orchestrator (run_scan/run_advanced_scan/          │
        │  run_media_scan/run_api_scan) -> checks._mk_session()              │
        │  <-- SEC-03 GAP: plain requests.Session(), no per-hop re-check --> │
        │  -> checks.py check_* functions -> outbound HTTP to target         │
        └───────────────────────────┬────────────────────────────────────────┘
                                     │ Report JSON (server-generated filename)
                                     ▼
        ┌──────────────────────────────────────────────────────────────────┐
        │  Report/CSV routes: scan_id -> _check_ownership -> Report.data    │
        │  (Postgres) or REPORTS_DIR/<server-generated fname> fallback -    │
        │  no route ever accepts a filename/path directly (SEC-06)          │
        └──────────────────────────────────────────────────────────────────┘
```

### Existing IDOR-guard pattern (SEC-01) — extend, don't replace

Three equivalent shapes already exist, one per ownership model:

1. **`_check_ownership(s)`** (`scan_routes.py:95-101`) — owner-or-org-admin, 404-not-403.
2. **`_check_asset_access(a)`** (`asset_routes.py:48-61`) — org-shared (any member), with an
   explicit solo-user (`org_id is None`) branch to avoid a `NULL == NULL` bypass.
3. **Inline `if x.org_id != current_user.org_id: abort(404)`** — used directly in
   `org_routes.py` (`verify_domain_view`, `resend_invitation`, `revoke_invitation`,
   `request_domain_deletion`) and `api_tokens_routes.py` (`t.user_id != current_user.id`).

`billing_routes.verify_invoice_route` is the one place that uses `abort(403)` instead of `404`
for the cross-org case (`billing_routes.py:96`) — this is not a bug (both block access; the
roadmap's success criterion accepts "403/404, never 200"), just an inconsistency worth noting,
not worth "fixing" (changing it would be an unnecessary scope-creep edit against a
frozen-adjacent file).

### Pattern: SSRF-safe redirect-following session (SEC-03 fix)

**What:** Override `requests.Session.resolve_redirects` so every redirect hop's hostname is
re-validated through the existing `is_ssrf_safe_hostname()` before `requests` follows it.
**When to use:** Applied once, in `checks._mk_session()` — every check function already receives
its `session` object from this one factory (called once per orchestrator in `scan_engine.py`),
so this is a single-point fix, not a per-check-function change.
**Example:**
```python
# Source: requests 2.x public API (Session.resolve_redirects is a documented,
# stable generator method — https://requests.readthedocs.io/en/latest/api/#requests.Session.resolve_redirects)
# [CITED: requests.readthedocs.io/en/latest/api/]
import requests
from urllib.parse import urlparse

class _SSRFSafeSession(requests.Session):
    def resolve_redirects(self, *args, **kwargs):
        for resp in super().resolve_redirects(*args, **kwargs):
            hostname = urlparse(resp.url).hostname
            if not hostname or not is_ssrf_safe_hostname(hostname):
                # Stop following — do not yield this hop. The caller's
                # in-flight response is the *last safe* response reached.
                return
            yield resp

def _mk_session():
    s = _SSRFSafeSession()
    s.headers.update({"User-Agent": UA})
    return s
```
Note: `resolve_redirects` is a generator that `requests` internally drives via `Session.send()`'s
`allow_redirects=True` branch — early-returning from the override (rather than raising) means the
scan check simply receives the last-known-safe response, the same "a blocked connection surfaces
as a clean finding, not an exception" convention every other check in `checks.py` already follows
(`is_ssrf_safe_hostname`'s own docstring: "Unresolvable hostnames are treated as unsafe too, so
the caller gets a clean rejection instead of a confusing downstream connection-error finding").
Calls that already pass `allow_redirects=False` (`checks.py:536`, `:1049`) are unaffected — they
never entered `resolve_redirects` to begin with, so nothing needs to change there.

### Pattern: CSRF-enforcement regression test (SEC-02 test gap)

**What:** A second, CSRF-enabled Flask app instance built the same way
`test_login_rate_limit_is_enforced` builds a rate-limit-enabled one.
**When to use:** One dedicated test module (or a fixture reused across a few) proving a POST
without a `csrf_token` gets a 400, not the normal success redirect.
**Example:**
```python
# Source: tests/test_auth_flows.py:483-498 (existing project pattern for the
# equivalent RATELIMIT_ENABLED override) [VERIFIED: tests/test_auth_flows.py:483-498, this session]
def test_csrf_protection_rejects_post_without_token(tmp_path):
    from glassbox import create_app
    from tests.conftest import TestConfig

    class _CSRFEnabledConfig(TestConfig):
        WTF_CSRF_ENABLED = True
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'csrf.db'}"

    csrf_app = create_app(_CSRFEnabledConfig)
    with csrf_app.app_context():
        from glassbox.extensions import db as _db
        _db.create_all()
    client = csrf_app.test_client()
    # ... log in, then POST to a state-changing route with no csrf_token field
    resp = client.post("/org/admin/invite", data={"email": "x@example.com", "role": "member"})
    assert resp.status_code == 400
```
This is the model to replicate for at least one state-changing route per blueprint that has one
(auth, org, billing, asset, api_tokens) — not necessarily every single route, since the mechanism
(`CSRFProtect`, app-wide) is identical for all of them; one proof per blueprint is sufficient to
confirm the app-wide protection is actually wired up and not silently disabled anywhere unexpected.

### Anti-Patterns to Avoid
- **Re-implementing ownership checks per-route instead of reusing `_check_ownership`/
  `_check_asset_access`:** every existing IDOR guard is a thin wrapper reused across every route
  in its blueprint — a new route-specific check would risk drifting from the established
  404-vs-403 convention.
- **"Fixing" `verify_invoice_route`'s `abort(403)` to match the `abort(404)` convention:**
  out of scope — both already satisfy SEC-01's literal success criterion (never 200); changing it
  is unnecessary churn against a file adjacent to the frozen `billing.py`.
- **Adding `pytest-flask` or a new secrets-scanning package for this phase's tooling needs:**
  both have zero-new-dependency alternatives already idiomatic to this repo (see Alternatives
  Considered above) — don't add a dependency merely to save writing ~30 lines of script.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| CSRF token generation/validation | A custom hidden-field + session-nonce scheme | Flask-WTF's `CSRFProtect` (already wired) | Already app-wide; a hand-rolled parallel mechanism would only create confusion about which one actually protects a given route |
| Redirect-hop URL validation | A manual `while` loop re-implementing `requests`' redirect-following | `Session.resolve_redirects` override (see Code Examples) | `requests` already handles cookie-jar/auth-header/method-downgrade semantics correctly across redirects — reimplementing the loop risks losing that correctness for a net-new bug surface |
| Secrets detection | A custom regex-only scanner | Targeted `git log -p <range> \| grep -E` for known credential shapes, scoped to the milestone commit range | No new tool needed for a one-time, milestone-scoped sweep; a permanent CI secrets-scanner is legitimate future work but out of this phase's scope |

**Key insight:** Nearly every "Don't Hand-Roll" risk in this phase is avoided by simply *reusing*
patterns the codebase already established in Phases 1-7, not by introducing anything new.

## Runtime State Inventory

Not applicable — this is a code-audit/hardening phase, not a rename/refactor/migration phase. No
stored-data keys, live-service configs, OS-registered state, secret names, or build artifacts are
being renamed or moved by this phase's work.

## Common Pitfalls

### Pitfall 1: Assuming PUT/DELETE HTTP methods exist to audit
**What goes wrong:** The roadmap's success criterion literally says "audited across GET/POST/PUT/
DELETE." A planner could spend time hunting for PUT/DELETE routes that don't exist.
**Why it happens:** The phrasing is a generic REST-audit checklist, not a description of this
app's actual routing.
**How to avoid:** [VERIFIED: grepped `methods=\[` across `glassbox/*.py`, this session] —
the only non-GET method in the entire app is `POST` (mutations are POST to
action-suffixed paths like `/assets/<id>/delete`, `/tokens/<id>/revoke`, never a literal HTTP
DELETE/PUT verb). Interpret the criterion as "every GET (read) and POST (mutation) route," full
stop — there is nothing else to check.
**Warning signs:** A plan task that says "test PUT /assets/<id>" — there is no such route.

### Pitfall 2: `resolve_redirects` override breaking a legitimate single-hop redirect
**What goes wrong:** Many sites 301/302 `http://` to `https://` on the same hostname, or `example.com`
to `www.example.com` — both fully legitimate, non-SSRF redirects. An overly strict override that
rejects *any* hostname change (rather than checking whether the new hostname is unsafe) would
break normal scanning.
**Why it happens:** Conflating "redirect changed the hostname" with "redirect is unsafe."
**How to avoid:** The fix in Code Examples only rejects a hop when `is_ssrf_safe_hostname()`
returns `False` (private/loopback/link-local/reserved/multicast/unresolvable) — a same-site or
even cross-domain redirect to another *public* address is allowed through unchanged, matching
`is_ssrf_safe_hostname`'s existing semantics used at submission time.
**Warning signs:** A regression test failing on a redirect-to-`www.` scenario that should pass.

### Pitfall 3: Treating CONCERNS.md's coverage numbers as current
**What goes wrong:** Scoping SEC-01/D-05 work off CONCERNS.md's "15 lines"/"no test_scan_engine.py"
claims would massively over-scope this phase — those files are now 222-549 lines with real
cross-org/orchestrator coverage (Phase 4 already closed HARD-02/HARD-03).
**Why it happens:** CONCERNS.md is dated 2026-08-10, before Phase 4-7 landed.
**How to avoid:** This research's "Phase Requirements" table below reflects what's *actually*
tested today, verified by reading test files this session, not by trusting the stale doc.
**Warning signs:** A plan task that says "write org_routes.py tests from scratch" — most already
exist; the real gap is narrower (see below).

### Pitfall 4: Weakening `authorized*`/`entitlements.py`/`is_ssrf_safe_hostname()` while "closing a gap"
**What goes wrong:** A well-intentioned SEC-03 fix that, e.g., relaxes `is_ssrf_safe_hostname()`
to accept a wider address range "to reduce false-positive redirect rejections" would violate the
phase's explicit frozen-surface constraint (CLAUDE.md, CONTEXT.md canonical_refs).
**Why it happens:** SSRF-guard tuning is tempting to touch when debugging a redirect-following
test failure.
**How to avoid:** The fix belongs entirely in `checks._mk_session()`/a new `_SSRFSafeSession`
class — `is_ssrf_safe_hostname()` itself is called, not modified.
**Warning signs:** A diff touching `is_ssrf_safe_hostname()`'s body instead of only
`_mk_session()`.

## Code Examples

### Existing cross-org IDOR test pattern to replicate (org_routes.py gaps)
```python
# Source: tests/test_org_routes.py:155-166 (existing pattern, domain-deletion
# variant) [VERIFIED: tests/test_org_routes.py:155-166, this session]
def test_resend_invitation_is_org_scoped(client, db):
    org_a = make_org(name="Org A")
    org_b = make_org(name="Org B")
    make_user("admin_a@example.com", org=org_a, role=Role.ORG_ADMIN)
    make_user("admin_b@example.com", org=org_b, role=Role.ORG_ADMIN)
    db.session.commit()
    login(client, "admin_b@example.com")
    client.post("/org/admin/invite", data={"email": "x@example.com", "role": Role.MEMBER.value})
    inv = Invitation.query.filter_by(org_id=org_b.id).first()

    login(client, "admin_a@example.com")
    resp = client.post(f"/org/admin/invite/{inv.id}/resend", data={})

    assert resp.status_code == 404
# Same pattern applies verbatim to /org/admin/invite/<id>/revoke.
```

### Route-level billing test gaps to backfill (SEC-09)
```python
# Pattern: tests/test_billing.py already covers billing.py's collision-retry
# and double-tx-hash-match logic at the unit level [VERIFIED: tests/test_billing.py
# def test_create_invoice_raises_after_exhausting_retry_budget (line 107),
# def test_verify_invoice_double_match_on_matched_tx_hash_returns_false (line 272)].
# Missing: route-level proof that billing_routes.py actually rejects cross-org
# access and that a second verify POST on an already-PAID invoice is a no-op,
# not a re-activation. tests/test_billing_routes.py is only 58 lines/2 tests today.
def test_verify_invoice_route_rejects_cross_org(client, db):
    org_a, org_b = make_org(name="A"), make_org(name="B")
    make_user("admin_a@example.com", org=org_a, role=Role.ORG_ADMIN)
    make_user("admin_b@example.com", org=org_b, role=Role.ORG_ADMIN)
    inv = make_pending_invoice(org=org_b)  # test helper, mirrors CryptoInvoice fields
    db.session.commit()

    login(client, "admin_a@example.com")
    resp = client.post(f"/account/billing/invoice/{inv.id}/verify", data={})

    assert resp.status_code == 403  # billing_routes.py:96 — existing behavior, needs a test
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| N/A — this is an internal-consistency audit, not a library-version upgrade | N/A | N/A | N/A |

**Deprecated/outdated:** None relevant — no dependency in this phase's scope is deprecated.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The live-probe pass (D-01/D-02) should use a standalone `requests`-based script rather than a new `pytest-flask` dependency | Standard Stack, Alternatives Considered | Low — this is explicitly left to planner/researcher discretion per CONTEXT.md; if the planner disagrees, adding `pytest-flask` is a one-line `requirements-dev.txt` change, not a redesign |
| A2 | `git log -p 00ae203..HEAD` is the correct commit range for SEC-08's "added this milestone" secrets sweep | Alternatives Considered, Standard Stack | Low-Medium — if v1.1 actually started at a different commit than the doc-only kickoff commit, the sweep range would need adjusting; verify against `.planning/STATE.md`'s milestone-start date if in doubt |
| A3 | `resolve_redirects` override (vs. a custom `HTTPAdapter`) is the lowest-risk fix point for SEC-03 | Architecture Patterns, Code Examples | Medium — this is a training-knowledge claim about `requests`' internals, CITED against its public docs but not executed/tested this session; the planner's implementation task should include a live redirect-following test (a local Flask test route that 302s to `127.0.0.1`) to confirm the override actually behaves as described before treating SEC-03 as closed |

## Open Questions

1. **Does `_SSRFSafeSession.resolve_redirects` need to also guard against a redirect to a
   *resolvable-but-different* public IP than the one `is_ssrf_safe_hostname` checked (partial
   DNS-rebinding coverage), or is checking the redirect target's *hostname* alone sufficient?**
   - What we know: `is_ssrf_safe_hostname()`'s own docstring explicitly disclaims DNS-rebinding
     protection as out of scope (`checks.py:391-397`), and REQUIREMENTS.md's Out of Scope table
     confirms "DNS-rebinding-proof SSRF pinning" is excluded from this milestone.
   - What's unclear: whether re-resolving and re-checking each redirect hop's *hostname* (not
     pinning the IP) is enough to satisfy SEC-03's literal wording ("must not be followed
     unchecked") without also solving DNS-rebinding.
   - Recommendation: Yes — SEC-03 only asks that a redirect to a **known-private/loopback/
     link-local/metadata hostname or literal IP** not be followed unchecked. Re-checking the
     hostname per hop (as in the Code Examples pattern) satisfies this without reopening the
     explicitly-deferred DNS-rebinding-pinning question. Do not conflate the two.

2. **Should the live dev-server probe pass (D-01) use a throwaway `.env`/DB, or run against the
   developer's real local `glassbox.db`?**
   - What we know: CLAUDE.md documents `FLASK_SKIP_DOTENV=1` for `flask db` commands from a
     worktree to avoid touching a shared DB; the same caution likely applies to a live probe run.
   - What's unclear: whether the planner should script a disposable SQLite file + two seeded test
     orgs (matching `tests/conftest.py`'s per-test isolation ethos) or accept touching the real
     dev DB for a one-off manual run.
   - Recommendation: Use a disposable SQLite file (`SQLALCHEMY_DATABASE_URI=sqlite:///<tmp>/probe.db`)
     and `flask db upgrade` against it before `python app.py`, mirroring `tests/conftest.py`'s
     isolation pattern — never point the live probe at a real/shared database.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python venv (`.venv`) | Running `python app.py` for the live probe pass, running `pytest` | ✓ [VERIFIED: `.venv/Scripts/` listing, this session] | — | — |
| requests | SEC-03 fix, live probe script | ✓ [VERIFIED: `pip show requests`, this session] | 2.34.2 | — |
| Flask-WTF | SEC-02 audit/tests | ✓ [VERIFIED: `pip show flask-wtf`, this session] | 1.3.0 | — |
| pytest | All regression tests this phase adds | ✓ [VERIFIED: `pip show pytest`, this session] | 9.1.1 | — |
| `pytest-flask` (`live_server` fixture) | Not required — see Alternatives Considered | ✗ [VERIFIED: absent from `requirements-dev.txt`, this session] | — | Standalone `requests`-based script against a manually-started `python app.py` |
| `detect-secrets`/`gitleaks` | Not required — see Alternatives Considered | ✗ [VERIFIED: not on PATH, not pip-installed, this session] | — | `git log -p <range> \| grep` targeted secrets sweep |

**Missing dependencies with no fallback:** None.

**Missing dependencies with fallback:** `pytest-flask` (fallback: standalone script);
`detect-secrets`/`gitleaks` (fallback: scoped `git log -p` + grep sweep).

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 9.1.1 [VERIFIED: `.venv` `pip show pytest`, this session] |
| Config file | none detected (no `pytest.ini`/`pyproject.toml [tool.pytest]` found — pytest runs on default discovery from the repo root) |
| Quick run command | `.venv\Scripts\python -m pytest tests/test_<module>.py -x` |
| Full suite command | `.venv\Scripts\python -m pytest` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SEC-01 | Cross-org IDOR on scan/report/asset/domain/invoice/token/org/user routes, incl. `/api/v1/*` | integration | `pytest tests/test_scan_ownership.py tests/test_asset_routes.py tests/test_api_routes.py tests/test_api_tokens_routes.py tests/test_org_routes.py -k "cross or other_org or 404 or scoped" -x` | ✅ mostly (scan/asset/api already covered); ❌ Wave 0: `resend_invitation`/`revoke_invitation` cross-org test in `tests/test_org_routes.py` |
| SEC-02 | Every state-changing route carries CSRF | integration | new test module, e.g. `pytest tests/test_csrf_enforcement.py -x` | ❌ Wave 0 — no test currently re-enables `WTF_CSRF_ENABLED`; only markup-presence checks exist |
| SEC-03 | SSRF-safe hostname redirect-following to private/loopback/metadata is rejected | integration | `pytest tests/test_ssrf_guard.py -k redirect -x` | ❌ Wave 0 — `_mk_session()` fix + new redirect-following test needed |
| SEC-04 | No unescaped user-controlled HTML | integration/static | grep-verified this session (zero `\|safe`, zero `Markup()`) — add one regression test asserting a finding `title`/`detail` containing `<script>` renders HTML-escaped in `scan_report.html` | ❌ Wave 0 — add one explicit escaping-proof test |
| SEC-05 | No raw/string-interpolated SQL | static | grep-verified this session (only `db.text("SELECT 1")` static string + parameterized Core `update()`) | ✅ — optionally add a static regression grep-test locking this |
| SEC-06 | File-serving routes reject path traversal | integration | `pytest tests/test_scan_routes.py -k report -x` (existing) + new containment-assertion test | ❌ Wave 0 — add explicit `../`-in-`json_path` defense-in-depth test |
| SEC-07 | Redirect targets confined to app origin | unit | `pytest tests/test_auth_flows.py -k safe_next -x` | ✅ — `_safe_next()` already tested; confirm no other user-influenced redirect exists (verified via grep this session — none does) |
| SEC-08 | No hardcoded secrets added this milestone | manual/scripted | `git log -p 00ae203..HEAD \| grep -inE "(api[_-]?key\|secret\|password\|token)\s*=\s*['\"][A-Za-z0-9]{16,}"` | ❌ Wave 0 — no existing automated test; this is a one-time scripted sweep, document result in plan summary |
| SEC-09 | Billing replay/double-activation/tampering/cross-org rejected | unit + integration | `pytest tests/test_billing.py tests/test_billing_routes.py -x` | ✅ unit-level (`billing.py`); ❌ Wave 0 — route-level cross-org/replay tests in `tests/test_billing_routes.py` |
| SEC-10 | 400/401/403/404/429/500 leak nothing in production mode | integration | new test forcing `TESTING=False`/`DEBUG=False` and asserting no traceback substring in body | ❌ Wave 0 — no existing test simulates `DEBUG=False` explicitly (tests always run under `TESTING=True`) |

### Sampling Rate
- **Per task commit:** `.venv\Scripts\python -m pytest tests/test_<touched_module>.py -x`
- **Per wave merge:** `.venv\Scripts\python -m pytest`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `tests/test_org_routes.py` — add cross-org tests for `resend_invitation`/`revoke_invitation` (SEC-01)
- [ ] `tests/test_csrf_enforcement.py` (new) — `WTF_CSRF_ENABLED=True` app instance, prove a token-less POST 400s on at least one route per blueprint (SEC-02)
- [ ] `checks._mk_session()` fix — `_SSRFSafeSession.resolve_redirects` override (SEC-03, code fix not just a test)
- [ ] `tests/test_ssrf_guard.py` — add a redirect-following test (mock a 302 response to a private-IP `Location` header, assert the session does not follow it) (SEC-03)
- [ ] `tests/test_scan_routes.py` or new module — one explicit HTML-escaping proof test (SEC-04)
- [ ] `tests/test_billing_routes.py` — cross-org `verify_invoice_route`/`create_invoice` route-level tests, plus a double-verify-call idempotency test (SEC-09)
- [ ] new error-leakage test forcing `DEBUG=False` explicitly (SEC-10)
- [ ] `scripts/live_probe_phase8.py` (new, scratch/manual-run tooling per D-01/D-02) — standalone `requests` script against a disposable-DB `python app.py` instance with two seeded test orgs

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V1 Architecture (V1.14 SSRF) | yes | `is_ssrf_safe_hostname()` at submission + new redirect-hop guard in `_mk_session()` |
| V4 Access Control | yes | `_check_ownership`/`_check_asset_access`/inline `org_id` checks (already present, this phase adds missing regression coverage) |
| V5 Input Validation / Injection | yes | Jinja2 autoescape (XSS) + SQLAlchemy parameterization (SQLi) — both already enforced, verify-only this phase |
| V7 Error Handling & Logging | yes | `app.debug=False` in production (`app.run(debug=False)`, gunicorn never sets `app.debug=True`); custom 404/429/500 handlers; 400/401/403 fall through to Werkzeug's default (safe under `DEBUG=False`, not a leak) |
| V13 API and Web Service | yes | `csrf.exempt(api)` for Bearer-token routes is correct (token auth isn't cookie-based, CSRF doesn't apply — `api_routes.py:35` comment) — confirm this exemption is not broader than the `/api/v1/*` blueprint itself |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Cross-org IDOR via sequential integer IDs | Elevation of Privilege | `_check_ownership`/`_check_asset_access`/inline org_id checks, 404-not-403 |
| CSRF on session-cookie-authenticated POST | Spoofing / Elevation of Privilege | `Flask-WTF` `CSRFProtect`, app-wide |
| SSRF via redirect to internal/metadata address | Elevation of Privilege / Info Disclosure | `is_ssrf_safe_hostname()` at submission + (new) per-redirect-hop re-check |
| Stored/reflected XSS via scanned-site content or org/domain names | Tampering | Jinja2 autoescape (default on, verified zero `\|safe` usage) |
| SQL injection | Tampering | SQLAlchemy ORM/Core parameterized queries exclusively (verified zero raw interpolation) |
| Path traversal on report/media download | Info Disclosure | No route accepts a raw path; filenames are server-generated and DB-stored |
| Open redirect via `next=`/invite/logout | Spoofing (phishing) | `_safe_next()`, the only user-influenced redirect surface in the app (verified via grep) |
| Billing invoice replay / double-activation / cross-org access | Tampering / Elevation of Privilege | `matched_tx_hash` unique constraint + amount-collision-retry (`billing.py`) + `inv.org_id != current_user.org_id: abort(403)` (`billing_routes.py:96`) |
| Stack-trace/env-var leakage on error | Info Disclosure | `app.debug=False` always in production; custom themed 404/429/500 |

## Sources

### Primary (HIGH confidence)
- This session's direct `Read`/`Grep`/`Bash` inspection of: `glassbox/__init__.py`,
  `decorators.py`, `extensions.py`, `config.py`, `scan_routes.py`, `asset_routes.py`,
  `api_routes.py`, `api_tokens_routes.py`, `org_routes.py`, `billing_routes.py`,
  `admin_routes.py`, `domain_verification.py`, `auth_routes.py`, `checks.py` (session/redirect
  logic), `scan_engine.py` (session construction), `billing.py`, `models.py` (enum/column
  definitions), `app.py`, `Procfile`, `render.yaml`, and the full `tests/` directory listing plus
  targeted reads of `tests/conftest.py`, `tests/test_org_routes.py`, `tests/test_domain_verification.py`,
  `tests/test_scan_ownership.py`, `tests/test_asset_routes.py`, `tests/test_api_routes.py`,
  `tests/test_api_tokens_routes.py`, `tests/test_billing.py`, `tests/test_billing_routes.py`,
  `tests/test_auth_flows.py`, `tests/test_scan_engine.py`.
- `pip show requests / Flask-WTF / pytest` inside `.venv` (this session) — installed-version ground truth.
- `git log --oneline` (this session) — v1.1 milestone-kickoff commit identification for SEC-08's scope.

### Secondary (MEDIUM confidence)
- `requests` library's `Session.resolve_redirects` public API — [CITED: requests.readthedocs.io/en/latest/api/]
  training-knowledge-informed, not executed this session (see Assumption A3 / Open Question).

### Tertiary (LOW confidence)
- None — every claim in this document is either grep/read-verified this session or explicitly
  logged in the Assumptions table above.

## Metadata

**Confidence breakdown:**
- Standard Stack: HIGH — no new dependencies, all versions confirmed via `pip show`
- Architecture: HIGH — every route file read directly this session
- Pitfalls: HIGH — each pitfall grounded in a specific grep/read finding, not general advice

**Research date:** 2026-08-18
**Valid until:** 30 days (stable, internal-codebase-only research; re-verify if any route file
changes before planning begins)
