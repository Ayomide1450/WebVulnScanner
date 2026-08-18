---
phase: 8
slug: security-re-audit-hardening
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-08-18
---

# Phase 8 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 9.1.1 |
| **Config file** | none detected — pytest runs on default discovery from the repo root |
| **Quick run command** | `.venv\Scripts\python -m pytest tests/test_<module>.py -x` |
| **Full suite command** | `.venv\Scripts\python -m pytest` |
| **Estimated runtime** | ~540 seconds (full suite, per this session's confirmed 646-test run) |

---

## Sampling Rate

- **After every task commit:** Run `.venv\Scripts\python -m pytest tests/test_<touched_module>.py -x`
- **After every plan wave:** Run `.venv\Scripts\python -m pytest`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** ~10 seconds per touched module, ~540 seconds for a full-suite wave gate

---

## Per-Task Verification Map

| Req ID | Behavior | Test Type | Automated Command | File Exists | Status |
|--------|----------|-----------|-------------------|-------------|--------|
| SEC-01 | Cross-org IDOR on scan/report/asset/domain/invoice/token/org/user routes, incl. `/api/v1/*` | integration | `pytest tests/test_scan_ownership.py tests/test_asset_routes.py tests/test_api_routes.py tests/test_api_tokens_routes.py tests/test_org_routes.py -k "cross or other_org or 404 or scoped" -x` | ✅ mostly; ❌ Wave 0: `resend_invitation`/`revoke_invitation` cross-org test in `tests/test_org_routes.py` | ⬜ pending |
| SEC-02 | Every state-changing route carries CSRF | integration | `pytest tests/test_csrf_enforcement.py -x` (new module) | ❌ Wave 0 — no test currently re-enables `WTF_CSRF_ENABLED`; only markup-presence checks exist today | ⬜ pending |
| SEC-03 | SSRF-safe hostname redirect-following to private/loopback/metadata is rejected | integration | `pytest tests/test_ssrf_guard.py -k redirect -x` | ❌ Wave 0 — `_mk_session()` fix (real vulnerability, not just missing test) + new redirect-following test needed | ⬜ pending |
| SEC-04 | No unescaped user-controlled HTML | integration/static | grep-verified this session (zero `\|safe`, zero `Markup()`) — add one regression test asserting a finding `title`/`detail` containing `<script>` renders HTML-escaped in `scan_report.html` | ❌ Wave 0 — add one explicit escaping-proof test | ⬜ pending |
| SEC-05 | No raw/string-interpolated SQL | static | grep-verified this session (only `db.text("SELECT 1")` static string + parameterized Core `update()`) | ✅ — optional static regression grep-test locking this | ⬜ pending |
| SEC-06 | File-serving routes reject path traversal | integration | `pytest tests/test_scan_routes.py -k report -x` (existing) + new containment-assertion test | ❌ Wave 0 — add explicit `../`-in-`json_path` defense-in-depth test | ⬜ pending |
| SEC-07 | Redirect targets confined to app origin | unit | `pytest tests/test_auth_flows.py -k safe_next -x` | ✅ `_safe_next()` already tested; no other user-influenced redirect exists (verified via grep this session) | ⬜ pending |
| SEC-08 | No hardcoded secrets added this milestone | manual/scripted | `git log -p 00ae203..HEAD \| grep -inE "(api[_-]?key\|secret\|password\|token)\s*=\s*['\"][A-Za-z0-9]{16,}"` | ❌ Wave 0 — no existing automated test; one-time scripted sweep, document result in plan summary | ⬜ pending |
| SEC-09 | Billing replay/double-activation/tampering/cross-org rejected | unit + integration | `pytest tests/test_billing.py tests/test_billing_routes.py -x` | ✅ unit-level; ❌ Wave 0 — route-level cross-org/replay tests in `tests/test_billing_routes.py` | ⬜ pending |
| SEC-10 | 400/401/403/404/429/500 leak nothing in production mode | integration | new test forcing `TESTING=False`/`DEBUG=False`, asserting no traceback substring in body | ❌ Wave 0 — no existing test simulates `DEBUG=False` explicitly | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/test_org_routes.py` — add cross-org tests for `resend_invitation`/`revoke_invitation` (SEC-01)
- [ ] `tests/test_csrf_enforcement.py` (new) — `WTF_CSRF_ENABLED=True` app instance, prove a token-less POST 400s on at least one route per blueprint (SEC-02)
- [ ] `webvulnscanner/checks.py` `_mk_session()` fix — `_SSRFSafeSession.resolve_redirects` override re-validating each hop's hostname (SEC-03; a real, currently-open vulnerability, not just a missing test — see Research §Validation Architecture)
- [ ] `tests/test_ssrf_guard.py` — redirect-following test (mock a 302 to a private-IP `Location` header, assert the session does not follow it) (SEC-03)
- [ ] `tests/test_scan_routes.py` or new module — one explicit HTML-escaping proof test (SEC-04)
- [ ] `tests/test_billing_routes.py` — cross-org `verify_invoice_route`/`create_invoice` route-level tests, plus a double-verify-call idempotency test (SEC-09)
- [ ] new error-leakage test forcing `DEBUG=False` explicitly (SEC-10)
- [ ] `scripts/live_probe_phase8.py` (new, scratch/manual-run tooling per CONTEXT.md D-01/D-02) — standalone `requests` script against a disposable-DB `python app.py` instance with two seeded test orgs, for the live dev-server probe pass

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Live cross-org IDOR/CSRF probe against a running dev instance | SEC-01, SEC-02 | CONTEXT.md D-01/D-02 explicitly calls for a live-server pass supplementing (not replacing) the automated suite — no CI/pytest fixture substitutes for firing real HTTP requests at `python app.py` | Run `scripts/live_probe_phase8.py` against a locally started `python app.py` with two seeded orgs; record pass/fail per route family in the plan's summary |
| Repo-wide secrets sweep | SEC-08 | One-time historical `git log -p` grep sweep, not a repeatable pytest assertion | Run the `git log -p` command in the Per-Task Verification Map row for SEC-08; record the result (clean or findings) in the plan's summary |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 540s (full suite)
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
