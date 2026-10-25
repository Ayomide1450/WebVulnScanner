---
phase: 8
slug: security-re-audit-hardening
status: complete
nyquist_compliant: true
wave_0_complete: true
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
| SEC-01 | Cross-org IDOR on scan/report/asset/domain/invoice/token/org/user routes, incl. `/api/v1/*` | integration | `pytest tests/test_cross_org_idor.py tests/test_scan_ownership.py tests/test_asset_routes.py tests/test_api_routes.py tests/test_api_tokens_routes.py tests/test_org_routes.py -x` | ✅ closed in 08-01: `tests/test_cross_org_idor.py`'s `url_map` enumeration lock, cross-org resend/revoke, `scan_report_csv`, `asset.update_schedule` | ✅ green |
| SEC-02 | Every state-changing route carries CSRF | integration | `pytest tests/test_csrf_enforcement.py -x` | ✅ closed in 08-02: 13 tests, real `WTF_CSRF_ENABLED=True` app instance, all six cookie-authenticated blueprints plus Smart Setup + exemption-scope lock | ✅ green |
| SEC-03 | SSRF-safe hostname redirect-following to private/loopback/metadata is rejected | integration | `pytest tests/test_ssrf_guard.py -x` | ✅ closed in 08-04: `checks._mk_session()` returns `_SSRFSafeSession`, proven against a real local `http.server` harness; **this was the phase's one confirmed-open live vulnerability**, fixed not just tested | ✅ green |
| SEC-04 | No unescaped user-controlled HTML | integration/static | `pytest tests/test_injection_and_traversal.py -x` | ✅ closed in 08-05: six escaping proofs + CSV counter-case + standing `\|safe`/`Markup()` source locks | ✅ green |
| SEC-05 | No raw/string-interpolated SQL | static | `pytest tests/test_injection_and_traversal.py -x` | ✅ closed in 08-05: exact-set allowlist lock over the app's only two raw `db.session.execute()` call sites, each independently proven safe | ✅ green |
| SEC-06 | File-serving routes reject path traversal | integration | `pytest tests/test_injection_and_traversal.py -x` | ✅ closed in 08-05: `scan_engine.read_report_file()` (realpath containment check), three call sites converted, reachability analysis recorded (not reachable today - defence in depth) | ✅ green |
| SEC-07 | Redirect targets confined to app origin | unit | `pytest tests/test_auth_flows.py -k safe_next -x` | ✅ closed in 08-06: seven adversarial `next` shapes, sole-surface source lock; **live finding fixed** - `_safe_next()` now also rejects backslash/CR/LF | ✅ green |
| SEC-08 | No hardcoded secrets added this milestone | scripted, self-tested | `.venv\Scripts\python scripts\secrets_sweep_phase8.py` / `pytest tests/test_secrets_hygiene.py -x` | ✅ closed in 08-06: `scripts/secrets_sweep_phase8.py`, working tree (265 files) + milestone commit range (108 commits) both clean, self-test proves patterns fire | ✅ green |
| SEC-09 | Billing replay/double-activation/tampering/cross-org rejected | unit + integration | `pytest tests/test_billing.py tests/test_billing_routes.py -x` | ✅ closed in 08-03: 15 tests at the route layer (cross-org 403, replay no-op, four tamper gates, org-id injection ignored, listing scope) | ✅ green |
| SEC-10 | 400/401/403/404/429/500 leak nothing in production mode | integration | `pytest tests/test_error_leakage.py -x` | ✅ closed in 08-06: first `TESTING=False`/`DEBUG=False` app config in the repo, all six status codes proven against a shared forbidden-substring constant | ✅ green |

**Live probe (D-01/D-02):** `scripts/live_probe_phase8.py` run against a real local
`python app.py` process (08-07 Task 2) - all 10 case(s) passed, exit code 0. See 08-07-SUMMARY.md
for the full per-case table.

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

All eight Wave 0 gaps identified at plan-creation time are closed:

- [x] `tests/test_org_routes.py` — cross-org tests for `resend_invitation`/`revoke_invitation` added (SEC-01, plan 08-01)
- [x] `tests/test_csrf_enforcement.py` (new) — `WTF_CSRF_ENABLED=True` app instance, token-less POST 400s proven on all six cookie-authenticated blueprints (SEC-02, plan 08-02)
- [x] `glassbox/checks.py` `_mk_session()` fix — `_SSRFSafeSession` overriding `get_redirect_target()` (not `resolve_redirects()` — that approach was tried and empirically falsified, see 08-04-SUMMARY.md) re-validates each hop's hostname (SEC-03, plan 08-04; this was the phase's one confirmed-open live vulnerability)
- [x] `tests/test_ssrf_guard.py` — redirect-following coverage against a real local `http.server` harness (SEC-03, plan 08-04)
- [x] new module — six explicit HTML-escaping proofs plus standing source locks (SEC-04, plan 08-05, `tests/test_injection_and_traversal.py`)
- [x] `tests/test_billing_routes.py` — cross-org `verify_invoice_route`/`create_invoice` route-level tests, replay idempotency test, four tamper gates (SEC-09, plan 08-03)
- [x] new error-leakage test forcing `DEBUG=False`/`TESTING=False` explicitly, all six status codes (SEC-10, plan 08-06, `tests/test_error_leakage.py`)
- [x] `scripts/live_probe_phase8.py` (new, scratch/manual-run tooling per CONTEXT.md D-01/D-02) — built (plan 08-07 Task 1) and run against a real local dev instance (plan 08-07 Task 2, all 10 cases passed, exit 0)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Result |
|----------|-------------|------------|--------|
| Live cross-org IDOR/CSRF probe against a running dev instance | SEC-01, SEC-02 | CONTEXT.md D-01/D-02 explicitly calls for a live-server pass supplementing (not replacing) the automated suite — no CI/pytest fixture substitutes for firing real HTTP requests at `python app.py` | **Done.** `scripts/live_probe_phase8.py --probe` run against a real `python app.py` on `http://127.0.0.1:5000`, seeded into a disposable SQLite file. All 10 cases passed, exit code 0. Full per-case table recorded in 08-07-SUMMARY.md. |
| Repo-wide secrets sweep | SEC-08 | One-time-per-milestone scripted sweep over commit history + working tree, not a plain pytest assertion over source alone | **Done.** `scripts/secrets_sweep_phase8.py` run directly: 265 files scanned in the working tree (clean), 108 commits swept in the milestone range (clean, all allowlisted hits have a written reason). Self-tested (`tests/test_secrets_hygiene.py`) to prove the patterns actually fire. Recorded in 08-06-SUMMARY.md. |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 540s (full suite)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved — phase evidence gate discharged, see 08-07-SUMMARY.md.
