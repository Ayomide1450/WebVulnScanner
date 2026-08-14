---
phase: 2
slug: api-cli-access
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-08-10
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest (per `pytest.ini`, `testpaths = tests`) |
| **Config file** | `pytest.ini` (repo root) |
| **Quick run command** | `pytest tests/test_api_tokens_routes.py tests/test_api_routes.py tests/test_cli.py -x` |
| **Full suite command** | `pytest` (172 tests as of end of Phase 1) |
| **Estimated runtime** | ~30-90 seconds (full suite, growing with each phase) |

---

## Sampling Rate

- **After every task commit:** `pytest tests/test_api_tokens_routes.py tests/test_api_routes.py tests/test_cli.py -x`
- **After every plan wave:** `pytest` (full suite)
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 90 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 02-01-TBD | 02 | 1 | API-01 | V2 Authentication / V6 Cryptography | User generates a token, sees the raw value exactly once, list shows only hash-derived metadata; revoke sets `revoked_at` and immediately fails auth | integration | `pytest tests/test_api_tokens_routes.py -x` | ❌ W0 | ⬜ pending |
| 02-01-TBD | 02 | 1 | API-02 | V4 Access Control | `GET /api/v1/assets` lists only the caller's org/solo-scoped Assets + each one's latest Scan status, same scoping as existing ownership checks | integration | `pytest tests/test_api_routes.py::test_list_assets_scoped -x` | ❌ W0 | ⬜ pending |
| 02-01-TBD | 02 | 1 | API-03 | V4 Access Control / V13 | `POST /api/v1/assets/<id>/scans` creates a `Scan` via `scheduler._fire`, re-checks SSRF/tier fresh, 404s for a non-owning org | integration | `pytest tests/test_api_routes.py::test_trigger_scan -x` | ❌ W0 | ⬜ pending |
| 02-01-TBD | 02 | 1 | API-04 | V4 Access Control | `GET /api/v1/scans/<id>/report` returns the same JSON the scan engine wrote, 404s for a non-owning caller (fixes the `_check_ownership`/`_check_asset_access` mismatch for this route) | integration | `pytest tests/test_api_routes.py::test_fetch_report -x` | ❌ W0 | ⬜ pending |
| 02-01-TBD | 02 | 1 | API-05 | V13 API and Web Service | A revoked/invalid token gets 401 not 500; a Free-tier token triggering a media/api scan gets the same tier-gate failure the scheduler already produces; rate limit returns 429 past threshold | integration | `pytest tests/test_api_routes.py::test_tier_gating_and_rate_limit -x` | ❌ W0 | ⬜ pending |
| 02-02-TBD | 02 | 2 | API-06 | — | CLI `login`/`assets list`/`scan start`/`report get` commands call the right endpoint and format output correctly, against a mocked/local API server | unit (mocked HTTP) | `pytest tests/test_cli.py -x` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*
*Task IDs are placeholders — the planner assigns real task IDs; this map's requirement→test
binding is the durable contract, not the specific ID string.*

---

## Wave 0 Requirements

- [ ] `tests/test_api_tokens_routes.py` — new file, covers API-01
- [ ] `tests/test_api_routes.py` — new file, covers API-02/03/04/05
- [ ] `tests/test_cli.py` — new file, covers API-06 (mock `requests` calls; no live Flask server
      needed)
- [ ] `tests/conftest.py` extension: a `make_api_token(user, name="test", revoked=False)` factory,
      mirroring the existing `make_asset`/`make_scan`/`make_user` helpers exactly — returns both
      the `ApiToken` row and the raw token string (generated inline, matching the real
      create-route's shape) so tests can authenticate as `Authorization: Bearer <raw>` without
      going through the HTML create-route first.
- [ ] Framework install: none — pytest already configured; `click` already resident via Flask's
      dependency chain (confirmed via `pip show` this session).

---

## Manual-Only Verifications

*None — all phase behaviors have automated verification per the map above.*

---

## Security Domain (from RESEARCH.md)

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | yes | Hash-only stored secrets (SHA-256 of a `secrets.token_urlsafe(32)` value), never plaintext, never logged |
| V3 Session Management | yes (partial) | Token auth is deliberately not session-based — `request_loader` must not set a session cookie for token-authenticated requests |
| V4 Access Control | yes | Every existing ownership/tier check reused unchanged per D-02 — no new authorization model introduced |
| V5 Input Validation | yes | `Authorization` header format validated before any DB query; existing form-validation allow-lists apply unchanged to token-management forms |
| V6 Cryptography | yes | `secrets.token_urlsafe` (CSPRNG) for generation, `hashlib.sha256` for storage-hash — never hand-roll |
| V13 API and Web Service | yes | Rate limiting + tier gating (API-05) enforces authorization at the API layer, not just the UI |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| Token leaked via logs/error pages | Information Disclosure | Never store/log the raw token past the single create-request; exclude the create-token route from verbose request-body logging |
| Token replay after revocation | Elevation of Privilege | `request_loader`'s lookup filters `revoked_at IS NULL` on every single request — never cached |
| Cross-org data leak via a token | Elevation of Privilege | D-02 forbids by design — a token can never see/do more than its creating user's session already could |
| Brute-forcing token values | Elevation of Privilege | 256 bits of entropy makes brute force infeasible; rate-limiting `/api/v1/*` additionally throttles guessing |
| SSRF via API-triggered scan bypassing web UI checks | Tampering / Elevation of Privilege | `scheduler._fire()` reuse guarantees `is_ssrf_safe_hostname` and tier gating run identically for API-triggered and scheduler-triggered scans |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending — planner will consume this map; sign-off completes after PLAN.md is created and verified.
