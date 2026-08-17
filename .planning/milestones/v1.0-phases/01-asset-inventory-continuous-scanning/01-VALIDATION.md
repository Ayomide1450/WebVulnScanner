---
phase: 1
slug: asset-inventory-continuous-scanning
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-08-10
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest [VERIFIED: pytest.ini:1-2, quoted: "[pytest] \n testpaths = tests"] |
| **Config file** | `pytest.ini` (repo root) |
| **Quick run command** | `pytest tests/test_scheduler.py tests/test_asset_routes.py -x` |
| **Full suite command** | `pytest` |
| **Estimated runtime** | ~30-60 seconds (full suite; project scale as of 2026-08-10) |

---

## Sampling Rate

- **After every task commit:** Run `pytest tests/test_scheduler.py tests/test_asset_routes.py -x`
- **After every plan wave:** Run `pytest` (full suite — this phase touches shared modules like
  `entitlements.py` and `models.py`, so regressions could surface in unrelated existing tests,
  e.g. `tests/test_entitlements.py`, `tests/test_scan_ownership.py`)
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 01-01-TBD | 01 | 1 | ASSET-01 | — | Asset registration creates a row, appears in inventory list | integration (route) | `pytest tests/test_asset_routes.py -k registration -x` | ❌ W0 | ⬜ pending |
| 01-01-TBD | 01 | 1 | ASSET-02 | V5 Input Validation | Registration rejects missing checkbox / unsafe hostname | integration (route) | `pytest tests/test_asset_routes.py -k authorization_and_ssrf -x` | ❌ W0 | ⬜ pending |
| 01-01-TBD | 01 | 1 | ASSET-03 | — | Schedule config (cadence + scan type) persists correctly | unit/integration | `pytest tests/test_asset_routes.py -k schedule_config -x` | ❌ W0 | ⬜ pending |
| 01-01-TBD | 01 | 1 | ASSET-04 | — | A due Asset fires a scan producing `Scan`/`Report` linked via `asset_id` | unit (scheduler) | `pytest tests/test_scheduler.py -k tick_fires_due_asset -x` | ❌ W0 | ⬜ pending |
| 01-01-TBD | 01 | 1 | ASSET-05 | — | History/trend view returns multiple scans for one Asset, ordered | integration (route) | `pytest tests/test_asset_routes.py -k history -x` | ❌ W0 | ⬜ pending |
| 01-01-TBD | 01 | 1 | ASSET-06 | — | Pause/resume/delete mutate `is_paused`/row correctly | integration (route) | `pytest tests/test_asset_routes.py -k pause_resume_delete -x` | ❌ W0 | ⬜ pending |
| 01-01-TBD | 01 | 1 | ASSET-07 | V1 Architecture / Business Logic | Free-tier Asset scheduled for media/api never runs; downgrade mid-cycle is respected at next fire — **highest-priority new test given Pitfall 1** | unit (scheduler) | `pytest tests/test_scheduler.py -k tier_gating -x` | ❌ W0 | ⬜ pending |
| 01-01-TBD | 01 | 1 | ASSET-08 | V1 Architecture / Business Logic | Two concurrent claim attempts on the same due Asset: only one succeeds | unit (claim guard) | `pytest tests/test_scheduler.py -k claim_guard_race -x` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*
*Task IDs are placeholders (`01-01-TBD`) — the planner assigns real task IDs; this map's
requirement→test binding is the durable contract, not the specific ID string.*

---

## Wave 0 Requirements

- [ ] `tests/test_scheduler.py` — new file, covers ASSET-04/07/08 (tick loop, claim guard,
      tier-gate replication for media/api)
- [ ] `tests/test_asset_routes.py` — new file, covers ASSET-01/02/03/05/06
- [ ] `tests/conftest.py` — extend with a `make_asset(...)` factory function, following the
      existing `make_scan`/`make_org`/`make_user` pattern
      [VERIFIED: tests/conftest.py:85-118, quoted factory signatures: "def make_org(plan=Plan.FREE,
      name=\"Test Org\"):" / "def make_scan(user, org=None, target_url=\"https://example.com\",
      scan_type=\"base\", status=ScanStatus.QUEUED):"], and set `SCHEDULER_ENABLED = False` on
      `TestConfig` (required — the in-process scheduler thread must not start under the
      fresh-app-per-test fixture, or every test leaks an infinite background thread).
- [ ] Framework install: none — pytest is already installed and configured.

---

## Manual-Only Verifications

*None — all phase behaviors have automated verification per the map above.*

---

## Security Domain (from RESEARCH.md)

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V4 Access Control | yes | Asset ownership scoped to `org_id`; reuse the existing 404-not-403 ownership-check convention (`_check_ownership` pattern in `scan_routes.py`) for cross-org Asset access |
| V5 Input Validation | yes | `is_ssrf_safe_hostname()` reused at both registration time and every scheduled fire; cadence/scan-type values validated against a fixed allow-list, not free text |
| V1 Architecture / Business Logic | yes | Claim-guard race-condition prevention (D-02); tier-gate replication for the scheduler's non-self-gating orchestrators is a business-logic authorization-boundary concern |
| V2 Authentication | no (unchanged) | Existing Flask-Login session auth applies unchanged to the new `asset_routes.py` blueprint via `@login_required` |
| V3 Session Management | no (unchanged) | No new session state introduced by this phase |
| V6 Cryptography | no | Not applicable |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| SSRF via a long-lived Asset whose target later resolves to a private address | Tampering / Elevation of Privilege | Re-check `is_ssrf_safe_hostname()` at every scheduled fire, not just registration |
| Privilege escalation via tier-downgrade bypass — a Free-tier org's schedule keeps running Paid/Org-verified checks | Elevation of Privilege | Recompute `effective_tier`/`FEATURE_REQUIREMENTS` gate at fire time, not schedule-creation time (ASSET-07's core requirement) |
| Double-fire / duplicate scan execution under concurrent workers | Tampering (data integrity) | D-02's conditional-UPDATE claim guard |
| Cross-org Asset access (viewing/pausing/deleting another org's Asset by guessing an ID) | Information Disclosure / Elevation of Privilege | Mirror `_check_ownership`'s 404-not-403 convention for every Asset route |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending — planner will consume this map; sign-off completes after PLAN.md is created and verified.
