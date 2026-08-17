---
phase: 3
slug: compliance-framework-reporting
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-08-11
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 7.x |
| **Config file** | none — repo has no pytest.ini/pyproject pytest section beyond defaults |
| **Quick run command** | `.venv/Scripts/python -m pytest tests/test_compliance.py -q` |
| **Full suite command** | `.venv/Scripts/python -m pytest -q` |
| **Estimated runtime** | ~100 seconds (full suite; 217 tests as of Phase 2 close) |

---

## Sampling Rate

- **After every task commit:** Run `.venv/Scripts/python -m pytest tests/test_compliance.py -q` (or the relevant existing test file if a task touches `scan_report.html`/`asset_detail.html` rendering)
- **After every plan wave:** Run `.venv/Scripts/python -m pytest -q` (full suite)
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** ~100 seconds

---

## Per-Task Verification Map

*To be filled in by gsd-planner when PLAN.md tasks are created — each task's `<verify>` command
and requirement mapping populates this table.*

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| TBD | 01 | 1 | COMP-01..04 | — | N/A | unit | TBD | TBD | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/test_compliance.py` — new test file for the `CHECK_COMPLIANCE` mapping dict + its
      coverage-regression test (mirrors `tests/test_scan_events.py`'s `CHECK_LABELS`/
      `CHECK_CATEGORY` coverage test, per COMP-04 and `03-RESEARCH.md`'s findings)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|--------------------|
| Compliance category badge renders legibly on `scan_report.html` at desktop + mobile widths | COMP-02 | Visual/CSS correctness isn't assertable by pytest | Live browser check (iframe-based viewport emulation per `handoff.md`'s `resize_window` gotcha) at desktop and ~375px width |
| Per-Asset compliance-coverage summary reads correctly against a real multi-scan Asset | COMP-03 | Requires real scan history data, not just unit-level report-dict assertions | Run 2+ scans against a real Asset, view its compliance summary, confirm categories checked/failing match the underlying findings |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 100s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
