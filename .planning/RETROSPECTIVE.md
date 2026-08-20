# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v1.1 — Production Audit, Hardening & Redesign

**Shipped:** 2026-08-20
**Phases:** 5 (numbered 5-9) | **Plans:** 25 | **Sessions:** multiple across ~5 days

### What Was Built
- Guided New Scan wizard (Select Domain → Select Type → Confirm Authorization → Start Scan)
  replacing four disconnected single-form pages, plus View Report reachability for every scan
  type (Phase 5)
- One canonical design-system token layer in `base.html`, fanned out across every template with
  no local drift left unconsolidated (Phase 6)
- Full responsive + accessibility compliance (320px-1280px, keyboard/AT operability, heading
  hierarchy, WCAG AA contrast) with standing regression locks (Phase 7)
- Full security re-audit of the v1.0-added API/scheduler/admin surfaces: cross-org IDOR
  enumeration lock, CSRF proof, the SEC-03 `_SSRFSafeSession` redirect-hop fix, injection/
  traversal sweep, closed via a real-process HTTP probe (Phase 8)
- SEO (robots.txt/sitemap.xml/meta tags/favicons), an N+1 audit (none found) plus real pagination
  on every unbounded list, and closed empty/submitting/duplicate-scan/timeout UX states (Phase 9)

### What Worked
- Freezing safety-critical code (`authorized*`, `entitlements.py`, `is_ssrf_safe_hostname()`) as
  an explicit constraint across the whole milestone meant no phase ever had to re-litigate
  whether a change was safe - it either touched frozen surface (not allowed) or didn't.
- Sequencing phases so each builds on a stable surface (redesign → design-system → responsive/a11y
  → security → SEO/perf) meant zero rework: no phase had to re-audit work a later phase was about
  to change underneath it.
- Phase 9 executed leanly (4 PLAN.md written directly by the main session, no researcher/planner/
  checker subagent cascade) per explicit user request to cut token overhead - zero merge conflicts
  across all 4 plans when merged, proving the file-disjoint wave-sequencing rationale held in
  practice without the extra subagent verification pass.
- Dispatching wave-parallel plans as background `gsd-executor` worktree agents (Phase 9's 09-01/
  09-02/09-04, then 09-03) let independent, file-disjoint work happen concurrently with clean
  `git merge --no-ff` results every time.

### What Was Inefficient
- Phase 9's three of four plans finished their execution without ever getting a SUMMARY.md
  written - discovered only at milestone-close time and had to be reconstructed retroactively
  from commit history/diffs. The lean-mode deviation (skip subagent cascade) should still end
  with each plan's SUMMARY.md written as part of closing that plan, not deferred indefinitely.
- Phases 5, 6, 7, and 9 each had a `checkpoint:human-verify`/live-verification gate that was
  never actually answered by a human across the whole milestone - closed via an explicit
  milestone-close override rather than real verification. The underlying implementation is done
  and test-covered, but the live-browser confirmation step itself is still owed.

### Patterns Established
- Background `gsd-executor` worktree agents for file-disjoint wave plans, verified by running the
  full test suite in the worktree before merge, `git merge --no-ff` into master, then a final
  full-suite run on the merged result before cleaning up the worktree/branch - repeatable pattern
  used successfully across all of Phase 9's four plans.
- When a plan's fix intentionally retires an old UI pattern (e.g. 09-02's `.warn-box` →
  `.empty-state` migration), the old regression test asserting the retired pattern needs its
  assertion updated in the same change, not left to fail as a false "gap."

### Key Lessons
1. A plan is not done until its SUMMARY.md exists, even under lean/token-saving execution -
   treat "write the summary" as part of the plan's own definition of done, not an optional
   wrap-up step that can slip.
2. `checkpoint:human-verify` gates left unanswered across a whole milestone should be resolved
   deliberately (schedule the live pass, or explicitly accept as milestone debt) rather than
   silently carried forward phase after phase - by milestone close they'd accumulated across 4 of
   5 phases.
3. Before assuming a test failure in freshly-merged work is a regression, check whether it's
   pre-existing on the base branch and/or reproducible in isolation - two of this milestone's
   post-merge "failures" turned out to be one intentional-migration stale assertion and one
   flaky unrelated test, not real regressions.

### Cost Observations
- Sessions: multiple, spanning Phase 5 discussion through Phase 9 lean execution and this
  milestone close
- Notable: Phase 9's lean-mode (no researcher/planner/checker subagents) plus background
  worktree-agent execution kept the phase's token cost noticeably lower than Phases 6-8's full
  subagent-cascade approach, with no loss of merge quality (zero conflicts, full suite green)

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Sessions | Phases | Key Change |
|-----------|----------|--------|------------|
| v1.0 | multiple | 4 | Initial GSD-driven build: asset inventory, API/CLI, compliance mapping, hardening |
| v1.1 | multiple | 5 | Introduced lean/no-subagent-cascade execution for scoped phases (Phase 9); background worktree-agent parallel execution used across the milestone |

### Top Lessons (Verified Across Milestones)

1. Freezing explicitly-named safety-critical code as a standing constraint (not just a one-time
   review) prevents an entire class of accidental regression across every phase that touches
   adjacent code.
