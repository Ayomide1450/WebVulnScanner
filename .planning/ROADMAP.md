# Roadmap: WebVulnScanner

## Milestones

- ✅ **v1.0 Asset Inventory, API/CLI, Compliance & Hardening** - Phases 1-4 (shipped 2026-08-13)
- ✅ **v1.1 Production Audit, Hardening & Redesign** - Phases 5-9 (shipped 2026-08-20)

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order. Phase numbering is
continuous across milestones.

<details>
<summary>✅ v1.0 Asset Inventory, API/CLI, Compliance & Hardening (Phases 1-4) - SHIPPED 2026-08-13</summary>

- [x] **Phase 1: Asset Inventory & Continuous Scanning** - Targets become persistent Assets that can be scanned on a recurring schedule, not just one-shot submissions.
- [x] **Phase 2: API & CLI Access** - Security teams can manage assets and scans programmatically instead of only through the web UI.
- [x] **Phase 3: Compliance & Framework Reporting** - Findings are mapped to OWASP Top 10/ASVS categories for audit-usable reporting.
- [x] **Phase 4: Production Hardening & Reliability** - The platform holds up under real multi-worker production load with test coverage and visual consistency matching a "production ready" bar.

Full phase detail archived at `.planning/milestones/v1.0-ROADMAP.md`.

</details>

<details>
<summary>✅ v1.1 Production Audit, Hardening & Redesign (Phases 5-9) - SHIPPED 2026-08-20</summary>

- [x] **Phase 5: New Scan Flow Redesign** - `/scan/new` became a guided Select Domain → Select Type → Confirm Authorization → Start Scan flow instead of four disconnected single-form pages.
- [x] **Phase 6: Design System Consistency** - Every template draws from one canonical typography scale, spacing scale, component style set, and container-width convention.
- [x] **Phase 7: Responsive & Accessibility Compliance** - Every page renders correctly from 320px to desktop and is fully operable by keyboard/assistive technology.
- [x] **Phase 8: Security Re-Audit & Hardening** - Every ID-accepting route, form, redirect, and file-serving path across the app (including v1.0's new API/scheduler/admin surfaces) is verified to enforce its existing safety guarantees, with gaps closed.
- [x] **Phase 9: SEO, Performance & UX States** - Public pages are correctly indexable, list-heavy pages don't degrade at scale, and every page communicates loading/empty/error states clearly.

Full phase detail archived at `.planning/milestones/v1.1-ROADMAP.md`.

**Known gap at close:** Phases 5, 6, 7, and 9's `checkpoint:human-verify`/live-verification
gates were never answered by a human (explicit user instruction: proceed without blocking on
them). All underlying work is implemented and covered by automated tests/regression locks
(802 passing at milestone close) — the gap is specifically the live-browser/human-observation
confirmation step, not missing implementation. See `.planning/milestones/v1.1-REQUIREMENTS.md`
and `STATE.md`'s Deferred Items for detail.

</details>

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Asset Inventory & Continuous Scanning | v1.0 | 2/2 | Complete | 2026-08-11 |
| 2. API & CLI Access | v1.0 | 3/3 | Complete | 2026-08-11 |
| 3. Compliance & Framework Reporting | v1.0 | 3/3 | Complete | 2026-08-11 |
| 4. Production Hardening & Reliability | v1.0 | 5/5 | Complete | 2026-08-13 |
| 5. New Scan Flow Redesign | v1.1 | 3/3 | Complete | 2026-08-20 |
| 6. Design System Consistency | v1.1 | 4/4 | Complete | 2026-08-20 |
| 7. Responsive & Accessibility Compliance | v1.1 | 7/7 | Complete | 2026-08-20 |
| 8. Security Re-Audit & Hardening | v1.1 | 7/7 | Complete | 2026-08-19 |
| 9. SEO, Performance & UX States | v1.1 | 4/4 | Complete | 2026-08-20 |
