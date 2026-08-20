# Phase 5: New Scan Flow Redesign - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-15
**Phase:** 5-new-scan-flow-redesign
**Areas discussed:** Domain-picker data source, Which scan types get the wizard, Upgrade-to-Unlock behavior, Post-launch / View Report placement

---

## Domain-picker data source

| Option | Description | Selected |
|--------|-------------|----------|
| Verified domains only | Dropdown lists only org-verified DomainVerification records; free-text stays equally visible | ✓ |
| Verified domains + registered Assets | Combine both record types into one dropdown | |
| Assets only | Only registered Assets, verified-but-unregistered domains excluded | |

**User's choice:** Verified domains only (Recommended option)
**Notes:** None beyond the recommendation — matches the requirement wording ("Select Verified Domain") exactly.

---

## Which scan types get the wizard

| Option | Description | Selected |
|--------|-------------|----------|
| All 4, Advanced routes to its existing form | Wizard shell for all types; Advanced's step routes into its existing credentials form | ✓ |
| Only Base/Media/API get the wizard | Advanced keeps its current separate page unchanged | |
| One universal dynamic form | Single form dynamically reveals Advanced's credential fields inline | |

**User's choice:** All 4, Advanced routes to its existing form (Recommended option)
**Notes:** Reuses existing credential-collection UI rather than building new dynamic-field logic — recorded as `costly` reversibility in CONTEXT.md D-02 since unifying further later would mean reworking the wizard/dedicated-form routing.

---

## Upgrade-to-Unlock behavior

| Option | Description | Selected |
|--------|-------------|----------|
| Context-aware destination | Links to Billing when tier is the gate, Verify Domain when domain-verification is the gate | ✓ |
| Always links to Billing | Single destination regardless of actual gate | |
| Inline explanation, no navigation | Tooltip/expandable explanation in place | |

**User's choice:** Context-aware destination (Recommended option)
**Notes:** Reuses existing `_tier_flags()` booleans plus `domain_is_org_verified()` to decide the destination — no new gating logic, just new UI branching on values that already exist.

---

## Post-launch / View Report placement

| Option | Description | Selected |
|--------|-------------|----------|
| Extend existing auto-redirect to advanced/media/api | Add polling to the non-SSE progress page so it also auto-redirects to the report on completion | ✓ |
| No changes needed | Treat existing next-page-load redirect as already satisfying SCANUX-05 | |
| Also add a landing-page shortcut | Do the poll/refresh fix AND add a "Your last scan" card on /scan/new | |

**User's choice:** Extend existing auto-redirect to advanced/media/api (Recommended option)
**Notes:** `scan_detail()` already redirects COMPLETED scans to the report, but only on a fresh page load — advanced/media/api's progress page has no polling at all today, so a user watching it wouldn't know to reload. Closes a real, previously-undocumented gap rather than a cosmetic one.

---

## Claude's Discretion

- Wizard mechanics (multi-page vs. single-page progressive JS) — follow existing GET+POST,
  minimal-JS convention already used across the app.
- Exact copy beyond what SCANUX-03 specifies verbatim.
- Whether D-04's polling reuses the existing `/scan/<id>/events` SSE endpoint or a new
  lightweight status endpoint.

## Deferred Ideas

None scope-wise. One cross-cutting process note (not specific to this phase): the user asked
that `handoff.md` be updated continuously through this milestone's work, not just at session end —
recorded in CONTEXT.md's `<deferred>` section as a standing practice for every phase.
