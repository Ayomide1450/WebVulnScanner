# Phase 30: Self-Hostable / Open-Core Decision

**Date**: 2026-08-25
**Decision**: **GO —有条件推进 (Conditional GO)**, scoped narrowly, deferred to v2 for execution
**Author**: Glassbox team (Claude + opencode)

---

## 1. Why This Question Exists

The 2026-08-22 audit flagged trust/data-residency as the single biggest adoption blocker for the
target audience (security engineers scanning their own production infrastructure). The exact quote
from `handoff.md`:

> A security engineer scanning their own production infra is often *more* wary of a third-party
> SaaS holding results than of the scan itself, and self-hostable/open-core (the Trivy/Semgrep
> model) is usually how tools in this space actually get adopted, hosted SaaS being the upsell
> rather than the front door.

This isn't hypothetical — it's the stated reason given by the first potential user who declined
to try the hosted version. The product's defensible position ("the most trustworthy,
engineer-controlled continuous web-app scanner") is undermined by requiring trust in a hosted
platform to use it at all.

---

## 2. What a Self-Hosted Edition Would/Wouldn't Include

### Included (the "core" that goes open)

| Component | Why it's core | Self-hosted feasibility |
|---|---|---|
| Scan engine (`checks.py`, `scan_engine.py`, all `check_*` functions) | The actual value prop — security detection logic | Trivial: pure Python, no external deps beyond `requests` |
| Community checks (`community_checks.py`, `checks/community/`) | Extensibility is the growth lever | Trivial: already a self-contained YAML loader |
| CLI (`cli/wvs.py`) | Engineer-first workflow; CLI is the front door in the Trivy model | Trivial: thin wrapper around the scan engine |
| SARIF/PDF/CSV export (`sarif_export.py`, report generation) | Portable artifacts are what engineers use in pipelines | Trivial: pure data transformation |
| API endpoints (token-authed scan triggers + report retrieval) | Pipeline integration requires API access | Moderate: needs to work without org/SaaS layers |
| Finding schema, compliance mapping, scoring (`_score_report`, `CHECK_COMPLIANCE`) | Core detection output | Trivial: already self-contained |
| SSRF safety (`is_ssrf_safe_hostname`) | Non-negotiable safety constraint | Trivial: already a standalone function |
| AI remediation summary (optional, local LLM) | Value-add but not core | Moderate: needs a local-model fallback path |

### Excluded (stays hosted-only / SaaS upsell)

| Component | Why it stays hosted | Self-hosting blocker |
|---|---|---|
| Crypto invoicing (`billing.py`, `billing_routes.py`, `CryptoInvoice` model) | Payment infrastructure has no business being in a self-hosted security tool | N/A: self-hosted users don't pay per-scan |
| Org management (`org_routes.py`, `Organization` model, invites) | Multi-tenant org model is a SaaS concept | Moderate: self-hosted would need a simpler auth model |
| Domain verification (`domain_verification.py`, DNS TXT/well-known checks) | Trust-gating for intrusive checks — meaningless when you own the infra | N/A: self-hosted users already own the infra |
| Tiered entitlement gating (`entitlements.py`) | Feature-gating by plan is a SaaS monetization layer | Moderate: would need a "self-hosted = all features unlocked" path |
| Platform admin (`admin_routes.py`) | Multi-tenant admin is SaaS-only | N/A |
| Webhook notifications (outbound to Slack/etc.) | Nice-to-have, not core | Low: could be added later if needed |
| Live scan progress SSE feed (`scan_events.py`) | UI polish, not detection | Low: could work locally with minor adaptation |
| Asset inventory + scheduling (`scheduler.py`, `Asset` model) | Persistence layer is SaaS-centric | Moderate: self-hosted would need SQLite + APScheduler |

### Gray Area (could go either way)

| Component | Consideration |
|---|---|
| AI summary via Groq | Could use local Ollama/llama.cpp instead; adds ~200MB dependency |
| Database (SQLite for self-hosted vs Postgres for SaaS) | SQLite is already the local dev default; self-hosted could use it trivially |
| Report storage (JSON on disk) | Already writes to `reports/`; self-hosted just skips the DB report row |

---

## 3. Licensing Model Options

### Option A: AGPL-3.0 (strong copyleft)

- **Precedent**: Grafana (pre-Elasticsearch), Gitea, Meilisearch
- **How it works**: Source available, anyone can self-host. If you modify the code and offer it as
  a service, you must release your modifications under AGPL. Commercial SaaS offering requires a
  separate commercial license.
- **Pros**: Maximum community trust; prevents a competitor from running a competing SaaS without
  contributing back; well-understood in the open-source world.
- **Cons**: Some enterprise users have blanket AGPL bans; limits adoption in corporate environments
  where legal review is slow.
- **Verdict**: Best fit for the "trust-first" positioning. The target audience (security engineers)
  overwhelmingly runs their own infra and would rather have AGPL assurance that no one else is
  running their scans on a third party.

### Option B: BSL 1.1 (Business Source License)

- **Precedent**: MariaDB, Grafana (current), HashiCorp
- **How it works**: Source available, free for non-commercial use. After a specified change date
  (typically 4 years), code converts to a standard open-source license.
- **Pros**: Protects against competitive SaaS while still being source-available; more
  enterprise-friendly than AGPL; gives a commercial moat.
- **Cons**: Not "open source" by OSI definition; some communities reject BSL as source-available
  rather than true open source; the 4-year conversion adds legal complexity.
- **Verdict**: Overkill for this stage. BSL is the right choice when you have a large user base
  to protect. At pre-v1.0 with no users, AGPL's community trust is more valuable.

### Option C: Apache 2.0 (permissive)

- **Precedent**: Semgrep, Trivy, most CNCF projects
- **How it works**: Anyone can do anything with the code, including run competing SaaS.
- **Pros**: Maximum adoption; no legal friction; enterprise-friendly; aligns with the
  security-tool ecosystem norms.
- **Cons**: Zero protection against someone running a competing hosted version; removes the
  commercial moat entirely.
- **Verdict**: Wrong choice for this product. The entire value proposition is trust and control.
  Apache 2.0 would let a VC-funded competitor fork the engine and undercut the hosted version on
  day one. The Trivy/Semgrep precedent is misleading — those projects have massive community
  contributions and CNCF backing that Glassbox doesn't have yet.

### Recommendation: **AGPL-3.0**

- Best matches the "trust-first" positioning
- Prevents competitive SaaS without contributing back
- The target audience (security engineers) is AGPL-literate and generally prefers it
- Enterprise AGPL concerns are a future problem, not a current one (zero enterprise users today)

---

## 4. Maintenance Burden of Two Deploy Shapes

### The Core Concern

Maintaining two deploy shapes (self-hosted + SaaS) doubles the testing matrix, increases
deployment complexity, and can create subtle feature divergence. This is the single biggest
argument against open-core.

### Why It's Manageable Here

1. **The codebase is small.** ~5,000 lines of application code across ~15 modules. A Nelson-style
   analysis says this is a team-of-one product. Doubling a small surface is still a small surface.

2. **The split is clean by module, not by conditional.** The excluded components (billing, org
   management, domain verification, platform admin) are already in separate route modules
   (`billing_routes.py`, `org_routes.py`, `admin_routes.py`). Self-hosting means not importing
   those modules — not maintaining `if self_hosted:` branches throughout the code.

3. **The scan engine has no SaaS dependencies.** `checks.py` and `scan_engine.py` don't import
   billing, org management, or tier-gating code. They depend only on `requests`, `bs4`, and the
   finding schema. This is the right boundary for an open core.

4. **SQLite is already the local dev default.** Self-hosted can use SQLite with zero additional
   work; SaaS uses Postgres. The models already work with both (with the `check_same_thread`
   caveat in `config.py`).

5. **The CLI already works standalone.** `cli/wvs.py` wraps the scan engine directly, bypassing
   Flask routes entirely. This is the natural self-hosted interface.

### What Adds Work

1. **A separate packaging/distribution step.** The SaaS is a Flask app; the self-hosted version
   needs a pip-installable package or Docker image with the CLI as the entry point.

2. **API route adaptation.** The API endpoints currently assume SaaS context (org membership,
   token auth tied to orgs). Self-hosted needs a simpler auth model (local API key or none).

3. **Two READMEs / two docs paths.** Self-hosted installation is different from SaaS deployment.
   This is a documentation burden, not a code burden.

4. **Community check curation.** The community checks directory ships with the self-hosted version.
   Malicious YAML is a supply-chain risk — need a review process or a `--no-community-checks`
   flag.

### Estimated Effort

- **Packaging + CLI entry point**: 1-2 days (Dockerfile + pyproject.toml + entry points)
- **Self-hosted auth model**: 1 day (local API key, no org complexity)
- **API adaptation**: 0.5 day (skip org-gated routes, return 404 for SaaS-only endpoints)
- **Docs**: 0.5 day (self-hosted README, Docker quickstart)
- **Total**: ~3-4 days of focused work, not a multi-week effort

---

## 5. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Feature divergence between self-hosted and SaaS | Medium | Medium | Strict rule: scan engine changes go in core first; SaaS-only features are additive, not entangled |
| Enterprise AGPL rejection | Low (current audience) | Low | Can dual-license later if enterprise demand materializes |
| Community check supply-chain attack | Low | High | `--community-checks-dir` flag; default shipped checks are curated; third-party checks require opt-in |
| Maintenance overhead exceeds benefit | Low | Medium | The split is module-based, not conditional; testing matrix grows by ~20% not 100% |
| Competitor forks the engine for free | Medium | Low | At pre-v1.0 with no users, distribution matters more than protection; AGPL prevents closed forks |

---

## 6. Decision

### **GO — Conditional推进**

**Recommendation**: Proceed with AGPL-3.0 open-core, but defer execution to v2.

**Rationale**:
- The trust/data-residency gap is real and documented; it's the #5 gap identified in the
  2026-08-22 audit and the only one that changes what the product fundamentally *is*
- The codebase architecture (module-separated SaaS vs core) makes the split clean
- The maintenance burden is manageable at current codebase size
- AGPL-3.0 is the right license for the positioning
- BUT: v1.7 is almost complete (Phases 27-29 shipped, 28 done, 30 is this doc); starting a
  packaging/CLI/distribution effort now would distract from the v1.8 cycle

**What happens now**:
- This decision is recorded. It will not be silently re-asked next milestone.
- v2.0 will include: AGPL-3.0 license, pip-installable package, Docker image, self-hosted
  README, simplified auth model for self-hosted mode
- v1.x remains SaaS-only (the scan engine changes that go into v1.x are still open-core-ready;
  they just aren't packaged for self-hosting yet)

---

## 7. Success Criteria (OSSD-01)

- [x] Decision doc covers: what's included/excluded, licensing model, maintenance burden
- [x] GO or NO-GO outcome recorded with reasoning
- [x] No follow-up phase scoped in this phase (deferred to v2 per the success criteria)
- [x] Question will not be silently re-asked (this doc is the permanent record)
