# Phase 3: Compliance & Framework Reporting - Research

**Researched:** 2026-08-11
**Domain:** Security-finding taxonomy / compliance-framework mapping (OWASP Top 10:2021, OWASP ASVS 4.0.3) layered onto an existing Flask vulnerability-scanner report pipeline
**Confidence:** MEDIUM (framework category list and codebase data flow are HIGH confidence; the specific check→OWASP/ASVS assignments are judgment calls, tagged `[ASSUMED]`, and should get a quick human sanity pass before being treated as locked)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** OWASP Top 10 category is the required/primary mapping for every check that gets
  mapped. ASVS control ID is an optional secondary tag, added only where it adds real audit value
  (not mandatory per check). Satisfies COMP-01's "OWASP Top 10 (and/or ASVS)" wording while
  keeping the mapping-authoring burden proportionate. — Reversibility: costly — adding ASVS
  later is additive (no breaking change), but retrofitting it onto checks shipped without it means
  re-touching every check's mapping entry a second time.
- **D-02:** Rationale for this split: the target audience spans both companies needing audit-grade
  detail and solo/vibe-coder users who need a quick, recognizable label. OWASP Top 10 is the
  broadly-recognized layer; ASVS is the audit-grade layer, added opportunistically.
- **D-03:** All checks across all 4 scan types (base/advanced/media/api) get a mapping entry in
  this phase — not just base-scan checks. Follows the same all-checks convention already
  established by `CHECK_LABELS`/`CHECK_CATEGORY` in `checks.py`.
- **D-04:** Checks/findings that don't map cleanly to any OWASP/ASVS category (info-only, pass
  findings, etc.) get an explicit "Uncategorized" bucket in the compliance view rather than being
  silently dropped — mirrors `CHECK_CATEGORY`'s existing `"shield"` icon fallback pattern.

### Claude's Discretion

- Report grouping/filter UX (new tab vs. toggle vs. inline badges on `scan_report.html`) — not
  discussed, left to planner/UI-SPEC judgment.
- Per-Asset compliance summary placement (new page vs. a section on `asset_detail.html`) and
  exact "currently failing" semantics (most-recent-scan-only vs. any-scan-in-history) — not
  discussed, left to planner/UI-SPEC judgment. Planner should pick the interpretation consistent
  with how `asset_detail.html` already presents scan history (Phase 1), and document the choice
  explicitly since it's user-visible.
- Exact mapping data structure (new dict in `checks.py`, e.g. `CHECK_COMPLIANCE`, following the
  `CHECK_LABELS`/`CHECK_CATEGORY` key-set convention) and how COMP-04's coverage-regression-test
  requirement gets implemented — technical detail, left to planner. (This research proposes a
  concrete design below — see "Architecture Patterns".)

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope. Only "Framework scope" was selected for discussion;
the other 3 identified gray areas (report grouping/filter UX, per-Asset summary placement, mapping
data maintenance) were explicitly left to planner discretion, not deferred to a future phase.

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| COMP-01 | Each check/finding category is tagged with the OWASP Top 10 category (and/or ASVS control) it maps to. | Full 26-entry proposed mapping table below (Standard Stack / Don't Hand-Roll sections), keyed by check name; concrete `CHECK_COMPLIANCE` dict design + `Finding.check_name` field recommendation in Architecture Patterns. |
| COMP-02 | A scan report includes a compliance-framework view — findings grouped/filterable by framework category, not only by severity. | `scan_report.html`'s existing `sort(attribute='category')` grouping loop (read this session, lines 111-132) is the exact mechanism to parallel/extend; Code Examples section shows the minimal diff. |
| COMP-03 | User can view a per-Asset compliance-coverage summary across its scan history. | Data-flow section explains why coverage ("was this category checked") must come from *which checks ran*, not from findings, and why "currently failing" must come from findings — with `Report.json_path` + `REPORTS_DIR` as the only persisted source (no findings table). Recommended default semantics documented under Pitfall 3. |
| COMP-04 | Compliance mapping data is maintained per check in a way that stays in sync as new checks are added, following the same coverage-regression-test convention already used for `CHECK_LABELS`/`CHECK_CATEGORY`. | Concrete regression-test design reusing the exact source-parsing technique already in `tests/test_entitlements.py`/`tests/test_scan_events.py` (read this session) — see "Validation Architecture" and Code Examples. |

</phase_requirements>

## Summary

This phase adds a compliance-framework taxonomy layer on top of an already-complete,
already-working findings pipeline — it does not change what any check *detects*, only how each
finding is *labeled* for audit/reporting purposes. The codebase already has two precedent dicts
(`CHECK_LABELS`, `CHECK_CATEGORY` in `glassbox/checks.py`, verified read this session) that
solve an almost-identical problem (per-check metadata + a sync regression test), but neither
covers anything beyond `run_scan()`'s 17 base-scan check names — Phase 3 must extend that
convention to all 26 check units across all 4 scan orchestrators (base/advanced/media/api), which
is a materially bigger surface than the existing precedent.

The single most important architectural finding from this research: **`Finding` (the dataclass
every check returns instances of) carries a free-text `category` string but no `check_name`**, and
that field is never populated anywhere in the ~50 `Finding(...)` call sites across `checks.py`
(verified — every call site inspected this session). Without a `check_name` on each `Finding`,
there is no way to look up its OWASP/ASVS tag once findings from all checks have been flattened
into a single `all_findings` list (every one of the 4 orchestrators in `scan_engine.py` does this
flattening). The recommended fix is small and centralized: add an optional `check_name: str = ""`
field to `Finding`, and set it in exactly 4 orchestrator functions (once per check's return value,
not at each `Finding()` construction site) — see Architecture Patterns for the exact diff shape.
This keeps `CHECK_COMPLIANCE` keyed by check name (mirroring `CHECK_LABELS`/`CHECK_CATEGORY`
exactly, per D-03), and gives COMP-01/02 (per-finding tagging) and COMP-03 (per-Asset coverage,
which needs "was this check run" independent of whether it found anything) a single shared source
of truth, satisfying COMP-04's sync-test requirement with one dict instead of two competing
designs.

Persistence is the other load-bearing fact for COMP-03: `Report` (verified in `models.py`, read
this session) stores only a `json_path` pointing at a timestamped JSON file under `reports/` — no
findings table, no per-category rollup anywhere in the DB. `scan_routes.scan_report()` already
demonstrates the read pattern (`json.load(open(os.path.join(REPORTS_DIR, s.report.json_path)))`,
verified read this session), and `scan_routes.diff_reports()` already demonstrates indexing
findings by `(f["category"], f["title"])` from that loaded JSON. COMP-03's per-Asset summary
should reuse exactly this pattern: iterate `Scan.query.filter_by(asset_id=...)`, load each
completed scan's report JSON off disk, and aggregate through `CHECK_COMPLIANCE`. Because the
mapping is applied at read time (not baked into the stored JSON), every already-completed scan
report written before this phase ships gets compliance tags for free, with no backfill/migration
step needed.

**Primary recommendation:** Add `check_name: str = ""` to `Finding`; populate it centrally in each
of the 4 `scan_engine.py` orchestrators (not at each of the ~50 `Finding()` call sites); add a
`CHECK_COMPLIANCE` dict in `checks.py` keyed by the same 26 check-name strings `CHECK_LABELS`-style
precedent already establishes for base scans, extended to advanced/media/api; write a regression
test that reuses the exact regex-based source-parsing + set-union technique already proven in
`tests/test_entitlements.py`'s `_run_scan_job_names()`/`ADVANCED_SCAN_CHECK_NAMES`/
`OUT_OF_JOBS_DICT_NAMES` (verified read this session) rather than inventing a new extraction
mechanism.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Compliance category assignment (per finding) | API / Backend (`checks.py`, `scan_engine.py`) | — | Findings are produced server-side; the tag must be attached where the `Finding` is created/collected, before the report JSON is ever serialized or rendered. |
| Compliance-grouped/filterable report view | Frontend Server (SSR, Jinja templates) | API / Backend (data already in the loaded report dict) | `scan_report.html` already groups server-rendered findings by `category` via a Jinja loop (no JS framework in this app) — the compliance view is the same SSR pattern with a different grouping key, not a new client-side data layer. |
| Per-Asset compliance-coverage summary | API / Backend (`asset_routes.py`, reading `Report.json_path` files + `Scan` rows) | Frontend Server (`asset_detail.html` rendering) | Requires aggregating across every historical `Scan`/`Report` for an `Asset` — a DB+filesystem read-and-aggregate step, same shape as the existing "risk score over time" sparkline already on `asset_detail.html`. |
| Coverage-regression test (COMP-04) | Test suite (`tests/`) | — | Mirrors `tests/test_entitlements.py`'s existing `FEATURE_REQUIREMENTS` coverage tests — a static, source-parsing check, not a runtime/DB concern. |

## Standard Stack

No new third-party libraries are needed for this phase — it is a data-modeling + template-rendering
change inside the existing Flask/Jinja/SQLAlchemy stack already used throughout
`glassbox/`. See "Package Legitimacy Audit" below.

### Core (existing, reused — no new install)
| Library | Version | Purpose | Why Standard (for this phase) |
|---------|---------|---------|-------------------------------|
| Flask / Jinja2 | (pinned in `requirements.txt`, unchanged) | Server-rendered `scan_report.html`/`asset_detail.html` | Every other report view already renders this way; no reason to introduce a client framework for a grouping/filter UI. |
| SQLAlchemy (Flask-SQLAlchemy) | (pinned in `requirements.txt`, unchanged) | `Scan`/`Report`/`Asset` queries for COMP-03's history walk | Same ORM already used by `asset_routes._render_asset_detail()`. |
| pytest | unpinned in `requirements-dev.txt` (`pytest` with no version pin — verified read this session) | COMP-04's regression test | Existing test suite convention; `pytest` was not found installed in this session's active Python (see Environment Availability) — the project's documented `.venv` + `pip install -r requirements-dev.txt` flow is the source of truth, not the ambient interpreter probed here. |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Per-request Python-side aggregation of compliance data (proposed) | A dedicated `Finding`/`ComplianceTag` DB table, normalized | Bigger schema change (new Alembic migration, backfill of historical `reports/*.json` into rows) for a v1 feature whose only consumers are two report views — disproportionate to phase scope. `models.py`'s `Report` deliberately stores only a file pointer (verified read this session) — introducing a normalized findings table would be a genuine architecture change, not a phase-3-sized task. Flag as a possible v2 follow-up if per-category cross-asset querying/filtering at the DB level becomes a real need. |
| A hand-rolled OWASP category enum as a Python `Enum` | Plain string constants (`"A01:2021"` etc.) matching `CHECK_LABELS`'/`CHECK_CATEGORY`'s existing plain-dict convention | This codebase's own precedent (`Tier(IntEnum)` in `entitlements.py`) shows it *does* use enums elsewhere, but `CHECK_LABELS`/`CHECK_CATEGORY` (the explicitly-cited precedent for this phase) are plain string-value dicts. Matching that exact precedent, not `Tier`, keeps COMP-04's dict-of-strings coverage test identical in shape to the existing ones. |

**Installation:** None — no new packages.

## Package Legitimacy Audit

Not applicable — this phase installs no external packages. All work is inside the existing
`glassbox/` package (new dict + one new dataclass field) and `templates/` (new Jinja
markup). No `npm install`/`pip install` step is part of this phase's scope.

## Architecture Patterns

### System Architecture Diagram

```
Check function (checks.py)                 Orchestrator (scan_engine.py)
──────────────────────────                 ─────────────────────────────
check_headers(resp)                         run_scan(...)
  → (header_data, [Finding(...), ...])        header_data, f1 = check_headers(...)
                                               for f in f1: f.check_name = "headers"   ◄── NEW centralized tag
check_xss_sqli(urls, session)                 ...
  → (data, [Finding(...), ...])               for name, fn in jobs.items():
                                                   data, findings = fut.result()
                                                   for f in findings:
                                                       f.check_name = name              ◄── NEW centralized tag
                                                   all_findings.extend(findings)
                                               ...
                                               return {"findings": [asdict(f) for f in ...], ...}
                                                          │
                                                          ▼
                                          save_report(report, prefix, hostname)  →  reports/*.json
                                          Report.json_path (DB) points at that file
                                                          │
              ┌───────────────────────────────────────────┴───────────────────────────────┐
              ▼                                                                            ▼
  scan_routes.scan_report(scan_id)                                       asset_routes.asset_detail(asset_id)
    json.load(open(REPORTS_DIR/report.json_path))                          Scan.query.filter_by(asset_id=...)
    → render scan_report.html                                              for each completed scan:
        group findings by CHECK_COMPLIANCE[f["check_name"]]["owasp"]           json.load(...report.json_path)
        (existing category-grouping loop, new grouping key)                    tally CHECK_COMPLIANCE per check_name
                                                                             → render asset_detail.html
                                                                                 coverage summary section
```

### Recommended Project Structure

No new files/folders — additions land in existing modules:

```
glassbox/
├── checks.py          # + check_name field on Finding; + CHECK_COMPLIANCE dict (next to CHECK_LABELS/CHECK_CATEGORY)
├── scan_engine.py      # + f.check_name = <name> at each of the 4 orchestrators' finding-collection points
├── asset_routes.py     # + coverage-summary aggregation helper for asset_detail()
templates/
├── scan_report.html    # + compliance grouping/filter view (COMP-02)
├── asset_detail.html   # + per-Asset compliance-coverage summary section (COMP-03)
tests/
├── test_entitlements.py or a new test_compliance.py  # + CHECK_COMPLIANCE coverage regression test (COMP-04)
```

### Pattern 1: Centralized `check_name` tagging (not per-`Finding()`-call-site)

**What:** Add `check_name: str = ""` as a new field on the existing `Finding` dataclass, defaulted
so all ~50 existing `Finding(...)` call sites across `checks.py` remain valid without edits. Set
the field centrally, once per check, at the point each orchestrator already collects that check's
`(data, findings)` return value.

**When to use:** Any time you need to associate metadata with "which check produced this finding"
without touching every individual finding-construction call site.

**Example (verified from `glassbox/scan_engine.py`, read this session — showing the base-scan
jobs-loop collection point, lines 356-375):**
```python
# Source: glassbox/scan_engine.py (this codebase, read this session)
with ThreadPoolExecutor(max_workers=max(len(jobs), 1)) as pool:
    future_map = {}
    for name, fn in jobs.items():
        if progress_cb:
            progress_cb(name, "started", done, total)
        future_map[pool.submit(fn)] = name
    for fut in as_completed(future_map):
        name = future_map[fut]
        try:
            data, findings = fut.result()
            phase, detail = "completed", _extract_detail(name, data)
        except Exception as e:
            data, findings = {"error": str(e)}, []
            phase, detail = "failed", str(e)[:255]
        for f in findings:            # NEW — one line, added once per orchestrator collection point
            f.check_name = name       # NEW
        results[name] = data
        all_findings.extend(findings)
        ...
```
The same one-line addition applies at `run_scan()`'s `f1`/`f2`/`f_ports` collection points, and at
each `data, findings = check_x(...)` call in `run_advanced_scan()`, `run_media_scan()`, and
`run_api_scan()` (verified read this session — 4 orchestrators total, ~9 collection points).

### Pattern 2: `CHECK_COMPLIANCE` dict — same shape as `CHECK_LABELS`/`CHECK_CATEGORY`, wider key set

**What:** A flat `dict[str, dict]` in `checks.py`, next to `CHECK_LABELS`/`CHECK_CATEGORY`
(verified at `checks.py:61` and `checks.py:79` this session), keyed by check name, valued with the
OWASP Top 10 category (required) and an optional ASVS reference (nullable).

**When to use:** This phase's COMP-01/COMP-04 requirement.

```python
# Proposed addition to glassbox/checks.py, mirroring CHECK_LABELS'/CHECK_CATEGORY's
# existing shape and "keep this dict in sync" comment convention (verified checks.py:47-87).
CHECK_COMPLIANCE = {
    # base scan
    "headers":           {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V14.4"},
    "cookies":            {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V3.4"},
    "tls":                {"owasp": "A02:2021-Cryptographic Failures",    "asvs": "V9.1"},
    "https_redirect":     {"owasp": "A02:2021-Cryptographic Failures",    "asvs": "V9.1"},
    "sensitive_paths":    {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "robots_sitemap":     {"owasp": "Uncategorized",                      "asvs": None},
    "open_ports":         {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "cors":               {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "http_methods":       {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "open_redirect":      {"owasp": "A01:2021-Broken Access Control",     "asvs": None},
    "directory_listing":  {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "mixed_content":      {"owasp": "A02:2021-Cryptographic Failures",    "asvs": None},
    "dns_email":          {"owasp": "A05:2021-Security Misconfiguration", "asvs": None},
    "vulnerable_js":      {"owasp": "A06:2021-Vulnerable and Outdated Components", "asvs": None},
    "xss_sqli":           {"owasp": "A03:2021-Injection",                 "asvs": "V5.3"},
    "secrets":            {"owasp": "A02:2021-Cryptographic Failures",    "asvs": "V6"},
    "sri":                {"owasp": "A08:2021-Software and Data Integrity Failures", "asvs": "V14.2"},
    # advanced scan
    "sqli_login":         {"owasp": "A03:2021-Injection",                 "asvs": "V5.3"},
    "bruteforce":         {"owasp": "A07:2021-Identification and Authentication Failures", "asvs": "V2.2"},
    "sqli_union":         {"owasp": "A03:2021-Injection",                 "asvs": "V5.3"},
    "xss_stored":         {"owasp": "A03:2021-Injection",                 "asvs": "V5.3"},
    "idor":               {"owasp": "A01:2021-Broken Access Control",     "asvs": "V4.2"},
    # media scan
    "media":              {"owasp": "A01:2021-Broken Access Control",     "asvs": "V8.3"},
    # api scan (matches run_api_scan's own results dict keys - verified scan_engine.py:110/114/118)
    "schema":             {"owasp": "A05:2021-Security Misconfiguration", "asvs": "V13"},
    "wordlist":           {"owasp": "A01:2021-Broken Access Control",     "asvs": "V13"},
    "js_discovery":       {"owasp": "A01:2021-Broken Access Control",     "asvs": "V13"},
}
```
**All 26 `owasp`/`asvs` value assignments above are `[ASSUMED]`** — they are this researcher's
judgment calls, cross-referenced against each check's actual `Finding.category`/behavior (verified
read this session, see table in "Don't Hand-Roll" below for the source line numbers), not sourced
from an authoritative document that maps *this specific tool's checks* to OWASP/ASVS (no such
document exists — that mapping is inherently this phase's own design work). Treat this table as a
strong first draft, not a locked deliverable; flag the more debatable ones (`cookies`, `dns_email`,
`open_redirect`, `media`, `secrets`) for a quick human sanity check before shipping, since this is
a compliance-facing feature. See "Assumptions Log" below.

### Pattern 3: Report-time compliance grouping (COMP-02) — parallels an existing loop, does not replace it

**What:** `scan_report.html` already groups `r.findings` by `f.category` using a single Jinja
`{% for f in r.findings|sort(attribute='category') %}` loop with a namespace-tracked "did the
category change" break (verified `templates/scan_report.html:110-132`, read this session — full
loop reproduced in Code Examples below). The compliance view is the same loop shape, with
`CHECK_COMPLIANCE[f["check_name"]]["owasp"]` (or `"Uncategorized"` fallback) as the sort/group key
instead of `f.category`.

**When to use:** COMP-02's "grouped/filterable by framework category" requirement.

**Anti-Patterns to Avoid**
- **Re-deriving the compliance tag from `f["category"]` (the free-text string) instead of
  `f["check_name"]`:** several checks share a `category` string but would need different OWASP
  tags (e.g. `check_sqli_login`'s "Auth" findings mix an auth-bypass finding — arguably
  A07:2021 — with a same-function SQLi-timing finding correctly tagged A03:2021 via `xss_sqli`'s
  sibling checks). Keying off `check_name` (added via Pattern 1) avoids this ambiguity entirely.
  Keying off `category` was considered and rejected for this reason — see "Don't Hand-Roll" table.
- **Baking the OWASP tag into the stored JSON at scan-time (`save_report()`):** this would mean
  every scan run before a future mapping-table fix ships stays permanently mis-tagged, and would
  require a backfill migration for `reports/*.json`. Applying `CHECK_COMPLIANCE` at *read* time
  (report-viewing time, both COMP-02 and COMP-03) means a mapping-table correction takes effect
  immediately for all historical scans, with zero backfill.
- **Introducing a new severity-colored `.pill` variant for the compliance tag:** `base.html`'s
  `.pill`/`.badge` variants (`.critical`/`.high`/`.medium`/`.low`/`.info`/`.pass`, verified
  `templates/base.html:60-66` this session) are all severity-semantic colors. Reusing one of them
  for an OWASP-category pill would visually imply a severity that isn't there. Add a neutral
  variant (e.g. `.pill.compliance` with `var(--muted)`/`var(--telemetry)` styling) instead of
  overloading an existing severity color.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Associating a `Finding` with the check that produced it | A new lookup keyed by the free-text `Finding.category` string | `Finding.check_name` (new field), set centrally in the 4 orchestrators | `category` strings are shared across checks with legitimately different OWASP categories in at least one case (`check_sqli_login` emits both `"Auth"`-category and `"SQL Injection"`-category findings — verified `checks.py:1287,1302,1318`, read this session) — a category-string-keyed map cannot express "same category text, different check, different OWASP tag" without ambiguity. `check_name` can. |
| Per-Asset historical findings storage for COMP-03 | A new normalized findings/compliance DB table + Alembic migration | Read-and-aggregate over existing `Scan`/`Report.json_path` files, same pattern `scan_routes.diff_reports()` already uses (verified `scan_routes.py:572-589`, read this session) | `Report` (verified `models.py:288-297`) intentionally stores just a file pointer — this is the established, working precedent for every other report-reading code path in the app; a new table is a bigger, riskier change than this phase's scope calls for. |
| Extracting "every check name a scan type can dispatch" for COMP-04's regression test | A hand-maintained list that silently drifts from `scan_engine.py` | The exact regex-based source-parsing technique already proven in `tests/test_entitlements.py`'s `_run_scan_job_names()` (verified `tests/test_entitlements.py:49-58`, read this session) plus its `ADVANCED_SCAN_CHECK_NAMES`/`OUT_OF_JOBS_DICT_NAMES` constants (verified `tests/test_entitlements.py:61-64`) | Those constants already exist, are already imported by one test module, and are the exact "source of truth for check names" this phase needs — reusing them (or importing them into a new compliance test module) means COMP-04's test breaks the same way `FEATURE_REQUIREMENTS`'s coverage test already breaks when `scan_engine.py`'s jobs dict changes, with zero duplicated logic. |

**Key insight:** Every piece of new state this phase needs (which check produced a finding; which
checks ran in a given scan; the OWASP/ASVS tag for a check) can be derived from data structures
that already exist in this codebase (`Finding`, the 4 orchestrators' `results`/`all_findings`
collection points, `Report.json_path`) plus one new field and one new dict. Resist the urge to add
a database table, a migration, or a second parallel finding-classification pipeline — the existing
report-JSON-on-disk architecture this app already committed to (see `save_report()`'s docstring,
verified `scan_engine.py:450-465`) is sufficient for a read-time compliance overlay.

## Common Pitfalls

### Pitfall 1: Treating `CHECK_LABELS`/`CHECK_CATEGORY`'s key set as the full check-name space

**What goes wrong:** A planner/executor greps `CHECK_LABELS` for "the list of all checks" and only
maps the 17 base-scan check names, missing the 5 advanced-scan checks, the 1 media check, and the
3 API sub-checks — directly violating D-03.
**Why it happens:** `CHECK_LABELS`'s own docstring says "Human-readable labels for `run_scan()`'s
base-scan check units" (verified `checks.py:47-60`, read this session) — it was never meant to
cover advanced/media/api, so grepping it as "the" precedent under-covers by 9 entries (17→26).
**How to avoid:** Use the full 26-key list enumerated in Pattern 2 above (cross-checked against
every `def check_*(...)` in `checks.py` and every orchestrator in `scan_engine.py`, both read in
full this session) as the authoritative starting key set, not `CHECK_LABELS`'s key set.
**Warning signs:** COMP-04's regression test only imports/checks against `run_scan()`'s jobs dict
and misses `ADVANCED_SCAN_CHECK_NAMES`-equivalent coverage for advanced/media/api.

### Pitfall 2: `FEATURE_REQUIREMENTS`'s `"media"`/`"api"` single-bucket granularity does not carry over

**What goes wrong:** Copying `FEATURE_REQUIREMENTS`'s tier-gating granularity (`"media"` and
`"api"` are each a *single* key gating the whole scan type, verified `entitlements.py:46-54`,
read this session) into `CHECK_COMPLIANCE` produces one compliance tag for `check_media` (fine,
it's genuinely one check) but collapses `check_api_schema_exposure`/`check_api_wordlist`/
`check_api_js_discovery` (3 distinct check functions, verified `checks.py:729,789,845`) into a
single `"api"` OWASP tag — losing the real distinction between "API docs/schema exposed"
(best mapped to A05:2021 Security Misconfiguration — unnecessary debug feature left on) and
"unauthenticated data returned from a discovered endpoint" (best mapped to A01:2021 Broken Access
Control — missing authorization check).
**Why it happens:** `FEATURE_REQUIREMENTS` and `CHECK_COMPLIANCE` solve different problems (tier
gating happens at the route level before `run_api_scan()` is even called — verified
`scan_engine.py`'s module docstring — so it genuinely only needs one bucket; compliance tagging
happens per-finding, after all 3 checks already ran, so it needs finer granularity).
**How to avoid:** Key `CHECK_COMPLIANCE` for the API scan type on `run_api_scan()`'s own
`results` dict sub-keys (`"schema"`, `"wordlist"`, `"js_discovery"`, verified
`scan_engine.py:109-119`), not on the single `"api"` `FEATURE_REQUIREMENTS` key.
**Warning signs:** `CHECK_COMPLIANCE` has exactly 24 keys instead of 26, and API-scan findings in
`scan_report.html` all show one identical OWASP tag regardless of which of the 3 API checks found
them.

### Pitfall 3: "Currently failing" (COMP-03) cannot be derived from findings alone

**What goes wrong:** Computing the per-Asset coverage summary purely from `report["findings"]`
misses every category where a check ran and found *nothing* — there is no synthetic "pass" Finding
emitted anywhere in the codebase today (verified: grepped every `Finding(` call site across
`checks.py`, read this session — `severity="pass"` never appears as an actual argument, only as a
UI-only literal in `scan_report.html`'s `{% if r.findings|length == 0 %}` zero-findings pill,
verified `templates/scan_report.html:86`). A coverage summary built only from findings would
report "0 categories checked" for a perfectly clean scan, which is wrong — it should report "all
of this scan type's mapped categories were checked, none are currently failing."
**Why it happens:** Findings model *problems*, not *checks performed*. "Which categories were
checked" is a property of *which check names executed* (available from the report dict's
`results.get(name, {"locked": True})` keys / `locked_checks` list, verified `scan_engine.py:424-447`),
not of the findings list.
**How to avoid:** Compute "categories checked" from the set of check names that actually ran (i.e.
NOT in `locked_checks`, present in `results`) mapped through `CHECK_COMPLIANCE`; compute
"currently failing" from `CHECK_COMPLIANCE[f["check_name"]]` for every finding with
`severity != "pass"` (i.e. every real finding, since "pass" is never actually emitted) in whichever
scan(s) COMP-03's semantics choice covers (see below).
**Warning signs:** A completely clean Asset (all scans A-grade, zero findings) shows an empty/
zero-coverage compliance summary instead of "all checked categories: passing."

**Recommended default for the "most-recent-scan-only vs. any-scan-in-history" discretion point:**
Use *most-recent completed scan of each `scan_type`* for both "checked" and "failing." Rationale:
`asset_detail.html`'s existing risk-score sparkline and "Latest scan" card (verified
`templates/asset_detail.html:84-113`, read this session) already establish "the latest scan is the
asset's current state" as this page's convention — an any-scan-in-history "failing" flag would
show a category as perpetually failing even after a real fix landed and a subsequent scan came back
clean, which contradicts the page's existing trend-line framing. Document this choice explicitly in
the plan per CONTEXT.md's instruction, since it's user-visible and was left to planner discretion.

## Code Examples

### Existing category-grouping loop this phase should parallel (COMP-02)
```jinja
{# Source: templates/scan_report.html, lines 110-132 (this codebase, read this session) #}
<h2 class="section">Findings ({{ r.findings|length }})</h2>
{% set ns = namespace(current_cat=None, first=true) %}
{% for f in r.findings|sort(attribute='category') %}
  {% if f.category != ns.current_cat %}
    {% if not ns.first %}</div></details>{% endif %}
    {% set ns.current_cat = f.category %}
    {% set ns.first = false %}
    <details open>
      <summary>{{ f.category }} <span class="arrow">&#9656;</span></summary>
      <div class="details-body">
  {% endif %}
  <div class="finding {{ f.severity }}">
    <span class="badge {{ f.severity }}">{{ f.severity }}</span>
    <div class="body">
      <b>{{ f.title }}</b>
      <div class="detail">{{ f.detail }}</div>
      {% if f.recommendation %}<div class="rec"><b>Fix:</b> {{ f.recommendation }}</div>{% endif %}
    </div>
  </div>
  {% if loop.last %}</div></details>{% endif %}
{% else %}
  <p class="empty">No findings.</p>
{% endfor %}
```

### Existing report-read pattern this phase's COMP-03 aggregation should reuse
```python
# Source: glassbox/scan_routes.py, lines 556-569 (this codebase, read this session)
@scan.route("/scan/<int:scan_id>/report")
@login_required
def scan_report(scan_id):
    s = Scan.query.get_or_404(scan_id)
    _check_ownership(s)
    if s.report is None:
        abort(404)

    with open(os.path.join(REPORTS_DIR, s.report.json_path), encoding="utf-8") as f:
        report = json.load(f)

    return render_template(
        "scan_report.html", scan=s, r=report, locked=report.get("locked_checks", []),
    )
```

### Existing findings-indexing pattern this phase's grouping/lookup should reuse
```python
# Source: glassbox/scan_routes.py, lines 572-589 (this codebase, read this session)
def diff_reports(report_a, report_b):
    def index_by_key(report):
        idx = {}
        for f in report.get("findings", []):
            idx[(f["category"], f["title"])] = f
        return idx
    ...
```

### Existing coverage-regression-test technique this phase's COMP-04 test should reuse
```python
# Source: tests/test_entitlements.py, lines 49-79 (this codebase, read this session)
def _run_scan_job_names():
    src = Path(__file__).resolve().parent.parent / "glassbox" / "scan_engine.py"
    text = src.read_text(encoding="utf-8")
    start = text.index("jobs = {")
    end = text.index("\n    }", start)
    block = text[start:end]
    return set(re.findall(r'"(\w+)":\s*lambda', block))


ADVANCED_SCAN_CHECK_NAMES = {"sqli_login", "bruteforce", "sqli_union", "xss_stored", "idor"}
OUT_OF_JOBS_DICT_NAMES = {"headers", "cookies", "open_ports"}


def test_feature_requirements_covers_run_scan_jobs():
    used = _run_scan_job_names()
    assert used, "extraction found no job names - regex or scan_engine.py's jobs dict shape changed"
    missing = used - set(FEATURE_REQUIREMENTS)
    assert not missing, (...)


def test_feature_requirements_covers_advanced_and_out_of_band_checks():
    missing = (ADVANCED_SCAN_CHECK_NAMES | OUT_OF_JOBS_DICT_NAMES) - set(FEATURE_REQUIREMENTS)
    assert not missing
```
**Proposed COMP-04 test (new, extending the above rather than replacing it):**
```python
# Proposed — new test, reusing the imports/helpers above plus two new constants
MEDIA_SCAN_CHECK_NAMES = {"media"}
API_SCAN_CHECK_NAMES = {"schema", "wordlist", "js_discovery"}  # matches run_api_scan's results keys

def test_check_compliance_covers_every_scan_type():
    from glassbox.checks import CHECK_COMPLIANCE
    all_names = (_run_scan_job_names() | OUT_OF_JOBS_DICT_NAMES
                 | ADVANCED_SCAN_CHECK_NAMES | MEDIA_SCAN_CHECK_NAMES | API_SCAN_CHECK_NAMES)
    missing = all_names - set(CHECK_COMPLIANCE)
    assert not missing, f"CHECK_COMPLIANCE is missing entries for {missing}"

def test_check_compliance_every_entry_has_owasp_category():
    from glassbox.checks import CHECK_COMPLIANCE
    for name, entry in CHECK_COMPLIANCE.items():
        assert entry.get("owasp"), f"{name} has no owasp category (D-01: required on every mapped check)"
```
This mirrors the existing tests' shape exactly (source-parsed job names ∪ hand-maintained constants
for check groups without a `jobs = {}` block), satisfying COMP-04's "same coverage-regression-test
convention" instruction precisely, and reusing `ADVANCED_SCAN_CHECK_NAMES`/`OUT_OF_JOBS_DICT_NAMES`
(importable from `tests/test_entitlements.py` or promoted to a shared test fixture module) instead
of re-deriving them.

## State of the Art

Not applicable in the "library version drift" sense — this is a first-time addition of a
compliance layer to an existing internal check pipeline, not an upgrade of an existing dependency.
The one relevant external fact is that **OWASP Top 10 2021 is the current published edition**
(cross-checked via WebSearch against owasp.org/Top10/2021/ this session; an OWASP Top 10 2025 blog
discussion appeared in search results but that draft/edition is not the one users of this tool will
expect an "OWASP Top 10" label to mean in an audit context as of this research date — using 2021 is
the safe, current, widely-adopted choice). Confirm before shipping if any newer OWASP Top 10
edition has been formally finalized and widely adopted by auditors by the time this phase executes.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | All 26 individual check→OWASP-category assignments in the `CHECK_COMPLIANCE` proposed table | Architecture Patterns / Pattern 2 | A wrong category on a compliance-facing feature could mislead an auditor or a user's compliance report; low technical risk (easy to edit a dict value), but real reputational/product-trust risk since D-02 explicitly frames this as an audit-grade feature for some users. Recommend a quick human read-through of the table before/during planning, prioritizing `cookies`, `dns_email`, `open_redirect`, `media`, and `secrets` (the least clear-cut assignments, called out inline above). |
| A2 | All 26 individual ASVS control/chapter references (`"V14.4"`, `"V3.4"`, etc.) | Architecture Patterns / Pattern 2 | Same as A1 but lower stakes per D-01 ("ASVS is optional... added only where it adds real audit value") — if a chapter number is wrong or too granular, the fix is a one-line dict-value edit, not a structural change. Chapter-level (not sub-control-level) references were chosen deliberately to reduce this risk. |
| A3 | "Most-recent-scan-only" is the right default for COMP-03's "currently failing" semantics | Common Pitfalls / Pitfall 3 | If the user actually wanted "any-scan-in-history ever failing," the UI would need to change from a snapshot view to a historical-any-match view — a real (if small) design change, not just a copy edit. Flagged explicitly per CONTEXT.md's instruction to document this choice. |
| A4 | `check_media`'s findings best map to A01:2021 Broken Access Control (rather than A05:2021 Security Misconfiguration, the other defensible option) | Architecture Patterns / Pattern 2 | Both are commonly used in the wild for "unintentionally public files" — genuinely ambiguous; wrong choice is a one-line fix, not structural. |

**None of the above block planning** — they are dict-value-level judgment calls in a proportionate,
low-blast-radius design (a plain dict + one dataclass field), not architectural risks. They are
flagged so the planner/executor treats the specific category/ASVS *values* as a first draft to spot-
check, not as verified fact, consistent with this being a compliance-facing feature.

## Open Questions

1. **Exact wording of `.pill.compliance` (or equivalent) CSS for the new neutral compliance-tag
   badge**
   - What we know: `base.html`'s existing `.pill`/`.badge` variants are all severity-colored
     (verified `templates/base.html:60-66`, read this session); a compliance tag is orthogonal to
     severity and needs a new, non-severity-colored variant.
   - What's unclear: exact color token to reuse (`--muted` for a flat neutral look, vs. `--telemetry`
     for something more "informational-blue," both already defined per `base.html`'s "Evolved
     operator console" motion-language section referenced in `CLAUDE.md`).
   - Recommendation: left to the UI-SPEC step (this phase has `UI hint: yes`) — flag `--muted`
     as the safer default (lowest risk of looking like a false severity signal).

2. **Whether the coverage-regression test (COMP-04) should live in a new `tests/test_compliance.py`
   or be appended to `tests/test_entitlements.py`**
   - What we know: `tests/test_entitlements.py` already owns the `_run_scan_job_names()` helper and
     the `ADVANCED_SCAN_CHECK_NAMES`/`OUT_OF_JOBS_DICT_NAMES` constants this phase's test needs to
     reuse.
   - What's unclear: whether importing those from `test_entitlements.py` into a new test module (vs.
     appending directly) is cleaner given `CHECK_COMPLIANCE` conceptually belongs to `checks.py`, not
     `entitlements.py`.
   - Recommendation: planner's call; either is fine functionally — note that `CHECK_LABELS`'s own
     coverage test lives in `tests/test_scan_events.py` (a third file, alongside `checks.py`'s
     `CHECK_LABELS`/`CHECK_CATEGORY` precedent, verified this session), so this codebase already
     tolerates "the coverage test doesn't live in the same file as the thing it's testing" — a new
     `tests/test_compliance.py` importing the shared constants is consistent with that precedent.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python | Running the app / tests | ✓ | 3.14.0 (ambient `python`, this session) | Project's documented `.venv` (see `CLAUDE.md` Commands) is the source of truth for the actual dev/CI interpreter, not necessarily 3.14 — confirm against `.venv` before assuming this exact version. |
| Flask | Existing app dependency, unaffected by this phase | ✓ | 3.1.3 (ambient `pip show`, this session) | — |
| pytest | COMP-04's regression test | ✗ (not found in ambient `pip show` this session) | — | `pip install -r requirements-dev.txt` inside the project's `.venv`, per `CLAUDE.md`'s documented Tests section — this is expected to already be the case in the real dev/CI environment; the ambient ✗ here reflects this research session's interpreter, not the project's `.venv`. |

**Missing dependencies with no fallback:** none.

**Missing dependencies with fallback:** pytest (fallback: use the project's documented `.venv` +
`requirements-dev.txt` install, per `CLAUDE.md`).

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest (unpinned version in `requirements-dev.txt`, verified read this session) |
| Config file | `pytest.ini` (`testpaths = tests`, verified read this session) |
| Quick run command | `.venv\Scripts\python -m pytest tests/test_entitlements.py tests/test_scan_events.py -x` (or the new compliance test module once created) |
| Full suite command | `.venv\Scripts\python -m pytest` (also runs via `.github/workflows/tests.yml` on every push/PR per `CLAUDE.md`) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| COMP-01 | `CHECK_COMPLIANCE` has an entry (with a non-empty `owasp` value) for every check name across all 4 scan types | unit | `pytest tests/test_compliance.py::test_check_compliance_every_entry_has_owasp_category -x` | ❌ Wave 0 |
| COMP-02 | `scan_report.html` renders a compliance-grouped/filterable view distinct from the severity list | manual-only (SSR template output — this app has no existing frontend/template-rendering test convention beyond route-level "does it 200 / render without exception" checks, e.g. `tests/test_org_routes.py`'s "single rendering test" noted in `REQUIREMENTS.md`'s HARD-03) | N/A — verify via `/gsd-verify-work` conversational UAT | — |
| COMP-03 | Per-Asset compliance-coverage summary shows checked/failing categories consistent with that Asset's actual scan history | integration | `pytest tests/test_asset_routes.py::test_asset_detail_shows_compliance_coverage -x` (new test, following `test_asset_routes.py`'s existing `make_scan`/`make_org` fixture conventions from `tests/conftest.py`) | ❌ Wave 0 |
| COMP-04 | `CHECK_COMPLIANCE`'s key set stays in sync with every check name dispatchable across `run_scan`/`run_advanced_scan`/`run_media_scan`/`run_api_scan` | unit (regression) | `pytest tests/test_compliance.py::test_check_compliance_covers_every_scan_type -x` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `.venv\Scripts\python -m pytest tests/test_compliance.py -x` (or whichever
  module ends up owning the new tests)
- **Per wave merge:** `.venv\Scripts\python -m pytest`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `tests/test_compliance.py` (or equivalent) — covers COMP-01, COMP-04 (the two purely
      data/dict-shape requirements, verifiable without a live scan)
- [ ] A new test in `tests/test_asset_routes.py` — covers COMP-03, following that file's existing
      `make_scan`/`make_org`/`make_user` fixtures (verified present in `tests/conftest.py` per
      other test files' imports)
- [ ] No new pytest plugin/framework install needed — existing `pytest` + existing `tests/conftest.py`
      app-factory fixture (per-test on-disk SQLite, verified via `CLAUDE.md`'s Tests section) covers
      everything this phase needs.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V1 Architecture, Design and Threat Modeling | Marginal | This phase adds a read-only labeling layer over existing, already-authorized scan data — no new attack surface or trust boundary is introduced. |
| V5 Input Validation | No | No new user input is accepted by this phase (the compliance view is a read-only rendering of already-collected findings). |
| V13 API and Web Service | No — this phase does not touch `API-0x` routes (Phase 2's scope); it only affects report-rendering routes already covered by Phase 2's token-auth/ownership checks. | — |

### Known Threat Patterns for this phase's stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| Compliance-summary route leaking one org's/user's finding data to another (an IDOR on the new aggregation endpoint) | Information Disclosure | Reuse the exact ownership-check pattern already enforced for every scan/asset route — `scan_routes._check_ownership(s)` (verified referenced at `scan_routes.py:560`) and `asset_routes._check_asset_access(a)` (verified referenced at `asset_routes.py:148`) — COMP-03's per-Asset summary must call `_check_asset_access` before reading any `Scan`/`Report` for that Asset, exactly as `asset_detail()` already does. No new auth mechanism should be invented for this phase. |
| Rendering raw finding `detail`/`title` text (which can contain content drawn from the *scanned site's own HTTP responses*, per `CLAUDE.md`'s AI-summary section) inside a new compliance-grouped view without the same escaping Jinja already applies elsewhere | Tampering (stored/reflected XSS in the report page itself) | Jinja2 auto-escapes by default and every existing finding-rendering block already relies on this (no `|safe` filter appears in the reviewed `scan_report.html` excerpt) — the new compliance view must render `f.title`/`f.detail` the same un-`|safe` way, not introduce a new raw-HTML rendering path for the sake of "highlighting" the compliance tag. |

This phase does not touch `authorized`/`authorized_adv`/`authorized_media`/`authorized_api`
checkbox gating, `entitlements.py`'s tier gating, or `checks.is_ssrf_safe_hostname()` — per
`CLAUDE.md`'s hardening constraints, none of that should be weakened or need to change for this
phase's scope (pure findings-labeling + report-rendering).

## Sources

### Primary (HIGH confidence — read directly this session)
- `glassbox/checks.py` (full file, 1523 lines) — `Finding` dataclass, `CHECK_LABELS`,
  `CHECK_CATEGORY`, every `def check_*(...)` and every `Finding(...)` call site's `category`
  argument.
- `glassbox/scan_engine.py` (full file, 466 lines) — all 4 orchestrators
  (`run_scan`/`run_advanced_scan`/`run_media_scan`/`run_api_scan`), `save_report()`.
- `glassbox/entitlements.py` (full file, 136 lines) — `FEATURE_REQUIREMENTS`, `Tier`.
- `glassbox/models.py` (excerpt: `Asset`/`Scan`/`Report`/`Subscription`/`CryptoInvoice`
  class definitions) — confirms `Report` stores only `json_path`, no findings table.
- `glassbox/scan_routes.py` (excerpts: `scan_report()`, `diff_reports()`) — the report-read
  and findings-indexing patterns this phase should reuse.
- `glassbox/asset_routes.py` (excerpts: `_render_asset_detail()`, `asset_detail()`,
  `update_schedule()`) — the existing Asset-scan-history query pattern.
- `templates/scan_report.html` (excerpts, lines 1-174) — the existing category-grouping loop and
  finding-card markup.
- `templates/asset_detail.html` (full file, 243 lines) — the existing scan-history/sparkline
  section conventions.
- `templates/base.html` (excerpt, `.pill`/`.badge`/`.status-pill`/`.finding` CSS block) — existing
  badge/pill component conventions.
- `tests/test_entitlements.py` (excerpt, lines 1-100) — `_run_scan_job_names()`,
  `ADVANCED_SCAN_CHECK_NAMES`, `OUT_OF_JOBS_DICT_NAMES`, the coverage-regression-test pattern.
- `tests/test_scan_events.py` (excerpts) — `CHECK_LABELS`/`CHECK_CATEGORY` coverage tests.
- `.planning/phases/03-compliance-framework-reporting/03-CONTEXT.md`,
  `.planning/REQUIREMENTS.md`, `.planning/STATE.md` — phase scope and locked decisions.
- `CLAUDE.md` (project root) — project conventions and hardening constraints.

### Secondary (MEDIUM confidence — WebSearch, cross-checked against official OWASP sources)
- [OWASP Top 10:2021](https://owasp.org/Top10/2021/) (via WebSearch summary matching this canonical
  URL) — confirmed the current, official 10-category list (A01–A10) used throughout this
  document's mapping table.
- [github.com/OWASP/ASVS](https://github.com/OWASP/ASVS) (via WebSearch, multiple hits referencing
  the official ASVS 4.0.3 repo/PDF) — confirmed the existence and general subject matter of ASVS
  chapters V1–V14 (Architecture, Authentication, Session Management, Access Control, Validation,
  Stored Cryptography, Error Handling, Data Protection, Communication, Malicious Code, Business
  Logic, Files and Resources, API and Web Service, Configuration) and specifically V3.4
  (Cookie-based Session Management), V9.1 (Client Communications Security), V5.3 (Output Encoding
  and Injection Prevention), V14.4 (HTTP Security Headers Requirements).

### Tertiary (LOW confidence — this researcher's judgment, not independently sourced)
- All 26 individual check→OWASP-category and check→ASVS-reference assignments in the
  `CHECK_COMPLIANCE` proposed table (Pattern 2) — see "Assumptions Log" A1/A2/A4.
- Whether A10:2017 (Unvalidated Redirects and Forwards, informing this document's `open_redirect`
  → A01:2021 mapping) was formally merged into A01:2021 vs. simply retired without an official
  1:1 successor — WebSearch did not turn up an explicit OWASP statement confirming the merge;
  A01:2021 was used as the best-fit community-convention mapping, not a confirmed OWASP statement.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new dependencies, pure reuse of existing Flask/Jinja/pytest/SQLAlchemy
  already pinned in this project.
- Architecture (Finding.check_name + CHECK_COMPLIANCE design): HIGH — derived directly from reading
  every relevant call site in `checks.py`/`scan_engine.py`/`scan_routes.py`/`asset_routes.py`/
  `models.py` this session, not from external inference.
- Compliance-category mapping values (the 26-row table): LOW/MEDIUM — OWASP Top 10 2021 category
  *names* are HIGH confidence (cross-checked); which category each specific check belongs to is
  this researcher's judgment call, explicitly flagged for human review.
- Pitfalls: HIGH — each pitfall traces to a specific, read-this-session line reference.

**Research date:** 2026-08-11
**Valid until:** 30 days (stable internal codebase; OWASP Top 10 2021 itself is stable, but confirm
no newer official Top 10 edition has superseded it by execution time — see "State of the Art").
