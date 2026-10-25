# Phase 3: Compliance & Framework Reporting - Pattern Map

**Mapped:** 2026-08-11
**Files analyzed:** 6 (2 backend modified, 1 backend field addition, 2 templates modified, 1 new test file)
**Analogs found:** 6 / 6

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|--------------------|------|-----------|-----------------|---------------|
| `glassbox/checks.py` (+`CHECK_COMPLIANCE` dict, +`Finding.check_name` field) | model/config (per-check lookup table) | transform (read-time lookup) | `glassbox/checks.py`'s own `CHECK_LABELS`/`CHECK_CATEGORY` dicts (lines 61-87) + `Finding` dataclass (line 146) | exact |
| `glassbox/scan_engine.py` (tag `f.check_name = name` at ~9 collection points across 4 orchestrators) | service/orchestrator | transform (CRUD-adjacent: enrich in-memory objects before persist) | `run_scan()`'s existing `all_findings.extend(findings)` collection points (lines 288-289, 356-375, 377-394) and the 3 sibling orchestrators' `data, findings = check_x(...)` lines | exact |
| `glassbox/asset_routes.py` (+coverage-aggregation helper for `asset_detail()`) | route/controller (read-aggregate) | request-response (file I/O: reads JSON report files per scan) | `asset_routes._check_asset_access()` + `asset_detail()` (lines 38, 146-148) and `scan_routes.diff_reports()`'s `index_by_key` aggregation pattern | role-match (ownership guard = exact; aggregation loop = partial, ported from scan_routes.py) |
| `templates/scan_report.html` (+compliance grouping/filter toggle, +inline compliance pill per finding) | component/template | request-response (SSR) | Same file's existing severity-grouping loop (lines 110-132) | exact |
| `templates/asset_detail.html` (+"Compliance coverage" card section) | component/template | request-response (SSR) | Same file's existing "Risk score over time" sparkline card section (lines 115+) and "Latest scan" status-pill card (lines 84-113) | exact |
| `tests/test_compliance.py` (new) | test | batch (static source-parsing regression test) | `tests/test_entitlements.py`'s `_run_scan_job_names()`/`ADVANCED_SCAN_CHECK_NAMES`/`OUT_OF_JOBS_DICT_NAMES` (lines 49-79) and `tests/test_scan_events.py`'s `CHECK_LABELS`/`CHECK_CATEGORY` coverage tests (lines 60-86) | exact |

## Pattern Assignments

### `glassbox/checks.py` — `CHECK_COMPLIANCE` dict + `Finding.check_name` field

**Analog:** `glassbox/checks.py:47-87` (`CHECK_LABELS`/`CHECK_CATEGORY`) and `:145-151` (`Finding`)

**Dict-shape pattern to copy** (`checks.py:61-87`):
```python
CHECK_LABELS = {
    "headers": "Security headers", "cookies": "Cookies", "tls": "TLS certificate",
    "https_redirect": "HTTP → HTTPS redirect", "sensitive_paths": "Sensitive path / file probe",
    "secrets": "Exposed API keys / secrets", "sri": "Third-party scripts/stylesheets without SRI",
    "open_ports": "Open ports", "cors": "CORS configuration", "http_methods": "HTTP methods",
    "open_redirect": "Open redirect probe", "directory_listing": "Directory listing",
    "mixed_content": "Mixed content", "dns_email": "DNS email security (SPF / DMARC / CAA)",
    "vulnerable_js": "Outdated JS libraries", "xss_sqli": "Same-origin crawl & parameter/XSS/SQLi testing",
    "robots_sitemap": "robots.txt / sitemap.xml",
}

# Icon-sprite key ... keep this dict in sync with CHECK_LABELS (same key set) if a check is ever
# added or removed from run_scan()'s jobs dict.
CHECK_CATEGORY = {
    "headers": "shield", "cookies": "shield",
    "tls": "lock", "https_redirect": "lock", "mixed_content": "lock",
    ...
}
```
`CHECK_COMPLIANCE` should be added directly below `CHECK_CATEGORY` (after line 87), same
plain-`dict[str, dict]` convention (per RESEARCH.md's "Don't Hand-Roll" — this app's own precedent
uses plain dicts here, not `Enum`, even though `Tier(IntEnum)` exists elsewhere). Key set is wider
than `CHECK_LABELS`'s 17 (that dict is base-scan-only per its own docstring, line 47-60) — must
cover all 26 check names across all 4 orchestrators (base 17 + advanced 5 + media 1 + api 3), per
CONTEXT.md D-03. Use RESEARCH.md's Pattern 2 table verbatim as the starting values (flagged
`[ASSUMED]` — spot-check `cookies`/`dns_email`/`open_redirect`/`media`/`secrets` per RESEARCH.md's
Assumptions Log A1/A4 before treating as final). "Uncategorized" is a value inside `owasp`/rendered
fallback, not a `CHECK_COMPLIANCE` key — mirrors `CHECK_CATEGORY`'s `"shield"` fallback being a
*value* choice at render time, not a dict key (D-04).

**Sync-comment convention to copy** (`checks.py:72-78`, immediately above `CHECK_CATEGORY`):
```python
# ... keep this dict in sync with CHECK_LABELS (same key set) if a check is ever
# added or removed from run_scan()'s jobs dict.
```
Write an equivalent comment above `CHECK_COMPLIANCE` pointing at `tests/test_compliance.py`'s
coverage test (see below) instead of `tests/test_scan_events.py`.

**`Finding` dataclass — add optional field, no existing call sites need editing** (`checks.py:145-151`):
```python
@dataclass
class Finding:
    category: str
    title: str
    severity: str  # critical | high | medium | low | info | pass
    detail: str
    recommendation: str = ""
    check_name: str = ""   # NEW — set centrally in scan_engine.py orchestrators, not at each of
                            # the ~50 Finding(...) call sites in this file.
```

---

### `glassbox/scan_engine.py` — centralized `check_name` tagging

**Analog:** the file's own existing collection points; also mirrors how `CHECK_LABELS`-style
per-check metadata is consumed elsewhere (`_extract_detail(name, data)` at `scan_engine.py:366`).

**Base-scan jobs-loop tagging point** (`scan_engine.py:356-375`):
```python
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
        for f in findings:            # NEW
            f.check_name = name       # NEW
        results[name] = data
        all_findings.extend(findings)
        ...
```
Apply the same `for f in findings: f.check_name = name` one-liner at every other collection point:
- `run_scan()`'s synchronous `f1`/`f2` (headers/cookies, lines 288-289) and `f_ports`
  (`check_open_ports`, lines 377-394) — outside the jobs dict, tag with `"headers"`, `"cookies"`,
  `"open_ports"` respectively (same 3 names as `OUT_OF_JOBS_DICT_NAMES` in
  `tests/test_entitlements.py:64`).
- `run_advanced_scan()` (lines 176-220) — 5 `data, findings = check_x(...)` sites, tag with
  `"sqli_login"`, `"bruteforce"`, `"sqli_union"`, `"xss_stored"`, `"idor"`.
- `run_media_scan()` (line 68) — 1 site, tag `"media"`.
- `run_api_scan()` (lines 109-119) — 3 sites, tag `"schema"`, `"wordlist"`, `"js_discovery"`
  (matches `run_api_scan()`'s own `results` dict sub-keys, NOT the single `"api"`
  `FEATURE_REQUIREMENTS` bucket — see RESEARCH.md Pitfall 2).

---

### `glassbox/asset_routes.py` — coverage-summary aggregation helper

**Analog (ownership guard):** `asset_routes.py:38` `_check_asset_access(a)`, called at the top of
every asset route including `asset_detail()` (`:146-148`).

**Analog (report-read + findings-index pattern to reuse):** `glassbox/scan_routes.py:556-589`
```python
# scan_report() - the load pattern
with open(os.path.join(REPORTS_DIR, s.report.json_path), encoding="utf-8") as f:
    report = json.load(f)

# diff_reports() - the findings-indexing pattern
def diff_reports(report_a, report_b):
    def index_by_key(report):
        idx = {}
        for f in report.get("findings", []):
            idx[(f["category"], f["title"])] = f
        return idx
    ...
```
The new coverage helper should: call `_check_asset_access(a)` first (IDOR guard — see Shared
Patterns below), then `Scan.query.filter_by(asset_id=asset.id)`, group by `scan_type`, take the
most-recent *completed* scan per `scan_type` (per RESEARCH.md's Pitfall 3 recommended default —
document this choice explicitly in the plan/UI per UI-SPEC's note), load each one's report JSON the
same way `scan_report()` does, and derive:
- "checked" categories from `results`/`locked_checks` keys mapped through `CHECK_COMPLIANCE`
  (NOT from findings — a clean scan has zero findings but full coverage).
- "failing" categories from `report["findings"]` entries' `check_name` → `CHECK_COMPLIANCE` lookup.

A missing/corrupt report JSON for one scan must be skipped, not raise (`try/except` around the
`json.load`, continue aggregating remaining scans) — matches this codebase's "one check's failure
doesn't kill the whole scan/page" convention (`CLAUDE.md`, `checks.py` module docstring) and
UI-SPEC's E4 backstop row.

---

### `templates/scan_report.html` — compliance grouping/filter view + inline pill

**Analog:** the file's own existing severity-grouping loop (`scan_report.html:110-132`):
```jinja
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
Per UI-SPEC: build a **second, parallel** loop with the identical `namespace`-tracked
`<details>`/`<summary>` accordion shape, keyed by
`CHECK_COMPLIANCE.get(f.check_name, {}).get("owasp", "Uncategorized")` instead of `f.category`,
toggled via a `?group=compliance` query param (default falls back silently to severity grouping —
UI-SPEC copy contract). Add the inline compliance pill to the *existing* finding-card markup
(`<span class="badge {{ f.severity }}">{{ f.severity }}</span>` line, ~122) regardless of which
grouping mode is active — UI-SPEC's E2 requirement that the tag is visible even in Severity mode.

**Locked-check styling analog for "not checked"** (`scan_report.html:33-36, 48-65`):
```css
.finding.locked-card { opacity: .65; border-left-color: var(--border); }
.finding.locked-card .badge { background: rgba(147,160,201,.15); color: var(--muted); }
```
```jinja
{% macro locked_card(name) %}
<div class="finding locked-card">
  <span class="badge">...locked</span>
  <div class="body">
    <b>{{ name|replace('_', ' ')|title }}</b>
    <div class="detail">
      {% if name in org_verified_checks %}
      Requires the <b>Org-verified</b> plan and a verified domain to unlock this check.
      <a href="{{ url_for('billing.view') }}">Upgrade to Org-verified</a> &middot;
      <a href="{{ url_for('org.verify_domain_view') }}">Verify domain ownership</a>
      {% else %}
      Requires the <b>Paid</b> plan to unlock this check.
      <a href="{{ url_for('billing.view') }}">Upgrade to Paid</a>
      {% endif %}
    </div>
  </div>
</div>
{% endmacro %}
```
Reuse verbatim for asset_detail.html's "Not checked" row when the reason is tier-locking (per
UI-SPEC's copywriting contract).

**New CSS to add** (per UI-SPEC Color section — one new neutral pill variant, `--muted`-based,
matching the exact rgba-background + solid-text formula every other `.pill` variant already uses,
`base.html:60-66`):
```css
.pill.compliance { background: rgba(139,150,173,.14); color: var(--muted); }
```

---

### `templates/asset_detail.html` — "Compliance coverage" summary card

**Analog:** the file's own existing "Latest scan" status-pill card and "Risk score over time"
sparkline card (`asset_detail.html:84-120`):
```jinja
<h2 class="section">Risk score over time</h2>
<div class="card sparkline-card">
  {% set scored = [] %}
  {% for s in scans %}
    {% if s.risk_score is not none %}{% set _ = scored.append(s) %}{% endif %}
  {% endfor %}
  ...
```
```jinja
<div class="status-pill {{ latest.status.value }}">{{ latest.status.value }}</div>
```
Build the new "Compliance coverage" section as a sibling `<h2 class="section">Compliance
coverage</h2>` + `.card` block, same visual weight as the existing "Scan history" table card (per
UI-SPEC's "Primary visual anchor" note — not elevated above the risk-score gauge). Reuse
`.status-pill`/`.pill.pass`/`.pill.{severity}` for row status per UI-SPEC's copywriting contract
("Passing" / "{N} finding(s), highest: {severity}" / "Not checked"), and the sparkline card's
existing empty-state `.hint` styling (`asset_detail.html:18` `.sparkline-card .hint`) for the "Not
enough completed scans yet..." copy.

## Shared Patterns

### IDOR/ownership guard (applies to any new asset-scoped read)
**Source:** `glassbox/asset_routes.py:38` (`_check_asset_access`), called at
`asset_detail()` line 148; sibling pattern `scan_routes._check_ownership()` referenced at
`scan_routes.py:560`.
**Apply to:** the new coverage-aggregation helper in `asset_routes.py` — must call
`_check_asset_access(a)` before reading any `Scan`/`Report` for that Asset, exactly as
`asset_detail()` already does. Per RESEARCH.md's Security Domain section, this is the phase's one
real threat pattern (compliance-summary route leaking one org's data to another) and must reuse the
existing guard, not invent a new one.

### "Missing dict entry degrades gracefully" fallback convention
**Source:** `glassbox/checks.py:47-60` (`CHECK_LABELS`, falls back to
`check_name.replace('_', ' ').title()`) and `:72-87` (`CHECK_CATEGORY`, falls back to `"shield"`).
**Apply to:** `CHECK_COMPLIANCE` lookups in both templates and the asset_routes helper — a
`check_name` missing from `CHECK_COMPLIANCE` (or an `owasp` value that's `None`/absent) must render
`"Uncategorized"` (D-04), never raise or silently drop the finding.

### Coverage-regression test technique
**Source:** `tests/test_entitlements.py:49-79` (`_run_scan_job_names()` — regex-parses
`scan_engine.py`'s `jobs = { ... }` block; `ADVANCED_SCAN_CHECK_NAMES`/`OUT_OF_JOBS_DICT_NAMES`
hand-maintained constants for check groups without a `jobs` dict) and `tests/test_scan_events.py:60-86`
(`test_check_labels_covers_every_run_scan_job_name`, `test_check_category_covers_every_check_label`
— the exact "coverage test lives in a third file" precedent this phase should follow for
`tests/test_compliance.py`).
```python
# Source: tests/test_entitlements.py:49-58
def _run_scan_job_names():
    src = Path(__file__).resolve().parent.parent / "glassbox" / "scan_engine.py"
    text = src.read_text(encoding="utf-8")
    start = text.index("jobs = {")
    end = text.index("\n    }", start)
    block = text[start:end]
    return set(re.findall(r'"(\w+)":\s*lambda', block))

ADVANCED_SCAN_CHECK_NAMES = {"sqli_login", "bruteforce", "sqli_union", "xss_stored", "idor"}
OUT_OF_JOBS_DICT_NAMES = {"headers", "cookies", "open_ports"}
```
**Apply to:** `tests/test_compliance.py` (new file) — import/reuse these constants (or re-derive
identically) plus two new ones, `MEDIA_SCAN_CHECK_NAMES = {"media"}` and
`API_SCAN_CHECK_NAMES = {"schema", "wordlist", "js_discovery"}`, and write:
```python
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

### Jinja auto-escaping (no `|safe`)
**Source:** every existing finding-rendering block in `scan_report.html` (e.g. lines 121-128) —
no `|safe` filter appears anywhere in the finding-card markup.
**Apply to:** the new compliance-grouped loop and compliance pill — render `f.title`/`f.detail`
the same un-`|safe` way; do not introduce a new raw-HTML path for "highlighting" the compliance tag
(per RESEARCH.md Security Domain — finding text can contain content drawn from the scanned site's
own HTTP responses).

## No Analog Found

None — every file in this phase's scope has a direct, same-file or same-codebase-precedent analog
(this phase is explicitly a "labeling layer on existing pipelines," not new architecture).

## Metadata

**Analog search scope:** `glassbox/` (checks.py, scan_engine.py, scan_routes.py,
asset_routes.py, entitlements.py, models.py), `templates/` (scan_report.html, asset_detail.html,
base.html), `tests/` (test_entitlements.py, test_scan_events.py)
**Files scanned:** 10
**Pattern extraction date:** 2026-08-11
