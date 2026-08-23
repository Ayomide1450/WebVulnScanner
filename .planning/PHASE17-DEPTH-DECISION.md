# Phase 17 / DEPTH-01 - Crawl-depth decision record

**Status**: APPROVED - 2026-08-23, user signed off "A AND B": variant
coverage (Option A) ships in Phase 17, AND the capped depth-2 crawl
(Option B) ships in the same phase under the caps below. Option C remains
rejected.
**Date drafted**: 2026-08-23
**Why this is a written decision**: loosening crawl depth changes the app's
safety posture (more requests against customer targets, wider probe surface),
so REQUIREMENTS.md DEPTH-01 requires it be decided explicitly, not defaulted.

## Current behavior (verified in code, not memory)

- `crawl_same_origin()` (checks.py:1873): **depth-1** - parses ONLY the
  homepage HTML, collects same-origin links that carry query params (cap:
  `limit=10` default; run_scan calls it with defaults), honors robots.txt
  `Disallow` rules, enumerates forms but NEVER submits them.
- Probing (`check_xss_sqli`, checks.py:2026): per discovered param -
  1 XSS request (single `"><svg onload=marker>` variant), 1 SQLi error probe
  (`'`), and only if no DB error signature matched, 2 boolean-blind requests
  (`1' AND '1'='1` / `'2`). Worst case ~4 requests/param + 0.15s spacing.
- Advanced checks already multi-variant: stored XSS has 3 tag templates,
  auth-bypass has 3 payloads plus time-blind per engine, UNION does column
  enumeration plus time-blind.

## Options

### Option A - Keep depth-1, spend the phase on variant coverage (RECOMMENDED)

Posture: unchanged. All DEPTH-02 work lands inside existing checks.

Rationale: most Glassbox targets are small marketing/SaaS sites where the
10-URL cap already covers the server-rendered surface; deeper crawling adds
risk without adding signal for them. Variant breadth is where misses happen
today - exactly one reflected-XSS string shape, one SQLi error-probe shape.

Cost: none. Safety doc untouched.

### Option B - Depth-2 crawl behind explicit caps (APPROVED with these caps)

(e.g. max 15 pages fetched, same-origin only, robots-honored, GET-only)

Posture: CHANGES. Interior pages (docs, blogs, catalog filters) often carry
the query-param URLs worth probing; modern JS-shell homepages expose almost
none of them server-side.

Costs/risks to accept explicitly: more requests against customer targets;
slower scans; needs its own page-count cap and robots discipline (already
implemented for hop-1); slightly wider accidental-probe surface on sensitive
interior paths even with robots honored.

**Binding caps for the approved implementation:**

1. MAX_CRAWL_PAGES = 15 interior pages fetched per scan (hop-2 only; the
   homepage fetch is not counted against this).
2. Same-origin strictly (existing netloc equality check per link AND per page).
3. robots.txt `Disallow` honored for every fetched page and harvested link
   (reuses `_fetch_robots_disallow_prefixes` / `_robots_disallows`).
4. Only plain HTML pages are fetched (skip non-HTML content types).
5. The PROBE list fed to check_xss_sqli stays capped at the existing
   limit=10 semantics: hop-1 links keep priority, hop-2 fills remaining
   slots after dedup - discovery grows, the intrusive-probe budget does not.
6. Forms still enumerated, never submitted. Probing stays GET-only.

### Option C - Deeper / unbounded crawl

Rejected up front: unbounded fan-out contradicts the tool's non-destructive,
capped ethos and would need rate-limiting infrastructure that does not exist
today.

## DEPTH-02 plan under any option (variant additions, same caps)

Reflected XSS (check_xss_sqli) - add marker-only variants, no alert(), no
execution proof beyond exact-string reflection:

1. `<img src=x onerror=marker>` (attribute-handler family)
2. `" onmouseover=marker x=" (attribute-breakout family)
3. Case-evasion `<ScRiPt>marker</ScRiPt>` (poor-man's filter-evasion signal)

SQLi (check_xss_sqli):

1. Numeric-context boolean pair `1 AND 1=1` / `1 AND 1=2` when the original
   param value is all-digits (current pair is quote-context only)
2. Two more SQL_ERROR_SIGNATURES (e.g. `System.Data.SqlClient.SqlException`,
   `mysql_fetch_array()`)

Budget guard so variants cannot blow past "same caps": a new
MAX_PROBE_REQUESTS_PER_URL constant (~12) asserted by a regression test -
if someone later adds variants that would exceed it, the test fails.

DEPTH-03: no NEW check names are introduced (variants live inside existing
checks), so FEATURE_REQUIREMENTS/CHECK_LABELS/CHECK_CATEGORY stay as-is and
their existing sync tests keep passing; add a source-parsing lock asserting
the variant lists never shrink below the Phase 17 counts.
