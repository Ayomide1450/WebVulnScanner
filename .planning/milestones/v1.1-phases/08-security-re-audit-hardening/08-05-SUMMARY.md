---
phase: 08-security-re-audit-hardening
plan: 05
subsystem: templates-orm-reports
tags: [jinja2, autoescape, sqlalchemy, path-traversal, containment, security]

# Dependency graph
requires:
  - phase: 08-security-re-audit-hardening (08-01, 08-02, 08-03)
    provides: "Green wave-1/wave-2 baseline this plan's audit sweep built on"
provides:
  - "End-to-end proof that six user/target-controlled strings (finding title, finding detail, ai_summary, org name, domain name, flashed error) render HTML-escaped, plus a CSV counter-case pinning that non-HTML export output is deliberately NOT escaped"
  - "Standing, comment-filtered source-level locks: no template disables autoescape or uses |safe, no module builds Markup()/calls render_template_string(), and an exact-set allowlist of the only two raw db.session.execute() call sites in the app, each independently proven safe (literal string / bound Core update)"
  - "glassbox/scan_engine.read_report_file() - one containment-checked reader replacing three independent inline REPORTS_DIR-joined open() blocks in scan_routes.py, api_routes.py and asset_routes.py, each keeping its own original failure contract"
  - "A reachability analysis recorded plainly: report-path traversal is not exploitable today (Report.json_path is server-generated only), so SEC-06's fix is defence in depth, not a live-vulnerability patch"
affects: [08-06, 08-07]

actuals:
  tokens: 68000
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Comment-filtered, full-line-only source scanning (strip full-line '#'/Jinja-comment lines, then split on trailing '#' before matching) for standing regression locks - same idiom test_csrf_enforcement.py already established, reused here for the autoescape/Markup/execute-call-site locks."
    - "Exact-set allowlist lock (module+function pairs) for a small, closed set of intentionally-raw constructs (the two db.session.execute() call sites), rather than a blanket ban - mirrors 08-02's csrf.exempt() scope lock shape."
    - "Containment via os.path.realpath() on BOTH sides (REPORTS_DIR and the candidate) before os.path.commonpath() comparison, not string-prefix arithmetic on the raw input - REPORTS_DIR is derived from __file__ and can itself sit behind a symlink."
    - "Positive-control tests seed a Report row with data=None specifically so the on-disk fallback branch is the one actually exercised - with Report.data set, the fallback never runs and the test would prove nothing."

key-files:
  created: []
  modified:
    - tests/test_injection_and_traversal.py
    - glassbox/scan_engine.py
    - glassbox/scan_routes.py
    - glassbox/api_routes.py
    - glassbox/asset_routes.py

key-decisions:
  - "SEC-04/SEC-05 needed proof and a standing lock, not a fix - 08-RESEARCH.md's audit found the codebase already correct (zero unsafe-filter usages, zero markup-construction calls, exactly two non-builder DB calls) and this plan's own re-scan confirmed the same zero-hit result before locking it in."
  - "read_report_file() was placed in scan_engine.py, not checks.py, specifically to avoid touching a file plan 08-04 was concurrently modifying in this same wave (an explicit prohibition in this plan's frontmatter) - scan_engine.py already owns save_report(), the new reader's symmetric counterpart."
  - "Each of the three converted call sites keeps its own distinct failure contract unchanged (None / 500 JSON body / silent skip) rather than being unified - api_routes.py's 500 JSON body is a real external contract cli/wvs.py depends on, and asset_routes.py's silent skip is load-bearing for the compliance summary's partial-data rendering."
  - "The reader's docstring explicitly states this is defence in depth, not a live-vulnerability fix, and the reachability chain (save_report() is the only writer of Report.json_path, always from a server-generated hostname+timestamp, never from a request parameter) is recorded both in code and in this summary - the plan's own must_haves required not overstating this as an exploit fix."

patterns-established:
  - "tests/test_injection_and_traversal.py is now the shared home for SEC-04/05/06 as one audit sweep (one payload constant, one templates/ scan, one glassbox/ scan, one containment-checked-reader section) rather than three separate test modules - reused directly by 08-04's coordination note and available as the pattern for any future 'prove X holds everywhere' requirement."

requirements-completed: [SEC-04, SEC-05, SEC-06]

coverage:
  - id: D1
    description: "Finding title/detail, ai_summary, org name, domain name and flashed errors all render HTML-escaped on their respective pages - escaped form present, raw form absent"
    requirement: SEC-04
    verification:
      - kind: unit
        ref: "tests/test_injection_and_traversal.py::test_finding_title_renders_escaped_on_scan_report, test_finding_detail_renders_escaped_on_scan_report, test_ai_summary_renders_escaped_on_scan_report, test_org_name_renders_escaped_on_org_admin, test_domain_name_renders_escaped_on_org_admin, test_flashed_error_message_renders_escaped"
        status: pass
    human_judgment: false
  - id: D2
    description: "CSV export output is deliberately NOT HTML-escaped (counter-case, not a bug)"
    requirement: SEC-04
    verification:
      - kind: unit
        ref: "tests/test_injection_and_traversal.py::test_csv_export_contains_raw_payload_unescaped"
        status: pass
    human_judgment: false
  - id: D3
    description: "No template disables autoescape or uses |safe; no module constructs Markup() or calls render_template_string() - standing, comment-filtered locks"
    requirement: SEC-04
    verification:
      - kind: unit
        ref: "tests/test_injection_and_traversal.py::test_no_template_disables_autoescaping_or_uses_safe_filter, test_no_module_constructs_markup_or_renders_template_string"
        status: pass
      - kind: manual
        ref: "Negative controls performed live during this recovery pass and reverted clean: (1) appended {{ \"neg-control\"|safe }} to templates/marketing.html -> AssertionError naming templates/marketing.html:484, mechanism '|safe filter'; (2) appended a Markup(\"<b>x</b>\") return to glassbox/public_routes.py -> AssertionError naming glassbox/public_routes.py:45. Both reverted via git checkout, diffs confirmed empty."
        status: pass
    human_judgment: false
  - id: D4
    description: "Every DB access goes through the ORM/Core query builders except exactly two named, individually-justified raw execute() call sites"
    requirement: SEC-05
    verification:
      - kind: unit
        ref: "tests/test_injection_and_traversal.py::test_raw_sql_execute_call_sites_are_exactly_the_two_known_ones, test_healthcheck_sql_argument_is_a_literal_string_constant, test_scheduler_update_binds_values_as_parameters"
        status: pass
      - kind: manual
        ref: "Negative control performed live and reverted clean: appended a third db.session.execute(\"SELECT 1\") call to glassbox/public_routes.py -> AssertionError: 'raw db.session.execute() call site(s) changed (SEC-05 regression) - expected exactly [(...healthz), (...try_claim)], found [(...healthz), (..._neg_control_execute), (...try_claim)]'. Reverted via git checkout, diff confirmed empty."
        status: pass
    human_judgment: false
  - id: D5
    description: "A Report whose json_path escapes REPORTS_DIR serves no file - traversal, absolute-path, and unresolvable-value inputs all return None and open nothing (proven with a real sentinel file outside the directory, asserted never read)"
    requirement: SEC-06
    verification:
      - kind: unit
        ref: "tests/test_injection_and_traversal.py::test_read_report_file_rejects_parent_directory_traversal, test_read_report_file_rejects_absolute_path, test_read_report_file_returns_none_for_value_that_raises_during_resolution"
        status: pass
    human_judgment: false
  - id: D6
    description: "A legitimate, server-generated filename still loads through every one of the three call sites, each keeping its own original failure contract"
    requirement: SEC-06
    verification:
      - kind: unit
        ref: "tests/test_injection_and_traversal.py::test_read_report_file_returns_parsed_json_for_a_legitimate_filename, test_scan_routes_report_page_uses_on_disk_fallback_via_read_report_file, test_api_routes_fetch_report_uses_on_disk_fallback_via_read_report_file, test_asset_routes_compliance_coverage_uses_on_disk_fallback_via_read_report_file"
        status: pass
    human_judgment: false
  - id: D7
    description: "No fourth call site can silently reintroduce an inline REPORTS_DIR-joined open()"
    requirement: SEC-06
    verification:
      - kind: unit
        ref: "tests/test_injection_and_traversal.py::test_no_module_inlines_an_open_on_a_reports_dir_join"
        status: pass
    human_judgment: false
  - id: D8
    description: "Reachability analysis: report-path traversal is not exploitable today (Report.json_path is server-generated only) - this is defence in depth, not a live-vulnerability fix"
    requirement: SEC-06
    verification:
      - kind: manual
        ref: "Recorded in read_report_file()'s docstring and in this summary; traced who writes Report.json_path (only scan_engine.save_report(), from a hostname+timestamp it builds itself) and confirmed no request parameter reaches it at any of the three call sites"
        status: pass
    human_judgment: false

duration: ~80min
completed: 2026-08-19
status: complete
---

# Phase 8 Plan 05: Escaping, SQL Parameterization and Report-Path Containment Summary

**Closed SEC-04, SEC-05 and SEC-06 as one audit sweep: proved the app's existing Jinja2 autoescaping and SQLAlchemy query-builder discipline are correct today and locked both standing, then collapsed three independently-unguarded report-file reads into one containment-checked `scan_engine.read_report_file()`.**

## Performance

- **Duration:** ~80 min
- **Completed:** 2026-08-19
- **Tasks:** 3 of 3 completed
- **Files modified:** 5

## Accomplishments

- Proved six user/target-controlled strings (finding title, finding detail, `ai_summary`, org name, domain name, flashed error message) render HTML-escaped wherever Jinja2 puts them on the page - each test asserts the escaped form is present AND the raw form is absent, using a single module-level payload constant with escaped/raw forms both derived via `markupsafe.escape` (never retyped by hand).
- Pinned the deliberate counter-case: CSV export output is NOT HTML-escaped (it isn't HTML), so a future "fix" that escapes it would itself be the regression.
- Added two standing, comment-filtered source-level locks: no template under `templates/` disables autoescape or uses `|safe`; no module under `glassbox/` constructs `Markup()` or calls `render_template_string()`. Both confirmed zero-hit on the real codebase, then negative-controlled live during this recovery pass (see Negative Controls below) with the resulting failure text captured verbatim.
- Added an exact-set allowlist lock over the only two raw `db.session.execute()` call sites in the app (`public_routes.healthz`, `scheduler._try_claim`), plus two more tests independently proving each is safe: the healthcheck's argument is a literal `"SELECT 1"` string constant (never an f-string/`.format()`), and the scheduler's Core `update()` binds its values via `.values()`. Negative-controlled live (see below).
- Added `scan_engine.read_report_file()`: resolves both `REPORTS_DIR` and the candidate path to real filesystem paths before comparing containment (not string-prefix arithmetic on the raw input, since `REPORTS_DIR` is derived from `__file__` and can itself sit behind a symlink), returning `None` on containment failure, a missing/unreadable file, invalid JSON, or any value that makes path resolution itself raise.
- Converted all three former independent `open(os.path.join(REPORTS_DIR, ...))` blocks (`scan_routes._load_report_json`, `api_routes.fetch_report`, `asset_routes.compliance_coverage`) to call the shared reader, each keeping its own pre-existing, distinct failure contract exactly: `None`, a `jsonify(error=...), 500` body (`cli/wvs.py` depends on this shape), and a silent `continue`/skip respectively.
- Proved traversal, an absolute path, and a null-byte value that makes resolution raise all return `None` and open nothing - each test creates a real sentinel file *outside* `REPORTS_DIR` under pytest's `tmp_path` and asserts its content never appears in the result, so a containment bug would make the test itself fail by leaking the secret, not just by returning a wrong-shaped value.
- Added one positive control per converted call site (`Report.data=None` so the on-disk fallback branch is the one actually exercised - with `data` set, the fallback never runs and the test proves nothing) plus a direct function-level positive control.
- Added a source-level lock preventing a fourth call site from reintroducing an inline `REPORTS_DIR`-joined `open()`.
- Recorded the reachability analysis plainly, in both the function's docstring and here: `Report.json_path` is written only by `save_report()`, always from a server-generated `hostname_timestamp.json` filename, never from a request parameter - path traversal on report reads is **not exploitable today**. This plan is defence in depth against a fourth caller with different provenance, not a fix for a live vulnerability, and is described that way rather than overclaimed.
- Full suite (`.venv\Scripts\python -m pytest -q`): **703 passed**, 0 failures, run in this plan's own worktree after all three tasks.

## Task Commits

1. **Task 1: End-to-end escaping proof for target-controlled finding text (SEC-04)** - `f80145a` (test)
2. **Task 2: Standing source-level locks for autoescape and SQL parameterization (SEC-04, SEC-05)** - `041e0f0` (test)
3. **Task 3: One containment-checked report reader, three call sites converted (SEC-06)** - `f672456` (feat)

## Files Created/Modified

- `tests/test_injection_and_traversal.py` - new module: payload constant + escaped/raw derivation, six escaping proofs, the CSV counter-case, the autoescape/Markup/execute-call-site source locks, and the SEC-06 containment/positive-control/source-lock section.
- `glassbox/scan_engine.py` - new `read_report_file()`, placed directly below `save_report()`.
- `glassbox/scan_routes.py`, `glassbox/api_routes.py`, `glassbox/asset_routes.py` - their inline report-read blocks replaced with calls to `read_report_file()`; each site's original failure contract unchanged.

## Decisions Made

- SEC-04 and SEC-05 needed proof and a standing lock, not a fix, per 08-RESEARCH.md's prior audit finding the codebase already correct - this plan's own independent re-scan reconfirmed zero hits before writing the locks, rather than trusting the research document's claim unverified.
- `read_report_file()` was deliberately placed in `scan_engine.py`, not `checks.py`, specifically because plan 08-04 was concurrently editing `checks.py` in this same wave (an explicit prohibition in this plan's own frontmatter) - `scan_engine.py` already owns `save_report()`, the reader's natural symmetric counterpart.
- Each of the three converted call sites keeps its own distinct failure contract rather than being unified into one shape, since `api_routes.py`'s 500 JSON body is a real external contract `cli/wvs.py` depends on and `asset_routes.py`'s silent skip is load-bearing for the compliance summary's partial-data rendering.

## Deviations from Plan

None. All three tasks were implemented as specified; no approach changes were needed.

## Negative Controls Performed

Task 1/2's negative controls were performed by the original authoring pass per the Task 2 commit message, but their exact console output was not preserved before this recovery picked the work back up (see "Recovery note" below) - re-ran three of them live during this pass instead of asserting from memory what they said:

1. **`|safe` filter injection** - appended `{{ "neg-control"|safe }}` to `templates/marketing.html`, ran `test_no_template_disables_autoescaping_or_uses_safe_filter` alone:
   `AssertionError: escaping-disabling construct(s) found (SEC-04 regression): templates/marketing.html:484 uses |safe filter -> '{{ "neg-control"|safe }}'`
   Reverted via `git checkout -- templates/marketing.html`; diff confirmed empty.
2. **`Markup()` construction** - appended a function returning `Markup("<b>x</b>")` to `glassbox/public_routes.py`, ran `test_no_module_constructs_markup_or_renders_template_string` alone:
   `AssertionError: markup-construction/string-template-render call(s) found (SEC-04 regression): glassbox/public_routes.py:45 -> 'return Markup("<b>x</b>")'`
   Reverted via `git checkout -- glassbox/public_routes.py`; diff confirmed empty.
3. **A third raw `.execute()` call site** - appended `db.session.execute("SELECT 1")` inside a new function in `glassbox/public_routes.py`, ran `test_raw_sql_execute_call_sites_are_exactly_the_two_known_ones` alone:
   `AssertionError: raw db.session.execute() call site(s) changed (SEC-05 regression) - expected exactly [('glassbox/public_routes.py', 'healthz'), ('glassbox/scheduler.py', '_try_claim')], found [('glassbox/public_routes.py', '_neg_control_execute'), ('glassbox/public_routes.py', 'healthz'), ('glassbox/scheduler.py', '_try_claim')].`
   Reverted via `git checkout -- glassbox/public_routes.py`; diff confirmed empty.

Task 3's two negative controls (the inline-open lock, and a containment-bypass check that a broken `read_report_file()` would have actually returned the sentinel's secret content) were performed by the original authoring pass per the trailing comment block at the end of `tests/test_injection_and_traversal.py`; not independently re-run in this recovery pass since Task 3's implementation was authored fresh in this recovery rather than found already-committed (see below).

## Recovery Note (process, not a plan deviation)

This plan's Task 1 and Task 2 commits (`f80145a`, `041e0f0`) were already present, complete, and passing when this recovery pass began - written by an earlier execution of this same worktree that was interrupted (a Claude Code session/API limit, consistent with prior sessions' documented failure mode in `handoff.md`) before Task 3 could be committed or `08-05-SUMMARY.md` written. Task 3's implementation (`read_report_file()` and the three converted call sites) was found already fully written and correct as **uncommitted** working-tree changes - verified by running its full targeted test suite (100 passed) and the full suite (703 passed) before committing it as-is, rather than being rewritten from scratch. This summary was written retroactively against the recovered, verified state; the three Task 1/2 negative controls were re-run live specifically because their original verbatim output was never captured (the interrupted session's own commit message says as much: "failure messages recorded in 08-05-SUMMARY.md", which never happened until now).

## Issues Encountered

None beyond the interrupted-session recovery described above.
