# opencodefailure.md — Mistake & Failure Log

> Append-only. Every time something you (opencode) build breaks, needs a revert, fails a test
> after being claimed green, ships a bug caught later, or gets factually corrected by a human/
> reviewer — log it here **the same session it happens**, before moving on. Do not edit or
> delete past entries; this file is a record, not a scratchpad. If a fix supersedes an earlier
> entry, add a new entry that references it — don't rewrite history.

## Why this file exists

The Claude-side reviewer (acting as senior UX/UI, full-stack, product, and DevOps reviewer for
this repo) reads this file before trusting a "shipped" claim in `opencode.md`. A clean track
record here is itself evidence of quality; a growing one with real root-causes recorded is more
trustworthy than a file that never has anything in it — that would just mean failures aren't
being logged, not that none happened.

## Entry format

```
### YYYY-MM-DD — <one-line summary>

**What broke**: concrete, specific — what a user/reviewer/test actually saw go wrong.
**Root cause**: the real mechanism, not "a bug" — trace it to the actual line/logic/assumption.
**Fix**: what changed, and why that's the right level to fix it at (not just patching the symptom).
**Caught by**: test / live-fire verification / human review / production incident / self-caught.
**Prevention**: what, if anything, changes going forward so this class of mistake doesn't recur
(a new test, a new convention line in opencode.md, a lint rule — or "nothing, one-off").
```

## Log

### 2026-08-24 — Phase 21 shipped as a standalone dev-tool page end users couldn't interpret

**What broke**: Phase 21's detection self-test went live as `/selftest` — its own top-level
nav/dashboard surface presenting "loopback-only lure server," "planted flaws," and a bare
Check/Ground-truth/Detected/Verdict matrix to end users, who read it as *a second scanner*
("which domain does THIS one hit?") — the exact confusion the loopback design exists to avoid.
**Root cause**: I optimized for engineering transparency (show the proof matrix raw) instead
of asking what relationship the UI implied. A verification feature that looks like a parallel
product undermines trust rather than building it.
**Fix**: Phase 21.1 (commit d124485) — route/page/button deleted (`/selftest` now 404s);
the engine now runs once per worker process inside `run_scan()` and surfaces as an
"Engine verified · N/10 detections confirmed" pill beside the report's risk score, captioned
explicitly as checked against Glassbox's own internal target.
**Caught by**: human/Claude review — live browser walkthrough of staging, 2026-08-24.
**Prevention**: operating-model rule #4 in opencode.md ("UX matters as much as correctness")
now names this exact case; every user-facing surface gets a "what relationship does this
imply?" pass before shipping.

### 2026-08-24 — Phase 22's first full-suite run failed 2 card-conversion scope locks

**What broke**: adding `templates/api_docs.html` tripped
`test_phase_gate_card_conversion_scope_is_exactly_eight_templates` twice (set membership +
count assertion) — the closed-set tripwire did its job, but only after a full 18-minute run
because I hadn't run the template-consistency suite during development.
**Root cause**: the card-conversion scope is a deliberately closed set; a new template must
be added to it AND the count renamed/asserted in the same change.
**Fix**: added `api_docs.html` to `_EXPECTED_CARD_CONVERSION_TEMPLATES`, renamed test to
`..._exactly_nine_templates`, asserted count == 9.
**Caught by**: full pytest run (self-caught, before any ship claim).
**Prevention**: run `tests/test_responsive_markup.py tests/test_template_consistency.py
tests/test_accessibility.py` targeted whenever a template is added — now habitual.

### 2026-08-24 — edit tooling momentarily swallowed `save_report`'s def line during 21.1

**What broke**: while appending `report["detection_verified"] = ...` to `run_scan()`'s tail,
an oldString/newString pair dropped the `def save_report(...)` line that followed the return,
leaving an orphaned docstring. Syntax stayed valid (docstring-as-expression), so nothing
failed loudly at that instant.
**Root cause**: my replacement string omitted the trailing context lines it had matched.
**Fix**: re-read the region, restored the def line; `ast.parse` smoke-check added to the
workflow for every touched module.
**Caught by**: self-caught on the immediate post-edit read-back (before any test).
**Prevention**: the ast.parse check per edited Python file; no recurrence since.

### 2026-08-24 - Phase 27: five pre-commit catches in one build (all self-caught by tests)

**What broke**: (1) the regression-timeline section was first inserted inside
asset_detail.html's `{% if scans %}` block, so brand-new Assets never rendered it; (2)
`_seed_completed` pushed a nested `app.app_context()` inside the caller's, minting a second
SQLAlchemy session/connection and deadlocking the on-disk SQLite file ("database is locked");
(3) the stubbed `run_media_scan` returned a report dict without the `hostname` key the media
branch reads at scan_routes.py:227, failing the scan under test; (4) used `hashlib.hmac`
instead of the stdlib `hmac` module; (5) `secret="s3cret-regression-key"` tripped
test_secrets_hygiene's credential-shaped-literal sweep.
**Root cause**: (1) inserted at a visually convenient anchor without mapping the enclosing
conditional's extent; (2) copied the fixture style of tests that run WITHOUT an outer context;
(3) wrote the stub from memory instead of re-reading the consuming branch's contract; (4/5)
careless stdlib/repo-convention slips.
**Fix**: relocated the section after the scans-conditional behind its own `{% if scans %}`;
flattened the helper to require the caller's context (documented why); added
hostname/score to the stub; `import hmac as hmac_mod` (matching test_webhooks.py); switched to
the `"4" * 64` hex-style fake secret test_webhooks already uses.
**Caught by**: every one by my own targeted tests before commit - render test for (1), pytest
traceback for (2)/(3), AttributeError for (4), the secrets sweep tripwire for (5).
**Prevention**: before inserting template markup, locate the closing tag of every enclosing
`{% if %}`; test helpers that touch the DB must state their app-context requirement; when
stubbing an orchestrator, read the branch that consumes its return value first; run
test_secrets_hygiene.py alongside any new test module that mentions webhook/signing fields.

### 2026-08-24 - PowerShell array splice mangled opencode.md (wrong indices)

**What broke**: updating the "What's next" v1.7 block, I spliced with line numbers from a
Select-String on a DIFFERENT pattern match (~517 vs actual 512) and used [0..16]/[25..]
instead of [0..511]/[520..] - silently deleting ~8 lines of the operating-model rules while
leaving the target block untouched.
**Root cause**: eyeballed indices instead of recomputing them from the same file read; two
different anchor patterns returned different LineNumbers and I mixed them.
**Fix**: `git checkout -- opencode.md` to restore, re-read the exact region, redid the splice
with verified indices ([0..511] + new + [520..end]); this also reverted my earlier
snapshot/Done edits, which were reapplied via the edit tool. Rules section verified intact by
grepping for its rule headings afterward.
**Caught by**: reading back the spliced region immediately after writing (the output showed
the old block unchanged plus a suspiciously short file).
**Prevention**: never hand-compute slice bounds for whole-file rewrites in PowerShell -
prefer the edit tool's string matching for targeted replacements; if a shell rewrite is truly
needed, echo the affected region BEFORE and AFTER in the same command.

### 2026-08-24 - Set-Content rewrote ALL of opencode.md double-encoded (+BOM), committed it

**What broke**: after a misindexed array splice damaged opencode.md, I restored from HEAD and
redid the edit via PowerShell `Set-Content -Encoding UTF8` on the full file. Windows
PowerShell 5.1 wrote UTF-8 WITH BOM and re-encoded every pre-existing em-dash/arrow as
double-encoded mojibake across all ~570 lines - and I then committed that degraded version
(93f62ff showed 320 changed lines for what should have been ~50).
**Root cause**: used a whole-file shell rewrite where a targeted string edit was the right
tool; PS 5.1's `-Encoding UTF8` is not BOM-less UTF-8; and I read the commit stat (320/156)
without stopping to ask why a docs commit touched every line.
**Fix**: `git checkout 93f62ff~1 -- opencode.md` to recover the good bytes, reapplied the three
intended changes with the edit tool only, verified diff = 33 insertions / 24 deletions and
zero mojibake lines before committing this corrective commit.
**Caught by**: self-caught reviewing 93f62ff's per-file diff stat immediately after committing.
**Prevention**: opencode.md (and every doc with typographic characters) gets edited ONLY via
the string-matching edit tool on this machine - never Set-Content/Add-Content whole-file
rewrites; treat "diff way bigger than the change" as an automatic stop-and-investigate.
