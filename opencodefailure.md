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
