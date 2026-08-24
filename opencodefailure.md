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

*(no entries yet as of 2026-08-24 — this file was created today; backfill anything from earlier
sessions you can reconstruct from git history if you have time, but don't block new work on it)*
