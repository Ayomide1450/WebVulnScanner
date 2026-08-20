# Deferred Items - Phase 8

Out-of-scope discoveries logged during plan execution, per the executor's SCOPE
BOUNDARY rule (auto-fix only issues directly caused by the current task's own
changes; log and defer everything else).

## From 08-02 (SEC-02: CSRF enforcement)

### Pre-existing flaky test: `tests/test_org_invite.py::test_decode_invite_token_rejects_tampered_signature`

- **File:** `tests/test_org_invite.py:212`
- **Not caused by 08-02.** `tests/test_org_invite.py` is not in this plan's
  `files_modified` and was not touched by any 08-02 commit.
- **What's wrong:** the test tampers a signed invite token by flipping only its
  *last* character:
  ```python
  tampered = token[:-1] + ("a" if token[-1] != "a" else "b")
  ```
  The token is an `itsdangerous.URLSafeTimedSerializer` payload whose trailing
  base64 signature character sometimes encodes only 2 significant bits (the
  rest is unused padding that Python's base64 decoder does not validate as
  zero) - so a specific replacement character has roughly a 1-in-16 chance of
  landing in the same 4-character decode-equivalence class as the original,
  in which case the "tampered" token decodes to the exact same bytes and
  still validates. Measured empirically at ~6.9% (343/5000 trials, distinct
  payloads) during 08-02's own investigation - see 08-02-SUMMARY.md.
- **Why this surfaced now:** it tripped during 08-02's own full-suite wave-gate
  run (`1 failed, 658 passed`), then passed cleanly on every reproduction
  attempt run in isolation, alongside `tests/test_csrf_enforcement.py`, and in
  a fast statistical loop that held the tampering position fixed (0/3000 -
  because rapid consecutive calls tend to land in the same wall-clock second
  and reuse an identical signature, hiding the bug). Varying the signed
  payload per iteration reproduced it reliably.
- **Same bug class 08-02 specifically avoided:** `tests/test_csrf_enforcement.py`'s
  own `_mutate_token()` helper originally had this exact same last-character
  bug (discovered and fixed during 08-02 Task 1 - see git history / the
  helper's docstring) before settling on flipping the *first* character
  instead, which reliably corrupts the signed payload every time.
- **Suggested fix** (not applied here - out of scope for 08-02): change
  `test_decode_invite_token_rejects_tampered_signature` to flip the first
  character of the token instead of the last, mirroring
  `tests/test_csrf_enforcement.py::_mutate_token`'s fix.
- **Tracked in:** `.planning/WINDOWS.md` (kind: `deviation`, phase 8, open).
