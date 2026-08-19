---
schema_version: 1
open_count: 1
waived_count: 0
fixed_count: 0
total_count: 1
last_updated: 2026-08-19T07:12:58.981Z
---

# Broken Windows Ledger

> Cross-phase defect register. `/gsd-ship` blocks while `open_count > 0`.
> Waive with `gsd-tools windows waive <id> "<reason>"` (reason required).
> Mark fixed with `gsd-tools windows fixed <id>`.

| id | phase | kind | file | line | description | status | reason | recorded_at | resolved_at |
|----|-------|------|------|------|-------------|--------|--------|-------------|-------------|
| 1 | 8 | deviation | tests/test_org_invite.py | 212 | Pre-existing flaky test: test_decode_invite_token_rejects_tampered_signature flips only the last base64 char of the itsdangerous signature, which ~6.9% of the time lands in the same 4-char decode-equivalence class as the original (base64 tail-byte padding bits), so the tampered token still validates and the assertion fails. Discovered incidentally during 08-02 (out of scope for 08-02, not fixed here). | open |  | 2026-08-19T07:12:58.981Z |  |

````json
[
  {
    "id": 1,
    "kind": "deviation",
    "phase": "8",
    "file": "tests/test_org_invite.py",
    "line": 212,
    "description": "Pre-existing flaky test: test_decode_invite_token_rejects_tampered_signature flips only the last base64 char of the itsdangerous signature, which ~6.9% of the time lands in the same 4-char decode-equivalence class as the original (base64 tail-byte padding bits), so the tampered token still validates and the assertion fails. Discovered incidentally during 08-02 (out of scope for 08-02, not fixed here).",
    "status": "open",
    "reason": "",
    "recorded_at": "2026-08-19T07:12:58.981Z",
    "resolved_at": null
  }
]
````
