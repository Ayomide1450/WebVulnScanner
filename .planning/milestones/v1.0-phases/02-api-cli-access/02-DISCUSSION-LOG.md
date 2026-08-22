# Phase 2: API & CLI Access - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-10
**Phase:** 2-API & CLI Access
**Areas discussed:** Token auth mechanism

---

## Token auth mechanism

### Token storage

| Option | Description | Selected |
|--------|-------------|----------|
| Hash-only, shown once | Token generated as a random string, shown to the user exactly once at creation, only its hash stored (indexed lookup on the hash column). Standard, simple, no plaintext secret ever persists. | ✓ |
| Prefix + secret split (GitHub-style) | `wvs_<id>_<secret>` — the id stored in plaintext for fast lookup, secret hashed. More scalable for future secret-scanning integration, but more moving parts than this phase needs. | |

**User's choice:** Hash-only, shown once (recommended option)
**Notes:** None beyond selecting the recommendation.

### Token scope

| Option | Description | Selected |
|--------|-------------|----------|
| User-scoped | A token acts as the specific user who created it, inheriting their exact existing role/permissions. Reuses all current authorization checks unchanged — no new authorization model to build. | ✓ |
| Org-scoped with independent role | A token has its own role assignment, not tied to a specific user. More flexible (survives the creating user leaving) but is a new authorization model to design and audit separately. | |

**User's choice:** User-scoped (recommended option)
**Notes:** Flagged as a one-way decision — switching to org-scoped later would be a breaking
change to token authorization semantics, not a simple addition.

### Revocation

| Option | Description | Selected |
|--------|-------------|----------|
| Soft-disable with revoked_at | Matches Phase 1's Asset soft-delete (deleted_at) convention — preserves an audit trail of when a token existed and was used, rather than losing that history. | ✓ |
| Hard delete | Simpler — revoking a token just deletes the row. No history of past token existence/usage retained. | |

**User's choice:** Soft-disable with revoked_at (recommended option)
**Notes:** None beyond selecting the recommendation.

### Token count

| Option | Description | Selected |
|--------|-------------|----------|
| Multiple named tokens | e.g. a separate token for a CI pipeline vs. a personal script, each independently revocable. Requires a name/label field per token for identification. | ✓ |
| Single active token | Creating a new token invalidates the old one. Simpler, but rotating breaks every other integration using the previous token. | |

**User's choice:** Multiple named tokens (recommended option)
**Notes:** None beyond selecting the recommendation.

---

## Claude's Discretion

Three other candidate gray areas were presented but not selected for deep-dive discussion; the
user chose "I'm ready for context" after Token auth mechanism. Left to researcher/planner
discretion, grounded in existing codebase conventions:

- API route design & versioning (URL prefix/blueprint structure, JSON response/error envelope,
  pagination for the asset-list endpoint).
- CLI distribution & authentication (how the CLI ships, how it stores/passes the token locally).
- Rate-limit & tier-gate consistency (reusing Flask-Limiter and entitlements.py so API access
  can't bypass what the web UI and scheduler already enforce).

## Deferred Ideas

None — discussion stayed within phase scope; no scope-creep suggestions arose during this
session.
