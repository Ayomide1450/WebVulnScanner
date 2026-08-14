# Vercel migration: architecture notes and current status

This document explains what part of WebVulnScanner can move to Vercel as-is, what
architecturally cannot, and what's actually shipped in this pass vs. left as a follow-up
project. It does not describe a completed migration — see "What's shipped in this pass" at the
bottom for the honest boundary.

## Why this isn't a drop-in Vercel port

WebVulnScanner's scan engine runs on a model that is fundamentally incompatible with Vercel's
serverless Python functions:

- **Scans run on a raw `threading.Thread` spawned from the request handler**
  (`webvulnscanner/scan_routes.py`'s `_spawn_scan_thread()`), a daemon thread that keeps running
  after the HTTP response returns. A serverless function is frozen or torn down once it returns
  a response — the thread would be killed mid-scan, and a base/advanced/media/api scan routinely
  makes 30+ outbound HTTP requests (`webvulnscanner/checks.py`) that take well past any
  request's lifetime.
- **The live SSE feed (`scan_events()` in `scan_routes.py`) is an indefinite polling loop** —
  it `sleep(0.5)`s and re-queries the DB in a `while` loop until the scan reaches
  `COMPLETED`/`FAILED`, with no upper bound tied to a single scan's duration. Vercel functions
  have hard execution-time caps (10s/60s/300s depending on plan) far shorter than a real
  active/advanced/media/api scan.
- **Reports and media downloads are written to local disk**
  (`scan_engine.py`'s `save_report()` → `reports/`, `checks.py`'s media-download path →
  `downloads/`). Vercel's filesystem is read-only outside an ephemeral `/tmp` that doesn't
  persist across invocations — nothing written there survives past the request.
- **Flask-Limiter's rate limiting uses in-memory storage** (`webvulnscanner/extensions.py`) —
  already documented as a single-process limitation; on serverless, every invocation is
  effectively a fresh process, so counters wouldn't be shared at all without an external store.

None of this is a small tweak — it's the difference between "a request handler that does the
work inline" and "a request handler that hands work to something durable." Vercel is a good fit
for the first half of this app (auth, billing, dashboards, report rendering) and a bad fit for
the second half (actually running a scan) unless that half moves somewhere with a persistent
process.

## What runs on Vercel as-is

Every synchronous request/response route with no long-lived state:

- Auth (`auth_routes.py`): signup, login, logout, email verification, password reset.
- Org admin (`org_routes.py`, `domain_verification.py`): member/invite management, domain
  verification instructions and status.
- Billing (`billing_routes.py`): invoice creation, and the manual
  `POST /billing/invoice/<id>/verify` route — this makes one outbound Polygonscan API call
  (`billing.py`'s `verify_invoice()`) and returns; comfortably within any serverless timeout.
- Dashboard, scan report, and scan compare rendering (`scan_routes.py`'s `scan_detail`,
  `scan_report`, `scan_compare` — all pure reads once a scan's data already exists in the DB).
- Static asset serving, `/healthz`.

## What cannot run on Vercel without a persistent worker

- Actually executing a scan (`run_scan`/`run_advanced_scan`/`run_media_scan`/`run_api_scan` in
  `scan_engine.py`) — needs to run somewhere that isn't torn down mid-request.
- The SSE progress feed as currently implemented — needs either a bounded-request redesign or
  to stay off serverless entirely.
- Local `reports/`/`downloads/` filesystem writes — needs to move to durable storage regardless
  of where the scan runs.

## Target architecture (design only — not built this pass)

```
                    ┌─────────────────────┐
   Browser  ───────▶│   Vercel (web/API)   │  Flask via WSGI adapter
                    │  auth/org/billing/    │  (@vercel/python wrapping
                    │  dashboard/report      │   webvulnscanner.create_app())
                    │  enqueues scan jobs    │
                    └──────────┬─────────────┘
                               │ enqueue                 ▲ poll/short-poll
                               ▼                          │ for progress
                    ┌─────────────────────┐               │
                    │  Queue (Upstash      │───────────────┘
                    │  Redis + RQ, or a    │
                    │  managed queue)       │
                    └──────────┬─────────────┘
                               │ dequeue
                               ▼
                    ┌─────────────────────┐
                    │ Background worker     │  persistent process
                    │ (Render worker /       │  (Render, Railway, or a
                    │  Railway / small VM)   │   small always-on VM) —
                    │ runs run_*_scan()      │  same scan_engine.py code,
                    │  unchanged             │  unchanged
                    └──────────┬─────────────┘
                               │ writes results
                               ▼
                    ┌─────────────────────┐
                    │ Neon Postgres          │  Scan/Report/ScanEvent rows
                    └─────────────────────┘
                    ┌─────────────────────┐
                    │ Object storage         │  report JSON / media downloads
                    │ (Cloudflare R2 or       │  (replaces local reports/,
                    │  S3-compatible)         │  downloads/)
                    └─────────────────────┘
```

- **Web/API → Vercel.** Flask app wrapped for `@vercel/python`'s WSGI entrypoint. Its only job
  regarding scans becomes "validate the request, enqueue a job, return" — not "spawn a thread
  and block."
- **Database → Neon Postgres**, already prepped (`config.py`'s `pool_pre_ping`/`pool_recycle`
  added after a real "server closed the connection unexpectedly" incident — see
  `handoff.md`). For many short-lived serverless invocations, prefer Neon's own
  pgbouncer-compatible pooled connection string over SQLAlchemy's own connection pool, which
  would otherwise get re-created on every cold start.
- **Background scan workers → a persistent process outside Vercel** (a Render worker service,
  Railway, or a small always-on VM) that dequeues jobs and calls the existing
  `run_*_scan()` functions in `scan_engine.py` completely unchanged — the check functions in
  `checks.py` don't need to know or care where they're executed.
- **Queue → Upstash Redis + RQ (or a managed queue of your choice)**, sitting between the web
  layer (enqueues) and the worker (dequeues) — this is the piece that replaces the direct
  `threading.Thread(...).start()` call.
- **Live progress → short-poll instead of indefinite SSE.** The existing
  `_serialize_new_events(scan_id, after_id)` helper in `scan_routes.py` already does exactly
  "give me events since cursor" and is reusable as-is behind a fast, bounded serverless
  endpoint the client polls every second or two, instead of holding one connection open for the
  scan's full duration. (Alternative: keep true SSE, but serve it from the worker/non-serverless
  side rather than from a Vercel function.)
- **Report/media storage → object storage.** `save_report()`'s JSON writes and the media-scan's
  downloaded files need to move off local disk to Cloudflare R2 or another S3-compatible bucket
  (this was already on the infra backlog per `handoff.md` item, independent of this migration).
  A DB-column JSON blob is also viable for reports specifically, given `Report` already has one
  row per scan.
- **Rate limiting → Upstash Redis** (or the same Redis instance as the queue) instead of
  Flask-Limiter's in-memory store — no longer optional once there's more than one process
  involved.
- **Email/AI/billing verification → unchanged.** Resend, Groq, and Polygonscan are already
  simple outbound HTTP calls from a request handler; all fine to run directly on Vercel.

## What's shipped in this pass

- This document.
- `vercel.json` (repo root) + `api/index.py` — routes the web/API layer only, to the existing
  Flask app via a WSGI entrypoint (`create_app()` unchanged). No `/static/*` route was added
  because the app currently has no `static/` folder at all — CSS is inline in templates, fonts
  load from Google Fonts' CDN, and the favicon is a `data:` URI. Does not touch scan execution,
  queueing, or storage.
- `docs/env-vars.md` — full environment variable reference for both the current
  Render/gunicorn deployment and the target Vercel deployment, including the variables the
  target architecture above would need but that are not wired into the code yet (queue/Redis
  URL, object storage credentials) marked clearly as "future."
- **Not shipped**: queue integration code, the worker service itself, or the storage migration.
  Building those is a separate, follow-up project — attempting to fake it here (e.g. quietly
  keeping `threading.Thread` and hoping it works on Vercel) would produce something that looks
  deployed but silently drops every scan past the function timeout. `flask run` and the existing
  Render/gunicorn deployment path are both unaffected by anything in this pass.
