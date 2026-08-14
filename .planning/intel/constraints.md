# Constraints

Extracted from `SPEC`-classified documents. Every entry below is verbatim/paraphrased from its
source; no field is inferred beyond what the source states.

## API exposure scan — GET-only except one narrow read-only POST
- source: docs/superpowers/specs/2026-08-05-api-exposure-and-media-streaming-design.md
- type: protocol
- content: All new requests are `GET`-only, with exactly one exception: a read-only GraphQL
  introspection query (`{"query": "{__schema{types{name}}}"}`) sent as `POST` to common GraphQL
  paths (`/graphql`, `/api/graphql`, `/v1/graphql`) — explicitly noted as metadata, not a
  mutation. No destructive requests anywhere in the feature.

## check_api_schema_exposure — endpoint contract
- source: docs/superpowers/specs/2026-08-05-api-exposure-and-media-streaming-design.md
- type: api-contract
- content: Probes a fixed list of schema/doc paths (`swagger.json`, `swagger.yaml`,
  `openapi.json`, `openapi.yaml`, `api-docs`, `v2/api-docs`, `v3/api-docs`, `graphiql`,
  `api/swagger.json`). A `200` with recognizable schema content (`"paths"`/`"openapi"`/
  `"swagger"` keys, or GraphQL response containing `"__schema"`/`"types"`) is a `high` finding.

## check_api_wordlist — SPA false-positive guard
- source: docs/superpowers/specs/2026-08-05-api-exposure-and-media-streaming-design.md
- type: nfr
- content: A wordlist hit only counts if the response is `200` AND looks like real API output
  (`Content-Type` JSON/XML, or body starts with `{`/`[` after stripping whitespace). Without this
  guard, SPAs that serve `index.html` for every path would falsely flag every wordlist entry.
  Severity: `high` if the path contains a sensitive hint (`admin`, `internal`, `config`, `debug`,
  `backup`, `token`, `secret`, `payment`, `key`), otherwise `info`.

## check_api_js_discovery — endpoint contract
- source: docs/superpowers/specs/2026-08-05-api-exposure-and-media-streaming-design.md
- type: api-contract
- content: Reuses `_fetch_same_origin_js(session, base_url, home_html, max_files, max_bytes)`
  extracted from `check_exposed_secrets`. Regex-extracts API-looking paths from
  `fetch(...)`/`axios.<verb>(...)`/`.ajax({...url:...})` calls and generic `/api/...`|`/graphql`
  string literals; resolves against `base_url`, dedupes, caps at ~30 candidates, then probes with
  the same request + SPA-guard logic as `check_api_wordlist`.

## HLS/DASH stream manifest verification requirement
- source: docs/superpowers/specs/2026-08-05-api-exposure-and-media-streaming-design.md
- type: nfr
- content: Each candidate stream URL (`.m3u8`/`.mpd` extracted from page HTML + same-origin JS)
  must be `GET`-verified and only kept if the body actually looks like a manifest — starts with
  `#EXTM3U` (HLS) or contains `<MPD` (DASH) — to avoid false positives from a URL that merely
  appears in a JS string/comment but never resolves to a real manifest. Streams are excluded from
  EXIF extraction and download-to-disk.

## Error handling — non-destructive network calls
- source: docs/superpowers/specs/2026-08-05-api-exposure-and-media-streaming-design.md
- type: nfr
- content: Every new network call is wrapped in `try/except requests.RequestException`, never
  raises past its own function, and a failed probe yields no finding for that item rather than
  aborting the scan. Same `REQUEST_TIMEOUT`/`UA` constants as the rest of the app.

## No automated test suite (this spec's explicit choice)
- source: docs/superpowers/specs/2026-08-05-api-exposure-and-media-streaming-design.md
- type: nfr
- content: No automated test suite exists in this repo (confirmed in `CLAUDE.md`); verification is
  manual — running the new scans against a real authorized target and checking reports/HTML.

## Scope boundary — explicitly out of scope
- source: docs/superpowers/specs/2026-08-05-api-exposure-and-media-streaming-design.md
- type: nfr
- content: TLS depth, DNS depth, infrastructure fingerprinting, JS hardening, reporting overhaul,
  and engineering-platform work (plugin system, SARIF, structured logging, etc.) are explicitly
  out of scope for this spec — to be broken into separate specs later. The tool remains strictly
  non-destructive per `CLAUDE.md`, contradicting an earlier "destructive" characterization
  mentioned elsewhere in the same conversation (spec explicitly rejects that framing).

## Non-SQLite connection reliability — pool_pre_ping/pool_recycle
- source: docs/superpowers/specs/2026-08-07-page-completion-and-polish-design.md
- type: nfr
- content: `SQLALCHEMY_ENGINE_OPTIONS` currently only sets anything for SQLite
  (`check_same_thread`). For non-SQLite (Postgres/Neon), add `pool_pre_ping=True` and
  `pool_recycle=280` (seconds, under Neon's typical idle timeout) so a dropped idle connection
  (confirmed live: `psycopg2.OperationalError: server closed the connection unexpectedly`)
  transparently reconnects instead of surfacing as a 500.

## No changes to entitlements/checks/SSRF/auth
- source: docs/superpowers/specs/2026-08-07-page-completion-and-polish-design.md
- type: nfr
- content: Explicit non-goal: no change to `entitlements.py`, `checks.py`,
  `checks.is_ssrf_safe_hostname()`, or any `_check_ownership` call site. This pass is
  presentation-layer plus the one connection-pooling config line.

## Reuse existing design-system components only
- source: docs/superpowers/specs/2026-08-07-page-completion-and-polish-design.md
- type: nfr
- content: All visual work extends the existing design system in `templates/base.html`
  (`.card`/`.btn`/`.pill`/`.badge`/`.finding`/`.warn-box`/`.glow-pulse`/`.hud-grid`) rather than
  introducing a new visual language, per `CLAUDE.md`'s explicit instruction. Never use emoji as
  icons — inline SVG only.

## Deployment target — Render, not Vercel
- source: docs/superpowers/specs/2026-08-07-page-completion-and-polish-design.md
- type: nfr
- content: No migration to Vercel. This repo already targets Render (`render.yaml`, `Procfile`,
  `/healthz`); the app's architecture (background-thread scans, SSE live feed) doesn't fit
  Vercel's serverless model without a real re-architecture.

## No account creation for external services
- source: docs/superpowers/specs/2026-08-07-page-completion-and-polish-design.md
- type: nfr
- content: Render/Neon/Resend/UptimeRobot signups remain something only the user can do — a
  plain-language deploy checklist is provided as reference only, not executed by the assistant.

## /terms and /privacy routes — no auth required
- source: docs/superpowers/specs/2026-08-07-page-completion-and-polish-design.md
- type: api-contract
- content: `templates/terms.html` and `templates/privacy.html` routed via `public_routes.py` as
  `/terms` and `/privacy`, no auth required. Each opens with a visible "Draft — not reviewed by
  counsel; do not rely on this without legal review" notice.

## Keep-alive heartbeat protocol
- source: docs/superpowers/specs/2026-08-07-page-completion-and-polish-design.md
- type: protocol
- content: Client-side script in `base.html`, loaded on every page, fires `fetch('/healthz')`
  every few minutes (implementation plan specifies 4 minutes) while a tab is open and visible.
  Explicitly scoped as a partial mitigation (only helps during active browsing sessions), not a
  substitute for an external uptime monitor.
