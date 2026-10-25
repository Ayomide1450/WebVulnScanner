# API Exposure Scan + Media Stream Discovery — Design

Status: Approved, ready for planning
Date: 2026-08-05

## Context

Glassbox is a local, single-user Flask app with three independent, non-destructive
scan pipelines (`/scan`, `/scan-advanced`, `/scan-media` — see `CLAUDE.md`). This spec adds
a fourth pipeline (API exposure) and strengthens the existing media pipeline (video/HLS/DASH
stream discovery). Both follow the codebase's existing conventions: every check function
returns `(data, findings)`, `Finding` objects drive a severity-weighted 0–100 score, requests
are `GET`-only (with one narrow, read-only exception noted below), and nothing is destructive.

This spec deliberately excludes the much larger feature roadmap discussed alongside it
(TLS depth, DNS depth, infrastructure fingerprinting, JS hardening, reporting overhaul,
engineering-platform work — plugin system, SARIF, structured logging, etc.). That work is
out of scope here and will be broken into its own specs later; see "Explicitly out of scope"
below for why, and keep this spec's diff focused on the two features described.

## Feature 1: API Exposure Scan (new pipeline)

### Goal

Scan a target for exposed API surface — schema/doc leaks, unauthenticated common API paths,
and endpoints the site's own frontend code actually calls — so a developer can lock down what
shouldn't be public before an attacker finds it.

### Route / orchestrator / template

- `POST /scan-api`, gated by a server-enforced `authorized_api` checkbox (same pattern as the
  other three routes).
- `run_api_scan(base_url)` orchestrator, following the same scoring formula (start at 100,
  subtract `SEVERITY_WEIGHT[finding.severity]` per finding, clamp to `[0, 100]`, map to an
  `A`–`F` grade) duplicated in the other three orchestrators — kept duplicated here too, for
  consistency with existing style, not extracted into a shared function.
- New template `templates/api_results.html`, modeled on `advanced_results.html` /
  `media_results.html`.
- Report saved to `reports/api_<hostname>_<timestamp>.json` (already gitignored).

### Checks

**`check_api_schema_exposure(base_url, session)`**
Probes a fixed list of common schema/doc paths: `/swagger.json`, `/swagger.yaml`,
`/openapi.json`, `/openapi.yaml`, `/api-docs`, `/v2/api-docs`, `/v3/api-docs`, `/graphiql`,
`/api/swagger.json`. Also sends one read-only GraphQL introspection query
(`{"query": "{__schema{types{name}}}"}`) as a `POST` to common GraphQL paths (`/graphql`,
`/api/graphql`, `/v1/graphql`) — this is the one non-`GET` request in the feature; it is
read-only metadata, not a mutation. A `200` with recognizable schema content (JSON containing
`"paths"`/`"openapi"`/`"swagger"` keys, or a GraphQL response containing `"__schema"`/`"types"`)
is a `high` finding: a fully exposed schema hands an attacker the whole API surface, including
routes never linked anywhere.

**`check_api_wordlist(base_url, session)`**
Threaded probe (same `ThreadPoolExecutor` pattern as `check_sensitive_paths`) over a small
built-in wordlist of common REST-ish paths (`api/admin`, `api/internal`, `api/users`,
`api/config`, `api/orders`, `api/auth`, `api/debug`, `api/backup`, `api/token`, etc.).

SPA false-positive guard: a hit only counts if the response is `200` **and** looks like actual
API output — `Content-Type` is JSON/XML, or the body starts with `{`/`[` after stripping
whitespace. Without this guard, any SPA that serves its `index.html` for every path would
falsely flag every wordlist entry.

Severity: `high` if the path contains a sensitive hint (`admin`, `internal`, `config`, `debug`,
`backup`, `token`, `secret`, `payment`, `key`), otherwise `info` (surfaced for manual review —
a public JSON endpoint is not inherently a bug).

**`check_api_js_discovery(session, base_url, home_html)`**
Reuses a new shared helper, `_fetch_same_origin_js(session, base_url, home_html,
max_files=MAX_SECRET_JS_FILES, max_bytes=MAX_JS_BYTES_PER_FILE)`, extracted from the existing
`check_exposed_secrets` (which currently inlines this same "collect same-origin `<script src>`
URLs, fetch up to N files capped at M bytes each" logic). `check_exposed_secrets` is updated to
call the shared helper instead of duplicating it.

Over the homepage HTML plus fetched JS text, regex-extracts API-looking paths from:
- `fetch(["'...'"])`
- `axios.<get|post|put|delete>(["'...'"])`
- `.ajax({... url: ["'...'"] ...})`
- generic string literals matching `/api/[\w\-/]+` or `/graphql`

Resolves each against `base_url`, dedupes, caps at ~30 candidates, then probes each with the
same request + SPA-guard logic as `check_api_wordlist`. This is the highest-signal check — it
finds endpoints the app actually calls rather than ones a wordlist happens to guess. Severity
follows the same sensitive-hint-vs-info split as the wordlist check.

### UI

Fourth section on `index.html`: target field + `authorized_api` checkbox + submit to
`/scan-api`, same visual pattern as the Media and Advanced sections.

## Feature 2: Media scan — HLS/DASH stream discovery

### Goal

The existing media crawl (`crawl_media` / `_extract_media_urls`) finds images, `<video>`
elements, and third-party video embeds, but misses adaptive-streaming manifests, which are
often built up in JS rather than placed in a `<video src>`. Add discovery for those.

### Changes

- New extraction function `_extract_stream_urls(base_url, text)`: regex-scans for `.m3u8`
  (HLS) and `.mpd` (DASH) URLs inside quoted strings, resolved via `urljoin`.
- `crawl_media` is extended to also fetch same-origin JS for each crawled page (reusing the
  same `_fetch_same_origin_js` helper introduced in Feature 1) and run
  `_extract_stream_urls` over both page HTML and fetched JS text, in addition to the existing
  `_extract_media_urls` pass. Discovered URLs accumulate into a new `stream_urls` set, kept
  separate from `media_urls`/`embeds`.
- **Verification before reporting**: each candidate stream URL gets a `GET` and is only kept
  if the body actually looks like a manifest — starts with `#EXTM3U` (HLS) or contains `<MPD`
  (DASH). This avoids false positives from a URL that merely appears in a JS comment/string
  literal but never resolves to a real manifest.
- Verified streams become media items with `kind: "stream"`, added to the same `media_items`
  list `check_media` already returns (a `kind` column distinguishes them in the results table —
  no separate report section, to avoid UI sprawl).
- Findings: streams get a finding only when the existing `MEDIA_PATH_HINTS` suspicious-path
  check trips (e.g. `/private/stream.m3u8`) — identical rule to how images/videos are already
  handled. Mere discovery of a normal public stream is not itself a finding.
- Streams are excluded from EXIF extraction and from download-to-disk (`want_exif`/
  `want_download` stay gated on `item["kind"] in ("image", "video")`, unaffected by this
  change) — manifests aren't a single downloadable file the way an image/video URL is.

### UI

`media_results.html`'s existing media table gains stream rows via the `kind` column; no new
template section.

## Shared refactor

`_fetch_same_origin_js(session, base_url, home_html, max_files, max_bytes)` — extracted from
`check_exposed_secrets`'s existing inline logic, used by three call sites after this change:
`check_exposed_secrets` (existing behavior, unchanged), `check_api_js_discovery` (Feature 1),
and `crawl_media` (Feature 2). Each call site passes its own `max_files`/`max_bytes` caps.

## Error handling

Every new network call follows the existing pattern: wrapped in
`try/except requests.RequestException`, never raises past its own function, and a failed probe
just yields no finding for that item rather than aborting the scan. Same `REQUEST_TIMEOUT` /
`UA` constants as the rest of the app.

## Testing

No automated test suite exists in this repo (confirmed in `CLAUDE.md`); verification will be
manual, per the project's existing practice — running the new scans against a real authorized
target and checking the reports/HTML render correctly.

## Explicitly out of scope

The larger roadmap discussed in the same conversation — TLS cipher/protocol/OCSP/forward-secrecy
depth, DNSSEC/DKIM/MX/reverse-DNS, CDN/WAF/hosting/framework/CMS fingerprinting, JS
source-map/`eval()` hardening, a reporting overhaul (CWE/OWASP mapping, executive summary,
SARIF/Markdown/HTML export), and engineering-platform work (plugin system, configurable
concurrency/rate-limiting, retry+backoff, structured logging, automated tests, cross-platform
docs) — is intentionally excluded from this spec. It's independent, multi-subsystem work that
needs its own brainstorming pass(es) rather than being bolted onto this one. Tackle it as
follow-up specs, prioritized separately.

Also note: the roadmap request used the word "destructive" to describe the tool's overall
goal, which contradicts every explicit requirement in the same request (non-destructive, safe,
low-impact testing) and the existing codebase's safety constraints. This spec — and the
features it describes — remain strictly non-destructive, consistent with `CLAUDE.md`.
