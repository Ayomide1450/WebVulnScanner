# Page completion & visual polish pass — design

Date: 2026-08-07
Branch: `saas-conversion-and-redesign`

## Context

Live click-through of the running app (signup → login → dashboard → billing → org admin →
new-scan forms → a real scan against `example.com` → live progress → report → 404) surfaced a
mix of genuine render bugs, unfinished-but-functional pages already flagged in `handoff.md` as
deferred redesign work, and two missing pages. This spec covers all of it as one pass, plus a
small reliability fix and a keep-alive heartbeat, per the user's direction to do it in one pass
and keep everything on the existing Render deploy target (not Vercel — see "Non-goals").

All visual work **extends the existing design system** in `templates/base.html` (CSS custom
properties, `.card`/`.btn`/`.pill`/`.badge`/`.finding`/`.warn-box`/`.glow-pulse`/`.hud-grid`, the
telemetry-blue "operator console" motion language already shipped on `scan_progress.html`) rather
than introducing a new visual language, per CLAUDE.md's explicit instruction to reuse these
components.

## Goals

1. Fix the three confirmed render/reliability bugs.
2. Fill the two missing pages (Terms of Service, Privacy Policy) and add the footer that links
   to them (no footer exists today).
3. Bring the remaining bland-but-functional pages up to the same visual standard as the
   scan-progress redesign, without changing their underlying data/behavior.
4. Add a code-only keep-alive heartbeat.
5. Leave a clear, human-actionable Render deployment checklist (account creation itself is
   off-limits for the assistant).

## 1. Bug fixes

- **`webvulnscanner/config.py`** — `SQLALCHEMY_ENGINE_OPTIONS` currently only sets anything for
  SQLite (`check_same_thread`). For non-SQLite (Postgres/Neon) it's `{}`, so a dropped idle
  connection (confirmed live: `psycopg2.OperationalError: server closed the connection
  unexpectedly`) surfaces as a hard 500 instead of transparently reconnecting. Add
  `pool_pre_ping=True` and a conservative `pool_recycle` (e.g. 280s, under Neon's typical idle
  timeout) to the non-SQLite branch.
- **`templates/marketing.html`** — the boot-animation JS currently blanks `heroHeadline` and adds
  `fade-pending` (opacity:0) to the sub/CTA row until the ~6s terminal-boot sequence finishes.
  Change: stop hiding the real hero content. The terminal box still types its boot lines as a
  decorative element, but the headline/sub/CTA render immediately and stay visible throughout —
  removes the "page looks empty on load" problem. No-JS/reduced-motion behavior (already just the
  static final render) is unaffected.
- **`templates/dashboard.html`** — the risk-trend sparkline's single-point case (`n == 1`, the
  common state for a new account) renders one `<circle>` with no `<polyline>` (SVG polylines need
  ≥2 points), i.e. an unlabeled floating dot. Fix: when there's exactly one scored scan, draw a
  flat reference line across the card width at that y-position (duplicate the point at x=0 and
  x=sw) and add a text label showing the score next to the dot, so it reads as "your one data
  point" instead of a glitch.

## 2. New pages

- **`templates/terms.html`**, **`templates/privacy.html`** — draft, app-specific content covering
  what this app actually collects/does: account/org data, domain-verification records, scan
  target URLs and findings, crypto invoice records (wallet address, tx hash), AI-summary calls to
  Groq (finding text leaves the server as part of the prompt). Each page opens with a visible
  "Draft — not reviewed by counsel; do not rely on this without legal review" notice. Routed via
  `public_routes.py` as `/terms` and `/privacy`, no auth required.
- **Footer partial** — new small footer block in `base.html` (`© {{ current year }} WebVulnScanner
  · Terms · Privacy`), styled with existing tokens, present on every page.

## 3. Visual polish (existing pages, no behavior change)

Each of these keeps its current routes/data/logic — this is template/CSS-only:

- **`dashboard.html`** — card treatment for the latest-scan gauge and the "Your scans" table
  consistent with the operator-console language; sparkline fix from §1 included here.
- **`billing.html`** — the crypto invoice flow gets a real payment card: amount, chain/asset,
  wallet address with a copy-to-clipboard button, and a pending-invoice status treatment —
  replacing the current plain `<code>` table cell.
- **`org_admin.html`** — members table and invite form get the same card treatment as dashboard.
- **`scan_report.html`** / **`scan_compare.html`** — spacing/hierarchy refinement of the findings
  accordion and comparison view (both already functionally solid from the live check).
- **`scan_new_base/advanced/media/api.html`** — consistency pass over the shared
  `_scan_form_styles.html` partial so all four read as one family.

## 4. Keep-alive heartbeat (code-only, no external accounts)

Add a small client-side script (in `base.html`, loaded on every page) that fires a `fetch('/healthz')`
every few minutes while a tab is open, keeping a Render free-tier instance warm during active
browsing sessions. Explicitly scoped as a mitigation, not a full solution — it only helps while
someone has the site open in a tab. Noted below (§6) as a followup if 24/7 uptime is wanted.

## 5. Testing / verification

- Re-run the full click-through (signup → login → dashboard → billing → org admin → new scan →
  live progress → report → 404) via claude-in-chrome after the pages are touched, at desktop and
  mobile widths.
- `pytest` after the `config.py` change and generally before calling this done.
- Add a couple of new tests: `/terms` and `/privacy` return 200 without auth; dashboard sparkline
  single-point case (`n == 1`) renders without error (regression test for the fix in §1, mirrors
  the "no fabricated event" discipline already used elsewhere in this codebase).

## Non-goals / explicitly out of scope

- **No migration to Vercel.** This repo already targets Render (`render.yaml`, `Procfile`,
  `/healthz`) and the app's architecture (background-thread scans, SSE live feed) doesn't fit
  Vercel's serverless model without a real re-architecture. Not attempted here.
- **No account creation.** Render/Neon/Resend/UptimeRobot signups remain something only the user
  can do — a plain-language checklist for the Render deploy is provided as a followup, not
  executed.
- **No change to `entitlements.py`, `checks.py`, the SSRF guard, or any ownership/auth check.**
  This pass is presentation-layer plus the one connection-pooling config line in §1.
- **External uptime monitor (UptimeRobot etc.) is not set up** — the user chose the code-only
  heartbeat instead; §4 states its real, limited scope so this isn't mistaken for full coverage.

## 6. Deploy checklist (for the user to execute — reference only)

Already true today, unchanged by this spec (see `handoff.md`): create a Render account, connect
this repo, deploy via the `render.yaml` Blueprint, set `SECRET_KEY`/`GROQ_API_KEY` in Render's
Environment tab; create a Neon Postgres project and set its connection string as
`SQLALCHEMY_DATABASE_URI`; optionally set up Resend for real email. Once deployed, pointing an
external uptime monitor at `/healthz` remains the only way to get true 24/7 keep-alive on a
free-tier host — the client-side heartbeat in §4 is a partial mitigation, not a replacement.
