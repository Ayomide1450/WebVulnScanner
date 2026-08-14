# Page Completion & Visual Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three confirmed render/reliability bugs, add the two missing legal pages plus a
site-wide footer, bring the remaining bland-but-functional pages up to the existing design
system's visual standard, and add a code-only keep-alive heartbeat — with zero changes to
`entitlements.py`, `checks.py`, the SSRF guard, or any ownership/auth check.

**Architecture:** Template/CSS/JS-only changes plus one backend config line
(`SQLALCHEMY_ENGINE_OPTIONS`). No new routes beyond `/terms` and `/privacy`, no schema changes,
no new dependencies. Every visual change reuses existing `base.html` tokens/components
(`.card`, `.pill`, `.warn-box`, `.glow-pulse`, `.hud-grid`) rather than inventing new ones.

**Tech Stack:** Flask/Jinja2, vanilla CSS (custom properties already defined in `base.html`),
vanilla JS (no framework, matches the rest of the codebase), pytest + Flask test client.

## Global Constraints

- Reuse existing design-system components (`.card`/`.btn`/`.pill`/`.badge`/`.finding`/
  `.warn-box`/`.glow-pulse`/`.hud-grid`) rather than hardcoding new colors or component styles —
  per `CLAUDE.md`'s explicit instruction.
- Never use emoji as icons — inline SVG only (reuse `base.html`'s icon sprite where an icon is
  needed).
- No changes to `entitlements.py`, `checks.py`, `checks.is_ssrf_safe_hostname()`, or any
  `_check_ownership` call site.
- `.env`/`.env.example` are sandbox-blocked from Read/Bash in this environment — do not attempt
  to read or write them; new env vars (there are none in this plan) would need documenting in
  README.md/CLAUDE.md instead.
- Terms/Privacy content is a clearly-marked draft ("not reviewed by counsel") — never present it
  as final legal advice.
- Run the full `pytest` suite before considering any task's tests "passing" in isolation — this
  codebase's `Limiter` is a process-wide singleton (see `extensions.py`), so cross-test
  interference is a real risk category here, not theoretical.

---

## File Structure

| File | Change |
|---|---|
| `webvulnscanner/config.py` | Modify — extract `_engine_options_for()`, add `pool_pre_ping`/`pool_recycle` for non-SQLite |
| `tests/test_config.py` | Create — Task 1 tests |
| `templates/marketing.html` | Modify — stop hiding hero content behind the boot animation |
| `templates/dashboard.html` | Modify — sparkline single-point fix (Task 3) + status pills (Task 5) |
| `tests/test_scan_routes.py` | Create — Task 3 + Task 5 tests |
| `webvulnscanner/public_routes.py` | Modify — add `/terms`, `/privacy` routes |
| `templates/terms.html` | Create |
| `templates/privacy.html` | Create |
| `templates/base.html` | Modify — footer (Task 4) + keep-alive heartbeat script (Task 10) |
| `webvulnscanner/__init__.py` | Modify — inject `current_year` into template context |
| `tests/test_public_routes.py` | Modify — add Task 4 tests |
| `templates/billing.html` | Modify — crypto invoice payment card (Task 6) |
| `tests/test_billing_routes.py` | Create — Task 6 tests |
| `templates/org_admin.html` | Modify — pill badges + row hover (Task 7) |
| `tests/test_org_routes.py` | Create — Task 7 tests |
| `templates/scan_report.html` | Modify — hover/spacing refinement (Task 8) |
| `templates/scan_compare.html` | Modify — hover refinement (Task 8) |
| `templates/_scan_form_styles.html` | Modify — input focus state + card hover (Task 9) |

---

## Task 1: Fix Postgres connection reliability (`pool_pre_ping`)

**Files:**
- Modify: `webvulnscanner/config.py:79-86`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `webvulnscanner.config._engine_options_for(db_uri: str) -> dict` — pure function, no
  Flask/app context needed. Later tasks don't depend on this.

- [ ] **Step 1: Write the failing test**

Create `tests/test_config.py`:

```python
"""Tests for webvulnscanner/config.py's engine-options branching.

_engine_options_for() is a pure function specifically so these can run
without reloading the config module or spinning up a Flask app - config.py
computes SQLALCHEMY_ENGINE_OPTIONS once at class-body/import time, so
testing the branches directly (rather than via importlib.reload gymnastics)
is both simpler and doesn't risk leaking state into other tests' already-
imported Config subclasses.
"""
from webvulnscanner.config import _engine_options_for


def test_sqlite_engine_options_keep_check_same_thread_false():
    assert _engine_options_for("sqlite:///whatever.db") == {
        "connect_args": {"check_same_thread": False},
    }


def test_postgres_engine_options_add_pool_pre_ping_and_recycle():
    # Confirmed live: a dropped idle Neon/Postgres connection surfaces as a
    # hard psycopg2.OperationalError ("server closed the connection
    # unexpectedly") without this - pool_pre_ping issues a cheap SELECT 1
    # before handing a pooled connection back out and transparently
    # reconnects if it's dead.
    assert _engine_options_for("postgresql://user:pass@host/db") == {
        "pool_pre_ping": True,
        "pool_recycle": 280,
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_config.py -v`
Expected: FAIL — `ImportError: cannot import name '_engine_options_for'`

- [ ] **Step 3: Write minimal implementation**

This is a two-part edit to `webvulnscanner/config.py`:

**3a.** Insert a new **module-level function** directly above the existing `class Config:` line
(line 51 — i.e. right after the `_secret_key`/`RuntimeError` block and before `class Config:`):

```python
def _engine_options_for(db_uri):
    """Pure function (no app/class-body coupling) so tests can exercise both
    branches directly - see tests/test_config.py.

    check_same_thread only means anything to SQLite (scans run in a
    background thread that writes to the same connection pool as the
    request thread) - Postgres connections are already safe to share across
    threads via the pool, and passing this connect_arg to psycopg2 would be
    a TypeError, not a no-op.

    pool_pre_ping/pool_recycle only matter for a real network DB (Postgres/
    Neon): a managed Postgres provider can silently close an idle connection
    server-side (confirmed live: psycopg2.OperationalError "server closed
    the connection unexpectedly") - pool_pre_ping issues a cheap SELECT 1
    before handing a pooled connection back out and transparently
    reconnects if it's dead, and pool_recycle (280s, comfortably under
    Neon's typical idle timeout) forces a connection to be replaced before
    it gets that stale in the first place. Neither means anything for
    SQLite's single local file.
    """
    if db_uri.startswith("sqlite"):
        return {"connect_args": {"check_same_thread": False}}
    return {"pool_pre_ping": True, "pool_recycle": 280}


class Config:
```

**3b.** Inside the class body, replace the existing comment + ternary (originally lines 79-86):

```python
    # check_same_thread only means anything to SQLite (scans run in a
    # background thread that writes to the same connection pool as the
    # request thread) - Postgres connections are already safe to share
    # across threads via the pool, and passing this connect_arg to
    # psycopg2 would be a TypeError, not a no-op.
    SQLALCHEMY_ENGINE_OPTIONS = (
        {"connect_args": {"check_same_thread": False}} if _db_uri.startswith("sqlite") else {}
    )
```

with:

```python
    SQLALCHEMY_ENGINE_OPTIONS = _engine_options_for(_db_uri)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_config.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Run the full suite to confirm no regression**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all tests still pass (this touches app boot config, low risk but worth confirming since
every other test's `app` fixture goes through `Config`/`TestConfig`).

- [ ] **Step 6: Commit**

```bash
git add webvulnscanner/config.py tests/test_config.py
git commit -m "fix: add pool_pre_ping/pool_recycle for non-SQLite DB connections

Fixes a live-reproduced psycopg2.OperationalError (\"server closed the
connection unexpectedly\") against Postgres/Neon - a dropped idle connection
now gets transparently replaced instead of surfacing as a 500.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 2: Fix marketing.html hiding hero content behind the boot animation

**Files:**
- Modify: `templates/marketing.html:9-32` (CSS) and `:68-151` (script)

**Interfaces:**
- None — self-contained template/JS change, no other task depends on this one.

- [ ] **Step 1: Remove the now-dead CSS rules**

In `templates/marketing.html`, in the `<style>` block, delete these two rules (they only existed
to support the hide/reveal choreography being removed):

```css
  .hero h1 .cursor { animation: blink 1s step-end infinite; }
```

and

```css
  .fade-pending { opacity: 0; }
```

Leave `.hero h1 { ... min-height: 1.2em; }` and the `transition: opacity 250ms ease;` on `.sub`/
`.cta-row` in place (harmless, and `.hero h1`'s `min-height` still prevents any layout shift from
the (now purely decorative) terminal box appearing/disappearing above it).

- [ ] **Step 2: Replace the boot-sequence script**

Replace the entire `<script>...</script>` block (lines 68-151) with:

```html
<script>
(function () {
  // Progressive enhancement only: the server-rendered headline/sub/CTA are
  // already the final, correct content, and now stay visible the ENTIRE
  // time - previously they were blanked/hidden (opacity:0) until the ~6s
  // terminal-boot sequence finished, which left the page looking empty on
  // load. The terminal box is now purely decorative, typing alongside the
  // real content instead of gating it.
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduceMotion) return;

  var terminalEl = document.getElementById('bootTerminal');
  var linesEl = document.getElementById('bootLines');
  if (!terminalEl || !linesEl) return;

  // Real check-registry lines, not invented "AI engine" theater - this is
  // representative of what checks.py's check_headers/check_tls_cert/
  // check_exposed_secrets/etc. and the domain-verification gate actually do.
  var bootLines = [
    'Initializing scan engine...',
    'Loading check registry...',
    'Discovering attack surface...',
    'Verifying domain ownership...',
    'Scanning headers, TLS, cookies...',
    'Probing exposed secrets & SRI...',
    'Compiling risk report...',
    'Done.'
  ];

  terminalEl.classList.add('active');

  function typeLine(text, cb) {
    var i = 0;
    var current = linesEl.textContent;
    (function step() {
      linesEl.textContent = current + text.slice(0, i);
      if (i < text.length) {
        i++;
        setTimeout(step, 14);
      } else {
        linesEl.textContent = current + text + '\n';
        setTimeout(cb, 180);
      }
    })();
  }

  function runBoot(index) {
    if (index >= bootLines.length) {
      // Leave "Done." visible briefly, then fade the terminal box out -
      // the real hero content next to it never moved.
      setTimeout(function () { terminalEl.classList.remove('active'); }, 1200);
      return;
    }
    typeLine(bootLines[index], function () { runBoot(index + 1); });
  }

  runBoot(0);
})();
</script>
```

- [ ] **Step 3: Manual verification (no automated test — pure client-side JS/CSS)**

Start the dev server (`.venv\Scripts\python app.py`) and, via claude-in-chrome:
1. Navigate to `http://127.0.0.1:5000/` and take a screenshot immediately (within ~1s).
2. Confirm the headline ("Your own automated security engineer."), subhead, and both CTA buttons
   ("Start free scan" / "Log in") are visible in that first screenshot — not just the terminal
   box.
3. Confirm the terminal box still types its boot lines and fades out after "Done." (cosmetic
   check, not required to block the task).

- [ ] **Step 4: Commit**

```bash
git add templates/marketing.html
git commit -m "fix: stop hiding marketing hero content behind boot animation

Headline/subhead/CTA now render immediately and stay visible; the terminal
boot sequence is purely decorative alongside them instead of gating the
page's real content behind ~6s of typing.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 3: Fix dashboard sparkline's single-scan case

**Files:**
- Modify: `templates/dashboard.html:56-83`
- Test: `tests/test_scan_routes.py` (new file)

**Interfaces:**
- Consumes: `tests/conftest.py`'s `make_org`, `make_user`, `make_scan`, `login` factories
  (already exist, signatures unchanged).
- Produces: nothing new consumed by later tasks (Task 5 edits the *same file* but a different
  block — do this task first so Task 5's line references are accurate).

- [ ] **Step 1: Write the failing test**

Create `tests/test_scan_routes.py`:

```python
"""Tests for webvulnscanner/scan_routes.py's dashboard() view."""
from tests.conftest import login, make_org, make_scan, make_user


def test_dashboard_single_scored_scan_renders_flat_reference_line(client, db):
    """Regression test for the single-point sparkline bug: with exactly one
    scored scan, the SVG used to render one bare <circle> with no
    <polyline> at all (SVG polylines need >=2 points) - an unlabeled
    floating dot. It should now render a flat 2-point reference line plus a
    text label."""
    org = make_org()
    user = make_user("solo@example.com", org=org)
    scan = make_scan(user, org=org)
    scan.risk_score = 42
    db.session.commit()

    login(client, "solo@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    sh = 70
    y = round(sh - (42 / 100 * sh), 1)
    assert f'<polyline points="0,{y} 560,{y}"' in body
    assert "only scan so far" in body


def test_dashboard_multiple_scored_scans_render_a_trend_polyline(client, db):
    org = make_org()
    user = make_user("trend@example.com", org=org)
    for score in (30, 70):
        s = make_scan(user, org=org)
        s.risk_score = score
    db.session.commit()

    login(client, "trend@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "only scan so far" not in body
    assert body.count("<circle cx=") >= 2


def test_dashboard_no_scored_scans_shows_not_enough_data_message(client, db):
    org = make_org()
    user = make_user("empty@example.com", org=org)
    make_scan(user, org=org)  # risk_score stays None (still queued)
    db.session.commit()

    login(client, "empty@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    assert "Not enough completed scans yet for a trend line." in resp.get_data(as_text=True)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_scan_routes.py -v`
Expected: FAIL on `test_dashboard_single_scored_scan_renders_flat_reference_line` — the current
template only ever emits one `<circle>` and a single-point (invalid) `<polyline>`, so the
`0,{y} 560,{y}` substring won't be found.

- [ ] **Step 3: Write minimal implementation**

In `templates/dashboard.html`, replace lines 56-83 (the entire "Risk score over time" `<h2>` +
`<div class="card sparkline-card">` block) with:

```html
  <h2 class="section">Risk score over time</h2>
  <div class="card sparkline-card">
    {% set scored = [] %}
    {% for s in scans %}
      {% if s.risk_score is not none %}{% set _ = scored.append(s) %}{% endif %}
    {% endfor %}
    {% set n = scored|length %}
    {% if n > 0 %}
    <p class="hint">{{ n }} completed scan(s) with a risk score, oldest to newest.</p>
    {% set sw = 560 %}{% set sh = 70 %}
    {% if n == 1 %}
      {% set only_y = (sh - (scored[0].risk_score / 100 * sh))|round(1) %}
      {% set pts = ['0,' + only_y|string, sw|string + ',' + only_y|string] %}
    {% else %}
      {% set pts = [] %}
      {% for s in scored|reverse %}
        {% set x = ((loop.index0 / (n - 1)) * sw)|round(1) %}
        {% set y = (sh - (s.risk_score / 100 * sh))|round(1) %}
        {% set _ = pts.append(x|string + ',' + y|string) %}
      {% endfor %}
    {% endif %}
    <svg width="100%" height="{{ sh + 10 }}" viewBox="0 0 {{ sw }} {{ sh + 10 }}" preserveAspectRatio="none" style="overflow:visible;">
      <polyline points="{{ pts|join(' ') }}" fill="none" stroke="var(--accent)" stroke-width="2"></polyline>
      {% if n == 1 %}
      <circle cx="{{ sw / 2 }}" cy="{{ only_y }}" r="3" fill="var(--accent2)"></circle>
      <text x="{{ (sw / 2) + 8 }}" y="{{ only_y - 8 }}" fill="var(--muted)" font-family="Fira Code, monospace" font-size="11">{{ scored[0].risk_score }} (only scan so far)</text>
      {% else %}
      {% for s in scored|reverse %}
        {% set x = ((loop.index0 / (n - 1)) * sw)|round(1) %}
        {% set y = (sh - (s.risk_score / 100 * sh))|round(1) %}
        <circle cx="{{ x }}" cy="{{ y }}" r="3" fill="var(--accent2)"></circle>
      {% endfor %}
      {% endif %}
    </svg>
    {% else %}
    <p class="hint" style="margin:0;">Not enough completed scans yet for a trend line.</p>
    {% endif %}
  </div>
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_scan_routes.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add templates/dashboard.html tests/test_scan_routes.py
git commit -m "fix: dashboard sparkline no longer renders a bare floating dot

With exactly one scored scan (the common state for a new account), draw a
labeled flat reference line instead of a single unlabeled <circle> with an
invalid one-point <polyline>.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 4: Add Terms of Service / Privacy Policy pages + site footer

**Files:**
- Modify: `webvulnscanner/public_routes.py`
- Create: `templates/terms.html`
- Create: `templates/privacy.html`
- Modify: `templates/base.html` (footer, near line 227 just before `{% block content %}`'s
  closing `</body>`)
- Modify: `webvulnscanner/__init__.py:55-58` (inject `current_year`)
- Modify: `tests/test_public_routes.py`

**Interfaces:**
- Produces: `url_for('public.terms')` → `/terms`, `url_for('public.privacy')` → `/privacy`,
  template context var `current_year` (int) available on every page.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_public_routes.py`:

```python


def test_terms_page_returns_200_without_auth(client):
    resp = client.get("/terms")
    assert resp.status_code == 200
    assert b"Terms of Service" in resp.data


def test_privacy_page_returns_200_without_auth(client):
    resp = client.get("/privacy")
    assert resp.status_code == 200
    assert b"Privacy Policy" in resp.data


def test_footer_links_to_terms_and_privacy(client):
    resp = client.get("/")
    body = resp.get_data(as_text=True)
    assert 'href="/terms"' in body
    assert 'href="/privacy"' in body
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_public_routes.py -v`
Expected: FAIL — `/terms`/`/privacy` 404, and no footer markup exists yet.

- [ ] **Step 3: Add the routes**

In `webvulnscanner/public_routes.py`, after the `index()` view (before `healthz()`), add:

```python
@public.route("/terms")
def terms():
    return render_template("terms.html")


@public.route("/privacy")
def privacy():
    return render_template("privacy.html")

```

- [ ] **Step 4: Create `templates/terms.html`**

```html
{% extends "base.html" %}
{% block title %}Terms of Service - WebVulnScanner{% endblock %}
{% block head %}
<style>
  .legal-wrap { max-width: 760px; margin: 0 auto; padding: 40px 22px 80px; }
  .legal-wrap h1 { margin-bottom: 4px; }
  .legal-wrap .updated { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
  .legal-wrap h2 { font-size: 17px; margin: 28px 0 8px; }
  .legal-wrap p, .legal-wrap li { color: var(--text); font-size: 14.5px; line-height: 1.65; }
  .legal-wrap ul { padding-left: 22px; margin: 8px 0; }
</style>
{% endblock %}
{% block content %}
<div class="legal-wrap">
  <h1>Terms of Service</h1>
  <p class="updated">Last updated {{ current_year }}</p>

  <div class="warn-box">
    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v4m0 4h.01M10.3 3.9 2.5 17a2 2 0 0 0 1.7 3h15.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>
    <div><b>Draft — not reviewed by counsel.</b> This is placeholder legal text describing what
    the product actually does. Do not rely on it without review by a qualified lawyer before
    using it in production.</div>
  </div>

  <h2>What this service is</h2>
  <p>WebVulnScanner lets an organization run security scans (passive recon through, for
  domain-verified orgs, active/intrusive checks) against domains that organization owns or has
  explicit authorization to test. You must own or be authorized to test any domain you submit —
  see the authorization checkbox on every scan form.</p>

  <h2>Your account</h2>
  <p>You're responsible for the accuracy of the information you provide at signup, for keeping
  your password confidential, and for all activity under your account. Organization admins are
  responsible for the members they invite and the scans run under their organization.</p>

  <h2>Acceptable use</h2>
  <ul>
    <li>Only submit domains you own or are explicitly authorized to test.</li>
    <li>Don't use this service to scan, probe, or attack infrastructure you don't control or
    lack permission to test.</li>
    <li>Don't attempt to circumvent the plan-tier or domain-verification gating that controls
    which checks a scan can run.</li>
  </ul>

  <h2>Billing</h2>
  <p>Paid plans are invoiced in USDT/USDC on the chain configured at checkout. Invoices expire
  after a fixed window if unpaid. Plan changes take effect once a payment is verified on-chain.</p>

  <h2>Disclaimer</h2>
  <p>Scan results are provided "as is," on a best-effort basis, and are not a guarantee that a
  target is free of vulnerabilities beyond what was actually checked. AI-assisted remediation
  summaries (where shown) are generated to help prioritize findings already produced by
  deterministic checks — they are not a substitute for professional security review.</p>

  <h2>Contact</h2>
  <p>Questions about these terms can be sent to the account owner for this deployment.</p>
</div>
{% endblock %}
```

- [ ] **Step 5: Create `templates/privacy.html`**

```html
{% extends "base.html" %}
{% block title %}Privacy Policy - WebVulnScanner{% endblock %}
{% block head %}
<style>
  .legal-wrap { max-width: 760px; margin: 0 auto; padding: 40px 22px 80px; }
  .legal-wrap h1 { margin-bottom: 4px; }
  .legal-wrap .updated { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
  .legal-wrap h2 { font-size: 17px; margin: 28px 0 8px; }
  .legal-wrap p, .legal-wrap li { color: var(--text); font-size: 14.5px; line-height: 1.65; }
  .legal-wrap ul { padding-left: 22px; margin: 8px 0; }
</style>
{% endblock %}
{% block content %}
<div class="legal-wrap">
  <h1>Privacy Policy</h1>
  <p class="updated">Last updated {{ current_year }}</p>

  <div class="warn-box">
    <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v4m0 4h.01M10.3 3.9 2.5 17a2 2 0 0 0 1.7 3h15.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>
    <div><b>Draft — not reviewed by counsel.</b> This is placeholder legal text describing what
    data this specific app actually collects. Do not rely on it without review by a qualified
    lawyer, and without confirming it against actual data handling before using it in
    production.</div>
  </div>

  <h2>What we collect</h2>
  <ul>
    <li><b>Account data</b> — email address, password hash, organization membership and role.</li>
    <li><b>Domain-verification records</b> — the domains you've asked to verify ownership of, and
    the DNS TXT / well-known-file proof used to verify them.</li>
    <li><b>Scan data</b> — the target URL you submit, and the findings a scan produces (which can
    include header values, redacted secret snippets, and other data drawn from the scanned
    site's own HTTP responses).</li>
    <li><b>Billing data</b> — for crypto invoices: the target plan, token/chain, receiving
    address, expected amount, and (once paid) the matched transaction hash. We do not collect
    card numbers, bank details, or wallet private keys.</li>
    <li><b>AI-summary data</b> — for Paid-tier scans, finding text is sent to Groq's API to
    generate a plain-English remediation summary. See `ai_summary.py`'s system prompt: finding
    data is always framed as data-to-summarize, never as instructions the model should follow.</li>
  </ul>

  <h2>Data retention</h2>
  <p>Scan reports and their findings are retained so you can view scan history and compare scans
  over time. Domain-verification proof is retained for as long as the verification is relied on
  to unlock intrusive checks against that domain.</p>

  <h2>Who sees your data</h2>
  <p>Scan results and organization data are visible to members of your organization according to
  their role. We don't sell scan data or share it with third parties beyond the processors named
  above (Groq for AI summaries, your chosen blockchain's public ledger for payment verification).</p>

  <h2>Your choices</h2>
  <p>You can request deletion of your account and associated data by contacting the account owner
  for this deployment.</p>
</div>
{% endblock %}
```

- [ ] **Step 6: Add the footer to `base.html`**

In `templates/base.html`, add footer CSS inside the main `<style>` block, right after the
`.wrap { ... }` rule (currently the last rule before `{% block head %}{% endblock %}`):

```css
  .site-footer { border-top: 1px solid var(--border); margin-top: 40px; }
  .footer-inner { max-width: 1040px; margin: 0 auto; padding: 20px; display:flex; justify-content:space-between; align-items:center; gap:16px; flex-wrap:wrap; color: var(--muted); font-size: 12.5px; }
  .footer-inner a { color: var(--muted); text-decoration:none; }
  .footer-inner a:hover { color: var(--text); }
```

Then, right before the closing `</body>` tag, add:

```html
  <footer class="site-footer">
    <div class="footer-inner">
      <span>&copy; {{ current_year }} WebVulnScanner</span>
      <span><a href="{{ url_for('public.terms') }}">Terms</a> &middot; <a href="{{ url_for('public.privacy') }}">Privacy</a></span>
    </div>
  </footer>
```

- [ ] **Step 7: Inject `current_year` into the template context**

In `webvulnscanner/__init__.py`, modify the existing context processor (lines 55-58):

```python
    @app.context_processor
    def inject_role_enum():
        # base.html's nav checks current_user.role == Role.ORG_ADMIN;
        # base.html's footer and terms.html/privacy.html use current_year.
        from datetime import datetime, timezone

        return {"Role": Role, "current_year": datetime.now(timezone.utc).year}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_public_routes.py -v`
Expected: PASS (5 tests total: the 2 pre-existing `/healthz` tests + 3 new ones)

- [ ] **Step 9: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all green — the footer now renders on every page, so this is worth confirming no other
test asserts on exact full-page HTML in a way the footer would break (unlikely given the existing
suite tests behavior/redirects, not literal markup, but confirm).

- [ ] **Step 10: Commit**

```bash
git add webvulnscanner/public_routes.py webvulnscanner/__init__.py templates/terms.html templates/privacy.html templates/base.html tests/test_public_routes.py
git commit -m "feat: add Terms of Service / Privacy Policy pages and site footer

Draft, app-specific content (clearly marked as not reviewed by counsel).
base.html grows its first footer, linking to both, present on every page.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 5: Dashboard visual polish — status pills + row hover

**Files:**
- Modify: `templates/dashboard.html` (the `<style>` block, plus the latest-scan status line and
  the "Your scans" table's status cell)
- Modify: `tests/test_scan_routes.py`

**Interfaces:**
- Consumes: same test factories as Task 3. Run this task *after* Task 3 (same file).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_scan_routes.py`:

```python


def test_dashboard_scan_status_renders_as_a_pill(client, db):
    org = make_org()
    user = make_user("pill@example.com", org=org)
    make_scan(user, org=org)  # default status is ScanStatus.QUEUED
    db.session.commit()

    login(client, "pill@example.com")
    resp = client.get("/dashboard")

    assert resp.status_code == 200
    assert 'class="status-pill queued"' in resp.get_data(as_text=True)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_scan_routes.py::test_dashboard_scan_status_renders_as_a_pill -v`
Expected: FAIL — no `status-pill` class exists yet.

- [ ] **Step 3: Add status-pill CSS**

In `templates/dashboard.html`'s `<style>` block, add after the existing `.sparkline-card .hint`
rule:

```css
  table tbody tr:hover td { background: rgba(255,255,255,.025); }
  .status-pill { display:inline-flex; align-items:center; font-size:11px; font-weight:700; padding:3px 9px; border-radius:999px; text-transform:uppercase; letter-spacing:.04em; }
  .status-pill.completed { background: rgba(34,197,94,.14); color: var(--accent); }
  .status-pill.running, .status-pill.queued { background: rgba(56,189,248,.14); color: var(--telemetry); }
  .status-pill.failed { background: rgba(248,113,113,.14); color: var(--critical); }
```

- [ ] **Step 4: Use the pill in the latest-scan summary line**

Two spots in `templates/dashboard.html` currently print `{{ latest.status.value }}` as plain
text — one inside the `{% if latest.risk_score is not none %}` branch, one in the `{% else %}`
branch. In both, replace:

```
{{ latest.target_url }}</code> &middot; {{ latest.scan_type }} scan &middot; {{ latest.status.value }}
```

with:

```
{{ latest.target_url }}</code> &middot; {{ latest.scan_type }} scan &middot;
            <span class="status-pill {{ latest.status.value }}">{{ latest.status.value }}</span>
```

(Match the existing indentation in each branch — the two occurrences have slightly different
surrounding whitespace since one is inside `<div style="font-size:13.5px; margin-top:4px;">` and
the other inside a bare `<div style="color: var(--muted); font-size:13.5px;">`.)

- [ ] **Step 5: Use the pill in the "Your scans" table**

In the `<table>` under `<h2 class="section">Your scans</h2>`, replace:

```
        <td>{{ s.status.value }}</td>
```

with:

```
        <td><span class="status-pill {{ s.status.value }}">{{ s.status.value }}</span></td>
```

- [ ] **Step 6: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_scan_routes.py -v`
Expected: PASS (all tests in this file, 4 total)

- [ ] **Step 7: Commit**

```bash
git add templates/dashboard.html tests/test_scan_routes.py
git commit -m "style: dashboard scan status renders as a colored pill, table rows get hover state

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 6: Billing visual polish — crypto invoice payment card

**Files:**
- Modify: `templates/billing.html`
- Create: `tests/test_billing_routes.py`

**Interfaces:**
- Consumes: `billing_routes.py`'s `view()` (`org`, `subscription`, `pending_invoices`,
  `plan_prices`, `token_symbols`, `upgradable_plans` — unchanged), `CryptoInvoice` model fields
  (`target_plan`, `token_symbol`, `expected_amount`, `receiving_address`, `expires_at`, `id`).

- [ ] **Step 1: Write the failing test**

Create `tests/test_billing_routes.py`:

```python
"""Tests for templates/billing.html's pending-invoice payment card."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from webvulnscanner.models import CryptoInvoice, InvoiceStatus, Plan
from tests.conftest import login, make_org, make_user


def make_pending_invoice(org, target_plan=Plan.PAID, token_symbol="USDT"):
    inv = CryptoInvoice(
        org_id=org.id,
        target_plan=target_plan,
        token_symbol=token_symbol,
        chain="polygon",
        receiving_address="0xABCDEF0123456789ABCDEF0123456789ABCDEF01",
        base_usd_amount=Decimal("19.00"),
        unique_offset=Decimal("0.000123"),
        expected_amount=Decimal("19.000123"),
        status=InvoiceStatus.PENDING,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    from webvulnscanner.extensions import db

    db.session.add(inv)
    db.session.flush()
    return inv


def test_pending_invoice_renders_as_a_payment_card_with_copy_button(client, db):
    # Viewing /account/billing only requires login (any member, not just an
    # org admin - creating/verifying invoices is the org-admin-only part),
    # so the default make_user() role is enough here.
    org = make_org()
    make_user("payer@example.com", org=org)
    inv = make_pending_invoice(org)
    db.session.commit()

    login(client, "payer@example.com")
    resp = client.get("/account/billing")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'class="invoice-card"' in body
    assert f'id="addr-{inv.id}"' in body
    assert "0xABCDEF0123456789ABCDEF0123456789ABCDEF01" in body
    assert "Copy" in body


def test_no_pending_invoices_still_shows_empty_state(client, db):
    org = make_org()
    user = make_user("nopay@example.com", org=org)
    db.session.commit()

    login(client, "nopay@example.com")
    resp = client.get("/account/billing")

    assert resp.status_code == 200
    assert "No pending invoices." in resp.get_data(as_text=True)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_billing_routes.py -v`
Expected: FAIL on the first test — no `invoice-card` class or `addr-{id}` id exists yet.

- [ ] **Step 3: Replace the pending-invoices table with payment cards**

In `templates/billing.html`, replace the whole `<h2 class="section">Pending invoices</h2>` block
through its closing `</div>` (currently lines 51-75) with:

```html
  <h2 class="section">Pending invoices</h2>
  <div class="card">
    {% if pending_invoices %}
    {% for inv in pending_invoices %}
    <div class="invoice-card">
      <div class="invoice-row">
        <div>
          <div class="invoice-label">Upgrade to</div>
          <div class="invoice-value">{{ inv.target_plan.value }}</div>
        </div>
        <div>
          <div class="invoice-label">Amount</div>
          <div class="invoice-value mono">{{ inv.expected_amount }} {{ inv.token_symbol }}</div>
        </div>
        <div>
          <div class="invoice-label">Expires</div>
          <div class="invoice-value">{{ inv.expires_at }}</div>
        </div>
      </div>
      <div class="invoice-address-row">
        <span class="invoice-label">Send to</span>
        <code class="invoice-address" id="addr-{{ inv.id }}">{{ inv.receiving_address }}</code>
        <button type="button" class="copy-btn" data-copy-target="addr-{{ inv.id }}">Copy</button>
      </div>
      <form method="POST" action="{{ url_for('billing.verify_invoice_route', invoice_id=inv.id) }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <button class="verify-btn" type="submit">Verify payment</button>
      </form>
    </div>
    {% endfor %}
    {% else %}
    <p style="color: var(--muted); font-size: 13.5px;">No pending invoices.</p>
    {% endif %}
  </div>
```

- [ ] **Step 4: Add the payment-card CSS and copy-button script**

Change `templates/billing.html`'s `{% block head %}` from just including
`_admin_form_styles.html` to also add a local `<style>` block:

```html
{% block head %}
{% include "_admin_form_styles.html" %}
<style>
  .invoice-card { border: 1px solid var(--border); border-radius: var(--radius); padding: var(--space-4); margin-bottom: var(--space-3); background: rgba(255,255,255,.02); }
  .invoice-card:last-child { margin-bottom: 0; }
  .invoice-row { display:flex; gap: var(--space-5); flex-wrap: wrap; margin-bottom: 14px; }
  .invoice-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .05em; margin-bottom: 3px; }
  .invoice-value { font-size: 14px; font-weight: 600; }
  .invoice-value.mono { font-family: "Fira Code", monospace; }
  .invoice-address-row { display:flex; align-items:center; gap: 10px; background: rgba(255,255,255,.03); border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; margin-bottom: 14px; flex-wrap: wrap; }
  .invoice-address { flex: 1; min-width: 200px; font-size: 12.5px; word-break: break-all; }
  .copy-btn { margin-top: 0; padding: 6px 12px; font-size: 12px; background: var(--panel2); color: var(--text); border: 1px solid var(--border); }
  .copy-btn.copied { background: var(--accent-dim); color: var(--accent); border-color: rgba(34,197,94,.4); }
</style>
{% endblock %}
```

Then, right before `{% endblock %}` at the very end of the file's `{% block content %}`, add:

```html
<script>
(function () {
  document.querySelectorAll('.copy-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var target = document.getElementById(btn.getAttribute('data-copy-target'));
      if (!target || !navigator.clipboard) return;
      navigator.clipboard.writeText(target.textContent.trim()).then(function () {
        var original = btn.textContent;
        btn.textContent = 'Copied';
        btn.classList.add('copied');
        setTimeout(function () { btn.textContent = original; btn.classList.remove('copied'); }, 1500);
      });
    });
  });
})();
</script>
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_billing_routes.py -v`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add templates/billing.html tests/test_billing_routes.py
git commit -m "style: billing.html pending invoices render as payment cards with copy-to-clipboard

Replaces the plain <code> table cell for the receiving address with a real
payment card (amount/chain/address) and a copy button.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 7: Org admin visual polish — pill badges + row hover

**Files:**
- Modify: `templates/org_admin.html`
- Create: `tests/test_org_routes.py`

**Interfaces:**
- Consumes: `org_routes.py`'s `admin()` view (`org`, `members`, `invite_form`, `domains`,
  `scans` — unchanged). Reuses `base.html`'s existing `.pill` component (no new CSS component).

- [ ] **Step 1: Write the failing test**

Create `tests/test_org_routes.py`:

```python
"""Tests for templates/org_admin.html's member/domain pill rendering."""
from webvulnscanner.models import Role
from tests.conftest import login, make_org, make_user


def test_org_admin_shows_member_verification_as_a_pill(client, db):
    org = make_org()
    make_user("admin@example.com", org=org, role=Role.ORG_ADMIN, verified=True)
    db.session.commit()

    login(client, "admin@example.com")
    resp = client.get("/org/admin")

    assert resp.status_code == 200
    assert 'class="pill pass"' in resp.get_data(as_text=True)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_org_routes.py -v`
Expected: FAIL — the current template puts `class="pass"` directly on the `<td>`, not
`class="pill pass"` on a `<span>`.

- [ ] **Step 3: Swap bare severity-text cells for `.pill` badges**

In `templates/org_admin.html`, replace:

```
        <td class="{{ 'pass' if m.email_verified_at else 'medium' }}">{{ 'yes' if m.email_verified_at else 'no' }}</td>
```

with:

```
        <td><span class="pill {{ 'pass' if m.email_verified_at else 'medium' }}">{{ 'yes' if m.email_verified_at else 'no' }}</span></td>
```

And replace:

```
        <td class="{{ 'pass' if dv.verified_at else 'medium' }}">{{ 'VERIFIED' if dv.verified_at else 'PENDING' }}</td>
```

with:

```
        <td><span class="pill {{ 'pass' if dv.verified_at else 'medium' }}">{{ 'VERIFIED' if dv.verified_at else 'PENDING' }}</span></td>
```

- [ ] **Step 4: Add row hover**

Change `templates/org_admin.html`'s `{% block head %}` to add a local style after the include:

```html
{% block head %}
{% include "_admin_form_styles.html" %}
<style>
  table tbody tr:hover td { background: rgba(255,255,255,.025); }
</style>
{% endblock %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_org_routes.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add templates/org_admin.html tests/test_org_routes.py
git commit -m "style: org_admin.html member/domain status renders as .pill badges, row hover

Reuses base.html's existing .pill component instead of the bare
text-color-only td classes.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 8: scan_report.html / scan_compare.html spacing refinement

**Files:**
- Modify: `templates/scan_report.html` (`<style>` block)
- Modify: `templates/scan_compare.html` (`<style>` block)

**Interfaces:** None — purely cosmetic CSS, no template logic changes, no other task depends on
this one.

- [ ] **Step 1: Add hover states to `scan_report.html`**

In `templates/scan_report.html`'s `<style>` block, add after the existing `.details-body` rule:

```css
  .finding { transition: border-color 150ms ease; }
  .finding:hover { border-color: rgba(255,255,255,.16); }
  summary:hover { background: rgba(255,255,255,.02); }
```

- [ ] **Step 2: Add the same hover state to `scan_compare.html`**

In `templates/scan_compare.html`'s `<style>` block, add after the existing `.empty` rule:

```css
  .finding { transition: border-color 150ms ease; }
  .finding:hover { border-color: rgba(255,255,255,.16); }
```

- [ ] **Step 3: No automated test for this task**

This is CSS-only (a `:hover` rule has no server-rendered signal to assert on). Verification
happens in Task 11's full browser pass — confirm both pages still render correctly and the hover
state is visible when moving the mouse over a finding card.

- [ ] **Step 4: Commit**

```bash
git add templates/scan_report.html templates/scan_compare.html
git commit -m "style: scan_report/scan_compare finding cards get a subtle hover state

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 9: scan_new_* consistency pass

**Files:**
- Modify: `templates/_scan_form_styles.html`

**Interfaces:** None — shared partial, affects `scan_new.html` and all four `scan_new_*.html`
pages identically (that's the point — see the partial's own header comment on why it's shared).

- [ ] **Step 1: Add input focus state**

In `templates/_scan_form_styles.html`, add after the `input[type=text] { ... }` rule:

```css
  input[type=text]:focus { border-color: var(--accent); background: rgba(34,197,94,.04); outline: none; }
```

- [ ] **Step 2: Add hover state to the 4-card chooser grid**

Add after the existing `.scan-type-grid .card { ... }` rule:

```css
  .scan-type-grid .card { transition: border-color 150ms ease, transform 150ms ease; }
  .scan-type-grid .card:hover { border-color: rgba(34,197,94,.35); transform: translateY(-2px); }
```

(This mirrors the `.feature:hover` pattern `marketing.html` already uses for its own 3-card
grid — bringing `scan_new.html`'s chooser to the same interaction standard.)

- [ ] **Step 3: No automated test for this task**

CSS-only (`:focus`/`:hover` states). Verification happens in Task 11's full browser pass.

- [ ] **Step 4: Commit**

```bash
git add templates/_scan_form_styles.html
git commit -m "style: scan_new_* forms get input focus state + chooser-card hover

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 10: Code-only keep-alive heartbeat

**Files:**
- Modify: `templates/base.html` (near the closing `</body>`, after the footer added in Task 4)

**Interfaces:** None. Consumes the existing `/healthz` route (`public_routes.py`, unchanged).

- [ ] **Step 1: Add the heartbeat script**

In `templates/base.html`, right before the closing `</body>` tag (i.e. immediately after the
`<footer class="site-footer">...</footer>` block added in Task 4), add:

```html
  <script>
  (function () {
    // Code-only keep-alive heartbeat: pings /healthz every 4 minutes while
    // this tab is open and visible, to help stop a free-tier host (e.g.
    // Render) from spinning down an active browsing session due to
    // inactivity. This only helps while someone has the site open in a
    // tab - true 24/7 uptime still needs an external monitor (e.g.
    // UptimeRobot) pointed at /healthz once deployed.
    var HEARTBEAT_INTERVAL_MS = 4 * 60 * 1000;
    function ping() {
      if (document.visibilityState !== 'visible') return;
      fetch('/healthz', { method: 'GET', cache: 'no-store', credentials: 'omit' }).catch(function () {});
    }
    setInterval(ping, HEARTBEAT_INTERVAL_MS);
  })();
  </script>
```

- [ ] **Step 2: No automated test for this task**

Pure client-side `setInterval`/`fetch` — not meaningfully unit-testable with the Flask test
client (no browser event loop). Verify manually via claude-in-chrome's
`read_network_requests` tool: load any page, wait >4 minutes (or temporarily lower
`HEARTBEAT_INTERVAL_MS` during manual testing only, then revert), and confirm a `/healthz`
request fires while the tab is visible.

- [ ] **Step 3: Commit**

```bash
git add templates/base.html
git commit -m "feat: add code-only keep-alive heartbeat pinging /healthz

Fires every 4 minutes while a tab is open and visible. A partial mitigation
(only helps during active browsing sessions) - full 24/7 uptime on a
free-tier host still needs an external monitor once deployed, documented
inline.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 11: Full verification pass

**Files:** None modified — this task only runs things.

**Interfaces:** None.

- [ ] **Step 1: Run the full automated test suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all tests pass (pre-existing 108+ tests, plus every new test added in Tasks 1, 3, 4, 5,
6, 7 above).

- [ ] **Step 2: Start the dev server**

Run (background): `.venv\Scripts\python app.py`
Confirm the terminal shows `Running on http://127.0.0.1:5000` and check
`Get-NetTCPConnection -LocalPort 5000 -State Listen` actually shows this process owns the port
(per `handoff.md`'s documented gotcha about stale servers from an earlier run silently still
answering).

- [ ] **Step 3: Full click-through via claude-in-chrome, desktop width**

In order, navigating and screenshotting each:
1. `/` — confirm hero content (headline/sub/CTA) is visible in the very first screenshot, not
   just the terminal box.
2. `/signup` → create a test account with an org name.
3. `/login` → log in.
4. `/dashboard` — with 0 scans: confirm "Not enough completed scans yet for a trend line."
   message (not a floating dot).
5. `/account/billing` — confirm the page renders; create an invoice via the form, confirm it now
   renders as an `.invoice-card` with a working "Copy" button (click it, confirm the button
   label flips to "Copied").
6. `/org/admin` — confirm member/domain status render as pill badges.
7. `/scan/new` → `/scan/new/base` — submit a real scan against `example.com` (already an
   authorized test target per this repo's own convention) with the authorization checkbox
   checked.
8. Live progress page (`/scan/<id>`) — confirm it still renders correctly (unchanged by this
   plan).
9. `/scan/<id>/report` — confirm findings render, hover a finding card, confirm the border-color
   hover transition from Task 8.
10. `/dashboard` again — now with exactly 1 scored scan: confirm the sparkline shows the flat
    reference line with the score label ("N (only scan so far)"), not a bare dot.
11. `/terms` and `/privacy` — confirm both render with the draft notice, and that the footer link
    from any page reaches them.
12. A nonexistent URL — confirm `404.html` still renders inside the app's theme (unchanged).

- [ ] **Step 4: Repeat steps 3-11 at a mobile viewport width**

Use claude-in-chrome's viewport-emulation approach already established in the Phase 2 redesign
(per `handoff.md`: iframe-based, since `resize_window` didn't affect that session's tab — check
if that's still true or if `resize_window` now works directly). Confirm no layout breaks
(especially the new invoice-card's `.invoice-row` wrapping, and the footer's `.footer-inner`
wrapping) at narrow widths.

- [ ] **Step 5: Report findings**

If any step surfaces a new issue, note it — do not silently fix scope beyond what this plan
covers. Otherwise, this task's completion is the plan's completion.

(No commit for this task — it's verification-only, nothing to stage.)
