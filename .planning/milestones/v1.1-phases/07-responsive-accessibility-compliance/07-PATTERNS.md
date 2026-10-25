# Phase 7: Responsive & Accessibility Compliance - Pattern Map

**Mapped:** 2026-08-18
**Files analyzed:** 17 modified templates (no new templates; 2 new test files)
**Analogs found:** 17 / 17 (this is a self-referential retrofit — every file's best analog is
another already-converted or already-correct part of the same codebase, per RESEARCH.md)

## File Classification

| File | Role | Data Flow | Closest Analog | Match Quality |
|------|------|-----------|-----------------|----------------|
| `templates/dashboard.html` (Scan History table) | component (record-list table) | CRUD (read) | `templates/asset_detail.html` (icon-btn/44px pattern) + itself as the Pattern-1 source | exact — this IS the canonical table RESEARCH.md's Pattern 1 example is built from |
| `templates/org_admin.html` (Members/Invitations/Domains/Scan History — 4 tables) | component (record-list tables) | CRUD (read + destructive POST actions) | `templates/dashboard.html`'s Scan History table (same bare `<tr><th>` shape, same `.table-scroll` wrapper) | exact (structural) |
| `templates/api_tokens.html` (Tokens table) | component (record-list table) | CRUD (read + destructive POST) | `templates/org_admin.html`'s Pending Invitations table (row has a name + status + destructive-action `<form>` cell) | exact (structural) |
| `templates/assets.html` (Assets list table) | component (record-list table) | CRUD (read) | `templates/dashboard.html`'s Scan History table (Target/Type/Status/Score/Created shape reused nearly verbatim per RESEARCH.md's "shared partial" note) | exact |
| `templates/asset_detail.html` (Scan history table) | component (record-list table) + icon-btn actions | CRUD (read) + event-driven (pause/resume) | Itself already defines the `.icon-btn` 44px pattern (line 43) other files must reuse; table shape mirrors `dashboard.html` | exact |
| `templates/org_verify_domain.html` (Domains table) | component (record-list table, app-shell not auth-wrap) | CRUD (read + destructive POST) | `templates/org_admin.html`'s Verified Domains table (same Domain/Status/Actions shape, same deletion-pending branch) | exact |
| `templates/scan_report.html` (20+ diagnostic tables) | component (diagnostic/attribute-dump tables) | request-response (read-only) | No card analog — stays `.table-scroll`; `.finding` card macro (already in same file, lines 118-129) is the analog for "how this codebase already does card-shaped result display" | role-match only (diagnostic, not record-list — see Pattern 3) |
| `templates/marketing.html` (heading hierarchy fix) | component (static content page) | request-response | `templates/scan_new_advanced.html` (same class of bug — H2→H4 skip) | exact (same defect class) |
| `templates/scan_new_advanced.html` (heading hierarchy fix) | component (form/accordion page) | request-response | Every other template's already-correct `h1→h2→h3` sequence (e.g. `dashboard.html`) is the target shape | exact (target pattern) |
| `templates/login.html`, `signup.html`, `forgot_password.html`, `reset_password.html`, `verify_email.html` (RESP-02 auth-wrap mobile fix) | component (auth form pages) | request-response | `login.html` itself (fully read this session) is the canonical `.auth-wrap` + `.pw-toggle` reference the other four already follow structurally | exact — all five share `_auth_form_styles.html` |
| `templates/_gauge.html` (hardcoded stroke colors → tokens) | component (shared SVG partial) | transform (score → visual) | `base.html`'s `--pass`/`--medium`/`--high`/`--critical` token definitions | exact — the fix target is defined in the analog itself |
| `templates/base.html` (new `--bp-card` breakpoint, `.mobile-record-cards`, `.record-card*` CSS, `.auth-wrap` mobile padding) | config (design-token/CSS cascade) | n/a | `base.html`'s own existing `@media (max-width: 640px) { .topnav ... }` block and `.icon-btn`/`.card` rules | exact — extending itself |
| `templates/scan_progress.html` (RESP-04 re-confirm only) | component (live SSE feed page) | streaming (SSE) | Itself — `.soc-grid`/`.soc-log-header` breakpoints already shipped, no analog needed | exact (no change expected) |
| `tests/test_accessibility.py` (NEW) | test | transform (rendered-HTML assertion) | `tests/test_template_consistency.py` (existing rendered-HTML substring/BeautifulSoup assertion pattern) | exact |
| `tests/test_responsive_markup.py` (NEW) | test | transform (rendered-HTML assertion) | `tests/test_template_consistency.py` | exact |

## Pattern Assignments

### `templates/dashboard.html`, `org_admin.html`, `api_tokens.html`, `assets.html`, `asset_detail.html`, `org_verify_domain.html` (record-list tables → dual-markup table/card)

**Analog:** `templates/dashboard.html:290-311` (the canonical instance) and `templates/org_admin.html:40-140` (multi-table instance showing the destructive-action-in-cell pattern to preserve)

**Current bare-table pattern to retrofit** (`templates/dashboard.html:290-311`, VERIFIED):
```html
<h2 class="section">Scan History</h2>
<div class="card">
  {% if scans %}
  <div class="table-scroll">
  <table>
    <tr><th>Target</th><th>Type</th><th>Status</th><th>Security Score</th><th>Created</th><th></th></tr>
    {% for s in scans %}
    <tr>
      <td><code>{{ s.target_url }}</code></td>
      <td>{{ scan_type_labels.get(s.scan_type, s.scan_type|title) }}</td>
      <td>{{ latest_status_pill(s.status.value) }}</td>
      <td>{{ s.risk_score if s.risk_score is not none else '-' }}</td>
      <td>{{ s.created_at.strftime('%b %d, %Y %H:%M') }}</td>
      <td><a class="row-link" href="{{ url_for('scan.scan_detail', scan_id=s.id) }}">View &rarr;</a></td>
    </tr>
    {% endfor %}
  </table>
  </div>
  {% else %}
  <div class="empty-state">No scans yet. ...</div>
  {% endif %}
</div>
```
No `<thead>`/`<tbody>` anywhere — every one of the ~9 in-scope tables has this exact bare
`<table><tr><th>` shape (confirmed by grep this session across `org_admin.html:46,86,116,154`,
`api_tokens.html:97`, `assets.html:24`, `org_verify_domain.html:35`).

**Destructive-action-in-cell pattern to preserve verbatim when moving into a card**
(`templates/org_admin.html:93-101`, VERIFIED):
```html
<td class="actions-cell">
  <form method="POST" action="{{ url_for('org.resend_invitation', invitation_id=inv.id) }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <button type="submit" class="verify-btn">Resend</button>
  </form>
  <form method="POST" action="{{ url_for('org.revoke_invitation', invitation_id=inv.id) }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <button type="submit" class="verify-btn danger">Revoke</button>
  </form>
</td>
```
Per UI-SPEC's anti-pattern list: do NOT reuse `.verify-btn`'s compact 13px/6-12px padding inside
the new mobile card — swap to `.btn.destructive.block` (44px+) wrapped in the same
`<form method="POST">` + `confirm()` structure.

**44px icon-btn touch-target class to reuse for any new icon-only card action**
(`templates/asset_detail.html:43`, VERIFIED):
```css
.icon-btn { min-width: 44px; min-height: 44px; padding: 0; justify-content:center; }
.icon-btn .icon { width:18px; height:18px; }
```

**Target dual-markup shape** (per UI-SPEC's Mobile Stacked-Card Pattern section — apply this
exact shape to all ~9 tables, add `<thead>`/`<tbody>` to the table half too):
```html
<div class="table-scroll desktop-table">
<table>
  <thead><tr><th>Target</th><th>Type</th><th>Status</th><th>Security Score</th><th>Created</th><th></th></tr></thead>
  <tbody>
    {% for s in scans %}
    <tr>...</tr>
    {% endfor %}
  </tbody>
</table>
</div>
<ul class="mobile-record-cards">
  {% for s in scans %}
  <li class="card record-card">
    <div class="record-card-top">
      <code>{{ s.target_url }}</code>
      {{ latest_status_pill(s.status.value) }}
    </div>
    <div class="record-card-meta">{{ s.risk_score if s.risk_score is not none else '-' }} / 100 &middot; {{ s.created_at.strftime('%b %d') }}</div>
    <a class="btn secondary block" href="{{ url_for('scan.scan_detail', scan_id=s.id) }}">View &rarr;</a>
  </li>
  {% endfor %}
</ul>
```
```css
.mobile-record-cards { display: none; }
@media (max-width: 430px) {
  .desktop-table { display: none; }
  .mobile-record-cards { display: flex; flex-direction: column; gap: var(--space-3); list-style: none; margin: 0; padding: 0; }
}
```
Both blocks must share the SAME `{% if scans %}...{% else %}<div class="empty-state">...{% endif %}`
wrapper — do not duplicate the empty-state branch per block.

---

### `templates/scan_report.html` (20+ diagnostic tables — Pattern 3, exception handling)

**Analog:** the `finding_card` macro already in the same file (`templates/scan_report.html:118-129`,
referenced by RESEARCH.md) shows this codebase's existing non-table "card" idiom:
```html
<div class="finding {{ f.severity }}">...</div>
```
**Directive:** do NOT convert these tables to `.mobile-record-cards`. Add `<thead>`/`<tbody>` only
(Pattern 2, zero-risk additive fix) and keep `.table-scroll`. Audit each table individually for
320px overflow before deciding if any (e.g. media-items, bruteforce-attempts) need card treatment
as a genuine exception — do not blanket-convert.

---

### `templates/marketing.html`, `templates/scan_new_advanced.html` (heading-hierarchy fix)

**Analog:** every other already-correct template's sequential heading pattern, e.g.
`templates/dashboard.html`'s `h1` → `h2.section` sequence (no skip).

**Current violation** (`templates/marketing.html:191,198`, VERIFIED per RESEARCH.md):
```html
<h2>What Glassbox checks</h2>
...
<h4>Exposed secrets</h4>  <!-- skips h3 -->
```
Same pattern again at `marketing.html:310,316` (`<h2>How it works</h2>` → `<h4>Enter your domain</h4>`).

**Current violation** (`templates/scan_new_advanced.html:31,81,110,127,152,185`, VERIFIED):
`<h1>` at line 31, then four `<h4>` accordion-group labels (81/110/127/152) appear before the
page's only `<h2>` (later, locked-state heading).

**Fix directive (from UI-SPEC, token-only, no new size):** insert `<h3>` grouping headings on
`marketing.html`; relabel the four `<h4>` accordion labels to `<h2>` on `scan_new_advanced.html`
so the later locked-state `<h2>` becomes the 5th sibling rather than a hierarchy anchor skipped
past. No new typography token — H2 role (20px/600) and H3 role (16px/600) already exist in
`base.html`.

---

### `templates/login.html`, `signup.html`, `forgot_password.html`, `reset_password.html`, `verify_email.html` (RESP-02 auth-wrap mobile fix)

**Analog:** `templates/login.html` (fully read this session) is the reference; all five share
`_auth_form_styles.html` and the `.auth-wrap` + `.card` shell.

**Current structure** (`templates/login.html:17-51`, VERIFIED):
```html
<div class="auth-wrap">
  <div class="card">
    <h1>Log in</h1>
    <form method="POST" action="{{ url_for('auth.login') }}" id="loginForm">
      ...
      <div class="pw-wrap">
        {{ form.password(...) }}
        <button type="button" class="pw-toggle" data-toggle-for="password" aria-label="Show password">
          <svg class="icon" ... aria-hidden="true">...</svg>
        </button>
      </div>
      ...
    </form>
    <div class="swap">Don't have an account? <a href="{{ url_for('auth.signup') }}">Sign up</a></div>
  </div>
</div>
<script>
  document.querySelectorAll('.pw-toggle').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var input = document.getElementById(btn.dataset.toggleFor);
      var showing = input.type === 'text';
      input.type = showing ? 'password' : 'text';
      btn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
    });
  });
</script>
```
This exact `.pw-toggle` dynamic-aria-label script is the reference pattern for any new
state-dependent icon-only control this phase adds — reuse verbatim, don't reinvent.

**Fix directive** (`base.html`-only, per UI-SPEC): add
`@media (max-width: 640px) { .auth-wrap { padding-top: var(--space-5); } }` (24px instead of the
current 48px `--space-7`) and suppress the redundant topnav CTA link at ≤640px on these five
pages only. No change to `login.html`'s own markup structure — the fix lives in `base.html`'s CSS
cascade plus a possible page-scoped conditional class.

---

### `templates/_gauge.html` (hardcoded stroke colors → token-based)

**Analog:** `base.html`'s `--pass`/`--medium`/`--high`/`--critical` custom properties (the tokens
these four hex values should reference).

**Current hardcoded ternary** (`templates/_gauge.html:21-24`, VERIFIED, full file read this session):
```html
<circle class="gauge-fg"
         id="{{ _gauge_id }}" cx="55" cy="55" r="46"
         stroke="{{ '#34d399' if score >= 90 else ('#fbbf24' if score >= 60 else ('#fb923c' if score >= 40 else '#fb7185')) }}"
         stroke-dasharray="289" stroke-dashoffset="289"></circle>
```
None of `#34d399`/`#fbbf24`/`#fb923c`/`#fb7185` match `--pass`/`--medium`/`--high`/`--critical`
exactly (e.g. `#fb7185` vs. token `--critical` `#f87171`).

**Fix directive:** replace inline `stroke=` ternary with a CSS class ternary
(`.gauge-fg.pass`/`.medium`/`.high`/`.critical`) referencing `stroke: var(--pass)` etc. added to
`base.html`, with `_gauge.html` emitting the class name via the same score ternary instead of a
raw hex. Confirms 3:1 non-text contrast via tool check, not by inspection.

---

### `templates/scan_progress.html` (RESP-04 — re-confirm only, no fix expected)

**Analog:** itself — the two breakpoints already exist and are the reference for "already-correct
responsive CSS in this codebase."

**Already-shipped breakpoints** (`templates/scan_progress.html:38-39,50-54`, VERIFIED):
```css
.soc-grid { display:grid; grid-template-columns: 1fr; gap: 18px; margin-top: 18px; }
@media (min-width: 880px) { .soc-grid { grid-template-columns: minmax(0, 2fr) minmax(240px, 1fr); align-items:start; } }
...
@media (max-width: 480px) {
  .soc-log-header { flex-direction: column; align-items: flex-start; }
  .bar-track { width: 100%; max-width: none; }
}
```
Do not modify these values unless a live `checkpoint:human-verify` at 320/375/768/1280px actually
finds a failure.

---

### `tests/test_accessibility.py`, `tests/test_responsive_markup.py` (NEW test files)

**Analog:** `tests/test_template_consistency.py` (existing rendered-HTML/template-source
assertion convention — `client.get(...).get_data(as_text=True)` or
`pathlib.Path("templates/x.html").read_text(...)` with substring/BeautifulSoup checks, no
Selenium/Playwright in this repo). Follow this exact convention: static assertions only, defer
live-viewport/contrast checks to `checkpoint:human-verify` tasks.

---

## Shared Patterns

### `.icon-btn` 44px touch target (A11Y touch-target minimum)
**Source:** `templates/asset_detail.html:43`
**Apply to:** every new icon-only control added inside a `.record-card` across all 6 D-01 tables.
```css
.icon-btn { min-width: 44px; min-height: 44px; padding: 0; justify-content:center; }
```

### `aria-label="<verb> <target>"` accessible-name pattern
**Source:** `templates/asset_detail.html:62,69,76`
**Apply to:** any new icon-only mobile-card action (e.g. `aria-label="Revoke {{ token.name }}"`).
```html
<button type="submit" class="btn secondary icon-btn" aria-label="Resume schedule for {{ asset.name }}">
  <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#icon-play"/></svg>
</button>
```

### Dynamic state-dependent aria-label (icon toggle pattern)
**Source:** `templates/login.html` bottom `<script>`
**Apply to:** any future toggle-style icon control (reference only — no new toggle is planned this
phase beyond the existing `.pw-toggle`).
```javascript
btn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
```

### Global focus-visible ring — do not override per-component
**Source:** `templates/base.html:68`
**Apply to:** all files; explicitly do NOT add a component-local `:focus` override anywhere,
including new `.record-card`/`<details><summary>` markup.
```css
:focus-visible { outline: 2px solid var(--ring); outline-offset: 2px; border-radius: 4px; }
```

### `.card` shape — extend, never redefine locally
**Source:** `templates/base.html:165`
**Apply to:** `.record-card` (new mobile-card class) must extend `.card`, not redefine
background/border/radius.
```css
.card { background: linear-gradient(180deg, var(--panel), var(--panel2)); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 22px; margin-bottom: 18px; }
```

### Destructive-action form (CSRF preservation — hard safety constraint)
**Source:** `templates/org_admin.html:93-101` / `templates/asset_detail.html:74-79`
**Apply to:** every destructive action moved into a mobile card (asset delete, token revoke,
domain deletion request, invitation revoke) — must stay a real
`<form method="POST">` + hidden `csrf_token` + `confirm()` JS dialog, never a bare `<a href>` or
`<div onclick>`.

## No Analog Found

None — every in-scope file has a same-codebase analog because this phase is a retrofit against
Phase 6's already-consolidated system (per RESEARCH.md's own framing: "almost everything this
phase needs already exists correctly somewhere in the codebase").

## Metadata

**Analog search scope:** `templates/*.html` (all ~35 templates), `templates/base.html`,
`tests/test_template_consistency.py`
**Files scanned:** 17 target files + `base.html` + 4 analog tables greped (`org_admin.html`,
`api_tokens.html`, `assets.html`, `org_verify_domain.html`) + `asset_detail.html`, `_gauge.html`,
`login.html` fully read this session
**Pattern extraction date:** 2026-08-18
