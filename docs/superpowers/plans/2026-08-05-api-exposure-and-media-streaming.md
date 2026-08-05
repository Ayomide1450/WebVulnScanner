# API Exposure Scan + Media Stream Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fourth scan pipeline (`/scan-api`) that detects exposed API schemas/docs, unauthenticated common API paths, and endpoints discovered from the site's own JS, and strengthen the existing media scan to discover and verify HLS/DASH video streams.

**Architecture:** Everything lives in `app.py`, following the codebase's existing conventions (see `CLAUDE.md`): every check function returns `(data, findings)`, `Finding` objects drive a duplicated-per-orchestrator severity-weighted scoring formula, and all new checks are `GET`-only except one narrow, read-only GraphQL introspection `POST`. A new shared helper (`_fetch_same_origin_js`) is extracted from existing code and reused by two of the new features.

**Tech Stack:** Flask, `requests`, `BeautifulSoup4`, stdlib `re`/`urllib.parse`/`concurrent.futures`. No new dependencies. No test framework is added (see Global Constraints) — verification uses throwaway scratch scripts with a hand-rolled fake `requests.Session`, never committed.

## Global Constraints

- No new pip dependencies (`requirements.txt` stays `flask`, `requests`, `beautifulsoup4`, `dnspython`, `Pillow`).
- Every new network call must be `try/except requests.RequestException`-guarded and never raise past its own function (existing repo convention).
- No destructive requests: `GET` for everything except one read-only GraphQL introspection `POST` (a metadata query, not a mutation).
- No automated test suite is introduced (spec's explicit, stated choice — see `docs/superpowers/specs/2026-08-05-api-exposure-and-media-streaming-design.md`, "Testing" section). Each task's "test" step is a throwaway scratch script (`verify_taskN.py` in the project root) using a hand-rolled fake session — write it, run it, then delete it. Never `git add` these scratch files.
- Follow the existing `Finding("Category", "Title", "severity", "detail", "recommendation")` dataclass shape and `SEVERITY_WEIGHT`/`SEVERITY_ORDER` scoring pattern exactly as used elsewhere in `app.py`.
- New report files follow the existing naming convention: `reports/<prefix>_<hostname>_<timestamp>.json`.

---

## Task 1: Extract shared same-origin JS-fetch helper

**Files:**
- Modify: `app.py` (add `_fetch_same_origin_js` near `check_exposed_secrets`, ~line 514-520; refactor `check_exposed_secrets`, ~lines 520-566)

**Interfaces:**
- Produces: `_fetch_same_origin_js(session, base_url, page_html, max_files, max_bytes) -> list[tuple[str, str]]` — returns `(url, text)` pairs for up to `max_files` same-origin `<script src>` URLs found in `page_html`, each fetched and capped at `max_bytes`. Failed fetches are silently skipped (existing behavior, preserved).

- [ ] **Step 1: Add the shared helper function**

Insert this directly above `check_exposed_secrets` in `app.py`:

```python
def _fetch_same_origin_js(session, base_url, page_html, max_files, max_bytes):
    """Collects up to max_files same-origin <script src> URLs referenced in
    page_html and fetches each, capped at max_bytes. Returns a list of
    (url, text) tuples. Used by both check_exposed_secrets (JS bundles that
    might contain hardcoded secrets) and crawl_media/check_api_js_discovery
    (JS that might reference stream manifests or API endpoints)."""
    origin = urlparse(base_url).netloc
    soup = BeautifulSoup(page_html, "html.parser")

    js_urls = []
    for tag in soup.find_all("script", src=True):
        abs_url = urljoin(base_url + "/", tag["src"])
        if urlparse(abs_url).netloc == origin and abs_url not in js_urls:
            js_urls.append(abs_url)
    js_urls = js_urls[:max_files]

    sources = []
    for url in js_urls:
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT, stream=True)
            content = b""
            for chunk in r.iter_content(chunk_size=16384):
                content += chunk
                if len(content) >= max_bytes:
                    break
            r.close()
            sources.append((url, content.decode("utf-8", errors="ignore")))
        except requests.RequestException:
            continue
    return sources
```

- [ ] **Step 2: Refactor `check_exposed_secrets` to use the helper**

Replace the body of `check_exposed_secrets` (the JS-collecting block between `sources = [("homepage HTML", home_html)]` and the `rows, findings = [], []` line) so it reads:

```python
def check_exposed_secrets(session, base_url, home_html):
    """Scans the homepage HTML plus up to MAX_SECRET_JS_FILES same-origin JS
    bundles for hardcoded API keys/tokens/private keys. Values are redacted
    in the report (only a few leading/trailing chars kept) so the report
    file itself doesn't become a second place the secret is exposed."""
    sources = [("homepage HTML", home_html)]
    js_sources = _fetch_same_origin_js(session, base_url, home_html,
                                        MAX_SECRET_JS_FILES, MAX_JS_BYTES_PER_FILE)
    sources.extend(js_sources)
    js_files_scanned = len(js_sources)

    rows, findings = [], []
    seen = set()
    for label, pattern, sev in SECRET_PATTERNS:
        for source_name, text in sources:
            for m in re.finditer(pattern, text):
                value = m.group(1) if m.groups() else m.group(0)
                key = (label, value)
                if key in seen:
                    continue
                seen.add(key)
                redacted = _redact_secret(value)
                rows.append({"type": label, "source": source_name, "value": redacted, "severity": sev})
                if sev != "info":
                    findings.append(Finding("Secrets", f"Possible exposed {label}", sev,
                                             f"Found in {source_name}: {redacted}",
                                             "Remove this credential from client-shipped code. If it's real, "
                                             "rotate it immediately and load secrets server-side only."))
    return {"rows": rows, "js_files_scanned": js_files_scanned}, findings
```

- [ ] **Step 3: Write and run a verification script**

Create `verify_task1.py` in the project root:

```python
import sys
sys.path.insert(0, ".")
from app import check_exposed_secrets

class FakeResponse:
    def __init__(self, text):
        self.text = text
        self._content = text.encode()
    def iter_content(self, chunk_size=16384):
        for i in range(0, len(self._content), chunk_size):
            yield self._content[i:i + chunk_size]
    def close(self):
        pass

class FakeSession:
    def __init__(self, routes):
        self.routes = routes
    def get(self, url, **kwargs):
        return FakeResponse(self.routes[url])

home_html = '<html><script src="/app.js"></script></html>'
js_body = 'const key = "AKIAABCDEFGHIJKLMNOP";'
session = FakeSession({"https://example.com/app.js": js_body})

data, findings = check_exposed_secrets(session, "https://example.com", home_html)

assert data["js_files_scanned"] == 1, data
assert len(findings) == 1, findings
assert findings[0].severity == "critical", findings[0]
assert "AK" in findings[0].detail and "OP" in findings[0].detail
print("Task 1 verification: PASS")
```

Run: `python verify_task1.py`
Expected: `Task 1 verification: PASS`

- [ ] **Step 4: Delete the scratch script**

```bash
rm verify_task1.py
```

- [ ] **Step 5: Commit**

```bash
git add app.py
git commit -m "Extract _fetch_same_origin_js helper from check_exposed_secrets"
```

---

## Task 2: HLS/DASH stream discovery in the media crawler

**Files:**
- Modify: `app.py` (add constants near `MAX_EXIF_IMAGES`, ~line 67-68; add `_extract_stream_urls` near `_extract_media_urls`, ~line 732; modify `crawl_media`, ~lines 787-817)

**Interfaces:**
- Consumes: `_fetch_same_origin_js` from Task 1.
- Produces: `_extract_stream_urls(base_url, text) -> set[str]`. `crawl_media(session, base_url)` now returns a 4-tuple `(media_urls, embed_urls, stream_urls, crawl_info)` instead of a 3-tuple — **this changes crawl_media's signature**, which Task 3 depends on.

- [ ] **Step 1: Add stream constants**

In `app.py`, right after the `MAX_EXIF_IMAGES = 15` / `MAX_MEDIA_FILE_BYTES = 20 * 1024 * 1024` block, add:

```python
MAX_MEDIA_JS_FILES = 4       # JS files fetched per crawled page for stream discovery
MAX_MEDIA_STREAMS = 10       # verified HLS/DASH streams kept in a report
```

- [ ] **Step 2: Add `_extract_stream_urls`**

Add this function directly above `crawl_media`:

```python
STREAM_URL_PATTERN = re.compile(r'["\']([^"\'()\s]+\.(?:m3u8|mpd)(?:\?[^"\'()\s]*)?)["\']')


def _extract_stream_urls(base_url, text):
    """Regex-scans text (HTML or JS) for HLS (.m3u8) / DASH (.mpd) manifest
    URLs inside quoted strings. Candidates are verified later (see
    check_media) before being reported - this function only extracts, it
    doesn't confirm the URL resolves to a real manifest."""
    urls = set()
    for m in STREAM_URL_PATTERN.finditer(text or ""):
        urls.add(urljoin(base_url + "/", m.group(1)))
    return urls
```

- [ ] **Step 3: Wire stream discovery into `crawl_media`**

Replace the body of `crawl_media` from `media_urls, embeds = _extract_media_urls(base_url, home_r.text)` through the `return` line with:

```python
    media_urls, embeds = _extract_media_urls(base_url, home_r.text)
    stream_urls = _extract_stream_urls(base_url, home_r.text)
    for _, js_text in _fetch_same_origin_js(session, base_url, home_r.text,
                                             MAX_MEDIA_JS_FILES, MAX_JS_BYTES_PER_FILE):
        stream_urls |= _extract_stream_urls(base_url, js_text)

    for page in pages[1:]:
        try:
            r = session.get(page, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue
        u, e = _extract_media_urls(base_url, r.text)
        media_urls |= u
        embeds |= e
        stream_urls |= _extract_stream_urls(base_url, r.text)
        for _, js_text in _fetch_same_origin_js(session, base_url, r.text,
                                                 MAX_MEDIA_JS_FILES, MAX_JS_BYTES_PER_FILE):
            stream_urls |= _extract_stream_urls(base_url, js_text)

    return (list(media_urls)[:MAX_MEDIA_ITEMS], list(embeds)[:20],
            list(stream_urls)[:MAX_MEDIA_STREAMS], {"pages_crawled": len(pages)})
```

- [ ] **Step 4: Write and run a verification script**

Create `verify_task2.py`:

```python
import sys
sys.path.insert(0, ".")
from app import crawl_media

class FakeResponse:
    def __init__(self, text):
        self.text = text

class FakeSession:
    def __init__(self, routes):
        self.routes = routes
    def get(self, url, **kwargs):
        if url not in self.routes:
            raise Exception("unmapped url: " + url)
        return FakeResponse(self.routes[url])

home_html = '<html><script src="/player.js"></script></html>'
js_body = 'var manifest = "/streams/live.m3u8"; var other = "/streams/dash.mpd";'
session = FakeSession({
    "https://example.com/": home_html,
    "https://example.com/player.js": js_body,
})

media_urls, embeds, stream_urls, crawl_info = crawl_media(session, "https://example.com")

assert stream_urls == ["https://example.com/streams/live.m3u8",
                        "https://example.com/streams/dash.mpd"] or \
       sorted(stream_urls) == sorted(["https://example.com/streams/live.m3u8",
                                       "https://example.com/streams/dash.mpd"]), stream_urls
print("Task 2 verification: PASS")
```

Run: `python verify_task2.py`
Expected: `Task 2 verification: PASS`

- [ ] **Step 5: Delete the scratch script**

```bash
rm verify_task2.py
```

- [ ] **Step 6: Commit**

```bash
git add app.py
git commit -m "Discover HLS/DASH stream URLs from page HTML and same-origin JS"
```

---

## Task 3: Verify and report discovered streams in `check_media`

**Files:**
- Modify: `app.py` (`check_media`, ~lines 858-968)
- Modify: `templates/media_results.html` (media table, ~lines 156-168)

**Interfaces:**
- Consumes: `crawl_media(session, base_url) -> (media_urls, embed_urls, stream_urls, crawl_info)` from Task 2.
- Produces: `check_media` report items may now include `{"url": ..., "kind": "stream", "status": 200, "content_type": "HLS"|"DASH", "size": None, "suspicious_path": bool}`.

- [ ] **Step 1: Update `check_media`'s unpacking of `crawl_media`**

Change the first line of `check_media`:

```python
    media_urls, embed_urls, stream_urls, crawl_info = crawl_media(session, base_url)
    if not media_urls and not embed_urls and not stream_urls:
        return {"media_items": [], "crawl_info": crawl_info, "downloaded_count": 0, "download_dir": None}, []
```

- [ ] **Step 2: Add stream verification + reporting**

Insert this new loop directly before the existing `for url in embed_urls:` loop near the end of `check_media` (after the images/videos `for i, url in enumerate(media_urls):` loop closes):

```python
    for url in stream_urls:
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue
        lower_url = url.lower()
        is_hls = lower_url.endswith(".m3u8") and "#EXTM3U" in r.text[:200]
        is_dash = lower_url.endswith(".mpd") and "<MPD" in r.text[:500]
        if r.status_code != 200 or not (is_hls or is_dash):
            continue  # regex-extracted but didn't resolve to a real manifest - skip

        path_lower = urlparse(url).path.lower()
        suspicious = any(hint in path_lower for hint in MEDIA_PATH_HINTS)
        items.append({"url": url, "kind": "stream", "status": r.status_code,
                       "content_type": "HLS" if is_hls else "DASH", "size": None,
                       "suspicious_path": suspicious})
        if suspicious:
            findings.append(Finding(
                "Media exposure", f"Possibly unintended public video stream: {url}", "medium",
                "The stream manifest path contains a hint (e.g. 'private', 'internal') suggesting this "
                "wasn't meant to be publicly reachable, but it's a verified, reachable manifest.",
                "Move non-public streams behind authentication or remove them from public access."))
```

- [ ] **Step 3: Update `media_results.html` to show stream rows**

The existing table already has a generic `Kind` column (`{{ item.kind or '-' }}`), a `Status`/`Size`/`Suspicious path` column that all work unmodified for `kind: "stream"` items (size will render as `-` since `item.size` is `None`, which matches the existing `'-'` fallback). Only the `Kind` cell needs a small tweak so `"stream"` shows its `content_type` (HLS/DASH) the same way `"embedded"` items already show theirs. Change line ~160:

```html
            <td>{% if item.kind == 'embedded' %}embedded ({{ item.content_type }}){% elif item.kind == 'stream' %}stream ({{ item.content_type }}){% else %}{{ item.kind or '-' }}{% endif %}</td>
```

- [ ] **Step 4: Write and run a verification script**

Create `verify_task3.py`:

```python
import sys
sys.path.insert(0, ".")
from app import check_media

class FakeResponse:
    def __init__(self, text, status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}

class FakeSession:
    def __init__(self, routes):
        self.routes = routes
    def get(self, url, **kwargs):
        return self.routes.get(url, FakeResponse("not found", 404))
    def head(self, url, **kwargs):
        return FakeResponse("", 405)  # force HEAD-unsupported fallback to GET path

home_html = "<html></html>"
manifest_body = "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=100\nchunk.m3u8\n"
session = FakeSession({
    "https://example.com/private/live.m3u8": FakeResponse(manifest_body),
})

# Bypass crawl_media (network-independent unit under test is the verification
# loop) by monkeypatching crawl_media's return for this script only.
import app as app_module
app_module.crawl_media = lambda session, base_url: ([], [], ["https://example.com/private/live.m3u8"], {"pages_crawled": 1})

data, findings = check_media(session, "https://example.com", download=False, max_files=0)

stream_items = [i for i in data["media_items"] if i["kind"] == "stream"]
assert len(stream_items) == 1, data["media_items"]
assert stream_items[0]["content_type"] == "HLS", stream_items[0]
assert stream_items[0]["suspicious_path"] is True, stream_items[0]
assert len(findings) == 1 and findings[0].severity == "medium", findings
print("Task 3 verification: PASS")
```

Run: `python verify_task3.py`
Expected: `Task 3 verification: PASS`

- [ ] **Step 5: Delete the scratch script**

```bash
rm verify_task3.py
```

- [ ] **Step 6: Commit**

```bash
git add app.py templates/media_results.html
git commit -m "Verify and report discovered HLS/DASH streams in media scan"
```

---

## Task 4: API schema/GraphQL-introspection exposure check

**Files:**
- Modify: `app.py` (add constants after `VULN_JS_LIBS`, ~line 123; add `check_api_schema_exposure` near other check functions, e.g. directly after `check_sri`, ~line 611)

**Interfaces:**
- Produces: `check_api_schema_exposure(base_url, session) -> (rows: list[dict], findings: list[Finding])`.

- [ ] **Step 1: Add API exposure constants**

Add this new block in `app.py` directly after the `VULN_JS_LIBS` dict (before `def _mk_session():`):

```python
# --------------------------------------------------------------------------
# API exposure checks (see check_api_schema_exposure / check_api_wordlist /
# check_api_js_discovery). Runs as its own scan (see run_api_scan / POST
# /scan-api), separate from the base scan.
# --------------------------------------------------------------------------
API_SCHEMA_PATHS = ["swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
                     "api-docs", "v2/api-docs", "v3/api-docs", "graphiql", "api/swagger.json"]
GRAPHQL_PATHS = ["graphql", "api/graphql", "v1/graphql"]
GRAPHQL_INTROSPECTION_QUERY = {"query": "{__schema{types{name}}}"}
API_SCHEMA_SIGNATURES = ('"openapi"', '"swagger"', '"paths"', "<title>swagger", "graphiql")

API_WORDLIST = ["api", "api/v1", "api/v2", "api/admin", "api/internal", "api/users",
                 "api/user", "api/config", "api/orders", "api/auth", "api/debug",
                 "api/backup", "api/token", "api/keys", "api/accounts", "api/payments",
                 "api/health", "api/status", "api/logs", "api/test"]
API_SENSITIVE_HINTS = ["admin", "internal", "config", "debug", "backup", "token",
                        "secret", "payment", "key", "credential"]
MAX_API_JS_ENDPOINTS = 30
```

- [ ] **Step 2: Add `check_api_schema_exposure`**

Add this function directly after `check_sri` (before `crawl_same_origin`):

```python
def check_api_schema_exposure(base_url, session):
    """Probes common OpenAPI/Swagger doc paths and sends one read-only
    GraphQL introspection query to common GraphQL paths. Either succeeding
    hands an attacker the full API surface, including routes never linked
    anywhere - a high-severity finding either way."""
    rows, findings = [], []

    def probe(path):
        try:
            r = session.get(f"{base_url}/{path}", timeout=REQUEST_TIMEOUT)
            return path, r
        except requests.RequestException:
            return path, None

    with ThreadPoolExecutor(max_workers=8) as pool:
        for path, r in pool.map(probe, API_SCHEMA_PATHS):
            if r is None:
                continue
            body_lower = r.text[:2000].lower()
            is_schema = r.status_code == 200 and any(sig in body_lower for sig in API_SCHEMA_SIGNATURES)
            rows.append({"path": "/" + path, "code": r.status_code, "status": "warn" if is_schema else "pass"})
            if is_schema:
                findings.append(Finding(
                    "API Exposure", f"Publicly reachable API schema/docs: /{path}", "high",
                    "Returns what looks like an OpenAPI/Swagger schema or interactive docs UI - reveals the "
                    "full API surface, including routes never linked anywhere.",
                    "Require authentication for schema/docs endpoints in production, or remove them."))

    for path in GRAPHQL_PATHS:
        try:
            r = session.post(f"{base_url}/{path}", json=GRAPHQL_INTROSPECTION_QUERY, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code == 200 and ('"__schema"' in r.text or '"types"' in r.text):
            rows.append({"path": "/" + path, "code": r.status_code, "status": "warn", "graphql_introspection": True})
            findings.append(Finding(
                "API Exposure", f"GraphQL introspection enabled at /{path}", "high",
                "A read-only __schema introspection query succeeded, revealing the full GraphQL type/field "
                "surface including anything not intentionally documented.",
                "Disable introspection in production (most GraphQL servers have a flag for this)."))

    return rows, findings
```

- [ ] **Step 3: Write and run a verification script**

Create `verify_task4.py`:

```python
import sys
sys.path.insert(0, ".")
from app import check_api_schema_exposure

class FakeResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code

class FakeSession:
    def __init__(self, get_routes, post_routes):
        self.get_routes = get_routes
        self.post_routes = post_routes
    def get(self, url, **kwargs):
        return self.get_routes.get(url, FakeResponse("not found", 404))
    def post(self, url, **kwargs):
        return self.post_routes.get(url, FakeResponse("not found", 404))

swagger_body = '{"openapi": "3.0.0", "paths": {"/users": {}}}'
introspection_body = '{"data": {"__schema": {"types": [{"name": "Query"}]}}}'

session = FakeSession(
    get_routes={"https://example.com/v3/api-docs": FakeResponse(swagger_body)},
    post_routes={"https://example.com/graphql": FakeResponse(introspection_body)},
)

rows, findings = check_api_schema_exposure("https://example.com", session)

assert any(f.title.startswith("Publicly reachable API schema") for f in findings), findings
assert any(f.title.startswith("GraphQL introspection enabled") for f in findings), findings
assert all(f.severity == "high" for f in findings), findings
print("Task 4 verification: PASS")
```

Run: `python verify_task4.py`
Expected: `Task 4 verification: PASS`

- [ ] **Step 4: Delete the scratch script**

```bash
rm verify_task4.py
```

- [ ] **Step 5: Commit**

```bash
git add app.py
git commit -m "Add API schema/GraphQL-introspection exposure check"
```

---

## Task 5: API wordlist probing with SPA-response guard

**Files:**
- Modify: `app.py` (add `_looks_like_api_response`, `_api_path_severity`, `check_api_wordlist` after `check_api_schema_exposure`)

**Interfaces:**
- Produces: `_looks_like_api_response(resp) -> bool`, `_api_path_severity(path) -> "high"|"info"`, `check_api_wordlist(base_url, session) -> (rows, findings)`. Both helpers are reused by Task 6.

- [ ] **Step 1: Add the two small helpers and `check_api_wordlist`**

Add directly after `check_api_schema_exposure`:

```python
def _looks_like_api_response(resp):
    """True if a response looks like real API output rather than an SPA's
    catch-all index.html (which would otherwise make every wordlist path
    falsely look like a hit, since SPAs commonly return 200 for everything)."""
    ctype = resp.headers.get("Content-Type", "").lower()
    if "json" in ctype or "xml" in ctype:
        return True
    body_start = resp.text.lstrip()[:1]
    return body_start in ("{", "[")


def _api_path_severity(path):
    lower = path.lower()
    return "high" if any(hint in lower for hint in API_SENSITIVE_HINTS) else "info"


def check_api_wordlist(base_url, session):
    """Threaded probe of a small built-in wordlist of common REST-ish
    paths. A hit only counts if the response is 200 AND looks like real
    API output (see _looks_like_api_response) - otherwise SPAs that serve
    the same index.html for every path would falsely flag every entry."""
    rows, findings = [], []

    def probe(path):
        try:
            r = session.get(f"{base_url}/{path}", timeout=REQUEST_TIMEOUT)
            return path, r
        except requests.RequestException:
            return path, None

    with ThreadPoolExecutor(max_workers=8) as pool:
        for path, r in pool.map(probe, API_WORDLIST):
            if r is None or r.status_code != 200 or not _looks_like_api_response(r):
                rows.append({"path": "/" + path, "status": "pass"})
                continue
            sev = _api_path_severity(path)
            rows.append({"path": "/" + path, "status": "warn", "severity": sev})
            findings.append(Finding(
                "API Exposure", f"Unauthenticated API response at /{path}", sev,
                "Returned HTTP 200 with an API-shaped body (JSON/XML) with no authentication.",
                "Confirm this endpoint is meant to be public; otherwise require authentication."))
    return rows, findings
```

- [ ] **Step 2: Write and run a verification script**

Create `verify_task5.py`:

```python
import sys
sys.path.insert(0, ".")
from app import check_api_wordlist

class FakeResponse:
    def __init__(self, text, status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}

class FakeSession:
    def __init__(self, routes):
        self.routes = routes
    def get(self, url, **kwargs):
        return self.routes.get(url, FakeResponse("<html>spa shell</html>", 200, {"Content-Type": "text/html"}))

session = FakeSession({
    "https://example.com/api/admin": FakeResponse(
        '{"users": []}', 200, {"Content-Type": "application/json"}),
})

rows, findings = check_api_wordlist("https://example.com", session)

hit = [f for f in findings if "api/admin" in f.title]
assert len(hit) == 1 and hit[0].severity == "high", findings
# Every other wordlist path returns the SPA shell and must NOT be flagged.
assert len(findings) == 1, findings
print("Task 5 verification: PASS")
```

Run: `python verify_task5.py`
Expected: `Task 5 verification: PASS`

- [ ] **Step 3: Delete the scratch script**

```bash
rm verify_task5.py
```

- [ ] **Step 4: Commit**

```bash
git add app.py
git commit -m "Add API wordlist probe with SPA-response false-positive guard"
```

---

## Task 6: JS-based API endpoint discovery

**Files:**
- Modify: `app.py` (add `API_ENDPOINT_PATTERNS`, `_discover_api_endpoints`, `check_api_js_discovery` after `check_api_wordlist`)

**Interfaces:**
- Consumes: `_fetch_same_origin_js` (Task 1), `_looks_like_api_response` / `_api_path_severity` (Task 5).
- Produces: `check_api_js_discovery(session, base_url, home_html) -> ({"rows": [...], "endpoints_discovered": int}, findings)`.

- [ ] **Step 1: Add endpoint-pattern extraction and the check**

Add directly after `check_api_wordlist`:

```python
API_ENDPOINT_PATTERNS = [
    re.compile(r'fetch\(\s*["\']([^"\']+)["\']'),
    re.compile(r'axios\.(?:get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']'),
    re.compile(r'\.ajax\(\s*\{[^}]*?url\s*:\s*["\']([^"\']+)["\']', re.S),
    re.compile(r'["\'](/(?:api|graphql)[\w\-/]*)["\']'),
]


def _discover_api_endpoints(base_url, texts):
    """Regex-extracts API-looking paths from fetch()/axios()/.ajax() calls
    and generic /api|/graphql string literals across the given texts
    (homepage HTML + fetched JS). Third-party (cross-origin) absolute URLs
    are skipped - this discovers the target's own API, not everyone it
    talks to."""
    origin = urlparse(base_url).netloc
    found = []
    for text in texts:
        for pattern in API_ENDPOINT_PATTERNS:
            for m in pattern.finditer(text):
                candidate = m.group(1)
                if candidate.startswith("http") and urlparse(candidate).netloc != origin:
                    continue
                abs_url = urljoin(base_url + "/", candidate)
                if abs_url not in found:
                    found.append(abs_url)
    return found[:MAX_API_JS_ENDPOINTS]


def check_api_js_discovery(session, base_url, home_html):
    """Discovers API endpoints the site's own frontend code actually calls
    (from homepage HTML + same-origin JS), then probes each the same way
    as check_api_wordlist. Highest-signal of the three API checks - it
    finds real endpoints, not guessed ones."""
    js_sources = _fetch_same_origin_js(session, base_url, home_html,
                                        MAX_SECRET_JS_FILES, MAX_JS_BYTES_PER_FILE)
    texts = [home_html] + [text for _, text in js_sources]
    endpoints = _discover_api_endpoints(base_url, texts)

    rows, findings = [], []

    def probe(url):
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT)
            return url, r
        except requests.RequestException:
            return url, None

    with ThreadPoolExecutor(max_workers=8) as pool:
        for url, r in pool.map(probe, endpoints):
            if r is None or r.status_code != 200 or not _looks_like_api_response(r):
                rows.append({"url": url, "status": "pass"})
                continue
            sev = _api_path_severity(urlparse(url).path)
            rows.append({"url": url, "status": "warn", "severity": sev})
            findings.append(Finding(
                "API Exposure", f"JS-referenced endpoint responds without auth: {url}", sev,
                "This endpoint is called from the site's own frontend code and returned an API-shaped "
                "response with no authentication.",
                "Confirm this endpoint is meant to be public; otherwise require authentication."))
    return {"rows": rows, "endpoints_discovered": len(endpoints)}, findings
```

- [ ] **Step 2: Write and run a verification script**

Create `verify_task6.py`:

```python
import sys
sys.path.insert(0, ".")
from app import check_api_js_discovery

class FakeResponse:
    def __init__(self, text, status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
    def iter_content(self, chunk_size=16384):
        data = self.text.encode()
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]
    def close(self):
        pass

class FakeSession:
    def __init__(self, routes):
        self.routes = routes
    def get(self, url, **kwargs):
        return self.routes.get(url, FakeResponse("not found", 404))

home_html = '<html><script src="/bundle.js"></script></html>'
js_body = 'fetch("/api/internal/orders").then(r => r.json());'
api_body = '{"orders": []}'

session = FakeSession({
    "https://example.com/bundle.js": FakeResponse(js_body),
    "https://example.com/api/internal/orders": FakeResponse(
        api_body, 200, {"Content-Type": "application/json"}),
})

data, findings = check_api_js_discovery(session, "https://example.com", home_html)

assert data["endpoints_discovered"] == 1, data
assert len(findings) == 1, findings
assert findings[0].severity == "high", findings[0]  # "internal" is a sensitive hint
assert "api/internal/orders" in findings[0].title
print("Task 6 verification: PASS")
```

Run: `python verify_task6.py`
Expected: `Task 6 verification: PASS`

- [ ] **Step 3: Delete the scratch script**

```bash
rm verify_task6.py
```

- [ ] **Step 4: Commit**

```bash
git add app.py
git commit -m "Add JS-based API endpoint discovery check"
```

---

## Task 7: `run_api_scan` orchestrator

**Files:**
- Modify: `app.py` (add `run_api_scan` after `run_media_scan`, ~line 996, before the "Advanced / authenticated checks" section banner)

**Interfaces:**
- Consumes: `check_api_schema_exposure`, `check_api_wordlist`, `check_api_js_discovery` (Tasks 4-6).
- Produces: `run_api_scan(base_url) -> dict` — a report dict with `target`, `hostname`, `scanned_at`, `score`, `risk_grade`, `severity_counts`, `findings`, `results` (keyed `schema`/`wordlist`/`js_discovery`). Same shape convention as `run_scan`/`run_media_scan`/`run_advanced_scan`.

- [ ] **Step 1: Add `run_api_scan`**

```python
def run_api_scan(base_url):
    """Runs all three API-exposure checks against base_url. Uses the same
    Finding/severity/scoring model as the other three orchestrators."""
    session = _mk_session()
    try:
        home_r = session.get(base_url + "/", timeout=REQUEST_TIMEOUT)
        home_html = home_r.text
    except requests.RequestException:
        home_html = ""

    results = {}
    all_findings = []

    data, findings = check_api_schema_exposure(base_url, session)
    results["schema"] = data
    all_findings.extend(findings)

    data, findings = check_api_wordlist(base_url, session)
    results["wordlist"] = data
    all_findings.extend(findings)

    data, findings = check_api_js_discovery(session, base_url, home_html)
    results["js_discovery"] = data
    all_findings.extend(findings)

    score = 100
    for f in all_findings:
        score -= SEVERITY_WEIGHT.get(f.severity, 0)
    score = max(0, min(100, score))
    risk_grade = ("A" if score >= 90 else "B" if score >= 75 else
                  "C" if score >= 60 else "D" if score >= 40 else "F")

    severity_counts = {s: 0 for s in SEVERITY_WEIGHT}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    findings_sorted = sorted(all_findings, key=lambda f: SEVERITY_ORDER.index(f.severity))

    return {
        "target": base_url,
        "hostname": urlparse(base_url).netloc,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "risk_grade": risk_grade,
        "severity_counts": severity_counts,
        "findings": [asdict(f) for f in findings_sorted],
        "results": results,
    }
```

- [ ] **Step 2: Write and run a verification script**

Create `verify_task7.py`:

```python
import sys
sys.path.insert(0, ".")
import app as app_module

# Stub out the three sub-checks so this test exercises only the
# orchestration/scoring logic, not network behavior already covered by
# Tasks 4-6's own verification scripts.
app_module.check_api_schema_exposure = lambda base_url, session: (
    [{"path": "/graphql", "code": 200, "status": "warn"}],
    [app_module.Finding("API Exposure", "GraphQL introspection enabled at /graphql", "high", "d", "r")])
app_module.check_api_wordlist = lambda base_url, session: ([], [])
app_module.check_api_js_discovery = lambda session, base_url, home_html: ({"rows": [], "endpoints_discovered": 0}, [])

class FakeResponse:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code

class FakeSession:
    def get(self, url, **kwargs):
        return FakeResponse("<html></html>")

app_module._mk_session = lambda: FakeSession()

report = app_module.run_api_scan("https://example.com")

assert report["hostname"] == "example.com", report
assert report["score"] == 85, report  # 100 - 15 (high)
assert report["risk_grade"] == "B", report
assert report["severity_counts"]["high"] == 1, report
assert list(report["results"].keys()) == ["schema", "wordlist", "js_discovery"], report
print("Task 7 verification: PASS")
```

Run: `python verify_task7.py`
Expected: `Task 7 verification: PASS`

- [ ] **Step 3: Delete the scratch script**

```bash
rm verify_task7.py
```

- [ ] **Step 4: Commit**

```bash
git add app.py
git commit -m "Add run_api_scan orchestrator"
```

---

## Task 8: `/scan-api` Flask route + index.html form section

**Files:**
- Modify: `app.py` (add `scan_api` route after `scan_media`, ~line 1554)
- Modify: `templates/index.html` (add a fourth `<details class="adv-details">` card after the "Media discovery" card, ~line 247; register the form's submit handler in the `<script>` block, ~line 278)

**Interfaces:**
- Consumes: `run_api_scan` (Task 7).
- Produces: `POST /scan-api` route, renders `templates/api_results.html` (created in Task 9) with `r=report, report_file=fname`.

- [ ] **Step 1: Add the Flask route**

Add directly after `scan_media` (before `if __name__ == "__main__":`):

```python
@app.route("/scan-api", methods=["POST"])
def scan_api():
    if not request.form.get("authorized_api"):
        return render_template("index.html",
                                error="You must confirm you own or are authorized to test this domain.")

    base_url = normalize_target(request.form.get("api_target", ""))
    if not base_url:
        return render_template("index.html", error="Enter a valid domain or URL for the API scan, e.g. example.com")

    try:
        report = run_api_scan(base_url)
    except requests.RequestException as e:
        return render_template("index.html", error=f"Could not reach {base_url}: {e}")

    fname = f"api_{report['hostname'].replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(os.path.join(REPORTS_DIR, fname), "w", encoding="utf-8") as f_out:
        json.dump(report, f_out, indent=2)

    return render_template("api_results.html", r=report, report_file=fname)
```

- [ ] **Step 2: Add the form section to `index.html`**

Insert a new card directly after the closing `</div>` of the "Media discovery (optional)" card (i.e. right after the `</details>\n    </div>` block that ends the media card, before the `<footer>` line):

```html
    <div class="card" style="margin-top:20px;">
      <details class="adv-details" open>
        <summary style="padding-left:0;"><span style="font-size:16px; font-weight:700;">API exposure scan (optional)</span> <span class="arrow">&#9656;</span></summary>
        <div class="adv-body" style="padding-left:0; padding-right:0;">
          <p class="hint" style="margin-top:2px;">Runs separately from the scan above. Probes for publicly
          reachable OpenAPI/Swagger docs and GraphQL introspection, checks a small wordlist of common
          unauthenticated API paths, and discovers real endpoints referenced in the site's own JavaScript
          (e.g. <code>fetch("/api/...")</code>) - the highest-signal of the three, since it finds endpoints the
          app actually calls rather than ones a wordlist happens to guess.</p>

          <form method="POST" action="/scan-api" id="apiForm">
            <label for="api_target">Target domain</label>
            <input type="text" id="api_target" name="api_target" placeholder="www.nextlevelhub.xyz" required>

            <div class="check-row">
              <input type="checkbox" id="authorized_api" name="authorized_api" required>
              <label for="authorized_api" style="margin:0; font-weight:500;">
                I own this domain, or I have explicit authorization to security-test it.
              </label>
            </div>

            <button type="submit">Run API exposure scan</button>
          </form>
        </div>
      </details>
    </div>
```

- [ ] **Step 3: Add the submit-overlay handler**

In the `<script>` block, directly after the `mediaForm` listener's closing `});`, add:

```javascript
    document.getElementById('apiForm').addEventListener('submit', function () {
      if (this.checkValidity()) {
        document.getElementById('overlayText').textContent = 'Scanning for exposed APIs…';
        document.getElementById('overlaySmall').textContent = 'Probing schema/docs paths, a wordlist, and JS-discovered endpoints.';
        document.getElementById('overlay').classList.add('show');
      }
    });
```

- [ ] **Step 4: Manual verification**

This task wires Flask routing/templating, which is best verified by actually running the app (no network target needed to prove the route is reachable and validates its inputs):

```bash
python app.py &
sleep 1
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:5000/scan-api -d "api_target=example.com"
```

Expected: `200` (the missing `authorized_api` checkbox re-renders `index.html` with an error, which is still a `200`) — confirms the route exists and doesn't 404/500. Then stop the server:

```bash
kill %1
```

- [ ] **Step 5: Commit**

```bash
git add app.py templates/index.html
git commit -m "Add /scan-api route and API exposure scan form section"
```

---

## Task 9: `templates/api_results.html`

**Files:**
- Create: `templates/api_results.html`

**Interfaces:**
- Consumes: the report dict shape produced by `run_api_scan` (Task 7): `r.hostname`, `r.scanned_at`, `r.score`, `r.risk_grade`, `r.severity_counts`, `r.findings`, `r.results.schema`, `r.results.wordlist`, `r.results.js_discovery`.

- [ ] **Step 1: Create the template**

Base it on `templates/advanced_results.html` (same head/style block, same score-card/findings-list structure — copy lines 1-136 of `advanced_results.html` verbatim except the `<title>` and `<h1>`/meta text), then replace its "Detailed check output" section with:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>API exposure results - {{ r.hostname }}</title>
<style>
  :root {
    --bg: #0b1020; --panel: #121a33; --panel2: #0e1530; --border: #23305c;
    --text: #e8ecff; --muted: #93a0c9; --accent: #5b8cff; --accent2: #8b6bff;
    --critical:#fb7185; --high:#fb923c; --medium:#fbbf24; --low:#60a5fa; --info:#93a0c9; --pass:#34d399;
  }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f4f6fb; --panel:#ffffff; --panel2:#f0f3fb; --border:#dde3f3; --text:#141a33; --muted:#5a6689; }
  }
  * { box-sizing: border-box; }
  body {
    margin:0; font-family: -apple-system, "Segoe UI", Inter, Arial, sans-serif;
    background: radial-gradient(1200px 600px at 80% -10%, rgba(91,140,255,.14), transparent), var(--bg);
    color: var(--text);
  }
  .wrap { max-width: 1040px; margin: 0 auto; padding: 40px 20px 90px; }
  .top { display:flex; justify-content:space-between; align-items:flex-start; gap: 20px; flex-wrap: wrap; }
  h1 { font-size: 26px; margin: 0 0 4px; }
  .meta { color: var(--muted); font-size: 13px; }
  .meta code { background: rgba(255,255,255,.06); padding: 1px 6px; border-radius: 5px; }
  a.back { color: var(--accent); text-decoration:none; font-size: 13.5px; }

  .score-card { display:flex; align-items:center; gap:20px; background: linear-gradient(180deg,var(--panel),var(--panel2)); border:1px solid var(--border); border-radius:16px; padding:20px 26px; margin-top:22px; }
  .gauge-wrap { position:relative; width:110px; height:110px; flex-shrink:0; }
  .gauge-wrap svg { transform: rotate(-90deg); }
  .gauge-bg { fill:none; stroke: rgba(255,255,255,.08); stroke-width: 10; }
  .gauge-fg { fill:none; stroke-width: 10; stroke-linecap: round; transition: stroke-dashoffset 1s ease; }
  .gauge-num { position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; }
  .gauge-num .n { font-size: 26px; font-weight: 800; }
  .gauge-num .g { font-size: 11px; color: var(--muted); }
  .score-summary h2 { margin: 0 0 6px; font-size: 18px; }
  .sev-pills { display:flex; gap:8px; flex-wrap:wrap; }
  .pill { font-size:12px; font-weight:700; padding:4px 10px; border-radius:999px; }
  .pill.critical { background: rgba(251,113,133,.15); color: var(--critical); }
  .pill.high { background: rgba(251,146,60,.15); color: var(--high); }
  .pill.medium { background: rgba(251,191,36,.15); color: var(--medium); }
  .pill.low { background: rgba(96,165,250,.15); color: var(--low); }
  .pill.info { background: rgba(147,160,201,.15); color: var(--info); }
  .pill.pass { background: rgba(52,211,153,.15); color: var(--pass); }

  h2.section { font-size: 15px; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; margin: 36px 0 12px; }

  .finding { display:flex; gap:14px; background: var(--panel); border:1px solid var(--border); border-left: 4px solid var(--muted); border-radius: 12px; padding: 14px 16px; margin-bottom: 10px; }
  .finding.critical { border-left-color: var(--critical); }
  .finding.high { border-left-color: var(--high); }
  .finding.medium { border-left-color: var(--medium); }
  .finding.low { border-left-color: var(--low); }
  .finding.info { border-left-color: var(--info); }
  .finding .badge { flex-shrink:0; font-size:11px; font-weight:800; padding: 3px 9px; border-radius: 6px; text-transform: uppercase; letter-spacing:.03em; height: fit-content; }
  .finding.critical .badge { background: rgba(251,113,133,.15); color: var(--critical); }
  .finding.high .badge { background: rgba(251,146,60,.15); color: var(--high); }
  .finding.medium .badge { background: rgba(251,191,36,.15); color: var(--medium); }
  .finding.low .badge { background: rgba(96,165,250,.15); color: var(--low); }
  .finding .body b { font-size: 14px; }
  .finding .cat { color: var(--muted); font-size: 11.5px; text-transform:uppercase; letter-spacing:.05em; }
  .finding .detail { font-size: 13.5px; color: var(--muted); margin-top: 4px; }
  .finding .rec { font-size: 13px; margin-top: 6px; }
  .finding .rec b { color: var(--accent); font-weight: 700; }
  .empty { color: var(--muted); font-size: 14px; padding: 18px 0; }

  details { background: var(--panel); border:1px solid var(--border); border-radius: 12px; margin-bottom: 8px; overflow:hidden; }
  summary { padding: 13px 16px; cursor: pointer; font-weight: 600; font-size: 14px; list-style: none; display:flex; justify-content: space-between; align-items:center; }
  summary::-webkit-details-marker { display: none; }
  summary .arrow { transition: transform .15s; color: var(--muted); }
  details[open] summary .arrow { transform: rotate(90deg); }
  .details-body { padding: 4px 16px 16px; overflow-x: auto; }

  table { width:100%; border-collapse: collapse; font-size: 12.5px; }
  th, td { text-align:left; padding: 7px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--muted); font-weight:600; }
  code { background: rgba(255,255,255,.06); padding: 1px 5px; border-radius: 5px; font-size: 11.5px; word-break: break-all; }
  .note { color: var(--muted); font-size: 12.5px; }
  td.critical, span.critical { color: var(--critical); }
  td.high, span.high { color: var(--high); }
  td.medium, span.medium { color: var(--medium); }
  td.pass, span.pass { color: var(--pass); }
  td.info, span.info { color: var(--info); }
</style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1>API exposure scan results</h1>
        <div class="meta">
          Target: <code>{{ r.hostname }}</code> &middot; {{ r.scanned_at }}
          &middot; saved as <code>reports/{{ report_file }}</code>
        </div>
      </div>
      <a class="back" href="/">&larr; Run another scan</a>
    </div>

    <div class="score-card">
      <div class="gauge-wrap">
        <svg width="110" height="110" viewBox="0 0 110 110">
          <circle class="gauge-bg" cx="55" cy="55" r="46"></circle>
          <circle class="gauge-fg"
                   id="gaugeFg" cx="55" cy="55" r="46"
                   stroke="{{ '#34d399' if r.score >= 90 else ('#fbbf24' if r.score >= 60 else ('#fb923c' if r.score >= 40 else '#fb7185')) }}"
                   stroke-dasharray="289" stroke-dashoffset="289"></circle>
        </svg>
        <div class="gauge-num"><div class="n">{{ r.score }}</div><div class="g">grade {{ r.risk_grade }}</div></div>
      </div>
      <div class="score-summary">
        <h2>API exposure risk score</h2>
        <div class="sev-pills">
          {% for sev in ['critical','high','medium','low','info'] %}
            {% if r.severity_counts.get(sev, 0) > 0 %}
            <span class="pill {{ sev }}">{{ r.severity_counts[sev] }} {{ sev }}</span>
            {% endif %}
          {% endfor %}
          {% if r.findings|length == 0 %}<span class="pill pass">No findings</span>{% endif %}
        </div>
      </div>
    </div>

    <h2 class="section">Findings ({{ r.findings|length }})</h2>
    {% if r.findings|length > 0 %}
    <div>
      {% for f in r.findings %}
      <div class="finding {{ f.severity }}">
        <span class="badge">{{ f.severity }}</span>
        <div class="body">
          <div class="cat">{{ f.category }}</div>
          <b>{{ f.title }}</b>
          <div class="detail">{{ f.detail }}</div>
          {% if f.recommendation %}<div class="rec"><b>Fix:</b> {{ f.recommendation }}</div>{% endif %}
        </div>
      </div>
      {% endfor %}
    </div>
    {% else %}
    <div class="empty">No exposed schema/docs, unauthenticated wordlist paths, or JS-discovered endpoints found.
    This only covers what these three checks found - treat it as one data point, not a guarantee.</div>
    {% endif %}

    <h2 class="section">Detailed check output</h2>

    <details open>
      <summary>Schema / GraphQL introspection <span class="arrow">&#9656;</span></summary>
      <div class="details-body">
        <table><tr><th>Path</th><th>Code</th><th>Status</th></tr>
          {% for row in r.results.schema %}
          <tr><td><code>{{ row.path }}</code></td><td>{{ row.code }}</td>
            <td class="{{ 'high' if row.status == 'warn' else 'pass' }}">{{ row.status }}</td></tr>
          {% endfor %}
        </table>
      </div>
    </details>

    <details open>
      <summary>Common API path wordlist <span class="arrow">&#9656;</span></summary>
      <div class="details-body">
        <table><tr><th>Path</th><th>Status</th></tr>
          {% for row in r.results.wordlist %}
          <tr><td><code>{{ row.path }}</code></td>
            <td class="{{ row.severity if row.status == 'warn' else 'pass' }}">{{ row.status }}</td></tr>
          {% endfor %}
        </table>
      </div>
    </details>

    <details open>
      <summary>JS-discovered endpoints ({{ r.results.js_discovery.endpoints_discovered }} found) <span class="arrow">&#9656;</span></summary>
      <div class="details-body">
        <table><tr><th>URL</th><th>Status</th></tr>
          {% for row in r.results.js_discovery.rows %}
          <tr><td><code>{{ row.url }}</code></td>
            <td class="{{ row.severity if row.status == 'warn' else 'pass' }}">{{ row.status }}</td></tr>
          {% endfor %}
        </table>
      </div>
    </details>
  </div>

  <script>
    const score = {{ r.score }};
    const circumference = 2 * Math.PI * 46;
    const fg = document.getElementById('gaugeFg');
    fg.setAttribute('stroke-dasharray', circumference);
    fg.setAttribute('stroke-dashoffset', circumference);
    requestAnimationFrame(() => {
      fg.style.strokeDashoffset = circumference * (1 - score / 100);
    });
  </script>
</body>
</html>
```

- [ ] **Step 2: Manual verification**

```bash
python -c "
import sys; sys.path.insert(0, '.')
from flask import Flask
from app import app
with app.test_request_context():
    from flask import render_template
    html = render_template('api_results.html', r={
        'hostname': 'example.com', 'scanned_at': '2026-08-05T00:00:00Z',
        'score': 85, 'risk_grade': 'B', 'severity_counts': {'high': 1},
        'findings': [{'severity': 'high', 'category': 'API Exposure', 'title': 't', 'detail': 'd', 'recommendation': 'r'}],
        'results': {'schema': [], 'wordlist': [], 'js_discovery': {'rows': [], 'endpoints_discovered': 0}},
    }, report_file='api_example.com_20260805_000000.json')
    assert 'API exposure scan results' in html
    print('Task 9 verification: PASS')
"
```

Expected: `Task 9 verification: PASS`

- [ ] **Step 3: Commit**

```bash
git add templates/api_results.html
git commit -m "Add api_results.html template"
```

---

## Task 10: Update `CLAUDE.md` and `README.md`

**Files:**
- Modify: `CLAUDE.md` (pipeline table + "Adding a new base-scan check" context)
- Modify: `README.md` ("What it checks" list)

**Interfaces:** None (documentation only).

- [ ] **Step 1: Update `CLAUDE.md`'s pipeline table**

In the "Three independent scan pipelines" table, add a fourth row:

```markdown
| `POST /scan-api` | `run_api_scan()` | `api_results.html` | API exposure: OpenAPI/Swagger/GraphQL-introspection exposure, an unauthenticated-common-path wordlist (with an SPA-response guard), and endpoints discovered from the site's own JS. |
```

Update the table's intro line from "Three independent scan pipelines" to "Four independent scan pipelines" (heading and prose).

Also add a short note under "Safety constraints baked into the design":

```markdown
- API probing (`check_api_wordlist`, `check_api_js_discovery`) only counts a `200` as a hit if the
  response actually looks like API output (JSON/XML content-type or a `{`/`[`-leading body) - guards
  against SPAs that return their `index.html` shell for every path.
```

- [ ] **Step 2: Update `README.md`'s feature list**

Add these bullets to "What it checks" (after the existing "Reflected-XSS canary..." bullet):

```markdown
- API exposure: publicly reachable OpenAPI/Swagger docs, GraphQL introspection, a
  small wordlist of common unauthenticated API paths (SPA-response-guarded to avoid
  false positives), and endpoints discovered directly from the site's own JavaScript
- HLS/DASH video stream discovery in the media scan, verified against the actual
  manifest content (not just a URL pattern match) before being reported
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "Document API exposure scan and media stream discovery"
```

---

## Self-Review Notes (completed during plan authoring)

- **Spec coverage:** All three API-exposure checks (schema/GraphQL, wordlist, JS-discovery), the shared JS-fetch refactor, HLS/DASH discovery + verification, and both templates/docs are covered by Tasks 1-10. Nothing from the approved spec is missing.
- **Placeholder scan:** No TBD/TODO; every code step has real, complete code.
- **Type consistency:** `crawl_media`'s new 4-tuple return is used consistently by `check_media` (Task 3); `_fetch_same_origin_js`'s `(session, base_url, page_html, max_files, max_bytes)` signature is identical at all three call sites (Tasks 1, 2, 6); `_looks_like_api_response`/`_api_path_severity` (Task 5) are reused unmodified by Task 6.
