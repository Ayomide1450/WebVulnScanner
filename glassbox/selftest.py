"""Built-in detection verification engine (Phase 21 / ST-01..06; user-facing
surface redesigned 2026-08-24 per user direction).

Spins up an ephemeral, loopback-only HTTP listener hosting deliberately
vulnerable endpoints ("the lure"), runs the ten Phase-20 intrusive checks
against it in-process using the exact same check functions and crawl
machinery a real scan uses, then compares what fired against a known-good
expectations matrix - five positives that MUST fire, five negatives that
MUST stay silent.

Why this exists: a clean scan of a real site cannot distinguish "the checks
work" from "the checks are silently broken". The lure gives the suite a
target with known ground truth, entirely inside the Glassbox process -
nothing is exposed on any external interface, no Scan row is ever created,
and the SSRF guard's route-level protections are untouched because no
user-supplied URL participates anywhere (the target address is generated
here and never leaves 127.0.0.1).

The traversal lure serves a DECOY passwd file when the probe escapes to
`etc/passwd`, so detection verifies identically on every OS (on POSIX hosts
a real read would return the same marker lines; the decoy simply makes the
ground truth deterministic everywhere).

User-facing surface (2026-08-24 decision): there is deliberately NO standalone
/selftest page or dashboard button anymore - users read a separate pass/fail
matrix page as "another scanner: which domain does THIS one hit?", exactly the
confusion the loopback design exists to avoid. Instead, `run_scan()` calls
`verification_summary()` at the end of its pipeline and attaches the result to
the report as `detection_verified`, which scan_report.html renders as an
"Engine verified" badge next to the risk score. The relationship is now
unambiguous: the lure proves the engine works; the user's own domain is what
the engine's verdicts are about. The matrix itself is cached once per worker
process (deploy lifetime) so scans don't pay the lure's runtime on every run.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import requests
from jinja2 import Template

from glassbox.checks import (
    check_cache_deception,
    check_crlf_injection,
    check_csrf_posture,
    check_graphql_deep,
    check_host_header,
    check_jwt_active,
    check_path_traversal,
    check_rate_limit_posture,
    check_ssti,
    check_subdomain_takeover,
    crawl_same_origin,
)

_JWT_SECRET = b"glassbox-selftest-lure-secret"
_DECOY_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
)


def _mint_token():
    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": "selftest-user", "role": "user",
                              "exp": int(time.time()) + 3600}).encode())
    sig = b64(hmac.new(_JWT_SECRET, f"{header}.{payload}".encode(),
                       hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def _token_state(raw):
    try:
        header_b64, payload_b64, sig_b64 = raw.split(".")
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    except Exception:
        return "invalid"
    if header.get("alg") == "none":
        return "forged"
    if header.get("alg") != "HS256":
        return "invalid"
    expected = base64.urlsafe_b64encode(hmac.new(
        _JWT_SECRET, f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256).digest()).rstrip(b"=").decode()
    return "valid" if hmac.compare_digest(expected, sig_b64) else "invalid"


class _LureHandler(BaseHTTPRequestHandler):
    server_version = "GlassboxSelfTestLure/1"

    def log_message(self, *args):
        pass

    def _reply(self, body, status=200, ctype="text/html; charset=utf-8",
               extra_headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _set_cookie_if_absent(self, headers):
        if not self.headers.get("Cookie"):
            headers["Set-Cookie"] = f"auth_token={_mint_token()}; Path=/"

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/robots.txt":
            self._reply("User-agent: *\nAllow: /\n", ctype="text/plain")
        elif path == "/":
            state = "anonymous"
            tok = _parse_cookie(self.headers.get("Cookie"), "auth_token")
            if tok:
                state = _token_state(tok)
                if state == "invalid":
                    self._reply("401 invalid credentials", status=401)
                    return
            who = ("Welcome back, selftest-user (authenticated via JWT)"
                   if state in ("valid", "forged") else
                   "Glassbox detection self-test lure - anonymous view.")
            headers = {}
            self._set_cookie_if_absent(headers)
            self._reply(_HOME_HTML.format(who=who), extra_headers=headers)
        elif path == "/ssti":
            qs = parse_qs(urlparse(self.path).query)
            name = (qs.get("name") or [""])[0]
            self._reply(Template("Hello " + name + "!").render())
        elif path == "/download":
            qs = parse_qs(urlparse(self.path).query)
            fname = (qs.get("file") or [""])[0]
            target = os.path.normpath(os.path.join(self.server.file_root, fname))
            if target.replace("\\", "/").endswith("/etc/passwd"):
                self._reply(_DECOY_PASSWD, ctype="text/plain")
            elif os.path.isfile(target):
                with open(target, "r", errors="replace") as fh:
                    self._reply(fh.read(), ctype="text/plain")
            else:
                self._reply("404 no such file", status=404)
        elif path == "/docs":
            qs = parse_qs(urlparse(self.path).query)
            page = (qs.get("page") or [""])[0]
            self._reply(f"<h1>Docs: {page}</h1>")
        elif path == "/login":
            self.server.login_hits += 1
            if self.server.login_hits > 3:
                self._reply("429 too many attempts", status=429,
                            ctype="text/plain")
            else:
                self._reply("<form method='post' action='/login'>"
                            "<input name='username'><input name='password' "
                            "type='password'></form>")
        else:
            self._reply("404 not found", status=404)

    def do_POST(self):
        if urlparse(self.path).path == "/graphql":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode() if length else ""
            if "__zzzNoSuchField" in raw:
                self._reply(json.dumps({
                    "errors": [{"message": "Cannot query field "
                                "'__zzzNoSuchField'. Did you mean '__schema'?"}]}),
                    ctype="application/json")
            else:
                self._reply(json.dumps(
                    {"data": {"__schema": {"queryType": {"name": "Query"}}}}),
                    ctype="application/json")
        else:
            self._reply("405 method not allowed", status=405)


def _parse_cookie(header, name):
    for part in (header or "").split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            if k == name:
                return v
    return None


_HOME_HTML = """<!doctype html><html><body>
<h1>Glassbox self-test lure</h1>
<p>{who}</p>
<form method="post" action="/login">
  <input name="username"><input name="password" type="password">
  <button type="submit">Sign in</button>
</form>
<ul>
  <li><a href="/ssti?name=Visitor">Template demo</a></li>
  <li><a href="/download?file=manual.pdf">Operator manual</a></li>
  <li><a href="/docs?page=overview">Docs viewer</a></li>
  <li>API: POST /graphql</li>
</ul>
</body></html>"""


def start_lure_listener():
    """Binds a ThreadingHTTPServer to 127.0.0.1 on an ephemeral port.
    Returns (server, base_url); caller MUST call server.shutdown() +
    server.server_close() (run_selftest does both in finally)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LureHandler)
    server.daemon_threads = True
    # Per-instance state so every listener starts with identical ground
    # truth (a module-level counter made repeated in-process runs see a
    # permanently pre-throttled /login).
    server.login_hits = 0
    file_root = tempfile.mkdtemp(prefix="glassbox-lure-")
    with open(os.path.join(file_root, "manual.pdf"), "w") as fh:
        fh.write("Self-test lure operator manual.\n")
    server.file_root = file_root
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    return server, f"http://{host}:{port}"


# (check_name, expect_finding, required_severities). Positives prove
# sensitivity; negatives prove specificity - a false positive on the lure's
# clean surfaces fails the matrix exactly like a missed detection does.
EXPECTATIONS = [
    ("ssti", True, {"critical"}),
    ("path_traversal", True, {"critical"}),
    ("jwt_active", True, {"critical"}),
    ("graphql_deep", True, {"medium"}),
    ("csrf_posture", True, set()),
    ("host_header", False, set()),
    ("crlf", False, set()),
    ("rate_limit", False, set()),
    ("cache_deception", False, set()),
    ("subdomain_takeover", False, set()),
]


def run_selftest():
    """Runs all ten checks against the in-process lure and returns
    {passed, duration_ms, results: [{name, ran, expect_finding, matched,
    findings: [{severity, title}], error?}]}. Never raises past cleanup;
    per-check exceptions are captured as that row's error."""
    started = time.monotonic()
    server, base_url = start_lure_listener()
    results = []
    passed = True
    try:
        session = requests.Session()
        home = session.get(base_url + "/", timeout=10)
        home_html = home.text
        param_urls, forms = crawl_same_origin(base_url, home_html,
                                              limit=10, session=session)
        hostname = urlparse(base_url).netloc
        jobs = {
            "ssti": lambda: check_ssti(param_urls, session),
            "path_traversal": lambda: check_path_traversal(param_urls, session),
            "jwt_active": lambda: check_jwt_active(session, base_url, home_html),
            "graphql_deep": lambda: check_graphql_deep(base_url, session),
            "csrf_posture": lambda: check_csrf_posture(forms),
            "host_header": lambda: check_host_header(base_url, session),
            "crlf": lambda: check_crlf_injection(param_urls, session),
            "rate_limit": lambda: check_rate_limit_posture(base_url, session),
            "cache_deception": lambda: check_cache_deception(base_url, session),
            "subdomain_takeover": lambda: check_subdomain_takeover(hostname),
        }
        for name, expect_finding, required_sevs in EXPECTATIONS:
            row = {"name": name, "ran": True, "expect_finding": expect_finding,
                   "findings": [], "error": None}
            try:
                _data, findings = jobs[name]()
                row["findings"] = [{"severity": f.severity, "title": f.title}
                                   for f in findings]
                severities = {f.severity for f in findings}
                has_any = bool(findings)
                if expect_finding:
                    matched = has_any and (
                        not required_sevs or bool(severities & required_sevs))
                else:
                    matched = not has_any
            except Exception as exc:  # noqa: BLE001 - one bad check must not
                # kill the matrix; surface it as a failed expectation instead.
                matched = False
                row["error"] = f"{type(exc).__name__}: {exc}"
            row["matched"] = matched
            if not matched:
                passed = False
            results.append(row)
    finally:
        server.shutdown()
        server.server_close()
    return {"passed": passed,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "results": results}


# ---------------------------------------------------------------------------
# Per-process cache + report badge summary (2026-08-24 redesign)
#
# run_scan() ends every base scan by attaching verification_summary()'s
# result as report["detection_verified"]. The full matrix runs at most once
# per worker process (a gunicorn worker lives for one deploy), so a scan
# never pays the lure's startup + ten-check runtime more than the first
# time; every later scan reads the cache. A raised exception is NOT cached -
# the next scan retries, and the current scan simply omits the badge rather
# than failing (same degrade-gracefully convention as every check_*).
# ---------------------------------------------------------------------------

_verification_cache = None
_verification_lock = threading.Lock()


def detection_verification(force_refresh=False):
    """The full matrix report ({passed, duration_ms, results}), computed once
    per process and cached; None if this attempt errored (uncached - retried
    on a later scan)."""
    global _verification_cache
    if _verification_cache is not None and not force_refresh:
        return _verification_cache
    with _verification_lock:
        if _verification_cache is None or force_refresh:
            try:
                _verification_cache = run_selftest()
            except Exception as exc:  # noqa: BLE001 - never fail a real scan
                logging.warning(
                    "detection verification unavailable this scan (will retry "
                    "on the next): %s: %s", type(exc).__name__, exc,
                )
                return None
    return _verification_cache


def reset_detection_verification_cache():
    """Test hook - drops the cache so a test can observe a fresh compute."""
    global _verification_cache
    with _verification_lock:
        _verification_cache = None


def verification_summary(force_refresh=False):
    """The compact dict run_scan() embeds in reports, or None when
    verification couldn't run. Shape:
    {passed, confirmed, total, duration_ms, failed: [check names]}."""
    matrix = detection_verification(force_refresh=force_refresh)
    if matrix is None:
        return None
    return {
        "passed": matrix["passed"],
        "confirmed": sum(1 for row in matrix["results"] if row["matched"]),
        "total": len(matrix["results"]),
        "duration_ms": matrix["duration_ms"],
        "failed": [row["name"] for row in matrix["results"] if not row["matched"]],
    }
