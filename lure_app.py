"""Glassbox Phase-20 lure app - deliberately vulnerable endpoints for
positive-detection verification ONLY. Never deploy this to production.

Lures implemented (each mirrors what webvulnscanner/checks.py probes):
  SSTI        GET /ssti?name=...        -> reflects input through Jinja;
                                            {{77*88}} must yield 6776.
  TRAVERSAL   GET /download?file=...    -> unsanitized join; the probe sends
                                            ../../../../../etc/passwd which
                                            reads the REAL /etc/passwd on a
                                            Linux host (root:x:0:0 marker).
  GRAPHQL     POST /graphql             -> introspection ENABLED; also leaks
                                            "Did you mean" suggestions.
  JWT         cookie auth_token on /    -> accepts HS256 (real) AND alg:none
                                            forgeries, rejects bad signatures
                                            (control) - exactly the acceptance
                                            matrix check_jwt_active measures.

Run:  pip install flask && python lure_app.py   (listens on :8000)
"""

import base64
import hashlib
import hmac
import json
import os
import time

from flask import Flask, Response, request
from jinja2 import Template

APP = Flask(__name__)
JWT_SECRET = b"lure-secret-key-do-not-use-anywhere-real"
FILE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "srv_files")


def _mint_token():
    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": "demo-user", "role": "user",
                              "exp": int(time.time()) + 86400}).encode())
    sig = b64(hmac.new(JWT_SECRET, f"{header}.{payload}".encode(),
                       hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def _token_state(raw_token):
    """Returns 'valid', 'alg-none-forgery', or 'invalid'."""
    try:
        header_b64, payload_b64, sig_b64 = raw_token.split(".")
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    except Exception:
        return "invalid"
    if header.get("alg") == "none":
        return "alg-none-forgery"
    if header.get("alg") != "HS256":
        return "invalid"
    try:
        expected = base64.urlsafe_b64encode(hmac.new(
            JWT_SECRET, f"{header_b64}.{payload_b64}".encode(),
            hashlib.sha256).digest()).rstrip(b"=").decode()
        if hmac.compare_digest(expected, sig_b64):
            return "valid"
    except Exception:
        pass
    return "invalid"


@APP.after_request
def _jwt_cookie(resp):
    # Mint only for anonymous visitors - rotating the cookie on every
    # response would re-seed a scanner's cookie jar between replay probes.
    if not request.cookies.get("auth_token"):
        resp.set_cookie("auth_token", _mint_token(), httponly=False, samesite=None)
    return resp


@APP.route("/")
def home():
    state = "anonymous"
    tok = request.cookies.get("auth_token")
    if tok:
        state = _token_state(tok)
    if state == "invalid":
        return Response("401 Invalid credentials", status=401)
    who = ("Welcome back, demo-user (authenticated via JWT)"
           if state in ("valid", "alg-none-forgery") else
           "Public landing page - you are not logged in.")
    return f"""<!doctype html><html><body>
<h1>Glassbox Lure Site</h1>
<p>{who}</p>
<ul>
  <li><a href="/ssti?name=Visitor">Template demo</a></li>
  <li><a href="/download?file=manual.pdf">Download the manual</a></li>
  <li><a href="/docs?page=overview">Docs viewer</a></li>
  <li>API: POST /graphql</li>
</ul>
</body></html>"""


@APP.route("/robots.txt")
def robots():
    return Response("User-agent: *\nAllow: /\n", mimetype="text/plain")


@APP.route("/ssti")
def ssti():
    name = request.args.get("name", "")
    # THE VULN: user input compiled as a template.
    return Response(Template("Hello " + name + "!").render())


@APP.route("/download")
def download():
    fname = request.args.get("file", "")
    # THE VULN: no canonical-path containment.
    target = os.path.normpath(os.path.join(FILE_ROOT, fname))
    if os.path.isfile(target):
        with open(target, "r", errors="replace") as fh:
            return Response(fh.read(), mimetype="text/plain")
    return Response("404 No such file", status=404)


@APP.route("/docs")
def docs():
    page = request.args.get("page", "")
    return Response(f"<h1>Docs: {page}</h1><p>Nothing here.</p>")


_GRAPHQL_INTROSPECTION_REPLY = {
    "data": {"__schema": {"queryType": {"name": "Query"}}}}
_GRAPHQL_SUGGESTION_REPLY = {
    "errors": [{"message":
                "Cannot query field '__zzzNoSuchField' on type 'Query'. "
                "Did you mean '__schema' or '__typename'?"}]}


@APP.route("/graphql", methods=["GET", "POST"])
def graphql():
    body = request.get_json(silent=True) or {}
    query = body.get("query", "")
    if "__zzzNoSuchField" in query:
        return _GRAPHQL_SUGGESTION_REPLY
    return _GRAPHQL_INTROSPECTION_REPLY


if __name__ == "__main__":
    os.makedirs(FILE_ROOT, exist_ok=True)
    manual = os.path.join(FILE_ROOT, "manual.pdf")
    if not os.path.exists(manual):
        with open(manual, "w") as fh:
            fh.write("Lure site operator manual. Nothing sensitive.\n")
    APP.run(host="0.0.0.0", port=8000)
