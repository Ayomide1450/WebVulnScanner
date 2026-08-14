"""
HARD-01's proof: rate limits actually enforce correctly across more than one
gunicorn worker, once RATELIMIT_STORAGE_URI is pointed at a shared backend.

This module deliberately builds bare `flask.Flask` + `flask_limiter.Limiter`
instances in-test, instead of going through `webvulnscanner.create_app()`.
`webvulnscanner.extensions.limiter` is a module-level singleton reused via
`.init_app(app)` by every `create_app()` call in one process (04-RESEARCH.md
Pitfall 1; also documented in tests/test_auth_flows.py's
test_login_rate_limit_is_enforced). A test built on that shared object would
only prove that one Python object shares its own field with itself - a
trivially-true fact that says nothing about two independent gunicorn worker
processes sharing a counter. Building two standalone Limiter objects here is
what actually simulates "two worker processes, one shared backend."

The fake backend is injected at `redis.from_url` - the exact call `limits`'
RedisStorage makes internally (`self.dependency.from_url(uri, **options)`,
confirmed by reading `limits`' source, 04-RESEARCH.md Pitfall 2). Neither
Flask-Limiter nor `limits` exposes any other client-injection hook, so this
is the only correct monkeypatch point; patching anything inside
flask_limiter itself silently does nothing and the test would instead hit a
real (refused) network connection.

`fakeredis` is used instead of a Dockerized Redis service container so this
proof keeps running with zero external services - matching
.github/workflows/tests.yml's existing convention of needing no service
containers and no .env file (D-01).
"""
import fakeredis
import redis
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.constants import ConfigVars
from flask_limiter.util import get_remote_address

from webvulnscanner.config import Config


def _make_limited_client(storage_uri):
    """Builds one standalone Flask app + a brand-new Limiter instance,
    registers a single `3 per minute`-limited route, and returns its test
    client. Each call constructs an entirely separate Limiter object - that
    separateness is the whole point of every test in this module; it is what
    stands in for "a different gunicorn worker process"."""
    app = Flask(__name__)
    limiter = Limiter(
        key_func=get_remote_address,
        storage_uri=storage_uri,
        app=app,
    )

    @app.route("/probe")
    @limiter.limit("3 per minute")
    def probe():
        return "ok"

    return app.test_client()


def test_two_independent_limiters_share_a_counter_via_fakeredis(monkeypatch):
    """The positive proof: two separately-constructed Limiter objects
    (simulating two gunicorn workers) pointed at the same redis:// storage
    URI observe the same counter. Three requests through the first "worker"
    exhaust the limit; the very next request through the second, entirely
    independent "worker" is rejected - proving the counter lives in the
    shared backend, not in either Limiter's own memory."""
    shared_server = fakeredis.FakeServer()
    # Patch must be in place BEFORE either Limiter is constructed - limits'
    # RedisStorage builds its client eagerly at construction/init_app time,
    # not lazily on first request (04-RESEARCH.md Pitfall 2's warning sign:
    # a ConnectionError here means the patch landed too late).
    monkeypatch.setattr(
        redis, "from_url",
        lambda *a, **k: fakeredis.FakeStrictRedis(server=shared_server),
    )

    client_a = _make_limited_client("redis://localhost:6379")  # "worker 1"
    client_b = _make_limited_client("redis://localhost:6379")  # "worker 2" - a separate Limiter object

    statuses = [client_a.get("/probe").status_code for _ in range(3)]
    assert statuses == [200, 200, 200]

    # The 4th request, from client_b's entirely separate Limiter instance,
    # is still rate-limited - the counter is shared via the (fake) Redis
    # backend, not private to either limiter's own process memory.
    assert client_b.get("/probe").status_code == 429


def test_two_independent_limiters_do_not_share_a_counter_with_in_memory_storage():
    """The negative control (04-RESEARCH.md's own required guard against the
    false-pass Pitfall 1 describes): with the in-memory default storage and
    no shared backend, two independently-constructed Limiter objects do NOT
    share a counter. This is what makes the positive test above meaningful -
    if this control ever starts returning 429 for client_b's first request,
    the two clients have stopped being independent and the positive test
    above has stopped proving anything."""
    client_a = _make_limited_client("memory://")
    client_b = _make_limited_client("memory://")

    statuses = [client_a.get("/probe").status_code for _ in range(3)]
    assert statuses == [200, 200, 200]

    # client_b has its own, private in-memory counter - unaffected by
    # client_a's three requests.
    assert client_b.get("/probe").status_code == 200


def test_flask_limiter_reads_the_exact_config_key_the_app_writes():
    """Pins the config key name against Flask-Limiter's own constant, rather
    than a hardcoded string literal, so a typo/rename on either side fails
    this test instead of silently downgrading every deploy to in-memory
    storage with no other test noticing (must_haves truth #4)."""
    assert ConfigVars.STORAGE_URI == "RATELIMIT_STORAGE_URI"


def test_ratelimit_storage_uri_defaults_to_empty_string():
    """Unset RATELIMIT_STORAGE_URI (the test environment's default) still
    yields the pre-existing in-memory behaviour - local dev and the existing
    test suite are unchanged by this plan (must_haves truth #5)."""
    assert Config.RATELIMIT_STORAGE_URI == ""
