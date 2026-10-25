"""
Tests for glassbox/scan_engine.py's shared scoring helper (HARD-04)
and the three orchestrators that previously had no automated coverage at
all - run_media_scan, run_api_scan, run_advanced_scan (HARD-02 / D-02,
D-03, D-04).

- `_score_report` section: unit tests for the arithmetic/grading/ordering
  the four orchestrators now share (score clamp, grade boundaries,
  severity_counts completeness, findings_sorted ordering/non-mutation, the
  ValueError on an unrecognised severity), plus a cross-orchestrator
  source-parsing regression lock asserting none of the four re-inlines the
  formula.
- `run_media_scan` / `run_api_scan` / `run_advanced_scan` sections:
  direct-invocation, fully-mocked coverage of each orchestrator's completed
  return shape and error-propagation path. Every check function is stubbed
  on `scan_engine`'s own module namespace (never on `glassbox.checks`)
  - `scan_engine.py` does `from glassbox.checks import check_x`, so
  patching `checks.check_x` would not intercept the orchestrator's call and
  the test would silently hit the network. See `tests/test_scan_events.py`'s
  module docstring for the same caveat, already established for `run_scan`.
  No test in this module touches the DB or a `Scan` row - the
  status-transition half of HARD-02 (`scan_routes._run_scan_in_background`)
  lives in plan 04-04, not here. `run_advanced_scan` is exercised via direct
  invocation only (D-04): `scheduler._fire()` has no `"advanced"` branch.

The "Safety-constraint regression locks (D-02)" section calls
`glassbox.checks` directly rather than through an orchestrator,
because orchestrator-level tests stub check functions out entirely and
therefore cannot observe the caps those checks enforce internally. No
function in `glassbox/checks.py` is modified by this plan - these
tests lock existing, already-shipped behaviour, they do not introduce it.
"""
from types import SimpleNamespace

import pytest

from glassbox import scan_engine
from glassbox.checks import SEVERITY_WEIGHT, Finding
from glassbox.entitlements import Tier

# --------------------------------------------------------------------------
# _score_report
# --------------------------------------------------------------------------


def _finding(severity, check_name="x"):
    return Finding("Cat", "Title", severity, "detail", "", check_name=check_name)


def test_score_report_empty_findings_is_perfect_score():
    score, grade, counts, findings_sorted = scan_engine._score_report([])
    assert (score, grade, findings_sorted) == (100, "A", [])
    assert set(counts) == set(SEVERITY_WEIGHT)
    assert all(v == 0 for v in counts.values())


def test_score_report_subtracts_weight_per_finding():
    findings = [_finding("high"), _finding("medium")]
    score, grade, counts, _ = scan_engine._score_report(findings)
    assert score == 100 - SEVERITY_WEIGHT["high"] - SEVERITY_WEIGHT["medium"]
    assert grade == "B"
    assert counts["high"] == 1
    assert counts["medium"] == 1


def test_score_report_clamps_at_zero_never_negative():
    findings = [_finding("critical") for _ in range(10)]
    score, grade, counts, _ = scan_engine._score_report(findings)
    assert score == 0
    assert grade == "F"
    assert counts["critical"] == 10


@pytest.mark.parametrize("raw_score,expected_grade", [
    (90, "A"), (89, "B"), (75, "B"), (74, "C"),
    (60, "C"), (59, "D"), (40, "D"), (39, "F"),
])
def test_score_report_grade_boundaries(monkeypatch, raw_score, expected_grade):
    # The real severity weights (25/15/7/3, gcd 1 but with an 11-point
    # Frobenius gap between 3 and 7) can't hit every exact deficit this
    # boundary table needs (e.g. 100-89=11 has no exact 25/15/7/3 combination).
    # Monkeypatch SEVERITY_WEIGHT to a synthetic 1-point-per-finding scheme
    # for "low" only, scoped to this test via monkeypatch, so any deficit
    # 0-100 can be hit exactly with `deficit` low-severity findings - this
    # test is about the score->grade mapping, not the weight values
    # themselves (those are covered by the subtraction/clamp tests above).
    monkeypatch.setattr(scan_engine, "SEVERITY_WEIGHT", {"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0})
    deficit = 100 - raw_score
    findings = [_finding("low") for _ in range(deficit)]

    score, grade, _, _ = scan_engine._score_report(findings)
    assert score == raw_score
    assert grade == expected_grade


def test_score_report_severity_counts_has_all_keys_even_when_zero():
    _, _, counts, _ = scan_engine._score_report([_finding("low")])
    assert set(counts) == set(SEVERITY_WEIGHT)
    assert counts["low"] == 1
    assert counts["critical"] == 0


def test_score_report_findings_sorted_orders_most_severe_first_and_does_not_mutate_input():
    original = [_finding("low"), _finding("critical"), _finding("medium")]
    original_copy = list(original)

    _, _, _, findings_sorted = scan_engine._score_report(original)

    assert [f.severity for f in findings_sorted] == ["critical", "medium", "low"]
    # The caller's input list is not reordered in place - a new list is
    # returned.
    assert original == original_copy
    assert findings_sorted is not original


def test_score_report_raises_on_unrecognised_severity():
    with pytest.raises(ValueError):
        scan_engine._score_report([_finding("nonsense-severity")])


# --------------------------------------------------------------------------
# run_media_scan
# --------------------------------------------------------------------------


def _stub_session(monkeypatch):
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: SimpleNamespace())


def test_run_media_scan_completed_shape_no_findings(monkeypatch):
    _stub_session(monkeypatch)
    monkeypatch.setattr(
        scan_engine, "check_media",
        lambda session, base_url, download, max_files: ({"images": [], "videos": []}, []),
    )

    report = scan_engine.run_media_scan("https://example.com", download=False, max_files=20)

    assert report["score"] == 100
    assert report["risk_grade"] == "A"
    assert report["findings"] == []
    assert report["media"] == {"images": [], "videos": []}


def test_run_media_scan_one_finding_scores_via_score_report_and_tags_check_name(monkeypatch):
    _stub_session(monkeypatch)
    finding = _finding("high")

    def fake_check_media(session, base_url, download, max_files):
        return {"images": [], "videos": []}, [finding]

    monkeypatch.setattr(scan_engine, "check_media", fake_check_media)

    report = scan_engine.run_media_scan("https://example.com", download=False, max_files=20)

    expected_score, expected_grade, _, _ = scan_engine._score_report([finding])
    assert report["score"] == expected_score
    assert report["risk_grade"] == expected_grade
    assert len(report["findings"]) == 1
    assert report["findings"][0]["check_name"] == "media"


def test_run_media_scan_propagates_check_media_exception(monkeypatch):
    import requests

    _stub_session(monkeypatch)

    def raising_check_media(*a, **k):
        raise requests.RequestException("boom")

    monkeypatch.setattr(scan_engine, "check_media", raising_check_media)

    with pytest.raises(requests.RequestException):
        scan_engine.run_media_scan("https://example.com", download=False, max_files=20)


# --------------------------------------------------------------------------
# run_api_scan
# --------------------------------------------------------------------------


class _RecordingSession:
    """Records every get/post call it receives; returns a bare-HTML page
    for `get` (run_api_scan's three check functions are stubbed out
    entirely in these tests, so `post` is never actually called by the
    orchestrator itself - only its own initial home-page `get` is)."""

    def __init__(self):
        self.calls = []

    def get(self, url, timeout=None, **kwargs):
        self.calls.append(("GET", url))
        return SimpleNamespace(text="<html></html>")

    def post(self, url, timeout=None, **kwargs):
        self.calls.append(("POST", url))
        return SimpleNamespace(text="")


def _stub_api_checks(monkeypatch, schema=None, wordlist=None, js_discovery=None):
    monkeypatch.setattr(scan_engine, "check_api_schema_exposure",
                         lambda base_url, session: schema or ({}, []))
    monkeypatch.setattr(scan_engine, "check_api_wordlist",
                         lambda base_url, session: wordlist or ({}, []))
    monkeypatch.setattr(scan_engine, "check_api_js_discovery",
                         lambda session, base_url, home_html: js_discovery or ({}, []))


def test_run_api_scan_completed_shape_no_findings(monkeypatch):
    session = _RecordingSession()
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: session)
    _stub_api_checks(monkeypatch)

    report = scan_engine.run_api_scan("https://example.com")

    assert report["score"] == 100
    assert report["risk_grade"] == "A"
    assert set(report["results"]) == {"schema", "wordlist", "js_discovery"}


def test_run_api_scan_tags_finding_with_matching_check_name(monkeypatch):
    session = _RecordingSession()
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: session)
    finding = _finding("medium")
    _stub_api_checks(monkeypatch, wordlist=({}, [finding]))

    report = scan_engine.run_api_scan("https://example.com")

    expected_score, expected_grade, _, _ = scan_engine._score_report([finding])
    assert report["score"] == expected_score
    assert report["risk_grade"] == expected_grade
    assert len(report["findings"]) == 1
    assert report["findings"][0]["check_name"] == "wordlist"


def test_run_api_scan_propagates_exception_from_wordlist_check(monkeypatch):
    import requests

    session = _RecordingSession()
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: session)
    monkeypatch.setattr(scan_engine, "check_api_schema_exposure", lambda base_url, session: ({}, []))

    def raising_wordlist(base_url, session):
        raise requests.RequestException("boom")

    monkeypatch.setattr(scan_engine, "check_api_wordlist", raising_wordlist)
    monkeypatch.setattr(scan_engine, "check_api_js_discovery",
                         lambda session, base_url, home_html: ({}, []))

    with pytest.raises(requests.RequestException):
        scan_engine.run_api_scan("https://example.com")


def test_run_api_scan_performs_exactly_one_home_page_fetch_before_any_check(monkeypatch):
    session = _RecordingSession()
    monkeypatch.setattr(scan_engine, "_mk_session", lambda: session)
    _stub_api_checks(monkeypatch)

    scan_engine.run_api_scan("https://example.com")

    gets = [call for call in session.calls if call[0] == "GET"]
    assert gets == [("GET", "https://example.com/")]


# --------------------------------------------------------------------------
# HARD-04 cross-orchestrator regression lock: none of the four orchestrators
# may carry an inline copy of the scoring arithmetic ever again. This is
# the source-parsing regression-lock technique tests/test_entitlements.py
# and tests/test_compliance.py already use for their own coverage maps.
# --------------------------------------------------------------------------


def test_no_orchestrator_carries_an_inline_scoring_block():
    import inspect

    orchestrators = (
        scan_engine.run_scan, scan_engine.run_advanced_scan,
        scan_engine.run_media_scan, scan_engine.run_api_scan,
    )
    regressed = []
    for fn in orchestrators:
        src = inspect.getsource(fn)
        has_inline_formula = "SEVERITY_WEIGHT" in src or "SEVERITY_ORDER" in src
        calls_helper = "_score_report(" in src
        if has_inline_formula or not calls_helper:
            regressed.append(fn.__name__)
    assert not regressed, (
        f"{regressed} no longer routes its score/grade/severity_counts through "
        "_score_report() - HARD-04's dedup has regressed (a formula change would "
        "now need to be made in more than one place again)."
    )


# --------------------------------------------------------------------------
# SEC-03 / D-05 backfill: every scan orchestrator must acquire its HTTP
# session from checks._mk_session() - the single choke point where plan
# 08-04's SSRF redirect guard (_SSRFSafeSession) is installed - and from
# nowhere else. Parsed per-function (not a whole-file occurrence count),
# same technique as the _score_report lock directly above: a whole-file
# `grep -c` would pass with four calls even if one orchestrator had two and
# another had none, which is exactly the regression this must catch.
# --------------------------------------------------------------------------


def test_every_orchestrator_acquires_its_session_via_mk_session():
    import inspect

    orchestrators = (
        scan_engine.run_scan, scan_engine.run_advanced_scan,
        scan_engine.run_media_scan, scan_engine.run_api_scan,
    )
    regressed = []
    for fn in orchestrators:
        src = inspect.getsource(fn)
        if "_mk_session()" not in src:
            regressed.append(fn.__name__)
    assert not regressed, (
        f"{regressed} no longer acquires its HTTP session via checks._mk_session() - "
        "_mk_session() is the only place the SSRF redirect guard (_SSRFSafeSession) is "
        "installed, so an orchestrator constructing its session another way would be an "
        "unguarded outbound client that bypasses the guard entirely."
    )


def test_scan_engine_module_never_constructs_a_bare_requests_session():
    import inspect
    import re

    src = inspect.getsource(scan_engine)
    # Comment-filtered: strip full-line comments, then strip trailing
    # inline comments, so an explanatory comment mentioning the term
    # cannot accidentally satisfy or break the match.
    code_only = "\n".join(
        line.split("#", 1)[0] for line in src.splitlines()
        if not line.strip().startswith("#")
    )
    bare_session = re.search(r"\brequests\.Session\s*\(", code_only)
    assert bare_session is None, (
        "glassbox/scan_engine.py constructs a requests.Session() directly - every "
        "HTTP session in the scan engine must come from checks._mk_session() so the SSRF "
        "redirect guard applies. Route the construction through _mk_session() instead."
    )


# --------------------------------------------------------------------------
# run_advanced_scan
#
# run_advanced_scan is exercised via direct invocation only (D-04) -
# scheduler._fire() has no "advanced" branch to fire, so there is no
# scheduler-fired test for it, by design (see the comment above the
# function in scan_engine.py).
# --------------------------------------------------------------------------


def _full_advanced_form():
    """Every field `_parse_advanced_form` (scan_routes.py) produces, all
    populated with obviously-fake example.com literals - mirrors the full
    field set a real advanced-scan submission would carry, so an
    "everything locked below tier" test actually exercises all five
    independent lock branches (04-RESEARCH.md Pitfall 5)."""
    return {
        "login_url": "https://example.com/login",
        "user_field": "username",
        "pass_field": "password",
        "fail_text": "invalid credentials",
        "bruteforce_username": "testuser",
        "bruteforce_passwords": ["pw1", "pw2", "pw3", "pw4", "pw5", "pw6", "pw7"],
        "sqli_union_url": "https://example.com/products?id=1",
        "sqli_union_param": "id",
        "stored_xss_submit_url": "https://example.com/comment",
        "stored_xss_field": "body",
        "stored_xss_view_url": "https://example.com/comments",
        "stored_xss_cookie": "session=fake-test-cookie-value",
        "idor_url_template": "https://example.com/orders/{id}",
        "idor_ids": ["1", "2", "3"],
        "idor_cookie_a": "session=fake-account-a-cookie",
        "idor_cookie_b": "session=fake-account-b-cookie",
    }


ALL_GROUP_NAMES = {"sqli_login", "bruteforce", "sqli_union", "xss_stored", "idor"}


def _stub_advanced_checks(monkeypatch):
    """Patches every check function run_advanced_scan can call, plus
    _mk_session, to network-free recording stubs. Returns a dict of
    call-argument-tuple lists keyed by check name so tests can assert call
    counts/arguments without ever reaching glassbox.checks."""
    calls = {name: [] for name in ALL_GROUP_NAMES}

    def make_stub(name):
        def _stub(*args):
            calls[name].append(args)
            return {}, []
        return _stub

    monkeypatch.setattr(scan_engine, "_mk_session", lambda: SimpleNamespace())
    monkeypatch.setattr(scan_engine, "check_sqli_login", make_stub("sqli_login"))
    monkeypatch.setattr(scan_engine, "check_bruteforce", make_stub("bruteforce"))
    monkeypatch.setattr(scan_engine, "check_sqli_union", make_stub("sqli_union"))
    monkeypatch.setattr(scan_engine, "check_xss_stored", make_stub("xss_stored"))
    monkeypatch.setattr(scan_engine, "check_idor", make_stub("idor"))
    return calls


def test_run_advanced_scan_all_allowed_runs_every_group_and_locks_nothing(monkeypatch):
    calls = _stub_advanced_checks(monkeypatch)

    report = scan_engine.run_advanced_scan(_full_advanced_form(), Tier.ORG_VERIFIED, True)

    assert set(report["ran"]) == ALL_GROUP_NAMES
    assert report["locked_checks"] == []
    for name in ALL_GROUP_NAMES:
        assert len(calls[name]) == 1


def test_run_advanced_scan_below_tier_locks_every_group_and_calls_nothing(monkeypatch):
    calls = _stub_advanced_checks(monkeypatch)

    report = scan_engine.run_advanced_scan(_full_advanced_form(), Tier.PAID, True)

    assert set(report["locked_checks"]) == ALL_GROUP_NAMES
    assert report["ran"] == []
    for name in ALL_GROUP_NAMES:
        assert calls[name] == []


def test_run_advanced_scan_at_tier_but_unverified_domain_locks_every_group(monkeypatch):
    calls = _stub_advanced_checks(monkeypatch)

    report = scan_engine.run_advanced_scan(_full_advanced_form(), Tier.ORG_VERIFIED, False)

    assert set(report["locked_checks"]) == ALL_GROUP_NAMES
    assert report["ran"] == []
    for name in ALL_GROUP_NAMES:
        assert calls[name] == []


def test_run_advanced_scan_empty_form_is_silently_skipped_not_locked(monkeypatch):
    # An unfilled group is skipped entirely, never locked - only a group
    # whose fields ARE present but whose tier/domain gating denies it lands
    # in locked_checks (04-RESEARCH.md Pitfall 5). A test that only checks
    # the all-filled-in case would never exercise this branch.
    calls = _stub_advanced_checks(monkeypatch)

    report = scan_engine.run_advanced_scan({}, Tier.ORG_VERIFIED, True)

    assert report["locked_checks"] == []
    assert report["ran"] == []
    for name in ALL_GROUP_NAMES:
        assert calls[name] == []


def test_run_advanced_scan_calls_bruteforce_exactly_once_with_unmodified_password_list(monkeypatch):
    calls = _stub_advanced_checks(monkeypatch)
    form = _full_advanced_form()

    scan_engine.run_advanced_scan(form, Tier.ORG_VERIFIED, True)

    assert len(calls["bruteforce"]) == 1
    # call signature: (session, login_url, user_field, pass_field, username, passwords, fail_text)
    passed_passwords = calls["bruteforce"][0][5]
    assert passed_passwords == form["bruteforce_passwords"]


def test_run_advanced_scan_propagates_exception_from_a_stubbed_check(monkeypatch):
    _stub_advanced_checks(monkeypatch)

    def raising_sqli_login(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(scan_engine, "check_sqli_login", raising_sqli_login)

    with pytest.raises(RuntimeError):
        scan_engine.run_advanced_scan(_full_advanced_form(), Tier.ORG_VERIFIED, True)


def test_run_advanced_scan_never_crawls(monkeypatch):
    _stub_advanced_checks(monkeypatch)

    def fail_if_called(*a, **k):
        raise AssertionError("run_advanced_scan must never crawl - it only reaches URLs "
                              "present in the caller's `advanced` dict")

    monkeypatch.setattr(scan_engine, "crawl_same_origin", fail_if_called)

    # Completes without raising - crawl_same_origin is never invoked, and no
    # discovered form is ever auto-submitted as a result.
    scan_engine.run_advanced_scan(_full_advanced_form(), Tier.ORG_VERIFIED, True)


# --------------------------------------------------------------------------
# Safety-constraint regression locks (D-02)
#
# These three tests call glassbox.checks directly rather than through
# an orchestrator, because the orchestrator-level tests above stub every
# check function out entirely and therefore cannot observe the caps/proof
# those checks enforce internally - the orchestrator-level tests can only
# verify run_advanced_scan passes through whatever the (mocked) check
# returns, not what the real check does with its inputs.
#
# No function in glassbox/checks.py is modified anywhere in this
# plan - these tests lock existing, already-shipped behaviour.
# --------------------------------------------------------------------------


class _RecordingAuthSession:
    """Fake session for check_bruteforce - records every POST it receives
    and returns a response whose body contains fail_text (i.e. the attempt
    "failed") for every call, unless `succeed_on_call_index` is set, in
    which case that one call's response omits fail_text (i.e. "succeeded")."""

    def __init__(self, fail_text, succeed_on_call_index=None):
        self.fail_text = fail_text
        self.succeed_on_call_index = succeed_on_call_index
        self.post_calls = []

    def request(self, method, url, data=None, timeout=None, **kwargs):
        # check_bruteforce goes through checks._timed_request, which always
        # calls session.request(method, ...), not session.post directly.
        self.post_calls.append((url, data))
        idx = len(self.post_calls) - 1
        if self.succeed_on_call_index is not None and idx == self.succeed_on_call_index:
            return SimpleNamespace(status_code=200, text="welcome back")
        return SimpleNamespace(status_code=200, text=f"error: {self.fail_text}")


def test_check_bruteforce_never_exceeds_max_attempts(monkeypatch):
    from glassbox import checks

    # Neutralise the deliberate 1s inter-attempt delay - see
    # 04-RESEARCH.md Pitfall 4 - so this test pays none of it.
    monkeypatch.setattr(checks.time, "sleep", lambda *a, **k: None)
    session = _RecordingAuthSession(fail_text="invalid credentials")
    seven_passwords = ["p1", "p2", "p3", "p4", "p5", "p6", "p7"]

    checks.check_bruteforce(session, "https://example.com/login", "user", "pass",
                             "someuser", seven_passwords, "invalid credentials")

    assert len(session.post_calls) == checks.MAX_BRUTEFORCE_ATTEMPTS


def test_check_bruteforce_stops_on_first_success_and_withholds_password_in_detail(monkeypatch):
    from glassbox import checks

    monkeypatch.setattr(checks.time, "sleep", lambda *a, **k: None)
    # Second password (index 1) succeeds.
    session = _RecordingAuthSession(fail_text="invalid credentials", succeed_on_call_index=1)
    passwords = ["wrongpass", "correctpass", "unused3", "unused4", "unused5"]

    data, findings = checks.check_bruteforce(session, "https://example.com/login", "user", "pass",
                                              "someuser", passwords, "invalid credentials")

    assert len(session.post_calls) == 2
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "correctpass" not in findings[0].detail


def test_check_xss_stored_contacts_only_submit_and_view_hosts_no_cookie_exfiltration(monkeypatch):
    from urllib.parse import urlparse

    from glassbox import checks

    submit_url = "https://example.com/comment"
    view_url = "https://example.com/comments"
    cookie = "session=super-secret-test-cookie"
    hosts_contacted = []
    cookies_sent_off_target = []
    last_payload = [""]

    class _FakeStoredXssSession:
        def post(self, url, data=None, headers=None, timeout=None, **kwargs):
            hosts_contacted.append(urlparse(url).netloc)
            if data:
                last_payload[0] = next(iter(data.values()))
            if headers and headers.get("Cookie") == cookie and urlparse(url).netloc != urlparse(submit_url).netloc:
                cookies_sent_off_target.append(url)
            return SimpleNamespace(status_code=200, text="ok")

        def get(self, url, headers=None, timeout=None, **kwargs):
            hosts_contacted.append(urlparse(url).netloc)
            if headers and headers.get("Cookie") == cookie and urlparse(url).netloc != urlparse(view_url).netloc:
                cookies_sent_off_target.append(url)
            # Reflect back whatever payload was most recently submitted, so
            # the first payload variant checks.py tries is confirmed -
            # decouples this test from checks.py's exact payload templates.
            return SimpleNamespace(status_code=200, text=last_payload[0])

    session = _FakeStoredXssSession()
    data, findings = checks.check_xss_stored(session, submit_url, "body", view_url, cookie)

    assert set(hosts_contacted) == {"example.com"}
    assert cookies_sent_off_target == []
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    # The finding proves execution via marker reflection; it must not claim
    # cookie theft was actually carried out (checks.py's own docstring: "does
    # not exfiltrate any cookie to a listener").
    assert "not executed" in findings[0].detail.lower()
