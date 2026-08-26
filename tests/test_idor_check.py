"""Unit tests for check_idor's false-positive fix - the same class as
check_http_methods (f2dc05a): a bare `status_code == 200` doesn't prove
account B (or an anonymous caller) actually read account A's private
data, since a route that soft-200s every id (real or bogus) would trip
this on every single probe. check_idor had zero direct behavioral test
coverage before this file (every existing reference monkeypatches it
away) - exactly the gap that let check_http_methods' bug ship unnoticed.
"""
from webvulnscanner.checks import check_idor

URL_TEMPLATE = "https://example.com/api/resource/{id}"
COOKIE_A = "session=account-a-token"
COOKIE_B = "session=account-b-token"


class _FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class _FakeSession:
    """responses: {(cookie_used, id_seen): _FakeResponse}. `cookie_used`
    is 'anon' or 'b' - lets the fake distinguish the two callers exactly
    like the real function's two separate session.get() call shapes."""

    def __init__(self, responses, bogus_response_anon=None, bogus_response_b=None):
        self.responses = responses
        self.bogus_anon = bogus_response_anon or _FakeResponse(404, "not found")
        self.bogus_b = bogus_response_b or _FakeResponse(404, "not found")
        self.calls = []

    def get(self, url, headers=None, timeout=None, **kwargs):
        rid = url.rsplit("/", 1)[-1]
        who = "b" if headers else "anon"
        self.calls.append((who, rid))
        if rid.startswith("wvscan-nonexistent-"):
            return self.bogus_b if who == "b" else self.bogus_anon
        return self.responses.get((who, rid), _FakeResponse(404, ""))


def test_cross_account_200_distinguishable_from_baseline_is_confirmed():
    session = _FakeSession(
        responses={("b", "42"): _FakeResponse(200, "account A's private invoice #42, total $9,001")},
        bogus_response_b=_FakeResponse(404, "not found"),
    )
    data, findings = check_idor(session, URL_TEMPLATE, ["42"], COOKIE_A, COOKIE_B)
    assert len(findings) == 1
    assert findings[0].confidence == "Confirmed"
    assert findings[0].severity == "high"
    assert "Account B accessed" in findings[0].title


def test_cross_account_200_matching_baseline_is_downgraded_to_potential():
    """The soft-200 case this fix targets: account B gets 200 for id=42,
    but so does a request for an obviously-bogus id - same status, near-
    identical body length. Not proof of real cross-account exposure."""
    same_page = "generic shell page rendered for any id, real or not, 60 bytes"
    session = _FakeSession(
        responses={("b", "42"): _FakeResponse(200, same_page)},
        bogus_response_b=_FakeResponse(200, same_page),
    )
    data, findings = check_idor(session, URL_TEMPLATE, ["42"], COOKIE_A, COOKIE_B)
    assert len(findings) == 1
    assert findings[0].confidence == "Potential"
    assert findings[0].severity == "medium"
    assert "unconfirmed" in findings[0].title


def test_public_200_distinguishable_from_baseline_is_confirmed():
    session = _FakeSession(
        responses={("anon", "42"): _FakeResponse(200, "account A's private invoice #42, total $9,001")},
        bogus_response_anon=_FakeResponse(404, "not found"),
    )
    data, findings = check_idor(session, URL_TEMPLATE, ["42"], COOKIE_A, COOKIE_B)
    assert len(findings) == 1
    assert findings[0].confidence == "Confirmed"
    assert "readable with no authentication at all" in findings[0].title


def test_public_200_matching_baseline_is_downgraded_to_potential():
    same_page = "generic shell page rendered for any id, real or not, 60 bytes"
    session = _FakeSession(
        responses={("anon", "42"): _FakeResponse(200, same_page)},
        bogus_response_anon=_FakeResponse(200, same_page),
    )
    data, findings = check_idor(session, URL_TEMPLATE, ["42"], COOKIE_A, COOKIE_B)
    assert len(findings) == 1
    assert findings[0].confidence == "Potential"
    assert "unconfirmed" in findings[0].title


def test_denied_status_codes_produce_no_finding():
    session = _FakeSession(responses={("b", "42"): _FakeResponse(403, "forbidden")})
    data, findings = check_idor(session, URL_TEMPLATE, ["42"], COOKIE_A, COOKIE_B)
    assert findings == []
    assert data["rows"][0]["status"] == "denied"


def test_baseline_probed_once_per_session_type_with_a_random_nonexistent_id():
    session = _FakeSession(responses={("b", "42"): _FakeResponse(403, "forbidden")})
    check_idor(session, URL_TEMPLATE, ["42", "43"], COOKIE_A, COOKIE_B)
    bogus_calls = [c for c in session.calls if c[1].startswith("wvscan-nonexistent-")]
    # One anon + one 'b' baseline call, regardless of how many ids are probed.
    assert len(bogus_calls) == 2
    assert {c[0] for c in bogus_calls} == {"anon", "b"}
