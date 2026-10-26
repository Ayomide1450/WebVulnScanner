"""check_idor_sweep - the discovery-driven IDOR sweep (roadmap #1).

Unlike check_idor (operator supplies url_template + ids), the sweep crawls
account A's authenticated surface, harvests object-id-addressable URLs
itself, and replays each as account B and anonymously. These tests drive
the whole path - discovery through classification - with a fake session, and
pin the confidence discipline it inherits from check_idor (a real-id 200 is
only "Confirmed" when distinguishable from a bogus-id baseline).
"""
from glassbox.checks import (
    _harvest_idor_urls,
    _idor_bogus_variant,
    _idor_value_is_id,
    check_idor_sweep,
)

BASE = "https://acme.test"
COOKIE_A = "session=a-token"
COOKIE_B = "session=b-token"


class _FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class _SweepSession:
    """Serves account-A HTML for the base page and per-(who, url) responses.

    `who` is 'a' (A's cookie), 'b' (B's cookie) or 'anon'. Any URL whose id
    token is in `bogus_ids` (the sweep's random bogus baselines) returns the
    configured baseline response for that caller - the fake can't predict the
    random bogus id, so it treats "an id I was never told about" as bogus."""

    def __init__(self, home_html, responses, baseline_b=None, baseline_anon=None, known_ids=()):
        self.home_html = home_html
        self.responses = responses  # {(who, url): _FakeResponse}
        self.baseline_b = baseline_b or _FakeResponse(404, "not found")
        self.baseline_anon = baseline_anon or _FakeResponse(404, "not found")
        self.known_ids = set(known_ids)
        self.calls = []

    def _who(self, headers):
        if not headers:
            return "anon"
        return "a" if "a-token" in headers.get("Cookie", "") else "b"

    def get(self, url, headers=None, timeout=None, **kwargs):
        who = self._who(headers)
        self.calls.append((who, url))
        if url.rstrip("/") == BASE:
            return _FakeResponse(200, self.home_html)
        # Any real configured response wins; otherwise this is a bogus-id
        # baseline probe (the sweep invented a random id we weren't told of).
        if (who, url) in self.responses:
            return self.responses[(who, url)]
        return self.baseline_b if who == "b" else self.baseline_anon


# --------------------------------------------------------------------------
# id detection + bogus-variant building
# --------------------------------------------------------------------------


def test_value_is_id_recognises_digits_and_uuids_but_not_slugs():
    assert _idor_value_is_id("1042")
    assert _idor_value_is_id("550e8400-e29b-41d4-a716-446655440000")
    assert not _idor_value_is_id("about-us")
    assert not _idor_value_is_id("")


def test_bogus_variant_rewrites_a_path_id():
    bogus = _idor_bogus_variant("https://acme.test/order/1042")
    assert bogus is not None
    assert "/order/1042" not in bogus
    assert bogus.startswith("https://acme.test/order/")


def test_bogus_variant_rewrites_an_idish_query_param_only():
    bogus = _idor_bogus_variant("https://acme.test/view?doc=88&sort=name")
    assert bogus is not None
    assert "doc=88" not in bogus
    assert "sort=name" in bogus  # non-id params preserved


def test_bogus_variant_returns_none_for_non_addressable_urls():
    assert _idor_bogus_variant("https://acme.test/about") is None
    assert _idor_bogus_variant("https://acme.test/blog?page=2") is None  # page is not an id key


def test_harvest_is_same_origin_and_dedups():
    html = """
      <a href="/order/1">o1</a>
      <a href="/order/1">dup</a>
      <a href="/profile/9">p9</a>
      <a href="/about">skip</a>
      <a href="https://evil.test/order/5">offsite</a>
    """
    urls = _harvest_idor_urls(BASE, [html], limit=10)
    assert urls == ["https://acme.test/order/1", "https://acme.test/profile/9"]


# --------------------------------------------------------------------------
# end-to-end sweep classification
# --------------------------------------------------------------------------


def test_cross_account_distinguishable_200_is_confirmed_high():
    home = '<a href="/order/42">my order</a>'
    session = _SweepSession(
        home_html=home,
        responses={("b", "https://acme.test/order/42"):
                   _FakeResponse(200, "Account A order #42 — total $9,001, ship to A's address")},
        baseline_b=_FakeResponse(404, "not found"),
    )
    data, findings = check_idor_sweep(session, BASE, COOKIE_A, COOKIE_B)
    assert data["discovered"] == 1
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].confidence == "Confirmed"
    assert "Account B accessed" in findings[0].title


def test_cross_account_200_indistinguishable_from_baseline_is_only_potential():
    home = '<a href="/order/42">my order</a>'
    same = _FakeResponse(200, "generic soft-200 page, identical for every id")
    session = _SweepSession(
        home_html=home,
        responses={("b", "https://acme.test/order/42"): same},
        baseline_b=_FakeResponse(200, "generic soft-200 page, identical for every id"),
    )
    _, findings = check_idor_sweep(session, BASE, COOKIE_A, COOKIE_B)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].confidence == "Potential"


def test_anonymous_exposure_outranks_cross_account():
    home = '<a href="/invoice/7">invoice</a>'
    session = _SweepSession(
        home_html=home,
        responses={
            ("anon", "https://acme.test/invoice/7"):
                _FakeResponse(200, "Invoice 7 for account A, distinct content here"),
            ("b", "https://acme.test/invoice/7"):
                _FakeResponse(200, "Invoice 7 for account A, distinct content here"),
        },
        baseline_anon=_FakeResponse(404, "nope"),
        baseline_b=_FakeResponse(404, "nope"),
    )
    _, findings = check_idor_sweep(session, BASE, COOKIE_A, COOKIE_B)
    assert len(findings) == 1
    assert "no authentication at all" in findings[0].title
    assert findings[0].severity == "high"


def test_properly_denied_resource_produces_no_finding():
    home = '<a href="/order/42">order</a>'
    session = _SweepSession(
        home_html=home,
        responses={
            ("b", "https://acme.test/order/42"): _FakeResponse(403, "forbidden"),
            ("anon", "https://acme.test/order/42"): _FakeResponse(401, "unauthorized"),
        },
    )
    data, findings = check_idor_sweep(session, BASE, COOKIE_A, COOKIE_B)
    assert findings == []
    assert data["rows"][0]["status"] == "denied"


def test_no_addressable_urls_means_no_probes_and_no_findings():
    home = '<a href="/about">about</a><a href="/contact">contact</a>'
    session = _SweepSession(home_html=home, responses={})
    data, findings = check_idor_sweep(session, BASE, COOKIE_A, COOKIE_B)
    assert data["discovered"] == 0
    assert findings == []


def test_sweep_is_get_only_never_posts():
    home = '<a href="/order/42">order</a>'
    session = _SweepSession(
        home_html=home,
        responses={("b", "https://acme.test/order/42"): _FakeResponse(404, "")},
    )
    check_idor_sweep(session, BASE, COOKIE_A, COOKIE_B)
    # _SweepSession only implements get(); a POST would be an AttributeError.
    # Belt-and-braces: assert every recorded call went through get().
    assert all(isinstance(c, tuple) and len(c) == 2 for c in session.calls)


def test_respects_the_url_cap():
    links = "".join(f'<a href="/order/{i}">o{i}</a>' for i in range(50))
    session = _SweepSession(home_html=links, responses={})
    data, _ = check_idor_sweep(session, BASE, COOKIE_A, COOKIE_B, max_urls=5)
    assert data["discovered"] == 5
