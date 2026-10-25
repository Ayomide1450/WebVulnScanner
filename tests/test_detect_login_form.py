"""
Tests for checks.detect_login_form() - the Advanced scan wizard's Smart
Setup helper (see checks.py's docstring). Isolated from the Flask route
layer (that's covered in tests/test_scan_wizard.py's detect-endpoint
tests) - these exercise the crawl/parse logic directly against a fake
`requests`-shaped session, same convention as tests/test_domain_verification.py's
_FakeHttpResponse.
"""
from glassbox.checks import detect_login_form


class _FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class _FakeSession:
    """Maps exact URLs to canned responses; anything else 404s."""

    def __init__(self, pages):
        self.pages = pages
        self.requested = []

    def get(self, url, timeout=None, allow_redirects=True):
        self.requested.append(url)
        if url in self.pages:
            return self.pages[url]
        return _FakeResponse(404, "")


LOGIN_FORM_HTML = """
<html><body>
<form action="/session" method="post">
  <input type="text" name="email">
  <input type="password" name="password">
</form>
</body></html>
"""

HOMEPAGE_WITH_LOGIN_LINK_HTML = """
<html><body>
<a href="/login">Log in</a>
<p>Welcome</p>
</body></html>
"""

NO_FORM_HTML = "<html><body><p>Nothing here.</p></body></html>"


def test_detect_finds_password_form_on_base_url_itself():
    session = _FakeSession({"https://example.com": _FakeResponse(200, LOGIN_FORM_HTML)})
    result = detect_login_form("https://example.com", session=session)
    assert result == {"login_url": "https://example.com/session", "user_field": "email", "pass_field": "password"}


def test_detect_follows_login_link_from_homepage():
    session = _FakeSession({
        "https://example.com": _FakeResponse(200, HOMEPAGE_WITH_LOGIN_LINK_HTML),
        "https://example.com/login": _FakeResponse(200, LOGIN_FORM_HTML),
    })
    result = detect_login_form("https://example.com", session=session)
    assert result is not None
    assert result["pass_field"] == "password"


def test_detect_tries_common_login_paths():
    session = _FakeSession({
        "https://example.com": _FakeResponse(200, NO_FORM_HTML),
        "https://example.com/login": _FakeResponse(200, LOGIN_FORM_HTML),
    })
    result = detect_login_form("https://example.com", session=session)
    assert result is not None
    assert result["login_url"] == "https://example.com/session"


def test_detect_returns_none_when_no_password_form_anywhere():
    session = _FakeSession({"https://example.com": _FakeResponse(200, NO_FORM_HTML)})
    result = detect_login_form("https://example.com", session=session)
    assert result is None


def test_detect_swallows_request_errors_on_individual_candidates():
    import requests

    class _ErroringSession(_FakeSession):
        def get(self, url, timeout=None, allow_redirects=True):
            if url == "https://example.com":
                raise requests.RequestException("boom")
            return super().get(url, timeout=timeout, allow_redirects=allow_redirects)

    session = _ErroringSession({"https://example.com/login": _FakeResponse(200, LOGIN_FORM_HTML)})
    result = detect_login_form("https://example.com", session=session)
    assert result is not None  # one dead candidate must not fail the whole attempt


def test_detect_returns_none_when_every_candidate_errors():
    import requests

    class _AllErrorSession:
        def get(self, url, timeout=None, allow_redirects=True):
            raise requests.RequestException("boom")

    result = detect_login_form("https://example.com", session=_AllErrorSession())
    assert result is None


def test_detect_ignores_non_password_form_fields():
    html = """
    <form action="/search"><input type="text" name="q"></form>
    """
    session = _FakeSession({"https://example.com": _FakeResponse(200, html)})
    result = detect_login_form("https://example.com", session=session)
    assert result is None


def test_detect_guesses_username_field_by_hint_order():
    html = """
    <form action="/session" method="post">
      <input type="text" name="csrf_token">
      <input type="text" name="user_email">
      <input type="password" name="pwd">
    </form>
    """
    session = _FakeSession({"https://example.com": _FakeResponse(200, html)})
    result = detect_login_form("https://example.com", session=session)
    assert result == {"login_url": "https://example.com/session", "user_field": "user_email", "pass_field": "pwd"}
