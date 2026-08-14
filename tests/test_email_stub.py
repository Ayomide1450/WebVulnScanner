"""Tests for webvulnscanner/email_stub.py's ResendEmailSender."""
import pytest

from webvulnscanner.email_stub import ConsoleEmailSender, ResendEmailSender, make_email_sender


def test_resend_sender_requires_api_key():
    with pytest.raises(RuntimeError, match="RESEND_API_KEY"):
        ResendEmailSender(api_key="", from_address="noreply@example.com")


def test_resend_sender_requires_from_address():
    with pytest.raises(RuntimeError, match="RESEND_FROM_EMAIL"):
        ResendEmailSender(api_key="re_test", from_address="")


def test_resend_sender_posts_to_resend_api(monkeypatch):
    calls = []

    class FakeResp:
        def raise_for_status(self):
            pass

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append((url, headers, json, timeout))
        return FakeResp()

    monkeypatch.setattr("webvulnscanner.email_stub.requests.post", fake_post)

    sender = ResendEmailSender(api_key="re_test", from_address="noreply@example.com")
    sender.send(to="user@example.com", subject="Verify", body="click here")

    assert len(calls) == 1
    url, headers, payload, timeout = calls[0]
    assert url == "https://api.resend.com/emails"
    assert headers["Authorization"] == "Bearer re_test"
    assert payload == {
        "from": "noreply@example.com", "to": ["user@example.com"],
        "subject": "Verify", "text": "click here",
    }


def test_make_email_sender_defaults_to_console():
    assert isinstance(make_email_sender("console"), ConsoleEmailSender)
    assert isinstance(make_email_sender("unknown-mode"), ConsoleEmailSender)


def test_make_email_sender_resend_mode_requires_config():
    with pytest.raises(RuntimeError):
        make_email_sender("resend", resend_api_key="", resend_from="")
    sender = make_email_sender("resend", resend_api_key="re_test", resend_from="noreply@example.com")
    assert isinstance(sender, ResendEmailSender)
