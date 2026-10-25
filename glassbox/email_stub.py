"""
Email delivery seam. Local dev tool -> no real SMTP; `ConsoleEmailSender`
just prints the message to stdout in a clearly delimited block so
verification-link / invite flows are exercisable without a mail server.

`create_app()` instantiates the sender based on `Config.EMAIL_MODE` and
stashes it at `app.extensions["email_sender"]` (Flask's own convention for
extension-owned state keyed on the app - see `flask.Flask.extensions`).
Route code reaches it via `current_app.extensions["email_sender"]`.
"""
from abc import ABC, abstractmethod

import requests


class EmailSender(ABC):
    @abstractmethod
    def send(self, to: str, subject: str, body: str) -> None:
        """Send (or, for stub implementations, simulate sending) an email."""
        raise NotImplementedError


class ConsoleEmailSender(EmailSender):
    """Dev-mode stub: prints the email to the server console instead of
    delivering it. Swappable seam for a future real-SMTP implementation."""

    def send(self, to: str, subject: str, body: str) -> None:
        print("[EMAIL STUB] " + "=" * 60)
        print(f"[EMAIL STUB] To: {to}")
        print(f"[EMAIL STUB] Subject: {subject}")
        print("[EMAIL STUB] " + "-" * 60)
        print(body)
        print("[EMAIL STUB] " + "=" * 60)


class ResendEmailSender(EmailSender):
    """Real transactional email via Resend's HTTP API (no `resend` package
    needed - `requests` is already a dependency and Resend's API is a plain
    REST POST). Fails at construction time, not at first send(), so a
    misconfigured deploy (EMAIL_MODE=resend with no API key) fails fast at
    startup instead of silently dropping every verification/reset email."""

    def __init__(self, api_key, from_address):
        if not api_key:
            raise RuntimeError(
                "RESEND_API_KEY is required when EMAIL_MODE=resend - get one at "
                "https://resend.com after verifying a sending domain."
            )
        if not from_address:
            raise RuntimeError("RESEND_FROM_EMAIL is required when EMAIL_MODE=resend.")
        self.api_key = api_key
        self.from_address = from_address

    def send(self, to: str, subject: str, body: str) -> None:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"from": self.from_address, "to": [to], "subject": subject, "text": body},
            timeout=10,
        )
        resp.raise_for_status()


def make_email_sender(email_mode: str, resend_api_key: str = "", resend_from: str = "") -> EmailSender:
    """Factory used by create_app(). "console" (the default) prints to
    stdout, for local dev; "resend" sends real email via Resend. Any other
    value falls back to the console sender rather than failing the whole
    app boot - see ConsoleEmailSender's docstring."""
    if email_mode == "resend":
        return ResendEmailSender(resend_api_key, resend_from)
    return ConsoleEmailSender()
