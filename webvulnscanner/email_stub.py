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


def make_email_sender(email_mode: str) -> EmailSender:
    """Factory used by create_app(). Only "console" is implemented today;
    unrecognized modes fall back to the console sender rather than failing
    the whole app boot, since this is a local dev tool."""
    if email_mode == "console":
        return ConsoleEmailSender()
    return ConsoleEmailSender()
