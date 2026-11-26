from __future__ import annotations

import smtplib
import ssl

import pytest

from vulpulse.config import Settings
from vulpulse.notifier.base import NotificationMessage
from vulpulse.notifier.email import EmailChannel

MESSAGE = NotificationMessage(
    subject="subject",
    text="text",
    markdown="markdown",
    url="https://example.test",
)


def test_rejects_missing_recipients() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    with pytest.raises(ValueError, match="non-empty"):
        EmailChannel({"to": []}, settings)
    with pytest.raises(ValueError, match="non-empty"):
        EmailChannel({"to": 42}, settings)


def test_requires_smtp_host_and_sender() -> None:
    channel = EmailChannel({"to": ["to@example.test"]}, Settings(_env_file=None))  # type: ignore[call-arg]

    with pytest.raises(RuntimeError, match="SMTP host"):
        channel._send_sync(MESSAGE)


def test_accepts_single_recipient_string() -> None:
    channel = EmailChannel(
        {"to": "to@example.test"},
        Settings(_env_file=None),  # type: ignore[call-arg]
    )

    assert channel.recipients == ["to@example.test"]


def test_starttls_uses_verified_context(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            captured["host"] = host

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            return None

        def starttls(self, context: ssl.SSLContext | None = None) -> None:
            captured["context"] = context

        def login(self, username: str, password: str) -> None:
            captured["login"] = (username, password)

        def send_message(self, message) -> None:
            captured["message"] = message

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        smtp_host="smtp.test",
        smtp_from="from@example.test",
        smtp_username="user",
        smtp_password="password",
        smtp_use_tls=True,
        smtp_use_ssl=False,
    )
    channel = EmailChannel({"to": ["to@example.test"]}, settings)

    channel._send_sync(MESSAGE)

    context = captured["context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_smtp_ssl_uses_verified_context(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeSMTPSSL:
        def __init__(
            self,
            host: str,
            port: int,
            timeout: int,
            context: ssl.SSLContext | None = None,
        ) -> None:
            captured["context"] = context

        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            return None

        def login(self, username: str, password: str) -> None:
            pass

        def send_message(self, message) -> None:
            pass

    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTPSSL)
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        smtp_host="smtp.test",
        smtp_from="from@example.test",
        smtp_use_tls=False,
        smtp_use_ssl=True,
    )
    channel = EmailChannel({"to": ["to@example.test"]}, settings)

    channel._send_sync(MESSAGE)

    context = captured["context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
