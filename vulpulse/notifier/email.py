"""SMTP email channel."""

from __future__ import annotations

import asyncio
import smtplib
from email.message import EmailMessage
from typing import Any

from vulpulse.config import Settings
from vulpulse.notifier.base import NotificationChannel, NotificationMessage


class EmailChannel(NotificationChannel):
    name = "email"

    def __init__(self, config: dict[str, Any], settings: Settings) -> None:
        self.recipients = _recipients(config.get("to"))
        if not self.recipients:
            raise ValueError("email channel requires a non-empty `to` list")
        self.settings = settings

    async def send(self, message: NotificationMessage) -> None:
        await asyncio.to_thread(self._send_sync, message)

    def _send_sync(self, message: NotificationMessage) -> None:
        settings = self.settings
        if not settings.smtp_host or not settings.smtp_from:
            raise RuntimeError("SMTP host and sender must be configured")

        email = EmailMessage()
        email["Subject"] = message.subject
        email["From"] = settings.smtp_from
        email["To"] = ", ".join(self.recipients)
        email.set_content(message.text)

        if settings.smtp_use_ssl:
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(
                settings.smtp_host,
                settings.smtp_port,
                timeout=20,
            )
        else:
            smtp = smtplib.SMTP(
                settings.smtp_host,
                settings.smtp_port,
                timeout=20,
            )

        with smtp:
            if settings.smtp_use_tls and not settings.smtp_use_ssl:
                smtp.starttls()
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(email)


def _recipients(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []
