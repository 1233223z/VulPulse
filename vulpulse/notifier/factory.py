"""Build a concrete channel from a database row."""

from __future__ import annotations

from vulpulse.config import Settings
from vulpulse.db.models import Channel
from vulpulse.notifier.base import NotificationChannel
from vulpulse.notifier.email import EmailChannel
from vulpulse.notifier.wecom import WeComChannel, validate_webhook_url


def build_channel(channel: Channel, settings: Settings) -> NotificationChannel:
    config = channel.config or {}

    if channel.type == "wecom":
        webhook_url = str(config.get("webhook_url") or settings.wecom_webhook_url or "")
        validate_webhook_url(webhook_url, settings.wecom_allowed_hosts)
        return WeComChannel(webhook_url)

    if channel.type == "email":
        return EmailChannel(config, settings)

    raise ValueError(f"Unsupported channel type: {channel.type}")
