"""Build a concrete channel from a database row."""

from __future__ import annotations

from vulpulse.config import Settings
from vulpulse.db.models import Channel
from vulpulse.notifier.base import NotificationChannel
from vulpulse.notifier.email import EmailChannel
from vulpulse.notifier.wecom import WeComChannel


def build_channel(channel: Channel, settings: Settings) -> NotificationChannel:
    config = channel.config or {}

    if channel.type == "wecom":
        webhook_url = config.get("webhook_url") or settings.wecom_webhook_url
        return WeComChannel(str(webhook_url or ""))

    if channel.type == "email":
        return EmailChannel(config, settings)

    raise ValueError(f"Unsupported channel type: {channel.type}")
