from __future__ import annotations

import pytest

from vulpulse.config import Settings
from vulpulse.db.models import Channel
from vulpulse.notifier.email import EmailChannel
from vulpulse.notifier.factory import build_channel
from vulpulse.notifier.wecom import WeComChannel


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {"_env_file": None}
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_builds_wecom_channel_from_row_config() -> None:
    channel = Channel(
        name="wecom",
        type="wecom",
        config={"webhook_url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x"},
    )

    built = build_channel(channel, make_settings())

    assert isinstance(built, WeComChannel)


def test_builds_wecom_channel_from_settings_default() -> None:
    channel = Channel(name="wecom", type="wecom", config=None)
    settings = make_settings(
        wecom_webhook_url="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x"
    )

    built = build_channel(channel, settings)

    assert isinstance(built, WeComChannel)


def test_builds_email_channel_from_row_config() -> None:
    channel = Channel(name="mail", type="email", config={"to": ["security@example.test"]})

    built = build_channel(channel, make_settings(smtp_host="smtp.test", smtp_from="from@test"))

    assert isinstance(built, EmailChannel)


def test_rejects_unknown_channel_type() -> None:
    channel = Channel(name="bad", type="slack", config={})

    with pytest.raises(ValueError, match="Unsupported channel type"):
        build_channel(channel, make_settings())


def test_rejects_unconfigured_wecom() -> None:
    channel = Channel(name="wecom", type="wecom", config={})

    with pytest.raises(ValueError, match="HTTPS"):
        build_channel(channel, make_settings())


def test_rejects_wecom_host_outside_allowlist() -> None:
    channel = Channel(
        name="wecom",
        type="wecom",
        config={"webhook_url": "https://evil.test/hook"},
    )

    with pytest.raises(ValueError, match="not allowed"):
        build_channel(channel, make_settings())
