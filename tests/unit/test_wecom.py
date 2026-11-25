from __future__ import annotations

import json

import httpx
import pytest

from vulpulse.notifier.base import NotificationMessage
from vulpulse.notifier.wecom import WeComChannel

MESSAGE = NotificationMessage(
    subject="subject",
    text="text",
    markdown="## VulPulse alert",
    url="https://example.test/vulns/CVE-2024-0001",
)


async def test_send_posts_markdown_payload() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json={"errcode": 0, "errmsg": "ok"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    channel = WeComChannel("https://wecom.test/webhook", client=client)

    try:
        await channel.send(MESSAGE)
    finally:
        await client.aclose()

    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["msgtype"] == "markdown"
    assert payload["markdown"]["content"] == "## VulPulse alert"


async def test_send_raises_on_business_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"errcode": 40001, "errmsg": "invalid key"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    channel = WeComChannel("https://wecom.test/webhook", client=client)

    try:
        with pytest.raises(RuntimeError, match="WeCom webhook rejected"):
            await channel.send(MESSAGE)
    finally:
        await client.aclose()
