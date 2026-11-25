"""WeCom (企业微信) group robot webhook channel."""

from __future__ import annotations

import httpx

from vulpulse.notifier.base import NotificationChannel, NotificationMessage


class WeComChannel(NotificationChannel):
    name = "wecom"

    def __init__(
        self,
        webhook_url: str,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not webhook_url:
            raise ValueError("WeCom channel requires a webhook_url")
        self.webhook_url = webhook_url
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=15.0)

    async def send(self, message: NotificationMessage) -> None:
        response = await self._client.post(
            self.webhook_url,
            json={
                "msgtype": "markdown",
                "markdown": {"content": message.markdown},
            },
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("errcode") != 0:
            raise RuntimeError(f"WeCom webhook rejected the message: {payload}")

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()
