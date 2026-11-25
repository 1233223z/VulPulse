"""WeCom (企业微信) group robot webhook channel."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from vulpulse.notifier.base import NotificationChannel, NotificationMessage


def validate_webhook_url(url: str, allowed_hosts: str) -> None:
    """Require HTTPS and an allowlisted host for WeCom webhooks."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("WeCom webhook must use HTTPS.")
    if not parsed.hostname:
        raise ValueError("WeCom webhook has no host.")
    if parsed.username or parsed.password:
        raise ValueError("WeCom webhook must not include credentials.")
    allowed = {host.strip().lower() for host in allowed_hosts.split(",") if host.strip()}
    if allowed and parsed.hostname.lower() not in allowed:
        raise ValueError("WeCom webhook host is not allowed.")


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
        if urlparse(webhook_url).scheme != "https":
            raise ValueError("WeCom webhook must use HTTPS.")
        self.webhook_url = webhook_url
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=15.0)

    async def send(self, message: NotificationMessage) -> None:
        try:
            response = await self._client.post(
                self.webhook_url,
                json={
                    "msgtype": "markdown",
                    "markdown": {"content": message.markdown},
                },
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(f"WeCom webhook returned HTTP {exc.response.status_code}") from exc
        except httpx.RequestError as exc:
            raise RuntimeError("WeCom webhook request failed") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError("WeCom webhook returned invalid JSON") from exc

        if payload.get("errcode") != 0:
            raise RuntimeError(
                f"WeCom webhook rejected the message: errcode={payload.get('errcode')}"
            )

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()
