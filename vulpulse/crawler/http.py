"""Shared async HTTP client with rate limiting and retries."""

from __future__ import annotations

from typing import Any

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential_jitter,
)

from vulpulse.crawler.rate_limit import AsyncRateLimiter


def _is_retryable(exc: BaseException) -> bool:
    """Retry transport errors, 429s and 5xx responses."""
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or 500 <= status < 600
    return isinstance(exc, httpx.TransportError)


class HttpClient:
    """Thin ``httpx.AsyncClient`` wrapper used by every source adapter."""

    def __init__(
        self,
        *,
        timeout: float = 30.0,
        user_agent: str = "VulPulse/0.1",
        rate_limiter: AsyncRateLimiter | None = None,
        max_attempts: int = 3,
        retry_initial_wait: float = 1.0,
        retry_max_wait: float = 8.0,
        headers: dict[str, str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")

        self._client = httpx.AsyncClient(
            timeout=timeout,
            transport=transport,
            follow_redirects=True,
            headers={"User-Agent": user_agent, **(headers or {})},
        )
        self._rate_limiter = rate_limiter
        self._max_attempts = max_attempts
        self._retry_initial_wait = retry_initial_wait
        self._retry_max_wait = retry_max_wait

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Perform a request, retrying transient failures."""
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self._max_attempts),
            wait=wait_exponential_jitter(
                multiplier=self._retry_initial_wait,
                max=self._retry_max_wait,
            ),
            retry=retry_if_exception(_is_retryable),
            reraise=True,
        ):
            with attempt:
                if self._rate_limiter is not None:
                    await self._rate_limiter.acquire()
                response = await self._client.request(method, url, **kwargs)
                response.raise_for_status()
                return response

        raise RuntimeError("retry loop exited without a response")  # pragma: no cover

    async def get_json(self, url: str, **kwargs: Any) -> Any:
        response = await self.request("GET", url, **kwargs)
        return response.json()

    async def get_text(self, url: str, **kwargs: Any) -> str:
        response = await self.request("GET", url, **kwargs)
        return response.text

    async def get_bytes(self, url: str, **kwargs: Any) -> bytes:
        response = await self.request("GET", url, **kwargs)
        return response.content
