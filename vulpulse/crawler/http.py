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


class ResponseTooLarge(RuntimeError):
    """Raised when a source response exceeds the configured byte cap."""


class UnexpectedRedirect(RuntimeError):
    """Raised when a source unexpectedly redirects to another URL."""


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
        max_response_bytes: int = 64 * 1024 * 1024,
        max_redirects: int = 3,
        headers: dict[str, str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if max_redirects < 0:
            raise ValueError("max_redirects must be zero or positive")

        self._client = httpx.AsyncClient(
            timeout=timeout,
            transport=transport,
            follow_redirects=False,
            headers={"User-Agent": user_agent, **(headers or {})},
        )
        self._rate_limiter = rate_limiter
        self._max_attempts = max_attempts
        self._retry_initial_wait = retry_initial_wait
        self._retry_max_wait = retry_max_wait
        self._max_response_bytes = max_response_bytes
        self._max_redirects = max_redirects

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _read_capped(self, response: httpx.Response) -> bytes:
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self._max_response_bytes:
                    raise ResponseTooLarge(f"response exceeds {self._max_response_bytes} bytes")
            except ValueError:
                pass

        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > self._max_response_bytes:
                raise ResponseTooLarge(f"response exceeds {self._max_response_bytes} bytes")
            chunks.append(chunk)
        return b"".join(chunks)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Perform a bounded request with same-host redirects and retries."""
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

                current = httpx.URL(url)
                redirects = 0
                request_kwargs = dict(kwargs)

                while True:
                    async with self._client.stream(
                        method,
                        current,
                        **request_kwargs,
                    ) as streamed:
                        if 300 <= streamed.status_code < 400:
                            location = streamed.headers.get("location")
                            if method.upper() != "GET" or not location:
                                raise UnexpectedRedirect(
                                    f"unexpected redirect from {url}: {streamed.status_code}"
                                )
                            next_url = current.join(location)
                            if next_url.scheme != "https" or next_url.host != current.host:
                                raise UnexpectedRedirect(f"cross-origin redirect from {url}")
                            redirects += 1
                            if redirects > self._max_redirects:
                                raise UnexpectedRedirect(f"too many redirects from {url}")
                            current = next_url
                            request_kwargs.pop("params", None)
                            continue

                        content = await self._read_capped(streamed)
                        headers = [
                            (name, value)
                            for name, value in streamed.headers.multi_items()
                            if name.lower()
                            not in {
                                "content-encoding",
                                "content-length",
                                "transfer-encoding",
                            }
                        ]
                        response = httpx.Response(
                            streamed.status_code,
                            headers=headers,
                            content=content,
                            request=streamed.request,
                        )

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
