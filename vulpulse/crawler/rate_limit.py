"""Async token-bucket rate limiter."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable


class AsyncRateLimiter:
    """Allow at most ``rate`` acquisitions per ``period`` seconds.

    The clock and sleep functions are injectable so tests do not need to wait
    for real time to pass.
    """

    def __init__(
        self,
        rate: int,
        period: float = 1.0,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        if period <= 0:
            raise ValueError("period must be positive")

        self._rate = float(rate)
        self._period = float(period)
        self._tokens = float(rate)
        self._updated_at = clock()
        self._clock = clock
        self._sleep = sleep
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        """Take ``tokens`` from the bucket, sleeping until enough are available."""
        if tokens <= 0:
            raise ValueError("tokens must be positive")
        if tokens > self._rate:
            raise ValueError("tokens cannot exceed the configured rate")

        async with self._lock:
            while True:
                now = self._clock()
                elapsed = max(0.0, now - self._updated_at)
                self._tokens = min(
                    self._rate,
                    self._tokens + elapsed * (self._rate / self._period),
                )
                self._updated_at = now

                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return

                missing = tokens - self._tokens
                await self._sleep(missing * (self._period / self._rate))
