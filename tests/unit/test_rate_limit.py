from __future__ import annotations

import pytest

from vulpulse.crawler.rate_limit import AsyncRateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.value

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


async def test_bucket_allows_burst_then_waits() -> None:
    clock = FakeClock()
    limiter = AsyncRateLimiter(rate=2, period=1.0, clock=clock, sleep=clock.sleep)

    await limiter.acquire()
    await limiter.acquire()
    assert clock.sleeps == []

    await limiter.acquire()
    assert clock.sleeps == [0.5]


async def test_bucket_refills_with_time() -> None:
    clock = FakeClock()
    limiter = AsyncRateLimiter(rate=1, period=1.0, clock=clock, sleep=clock.sleep)

    await limiter.acquire()
    clock.value += 2.0
    await limiter.acquire()

    assert clock.sleeps == []


@pytest.mark.parametrize(("rate", "period"), [(0, 1.0), (1, 0.0), (-1, 1.0)])
def test_invalid_configuration(rate: int, period: float) -> None:
    with pytest.raises(ValueError):
        AsyncRateLimiter(rate=rate, period=period)


async def test_invalid_token_count() -> None:
    limiter = AsyncRateLimiter(rate=1, period=1.0)

    with pytest.raises(ValueError):
        await limiter.acquire(0)

    with pytest.raises(ValueError):
        await limiter.acquire(2)
