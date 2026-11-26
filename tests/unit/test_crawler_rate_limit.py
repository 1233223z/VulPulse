from __future__ import annotations

import pytest

from vulpulse.crawler.rate_limit import AsyncRateLimiter


class FakeTime:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError, match="rate"):
        AsyncRateLimiter(0)
    with pytest.raises(ValueError, match="period"):
        AsyncRateLimiter(1, 0)


async def test_rejects_invalid_token_requests() -> None:
    limiter = AsyncRateLimiter(2)

    with pytest.raises(ValueError, match="positive"):
        await limiter.acquire(0)
    with pytest.raises(ValueError, match="exceed"):
        await limiter.acquire(3)


async def test_bucket_refills_and_sleeps() -> None:
    fake = FakeTime()
    limiter = AsyncRateLimiter(2, 1.0, clock=fake.clock, sleep=fake.sleep)

    await limiter.acquire()
    await limiter.acquire()
    assert fake.sleeps == []

    await limiter.acquire()
    assert fake.sleeps == [0.5]

    fake.now += 1.0
    await limiter.acquire()
    assert fake.sleeps == [0.5]


async def test_partial_refill_is_accumulated() -> None:
    fake = FakeTime()
    limiter = AsyncRateLimiter(2, 1.0, clock=fake.clock, sleep=fake.sleep)

    await limiter.acquire(2)
    fake.now += 0.25
    await limiter.acquire()
    assert fake.sleeps == [0.25]
