"""In-process sliding-window rate limiting for the public API."""

from __future__ import annotations

import ipaddress
import math
import time
from collections import deque
from dataclasses import dataclass

from fastapi import Request

WINDOW_SECONDS = 60.0
MAX_TRACKED_CLIENTS = 4096


@dataclass(frozen=True)
class RateLimitResult:
    """Outcome of one rate-limit check."""

    allowed: bool
    remaining: int
    retry_after: int


class SlidingWindowRateLimiter:
    """Per-client sliding-window limiter.

    State is intentionally in-process: VulPulse runs a single API process
    against SQLite, and this limit is a safety net rather than a distributed
    quota. Deployments with multiple API workers should also enforce a limit
    at the reverse proxy.
    """

    def __init__(
        self,
        limit_per_minute: int,
        *,
        window_seconds: float = WINDOW_SECONDS,
        max_clients: int = MAX_TRACKED_CLIENTS,
    ) -> None:
        self.limit = max(0, limit_per_minute)
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self._buckets: dict[str, deque[float]] = {}

    @property
    def enabled(self) -> bool:
        return self.limit > 0

    def check(self, key: str, *, now: float | None = None) -> RateLimitResult:
        """Record a request for ``key`` and return whether it is allowed."""
        if not self.enabled:
            return RateLimitResult(allowed=True, remaining=0, retry_after=0)

        current = time.monotonic() if now is None else now
        bucket = self._buckets.setdefault(key, deque())
        cutoff = current - self.window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= self.limit:
            retry_after = max(1, math.ceil(bucket[0] + self.window_seconds - current))
            self._prune(current)
            return RateLimitResult(allowed=False, remaining=0, retry_after=retry_after)

        bucket.append(current)
        self._prune(current)
        return RateLimitResult(
            allowed=True,
            remaining=max(0, self.limit - len(bucket)),
            retry_after=0,
        )

    def reset(self) -> None:
        """Clear all state. Intended for tests and process restarts."""
        self._buckets.clear()

    def _prune(self, now: float) -> None:
        """Bound memory if many distinct clients hit the API."""
        if len(self._buckets) <= self.max_clients:
            return

        cutoff = now - self.window_seconds
        stale = [key for key, bucket in self._buckets.items() if not bucket or bucket[-1] <= cutoff]
        for key in stale:
            del self._buckets[key]

        while len(self._buckets) > self.max_clients:
            self._buckets.pop(next(iter(self._buckets)))


def parse_trusted_proxies(
    value: str,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse a comma-separated list of IP addresses or CIDR networks."""
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in value.split(","):
        item = item.strip()
        if item:
            networks.append(ipaddress.ip_network(item, strict=False))
    return tuple(networks)


def client_ip(
    request: Request,
    trusted_proxies: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (),
) -> str:
    """Return the client IP, trusting ``X-Forwarded-For`` only when configured.

    Forwarded headers are honored only when the immediate peer is in
    ``trusted_proxies``. The header is then walked right-to-left, skipping
    trusted proxies, so a client cannot spoof its address by sending its own
    ``X-Forwarded-For`` through an untrusted connection.
    """
    peer = request.client.host if request.client else "unknown"
    if not trusted_proxies:
        return peer

    try:
        peer_address = ipaddress.ip_address(peer)
    except ValueError:
        return peer

    if not any(peer_address in network for network in trusted_proxies):
        return peer

    forwarded = request.headers.get("x-forwarded-for", "")
    if not forwarded:
        return peer

    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for item in forwarded.split(","):
        try:
            candidates.append(ipaddress.ip_address(item.strip()))
        except ValueError:
            # A malformed header is not a trustworthy basis for identity.
            return peer

    for candidate in reversed(candidates):
        if not any(candidate in network for network in trusted_proxies):
            return str(candidate)
    return str(candidates[0]) if candidates else peer
