from __future__ import annotations

from fastapi import Request

from vulpulse.api.rate_limit import (
    SlidingWindowRateLimiter,
    client_ip,
    parse_trusted_proxies,
)


def make_request(peer: str, forwarded: str | None = None) -> Request:
    headers = []
    if forwarded is not None:
        headers.append((b"x-forwarded-for", forwarded.encode()))
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/api",
            "raw_path": b"/api",
            "query_string": b"",
            "headers": headers,
            "client": (peer, 12345),
            "server": ("testserver", 80),
        }
    )


def test_limiter_allows_requests_up_to_limit() -> None:
    limiter = SlidingWindowRateLimiter(2, window_seconds=60)

    first = limiter.check("client", now=0)
    second = limiter.check("client", now=1)

    assert first.allowed is True
    assert first.remaining == 1
    assert second.allowed is True
    assert second.remaining == 0

    blocked = limiter.check("client", now=2)

    assert blocked.allowed is False
    assert blocked.remaining == 0
    assert blocked.retry_after == 58


def test_limiter_window_expires_old_requests() -> None:
    limiter = SlidingWindowRateLimiter(1, window_seconds=60)

    assert limiter.check("client", now=0).allowed is True
    assert limiter.check("client", now=30).allowed is False
    assert limiter.check("client", now=60).allowed is True


def test_limiter_tracks_clients_independently() -> None:
    limiter = SlidingWindowRateLimiter(1, window_seconds=60)

    assert limiter.check("one", now=0).allowed is True
    assert limiter.check("two", now=0).allowed is True
    assert limiter.check("one", now=0).allowed is False
    assert limiter.check("two", now=0).allowed is False


def test_limiter_can_be_disabled() -> None:
    limiter = SlidingWindowRateLimiter(0)

    assert limiter.enabled is False
    for _ in range(20):
        assert limiter.check("client").allowed is True


def test_limiter_bounds_tracked_clients() -> None:
    limiter = SlidingWindowRateLimiter(1, max_clients=2)

    limiter.check("one", now=0)
    limiter.check("two", now=0)
    limiter.check("three", now=0)

    assert len(limiter._buckets) == 2


def test_parse_trusted_proxies_accepts_cidrs_and_addresses() -> None:
    networks = parse_trusted_proxies("10.0.0.0/8, 192.0.2.1, 2001:db8::/32")

    assert len(networks) == 3


def test_client_ip_ignores_forwarded_header_without_trusted_proxies() -> None:
    request = make_request("203.0.113.5", "198.51.100.9")

    assert client_ip(request) == "203.0.113.5"


def test_client_ip_uses_forwarded_header_from_trusted_proxy() -> None:
    request = make_request("10.1.2.3", "203.0.113.7, 10.2.3.4")
    networks = parse_trusted_proxies("10.0.0.0/8")

    assert client_ip(request, networks) == "203.0.113.7"


def test_client_ip_ignores_forwarded_header_from_untrusted_peer() -> None:
    request = make_request("203.0.113.5", "198.51.100.9")
    networks = parse_trusted_proxies("10.0.0.0/8")

    assert client_ip(request, networks) == "203.0.113.5"


def test_client_ip_rejects_malformed_forwarded_header() -> None:
    request = make_request("10.1.2.3", "not-an-ip")
    networks = parse_trusted_proxies("10.0.0.0/8")

    assert client_ip(request, networks) == "10.1.2.3"


def test_client_ip_returns_trusted_chain_when_all_hops_are_trusted() -> None:
    request = make_request("10.1.2.3", "10.2.3.4, 10.3.4.5")
    networks = parse_trusted_proxies("10.0.0.0/8")

    assert client_ip(request, networks) == "10.2.3.4"
