from __future__ import annotations

import httpx
import pytest
import respx

from vulpulse.crawler.http import HttpClient


def _client(**kwargs) -> HttpClient:
    defaults = {
        "max_attempts": 3,
        "retry_initial_wait": 0.001,
        "retry_max_wait": 0.001,
    }
    defaults.update(kwargs)
    return HttpClient(**defaults)


@respx.mock
async def test_get_json_success() -> None:
    respx.get("https://example.test/data").mock(return_value=httpx.Response(200, json={"ok": True}))

    async with _client() as client:
        payload = await client.get_json("https://example.test/data")

    assert payload == {"ok": True}


@respx.mock
async def test_retries_on_5xx_then_succeeds() -> None:
    respx.get("https://example.test/data").mock(
        side_effect=[
            httpx.Response(500),
            httpx.Response(200, json={"ok": True}),
        ]
    )

    async with _client() as client:
        payload = await client.get_json("https://example.test/data")

    assert payload == {"ok": True}


@respx.mock
async def test_retries_on_429() -> None:
    route = respx.get("https://example.test/data").mock(
        side_effect=[
            httpx.Response(429),
            httpx.Response(200, json={"ok": True}),
        ]
    )

    async with _client() as client:
        await client.get_json("https://example.test/data")

    assert route.call_count == 2


@respx.mock
async def test_does_not_retry_4xx() -> None:
    route = respx.get("https://example.test/missing").mock(return_value=httpx.Response(404))

    async with _client() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_json("https://example.test/missing")

    assert route.call_count == 1


@respx.mock
async def test_exhausts_retries_and_raises() -> None:
    route = respx.get("https://example.test/data").mock(return_value=httpx.Response(503))

    async with _client(max_attempts=2) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_json("https://example.test/data")

    assert route.call_count == 2
