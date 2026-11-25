from __future__ import annotations

import gzip

import httpx
import pytest
import respx

from vulpulse.crawler.http import (
    HttpClient,
    ResponseTooLarge,
    UnexpectedRedirect,
)


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


@respx.mock
async def test_decodes_gzip_once() -> None:
    payload = gzip.compress(b'{"ok": true}')
    respx.get("https://example.test/gzip").mock(
        return_value=httpx.Response(
            200,
            content=payload,
            headers={"Content-Encoding": "gzip"},
        )
    )

    async with _client() as client:
        payload_json = await client.get_json("https://example.test/gzip")

    assert payload_json == {"ok": True}


@respx.mock
async def test_rejects_oversized_response() -> None:
    respx.get("https://example.test/large").mock(
        return_value=httpx.Response(200, content=b"x" * 100)
    )

    async with _client(max_response_bytes=10) as client:
        with pytest.raises(ResponseTooLarge):
            await client.get_bytes("https://example.test/large")


@respx.mock
async def test_rejects_cross_origin_redirect() -> None:
    respx.get("https://example.test/redirect").mock(
        return_value=httpx.Response(
            302,
            headers={"Location": "https://internal.test/secret"},
        )
    )

    async with _client() as client:
        with pytest.raises(UnexpectedRedirect):
            await client.get_json("https://example.test/redirect")


@respx.mock
async def test_follows_same_host_redirect() -> None:
    respx.get("https://example.test/start").mock(
        return_value=httpx.Response(
            302,
            headers={"Location": "https://example.test/final"},
        )
    )
    respx.get("https://example.test/final").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )

    async with _client() as client:
        payload = await client.get_json("https://example.test/start")

    assert payload == {"ok": True}


@respx.mock
async def test_rejects_too_many_redirects() -> None:
    respx.get("https://example.test/loop").mock(
        return_value=httpx.Response(
            302,
            headers={"Location": "https://example.test/loop"},
        )
    )

    async with _client(max_redirects=1) as client:
        with pytest.raises(UnexpectedRedirect, match="too many redirects"):
            await client.get_json("https://example.test/loop")
