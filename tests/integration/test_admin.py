from __future__ import annotations

import re

import pytest
from httpx import AsyncClient

from vulpulse.config import get_settings
from vulpulse.db.repositories import ChannelRepository, SubscriptionRepository
from vulpulse.db.session import Database


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


async def login(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    key: str = "test-key",
):
    monkeypatch.setenv("VULPULSE_API_KEY", key)
    get_settings.cache_clear()
    return await client.post(
        "/admin/login",
        data={"api_key": key},
        follow_redirects=False,
    )


async def test_admin_redirects_to_login(client: AsyncClient) -> None:
    response = await client.get("/admin/subscriptions", follow_redirects=False)

    assert response.status_code == 303
    assert "/admin/login" in response.headers["location"]


async def test_admin_login_disabled_without_api_key(client: AsyncClient) -> None:
    response = await client.post(
        "/admin/login",
        data={"api_key": "anything"},
        follow_redirects=False,
    )

    assert response.status_code == 503


async def test_admin_login_rejects_wrong_key(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULPULSE_API_KEY", "test-key")
    get_settings.cache_clear()

    response = await client.post(
        "/admin/login",
        data={"api_key": "wrong"},
        follow_redirects=False,
    )

    assert response.status_code == 401


async def test_admin_channel_and_subscription_crud(
    client: AsyncClient,
    db: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = await login(client, monkeypatch)
    assert response.status_code == 303

    page = await client.get("/admin/subscriptions")
    assert page.status_code == 200
    token = csrf_from(page.text)

    created = await client.post(
        "/admin/channels",
        data={
            "name": "wecom-ui",
            "channel_type": "wecom",
            "webhook_url": "https://wecom.test/hook",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert created.status_code == 303

    async with db.session() as session:
        channel = await ChannelRepository(session).get_by_name("wecom-ui")
        assert channel is not None
        channel_id = channel.id

    created_subscription = await client.post(
        "/admin/subscriptions",
        data={
            "name": "critical-kev-ui",
            "channel_id": str(channel_id),
            "severities": ["critical", "high"],
            "kev": "on",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert created_subscription.status_code == 303

    page = await client.get("/admin/subscriptions")
    assert "critical-kev-ui" in page.text
    assert "wecom-ui" in page.text

    async with db.session() as session:
        subscription = await SubscriptionRepository(session).get_by_name("critical-kev-ui")
        assert subscription is not None
        assert subscription.rule_json["in_kev"] is True
        subscription_id = subscription.id

    toggled = await client.post(
        f"/admin/subscriptions/{subscription_id}/toggle",
        data={"csrf_token": token},
        follow_redirects=False,
    )
    assert toggled.status_code == 303

    async with db.session() as session:
        subscription = await SubscriptionRepository(session).get_by_id(subscription_id)
        assert subscription is not None
        assert subscription.enabled is False

    deleted = await client.post(
        f"/admin/subscriptions/{subscription_id}/delete",
        data={"csrf_token": token},
        follow_redirects=False,
    )
    assert deleted.status_code == 303

    async with db.session() as session:
        assert await SubscriptionRepository(session).get_by_id(subscription_id) is None


async def test_admin_rejects_missing_csrf(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = await login(client, monkeypatch)
    assert response.status_code == 303

    response = await client.post(
        "/admin/channels",
        data={
            "name": "no-csrf",
            "channel_type": "wecom",
            "webhook_url": "https://wecom.test/hook",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


async def test_admin_logout_clears_session(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await login(client, monkeypatch)
    page = await client.get("/admin/channels")
    token = csrf_from(page.text)

    response = await client.post(
        "/admin/logout",
        data={"csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303

    response = await client.get("/admin/subscriptions", follow_redirects=False)
    assert response.status_code == 303
    assert "/admin/login" in response.headers["location"]
