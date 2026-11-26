from __future__ import annotations

import re

import pytest
from httpx import AsyncClient

from vulpulse.config import get_settings
from vulpulse.db.repositories import ChannelRepository, SubscriptionRepository
from vulpulse.db.session import Database
from vulpulse.web.admin_auth import reset_login_attempts


@pytest.fixture(autouse=True)
def _reset_login_rate_limit() -> None:
    reset_login_attempts()
    yield
    reset_login_attempts()


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


async def test_admin_login_handles_non_ascii_key(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULPULSE_API_KEY", "test-key")
    get_settings.cache_clear()

    response = await client.post(
        "/admin/login",
        data={"api_key": "é"},
        follow_redirects=False,
    )

    assert response.status_code == 401


async def test_admin_session_is_invalidated_by_key_rotation(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (await login(client, monkeypatch, key="key-one")).status_code == 303
    assert (await client.get("/admin/subscriptions")).status_code == 200

    monkeypatch.setenv("VULPULSE_API_KEY", "key-two")
    get_settings.cache_clear()

    response = await client.get("/admin/subscriptions", follow_redirects=False)
    assert response.status_code == 303


async def test_admin_login_is_rate_limited(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULPULSE_API_KEY", "test-key")
    get_settings.cache_clear()

    for _ in range(5):
        response = await client.post(
            "/admin/login",
            data={"api_key": "wrong"},
            follow_redirects=False,
        )
        assert response.status_code == 401

    response = await client.post(
        "/admin/login",
        data={"api_key": "wrong"},
        follow_redirects=False,
    )
    assert response.status_code == 429


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
            "webhook_url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
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
            "webhook_url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test",
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


async def test_admin_channel_validation_and_lifecycle(
    client: AsyncClient,
    db: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await login(client, monkeypatch)
    page = await client.get("/admin/channels")
    token = csrf_from(page.text)

    missing_name = await client.post(
        "/admin/channels",
        data={"name": "", "channel_type": "email", "email_to": "a@test", "csrf_token": token},
        follow_redirects=False,
    )
    assert missing_name.status_code == 400
    assert "Name is required" in missing_name.text

    bad_type = await client.post(
        "/admin/channels",
        data={"name": "bad-type", "channel_type": "slack", "csrf_token": token},
        follow_redirects=False,
    )
    assert bad_type.status_code == 400
    assert "wecom or email" in bad_type.text

    bad_webhook = await client.post(
        "/admin/channels",
        data={
            "name": "bad-webhook",
            "channel_type": "wecom",
            "webhook_url": "http://evil.test/hook",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert bad_webhook.status_code == 400
    assert "HTTPS" in bad_webhook.text

    missing_email = await client.post(
        "/admin/channels",
        data={"name": "missing-email", "channel_type": "email", "csrf_token": token},
        follow_redirects=False,
    )
    assert missing_email.status_code == 400
    assert "recipient" in missing_email.text

    created = await client.post(
        "/admin/channels",
        data={
            "name": "email-ui",
            "channel_type": "email",
            "email_to": "security@example.test",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert created.status_code == 303

    async with db.session() as session:
        channel = await ChannelRepository(session).get_by_name("email-ui")
        assert channel is not None
        channel_id = channel.id

    duplicate = await client.post(
        "/admin/channels",
        data={
            "name": "email-ui",
            "channel_type": "email",
            "email_to": "other@example.test",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert duplicate.status_code == 400
    assert "already exists" in duplicate.text

    toggled = await client.post(
        f"/admin/channels/{channel_id}/toggle",
        data={"csrf_token": token},
        follow_redirects=False,
    )
    assert toggled.status_code == 303

    async with db.session() as session:
        channel = await ChannelRepository(session).get_by_id(channel_id)
        assert channel is not None and channel.enabled is False

    deleted = await client.post(
        f"/admin/channels/{channel_id}/delete",
        data={"csrf_token": token},
        follow_redirects=False,
    )
    assert deleted.status_code == 303

    missing = await client.post(
        "/admin/channels/999999/delete",
        data={"csrf_token": token},
        follow_redirects=False,
    )
    assert missing.status_code == 404


async def test_admin_subscription_validation_and_lifecycle(
    client: AsyncClient,
    db: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with db.session() as session:
        channel = await ChannelRepository(session).create(
            "subscription-email",
            "email",
            {"to": ["security@example.test"]},
        )
        await session.commit()
        channel_id = channel.id

    await login(client, monkeypatch)
    page = await client.get("/admin/subscriptions")
    token = csrf_from(page.text)

    missing_name = await client.post(
        "/admin/subscriptions",
        data={"name": "", "channel_id": str(channel_id), "csrf_token": token},
        follow_redirects=False,
    )
    assert missing_name.status_code == 400
    assert "Name is required" in missing_name.text

    bad_channel = await client.post(
        "/admin/subscriptions",
        data={"name": "bad-channel", "channel_id": "not-a-number", "csrf_token": token},
        follow_redirects=False,
    )
    assert bad_channel.status_code == 400
    assert "valid channel" in bad_channel.text

    bad_rule = await client.post(
        "/admin/subscriptions",
        data={
            "name": "bad-rule",
            "channel_id": str(channel_id),
            "cvss_min": "not-a-number",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert bad_rule.status_code == 400
    assert "Invalid rule" in bad_rule.text

    bad_window = await client.post(
        "/admin/subscriptions",
        data={
            "name": "bad-window",
            "channel_id": str(channel_id),
            "within_days": "not-a-number",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert bad_window.status_code == 400
    assert "Invalid rule" in bad_window.text

    created = await client.post(
        "/admin/subscriptions",
        data={
            "name": "filtered-ui",
            "channel_id": str(channel_id),
            "severities": ["critical", "high"],
            "keywords": "struts, log4j",
            "vendors": "apache",
            "products": "struts",
            "sources": "nvd",
            "kev": "on",
            "exploit": "on",
            "cvss_min": "9.0",
            "epss_min": "0.5",
            "within_days": "30",
            "csrf_token": token,
        },
        follow_redirects=False,
    )
    assert created.status_code == 303

    async with db.session() as session:
        subscription = await SubscriptionRepository(session).get_by_name("filtered-ui")
        assert subscription is not None
        subscription_id = subscription.id
        assert subscription.rule_json["keywords"] == ["struts", "log4j"]
        assert subscription.rule_json["published_within_days"] == 30

    duplicate = await client.post(
        "/admin/subscriptions",
        data={"name": "filtered-ui", "channel_id": str(channel_id), "csrf_token": token},
        follow_redirects=False,
    )
    assert duplicate.status_code == 400
    assert "already exists" in duplicate.text

    toggled = await client.post(
        f"/admin/subscriptions/{subscription_id}/toggle",
        data={"csrf_token": token},
        follow_redirects=False,
    )
    assert toggled.status_code == 303

    missing = await client.post(
        "/admin/subscriptions/999999/toggle",
        data={"csrf_token": token},
        follow_redirects=False,
    )
    assert missing.status_code == 404

    deleted = await client.post(
        f"/admin/subscriptions/{subscription_id}/delete",
        data={"csrf_token": token},
        follow_redirects=False,
    )
    assert deleted.status_code == 303

    missing_csrf = await client.post(
        "/admin/subscriptions/999999/delete",
        data={},
        follow_redirects=False,
    )
    assert missing_csrf.status_code == 400
