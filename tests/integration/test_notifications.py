from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from vulpulse.config import Settings
from vulpulse.db.models import Delivery, Subscription
from vulpulse.db.repositories import (
    ChannelRepository,
    SubscriptionRepository,
    VulnerabilityRepository,
)
from vulpulse.db.session import Database
from vulpulse.notifier.base import NotificationMessage
from vulpulse.notifier.service import NotificationService
from vulpulse.timeutils import utcnow


class FakeChannel:
    def __init__(self, failures: int = 0) -> None:
        self.failures = failures
        self.attempts = 0
        self.messages: list[NotificationMessage] = []
        self.closed = False

    async def send(self, message: NotificationMessage) -> None:
        self.attempts += 1
        if self.attempts <= self.failures:
            raise RuntimeError("simulated delivery failure")
        self.messages.append(message)

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
async def db(tmp_path) -> AsyncIterator[Database]:
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'notify.db'}")
    await database.create_schema()
    yield database
    await database.dispose()


async def seed(db: Database) -> dict[str, int]:
    async with db.session() as session:
        channel = await ChannelRepository(session).create(
            "wecom-test",
            "wecom",
            {"webhook_url": "https://wecom.test/webhook"},
        )
        subscription = await SubscriptionRepository(session).create(
            "critical-kev",
            channel.id,
            {"severities": ["critical"], "in_kev": True},
        )

        repo = VulnerabilityRepository(session)
        target, _ = await repo.upsert(
            "cve:CVE-2024-0001",
            cve_id="CVE-2024-0001",
            title="KEV critical",
            severity="critical",
            in_kev=True,
            published_at=utcnow() - timedelta(days=1),
        )
        await repo.upsert(
            "cve:CVE-2024-0002",
            cve_id="CVE-2024-0002",
            title="Non-KEV critical",
            severity="critical",
            published_at=utcnow() - timedelta(days=1),
        )
        await repo.upsert(
            "cve:CVE-2024-0003",
            cve_id="CVE-2024-0003",
            title="KEV medium",
            severity="medium",
            in_kev=True,
            published_at=utcnow() - timedelta(days=1),
        )
        await session.commit()

        return {
            "subscription_id": subscription.id,
            "target_id": target.id,
        }


async def test_cycle_sends_once_and_deduplicates(db: Database) -> None:
    ids = await seed(db)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    fake = FakeChannel()
    service = NotificationService(
        db,
        settings,
        channel_factory=lambda channel, settings: fake,
    )

    first = await service.run_cycle()

    assert first.subscriptions == 1
    assert first.matched == 1
    assert first.created == 1
    assert first.sent == 1
    assert first.failed == 0
    assert len(fake.messages) == 1
    assert fake.messages[0].url.endswith("/vulns/CVE-2024-0001")

    async with db.session() as session:
        delivery = await session.scalar(select(Delivery))
        assert delivery is not None
        assert delivery.status == "sent"
        assert delivery.attempts == 1
        subscription = await session.get(Subscription, ids["subscription_id"])
        assert subscription is not None
        assert subscription.last_checked_at is not None

    second = await service.run_cycle()

    assert second.matched == 0
    assert second.created == 0
    assert second.sent == 0
    async with db.session() as session:
        assert await session.scalar(select(func.count(Delivery.id))) == 1


async def test_failed_delivery_is_retried(db: Database) -> None:
    await seed(db)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    fake = FakeChannel(failures=1)
    service = NotificationService(
        db,
        settings,
        channel_factory=lambda channel, settings: fake,
    )

    first = await service.run_cycle()

    assert first.created == 1
    assert first.sent == 0
    assert first.failed == 1
    async with db.session() as session:
        delivery = await session.scalar(select(Delivery))
        assert delivery is not None
        assert delivery.status == "failed"
        assert delivery.attempts == 1

    second = await service.run_cycle()

    assert second.created == 0
    assert second.sent == 1
    assert second.failed == 0
    async with db.session() as session:
        delivery = await session.scalar(select(Delivery))
        assert delivery is not None
        assert delivery.status == "sent"
        assert delivery.attempts == 2


async def test_dry_run_does_not_persist(db: Database) -> None:
    ids = await seed(db)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    fake = FakeChannel()
    service = NotificationService(
        db,
        settings,
        channel_factory=lambda channel, settings: fake,
    )

    stats = await service.run_cycle(dry_run=True)

    assert stats.matched == 1
    assert stats.created == 0
    assert stats.sent == 0
    assert fake.attempts == 0
    async with db.session() as session:
        assert await session.scalar(select(func.count(Delivery.id))) == 0
        subscription = await session.get(Subscription, ids["subscription_id"])
        assert subscription is not None
        assert subscription.last_checked_at is None
