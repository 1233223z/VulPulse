"""Match subscriptions, create deliveries and send notifications."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from loguru import logger
from pydantic import ValidationError

from vulpulse.config import Settings, get_settings
from vulpulse.db.models import Channel
from vulpulse.db.repositories import (
    DeliveryRepository,
    SubscriptionRepository,
    VulnerabilityRepository,
)
from vulpulse.db.session import Database, get_database
from vulpulse.notifier.base import NotificationChannel
from vulpulse.notifier.factory import build_channel
from vulpulse.notifier.message import build_message
from vulpulse.notifier.rules import SubscriptionRule
from vulpulse.timeutils import utcnow

ChannelFactory = Callable[[Channel, Settings], NotificationChannel]


@dataclass
class NotificationStats:
    subscriptions: int = 0
    matched: int = 0
    created: int = 0
    sent: int = 0
    failed: int = 0
    dry_run: bool = False

    def as_dict(self) -> dict[str, int | bool]:
        return {
            "subscriptions": self.subscriptions,
            "matched": self.matched,
            "created": self.created,
            "sent": self.sent,
            "failed": self.failed,
            "dry_run": self.dry_run,
        }


class NotificationService:
    def __init__(
        self,
        database: Database | None = None,
        settings: Settings | None = None,
        channel_factory: ChannelFactory = build_channel,
        *,
        max_attempts: int | None = None,
    ) -> None:
        self.database = database or get_database()
        self.settings = settings or get_settings()
        self.channel_factory = channel_factory
        self.max_attempts = max_attempts or self.settings.notify_max_attempts

    async def run_cycle(self, *, dry_run: bool = False) -> NotificationStats:
        started_at = utcnow()
        stats = NotificationStats(dry_run=dry_run)

        async with self.database.session() as session:
            subscriptions = await SubscriptionRepository(session).list_enabled()
            stats.subscriptions = len(subscriptions)
            vulnerabilities = VulnerabilityRepository(session)
            deliveries = DeliveryRepository(session)

            for subscription in subscriptions:
                if subscription.channel is None or not subscription.channel.enabled:
                    continue

                try:
                    rule = SubscriptionRule.model_validate(subscription.rule_json)
                except ValidationError:
                    logger.exception("Invalid rule for subscription {}", subscription.name)
                    continue

                since = subscription.last_checked_at or (
                    started_at - timedelta(days=self.settings.notify_initial_lookback_days)
                )
                candidates = await vulnerabilities.recent_for_alerts(since)
                matches = [vuln for vuln in candidates if rule.matches(vuln)]
                stats.matched += len(matches)

                if dry_run:
                    continue

                for vuln in matches:
                    _, created = await deliveries.get_or_create(
                        subscription,
                        vuln,
                        subscription.channel,
                    )
                    if created:
                        stats.created += 1

                actionable = await deliveries.list_actionable(
                    subscription.id,
                    self.max_attempts,
                )
                try:
                    channel = self.channel_factory(
                        subscription.channel,
                        self.settings,
                    )
                except Exception:
                    logger.exception(
                        "Cannot build channel for subscription {}",
                        subscription.name,
                    )
                    subscription.last_checked_at = started_at
                    await session.commit()
                    continue

                try:
                    for delivery in actionable:
                        message = build_message(
                            delivery.vulnerability,
                            self.settings.public_base_url,
                        )
                        try:
                            await channel.send(message)
                            await deliveries.mark_sent(delivery)
                            stats.sent += 1
                        except Exception as exc:
                            await deliveries.mark_failed(delivery, str(exc))
                            stats.failed += 1
                            logger.exception(
                                "Notification delivery failed for {}",
                                delivery.vulnerability.cve_id,
                            )
                        await session.commit()
                finally:
                    await channel.close()

                subscription.last_checked_at = started_at
                await session.commit()

        return stats
