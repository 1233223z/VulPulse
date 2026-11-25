"""Repository layer: the only place that talks to SQLAlchemy sessions."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from vulpulse.db.models import (
    Channel,
    CrawlRun,
    Cwe,
    Delivery,
    Product,
    Source,
    SourceRecord,
    Subscription,
    VulnCwe,
    Vulnerability,
    VulnProduct,
    VulnReference,
)
from vulpulse.timeutils import to_naive_utc, utcnow


class SourceRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_name(self, name: str) -> Source | None:
        return await self.session.scalar(select(Source).where(Source.name == name))

    async def list_all(self) -> list[Source]:
        result = await self.session.scalars(select(Source).order_by(Source.name))
        return list(result.all())

    async def count_records(self, source_id: int) -> int:
        statement = select(func.count(SourceRecord.id)).where(SourceRecord.source_id == source_id)
        return int(await self.session.scalar(statement) or 0)

    async def latest_run(self, source_id: int) -> CrawlRun | None:
        statement = (
            select(CrawlRun)
            .where(CrawlRun.source_id == source_id)
            .order_by(CrawlRun.started_at.desc())
            .limit(1)
        )
        return await self.session.scalar(statement)

    async def get_or_create(
        self,
        name: str,
        kind: str,
        *,
        base_url: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> Source:
        source = await self.get_by_name(name)
        if source is None:
            source = Source(name=name, kind=kind, base_url=base_url, config=config)
            self.session.add(source)
            await self.session.flush()
        return source


class VulnerabilityRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_dedupe_key(self, dedupe_key: str) -> Vulnerability | None:
        return await self.session.scalar(
            select(Vulnerability).where(Vulnerability.dedupe_key == dedupe_key)
        )

    async def get_by_cve_id(self, cve_id: str) -> Vulnerability | None:
        return await self.session.scalar(
            select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        )

    async def upsert(self, dedupe_key: str, **fields: Any) -> tuple[Vulnerability, bool]:
        """Insert or update a vulnerability by dedupe key.

        Non-null fields overwrite existing values. Merge policy (which source
        wins for which field) belongs in the analyzer/merger, not here.
        """
        vuln = await self.get_by_dedupe_key(dedupe_key)
        if vuln is None:
            vuln = Vulnerability(dedupe_key=dedupe_key, **fields)
            self.session.add(vuln)
            await self.session.flush()
            return vuln, True

        for key, value in fields.items():
            if value is not None:
                setattr(vuln, key, value)
        await self.session.flush()
        return vuln, False

    async def add_source_record(
        self,
        vulnerability: Vulnerability,
        source: Source,
        source_vuln_id: str,
        *,
        url: str | None = None,
        raw_json: dict[str, Any] | None = None,
    ) -> SourceRecord:
        stmt = select(SourceRecord).where(
            SourceRecord.source_id == source.id,
            SourceRecord.source_vuln_id == source_vuln_id,
        )
        record = await self.session.scalar(stmt)
        if record is None:
            record = SourceRecord(
                vuln_id=vulnerability.id,
                source_id=source.id,
                source_vuln_id=source_vuln_id,
                url=url,
                raw_json=raw_json,
            )
            self.session.add(record)
            await self.session.flush()
        return record

    async def count(self) -> int:
        return int(await self.session.scalar(select(func.count(Vulnerability.id))) or 0)

    async def count_in_kev(self) -> int:
        statement = (
            select(func.count()).select_from(Vulnerability).where(Vulnerability.in_kev.is_(True))
        )
        return int(await self.session.scalar(statement) or 0)

    async def count_with_exploit(self) -> int:
        statement = (
            select(func.count())
            .select_from(Vulnerability)
            .where(Vulnerability.exploit_available.is_(True))
        )
        return int(await self.session.scalar(statement) or 0)

    async def count_with_epss(self) -> int:
        statement = (
            select(func.count())
            .select_from(Vulnerability)
            .where(Vulnerability.epss_score.is_not(None))
        )
        return int(await self.session.scalar(statement) or 0)

    async def severity_counts(self) -> dict[str, int]:
        statement = select(Vulnerability.severity, func.count()).group_by(Vulnerability.severity)
        result = await self.session.execute(statement)
        return {str(severity): int(count) for severity, count in result.all()}

    async def risk_level_counts(self) -> dict[str, int]:
        statement = (
            select(Vulnerability.risk_level, func.count())
            .where(Vulnerability.risk_level.is_not(None))
            .group_by(Vulnerability.risk_level)
        )
        result = await self.session.execute(statement)
        return {str(level): int(count) for level, count in result.all()}

    async def published_trend(self, days: int = 30) -> list[tuple[str, int]]:
        start = utcnow() - timedelta(days=days)
        day = func.date(Vulnerability.published_at)
        statement = (
            select(day, func.count())
            .where(
                Vulnerability.published_at.is_not(None),
                Vulnerability.published_at >= start,
            )
            .group_by(day)
            .order_by(day)
        )
        result = await self.session.execute(statement)
        return [(str(day_value), int(count)) for day_value, count in result.all()]

    async def search(
        self,
        *,
        q: str | None = None,
        severity: str | None = None,
        source: str | None = None,
        vendor: str | None = None,
        product: str | None = None,
        in_kev: bool | None = None,
        exploit_available: bool | None = None,
        cvss_min: float | None = None,
        epss_min: float | None = None,
        risk_min: float | None = None,
        published_from: datetime | None = None,
        published_to: datetime | None = None,
        sort: str = "published_at",
        order: str = "desc",
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[Vulnerability], int]:
        filters: list[Any] = []

        if q and q.strip():
            pattern = f"%{q.strip()}%"
            filters.append(
                or_(
                    Vulnerability.cve_id.ilike(pattern),
                    Vulnerability.title.ilike(pattern),
                    Vulnerability.description.ilike(pattern),
                )
            )
        if severity:
            filters.append(Vulnerability.severity == severity)
        if source:
            source_records = (
                select(SourceRecord.vuln_id)
                .join(Source, Source.id == SourceRecord.source_id)
                .where(Source.name == source)
            )
            filters.append(Vulnerability.id.in_(source_records))
        if vendor or product:
            product_links = select(VulnProduct.vuln_id).join(
                Product,
                Product.id == VulnProduct.product_id,
            )
            if vendor:
                product_links = product_links.where(func.lower(Product.vendor) == vendor.lower())
            if product:
                product_links = product_links.where(func.lower(Product.product) == product.lower())
            filters.append(Vulnerability.id.in_(product_links))
        if in_kev is not None:
            filters.append(Vulnerability.in_kev.is_(in_kev))
        if exploit_available is not None:
            filters.append(Vulnerability.exploit_available.is_(exploit_available))
        if cvss_min is not None:
            filters.append(Vulnerability.cvss_score >= cvss_min)
        if epss_min is not None:
            filters.append(Vulnerability.epss_score >= epss_min)
        if risk_min is not None:
            filters.append(Vulnerability.risk_score >= risk_min)
        if published_from is not None:
            filters.append(Vulnerability.published_at >= to_naive_utc(published_from))
        if published_to is not None:
            filters.append(Vulnerability.published_at <= to_naive_utc(published_to))

        count_statement = select(func.count()).select_from(Vulnerability).where(*filters)
        total = int(await self.session.scalar(count_statement) or 0)

        sort_columns = {
            "published_at": Vulnerability.published_at,
            "modified_at": Vulnerability.modified_at,
            "cvss_score": Vulnerability.cvss_score,
            "epss_score": Vulnerability.epss_score,
            "risk_score": Vulnerability.risk_score,
            "created_at": Vulnerability.created_at,
        }
        sort_column = sort_columns.get(sort, Vulnerability.published_at)
        ordering = sort_column.desc() if order == "desc" else sort_column.asc()

        statement = (
            select(Vulnerability)
            .where(*filters)
            .order_by(ordering, Vulnerability.id.desc())
            .limit(limit)
            .offset(offset)
        )
        items = list((await self.session.scalars(statement)).all())
        return items, total

    async def recent_for_alerts(self, since: datetime) -> list[Vulnerability]:
        """Load recently published/updated vulnerabilities for rule matching."""
        statement = (
            select(Vulnerability)
            .where(
                or_(
                    Vulnerability.published_at >= since,
                    Vulnerability.modified_at >= since,
                    Vulnerability.created_at >= since,
                )
            )
            .options(
                selectinload(Vulnerability.source_records).selectinload(SourceRecord.source),
                selectinload(Vulnerability.product_links).selectinload(VulnProduct.product),
            )
        )
        return list((await self.session.scalars(statement)).all())

    async def get_detail(self, identifier: str) -> Vulnerability | None:
        statement = select(Vulnerability).options(
            selectinload(Vulnerability.source_records).selectinload(SourceRecord.source),
            selectinload(Vulnerability.product_links).selectinload(VulnProduct.product),
            selectinload(Vulnerability.cwe_links).selectinload(VulnCwe.cwe),
            selectinload(Vulnerability.references),
        )
        if identifier.isdigit():
            statement = statement.where(Vulnerability.id == int(identifier))
        else:
            statement = statement.where(Vulnerability.cve_id == identifier.strip().upper())
        return await self.session.scalar(statement)

    async def get_or_create_product(self, vendor: str | None, product: str) -> Product:
        stmt = select(Product).where(func.lower(Product.product) == product.lower())
        if vendor is None:
            stmt = stmt.where(Product.vendor.is_(None))
        else:
            stmt = stmt.where(func.lower(Product.vendor) == vendor.lower())

        existing = await self.session.scalar(stmt)
        if existing is not None:
            return existing

        created = Product(vendor=vendor, product=product)
        self.session.add(created)
        await self.session.flush()
        return created

    async def link_product(
        self,
        vulnerability: Vulnerability,
        product: Product,
        *,
        version_range: str | None = None,
        cpe: str | None = None,
    ) -> VulnProduct:
        stmt = select(VulnProduct).where(
            VulnProduct.vuln_id == vulnerability.id,
            VulnProduct.product_id == product.id,
            VulnProduct.version_range == version_range,
            VulnProduct.cpe == cpe,
        )
        existing = await self.session.scalar(stmt)
        if existing is not None:
            return existing

        created = VulnProduct(
            vuln_id=vulnerability.id,
            product_id=product.id,
            version_range=version_range,
            cpe=cpe,
        )
        self.session.add(created)
        await self.session.flush()
        return created

    async def get_or_create_cwe(self, cwe_id: str) -> Cwe:
        normalized = cwe_id.strip().upper()
        existing = await self.session.get(Cwe, normalized)
        if existing is not None:
            return existing

        created = Cwe(id=normalized)
        self.session.add(created)
        await self.session.flush()
        return created

    async def link_cwe(self, vulnerability: Vulnerability, cwe: Cwe) -> VulnCwe:
        existing = await self.session.get(VulnCwe, (vulnerability.id, cwe.id))
        if existing is not None:
            return existing

        created = VulnCwe(vuln_id=vulnerability.id, cwe_id=cwe.id)
        self.session.add(created)
        await self.session.flush()
        return created

    async def add_reference(
        self,
        vulnerability: Vulnerability,
        url: str,
        tags: list[str] | None = None,
    ) -> VulnReference:
        stmt = select(VulnReference).where(
            VulnReference.vuln_id == vulnerability.id,
            VulnReference.url == url,
        )
        existing = await self.session.scalar(stmt)
        if existing is not None:
            return existing

        created = VulnReference(vuln_id=vulnerability.id, url=url, tags=tags)
        self.session.add(created)
        await self.session.flush()
        return created


class VendorRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    @staticmethod
    def _aggregate_columns() -> tuple[Any, ...]:
        return (
            func.lower(Product.vendor).label("vendor"),
            func.count(func.distinct(Vulnerability.id)).label("vulnerabilities"),
            func.count(func.distinct(Product.id)).label("products"),
            func.coalesce(
                func.sum(case((Vulnerability.risk_level == "critical", 1), else_=0)),
                0,
            ).label("critical"),
            func.coalesce(
                func.sum(case((Vulnerability.risk_level == "high", 1), else_=0)),
                0,
            ).label("high"),
            func.coalesce(
                func.sum(case((Vulnerability.risk_level == "medium", 1), else_=0)),
                0,
            ).label("medium"),
            func.coalesce(
                func.sum(case((Vulnerability.risk_level == "low", 1), else_=0)),
                0,
            ).label("low"),
            func.coalesce(
                func.sum(case((Vulnerability.risk_level == "minimal", 1), else_=0)),
                0,
            ).label("minimal"),
            func.avg(Vulnerability.risk_score).label("avg_risk"),
            func.max(Vulnerability.risk_score).label("max_risk"),
        )

    @classmethod
    def _aggregate_query(cls) -> Any:
        return (
            select(*cls._aggregate_columns())
            .select_from(Product)
            .join(VulnProduct, VulnProduct.product_id == Product.id)
            .join(Vulnerability, Vulnerability.id == VulnProduct.vuln_id)
            .where(Product.vendor.is_not(None))
            .group_by(func.lower(Product.vendor))
        )

    async def list_top(self, limit: int = 20) -> list[dict[str, Any]]:
        statement = (
            self._aggregate_query()
            .order_by(
                func.count(func.distinct(Vulnerability.id)).desc(),
                func.max(Vulnerability.risk_score).desc(),
            )
            .limit(limit)
        )
        rows = (await self.session.execute(statement)).all()
        return [self._normalize(row) for row in rows]

    async def get_summary(self, vendor: str) -> dict[str, Any] | None:
        statement = self._aggregate_query().where(
            func.lower(Product.vendor) == vendor.strip().lower()
        )
        row = (await self.session.execute(statement)).first()
        return self._normalize(row) if row is not None else None

    async def get_products(self, vendor: str) -> list[dict[str, Any]]:
        statement = (
            select(
                Product.product,
                func.count(func.distinct(Vulnerability.id)).label("vulnerabilities"),
                func.avg(Vulnerability.risk_score).label("avg_risk"),
                func.max(Vulnerability.risk_score).label("max_risk"),
            )
            .select_from(Product)
            .join(VulnProduct, VulnProduct.product_id == Product.id)
            .join(Vulnerability, Vulnerability.id == VulnProduct.vuln_id)
            .where(func.lower(Product.vendor) == vendor.strip().lower())
            .group_by(Product.product)
            .order_by(
                func.count(func.distinct(Vulnerability.id)).desc(),
                func.max(Vulnerability.risk_score).desc(),
            )
        )
        rows = (await self.session.execute(statement)).all()
        return [
            {
                "product": row.product,
                "vulnerabilities": int(row.vulnerabilities or 0),
                "avg_risk": round(float(row.avg_risk), 2) if row.avg_risk is not None else None,
                "max_risk": round(float(row.max_risk), 2) if row.max_risk is not None else None,
            }
            for row in rows
        ]

    @staticmethod
    def _normalize(row: Any) -> dict[str, Any]:
        mapping = row._mapping
        return {
            "vendor": mapping["vendor"],
            "vulnerabilities": int(mapping["vulnerabilities"] or 0),
            "products": int(mapping["products"] or 0),
            "critical": int(mapping["critical"] or 0),
            "high": int(mapping["high"] or 0),
            "medium": int(mapping["medium"] or 0),
            "low": int(mapping["low"] or 0),
            "minimal": int(mapping["minimal"] or 0),
            "avg_risk": round(float(mapping["avg_risk"]), 2)
            if mapping["avg_risk"] is not None
            else None,
            "max_risk": round(float(mapping["max_risk"]), 2)
            if mapping["max_risk"] is not None
            else None,
        }


class ChannelRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_name(self, name: str) -> Channel | None:
        return await self.session.scalar(select(Channel).where(Channel.name == name))

    async def get_by_id(self, channel_id: int) -> Channel | None:
        return await self.session.get(Channel, channel_id)

    async def delete(self, channel: Channel) -> None:
        await self.session.delete(channel)
        await self.session.flush()

    async def list_all(self) -> list[Channel]:
        result = await self.session.scalars(select(Channel).order_by(Channel.name))
        return list(result.all())

    async def create(
        self,
        name: str,
        type: str,
        config: dict[str, Any] | None = None,
        *,
        enabled: bool = True,
    ) -> Channel:
        channel = Channel(name=name, type=type, config=config, enabled=enabled)
        self.session.add(channel)
        await self.session.flush()
        return channel


class SubscriptionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_name(self, name: str) -> Subscription | None:
        return await self.session.scalar(select(Subscription).where(Subscription.name == name))

    async def get_by_id(self, subscription_id: int) -> Subscription | None:
        return await self.session.get(Subscription, subscription_id)

    async def delete(self, subscription: Subscription) -> None:
        await self.session.delete(subscription)
        await self.session.flush()

    async def list_all(self) -> list[Subscription]:
        statement = (
            select(Subscription)
            .options(selectinload(Subscription.channel))
            .order_by(Subscription.id)
        )
        return list((await self.session.scalars(statement)).all())

    async def list_enabled(self) -> list[Subscription]:
        statement = (
            select(Subscription)
            .where(Subscription.enabled.is_(True))
            .options(selectinload(Subscription.channel))
            .order_by(Subscription.id)
        )
        return list((await self.session.scalars(statement)).all())

    async def create(
        self,
        name: str,
        channel_id: int,
        rule_json: dict[str, Any],
        *,
        enabled: bool = True,
    ) -> Subscription:
        subscription = Subscription(
            name=name,
            channel_id=channel_id,
            rule_json=rule_json,
            enabled=enabled,
        )
        self.session.add(subscription)
        await self.session.flush()
        return subscription


class DeliveryRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_or_create(
        self,
        subscription: Subscription,
        vulnerability: Vulnerability,
        channel: Channel,
    ) -> tuple[Delivery, bool]:
        statement = select(Delivery).where(
            Delivery.subscription_id == subscription.id,
            Delivery.vuln_id == vulnerability.id,
            Delivery.channel_id == channel.id,
        )
        existing = await self.session.scalar(statement)
        if existing is not None:
            return existing, False

        delivery = Delivery(
            subscription_id=subscription.id,
            vuln_id=vulnerability.id,
            channel_id=channel.id,
            status="pending",
        )
        self.session.add(delivery)
        await self.session.flush()
        return delivery, True

    async def list_actionable(
        self,
        subscription_id: int,
        max_attempts: int,
    ) -> list[Delivery]:
        statement = (
            select(Delivery)
            .where(
                Delivery.subscription_id == subscription_id,
                Delivery.status.in_(("pending", "failed")),
                Delivery.attempts < max_attempts,
            )
            .options(selectinload(Delivery.vulnerability))
            .order_by(Delivery.id)
        )
        return list((await self.session.scalars(statement)).all())

    async def mark_sent(self, delivery: Delivery) -> None:
        delivery.status = "sent"
        delivery.sent_at = utcnow()
        delivery.attempts += 1
        delivery.last_error = None
        await self.session.flush()

    async def mark_failed(self, delivery: Delivery, error: str) -> None:
        delivery.status = "failed"
        delivery.attempts += 1
        delivery.last_error = error[:1000]
        await self.session.flush()


class CrawlRunRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def start(self, source: Source) -> CrawlRun:
        run = CrawlRun(source_id=source.id, status="running")
        self.session.add(run)
        await self.session.flush()
        return run

    async def finish(
        self,
        run: CrawlRun,
        *,
        status: str,
        stats: dict[str, Any] | None = None,
        error: str | None = None,
        checkpoint: dict[str, Any] | None = None,
    ) -> CrawlRun:
        run.status = status
        run.finished_at = utcnow()
        run.stats = stats
        run.error = error
        run.checkpoint = checkpoint
        await self.session.flush()
        return run
