"""Repository layer: the only place that talks to SQLAlchemy sessions."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.db.base import utcnow
from vulpulse.db.models import (
    CrawlRun,
    Cwe,
    Product,
    Source,
    SourceRecord,
    VulnCwe,
    Vulnerability,
    VulnProduct,
    VulnReference,
)


class SourceRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_name(self, name: str) -> Source | None:
        return await self.session.scalar(select(Source).where(Source.name == name))

    async def list_all(self) -> list[Source]:
        result = await self.session.scalars(select(Source).order_by(Source.name))
        return list(result.all())

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
