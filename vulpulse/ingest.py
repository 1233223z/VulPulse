"""Orchestrate one crawl: normalize, upsert, link relations, record the run."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select

from vulpulse.analyzer.normalizer import normalize_raw
from vulpulse.crawler.base import BaseSource
from vulpulse.crawler.models import RawVuln
from vulpulse.db.models import CrawlRun, Source
from vulpulse.db.repositories import (
    CrawlRunRepository,
    SourceRepository,
    VulnerabilityRepository,
)
from vulpulse.db.session import Database, get_database
from vulpulse.timeutils import to_naive_utc, utcnow


@dataclass
class IngestStats:
    fetched: int = 0
    created: int = 0
    updated: int = 0
    products: int = 0
    cwes: int = 0
    references: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "fetched": self.fetched,
            "created": self.created,
            "updated": self.updated,
            "products": self.products,
            "cwes": self.cwes,
            "references": self.references,
        }


class IngestService:
    """Writes crawled records into the database in bounded transactions."""

    def __init__(self, database: Database | None = None) -> None:
        self.database = database or get_database()

    async def ingest(
        self,
        source: BaseSource,
        *,
        since: datetime | None = None,
        checkpoint: dict[str, Any] | None = None,
        batch_size: int = 100,
    ) -> IngestStats:
        stats = IngestStats()
        latest_modified: datetime | None = None
        run_id = await self._start_run(source)

        try:
            async with self.database.session() as session:
                source_model = await SourceRepository(session).get_by_name(source.name)
                if source_model is None:  # pragma: no cover - defensive
                    raise RuntimeError(f"Source not registered: {source.name}")

                repo = VulnerabilityRepository(session)
                async for raw in source.fetch(since=since, checkpoint=checkpoint):
                    stats.fetched += 1
                    modified = to_naive_utc(raw.modified_at)
                    if modified is not None and (
                        latest_modified is None or modified > latest_modified
                    ):
                        latest_modified = modified

                    created = await self._ingest_one(repo, source_model, raw, stats)
                    if created:
                        stats.created += 1
                    else:
                        stats.updated += 1

                    if stats.fetched % batch_size == 0:
                        await session.commit()

                await session.commit()
        except Exception as exc:
            await self._finish_run(run_id, status="failed", stats=stats, error=str(exc))
            raise

        checkpoint = {"last_modified": latest_modified.isoformat()} if latest_modified else None
        await self._finish_run(
            run_id,
            status="success",
            stats=stats,
            checkpoint=checkpoint,
        )
        return stats

    async def last_checkpoint(self, source_name: str) -> dict[str, Any] | None:
        """Return the checkpoint of the newest successful run for a source."""
        async with self.database.session() as session:
            statement = (
                select(CrawlRun.checkpoint)
                .join(Source, Source.id == CrawlRun.source_id)
                .where(
                    Source.name == source_name,
                    CrawlRun.status == "success",
                    CrawlRun.checkpoint.is_not(None),
                )
                .order_by(CrawlRun.finished_at.desc())
                .limit(1)
            )
            checkpoint = await session.scalar(statement)
        return checkpoint if isinstance(checkpoint, dict) else None

    async def _ingest_one(
        self,
        repo: VulnerabilityRepository,
        source_model: Source,
        raw: RawVuln,
        stats: IngestStats,
    ) -> bool:
        fields = normalize_raw(raw)
        vulnerability, created = await repo.upsert(raw.dedupe_key, **fields)

        await repo.add_source_record(
            vulnerability,
            source_model,
            raw.source_vuln_id,
            url=raw.source_url,
            raw_json=raw.raw or None,
        )

        for item in raw.products:
            if not item.product:
                continue
            product = await repo.get_or_create_product(item.vendor, item.product)
            await repo.link_product(
                vulnerability,
                product,
                version_range=item.version_range,
                cpe=item.cpe,
            )
            stats.products += 1

        for cwe_id in raw.cwes:
            cwe = await repo.get_or_create_cwe(cwe_id)
            await repo.link_cwe(vulnerability, cwe)
            stats.cwes += 1

        for url in raw.references:
            await repo.add_reference(vulnerability, url)
            stats.references += 1

        return created

    async def _start_run(self, source: BaseSource) -> int:
        async with self.database.session() as session:
            source_model = await SourceRepository(session).get_or_create(
                source.name,
                source.kind,
            )
            run = await CrawlRunRepository(session).start(source_model)
            await session.commit()
            return run.id

    async def _finish_run(
        self,
        run_id: int,
        *,
        status: str,
        stats: IngestStats,
        error: str | None = None,
        checkpoint: dict[str, Any] | None = None,
    ) -> None:
        async with self.database.session() as session:
            run = await session.get(CrawlRun, run_id)
            if run is None:  # pragma: no cover - defensive
                return
            await CrawlRunRepository(session).finish(
                run,
                status=status,
                stats=stats.as_dict(),
                error=error,
                checkpoint=checkpoint,
            )
            if status == "success":
                source = await session.get(Source, run.source_id)
                if source is not None:
                    source.last_success_at = utcnow()
            await session.commit()
