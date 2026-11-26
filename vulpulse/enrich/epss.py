"""FIRST EPSS enrichment.

Unlike a crawler source, EPSS is a score lookup over CVEs that already exist in
the database. Creating a vulnerability row for every EPSS entry would add
hundreds of thousands of context-free records, so this module updates in place.
"""

from __future__ import annotations

import csv
import gzip
import io
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import Table, bindparam, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from vulpulse.config import Settings, get_settings
from vulpulse.crawler.http import HttpClient
from vulpulse.db.models import Vulnerability
from vulpulse.db.session import Database, get_database
from vulpulse.timeutils import utcnow


@dataclass
class EpssStats:
    matched: int = 0
    updated: int = 0


class EpssEnricher:
    def __init__(
        self,
        database: Database | None = None,
        settings: Settings | None = None,
        client: HttpClient | None = None,
    ) -> None:
        self.database = database or get_database()
        self.settings = settings or get_settings()
        self._owns_client = client is None
        self.client = client or HttpClient(
            timeout=self.settings.http_timeout_seconds,
            user_agent=self.settings.http_user_agent,
        )

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def enrich(self, *, batch_size: int = 1000) -> EpssStats:
        cve_ids = await self._load_cve_ids()
        if not cve_ids:
            return EpssStats()

        payload = await self.client.get_bytes(self.settings.epss_scores_url)
        rows = list(
            parse_scores(
                decode_scores(
                    payload,
                    max_bytes=self.settings.http_max_response_bytes,
                ),
                cve_ids,
            )
        )
        stats = EpssStats(matched=len(rows))

        async with self.database.session() as session:
            for batch in _chunks(rows, batch_size):
                await self._update_batch(session, batch)
                await session.commit()

        stats.updated = len(rows)

        # EPSS changes the risk score, so refresh it after every enrichment run.
        from vulpulse.analyzer.scoring_service import RiskService

        await RiskService(self.database, self.settings).score_all()
        return stats

    async def _load_cve_ids(self) -> set[str]:
        async with self.database.session() as session:
            result = await session.scalars(
                select(Vulnerability.cve_id).where(Vulnerability.cve_id.is_not(None))
            )
            return {cve for cve in result.all() if cve}

    async def _update_batch(
        self,
        session: AsyncSession,
        batch: list[dict[str, Any]],
    ) -> None:
        table = cast(Table, Vulnerability.__table__)
        statement = (
            update(table)
            .where(table.c.cve_id == bindparam("b_cve_id"))
            .values(
                epss_score=bindparam("b_epss_score"),
                epss_percentile=bindparam("b_epss_percentile"),
                updated_at=utcnow(),
            )
        )
        await session.execute(statement, batch)


def decode_scores(
    payload: bytes,
    *,
    max_bytes: int = 64 * 1024 * 1024,
) -> str:
    """Decode an EPSS CSV with a hard cap on decompressed size."""
    if payload[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as archive:
            content = archive.read(max_bytes + 1)
    else:
        content = payload
    if len(content) > max_bytes:
        raise ValueError("EPSS payload exceeds the decompressed size limit")
    return content.decode("utf-8-sig")


def parse_scores(text: str, wanted: set[str]) -> Iterator[dict[str, Any]]:
    """Yield update parameters for CVEs present in ``wanted``."""
    lines = (line for line in text.splitlines() if line and not line.startswith("#"))
    reader = csv.DictReader(lines)

    for row in reader:
        cve_id = (row.get("cve") or "").strip().upper()
        if cve_id not in wanted:
            continue
        try:
            epss_score = float(row["epss"])
            epss_percentile = float(row["percentile"])
        except (KeyError, TypeError, ValueError):
            continue
        yield {
            "b_cve_id": cve_id,
            "b_epss_score": epss_score,
            "b_epss_percentile": epss_percentile,
        }


def _chunks(items: list[dict[str, Any]], size: int) -> Iterator[list[dict[str, Any]]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]
