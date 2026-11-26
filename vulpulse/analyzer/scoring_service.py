"""Bulk risk-score computation and persistence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import Table, bindparam, select, update

from vulpulse.analyzer.scorer import RiskWeights, score_risk
from vulpulse.config import Settings, get_settings
from vulpulse.db.models import Vulnerability
from vulpulse.db.session import Database, get_database
from vulpulse.timeutils import utcnow


@dataclass
class ScoreStats:
    total: int = 0
    updated: int = 0
    average: float = 0.0


class RiskService:
    def __init__(
        self,
        database: Database | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.database = database or get_database()
        self.settings = settings or get_settings()
        self.weights = RiskWeights.from_settings(self.settings)
        self.recency_days = self.settings.risk_recency_days

    async def score_all(self, *, batch_size: int = 1000) -> ScoreStats:
        now = utcnow()
        async with self.database.session() as session:
            result = await session.execute(
                select(
                    Vulnerability.id,
                    Vulnerability.severity,
                    Vulnerability.cvss_score,
                    Vulnerability.epss_score,
                    Vulnerability.in_kev,
                    Vulnerability.exploit_available,
                    Vulnerability.published_at,
                    Vulnerability.modified_at,
                    Vulnerability.created_at,
                )
            )
            rows = result.all()

            scored: list[dict[str, Any]] = []
            total_score = 0.0
            for row in rows:
                risk = score_risk(
                    row,
                    self.weights,
                    recency_days=self.recency_days,
                    now=now,
                )
                total_score += risk.score
                scored.append(
                    {
                        "b_id": row.id,
                        "b_score": risk.score,
                        "b_level": risk.level,
                    }
                )

            table = cast(Table, Vulnerability.__table__)
            statement = (
                update(table)
                .where(table.c.id == bindparam("b_id"))
                .values(
                    risk_score=bindparam("b_score"),
                    risk_level=bindparam("b_level"),
                    updated_at=now,
                )
            )
            for index in range(0, len(scored), batch_size):
                await session.execute(statement, scored[index : index + batch_size])
                await session.commit()

        return ScoreStats(
            total=len(scored),
            updated=len(scored),
            average=round(total_score / len(scored), 2) if scored else 0.0,
        )
