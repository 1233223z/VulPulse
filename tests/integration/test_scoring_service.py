from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta

import pytest

from vulpulse.analyzer.scoring_service import RiskService
from vulpulse.config import Settings
from vulpulse.db.repositories import VulnerabilityRepository
from vulpulse.db.session import Database
from vulpulse.timeutils import utcnow


@pytest.fixture
async def db(tmp_path) -> AsyncIterator[Database]:
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'risk.db'}")
    await database.create_schema()
    yield database
    await database.dispose()


async def seed(db: Database) -> None:
    now = utcnow()
    async with db.session() as session:
        repo = VulnerabilityRepository(session)
        await repo.upsert(
            "cve:CVE-2024-0001",
            cve_id="CVE-2024-0001",
            severity="critical",
            cvss_score=9.8,
            epss_score=0.95,
            in_kev=True,
            exploit_available=True,
            published_at=now - timedelta(days=1),
        )
        await repo.upsert(
            "cve:CVE-2024-0002",
            cve_id="CVE-2024-0002",
            severity="low",
            cvss_score=2.0,
            epss_score=0.01,
            in_kev=False,
            exploit_available=False,
            published_at=now - timedelta(days=365),
        )
        await session.commit()


async def test_score_all_persists_risk_fields(db: Database) -> None:
    await seed(db)
    service = RiskService(db, Settings(_env_file=None))  # type: ignore[call-arg]

    stats = await service.score_all()

    assert stats.total == 2
    assert stats.updated == 2
    assert stats.average > 0

    async with db.session() as session:
        repo = VulnerabilityRepository(session)
        high = await repo.get_by_cve_id("CVE-2024-0001")
        low = await repo.get_by_cve_id("CVE-2024-0002")

        assert high is not None
        assert low is not None
        assert high.risk_score is not None
        assert high.risk_level == "critical"
        assert low.risk_score is not None
        assert low.risk_level in {"minimal", "low"}
        assert high.risk_score > low.risk_score


async def test_score_all_is_idempotent(db: Database) -> None:
    await seed(db)
    service = RiskService(db, Settings(_env_file=None))  # type: ignore[call-arg]

    first = await service.score_all()
    second = await service.score_all()

    assert first.total == second.total == 2
    assert first.average == second.average
