from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import pytest

from vulpulse.config import Settings
from vulpulse.crawler.base import BaseSource
from vulpulse.crawler.models import RawVuln
from vulpulse.crawler.registry import (
    available_sources,
    create_source,
    register_source,
)


class DummySource(BaseSource):
    name = "dummy"

    async def fetch(
        self,
        *,
        since: datetime | None = None,
        checkpoint: dict[str, Any] | None = None,
    ) -> AsyncIterator[RawVuln]:
        yield RawVuln(source=self.name, source_vuln_id="1")


@pytest.fixture(autouse=True)
def _isolated_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulpulse.crawler.registry._REGISTRY", {})


def test_register_and_create() -> None:
    register_source(DummySource)

    assert available_sources() == ["dummy"]
    source = create_source("dummy", Settings(_env_file=None))  # type: ignore[call-arg]
    assert isinstance(source, DummySource)


def test_duplicate_name_is_rejected() -> None:
    register_source(DummySource)

    class OtherSource(DummySource):
        name = "dummy"

    with pytest.raises(ValueError, match="Duplicate source name"):
        register_source(OtherSource)


def test_source_without_name_is_rejected() -> None:
    class UnnamedSource(DummySource):
        name = ""

    with pytest.raises(ValueError, match="non-empty"):
        register_source(UnnamedSource)


def test_unknown_source() -> None:
    with pytest.raises(KeyError, match="Unknown source"):
        create_source("nope", Settings(_env_file=None))  # type: ignore[call-arg]


async def test_fetch_is_an_async_iterator() -> None:
    source = DummySource(Settings(_env_file=None))  # type: ignore[call-arg]
    try:
        items = [item async for item in source.fetch()]
    finally:
        await source.close()

    assert [item.source_vuln_id for item in items] == ["1"]
