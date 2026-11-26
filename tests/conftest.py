"""Shared pytest fixtures."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest

# Set before test modules import the FastAPI app.
os.environ.setdefault("VULPULSE_SESSION_SECRET", "test-session-secret")


@pytest.fixture(autouse=True)
def _clean_vulpulse_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep developer machines' environment from leaking into tests."""
    for key in list(os.environ):
        if key.startswith("VULPULSE_"):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture(autouse=True)
async def _clear_settings_cache() -> AsyncIterator[None]:
    """Reset the settings and database singletons before and after each test."""
    from vulpulse.config import get_settings
    from vulpulse.db.session import dispose_database

    get_settings.cache_clear()
    yield
    # Dispose before clearing: a cached engine created inside a CLI command's
    # ``asyncio.run`` loop would otherwise leave aiosqlite worker threads
    # pointing at a closed loop.
    await dispose_database()
    get_settings.cache_clear()
