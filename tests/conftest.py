"""Shared pytest fixtures."""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _clean_vulpulse_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep developer machines' environment from leaking into tests."""
    for key in list(os.environ):
        if key.startswith("VULPULSE_"):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> None:
    """Reset the settings and database singletons before and after each test."""
    from vulpulse.config import get_settings
    from vulpulse.db.session import get_database

    get_settings.cache_clear()
    get_database.cache_clear()
    yield
    get_settings.cache_clear()
    get_database.cache_clear()
