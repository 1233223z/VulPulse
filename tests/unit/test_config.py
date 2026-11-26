from __future__ import annotations

from pathlib import Path

import pytest

from vulpulse import __version__
from vulpulse.config import Settings


def test_defaults() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    assert settings.app_name == "VulPulse"
    assert settings.env == "dev"
    assert settings.log_level == "INFO"
    assert settings.database_url.startswith("sqlite+aiosqlite")
    assert isinstance(settings.data_dir, Path)


def test_env_override(monkeypatch) -> None:
    monkeypatch.setenv("VULPULSE_LOG_LEVEL", "debug")
    monkeypatch.setenv("VULPULSE_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    assert settings.log_level == "DEBUG"
    assert settings.database_url == "sqlite+aiosqlite:///:memory:"


def test_ensure_dirs(tmp_path) -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
    )

    settings.ensure_dirs()

    assert settings.data_dir.is_dir()
    assert settings.log_dir.is_dir()


def test_api_defaults() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    assert settings.api_rate_limit_per_minute == 120
    assert settings.docs_enabled is None
    assert settings.http_user_agent == f"VulPulse/{__version__}"


def test_empty_docs_enabled_means_auto(monkeypatch) -> None:
    monkeypatch.setenv("VULPULSE_DOCS_ENABLED", "")

    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    assert settings.docs_enabled is None


def test_invalid_trusted_proxy_is_rejected() -> None:
    with pytest.raises(ValueError):
        Settings(  # type: ignore[call-arg]
            _env_file=None,
            trusted_proxies="not-a-cidr",
        )
