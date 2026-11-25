"""Application configuration loaded from environment variables and ``.env``."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings.

    Every field can be overridden with a ``VULPULSE_``-prefixed environment
    variable (for example ``VULPULSE_LOG_LEVEL=DEBUG``) or via ``.env``.
    """

    model_config = SettingsConfigDict(
        env_prefix="VULPULSE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application
    app_name: str = "VulPulse"
    env: Literal["dev", "test", "prod"] = "dev"
    log_level: str = "INFO"
    data_dir: Path = Path("data")
    log_dir: Path = Path("data/logs")

    # Database
    database_url: str = "sqlite+aiosqlite:///./data/vulpulse.db"

    # Admin API
    api_key: str = ""

    # Data sources
    nvd_api_key: str = ""
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    exploitdb_csv_url: str = (
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    )
    epss_scores_url: str = "https://epss.cyentia.com/epss_scores-current.csv.gz"

    # HTTP client
    http_timeout_seconds: float = 30.0
    http_user_agent: str = "VulPulse/0.1"

    # Notifications
    wecom_webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_use_tls: bool = True

    @field_validator("log_level")
    @classmethod
    def _normalize_log_level(cls, value: str) -> str:
        return value.upper()

    def ensure_dirs(self) -> None:
        """Create runtime directories if they do not exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    return Settings()
