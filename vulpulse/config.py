"""Application configuration loaded from environment variables and ``.env``."""

from __future__ import annotations

import contextlib
import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from vulpulse import __version__


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

    # Source plugins
    plugins_enabled: bool = True

    # Database
    database_url: str = "sqlite+aiosqlite:///./data/vulpulse.db"

    # Admin API and admin web UI
    api_key: str = ""
    session_secret: str = ""
    session_https_only: bool = False
    session_max_age_hours: int = 8

    # Public API
    api_rate_limit_per_minute: int = 120
    trusted_proxies: str = ""
    # None means "enabled outside prod"; set explicitly to override.
    docs_enabled: bool | None = None

    # Data sources
    nvd_api_key: str = ""
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    exploitdb_csv_url: str = (
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    )
    epss_scores_url: str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

    # HTTP client
    http_timeout_seconds: float = 30.0
    http_user_agent: str = f"VulPulse/{__version__}"
    http_max_response_bytes: int = 64 * 1024 * 1024
    http_max_redirects: int = 3

    # Scheduler
    scheduler_run_on_start: bool = True
    nvd_interval_minutes: int = 60
    kev_interval_hours: int = 6
    exploitdb_interval_hours: int = 24
    epss_interval_hours: int = 24
    nvd_lookback_days: int = 2
    notify_interval_minutes: int = 5
    score_interval_hours: int = 6

    # Risk scoring
    risk_recency_days: int = 90
    risk_weight_cvss: float = 0.40
    risk_weight_epss: float = 0.25
    risk_weight_kev: float = 0.20
    risk_weight_exploit: float = 0.10
    risk_weight_recency: float = 0.05

    # Notifications
    notify_max_attempts: int = 3
    notify_initial_lookback_days: int = 7
    public_base_url: str = "http://localhost:8000"

    # Notifications
    wecom_webhook_url: str = ""
    wecom_allowed_hosts: str = "qyapi.weixin.qq.com"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False

    @field_validator("log_level")
    @classmethod
    def _normalize_log_level(cls, value: str) -> str:
        return value.upper()

    @field_validator(
        "nvd_interval_minutes",
        "kev_interval_hours",
        "exploitdb_interval_hours",
        "epss_interval_hours",
        "notify_interval_minutes",
        "notify_max_attempts",
        "notify_initial_lookback_days",
        "score_interval_hours",
        "risk_recency_days",
        "session_max_age_hours",
        "http_max_response_bytes",
    )
    @classmethod
    def _positive_interval(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("scheduler and notification values must be positive")
        return value

    @model_validator(mode="after")
    def _validate_risk_weights(self) -> Settings:
        weights = (
            self.risk_weight_cvss,
            self.risk_weight_epss,
            self.risk_weight_kev,
            self.risk_weight_exploit,
            self.risk_weight_recency,
        )
        if any(weight < 0 for weight in weights):
            raise ValueError("risk weights must be zero or positive")
        if sum(weights) <= 0:
            raise ValueError("at least one risk weight must be positive")
        return self

    @field_validator("nvd_lookback_days")
    @classmethod
    def _non_negative_lookback(cls, value: int) -> int:
        if value < 0:
            raise ValueError("nvd_lookback_days must be zero or positive")
        return value

    @field_validator("api_rate_limit_per_minute")
    @classmethod
    def _non_negative_rate_limit(cls, value: int) -> int:
        if value < 0:
            raise ValueError("api_rate_limit_per_minute must be zero or positive")
        return value

    @field_validator("docs_enabled", mode="before")
    @classmethod
    def _empty_docs_as_none(cls, value: object) -> object:
        if value is None or value == "":
            return None
        return value

    @field_validator("trusted_proxies")
    @classmethod
    def _valid_trusted_proxies(cls, value: str) -> str:
        for item in value.split(","):
            item = item.strip()
            if item:
                ipaddress.ip_network(item, strict=False)
        return value

    def ensure_dirs(self) -> None:
        """Create runtime directories with owner-only permissions."""
        import os

        for directory in (self.data_dir, self.log_dir):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            with contextlib.suppress(OSError):
                os.chmod(directory, 0o700)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    return Settings()
