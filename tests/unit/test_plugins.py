from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import pytest

from vulpulse.config import Settings
from vulpulse.crawler.base import BaseSource, SchedulePolicy
from vulpulse.crawler.models import RawVuln
from vulpulse.crawler.registry import available_sources
from vulpulse.plugins import (
    ENTRY_POINT_GROUP,
    load_plugins,
    plugin_failures,
    plugin_infos,
    reset_plugin_loading,
)
from vulpulse.scheduler.jobs import default_schedules


class PluginSource(BaseSource):
    name = "plugin_test"
    description = "A test plugin source."
    default_interval_minutes = 120
    default_lookback_days = 2

    async def fetch(
        self,
        *,
        since: datetime | None = None,
        checkpoint: dict[str, Any] | None = None,
    ) -> AsyncIterator[RawVuln]:
        yield RawVuln(source=self.name, source_vuln_id="PLUGIN-1")


class ScheduledPluginSource(PluginSource):
    name = "plugin_scheduled"

    @classmethod
    def plugin_schedule(cls, settings: Settings) -> SchedulePolicy:
        return SchedulePolicy(
            interval_seconds=45 * 60,
            lookback_days=3,
            run_on_start=False,
        )


class FakeEntryPoint:
    def __init__(self, name: str, loaded: object, value: str | None = None) -> None:
        self.name = name
        self.value = value or f"test_plugins:{name}"
        self._loaded = loaded

    def load(self) -> object:
        return self._loaded


class FakeEntryPoints:
    def __init__(self, entries: list[FakeEntryPoint]) -> None:
        self._entries = entries

    def select(self, group: str) -> list[FakeEntryPoint]:
        assert group == ENTRY_POINT_GROUP
        return self._entries


@pytest.fixture(autouse=True)
def _isolated_plugin_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulpulse.crawler.registry._REGISTRY", {})
    reset_plugin_loading()
    yield
    reset_plugin_loading()


def install_entry_points(monkeypatch: pytest.MonkeyPatch, *entries: FakeEntryPoint) -> None:
    monkeypatch.setattr(
        "vulpulse.plugins.entry_points",
        lambda: FakeEntryPoints(list(entries)),
    )


def test_builtins_are_registered_and_described() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    infos = {info.name: info for info in plugin_infos(settings)}

    assert {"nvd", "cisa_kev", "exploitdb"} <= set(infos)
    assert infos["nvd"].builtin is True
    assert infos["nvd"].interval_seconds == settings.nvd_interval_minutes * 60
    assert infos["cisa_kev"].description


def test_entry_point_class_is_loaded(monkeypatch: pytest.MonkeyPatch) -> None:
    install_entry_points(monkeypatch, FakeEntryPoint("plugin-test", PluginSource))
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    failures = load_plugins(settings, force=True)
    infos = {info.name: info for info in plugin_infos(settings)}

    assert failures == []
    assert "plugin_test" in available_sources()
    assert infos["plugin_test"].builtin is False
    assert infos["plugin_test"].interval_seconds == 120 * 60
    assert infos["plugin_test"].entry_point == "test_plugins:plugin-test"


def test_entry_point_factory_is_loaded(monkeypatch: pytest.MonkeyPatch) -> None:
    def factory() -> type[BaseSource]:
        return PluginSource

    install_entry_points(monkeypatch, FakeEntryPoint("plugin-factory", factory))
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    assert load_plugins(settings, force=True) == []
    assert "plugin_test" in available_sources()


def test_schedule_override_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    install_entry_points(monkeypatch, FakeEntryPoint("scheduled", ScheduledPluginSource))
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    load_plugins(settings, force=True)

    infos = {info.name: info for info in plugin_infos(settings)}

    assert infos["plugin_scheduled"].interval_seconds == 45 * 60
    assert infos["plugin_scheduled"].lookback_days == 3
    assert infos["plugin_scheduled"].run_on_start is False


def test_plugin_with_wrong_api_version_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    class WrongVersion(PluginSource):
        name = "plugin_wrong_version"
        plugin_api_version = 99

    install_entry_points(monkeypatch, FakeEntryPoint("wrong-version", WrongVersion))
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    failures = load_plugins(settings, force=True)

    assert len(failures) == 1
    assert "unsupported plugin API version" in failures[0].error
    assert "plugin_wrong_version" not in available_sources()


def test_broken_plugin_does_not_block_others(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> type[BaseSource]:
        raise RuntimeError("plugin exploded")

    install_entry_points(
        monkeypatch,
        FakeEntryPoint("broken", broken),
        FakeEntryPoint("good", PluginSource),
    )
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    failures = load_plugins(settings, force=True)

    assert [failure.entry_point for failure in failures] == ["broken"]
    assert "plugin exploded" in failures[0].error
    assert "plugin_test" in available_sources()
    assert plugin_failures() == failures


def test_scheduler_adds_jobs_for_loaded_plugins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_entry_points(monkeypatch, FakeEntryPoint("scheduled", ScheduledPluginSource))
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    load_plugins(settings, force=True)

    schedules = {schedule.job_id: schedule for schedule in default_schedules(settings)}

    assert schedules["crawl:plugin_scheduled"].interval_seconds == 45 * 60
    assert schedules["crawl:plugin_scheduled"].lookback_days == 3
    assert schedules["crawl:plugin_scheduled"].run_on_start is False


def test_plugins_can_be_disabled_without_losing_builtins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def load() -> object:
        nonlocal called
        called = True
        return PluginSource

    install_entry_points(monkeypatch, FakeEntryPoint("disabled", load))
    settings = Settings(  # type: ignore[call-arg]
        _env_file=None,
        plugins_enabled=False,
    )

    assert load_plugins(settings, force=True) == []
    infos = {info.name: info for info in plugin_infos(settings)}

    assert called is False
    assert {"nvd", "cisa_kev", "exploitdb"} <= set(infos)
    assert "plugin_test" not in infos
