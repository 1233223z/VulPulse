"""Source plugin discovery and metadata.

A plugin is a Python distribution that exposes a ``vulpulse.sources`` entry
point. The entry point may point at a :class:`~vulpulse.crawler.base.BaseSource`
subclass or at a zero-argument factory returning one.

Plugin code is imported and executed in-process. Install only plugins you
trust; ``VULPULSE_PLUGINS_ENABLED=false`` disables third-party discovery while
keeping the built-in sources available.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Any

from loguru import logger

from vulpulse.config import Settings, get_settings
from vulpulse.crawler.base import PLUGIN_API_VERSION, BaseSource
from vulpulse.crawler.registry import register_source, registered_sources
from vulpulse.crawler.sources import CisaKevSource, ExploitDbSource, NvdSource

ENTRY_POINT_GROUP = "vulpulse.sources"

_BUILTIN_SOURCES = (NvdSource, CisaKevSource, ExploitDbSource)
_LOADED = False
_FAILURES: list[PluginLoadFailure] = []
_ENTRY_POINTS: dict[str, str] = {}


@dataclass(frozen=True)
class PluginInfo:
    """Public metadata for one installed source plugin."""

    name: str
    description: str
    kind: str
    interval_seconds: int
    lookback_days: int
    run_on_start: bool
    api_version: int
    module: str
    entry_point: str | None
    builtin: bool


@dataclass(frozen=True)
class PluginLoadFailure:
    """A plugin that could not be loaded; other plugins keep working."""

    entry_point: str
    error: str


def _register_builtins() -> None:
    for source_class in _BUILTIN_SOURCES:
        register_source(source_class)


def _iter_entry_points() -> list[Any]:
    discovered = entry_points()
    select = getattr(discovered, "select", None)
    if select is not None:
        return list(select(group=ENTRY_POINT_GROUP))
    # Python 3.10 compatibility for the mapping-style EntryPoints object.
    return list(discovered.get(ENTRY_POINT_GROUP, []))  # type: ignore[union-attr]


def _resolve_source(entry_point: Any) -> type[BaseSource]:
    loaded = entry_point.load()
    if isinstance(loaded, type):
        source_class = loaded
    elif callable(loaded):
        source_class = loaded()
    else:
        raise TypeError("entry point must expose a BaseSource subclass or factory")

    if not isinstance(source_class, type) or not issubclass(source_class, BaseSource):
        raise TypeError("entry point did not resolve to a BaseSource subclass")
    return source_class


def load_plugins(
    settings: Settings | None = None, *, force: bool = False
) -> list[PluginLoadFailure]:
    """Load built-in sources and third-party entry points.

    Built-in sources are always registered. Third-party discovery is skipped
    when ``VULPULSE_PLUGINS_ENABLED`` is false. A broken plugin is recorded as a
    failure and does not prevent the application from starting.
    """
    global _LOADED
    _register_builtins()

    if _LOADED and not force:
        return list(_FAILURES)

    if force:
        _FAILURES.clear()
        _ENTRY_POINTS.clear()

    current = settings or get_settings()
    if not current.plugins_enabled:
        logger.info("Third-party source plugin discovery is disabled")
        _LOADED = True
        return []

    for entry_point in _iter_entry_points():
        entry_point_name = getattr(entry_point, "name", repr(entry_point))
        try:
            source_class = _resolve_source(entry_point)
            version = int(getattr(source_class, "plugin_api_version", 0))
            if version != PLUGIN_API_VERSION:
                raise ValueError(
                    f"unsupported plugin API version {version}; expected {PLUGIN_API_VERSION}"
                )
            if not getattr(source_class, "name", ""):
                raise ValueError("plugin source must define a non-empty name")
            policy = source_class.plugin_schedule(current)
            if policy.interval_seconds <= 0:
                raise ValueError("plugin schedule interval must be positive")
            register_source(source_class)
            entry_point_value = getattr(entry_point, "value", entry_point_name)
            _ENTRY_POINTS[source_class.name] = str(entry_point_value)
            logger.info(
                "Loaded source plugin {} from {}",
                source_class.name,
                entry_point_name,
            )
        except Exception as exc:
            failure = PluginLoadFailure(entry_point=entry_point_name, error=str(exc))
            _FAILURES.append(failure)
            logger.warning(
                "Failed to load source plugin {}: {}",
                entry_point_name,
                exc,
            )

    _LOADED = True
    return list(_FAILURES)


def plugin_infos(settings: Settings | None = None) -> list[PluginInfo]:
    """Return metadata for built-in and loaded source plugins."""
    current = settings or get_settings()
    load_plugins(current)
    infos: list[PluginInfo] = []

    for name, source_class in sorted(registered_sources().items()):
        try:
            policy = source_class.plugin_schedule(current)
            if policy.interval_seconds <= 0:
                raise ValueError("schedule interval must be positive")
        except Exception as exc:
            logger.warning("Ignoring source plugin {} with invalid schedule: {}", name, exc)
            continue

        doc = (source_class.__doc__ or "").strip()
        description = getattr(source_class, "description", "") or (
            doc.splitlines()[0] if doc else ""
        )
        module = source_class.__module__
        infos.append(
            PluginInfo(
                name=name,
                description=description,
                kind=getattr(source_class, "kind", "api"),
                interval_seconds=policy.interval_seconds,
                lookback_days=policy.lookback_days,
                run_on_start=policy.run_on_start,
                api_version=int(getattr(source_class, "plugin_api_version", 0)),
                module=module,
                entry_point=_ENTRY_POINTS.get(name),
                builtin=module.startswith("vulpulse.crawler.sources"),
            )
        )

    return infos


def plugin_failures() -> list[PluginLoadFailure]:
    """Return plugins that failed to load during the last discovery pass."""
    return list(_FAILURES)


def reset_plugin_loading() -> None:
    """Reset discovery state. Intended for tests and embedding applications."""
    global _LOADED
    _LOADED = False
    _FAILURES.clear()
    _ENTRY_POINTS.clear()
