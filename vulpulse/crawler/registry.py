"""Registry of available crawler sources."""

from __future__ import annotations

from typing import TypeVar

from vulpulse.config import Settings
from vulpulse.crawler.base import BaseSource

SourceClass = TypeVar("SourceClass", bound=type[BaseSource])

_REGISTRY: dict[str, type[BaseSource]] = {}


def register_source(cls: SourceClass) -> SourceClass:
    """Class decorator that makes a source discoverable by name."""
    name = getattr(cls, "name", "")
    if not name:
        raise ValueError("Source classes must define a non-empty `name`")
    if name in _REGISTRY and _REGISTRY[name] is not cls:
        raise ValueError(f"Duplicate source name: {name}")
    _REGISTRY[name] = cls
    return cls


def available_sources() -> list[str]:
    return sorted(_REGISTRY)


def registered_sources() -> dict[str, type[BaseSource]]:
    """Return a copy of the current source class registry."""
    return dict(_REGISTRY)


def create_source(name: str, settings: Settings) -> BaseSource:
    try:
        cls = _REGISTRY[name]
    except KeyError as exc:
        raise KeyError(f"Unknown source: {name}") from exc
    return cls(settings)
