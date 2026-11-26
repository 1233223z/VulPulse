"""Installed source plugin metadata."""

from __future__ import annotations

from fastapi import APIRouter

from vulpulse.api.schemas import PluginInfoOut
from vulpulse.config import get_settings
from vulpulse.plugins import plugin_infos

router = APIRouter(prefix="/plugins", tags=["plugins"])


@router.get("", response_model=list[PluginInfoOut])
async def list_plugins() -> list[PluginInfoOut]:
    settings = get_settings()
    return [
        PluginInfoOut(
            name=plugin.name,
            description=plugin.description,
            kind=plugin.kind,
            interval_seconds=plugin.interval_seconds,
            lookback_days=plugin.lookback_days,
            run_on_start=plugin.run_on_start,
            api_version=plugin.api_version,
            module=plugin.module,
            entry_point=plugin.entry_point,
            builtin=plugin.builtin,
        )
        for plugin in plugin_infos(settings)
    ]
