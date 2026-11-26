"""Crawler framework: source adapters, HTTP client and raw models."""

from vulpulse.crawler.base import PLUGIN_API_VERSION, BaseSource, SchedulePolicy
from vulpulse.crawler.models import RawProduct, RawVuln
from vulpulse.crawler.registry import available_sources, create_source, register_source
from vulpulse.crawler.sources import CisaKevSource, ExploitDbSource, NvdSource

__all__ = [
    "PLUGIN_API_VERSION",
    "BaseSource",
    "CisaKevSource",
    "ExploitDbSource",
    "NvdSource",
    "RawProduct",
    "RawVuln",
    "SchedulePolicy",
    "available_sources",
    "create_source",
    "register_source",
]
