"""Crawler framework: source adapters, HTTP client and raw models."""

from vulpulse.crawler.base import BaseSource
from vulpulse.crawler.models import RawProduct, RawVuln
from vulpulse.crawler.registry import available_sources, create_source, register_source
from vulpulse.crawler.sources import CisaKevSource, ExploitDbSource, NvdSource

__all__ = [
    "BaseSource",
    "CisaKevSource",
    "ExploitDbSource",
    "NvdSource",
    "RawProduct",
    "RawVuln",
    "available_sources",
    "create_source",
    "register_source",
]
