"""Crawler framework: source adapters, HTTP client and raw models."""

from vulpulse.crawler.base import BaseSource
from vulpulse.crawler.models import RawProduct, RawVuln
from vulpulse.crawler.registry import available_sources, create_source, register_source

__all__ = [
    "BaseSource",
    "RawProduct",
    "RawVuln",
    "available_sources",
    "create_source",
    "register_source",
]
