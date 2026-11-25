"""Concrete crawler sources. Importing this package populates the registry."""

from vulpulse.crawler.sources.cisa_kev import CisaKevSource
from vulpulse.crawler.sources.nvd import NvdSource

__all__ = ["CisaKevSource", "NvdSource"]
