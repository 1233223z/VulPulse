"""Optional AI-assisted vulnerability analysis."""

from vulpulse.ai.summarizer import (
    SummaryConfigurationError,
    SummaryDisabled,
    SummaryError,
    SummaryRefused,
    SummaryResult,
    VulnSummarizer,
)

__all__ = [
    "SummaryConfigurationError",
    "SummaryDisabled",
    "SummaryError",
    "SummaryRefused",
    "SummaryResult",
    "VulnSummarizer",
]
