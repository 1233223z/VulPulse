"""Normalization, merging and (later) risk scoring."""

from vulpulse.analyzer.normalizer import (
    normalize_raw,
    normalize_severity,
    severity_from_score,
)

__all__ = ["normalize_raw", "normalize_severity", "severity_from_score"]
