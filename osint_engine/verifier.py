"""Intelligence verification and confidence scoring utilities."""

from __future__ import annotations

from enum import Enum


class ConfidenceLevel(str, Enum):
    VERY_HIGH = "VERY HIGH"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    UNVERIFIED = "UNVERIFIED"


VALID_CONFIDENCE = {c.value for c in ConfidenceLevel}


def normalize_confidence(level: str) -> str:
    upper = level.strip().upper()
    if upper in VALID_CONFIDENCE:
        return upper
    return ConfidenceLevel.UNVERIFIED.value


def score_from_sources(source_count: int, has_authoritative: bool = False, has_conflict: bool = False) -> str:
    """Compute a conservative confidence rating from independent corroboration."""
    if has_conflict:
        return ConfidenceLevel.LOW.value
    if source_count <= 0:
        return ConfidenceLevel.UNVERIFIED.value
    if has_authoritative and source_count >= 2:
        return ConfidenceLevel.VERY_HIGH.value
    if has_authoritative or source_count >= 3:
        return ConfidenceLevel.HIGH.value
    if source_count == 2:
        return ConfidenceLevel.MODERATE.value
    return ConfidenceLevel.LOW.value
