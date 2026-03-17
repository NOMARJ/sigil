"""
Scanner v2 service functions.

Handles scanner version tracking, confidence calculation, and
progressive migration between scanner versions.
"""

from __future__ import annotations

from typing import List
from api.models import Finding, Confidence
from api.schemas.scan import ConfidenceSummary


def calculate_confidence_summary(findings: List[Finding]) -> ConfidenceSummary:
    """Calculate confidence summary from a list of findings."""
    if not findings:
        return ConfidenceSummary()

    high_count = sum(1 for f in findings if f.confidence == Confidence.HIGH)
    medium_count = sum(1 for f in findings if f.confidence == Confidence.MEDIUM)
    low_count = sum(1 for f in findings if f.confidence == Confidence.LOW)

    # Calculate average confidence (HIGH=1.0, MEDIUM=0.5, LOW=0.0)
    confidence_values = []
    for finding in findings:
        if finding.confidence == Confidence.HIGH:
            confidence_values.append(1.0)
        elif finding.confidence == Confidence.MEDIUM:
            confidence_values.append(0.5)
        else:  # LOW
            confidence_values.append(0.0)

    avg_confidence = (
        sum(confidence_values) / len(confidence_values) if confidence_values else 0.0
    )

    # Estimate false positive likelihood based on confidence distribution
    total = len(findings)
    low_ratio = low_count / total if total > 0 else 0

    if low_ratio >= 0.7:
        fp_likelihood = "HIGH"
    elif low_ratio >= 0.4:
        fp_likelihood = "MEDIUM"
    elif low_ratio >= 0.1:
        fp_likelihood = "LOW"
    else:
        fp_likelihood = "LOW"

    return ConfidenceSummary(
        high_confidence_count=high_count,
        medium_confidence_count=medium_count,
        low_confidence_count=low_count,
        average_confidence=round(avg_confidence, 3),
        false_positive_likelihood=fp_likelihood,
    )


def is_scanner_v2_enabled() -> bool:
    """Check if scanner v2 is enabled via feature flag."""
    from api.config import settings

    return settings.scanner_version.startswith("2.")


def get_current_scanner_version() -> str:
    """Get the current scanner version from configuration."""
    from api.config import settings

    return settings.scanner_version
