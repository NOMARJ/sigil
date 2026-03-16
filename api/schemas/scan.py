"""
Scan-related schemas for Scanner v2 migration.

This module extends the existing models with scanner version tracking,
confidence levels, and enhanced metadata for progressive migration.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from api.models import Finding, Verdict, ThreatEntry


class ConfidenceSummary(BaseModel):
    """Summary of confidence levels across findings."""
    
    high_confidence_count: int = Field(
        0, 
        description="Number of findings with HIGH confidence"
    )
    medium_confidence_count: int = Field(
        0, 
        description="Number of findings with MEDIUM confidence"
    )
    low_confidence_count: int = Field(
        0, 
        description="Number of findings with LOW confidence"
    )
    average_confidence: float = Field(
        0.0,
        description="Average confidence score (0.0-1.0)"
    )
    false_positive_likelihood: str = Field(
        "UNKNOWN",
        description="Estimated false positive rate: LOW/MEDIUM/HIGH/UNKNOWN"
    )


class ScanResponseV2(BaseModel):
    """Enhanced scan response with version tracking and confidence data."""
    
    disclaimer: str = Field(
        default="Automated static analysis result. Not a security certification. "
        "Provided as-is without warranty. See sigilsec.ai/terms for full terms.",
        description="Legal disclaimer — always included in responses",
    )
    scan_id: str = Field(..., description="Unique identifier for this scan")
    scanner_version: str = Field(
        "2.0.0", 
        description="Version of scanner used for this scan"
    )
    target: str
    target_type: str
    files_scanned: int = 0
    findings: List[Finding] = Field(default_factory=list)
    risk_score: float = Field(0.0, description="Aggregate weighted risk score")
    verdict: Verdict = Field(
        Verdict.LOW_RISK, description="Overall risk classification"
    )
    confidence_summary: ConfidenceSummary = Field(
        default_factory=ConfidenceSummary,
        description="Summary of confidence levels across findings"
    )
    threat_intel_hits: List[ThreatEntry] = Field(
        default_factory=list,
        description="Known threat entries matching this scan",
    )
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Additional scan metadata and feature flags"
    )
    
    # V2 specific fields for migration tracking
    original_score: Optional[float] = Field(
        None,
        description="Original score from previous scanner version (if rescanned)"
    )
    rescanned_at: Optional[datetime] = Field(
        None,
        description="Timestamp when this item was rescanned"
    )
    context_weight: float = Field(
        1.0,
        description="Context weighting applied to findings"
    )