"""
Data models for LLM service responses.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class LLMAnalysisType(str, Enum):
    """Types of LLM analysis available."""

    ZERO_DAY_DETECTION = "zero_day_detection"
    OBFUSCATION_ANALYSIS = "obfuscation_analysis"
    BEHAVIORAL_PATTERN = "behavioral_pattern"
    SUPPLY_CHAIN_RISK = "supply_chain_risk"
    AI_ATTACK_VECTOR = "ai_attack_vector"
    CONTEXTUAL_CORRELATION = "contextual_correlation"

    CONTEXT_CORRELATION = "contextual_correlation"


class LLMConfidence(str, Enum):
    """Confidence levels for LLM analysis."""

    LOW = "low"  # < 0.3
    MEDIUM = "medium"  # 0.3 - 0.7
    HIGH = "high"  # 0.7 - 0.9
    VERY_HIGH = "very_high"  # > 0.9


class LLMThreatCategory(str, Enum):
    """Categories of threats that LLM can detect."""

    CODE_INJECTION = "code_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_THEFT = "credential_theft"
    SUPPLY_CHAIN_ATTACK = "supply_chain_attack"
    PROMPT_INJECTION = "prompt_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    OBFUSCATED_MALWARE = "obfuscated_malware"
    TIME_BOMB = "time_bomb"
    BACKDOOR = "backdoor"
    UNKNOWN_PATTERN = "unknown_pattern"


class LLMInsight(BaseModel):
    """A single insight from LLM analysis."""

    analysis_type: LLMAnalysisType = Field(
        ..., description="Type of analysis performed"
    )
    threat_category: LLMThreatCategory = Field(
        ..., description="Category of threat detected"
    )
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0-1")
    confidence_level: LLMConfidence = Field(
        ..., description="Confidence level category"
    )

    title: str = Field(..., description="Human-readable title of the finding")
    description: str = Field(..., description="Detailed explanation of the threat")
    reasoning: str = Field(..., description="AI reasoning behind the detection")

    # Evidence and context
    evidence_snippets: list[str] = Field(
        default_factory=list, description="Code snippets as evidence"
    )
    affected_files: list[str] = Field(
        default_factory=list, description="Files where threat was detected"
    )

    # Risk assessment
    severity_adjustment: float = Field(
        default=0.0, description="Suggested adjustment to base severity (-5.0 to +5.0)"
    )
    false_positive_likelihood: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Likelihood this is a false positive"
    )

    # Remediation
    remediation_suggestions: list[str] = Field(
        default_factory=list, description="Suggested fixes"
    )
    mitigation_steps: list[str] = Field(
        default_factory=list, description="Immediate mitigation steps"
    )


class LLMContextAnalysis(BaseModel):
    """Contextual analysis across multiple files/findings."""

    attack_chain_detected: bool = Field(
        default=False, description="Multi-step attack detected"
    )
    coordinated_threat: bool = Field(
        default=False, description="Coordinated threat across files"
    )

    attack_chain_steps: list[str] = Field(
        default_factory=list, description="Steps in the attack chain"
    )
    correlation_insights: list[str] = Field(
        default_factory=list, description="Cross-file correlations"
    )

    overall_intent: str = Field(default="", description="Overall intent assessment")
    sophistication_level: str = Field(
        default="basic",
        description="Attack sophistication: basic, intermediate, advanced",
    )


class LLMAnalysisRequest(BaseModel):
    """Request model for LLM analysis."""

    # Core content
    file_contents: dict[str, str] = Field(
        ..., description="Filename -> content mapping"
    )
    static_findings: list[dict[str, Any]] = Field(
        default_factory=list, description="Existing static analysis findings"
    )

    # Context
    repository_context: dict[str, Any] = Field(
        default_factory=dict, description="Repository metadata"
    )
    target_type: str = Field(
        default="directory", description="Type of target being scanned"
    )

    # Analysis options
    analysis_types: list[LLMAnalysisType] = Field(
        default_factory=lambda: [LLMAnalysisType.ZERO_DAY_DETECTION],
        description="Types of analysis to perform",
    )
    max_insights: int = Field(
        default=10, ge=1, le=50, description="Maximum insights to return"
    )

    # Cost controls
    max_tokens: int = Field(default=8000, description="Maximum tokens for analysis")
    include_context_analysis: bool = Field(
        default=True, description="Include cross-file analysis"
    )


class LLMAnalysisResponse(BaseModel):
    """Response model for LLM analysis."""

    # Analysis results
    insights: list[LLMInsight] = Field(
        default_factory=list, description="Individual threat insights"
    )
    context_analysis: LLMContextAnalysis | None = Field(
        None, description="Cross-file contextual analysis"
    )

    # Meta information
    analysis_id: str = Field(..., description="Unique identifier for this analysis")
    model_used: str = Field(..., description="LLM model that performed the analysis")
    tokens_used: int = Field(default=0, description="Number of tokens consumed")
    processing_time_ms: int = Field(
        default=0, description="Processing time in milliseconds"
    )

    # Quality indicators
    cache_hit: bool = Field(
        default=False, description="Whether results came from cache"
    )
    confidence_summary: dict[str, int] = Field(
        default_factory=dict, description="Count by confidence level"
    )
    threat_summary: dict[str, int] = Field(
        default_factory=dict, description="Count by threat category"
    )

    # Status
    success: bool = Field(
        default=True, description="Whether analysis completed successfully"
    )
    error_message: str | None = Field(
        None, description="Error message if analysis failed"
    )
    fallback_used: bool = Field(
        default=False, description="Whether fallback to static analysis was used"
    )

    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.utcnow, description="When analysis was performed"
    )


class LLMUsageMetrics(BaseModel):
    """Usage tracking for LLM service."""

    user_id: str = Field(..., description="User who initiated the analysis")
    analysis_id: str = Field(..., description="Unique analysis identifier")

    # Costs
    tokens_used: int = Field(default=0, description="Tokens consumed")
    estimated_cost_usd: float = Field(default=0.0, description="Estimated cost in USD")

    # Performance
    response_time_ms: int = Field(default=0, description="Total response time")
    cache_hit: bool = Field(default=False, description="Whether cache was used")

    # Quality
    insights_generated: int = Field(
        default=0, description="Number of insights generated"
    )
    high_confidence_insights: int = Field(
        default=0, description="Number of high-confidence insights"
    )

    # Meta
    model_used: str = Field(..., description="LLM model used")
    provider: str = Field(..., description="LLM provider (openai, azure, anthropic)")
    created_at: datetime = Field(
        default_factory=datetime.utcnow, description="Timestamp"
    )


def confidence_to_level(score: float) -> LLMConfidence:
    """Convert numeric confidence score to level enum."""
    if score < 0.3:
        return LLMConfidence.LOW
    elif score < 0.7:
        return LLMConfidence.MEDIUM
    elif score < 0.9:
        return LLMConfidence.HIGH
    else:
        return LLMConfidence.VERY_HIGH
