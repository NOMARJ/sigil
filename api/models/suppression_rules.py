"""
Suppression Rules Model
Defines suppression rules learned from user feedback
"""

from __future__ import annotations

from typing import Optional, Dict
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field


class FeedbackType(str, Enum):
    """Types of user feedback"""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


class SuppressionScope(str, Enum):
    """Scope of suppression rule"""

    PERSONAL = "personal"  # Only affects user's scans
    TEAM = "team"  # Affects team members (opt-in)
    PROJECT = "project"  # Project-specific
    GLOBAL = "global"  # System-wide (admin only)


class SuppressionRule(BaseModel):
    """A suppression rule learned from feedback"""

    rule_id: str = Field(..., description="Unique rule identifier")
    user_id: str = Field(..., description="User who created the rule")
    team_id: Optional[str] = Field(None, description="Team ID for team rules")
    project_id: Optional[str] = Field(None, description="Project ID for project rules")

    # Pattern matching
    pattern_type: str = Field(
        ..., description="Type of pattern (SQL_INJECTION, XSS, etc.)"
    )
    rule_name: str = Field(..., description="Specific rule name")
    file_pattern: Optional[str] = Field(None, description="File path pattern (regex)")
    evidence_pattern: Optional[str] = Field(
        None, description="Evidence pattern (regex)"
    )

    # Suppression details
    scope: SuppressionScope = Field(SuppressionScope.PERSONAL, description="Rule scope")
    confidence_adjustment: float = Field(
        0.0, ge=-1.0, le=1.0, description="Confidence adjustment (-1 to 1)"
    )
    suppress_completely: bool = Field(
        False, description="Completely suppress matching findings"
    )

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    feedback_count: int = Field(
        1, description="Number of feedbacks supporting this rule"
    )
    last_applied: Optional[datetime] = Field(
        None, description="Last time rule was applied"
    )

    # Learning context
    original_finding_id: str = Field(
        ..., description="ID of finding that triggered rule"
    )
    original_feedback: FeedbackType = Field(..., description="Original feedback type")
    reason: Optional[str] = Field(None, description="User-provided reason")

    # Effectiveness tracking
    times_applied: int = Field(0, description="Times this rule has been applied")
    times_overridden: int = Field(0, description="Times user disagreed with rule")
    effectiveness_score: float = Field(
        1.0, ge=0.0, le=1.0, description="Rule effectiveness (0-1)"
    )

    # Status
    active: bool = Field(True, description="Whether rule is active")
    expires_at: Optional[datetime] = Field(None, description="Optional expiration date")


class UserFeedback(BaseModel):
    """User feedback on a finding"""

    feedback_id: str = Field(..., description="Unique feedback identifier")
    user_id: str = Field(..., description="User providing feedback")
    finding_id: str = Field(..., description="Finding being evaluated")
    scan_id: str = Field(..., description="Associated scan")

    # Feedback details
    feedback_type: FeedbackType = Field(..., description="Type of feedback")
    confidence: float = Field(
        1.0, ge=0.0, le=1.0, description="User confidence in feedback"
    )
    reason: Optional[str] = Field(None, description="Explanation for feedback")

    # Finding context
    pattern_type: str = Field(..., description="Pattern type of finding")
    rule_name: str = Field(..., description="Rule that triggered finding")
    file_path: str = Field(..., description="File where finding occurred")
    line_number: int = Field(..., description="Line number of finding")
    severity: str = Field(..., description="Original severity")

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    session_id: Optional[str] = Field(None, description="Interactive session ID")

    # Team sharing
    share_with_team: bool = Field(False, description="Share feedback with team")
    team_id: Optional[str] = Field(None, description="Team to share with")


class FeedbackAggregation(BaseModel):
    """Aggregated feedback for pattern learning"""

    pattern_type: str = Field(..., description="Pattern type")
    rule_name: str = Field(..., description="Rule name")

    # Aggregated stats
    total_feedback: int = Field(0, description="Total feedback count")
    true_positive_count: int = Field(0)
    false_positive_count: int = Field(0)
    uncertain_count: int = Field(0)

    # Calculated metrics
    false_positive_rate: float = Field(0.0, description="FP rate (0-1)")
    confidence_adjustment: float = Field(
        0.0, description="Suggested confidence adjustment"
    )

    # User breakdown
    unique_users: int = Field(0, description="Number of unique users")
    team_consensus: Optional[float] = Field(None, description="Team agreement rate")

    # Time-based
    last_feedback: Optional[datetime] = Field(None)
    trend: str = Field("stable", description="Trend: improving, worsening, stable")


class AccuracyMetrics(BaseModel):
    """Accuracy metrics for feedback learning"""

    user_id: Optional[str] = Field(None, description="User ID (None for global)")
    team_id: Optional[str] = Field(None, description="Team ID (None for non-team)")
    time_period: str = Field("30d", description="Time period for metrics")

    # Overall metrics
    total_findings: int = Field(0)
    total_feedback: int = Field(0)
    feedback_rate: float = Field(0.0, description="Percentage with feedback")

    # Accuracy metrics
    true_positive_rate: float = Field(0.0, description="TPR (0-1)")
    false_positive_rate: float = Field(0.0, description="FPR (0-1)")
    precision: float = Field(0.0, description="Precision (0-1)")
    recall: float = Field(0.0, description="Recall (0-1)")
    f1_score: float = Field(0.0, description="F1 score (0-1)")

    # Pattern-specific accuracy
    pattern_accuracy: Dict[str, Dict[str, float]] = Field(
        default_factory=dict, description="Accuracy by pattern type"
    )

    # Learning effectiveness
    suppression_rules_created: int = Field(0)
    suppressions_applied: int = Field(0)
    suppressions_overridden: int = Field(0)
    learning_effectiveness: float = Field(
        0.0, description="How well the system is learning (0-1)"
    )

    # Trends
    accuracy_trend: str = Field("stable", description="Trend over time")
    improvement_rate: float = Field(0.0, description="Monthly improvement rate")

    # Timestamp
    calculated_at: datetime = Field(default_factory=datetime.utcnow)


class SuppressionRuleUpdate(BaseModel):
    """Update request for suppression rule"""

    confidence_adjustment: Optional[float] = Field(None, ge=-1.0, le=1.0)
    suppress_completely: Optional[bool] = None
    file_pattern: Optional[str] = None
    evidence_pattern: Optional[str] = None
    scope: Optional[SuppressionScope] = None
    active: Optional[bool] = None
    expires_at: Optional[datetime] = None
    reason: Optional[str] = None
