"""
Usage Metrics Models for Sigil Pro Analytics

Data models for tracking LLM usage, threat discoveries, and user engagement
metrics to support business intelligence and churn prediction.
"""

from __future__ import annotations

from datetime import datetime, date
from decimal import Decimal
from typing import Optional, Dict, List, Tuple, Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Core Analytics Models
# ---------------------------------------------------------------------------


class UsageEvent(BaseModel):
    """General analytics event for business intelligence tracking."""
    
    user_id: str = Field(..., description="User who triggered the event")
    event_type: str = Field(..., description="Type of event (llm_scan, threat_detected, etc.)")
    event_data: Optional[Dict[str, Any]] = Field(None, description="Event-specific data as JSON")
    tier: str = Field(..., description="User's current subscription tier")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class LLMUsageRecord(BaseModel):
    """Detailed record of LLM API usage for cost and performance tracking."""
    
    user_id: str = Field(..., description="User who initiated the analysis")
    scan_id: str = Field(..., description="Unique identifier for the scan")
    model_used: str = Field(..., description="LLM model used (gpt-4, claude-3-sonnet, etc.)")
    tokens_used: int = Field(0, description="Total tokens consumed")
    processing_time_ms: int = Field(0, description="Time taken for analysis in milliseconds")
    cost_cents: Decimal = Field(Decimal('0.00'), description="Estimated cost in cents")
    insights_generated: int = Field(0, description="Number of AI insights produced")
    threats_found: int = Field(0, description="Number of threats detected (confidence > 0.7)")
    confidence_avg: float = Field(0.0, description="Average confidence score (0-1)")
    cache_hit: bool = Field(False, description="Whether result came from cache")
    fallback_used: bool = Field(False, description="Whether fallback was used due to errors")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    @field_validator('confidence_avg')
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Ensure confidence is between 0 and 1."""
        return max(0.0, min(1.0, v))


class ThreatDiscovery(BaseModel):
    """Individual threat discovery record for trend analysis."""
    
    user_id: str = Field(..., description="User who discovered the threat")
    scan_id: Optional[str] = Field(None, description="Associated scan ID")
    threat_type: str = Field(..., description="Category of threat (code_injection, credential_theft, etc.)")
    severity: str = Field(..., description="Severity level (info, low, medium, high, critical)")
    confidence: float = Field(..., description="Confidence score (0-1)")
    is_zero_day: bool = Field(False, description="Whether this is a zero-day discovery")
    file_path: Optional[str] = Field(None, description="Path to affected file")
    threat_hash: Optional[str] = Field(None, description="SHA-256 hash for deduplication")
    analysis_type: str = Field("llm_analysis", description="Type of analysis that found this threat")
    evidence_snippet: Optional[str] = Field(None, description="Code snippet showing the threat")
    remediation_suggested: List[str] = Field(default_factory=list, description="Suggested remediation steps")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Ensure confidence is between 0 and 1."""
        return max(0.0, min(1.0, v))


class UserEngagementMetrics(BaseModel):
    """Daily user engagement metrics for churn prediction."""
    
    user_id: str = Field(..., description="User being tracked")
    date_tracked: date = Field(..., description="Date of metrics aggregation")
    scans_performed: int = Field(0, description="Number of scans performed")
    threats_discovered: int = Field(0, description="Total threats discovered")
    zero_days_found: int = Field(0, description="Zero-day discoveries")
    llm_tokens_used: int = Field(0, description="LLM tokens consumed")
    session_duration_minutes: int = Field(0, description="Total session time in minutes")
    features_used: List[str] = Field(default_factory=list, description="Features accessed during the day")
    upgrade_prompts_shown: int = Field(0, description="Number of upgrade prompts shown to free users")
    upgrade_prompts_dismissed: int = Field(0, description="Number of upgrade prompts dismissed")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class BillingUsageSummary(BaseModel):
    """Billing period usage summary for cost tracking and limits."""
    
    user_id: str = Field(..., description="User being billed")
    billing_period_start: date = Field(..., description="Start of billing period")
    billing_period_end: date = Field(..., description="End of billing period")
    tier: str = Field(..., description="Subscription tier during this period")
    total_scans: int = Field(0, description="Total scans performed")
    total_llm_tokens: int = Field(0, description="Total LLM tokens used")
    total_cost_cents: Decimal = Field(Decimal('0.00'), description="Total cost in cents")
    total_threats_found: int = Field(0, description="Total threats discovered")
    zero_days_discovered: int = Field(0, description="Zero-day discoveries in this period")
    overage_charges_cents: Decimal = Field(Decimal('0.00'), description="Charges for usage beyond plan limits")
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Analytics Response Models
# ---------------------------------------------------------------------------


class DailyUsageReport(BaseModel):
    """Daily usage report for business intelligence."""
    
    date_range: Tuple[datetime, datetime] = Field(..., description="Start and end dates for the report")
    active_users: int = Field(0, description="Number of active Pro users")
    llm_scans: int = Field(0, description="Total LLM-powered scans")
    total_tokens: int = Field(0, description="Total tokens consumed")
    total_cost: Decimal = Field(Decimal('0.00'), description="Total estimated cost")
    avg_processing_time: float = Field(0.0, description="Average processing time in milliseconds")
    insights_generated: int = Field(0, description="Total AI insights generated")
    threats_detected: int = Field(0, description="Total threats detected")
    zero_day_discoveries: int = Field(0, description="Zero-day discoveries")
    cache_hit_rate: float = Field(0.0, description="Cache hit rate percentage")
    fallback_rate: float = Field(0.0, description="Fallback usage rate percentage")


class ChurnRiskMetrics(BaseModel):
    """Churn risk assessment for individual users."""
    
    user_id: str = Field(..., description="User being assessed")
    risk_score: int = Field(..., description="Risk score (0-100, higher = more likely to churn)")
    risk_category: str = Field(..., description="Risk category (HEALTHY, LOW_ENGAGEMENT, MEDIUM_RISK, HIGH_RISK)")
    last_scan_date: Optional[datetime] = Field(None, description="Date of last scan activity")
    monthly_scans: int = Field(0, description="Number of scans in last 30 days")
    threat_hit_rate: float = Field(0.0, description="Percentage of scans that found threats")
    avg_session_duration: float = Field(0.0, description="Average session duration in minutes")
    feature_adoption_score: float = Field(0.0, description="Score based on features used (0-1)")
    upgrade_prompt_response: Optional[str] = Field(None, description="Response to upgrade prompts (for free users)")


class ThreatTrendAnalysis(BaseModel):
    """Threat discovery trends for security intelligence."""
    
    date_range: Tuple[datetime, datetime] = Field(..., description="Analysis period")
    threat_type: str = Field(..., description="Type of threat analyzed")
    total_discoveries: int = Field(0, description="Total discoveries in period")
    zero_day_count: int = Field(0, description="Zero-day discoveries")
    avg_confidence: float = Field(0.0, description="Average confidence score")
    severity_distribution: Dict[str, int] = Field(default_factory=dict, description="Count by severity level")
    discovery_velocity: float = Field(0.0, description="Discoveries per day")
    unique_users_affected: int = Field(0, description="Number of unique users who encountered this threat")


class UserUsageStats(BaseModel):
    """Personal usage statistics for user dashboard."""
    
    user_id: str = Field(..., description="User requesting stats")
    current_period_start: date = Field(..., description="Start of current billing period")
    scans_this_period: int = Field(0, description="Scans performed this billing period")
    tokens_used: int = Field(0, description="LLM tokens used this period")
    cost_this_period: Decimal = Field(Decimal('0.00'), description="Estimated cost this period")
    threats_discovered: int = Field(0, description="Threats discovered this period")
    zero_days_found: int = Field(0, description="Zero-day discoveries this period")
    plan_limits: Dict[str, Any] = Field(default_factory=dict, description="Current plan limits")
    usage_by_day: List[Dict[str, Any]] = Field(default_factory=list, description="Daily breakdown")
    top_threat_categories: List[Dict[str, Any]] = Field(default_factory=list, description="Most common threat types found")


# ---------------------------------------------------------------------------
# Analytics Request Models
# ---------------------------------------------------------------------------


class AnalyticsQuery(BaseModel):
    """Base class for analytics queries."""
    
    start_date: datetime = Field(..., description="Start date for analysis")
    end_date: datetime = Field(..., description="End date for analysis")
    user_ids: Optional[List[str]] = Field(None, description="Filter to specific users")
    tiers: Optional[List[str]] = Field(None, description="Filter to specific subscription tiers")


class UsageAnalyticsQuery(AnalyticsQuery):
    """Query for usage analytics and reports."""
    
    include_cost_breakdown: bool = Field(False, description="Include detailed cost analysis")
    include_model_performance: bool = Field(False, description="Include model performance metrics")
    group_by_day: bool = Field(True, description="Group results by day")


class ThreatAnalyticsQuery(AnalyticsQuery):
    """Query for threat discovery analytics."""
    
    threat_types: Optional[List[str]] = Field(None, description="Filter to specific threat types")
    min_confidence: float = Field(0.0, description="Minimum confidence threshold")
    include_zero_days_only: bool = Field(False, description="Only include zero-day discoveries")
    severity_levels: Optional[List[str]] = Field(None, description="Filter to specific severity levels")


class ChurnAnalyticsQuery(BaseModel):
    """Query for churn risk analysis."""
    
    risk_categories: Optional[List[str]] = Field(None, description="Filter to specific risk categories")
    min_risk_score: int = Field(0, description="Minimum risk score threshold")
    include_recommendations: bool = Field(True, description="Include retention recommendations")


# ---------------------------------------------------------------------------
# Aggregated Analytics Models
# ---------------------------------------------------------------------------


class BusinessMetricsSummary(BaseModel):
    """High-level business metrics for executive dashboards."""
    
    period_type: str = Field(..., description="Period type (daily, weekly, monthly)")
    period_start: datetime = Field(..., description="Start of metrics period")
    period_end: datetime = Field(..., description="End of metrics period")
    
    # Revenue metrics
    active_pro_subscribers: int = Field(0, description="Number of active Pro subscribers")
    mrr_cents: Decimal = Field(Decimal('0.00'), description="Monthly recurring revenue in cents")
    churn_rate: float = Field(0.0, description="Churn rate percentage")
    
    # Product usage metrics
    total_scans: int = Field(0, description="Total scans across all users")
    ai_powered_scans: int = Field(0, description="AI-powered (Pro) scans")
    unique_threats_discovered: int = Field(0, description="Unique threats discovered")
    zero_day_discoveries: int = Field(0, description="Zero-day discoveries")
    
    # Cost metrics
    llm_costs_cents: Decimal = Field(Decimal('0.00'), description="LLM API costs in cents")
    cost_per_insight: Decimal = Field(Decimal('0.00'), description="Cost per AI insight generated")
    margin_percentage: float = Field(0.0, description="Gross margin percentage")
    
    # Quality metrics
    avg_threat_confidence: float = Field(0.0, description="Average confidence of threat detections")
    false_positive_rate: float = Field(0.0, description="Estimated false positive rate")
    user_satisfaction_score: Optional[float] = Field(None, description="User satisfaction score if available")


# ---------------------------------------------------------------------------
# Analytics Configuration Models
# ---------------------------------------------------------------------------


class AnalyticsConfig(BaseModel):
    """Configuration for analytics tracking and reporting."""
    
    track_individual_events: bool = Field(True, description="Track individual usage events")
    aggregate_daily_metrics: bool = Field(True, description="Create daily metric aggregations")
    retention_days: int = Field(90, description="Days to retain detailed analytics data")
    cost_calculation_enabled: bool = Field(True, description="Calculate LLM usage costs")
    churn_prediction_enabled: bool = Field(True, description="Enable churn risk prediction")
    real_time_alerts: bool = Field(False, description="Enable real-time usage alerts")
    anonymize_after_days: int = Field(365, description="Days after which to anonymize user data")