"""
Analytics API Endpoints for Sigil Pro Usage Tracking

Provides endpoints for analytics reporting, usage metrics, and business intelligence
for Pro tier features including LLM analysis tracking and churn prediction.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from typing_extensions import Annotated

from middleware.tier_check import require_pro_tier, get_user_tier
from models import PlanTier
from models.llm_models import (
    DailyUsageReport,
    ChurnRiskMetrics,
    UserUsageStats,
    ThreatTrendAnalysis,
)
from routers.auth import get_current_user_unified, UserResponse
from services.analytics_service import analytics_service


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/analytics", tags=["analytics"])


# -------------------------------------------------------------------------
# Admin Analytics Endpoints (Enterprise/Internal Only)
# -------------------------------------------------------------------------


async def require_admin_tier(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> UserResponse:
    """Require admin/enterprise access for business analytics."""
    user_tier = await get_user_tier(current_user)

    # Only allow enterprise users or internal admin users
    if user_tier != PlanTier.ENTERPRISE and not getattr(
        current_user, "is_admin", False
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or Enterprise tier required for business analytics",
        )

    return current_user


@router.get("/admin/daily-usage", response_model=DailyUsageReport)
async def get_daily_usage_admin(
    start_date: Optional[datetime] = Query(None, description="Start date for report"),
    end_date: Optional[datetime] = Query(None, description="End date for report"),
    user_ids: Optional[List[str]] = Query(None, description="Filter to specific users"),
    current_user: UserResponse = Depends(require_admin_tier),
) -> DailyUsageReport:
    """
    Get daily usage report for business intelligence (admin only).

    Provides comprehensive analytics including:
    - Active Pro user counts
    - LLM usage and costs
    - Threat detection metrics
    - Performance indicators
    """
    try:
        # Default to last 30 days if no dates provided
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=30)
        if not end_date:
            end_date = datetime.utcnow()

        # Validate date range
        if (end_date - start_date).days > 365:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Date range cannot exceed 365 days",
            )

        report = await analytics_service.get_daily_usage_report(
            start_date=start_date, end_date=end_date, user_ids=user_ids
        )

        logger.info(f"Generated daily usage report for admin {current_user.id}")
        return report

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Failed to generate daily usage report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate usage report",
        )


@router.get("/admin/churn-risk/{user_id}", response_model=ChurnRiskMetrics)
async def get_user_churn_risk_admin(
    user_id: str, current_user: UserResponse = Depends(require_admin_tier)
) -> ChurnRiskMetrics:
    """
    Get churn risk assessment for specific user (admin only).

    Provides comprehensive churn prediction including:
    - Risk score (0-100)
    - Usage patterns
    - Engagement metrics
    - Retention recommendations
    """
    try:
        metrics = await analytics_service.get_user_churn_risk(user_id)

        logger.info(
            f"Generated churn risk assessment for user {user_id} by admin {current_user.id}"
        )
        return metrics

    except Exception as e:
        logger.exception(f"Failed to calculate churn risk for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to calculate churn risk",
        )


@router.get("/admin/threat-trends", response_model=List[ThreatTrendAnalysis])
async def get_threat_trends_admin(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    threat_types: Optional[List[str]] = Query(
        None, description="Filter to specific threat types"
    ),
    min_confidence: float = Query(
        0.0, ge=0.0, le=1.0, description="Minimum confidence threshold"
    ),
    current_user: UserResponse = Depends(require_admin_tier),
) -> List[ThreatTrendAnalysis]:
    """
    Get threat discovery trends for security intelligence (admin only).

    Analyzes patterns in threat discoveries including:
    - Discovery velocity
    - Threat type distributions
    - Zero-day discovery rates
    - Confidence trends
    """
    try:
        # Default to last 90 days
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=90)
        if not end_date:
            end_date = datetime.utcnow()

        # This is a placeholder - would need to implement in analytics_service
        # For now, return empty list
        return []

    except Exception as e:
        logger.exception(f"Failed to generate threat trends: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate threat trends",
        )


# -------------------------------------------------------------------------
# User Analytics Endpoints (Pro Users)
# -------------------------------------------------------------------------


@router.get("/my/usage", response_model=UserUsageStats)
async def get_my_usage_stats(
    days: int = Query(
        30, ge=1, le=365, description="Number of days to include in stats"
    ),
    current_user: UserResponse = Depends(require_pro_tier),
) -> UserUsageStats:
    """
    Get personal usage statistics for current Pro user.

    Provides detailed usage analytics including:
    - Scan counts and token usage
    - Cost tracking
    - Threat discoveries
    - Daily usage breakdown
    - Top threat categories found
    """
    try:
        stats = await analytics_service.get_user_usage_stats(
            user_id=current_user.id, days=days
        )

        logger.info(f"Generated usage stats for user {current_user.id}")
        return stats

    except Exception as e:
        logger.exception(f"Failed to get usage stats for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve usage statistics",
        )


@router.get("/my/churn-risk", response_model=ChurnRiskMetrics)
async def get_my_churn_risk(
    current_user: UserResponse = Depends(require_pro_tier),
) -> ChurnRiskMetrics:
    """
    Get churn risk assessment for current user.

    Provides engagement insights including:
    - Usage frequency analysis
    - Feature adoption score
    - Engagement recommendations
    """
    try:
        metrics = await analytics_service.get_user_churn_risk(current_user.id)

        # Remove sensitive risk categorization for user-facing endpoint
        user_metrics = ChurnRiskMetrics(
            user_id=metrics.user_id,
            risk_score=min(metrics.risk_score, 50),  # Cap at 50 for user display
            risk_category="ENGAGEMENT_METRICS"
            if metrics.risk_category != "HEALTHY"
            else "HEALTHY",
            last_scan_date=metrics.last_scan_date,
            monthly_scans=metrics.monthly_scans,
            threat_hit_rate=metrics.threat_hit_rate,
            avg_session_duration=metrics.avg_session_duration,
            feature_adoption_score=metrics.feature_adoption_score,
        )

        logger.info(f"Generated engagement metrics for user {current_user.id}")
        return user_metrics

    except Exception as e:
        logger.exception(
            f"Failed to calculate engagement metrics for user {current_user.id}: {e}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to calculate engagement metrics",
        )


# -------------------------------------------------------------------------
# Analytics Tracking Endpoints (Internal Use)
# -------------------------------------------------------------------------


@router.post("/track/session-duration")
async def track_session_duration(
    duration_minutes: int = Query(..., description="Session duration in minutes"),
    features_used: List[str] = Query(
        ..., description="Features accessed during session"
    ),
    current_user: UserResponse = Depends(get_current_user_unified),
) -> dict[str, str]:
    """
    Track user session duration and feature usage for engagement analytics.
    Called by frontend to track user engagement patterns.
    """
    try:
        # Track session event
        await analytics_service.track_event(
            user_id=current_user.id,
            event_type="session_completed",
            event_data={
                "duration_minutes": duration_minutes,
                "features_used": features_used,
                "session_end": datetime.utcnow().isoformat(),
            },
        )

        # Update daily engagement metrics
        await analytics_service._update_daily_engagement(
            user_id=current_user.id,
            metrics={"session_duration_minutes": duration_minutes},
        )

        return {"status": "success", "message": "Session tracked"}

    except Exception as e:
        logger.exception(f"Failed to track session for user {current_user.id}: {e}")
        # Don't raise error - this is non-critical tracking
        return {"status": "error", "message": "Failed to track session"}


@router.post("/track/upgrade-prompt")
async def track_upgrade_prompt(
    action: str = Query(
        ..., description="Action taken: 'shown', 'clicked', 'dismissed'"
    ),
    prompt_type: str = Query(..., description="Type of prompt shown"),
    current_user: UserResponse = Depends(get_current_user_unified),
) -> dict[str, str]:
    """
    Track upgrade prompt interactions for conversion analysis.
    Called when upgrade prompts are shown to free users.
    """
    try:
        # Only track for free users
        user_tier = await get_user_tier(current_user)
        if user_tier != PlanTier.FREE:
            return {"status": "ignored", "message": "Not applicable for non-free users"}

        await analytics_service.track_event(
            user_id=current_user.id,
            event_type="upgrade_prompt",
            event_data={
                "action": action,
                "prompt_type": prompt_type,
                "timestamp": datetime.utcnow().isoformat(),
            },
            tier=user_tier.value,
        )

        return {"status": "success", "message": "Upgrade prompt tracked"}

    except Exception as e:
        logger.exception(
            f"Failed to track upgrade prompt for user {current_user.id}: {e}"
        )
        return {"status": "error", "message": "Failed to track upgrade prompt"}


# -------------------------------------------------------------------------
# Health and Status Endpoints
# -------------------------------------------------------------------------


@router.get("/health")
async def analytics_health() -> dict[str, str]:
    """Check analytics service health."""
    try:
        # Test database connection
        await analytics_service.track_event(
            user_id="health_check",
            event_type="health_check",
            event_data={"timestamp": datetime.utcnow().isoformat()},
        )

        return {
            "status": "healthy",
            "service": "analytics",
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.exception("Analytics health check failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Analytics service unhealthy: {str(e)}",
        )
