"""
Analytics API Endpoints for Sigil Pro Usage Tracking

Provides endpoints for analytics reporting, usage metrics, and business intelligence
for Pro tier features including LLM analysis tracking and churn prediction.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from typing_extensions import Annotated

from api.middleware.tier_check import require_pro_tier, get_user_tier
from api.models import PlanTier
from api.usage_metrics import (
    DailyUsageReport,
    ChurnRiskMetrics,
    UserUsageStats,
    ThreatTrendAnalysis,
)
from api.routers.auth import get_current_user_unified, UserResponse
from api.services.analytics_service import analytics_service


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
# Revenue Analytics Endpoints (Team+ Users)
# -------------------------------------------------------------------------


@router.get("/revenue/mrr")
async def get_mrr_metrics(
    current_user: UserResponse = Depends(require_admin_tier),
    months_back: int = Query(
        default=12, ge=1, le=24, description="Months of historical data"
    ),
) -> Dict[str, Any]:
    """
    Get Monthly Recurring Revenue metrics and trends.

    Requires admin/enterprise access.
    """
    try:
        from api.analytics.revenue_metrics import revenue_analytics

        mrr_data = await revenue_analytics.get_mrr_data(months_back)

        return {
            "current_mrr": float(mrr_data.current_mrr),
            "growth_rate": mrr_data.mrr_growth_rate,
            "mrr_by_plan": {k: float(v) for k, v in mrr_data.mrr_by_plan.items()},
            "trend_12m": mrr_data.mrr_trend_12m,
        }

    except Exception as e:
        logger.exception(f"Failed to get MRR metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve MRR metrics",
        )


@router.get("/revenue/conversions")
async def get_conversion_metrics(
    current_user: UserResponse = Depends(require_admin_tier),
) -> Dict[str, Any]:
    """
    Get user conversion funnel metrics.

    Requires admin/enterprise access.
    """
    try:
        from api.analytics.revenue_metrics import revenue_analytics

        conversion_data = await revenue_analytics.get_conversion_metrics()

        return {
            "total_signups": conversion_data.total_signups,
            "free_to_pro_rate": conversion_data.free_to_pro_conversion_rate,
            "pro_to_team_rate": conversion_data.pro_to_team_conversion_rate,
            "avg_time_to_convert": conversion_data.time_to_conversion_avg_days,
            "conversion_by_cohort": conversion_data.conversion_by_cohort,
        }

    except Exception as e:
        logger.exception(f"Failed to get conversion metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve conversion metrics",
        )


@router.get("/revenue/churn")
async def get_churn_metrics(
    current_user: UserResponse = Depends(require_admin_tier),
) -> Dict[str, Any]:
    """
    Get customer churn analysis.

    Requires admin/enterprise access.
    """
    try:
        from api.analytics.revenue_metrics import revenue_analytics

        churn_data = await revenue_analytics.get_churn_analysis()

        return {
            "monthly_churn_rate": churn_data.monthly_churn_rate,
            "churn_by_plan": churn_data.churn_by_plan,
            "churn_by_tenure": churn_data.churn_by_tenure,
            "churn_reasons": churn_data.churn_reasons,
            "at_risk_customers_count": len(churn_data.at_risk_customers),
            "at_risk_customers": churn_data.at_risk_customers[:10],  # Top 10 only
        }

    except Exception as e:
        logger.exception(f"Failed to get churn metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve churn metrics",
        )


@router.get("/revenue/credits")
async def get_credit_analytics(
    current_user: UserResponse = Depends(require_admin_tier),
) -> Dict[str, Any]:
    """
    Get credit usage and monetization analytics.

    Requires admin/enterprise access.
    """
    try:
        from api.analytics.revenue_metrics import revenue_analytics

        credit_data = await revenue_analytics.get_credit_analytics()

        return {
            "consumption_trend": credit_data.credits_consumed_trend,
            "purchase_revenue": float(credit_data.credit_purchase_revenue),
            "avg_credits_per_user": credit_data.avg_credits_per_user,
            "monetization_rate": credit_data.credit_monetization_rate,
            "top_credit_features": credit_data.top_credit_features,
        }

    except Exception as e:
        logger.exception(f"Failed to get credit analytics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve credit analytics",
        )


@router.get("/revenue/dashboard")
async def get_revenue_dashboard(
    current_user: UserResponse = Depends(require_admin_tier),
) -> Dict[str, Any]:
    """
    Get comprehensive revenue dashboard summary.

    Requires admin/enterprise access.
    """
    try:
        from api.analytics.revenue_metrics import revenue_analytics
        from api.monitoring.billing_metrics import billing_monitor

        # Get revenue and billing data
        revenue_data = await revenue_analytics.get_revenue_dashboard_summary()
        billing_data = await billing_monitor.get_billing_dashboard_data()

        return {
            "revenue_metrics": revenue_data,
            "billing_health": billing_data,
            "summary_kpis": {
                "mrr": revenue_data["mrr"]["current"],
                "mrr_growth": revenue_data["mrr"]["growth_rate"],
                "churn_rate": revenue_data["churn"]["monthly_rate"],
                "conversion_rate": revenue_data["conversions"]["free_to_pro_rate"],
                "ltv_cac_ratio": revenue_data["ltv"]["ltv_to_cac_ratio"],
                "payment_success_rate": billing_data["payments"]["success_rate"],
                "active_subscriptions": billing_data["subscriptions"]["total_active"],
            },
            "generated_at": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.exception(f"Failed to get revenue dashboard: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve revenue dashboard",
        )


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
