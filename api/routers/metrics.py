"""
Metrics API Router

Provides endpoints for accessing scanner performance metrics,
false positive rates, and migration progress tracking.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from typing_extensions import Annotated

from fastapi import APIRouter, Depends, Query, status

from api.rate_limit import RateLimiter
from api.routers.auth import get_current_user_unified, UserResponse
from api.services.scanner_metrics import scanner_metrics
from api.models import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.get(
    "/scanner",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get scanner performance metrics and comparison",
    responses={
        401: {"model": ErrorResponse},
        429: {"description": "Rate limit exceeded"},
    },
    dependencies=[
        Depends(RateLimiter(max_requests=30, window=300))
    ],  # 30 requests per 5 minutes
)
async def get_scanner_metrics(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    days: int = Query(
        30, ge=1, le=90, description="Number of days to include in analysis"
    ),
    include_details: bool = Query(True, description="Include detailed breakdown"),
) -> Dict[str, Any]:
    """
    Get comprehensive scanner performance metrics.

    Returns metrics comparing Scanner v1 vs v2 performance including:
    - False positive rates per version
    - Average risk scores and improvements
    - Migration progress and completion percentage
    - Confidence level distributions
    - Rescan activity and effectiveness

    Part of the Scanner v2 migration monitoring system.
    """
    try:
        logger.info(
            "Collecting scanner metrics for %d days (user: %s)", days, current_user.id
        )

        # Get comprehensive scanner statistics
        stats = await scanner_metrics.get_scanner_statistics(days_back=days)

        if not include_details:
            # Return only summary information
            summary = stats.get("summary", {})
            migration_progress = stats.get("migration_progress", {})
            improvements = stats.get("improvements", {})

            return {
                "period_days": days,
                "migration_percentage": migration_progress.get(
                    "migration_percentage", 0
                ),
                "false_positive_improvement": improvements.get(
                    "false_positive_reduction_percentage", 0
                ),
                "score_improvement": improvements.get("score_reduction_percentage", 0),
                "status": summary.get("status", "unknown"),
                "summary_message": summary.get("message", "No summary available"),
            }

        # Return full detailed metrics
        return stats

    except Exception as e:
        logger.exception(
            "Failed to get scanner metrics for user %s: %s", current_user.id, e
        )
        return {
            "error": str(e),
            "period_days": days,
            "migration_percentage": 0,
            "false_positive_improvement": 0,
            "score_improvement": 0,
            "status": "error",
            "summary_message": f"Failed to collect metrics: {str(e)}",
        }


@router.get(
    "/scanner/migration",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get Scanner v2 migration progress",
    responses={
        401: {"model": ErrorResponse},
        429: {"description": "Rate limit exceeded"},
    },
    dependencies=[
        Depends(RateLimiter(max_requests=60, window=300))
    ],  # Higher limit for dashboard polling
)
async def get_migration_progress(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> Dict[str, Any]:
    """
    Get current Scanner v2 migration progress.

    Lightweight endpoint optimized for dashboard polling.
    Returns migration percentage and recent activity.
    """
    try:
        # Get recent migration statistics (last 7 days)
        stats = await scanner_metrics.get_scanner_statistics(days_back=7)

        migration_progress = stats.get("migration_progress", {})
        rescan_stats = stats.get("rescan_statistics", {})
        improvements = stats.get("improvements", {})

        return {
            "migration": {
                "percentage": migration_progress.get("migration_percentage", 0),
                "v1_scans": migration_progress.get("v1_scans", 0),
                "v2_scans": migration_progress.get("v2_scans", 0),
                "total_scans": migration_progress.get("total_scans", 0),
            },
            "recent_activity": {
                "rescanned_last_24h": rescan_stats.get("recent_activity", {}).get(
                    "rescanned_last_24h", 0
                ),
                "rescanned_last_7_days": rescan_stats.get("recent_activity", {}).get(
                    "rescanned_last_7_days", 0
                ),
            },
            "improvements": {
                "false_positive_reduction": improvements.get(
                    "false_positive_reduction_percentage", 0
                ),
                "score_reduction": improvements.get("score_reduction_percentage", 0),
                "status": improvements.get("available", False),
            },
            "timestamp": stats.get("period", {}).get("end_date"),
        }

    except Exception as e:
        logger.exception(
            "Failed to get migration progress for user %s: %s", current_user.id, e
        )
        return {
            "migration": {
                "percentage": 0,
                "v1_scans": 0,
                "v2_scans": 0,
                "total_scans": 0,
            },
            "recent_activity": {"rescanned_last_24h": 0, "rescanned_last_7_days": 0},
            "improvements": {
                "false_positive_reduction": 0,
                "score_reduction": 0,
                "status": False,
            },
            "error": str(e),
        }


@router.get(
    "/scanner/false-positives",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get false positive analysis",
    responses={
        401: {"model": ErrorResponse},
        429: {"description": "Rate limit exceeded"},
    },
    dependencies=[Depends(RateLimiter(max_requests=20, window=300))],
)
async def get_false_positive_analysis(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    days: int = Query(30, ge=1, le=90, description="Number of days to analyze"),
) -> Dict[str, Any]:
    """
    Get detailed false positive analysis comparing v1 vs v2.

    Returns confidence distributions, false positive estimates,
    and patterns that help validate v2 improvements.
    """
    try:
        stats = await scanner_metrics.get_scanner_statistics(days_back=days)

        fp_analysis = stats.get("false_positive_analysis", {})
        version_comparison = stats.get("version_comparison", {})
        improvements = stats.get("improvements", {})

        # Extract false positive rates
        v1_fp_rate = None
        v2_fp_rate = None

        if version_comparison.get("v1"):
            v1_fp_rate = version_comparison["v1"].get("false_positive_rate")
        if version_comparison.get("v2"):
            v2_fp_rate = version_comparison["v2"].get("false_positive_rate")

        return {
            "period_days": days,
            "false_positive_rates": {
                "v1_estimated": v1_fp_rate,
                "v2_estimated": v2_fp_rate,
                "improvement": improvements.get("false_positive_reduction_percentage"),
            },
            "confidence_analysis": {
                "total_low_confidence": fp_analysis.get("low_confidence_findings", 0),
                "total_high_confidence": fp_analysis.get("high_confidence_findings", 0),
                "likely_false_positives": fp_analysis.get("likely_false_positives", 0),
                "distribution": fp_analysis.get("confidence_distribution", {}),
            },
            "version_breakdown": {
                "v1_verdicts": version_comparison.get("v1", {}).get(
                    "verdict_distribution", {}
                ),
                "v2_verdicts": version_comparison.get("v2", {}).get(
                    "verdict_distribution", {}
                ),
            },
            "validation": {
                "target_fp_rate": 5.0,  # Target <5% false positive rate
                "baseline_fp_rate": 36.0,  # Original v1 baseline
                "current_v2_rate": v2_fp_rate,
                "target_achieved": v2_fp_rate is not None and v2_fp_rate < 5.0,
            },
        }

    except Exception as e:
        logger.exception(
            "Failed to get false positive analysis for user %s: %s", current_user.id, e
        )
        return {
            "period_days": days,
            "false_positive_rates": {
                "v1_estimated": None,
                "v2_estimated": None,
                "improvement": None,
            },
            "confidence_analysis": {
                "total_low_confidence": 0,
                "total_high_confidence": 0,
            },
            "version_breakdown": {"v1_verdicts": {}, "v2_verdicts": {}},
            "validation": {"target_achieved": False},
            "error": str(e),
        }
