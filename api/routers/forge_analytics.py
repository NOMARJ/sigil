"""
Forge Analytics API Router

Provides plan-gated analytics endpoints for personal, team, and organization-level insights.
Supports real-time event tracking and cached analytics dashboards.
"""

from __future__ import annotations

import logging
from typing import Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request

from api.gates import require_plan, get_user_plan
from api.models import (
    PlanTier,
    ForgeEventType,
    PersonalAnalyticsRequest,
    PersonalAnalyticsResponse,
    TeamAnalyticsResponse,
    OrganizationAnalyticsResponse,
    AnalyticsEventCreateRequest,
    AnalyticsEventBatchRequest,
)
from routers.auth import get_current_user_unified, UserResponse
from services.forge_analytics import analytics_service, track_forge_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/forge/analytics", tags=["Forge Analytics"])


# ============================================================================
# Event Tracking Endpoints
# ============================================================================


@router.post("/events")
async def track_event(
    request: AnalyticsEventCreateRequest,
    http_request: Request,
    current_user: UserResponse = Depends(get_current_user_unified),
):
    """Track a single analytics event."""

    # Extract request metadata
    session_id = request.session_id
    ip_address = http_request.client.host if http_request.client else None
    user_agent = http_request.headers.get("user-agent")

    success = await track_forge_event(
        user_id=current_user.id,
        event_type=request.event_type,
        event_data=request.event_data,
        session_id=session_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    if not success:
        raise HTTPException(status_code=500, detail="Failed to track event")

    return {"success": True, "event_type": request.event_type.value}


@router.post("/events/batch")
async def track_events_batch(
    request: AnalyticsEventBatchRequest,
    http_request: Request,
    current_user: UserResponse = Depends(get_current_user_unified),
):
    """Track multiple analytics events in batch."""

    if len(request.events) > 100:
        raise HTTPException(
            status_code=400, detail="Maximum 100 events per batch request"
        )

    # Extract request metadata
    ip_address = http_request.client.host if http_request.client else None
    user_agent = http_request.headers.get("user-agent")

    # Convert to batch format
    events_data = [(event.event_type, event.event_data) for event in request.events]

    session_id = request.events[0].session_id if request.events else None

    success_count = await analytics_service.track_events_batch(
        user_id=current_user.id,
        events=events_data,
        session_id=session_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return {
        "success": True,
        "events_tracked": success_count,
        "total_requested": len(request.events),
    }


# ============================================================================
# Personal Analytics (Pro+ Plan)
# ============================================================================


@router.get("/personal", response_model=PersonalAnalyticsResponse)
async def get_personal_analytics(
    days_back: int = 30,
    categories: Optional[str] = None,
    ecosystems: Optional[str] = None,
    current_user: UserResponse = Depends(get_current_user_unified),
    _: None = Depends(require_plan(PlanTier.PRO)),
):
    """Get personal analytics for Pro+ users."""

    # Validate parameters
    if days_back < 1 or days_back > 365:
        raise HTTPException(
            status_code=400, detail="days_back must be between 1 and 365"
        )

    # Parse filters
    categories_list = categories.split(",") if categories else None
    ecosystems_list = ecosystems.split(",") if ecosystems else None

    try:
        analytics = await analytics_service.get_personal_analytics(
            user_id=current_user.id,
            days_back=days_back,
            categories=categories_list,
            ecosystems=ecosystems_list,
        )

        return analytics

    except Exception as e:
        logger.error(f"Personal analytics failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Analytics temporarily unavailable")


@router.post("/personal/export")
async def export_personal_analytics(
    request: PersonalAnalyticsRequest,
    current_user: UserResponse = Depends(get_current_user_unified),
    _: None = Depends(require_plan(PlanTier.PRO)),
):
    """Export personal analytics data."""

    # Track export event
    await track_forge_event(
        user_id=current_user.id,
        event_type=ForgeEventType.EXPORT_PERFORMED,
        event_data={
            "export_type": "personal_analytics",
            "days_back": request.days_back,
        },
    )

    analytics = await analytics_service.get_personal_analytics(
        user_id=current_user.id,
        days_back=request.days_back,
        categories=request.categories,
        ecosystems=request.ecosystems,
    )

    return {
        "export_data": analytics.model_dump(),
        "exported_at": datetime.utcnow().isoformat(),
        "format": "json",
    }


# ============================================================================
# Team Analytics (Team+ Plan)
# ============================================================================


@router.get("/team", response_model=TeamAnalyticsResponse)
async def get_team_analytics(
    days_back: int = 30,
    current_user: UserResponse = Depends(get_current_user_unified),
    _: None = Depends(require_plan(PlanTier.TEAM)),
):
    """Get team analytics for Team+ users."""

    # Verify user has team access
    if not current_user.team_id:
        raise HTTPException(status_code=400, detail="User is not part of a team")

    # Validate parameters
    if days_back < 1 or days_back > 365:
        raise HTTPException(
            status_code=400, detail="days_back must be between 1 and 365"
        )

    try:
        analytics = await analytics_service.get_team_analytics(
            team_id=current_user.team_id, days_back=days_back
        )

        # Track analytics view
        await track_forge_event(
            user_id=current_user.id,
            event_type=ForgeEventType.ANALYTICS_VIEWED,
            event_data={"analytics_type": "team", "team_id": current_user.team_id},
        )

        return analytics

    except Exception as e:
        logger.error(f"Team analytics failed for team {current_user.team_id}: {e}")
        raise HTTPException(status_code=500, detail="Analytics temporarily unavailable")


@router.get("/team/{team_id}/members")
async def get_team_member_analytics(
    team_id: str,
    days_back: int = 30,
    current_user: UserResponse = Depends(get_current_user_unified),
    _: None = Depends(require_plan(PlanTier.TEAM)),
):
    """Get individual team member analytics breakdown."""

    # Verify user has access to this team
    if current_user.team_id != team_id:
        raise HTTPException(
            status_code=403, detail="Access denied to this team's analytics"
        )

    # This would get detailed member-level analytics
    # Implementation depends on privacy requirements
    return {
        "team_id": team_id,
        "member_summary": "Individual analytics require additional permissions",
        "total_members": 0,  # Placeholder
    }


# ============================================================================
# Organization Analytics (Enterprise Plan)
# ============================================================================


@router.get("/organization", response_model=OrganizationAnalyticsResponse)
async def get_organization_analytics(
    current_user: UserResponse = Depends(get_current_user_unified),
    _: None = Depends(require_plan(PlanTier.ENTERPRISE)),
):
    """Get organization analytics for Enterprise users."""

    # Get user's organization ID (this would come from user/team data)
    organization_id = (
        current_user.organization_id
        if hasattr(current_user, "organization_id")
        else None
    )

    if not organization_id:
        raise HTTPException(
            status_code=400, detail="User is not part of an organization"
        )

    try:
        analytics = await analytics_service.get_organization_analytics(
            organization_id=organization_id
        )

        # Track analytics view
        await track_forge_event(
            user_id=current_user.id,
            event_type=ForgeEventType.ANALYTICS_VIEWED,
            event_data={
                "analytics_type": "organization",
                "organization_id": organization_id,
            },
        )

        return analytics

    except Exception as e:
        logger.error(f"Organization analytics failed for org {organization_id}: {e}")
        raise HTTPException(status_code=500, detail="Analytics temporarily unavailable")


@router.get("/organization/departments")
async def get_department_breakdown(
    current_user: UserResponse = Depends(get_current_user_unified),
    _: None = Depends(require_plan(PlanTier.ENTERPRISE)),
):
    """Get detailed department-level analytics breakdown."""

    organization_id = getattr(current_user, "organization_id", None)

    if not organization_id:
        raise HTTPException(
            status_code=400, detail="User is not part of an organization"
        )

    # This would return detailed department analytics
    return {
        "departments": [],
        "total_departments": 0,
        "implementation_note": "Department analytics require organizational structure setup",
    }


# ============================================================================
# Real-time Analytics Endpoints
# ============================================================================


@router.get("/realtime/dashboard")
async def get_realtime_dashboard(
    current_user: UserResponse = Depends(get_current_user_unified),
):
    """Get real-time dashboard data (available to all plans)."""

    user_plan = await get_user_plan(current_user.id)

    # Basic dashboard data for all users
    dashboard_data = {
        "user_id": current_user.id,
        "plan": user_plan.value,
        "last_updated": datetime.utcnow().isoformat(),
        "features_available": {
            "personal_analytics": user_plan
            in [PlanTier.PRO, PlanTier.TEAM, PlanTier.ENTERPRISE],
            "team_analytics": user_plan in [PlanTier.TEAM, PlanTier.ENTERPRISE],
            "organization_analytics": user_plan == PlanTier.ENTERPRISE,
            "real_time_updates": True,
            "export_data": user_plan != PlanTier.FREE,
        },
    }

    # Track dashboard access
    await track_forge_event(
        user_id=current_user.id,
        event_type=ForgeEventType.DASHBOARD_ACCESSED,
        event_data={
            "plan": user_plan.value,
            "timestamp": datetime.utcnow().isoformat(),
        },
    )

    return dashboard_data


@router.post("/realtime/invalidate")
async def invalidate_analytics_cache(
    current_user: UserResponse = Depends(get_current_user_unified),
    _: None = Depends(require_plan(PlanTier.PRO)),
):
    """Manually invalidate analytics cache for fresh data."""

    try:
        await analytics_service.invalidate_user_cache(current_user.id)

        if current_user.team_id:
            await analytics_service.invalidate_team_cache(current_user.team_id)

        return {"success": True, "message": "Analytics cache invalidated"}

    except Exception as e:
        logger.error(f"Cache invalidation failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to invalidate cache")


# ============================================================================
# Analytics Configuration
# ============================================================================


@router.get("/config")
async def get_analytics_config(
    current_user: UserResponse = Depends(get_current_user_unified),
):
    """Get analytics configuration and feature availability."""

    user_plan = await get_user_plan(current_user.id)

    config = {
        "user_id": current_user.id,
        "current_plan": user_plan.value,
        "features": {
            "event_tracking": True,  # Available to all
            "basic_analytics": True,  # Available to all
            "personal_analytics": user_plan
            in [PlanTier.PRO, PlanTier.TEAM, PlanTier.ENTERPRISE],
            "team_analytics": user_plan in [PlanTier.TEAM, PlanTier.ENTERPRISE],
            "organization_analytics": user_plan == PlanTier.ENTERPRISE,
            "export_capabilities": user_plan != PlanTier.FREE,
            "real_time_updates": True,
            "cache_invalidation": user_plan != PlanTier.FREE,
        },
        "limits": {
            "events_per_batch": 100,
            "max_days_back": 365 if user_plan != PlanTier.FREE else 30,
            "cache_ttl_seconds": 300,
        },
        "upgrade_info": {
            "current_tier": user_plan.value,
            "next_tier": _get_next_tier(user_plan),
            "upgrade_url": "https://app.sigilsec.ai/upgrade",
        }
        if user_plan != PlanTier.ENTERPRISE
        else None,
    }

    return config


def _get_next_tier(current_tier: PlanTier) -> str:
    """Get the next available tier for upgrade suggestions."""
    if current_tier == PlanTier.FREE:
        return PlanTier.PRO.value
    elif current_tier == PlanTier.PRO:
        return PlanTier.TEAM.value
    elif current_tier == PlanTier.TEAM:
        return PlanTier.ENTERPRISE.value
    else:
        return "enterprise"  # Already at top tier
