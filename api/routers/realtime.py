"""
Real-time WebSocket Router

Handles WebSocket connections for real-time dashboard updates, notifications,
and analytics streaming for Forge premium features.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import List

from fastapi import (
    APIRouter,
    WebSocket,
    WebSocketDisconnect,
    Depends,
    HTTPException,
    Query,
)
from pydantic import BaseModel

from api.gates import get_user_plan, require_plan
from api.models import PlanTier
from api.routers.auth import get_current_user_unified, UserResponse
from api.services.realtime_dashboard import (
    dashboard_service,
    send_security_notification,
)
from api.services.forge_analytics import track_forge_event, ForgeEventType

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/realtime", tags=["Real-time Updates"])


class WebSocketSubscription(BaseModel):
    """WebSocket subscription configuration."""

    analytics: bool = True
    dashboard_stats: bool = True
    notifications: bool = True
    security_alerts: bool = True
    team_updates: bool = False  # Team+ only
    organization_updates: bool = False  # Enterprise only


class NotificationRequest(BaseModel):
    """Request to send a notification."""

    message: str
    type: str = "info"  # info, warning, error, success
    severity: str = "medium"  # low, medium, high, critical


# ============================================================================
# WebSocket Endpoints
# ============================================================================


@router.websocket("/dashboard/{user_id}")
async def websocket_dashboard(
    websocket: WebSocket,
    user_id: str,
    subscriptions: str = Query("analytics,dashboard_stats,notifications"),
):
    """WebSocket endpoint for real-time dashboard updates."""

    # Parse subscription preferences
    subscription_list = [s.strip() for s in subscriptions.split(",")]

    logger.info(
        f"WebSocket connection attempt: user={user_id}, subs={subscription_list}"
    )

    try:
        # Connect and handle the WebSocket session
        await dashboard_service.connect_websocket(
            websocket=websocket, user_id=user_id, subscriptions=subscription_list
        )

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: user={user_id}")
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {e}")


# ============================================================================
# Real-time Trigger Endpoints (HTTP)
# ============================================================================


@router.post("/trigger/dashboard-refresh")
async def trigger_dashboard_refresh(
    current_user: UserResponse = Depends(get_current_user_unified),
):
    """Manually trigger dashboard refresh for current user."""

    try:
        await dashboard_service.invalidate_user_dashboard(current_user.id)

        # Track analytics event
        await track_forge_event(
            user_id=current_user.id,
            event_type=ForgeEventType.DASHBOARD_ACCESSED,
            event_data={"trigger": "manual_refresh"},
        )

        return {"success": True, "message": "Dashboard refresh triggered"}

    except Exception as e:
        logger.error(f"Dashboard refresh failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to refresh dashboard")


@router.post("/trigger/team-refresh")
async def trigger_team_refresh(
    current_user: UserResponse = Depends(get_current_user_unified),
    _: None = Depends(require_plan(PlanTier.TEAM)),
):
    """Manually trigger team dashboard refresh."""

    if not current_user.team_id:
        raise HTTPException(status_code=400, detail="User is not part of a team")

    try:
        await dashboard_service.invalidate_team_dashboard(current_user.team_id)

        return {"success": True, "message": "Team dashboard refresh triggered"}

    except Exception as e:
        logger.error(f"Team refresh failed for team {current_user.team_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to refresh team dashboard")


@router.post("/notifications/send")
async def send_notification(
    request: NotificationRequest,
    target_user_id: str = Query(..., description="Target user ID"),
    current_user: UserResponse = Depends(get_current_user_unified),
):
    """Send real-time notification to a user (admin/team lead only)."""

    # Basic permission check - only allow sending to self or team members
    if target_user_id != current_user.id:
        # Check if target user is in same team
        if not current_user.team_id:
            raise HTTPException(status_code=403, detail="Permission denied")

        # Get target user info
        from database import db

        target_user = await db.select_one("users", {"id": target_user_id})
        if not target_user or target_user.get("team_id") != current_user.team_id:
            raise HTTPException(status_code=403, detail="Permission denied")

    try:
        await send_security_notification(
            user_id=target_user_id, message=request.message, severity=request.severity
        )

        return {"success": True, "message": "Notification sent"}

    except Exception as e:
        logger.error(f"Failed to send notification: {e}")
        raise HTTPException(status_code=500, detail="Failed to send notification")


# ============================================================================
# Real-time Analytics Streaming
# ============================================================================


@router.get("/analytics/stream")
async def get_analytics_stream_info(
    current_user: UserResponse = Depends(get_current_user_unified),
):
    """Get information about available real-time analytics streams."""

    user_plan = await get_user_plan(current_user.id)

    available_streams = {
        "personal_analytics": user_plan
        in [PlanTier.PRO, PlanTier.TEAM, PlanTier.ENTERPRISE],
        "team_analytics": user_plan in [PlanTier.TEAM, PlanTier.ENTERPRISE],
        "organization_analytics": user_plan == PlanTier.ENTERPRISE,
        "security_alerts": True,
        "scan_results": True,
        "tool_updates": True,
    }

    stream_endpoints = {
        "websocket_url": f"/realtime/dashboard/{current_user.id}",
        "supported_subscriptions": [
            "analytics",
            "dashboard_stats",
            "notifications",
            "security_alerts",
        ],
    }

    if available_streams["team_analytics"]:
        stream_endpoints["supported_subscriptions"].append("team_updates")

    if available_streams["organization_analytics"]:
        stream_endpoints["supported_subscriptions"].append("organization_updates")

    return {
        "user_id": current_user.id,
        "plan": user_plan.value,
        "available_streams": available_streams,
        "stream_endpoints": stream_endpoints,
        "connection_info": {
            "protocol": "websocket",
            "heartbeat_interval": 30,
            "max_reconnect_attempts": 5,
        },
    }


# ============================================================================
# Cache Management
# ============================================================================


@router.post("/cache/invalidate")
async def invalidate_caches(
    cache_types: List[str] = Query(..., description="Cache types to invalidate"),
    current_user: UserResponse = Depends(get_current_user_unified),
):
    """Invalidate specific cache types for current user."""

    valid_cache_types = ["analytics", "dashboard", "team", "personal"]
    invalid_types = [t for t in cache_types if t not in valid_cache_types]

    if invalid_types:
        raise HTTPException(
            status_code=400, detail=f"Invalid cache types: {invalid_types}"
        )

    try:
        results = {}

        if "analytics" in cache_types or "personal" in cache_types:
            from api.services.forge_analytics import analytics_service

            await analytics_service.invalidate_user_cache(current_user.id)
            results["personal_analytics"] = "invalidated"

        if "dashboard" in cache_types:
            await dashboard_service.invalidate_user_dashboard(current_user.id)
            results["dashboard"] = "invalidated"

        if "team" in cache_types and current_user.team_id:
            await dashboard_service.invalidate_team_dashboard(current_user.team_id)
            results["team"] = "invalidated"

        return {"success": True, "invalidated": results, "user_id": current_user.id}

    except Exception as e:
        logger.error(f"Cache invalidation failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to invalidate caches")


# ============================================================================
# System Health and Status
# ============================================================================


@router.get("/status")
async def get_realtime_status():
    """Get real-time system status (public endpoint)."""

    try:
        # Check Redis connection
        redis_status = "connected" if dashboard_service.redis else "disconnected"

        # Count active connections
        active_connections = len(dashboard_service.active_connections)

        # Get basic system info
        status_info = {
            "status": "operational",
            "redis_status": redis_status,
            "active_websocket_connections": active_connections,
            "features_enabled": {
                "real_time_updates": redis_status == "connected",
                "websocket_support": True,
                "cache_invalidation": True,
                "push_notifications": redis_status == "connected",
            },
            "timestamp": datetime.utcnow().isoformat(),
        }

        return status_info

    except Exception as e:
        logger.error(f"Status check failed: {e}")
        return {
            "status": "degraded",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }
