"""
System Router

Provides root-level system endpoints that clients expect to find at the API root.
These are convenience endpoints that either redirect to more specific endpoints
or provide simplified versions of existing functionality.
"""

from __future__ import annotations

from fastapi import APIRouter

from api.services.realtime_dashboard import dashboard_service
# from api.routers.forge import get_classified_skills  # Forge archived

# Stub for get_classified_skills to prevent errors during Forge sunset
async def get_classified_skills():
    return []

router = APIRouter(tags=["System"])


@router.get("/status")
async def get_status():
    """System status endpoint (convenience wrapper for /realtime/status)."""
    try:
        # Check Redis connection
        redis_status = "connected" if dashboard_service.redis else "disconnected"

        # Count active connections
        active_connections = len(dashboard_service.active_connections)

        # Return simplified status
        return {
            "status": "operational",
            "redis_status": redis_status,
            "active_websocket_connections": active_connections,
            "features_enabled": {
                "real_time_updates": redis_status == "connected",
                "websocket_support": True,
                "cache_invalidation": True,
                "push_notifications": redis_status == "connected",
            },
        }
    except Exception:
        return {
            "status": "degraded",
            "redis_status": "unknown",
            "active_websocket_connections": 0,
            "features_enabled": {
                "real_time_updates": False,
                "websocket_support": True,
                "cache_invalidation": False,
                "push_notifications": False,
            },
        }


@router.get("/skills")
async def get_skills(limit: int = 20):
    """Skills endpoint (deprecated - Forge functionality archived)."""
    return {"status": "deprecated", "message": "Forge functionality has been archived. This endpoint is no longer available."}
