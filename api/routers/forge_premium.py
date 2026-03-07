"""
Sigil Forge Premium — Authenticated API Endpoints

Provides plan-gated premium features for Forge:
- Personal tool tracking and management
- Custom stacks creation and sharing
- Analytics dashboards (Pro+)
- Alert subscriptions and notifications
- User preferences and settings

All endpoints require authentication and respect plan tier limits.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query

from database import db
from gates import PlanTier, require_plan
from models import (
    AlertSubscription,
    CreateAlertSubscriptionRequest,
    CreateStackRequest,
    ForgeStack,
    ForgeUserSettings,
    PersonalAnalyticsRequest,
    PersonalAnalyticsResponse,
    TeamAnalyticsResponse,
    TrackedTool,
    TrackToolRequest,
    UpdateAlertSubscriptionRequest,
    UpdateForgeSettingsRequest,
    UpdateStackRequest,
    UpdateTrackedToolRequest,
)
from routers.auth import UserResponse, get_current_user_unified

logger = logging.getLogger(__name__)

# Create router with auth prefix for premium features
router = APIRouter(prefix="/v1/forge", tags=["Forge Premium"])


async def _plan_for_user(user_id: str) -> str:
    sub = await db.get_subscription(user_id)
    return (sub or {}).get("plan", "free")


async def _require_pro(current_user: UserResponse) -> None:
    plan = await _plan_for_user(current_user.id)
    if plan not in {"pro", "team", "enterprise"}:
        raise HTTPException(status_code=403, detail="This endpoint requires Pro plan")


async def _require_team(current_user: UserResponse) -> None:
    plan = await _plan_for_user(current_user.id)
    if plan not in {"team", "enterprise"}:
        raise HTTPException(status_code=403, detail="This endpoint requires Team plan")


def _validate_repository_url(url: str) -> None:
    if not re.match(r"^https://github\.com/[\w.-]+/[\w.-]+/?$", url or ""):
        raise HTTPException(status_code=422, detail="Invalid repository URL")


@router.post("/tools/track", status_code=201)
async def track_tool_compat(
    payload: dict[str, Any],
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
):
    await _require_pro(current_user)

    name = (payload.get("name") or "").strip()
    repository_url = (payload.get("repository_url") or "").strip()
    if not name or not repository_url:
        raise HTTPException(status_code=422, detail="Missing required fields")
    _validate_repository_url(repository_url)

    existing = await db.select_one(
        "forge_user_tools",
        {
            "user_id": current_user.id,
            "repository_url": repository_url,
            "name": name,
        },
    )
    if existing:
        raise HTTPException(status_code=409, detail="Tool already tracked")

    row = {
        "id": str(uuid4()),
        "user_id": current_user.id,
        "name": name,
        "repository_url": repository_url,
        "description": payload.get("description", ""),
        "category": payload.get("category", ""),
        "tracked_at": datetime.now(timezone.utc),
    }
    await db.insert("forge_user_tools", row)
    return row


@router.get("/tools")
async def list_tools_compat(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
):
    await _require_pro(current_user)
    return await db.select(
        "forge_user_tools",
        {"user_id": current_user.id},
        order_by="tracked_at",
        order_desc=True,
    )


@router.delete("/tools/{tool_id}")
async def untrack_tool_compat(
    tool_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
):
    await _require_pro(current_user)
    tool = await db.select_one(
        "forge_user_tools", {"id": tool_id, "user_id": current_user.id}
    )
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    await db.delete("forge_user_tools", {"id": tool_id})
    return {"deleted": True}


@router.get("/analytics/personal")
async def personal_analytics_compat(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    start_date: str | None = Query(None),
    end_date: str | None = Query(None),
):
    await _require_pro(current_user)
    tools = await db.select("forge_user_tools", {"user_id": current_user.id})
    start = (start_date or datetime.now(timezone.utc).date().isoformat()).split("T")[0]
    end = (end_date or datetime.now(timezone.utc).date().isoformat()).split("T")[0]
    return {
        "tools_tracked": len(tools),
        "risk_distribution": {"low": len(tools), "medium": 0, "high": 0},
        "recent_activity": [],
        "trends": {},
        "date_range": {"start": start, "end": end},
    }


@router.get("/analytics/team")
async def team_analytics_compat(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
):
    await _require_team(current_user)
    return {"team_activity": []}


@router.get("/settings")
async def get_settings_compat(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
):
    await _require_pro(current_user)
    row = await db.select_one("forge_user_settings", {"user_id": current_user.id})
    if not row:
        row = {
            "id": str(uuid4()),
            "user_id": current_user.id,
            "notifications": {"weekly_digest": True, "security_alerts": True},
            "privacy": {"public_profile": False, "share_stacks": False},
            "preferences": {
                "risk_threshold": "medium",
                "auto_track_dependencies": False,
            },
            "updated_at": datetime.now(timezone.utc),
        }
        await db.insert("forge_user_settings", row)
    return {
        "notifications": row.get("notifications", {"weekly_digest": True}),
        "privacy": row.get("privacy", {"public_profile": False}),
        "preferences": row.get("preferences", {"risk_threshold": "medium"}),
    }


@router.put("/settings")
async def update_settings_compat(
    payload: dict[str, Any],
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
):
    await _require_pro(current_user)

    preferences = payload.get("preferences")
    if isinstance(preferences, dict):
        if "risk_threshold" in preferences and preferences["risk_threshold"] not in {
            "low",
            "medium",
            "high",
        }:
            raise HTTPException(status_code=422, detail="Invalid preferences")
        if "default_scan_depth" in preferences and not isinstance(
            preferences["default_scan_depth"], str
        ):
            raise HTTPException(status_code=422, detail="Invalid preferences")

    row = await db.select_one("forge_user_settings", {"user_id": current_user.id}) or {
        "id": str(uuid4()),
        "user_id": current_user.id,
        "notifications": {"weekly_digest": True, "security_alerts": True},
        "privacy": {"public_profile": False, "share_stacks": False},
        "preferences": {"risk_threshold": "medium", "auto_track_dependencies": False},
        "updated_at": datetime.now(timezone.utc),
    }
    for key in ["notifications", "privacy", "preferences"]:
        if key in payload and isinstance(payload[key], dict):
            row[key] = payload[key]
    row["updated_at"] = datetime.now(timezone.utc)
    await db.upsert("forge_user_settings", row)
    return {
        "notifications": row["notifications"],
        "privacy": row["privacy"],
        "preferences": row["preferences"],
    }


@router.post("/stacks", status_code=201)
async def create_stack_compat(
    payload: dict[str, Any],
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
):
    await _require_team(current_user)
    row = {
        "id": str(uuid4()),
        "user_id": current_user.id,
        "name": payload.get("name", "Untitled Stack"),
        "tools": payload.get("tools", []),
        "created_at": datetime.now(timezone.utc),
    }
    await db.insert("forge_stacks", row)
    return row


@router.get("/stacks")
async def list_stacks_compat(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
):
    await _require_team(current_user)
    return await db.select("forge_stacks", {"user_id": current_user.id})


# ============================================================================
# Tool Tracking Management (Pro+ features)
# ============================================================================


@router.get("/my-tools", response_model=list[TrackedTool])
async def get_tracked_tools(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
    starred_only: bool = Query(False, description="Show only starred tools"),
    ecosystem: str | None = Query(None, description="Filter by ecosystem"),
    tags: list[str] = Query(default=[], description="Filter by tags"),
):
    """Get user's tracked tools with metadata (Pro+ feature)."""

    try:
        # Build filters
        filters = {"user_id": current_user.id}
        if starred_only:
            filters["is_starred"] = True
        if ecosystem:
            filters["ecosystem"] = ecosystem

        # Get tracked tools
        tracked_tools = await db.select(
            "forge_user_tools", filters, order_by="tracked_at", order_desc=True
        )

        # Filter by tags if specified (JSON contains check would be better in SQL)
        if tags:
            filtered_tools = []
            for tool in tracked_tools:
                tool_tags = json.loads(tool.get("custom_tags", "[]"))
                if any(tag in tool_tags for tag in tags):
                    filtered_tools.append(tool)
            tracked_tools = filtered_tools

        # Build response with trust scores
        results = []
        for tool in tracked_tools:
            # Get current trust score from public scans
            trust_score = 50.0  # Default
            scan = await db.select_one(
                "public_scans",
                {"ecosystem": tool["ecosystem"], "package_name": tool["tool_id"]},
            )
            if scan:
                risk_score = scan.get("risk_score", 0.0)
                trust_score = max(0.0, 100.0 - (risk_score * 5))

            results.append(
                TrackedTool(
                    id=str(tool["id"]),
                    tool_id=tool["tool_id"],
                    ecosystem=tool["ecosystem"],
                    tracked_at=tool["tracked_at"],
                    is_starred=bool(tool.get("is_starred", False)),
                    custom_tags=json.loads(tool.get("custom_tags", "[]")),
                    notes=tool.get("notes", ""),
                    trust_score=trust_score,
                )
            )

        return results

    except Exception as e:
        logger.error(f"Get tracked tools failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/my-tools/track", response_model=TrackedTool, status_code=201)
async def track_tool(
    request: TrackToolRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
):
    """Add tool to user's tracking list (Pro+ feature)."""

    try:
        # Check if tool exists in Forge classification
        classification = await db.select_one(
            "forge_classification",
            {"ecosystem": request.ecosystem, "package_name": request.tool_id},
        )

        if not classification:
            raise HTTPException(
                status_code=404,
                detail=f"Tool {request.tool_id} not found in {request.ecosystem} ecosystem",
            )

        # Check if already tracked
        existing = await db.select_one(
            "forge_user_tools",
            {
                "user_id": current_user.id,
                "tool_id": request.tool_id,
                "ecosystem": request.ecosystem,
            },
        )

        if existing:
            raise HTTPException(status_code=409, detail="Tool is already being tracked")

        # Create tracking record
        tracking_data = {
            "id": str(uuid4()),
            "user_id": current_user.id,
            "tool_id": request.tool_id,
            "ecosystem": request.ecosystem,
            "tracked_at": datetime.now(timezone.utc),
            "is_starred": request.is_starred,
            "custom_tags": json.dumps(request.custom_tags),
            "notes": request.notes,
        }

        await db.insert("forge_user_tools", tracking_data)

        # Track analytics event
        await _track_analytics_event(
            current_user.id,
            "tool_tracked",
            {
                "tool_id": request.tool_id,
                "ecosystem": request.ecosystem,
                "is_starred": request.is_starred,
                "has_tags": len(request.custom_tags) > 0,
                "has_notes": len(request.notes) > 0,
            },
        )

        # Get trust score for response
        trust_score = 50.0
        scan = await db.select_one(
            "public_scans",
            {"ecosystem": request.ecosystem, "package_name": request.tool_id},
        )
        if scan:
            risk_score = scan.get("risk_score", 0.0)
            trust_score = max(0.0, 100.0 - (risk_score * 5))

        return TrackedTool(
            id=tracking_data["id"],
            tool_id=request.tool_id,
            ecosystem=request.ecosystem,
            tracked_at=tracking_data["tracked_at"],
            is_starred=request.is_starred,
            custom_tags=request.custom_tags,
            notes=request.notes,
            trust_score=trust_score,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Track tool failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/my-tools/{tool_id}/untrack", status_code=204)
async def untrack_tool(
    tool_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
    ecosystem: str = Query(..., description="Tool ecosystem"),
):
    """Remove tool from user's tracking list (Pro+ feature)."""

    try:
        # Find tracking record
        tracking = await db.select_one(
            "forge_user_tools",
            {"user_id": current_user.id, "tool_id": tool_id, "ecosystem": ecosystem},
        )

        if not tracking:
            raise HTTPException(status_code=404, detail="Tool is not being tracked")

        # Delete tracking record
        await db.delete("forge_user_tools", {"id": tracking["id"]})

        # Track analytics event
        await _track_analytics_event(
            current_user.id,
            "tool_untracked",
            {
                "tool_id": tool_id,
                "ecosystem": ecosystem,
                "was_starred": tracking.get("is_starred", False),
            },
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Untrack tool failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/my-tools/{tool_id}", response_model=TrackedTool)
async def update_tracked_tool(
    tool_id: str,
    request: UpdateTrackedToolRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
    ecosystem: str = Query(..., description="Tool ecosystem"),
):
    """Update metadata for a tracked tool (Pro+ feature)."""

    try:
        # Find tracking record
        tracking = await db.select_one(
            "forge_user_tools",
            {"user_id": current_user.id, "tool_id": tool_id, "ecosystem": ecosystem},
        )

        if not tracking:
            raise HTTPException(status_code=404, detail="Tool is not being tracked")

        # Build update data
        updates = {}
        if request.is_starred is not None:
            updates["is_starred"] = request.is_starred
        if request.custom_tags is not None:
            updates["custom_tags"] = json.dumps(request.custom_tags)
        if request.notes is not None:
            updates["notes"] = request.notes

        if updates:
            await db.update("forge_user_tools", {"id": tracking["id"]}, updates)

        # Get updated tracking record
        updated = await db.select_one("forge_user_tools", {"id": tracking["id"]})

        # Track analytics event
        await _track_analytics_event(
            current_user.id,
            "tool_starred" if request.is_starred else "tool_updated",
            {
                "tool_id": tool_id,
                "ecosystem": ecosystem,
                "update_fields": list(updates.keys()),
            },
        )

        # Get trust score
        trust_score = 50.0
        scan = await db.select_one(
            "public_scans", {"ecosystem": ecosystem, "package_name": tool_id}
        )
        if scan:
            risk_score = scan.get("risk_score", 0.0)
            trust_score = max(0.0, 100.0 - (risk_score * 5))

        return TrackedTool(
            id=str(updated["id"]),
            tool_id=updated["tool_id"],
            ecosystem=updated["ecosystem"],
            tracked_at=updated["tracked_at"],
            is_starred=bool(updated.get("is_starred", False)),
            custom_tags=json.loads(updated.get("custom_tags", "[]")),
            notes=updated.get("notes", ""),
            trust_score=trust_score,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update tracked tool failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Custom Stacks Management (Pro+ features)
# ============================================================================


@router.get("/stacks", response_model=list[ForgeStack])
async def get_user_stacks(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
    include_public: bool = Query(True, description="Include public stacks from team"),
):
    """Get user's custom tool stacks (Pro+ feature)."""

    try:
        # Get user's own stacks
        user_stacks = await db.select(
            "forge_stacks",
            {"user_id": current_user.id},
            order_by="updated_at",
            order_desc=True,
        )

        stacks = list(user_stacks)

        # Optionally include public stacks from team
        if include_public and current_user.team_id:
            team_stacks = await db.select(
                "forge_stacks",
                {"team_id": current_user.team_id, "is_public": True},
                order_by="updated_at",
                order_desc=True,
            )

            # Filter out user's own stacks to avoid duplicates
            team_stacks = [s for s in team_stacks if s["user_id"] != current_user.id]
            stacks.extend(team_stacks)

        # Build response
        results = []
        for stack in stacks:
            results.append(
                ForgeStack(
                    id=str(stack["id"]),
                    name=stack["name"],
                    description=stack.get("description", ""),
                    tools=json.loads(stack.get("tools", "[]")),
                    is_public=bool(stack.get("is_public", False)),
                    user_id=str(stack["user_id"]),
                    team_id=str(stack["team_id"]) if stack.get("team_id") else None,
                    created_at=stack["created_at"],
                    updated_at=stack["updated_at"],
                )
            )

        return results

    except Exception as e:
        logger.error(f"Get user stacks failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stacks", response_model=ForgeStack, status_code=201)
async def create_stack(
    request: CreateStackRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
):
    """Create a new custom tool stack (Pro+ feature)."""

    try:
        stack_id = str(uuid4())
        now = datetime.now(timezone.utc)

        # Create stack record
        stack_data = {
            "id": stack_id,
            "user_id": current_user.id,
            "team_id": current_user.team_id if request.is_public else None,
            "name": request.name,
            "description": request.description,
            "tools": json.dumps(request.tools),
            "is_public": request.is_public,
            "created_at": now,
            "updated_at": now,
        }

        await db.insert("forge_stacks", stack_data)

        # Track analytics event
        await _track_analytics_event(
            current_user.id,
            "stack_created",
            {
                "stack_id": stack_id,
                "tool_count": len(request.tools),
                "is_public": request.is_public,
                "has_description": len(request.description) > 0,
            },
        )

        return ForgeStack(
            id=stack_id,
            name=request.name,
            description=request.description,
            tools=request.tools,
            is_public=request.is_public,
            user_id=current_user.id,
            team_id=current_user.team_id if request.is_public else None,
            created_at=now,
            updated_at=now,
        )

    except Exception as e:
        logger.error(f"Create stack failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/stacks/{stack_id}", response_model=ForgeStack)
async def update_stack(
    stack_id: str,
    request: UpdateStackRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
):
    """Update an existing stack (Pro+ feature)."""

    try:
        # Find stack
        stack = await db.select_one("forge_stacks", {"id": stack_id})
        if not stack:
            raise HTTPException(status_code=404, detail="Stack not found")

        # Check ownership
        if stack["user_id"] != current_user.id:
            raise HTTPException(
                status_code=403, detail="You can only update your own stacks"
            )

        # Build updates
        updates = {"updated_at": datetime.now(timezone.utc)}
        if request.name is not None:
            updates["name"] = request.name
        if request.description is not None:
            updates["description"] = request.description
        if request.tools is not None:
            updates["tools"] = json.dumps(request.tools)
        if request.is_public is not None:
            updates["is_public"] = request.is_public
            updates["team_id"] = current_user.team_id if request.is_public else None

        await db.update("forge_stacks", {"id": stack_id}, updates)

        # Get updated stack
        updated = await db.select_one("forge_stacks", {"id": stack_id})

        return ForgeStack(
            id=str(updated["id"]),
            name=updated["name"],
            description=updated.get("description", ""),
            tools=json.loads(updated.get("tools", "[]")),
            is_public=bool(updated.get("is_public", False)),
            user_id=str(updated["user_id"]),
            team_id=str(updated["team_id"]) if updated.get("team_id") else None,
            created_at=updated["created_at"],
            updated_at=updated["updated_at"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update stack failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/stacks/{stack_id}", status_code=204)
async def delete_stack(
    stack_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
):
    """Delete a stack (Pro+ feature)."""

    try:
        # Find stack
        stack = await db.select_one("forge_stacks", {"id": stack_id})
        if not stack:
            raise HTTPException(status_code=404, detail="Stack not found")

        # Check ownership
        if stack["user_id"] != current_user.id:
            raise HTTPException(
                status_code=403, detail="You can only delete your own stacks"
            )

        await db.delete("forge_stacks", {"id": stack_id})

        # Track analytics event
        await _track_analytics_event(
            current_user.id,
            "stack_deleted",
            {"stack_id": stack_id, "was_public": stack.get("is_public", False)},
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete stack failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Analytics Endpoints (Pro+ and Team+ features)
# ============================================================================


@router.get("/analytics/personal", response_model=PersonalAnalyticsResponse)
async def get_personal_analytics(
    request: Annotated[PersonalAnalyticsRequest, Depends()],
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
):
    """Get personal analytics dashboard (Pro+ feature)."""

    try:
        # This would be implemented with the analytics service
        # For now, return basic structure with dummy data

        # Track analytics view event
        await _track_analytics_event(
            current_user.id,
            "analytics_viewed",
            {
                "view_type": "personal",
                "days_back": request.days_back,
                "filters": {
                    "categories": request.categories,
                    "ecosystems": request.ecosystems,
                },
            },
        )

        return PersonalAnalyticsResponse(
            period_days=request.days_back,
            total_tool_views=0,
            total_tools_tracked=0,
            total_searches=0,
            total_stacks_created=0,
            most_viewed_tools=[],
            most_tracked_tools=[],
            discovery_sources={},
            category_preferences={},
            ecosystem_usage={},
            trust_score_trends=[],
            security_findings_timeline=[],
            daily_activity={},
            hourly_activity={},
        )

    except Exception as e:
        logger.error(f"Get personal analytics failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analytics/team", response_model=TeamAnalyticsResponse)
async def get_team_analytics(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.TEAM))],
    days_back: int = Query(30, ge=1, le=365, description="Days to look back"),
):
    """Get team analytics dashboard (Team+ feature)."""

    try:
        if not current_user.team_id:
            raise HTTPException(
                status_code=400,
                detail="User must be part of a team to view team analytics",
            )

        # Track analytics view event
        await _track_analytics_event(
            current_user.id,
            "analytics_viewed",
            {
                "view_type": "team",
                "team_id": current_user.team_id,
                "days_back": days_back,
            },
        )

        return TeamAnalyticsResponse(
            period_days=days_back,
            team_id=current_user.team_id,
            active_members=0,
            total_tools_tracked=0,
            total_stacks_shared=0,
            total_scans_performed=0,
            most_popular_tools=[],
            shared_tool_stacks=[],
            member_activity=[],
            tool_adoption_timeline=[],
            category_distribution={},
            ecosystem_distribution={},
            security_compliance_score=0.0,
            security_findings_summary={},
            tools_needing_review=[],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get team analytics failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Alert Subscriptions (Pro+ features)
# ============================================================================


@router.get("/alerts", response_model=list[AlertSubscription])
async def get_alert_subscriptions(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
):
    """Get user's alert subscriptions (Pro+ feature)."""

    try:
        subscriptions = await db.select(
            "forge_alert_subscriptions",
            {"user_id": current_user.id},
            order_by="created_at",
            order_desc=True,
        )

        results = []
        for sub in subscriptions:
            results.append(
                AlertSubscription(
                    id=str(sub["id"]),
                    tool_id=sub.get("tool_id"),
                    ecosystem=sub.get("ecosystem"),
                    alert_types=json.loads(sub.get("alert_types", "[]")),
                    channels=json.loads(sub.get("channels", "{}")),
                    is_active=bool(sub.get("is_active", True)),
                    created_at=sub["created_at"],
                )
            )

        return results

    except Exception as e:
        logger.error(f"Get alert subscriptions failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/alerts", response_model=AlertSubscription, status_code=201)
async def create_alert_subscription(
    request: CreateAlertSubscriptionRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
):
    """Create a new alert subscription (Pro+ feature)."""

    try:
        subscription_id = str(uuid4())

        subscription_data = {
            "id": subscription_id,
            "user_id": current_user.id,
            "tool_id": request.tool_id,
            "ecosystem": request.ecosystem,
            "alert_types": json.dumps(request.alert_types),
            "channels": json.dumps(request.channels),
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
        }

        await db.insert("forge_alert_subscriptions", subscription_data)

        # Track analytics event
        await _track_analytics_event(
            current_user.id,
            "alert_configured",
            {
                "subscription_id": subscription_id,
                "tool_id": request.tool_id,
                "ecosystem": request.ecosystem,
                "alert_types": request.alert_types,
                "channels": list(request.channels.keys()),
            },
        )

        return AlertSubscription(
            id=subscription_id,
            tool_id=request.tool_id,
            ecosystem=request.ecosystem,
            alert_types=request.alert_types,
            channels=request.channels,
            is_active=True,
            created_at=subscription_data["created_at"],
        )

    except Exception as e:
        logger.error(
            f"Create alert subscription failed for user {current_user.id}: {e}"
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/alerts/{subscription_id}", response_model=AlertSubscription)
async def update_alert_subscription(
    subscription_id: str,
    request: UpdateAlertSubscriptionRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
):
    """Update an alert subscription (Pro+ feature)."""

    try:
        # Find subscription
        subscription = await db.select_one(
            "forge_alert_subscriptions",
            {"id": subscription_id, "user_id": current_user.id},
        )

        if not subscription:
            raise HTTPException(status_code=404, detail="Alert subscription not found")

        # Build updates
        updates = {}
        if request.alert_types is not None:
            updates["alert_types"] = json.dumps(request.alert_types)
        if request.channels is not None:
            updates["channels"] = json.dumps(request.channels)
        if request.is_active is not None:
            updates["is_active"] = request.is_active

        if updates:
            await db.update(
                "forge_alert_subscriptions", {"id": subscription_id}, updates
            )

        # Get updated subscription
        updated = await db.select_one(
            "forge_alert_subscriptions", {"id": subscription_id}
        )

        return AlertSubscription(
            id=str(updated["id"]),
            tool_id=updated.get("tool_id"),
            ecosystem=updated.get("ecosystem"),
            alert_types=json.loads(updated.get("alert_types", "[]")),
            channels=json.loads(updated.get("channels", "{}")),
            is_active=bool(updated.get("is_active", True)),
            created_at=updated["created_at"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Update alert subscription failed for user {current_user.id}: {e}"
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/alerts/{subscription_id}", status_code=204)
async def delete_alert_subscription(
    subscription_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
):
    """Delete an alert subscription (Pro+ feature)."""

    try:
        # Find subscription
        subscription = await db.select_one(
            "forge_alert_subscriptions",
            {"id": subscription_id, "user_id": current_user.id},
        )

        if not subscription:
            raise HTTPException(status_code=404, detail="Alert subscription not found")

        await db.delete("forge_alert_subscriptions", {"id": subscription_id})

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Delete alert subscription failed for user {current_user.id}: {e}"
        )
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# User Settings (Pro+ features)
# ============================================================================


@router.get("/settings", response_model=ForgeUserSettings)
async def get_forge_settings(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
):
    """Get user's Forge preferences and settings (Pro+ feature)."""

    try:
        settings = await db.select_one(
            "forge_user_settings", {"user_id": current_user.id}
        )

        if not settings:
            # Create default settings
            now = datetime.now(timezone.utc)
            default_settings = {
                "user_id": current_user.id,
                "alert_frequency": "daily",
                "alert_types": json.dumps(["security", "updates"]),
                "delivery_channels": json.dumps(["email"]),
                "quiet_hours": None,
                "email_notifications": True,
                "slack_notifications": False,
                "weekly_digest": True,
                "created_at": now,
                "updated_at": now,
            }

            await db.insert("forge_user_settings", default_settings)
            settings = default_settings

        return ForgeUserSettings(
            alert_frequency=settings.get("alert_frequency", "daily"),
            alert_types=json.loads(
                settings.get("alert_types", '["security", "updates"]')
            ),
            delivery_channels=json.loads(
                settings.get("delivery_channels", '["email"]')
            ),
            quiet_hours=json.loads(settings["quiet_hours"])
            if settings.get("quiet_hours")
            else None,
            email_notifications=bool(settings.get("email_notifications", True)),
            slack_notifications=bool(settings.get("slack_notifications", False)),
            weekly_digest=bool(settings.get("weekly_digest", True)),
            created_at=settings["created_at"],
            updated_at=settings["updated_at"],
        )

    except Exception as e:
        logger.error(f"Get Forge settings failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/settings", response_model=ForgeUserSettings)
async def update_forge_settings(
    request: UpdateForgeSettingsRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
):
    """Update user's Forge preferences and settings (Pro+ feature)."""

    try:
        # Build updates
        updates = {"updated_at": datetime.now(timezone.utc)}

        if request.alert_frequency is not None:
            updates["alert_frequency"] = request.alert_frequency
        if request.alert_types is not None:
            updates["alert_types"] = json.dumps(request.alert_types)
        if request.delivery_channels is not None:
            updates["delivery_channels"] = json.dumps(request.delivery_channels)
        if request.quiet_hours is not None:
            updates["quiet_hours"] = json.dumps(request.quiet_hours)
        if request.email_notifications is not None:
            updates["email_notifications"] = request.email_notifications
        if request.slack_notifications is not None:
            updates["slack_notifications"] = request.slack_notifications
        if request.weekly_digest is not None:
            updates["weekly_digest"] = request.weekly_digest

        # Check if settings exist
        existing = await db.select_one(
            "forge_user_settings", {"user_id": current_user.id}
        )

        if existing:
            await db.update(
                "forge_user_settings", {"user_id": current_user.id}, updates
            )
        else:
            # Create new settings record
            now = datetime.now(timezone.utc)
            new_settings = {
                "user_id": current_user.id,
                "alert_frequency": request.alert_frequency or "daily",
                "alert_types": json.dumps(
                    request.alert_types or ["security", "updates"]
                ),
                "delivery_channels": json.dumps(request.delivery_channels or ["email"]),
                "quiet_hours": json.dumps(request.quiet_hours)
                if request.quiet_hours
                else None,
                "email_notifications": request.email_notifications
                if request.email_notifications is not None
                else True,
                "slack_notifications": request.slack_notifications
                if request.slack_notifications is not None
                else False,
                "weekly_digest": request.weekly_digest
                if request.weekly_digest is not None
                else True,
                "created_at": now,
                "updated_at": now,
            }
            await db.insert("forge_user_settings", new_settings)

        # Get updated settings
        updated = await db.select_one(
            "forge_user_settings", {"user_id": current_user.id}
        )

        # Track analytics event
        await _track_analytics_event(
            current_user.id,
            "settings_updated",
            {"updated_fields": list(updates.keys())},
        )

        return ForgeUserSettings(
            alert_frequency=updated.get("alert_frequency", "daily"),
            alert_types=json.loads(
                updated.get("alert_types", '["security", "updates"]')
            ),
            delivery_channels=json.loads(updated.get("delivery_channels", '["email"]')),
            quiet_hours=json.loads(updated["quiet_hours"])
            if updated.get("quiet_hours")
            else None,
            email_notifications=bool(updated.get("email_notifications", True)),
            slack_notifications=bool(updated.get("slack_notifications", False)),
            weekly_digest=bool(updated.get("weekly_digest", True)),
            created_at=updated["created_at"],
            updated_at=updated["updated_at"],
        )

    except Exception as e:
        logger.error(f"Update Forge settings failed for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Helper Functions
# ============================================================================


async def _track_analytics_event(
    user_id: str, event_type: str, event_data: dict
) -> None:
    """Track an analytics event for user behavior analysis."""

    try:
        event_record = {
            "id": str(uuid4()),
            "user_id": user_id,
            "event_type": event_type,
            "event_data": json.dumps(event_data),
            "timestamp": datetime.now(timezone.utc),
        }

        await db.insert("forge_analytics_events", event_record)

    except Exception as e:
        # Don't fail requests if analytics tracking fails
        logger.warning(f"Failed to track analytics event: {e}")
