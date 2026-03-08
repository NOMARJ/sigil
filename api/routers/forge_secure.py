"""
Sigil Forge — Secure API Endpoints

Premium Forge endpoints with comprehensive security, access control, and audit logging.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from api.config import settings
from api.database import db
from api.security.forge_access import (
    AuditAction,
    AuditLogger,
    ForgeFeature,
    ForgeUser,
    TeamRole,
    apply_rate_limit,
    audit_action,
    forge_security,
    get_forge_user,
    requires_forge_feature,
    requires_team_role,
)

# Rate limits per subscription plan
RATE_LIMITS = {
    "free": 100,
    "pro": 1000,
    "team": 5000,
}

# Data retention periods per subscription plan (in days)
DATA_RETENTION = {
    "free": 30,
    "pro": 90,
    "team": 365,
}

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/forge", tags=["forge"])


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------


class TrackedToolRequest(BaseModel):
    """Request to track a new tool."""

    package_name: str = Field(..., description="Name of the package to track")
    ecosystem: str = Field(
        ..., description="Package ecosystem (npm, pypi, skills, mcp)"
    )
    version: Optional[str] = Field(None, description="Specific version to track")
    tracking_reason: Optional[str] = Field(None, description="Why tracking this tool")
    tags: List[str] = Field(default_factory=list, description="Custom tags")
    alert_on_update: bool = Field(True, description="Alert on new versions")
    alert_on_vulnerability: bool = Field(True, description="Alert on security issues")


class TrackedToolResponse(BaseModel):
    """A tracked tool with metadata."""

    id: int
    package_name: str
    ecosystem: str
    version: Optional[str]
    tracking_reason: Optional[str]
    tags: List[str]
    alert_settings: Dict[str, bool]
    tracked_at: datetime
    last_checked: Optional[datetime]
    latest_scan: Optional[Dict[str, Any]]


class CustomStackRequest(BaseModel):
    """Request to create a custom stack."""

    stack_name: str = Field(..., description="Name of the stack")
    description: Optional[str] = Field(None, description="Stack description")
    use_case: Optional[str] = Field(None, description="Primary use case")
    skills: List[str] = Field(default_factory=list, description="Skill packages")
    mcps: List[str] = Field(default_factory=list, description="MCP servers")
    is_public: bool = Field(False, description="Make stack publicly discoverable")
    is_team_shared: bool = Field(False, description="Share with team members")


class CustomStackResponse(BaseModel):
    """A custom stack configuration."""

    id: int
    stack_name: str
    description: Optional[str]
    use_case: Optional[str]
    skills: List[str]
    mcps: List[str]
    is_public: bool
    is_team_shared: bool
    share_url: Optional[str]
    view_count: int
    fork_count: int
    created_at: datetime
    updated_at: datetime


class PersonalAnalyticsResponse(BaseModel):
    """Personal productivity analytics."""

    total_tools_tracked: int
    tools_by_ecosystem: Dict[str, int]
    recent_vulnerabilities: int
    tools_updated_this_week: int
    most_used_categories: List[Dict[str, Any]]
    security_score: float
    tracking_history: List[Dict[str, Any]]


class TeamAnalyticsResponse(BaseModel):
    """Team-wide analytics."""

    team_name: str
    member_count: int
    total_tools_tracked: int
    shared_stacks: int
    top_tools: List[Dict[str, Any]]
    security_posture: Dict[str, Any]
    member_activity: List[Dict[str, Any]]


class ApiKeyRequest(BaseModel):
    """Request to create an API key."""

    name: str = Field(..., description="Name for the API key")
    description: Optional[str] = Field(None, description="Key description")
    scopes: List[str] = Field(default_factory=list, description="Allowed scopes")
    expires_in_days: Optional[int] = Field(None, description="Expiration in days")


class ApiKeyResponse(BaseModel):
    """API key creation response."""

    id: str
    key: str  # Only shown once at creation
    key_prefix: str
    name: str
    scopes: List[str]
    expires_at: Optional[datetime]
    created_at: datetime


# ---------------------------------------------------------------------------
# Tool Tracking Endpoints (Pro+)
# ---------------------------------------------------------------------------


@router.post("/track-tool", response_model=TrackedToolResponse)
@requires_forge_feature(ForgeFeature.TOOL_TRACKING)
@audit_action(AuditAction.TOOL_TRACKED, "tool")
async def track_tool(
    request: Request,
    body: TrackedToolRequest,
    forge_user: ForgeUser = Depends(get_forge_user),
) -> TrackedToolResponse:
    """Track a new tool for monitoring (Pro+ feature)."""

    # Apply rate limiting
    await apply_rate_limit(request, forge_user)

    # Check if already tracking
    existing = await db.select_one(
        "forge_user_tools",
        {
            "user_id": forge_user.id,
            "package_name": body.package_name,
            "ecosystem": body.ecosystem,
        },
    )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You are already tracking this tool",
        )

    # Create tracking entry
    tool_data = {
        "user_id": forge_user.id,
        "team_id": forge_user.team_id,
        "package_name": body.package_name,
        "ecosystem": body.ecosystem,
        "package_version": body.version,
        "tracking_reason": body.tracking_reason,
        "tags": body.tags,
        "alert_on_update": body.alert_on_update,
        "alert_on_vulnerability": body.alert_on_vulnerability,
        "alert_on_removal": False,
        "tracked_at": datetime.utcnow(),
    }

    tool_id = await db.insert("forge_user_tools", tool_data)

    # Get latest scan data if available
    latest_scan = await db.select_one_raw(
        """
        SELECT TOP 1 s.* FROM scans s
        WHERE s.target LIKE :pattern
        ORDER BY s.created_at DESC
        """,
        {"pattern": f"%{body.package_name}%"},
    )

    return TrackedToolResponse(
        id=tool_id,
        package_name=body.package_name,
        ecosystem=body.ecosystem,
        version=body.version,
        tracking_reason=body.tracking_reason,
        tags=body.tags,
        alert_settings={
            "update": body.alert_on_update,
            "vulnerability": body.alert_on_vulnerability,
        },
        tracked_at=tool_data["tracked_at"],
        last_checked=None,
        latest_scan=dict(latest_scan) if latest_scan else None,
    )


@router.get("/my-tools", response_model=List[TrackedToolResponse])
@requires_forge_feature(ForgeFeature.TOOL_TRACKING)
async def get_tracked_tools(
    request: Request,
    ecosystem: Optional[str] = Query(None, description="Filter by ecosystem"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    forge_user: ForgeUser = Depends(get_forge_user),
) -> List[TrackedToolResponse]:
    """Get user's tracked tools (Pro+ feature)."""

    await apply_rate_limit(request, forge_user)

    # Build query with filters
    query = """
        SELECT t.*, s.risk_score, s.verdict, s.created_at as last_scan_date
        FROM forge_user_tools t
        LEFT JOIN (
            SELECT target, risk_score, verdict, created_at,
                   ROW_NUMBER() OVER (PARTITION BY target ORDER BY created_at DESC) as rn
            FROM scans
        ) s ON t.package_name = s.target AND s.rn = 1
        WHERE t.user_id = :user_id
    """
    params = {"user_id": forge_user.id}

    if ecosystem:
        query += " AND t.ecosystem = :ecosystem"
        params["ecosystem"] = ecosystem

    if tag:
        query += " AND t.tags LIKE :tag"
        params["tag"] = f"%{tag}%"

    query += " ORDER BY t.tracked_at DESC"

    results = await db.fetch_all_raw(query, params)

    return [
        TrackedToolResponse(
            id=row["id"],
            package_name=row["package_name"],
            ecosystem=row["ecosystem"],
            version=row["package_version"],
            tracking_reason=row["tracking_reason"],
            tags=row["tags"] or [],
            alert_settings={
                "update": row["alert_on_update"],
                "vulnerability": row["alert_on_vulnerability"],
            },
            tracked_at=row["tracked_at"],
            last_checked=row["last_checked"],
            latest_scan={
                "risk_score": row["risk_score"],
                "verdict": row["verdict"],
                "scan_date": row["last_scan_date"],
            }
            if row["risk_score"]
            else None,
        )
        for row in results
    ]


@router.delete("/track-tool/{tool_id}", status_code=status.HTTP_204_NO_CONTENT)
@requires_forge_feature(ForgeFeature.TOOL_TRACKING)
@audit_action(AuditAction.TOOL_UNTRACKED, "tool")
async def untrack_tool(
    request: Request, tool_id: int, forge_user: ForgeUser = Depends(get_forge_user)
) -> None:
    """Stop tracking a tool (Pro+ feature)."""

    await apply_rate_limit(request, forge_user)

    # Verify ownership
    tool = await db.select_one(
        "forge_user_tools", {"id": tool_id, "user_id": forge_user.id}
    )
    if not tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tool not found or you don't have permission to untrack it",
        )

    await db.delete("forge_user_tools", {"id": tool_id})


# ---------------------------------------------------------------------------
# Personal Analytics (Pro+)
# ---------------------------------------------------------------------------


@router.get("/analytics/personal", response_model=PersonalAnalyticsResponse)
@requires_forge_feature(ForgeFeature.PERSONAL_ANALYTICS)
async def get_personal_analytics(
    request: Request,
    days: int = Query(30, description="Number of days to analyze"),
    forge_user: ForgeUser = Depends(get_forge_user),
) -> PersonalAnalyticsResponse:
    """Get personal productivity analytics (Pro+ feature)."""

    await apply_rate_limit(request, forge_user)

    # Get tool tracking statistics
    stats = await db.fetch_one_raw(
        """
        SELECT 
            COUNT(*) as total_tools,
            COUNT(DISTINCT ecosystem) as ecosystems,
            SUM(CASE WHEN alert_on_vulnerability = 1 THEN 1 ELSE 0 END) as vuln_alerts
        FROM forge_user_tools
        WHERE user_id = :user_id
        """,
        {"user_id": forge_user.id},
    )

    # Get ecosystem breakdown
    ecosystem_stats = await db.fetch_all_raw(
        """
        SELECT ecosystem, COUNT(*) as count
        FROM forge_user_tools
        WHERE user_id = :user_id
        GROUP BY ecosystem
        """,
        {"user_id": forge_user.id},
    )

    # Get recent vulnerability alerts
    vuln_count = await db.fetch_one_raw(
        """
        SELECT COUNT(*) as count
        FROM scans s
        INNER JOIN forge_user_tools t ON s.target = t.package_name
        WHERE t.user_id = :user_id
          AND s.verdict IN ('HIGH_RISK', 'CRITICAL_RISK')
          AND s.created_at >= :since
        """,
        {"user_id": forge_user.id, "since": datetime.utcnow() - timedelta(days=days)},
    )

    # Get tracking history
    history = await db.fetch_all_raw(
        """
        SELECT DATE(tracked_at) as date, COUNT(*) as additions
        FROM forge_user_tools
        WHERE user_id = :user_id
          AND tracked_at >= :since
        GROUP BY DATE(tracked_at)
        ORDER BY date DESC
        LIMIT 30
        """,
        {"user_id": forge_user.id, "since": datetime.utcnow() - timedelta(days=days)},
    )

    # Calculate security score (0-100)
    total_tools = stats["total_tools"] or 0
    tools_with_vulns = vuln_count["count"] or 0
    security_score = 100.0
    if total_tools > 0:
        security_score = max(0, 100 - (tools_with_vulns / total_tools * 100))

    return PersonalAnalyticsResponse(
        total_tools_tracked=total_tools,
        tools_by_ecosystem={row["ecosystem"]: row["count"] for row in ecosystem_stats},
        recent_vulnerabilities=tools_with_vulns,
        tools_updated_this_week=0,  # TODO: Implement version tracking
        most_used_categories=[],  # TODO: Implement category tracking
        security_score=round(security_score, 1),
        tracking_history=[dict(row) for row in history],
    )


# ---------------------------------------------------------------------------
# Team Analytics (Team+)
# ---------------------------------------------------------------------------


@router.get("/analytics/team", response_model=TeamAnalyticsResponse)
@requires_forge_feature(ForgeFeature.TEAM_ANALYTICS)
@requires_team_role(TeamRole.MEMBER)
async def get_team_analytics(
    request: Request, forge_user: ForgeUser = Depends(get_forge_user)
) -> TeamAnalyticsResponse:
    """Get team-wide analytics (Team+ feature)."""

    await apply_rate_limit(request, forge_user)

    if not forge_user.team_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You must be part of a team to access team analytics",
        )

    # Get team info
    team = await db.select_one("teams", {"id": forge_user.team_id})
    if not team:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Team not found"
        )

    # Get member count
    member_count = await db.fetch_one_raw(
        "SELECT COUNT(*) as count FROM users WHERE team_id = :team_id",
        {"team_id": forge_user.team_id},
    )

    # Get team tool statistics
    team_stats = await db.fetch_one_raw(
        """
        SELECT 
            COUNT(DISTINCT package_name) as total_tools,
            COUNT(DISTINCT user_id) as active_users
        FROM forge_user_tools
        WHERE team_id = :team_id
        """,
        {"team_id": forge_user.team_id},
    )

    # Get shared stacks count
    stack_count = await db.fetch_one_raw(
        """
        SELECT COUNT(*) as count
        FROM forge_user_stacks
        WHERE team_id = :team_id AND is_team_shared = 1
        """,
        {"team_id": forge_user.team_id},
    )

    # Get top tools
    top_tools = await db.fetch_all_raw(
        """
        SELECT package_name, ecosystem, COUNT(*) as user_count
        FROM forge_user_tools
        WHERE team_id = :team_id
        GROUP BY package_name, ecosystem
        ORDER BY user_count DESC
        LIMIT 10
        """,
        {"team_id": forge_user.team_id},
    )

    # Get member activity
    member_activity = await db.fetch_all_raw(
        """
        SELECT 
            u.email, u.name,
            COUNT(DISTINCT t.package_name) as tools_tracked,
            MAX(t.tracked_at) as last_activity
        FROM users u
        LEFT JOIN forge_user_tools t ON u.id = t.user_id
        WHERE u.team_id = :team_id
        GROUP BY u.id, u.email, u.name
        ORDER BY tools_tracked DESC
        """,
        {"team_id": forge_user.team_id},
    )

    # Calculate security posture
    security_data = await db.fetch_one_raw(
        """
        SELECT 
            AVG(s.risk_score) as avg_risk,
            SUM(CASE WHEN s.verdict = 'CRITICAL_RISK' THEN 1 ELSE 0 END) as critical_count,
            SUM(CASE WHEN s.verdict = 'HIGH_RISK' THEN 1 ELSE 0 END) as high_count
        FROM scans s
        WHERE s.team_id = :team_id
          AND s.created_at >= :since
        """,
        {
            "team_id": forge_user.team_id,
            "since": datetime.utcnow() - timedelta(days=30),
        },
    )

    return TeamAnalyticsResponse(
        team_name=team["name"],
        member_count=member_count["count"],
        total_tools_tracked=team_stats["total_tools"],
        shared_stacks=stack_count["count"],
        top_tools=[dict(row) for row in top_tools],
        security_posture={
            "average_risk_score": round(security_data["avg_risk"] or 0, 2),
            "critical_findings": security_data["critical_count"] or 0,
            "high_findings": security_data["high_count"] or 0,
        },
        member_activity=[dict(row) for row in member_activity],
    )


# ---------------------------------------------------------------------------
# Custom Stacks (Pro+)
# ---------------------------------------------------------------------------


@router.post("/stacks", response_model=CustomStackResponse)
@requires_forge_feature(ForgeFeature.CUSTOM_STACKS)
@audit_action(AuditAction.STACK_CREATED, "stack")
async def create_custom_stack(
    request: Request,
    body: CustomStackRequest,
    forge_user: ForgeUser = Depends(get_forge_user),
) -> CustomStackResponse:
    """Create a custom tool stack (Pro+ feature)."""

    await apply_rate_limit(request, forge_user)

    # Check for duplicate name
    existing = await db.select_one(
        "forge_user_stacks", {"user_id": forge_user.id, "stack_name": body.stack_name}
    )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You already have a stack with this name",
        )

    # Validate team sharing permission
    if body.is_team_shared and not forge_user.team_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You must be part of a team to share stacks",
        )

    # Create stack
    import secrets

    share_token = secrets.token_urlsafe(32) if body.is_public else None

    stack_data = {
        "user_id": forge_user.id,
        "team_id": forge_user.team_id if body.is_team_shared else None,
        "stack_name": body.stack_name,
        "description": body.description,
        "use_case": body.use_case,
        "skills": body.skills,
        "mcps": body.mcps,
        "is_public": body.is_public,
        "is_team_shared": body.is_team_shared,
        "share_token": share_token,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }

    stack_id = await db.insert("forge_user_stacks", stack_data)

    share_url = None
    if body.is_public and share_token:
        share_url = f"{settings.cors_origins[0]}/forge/stack/{share_token}"

    return CustomStackResponse(
        id=stack_id,
        stack_name=body.stack_name,
        description=body.description,
        use_case=body.use_case,
        skills=body.skills,
        mcps=body.mcps,
        is_public=body.is_public,
        is_team_shared=body.is_team_shared,
        share_url=share_url,
        view_count=0,
        fork_count=0,
        created_at=stack_data["created_at"],
        updated_at=stack_data["updated_at"],
    )


@router.get("/stacks", response_model=List[CustomStackResponse])
@requires_forge_feature(ForgeFeature.CUSTOM_STACKS)
async def get_custom_stacks(
    request: Request,
    include_team: bool = Query(False, description="Include team stacks"),
    forge_user: ForgeUser = Depends(get_forge_user),
) -> List[CustomStackResponse]:
    """Get user's custom stacks (Pro+ feature)."""

    await apply_rate_limit(request, forge_user)

    # Build query based on access level
    if include_team and forge_user.team_id:
        query = """
            SELECT * FROM forge_user_stacks
            WHERE user_id = :user_id
               OR (team_id = :team_id AND is_team_shared = 1)
            ORDER BY updated_at DESC
        """
        params = {"user_id": forge_user.id, "team_id": forge_user.team_id}
    else:
        query = """
            SELECT * FROM forge_user_stacks
            WHERE user_id = :user_id
            ORDER BY updated_at DESC
        """
        params = {"user_id": forge_user.id}

    results = await db.fetch_all_raw(query, params)

    return [
        CustomStackResponse(
            id=row["id"],
            stack_name=row["stack_name"],
            description=row["description"],
            use_case=row["use_case"],
            skills=row["skills"] or [],
            mcps=row["mcps"] or [],
            is_public=row["is_public"],
            is_team_shared=row["is_team_shared"],
            share_url=f"{settings.cors_origins[0]}/forge/stack/{row['share_token']}"
            if row["is_public"] and row["share_token"]
            else None,
            view_count=row["view_count"],
            fork_count=row["fork_count"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
        for row in results
    ]


# ---------------------------------------------------------------------------
# API Key Management (Pro+)
# ---------------------------------------------------------------------------


@router.post("/api-keys", response_model=ApiKeyResponse)
@requires_forge_feature(ForgeFeature.API_ACCESS)
@audit_action(AuditAction.API_KEY_CREATED, "api_key")
async def create_api_key(
    request: Request,
    body: ApiKeyRequest,
    forge_user: ForgeUser = Depends(get_forge_user),
) -> ApiKeyResponse:
    """Create a new API key (Pro+ feature)."""

    await apply_rate_limit(request, forge_user)

    # Generate secure API key
    import secrets
    import hashlib

    raw_key = f"sk_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:10]

    # Calculate expiration
    expires_at = None
    if body.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=body.expires_in_days)

    # Create key record
    key_data = {
        "user_id": forge_user.id,
        "team_id": forge_user.team_id,
        "key_hash": key_hash,
        "key_prefix": key_prefix,
        "name": body.name,
        "description": body.description,
        "scopes": body.scopes,
        "expires_at": expires_at,
        "created_at": datetime.utcnow(),
    }

    key_id = await db.insert("api_keys", key_data)

    return ApiKeyResponse(
        id=str(key_id),
        key=raw_key,  # Only shown once!
        key_prefix=key_prefix,
        name=body.name,
        scopes=body.scopes,
        expires_at=expires_at,
        created_at=key_data["created_at"],
    )


@router.get("/api-keys", response_model=List[Dict[str, Any]])
@requires_forge_feature(ForgeFeature.API_ACCESS)
async def list_api_keys(
    request: Request, forge_user: ForgeUser = Depends(get_forge_user)
) -> List[Dict[str, Any]]:
    """List user's API keys (Pro+ feature)."""

    await apply_rate_limit(request, forge_user)

    keys = await db.fetch_all(
        "api_keys", {"user_id": forge_user.id, "revoked_at": None}
    )

    return [
        {
            "id": str(key["id"]),
            "key_prefix": key["key_prefix"],
            "name": key["name"],
            "scopes": key["scopes"] or [],
            "last_used": key["last_used"],
            "usage_count": key["usage_count"],
            "expires_at": key["expires_at"],
            "created_at": key["created_at"],
        }
        for key in keys
    ]


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
@requires_forge_feature(ForgeFeature.API_ACCESS)
@audit_action(AuditAction.API_KEY_REVOKED, "api_key")
async def revoke_api_key(
    request: Request, key_id: str, forge_user: ForgeUser = Depends(get_forge_user)
) -> None:
    """Revoke an API key (Pro+ feature)."""

    await apply_rate_limit(request, forge_user)

    # Verify ownership
    key = await db.select_one("api_keys", {"id": key_id, "user_id": forge_user.id})
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="API key not found"
        )

    # Revoke the key
    await db.update("api_keys", {"id": key_id}, {"revoked_at": datetime.utcnow()})


# ---------------------------------------------------------------------------
# Audit Logs (Enterprise)
# ---------------------------------------------------------------------------


@router.get("/audit-logs", response_model=List[Dict[str, Any]])
@requires_forge_feature(ForgeFeature.COMPLIANCE_REPORTING)
async def get_audit_logs(
    request: Request,
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
    forge_user: ForgeUser = Depends(get_forge_user),
) -> List[Dict[str, Any]]:
    """Get audit logs (Enterprise feature)."""

    await apply_rate_limit(request, forge_user)

    # Use AuditLogger to get logs with proper access control
    logs = await AuditLogger.get_audit_logs(
        forge_user=forge_user,
        start_date=start_date,
        end_date=end_date,
        action=AuditAction(action) if action else None,
        resource_type=resource_type,
        limit=limit,
    )

    return logs


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------


@router.get("/security/status")
async def security_status(
    forge_user: ForgeUser = Depends(get_forge_user),
) -> Dict[str, Any]:
    """Get current security status and limits."""

    return {
        "user_id": forge_user.id,
        "subscription_plan": forge_user.subscription_plan.value,
        "team_id": forge_user.team_id,
        "team_role": forge_user.team_role.value if forge_user.team_role else None,
        "api_calls_remaining": RATE_LIMITS[forge_user.subscription_plan]
        - forge_user.api_calls_this_period,
        "rate_limit": RATE_LIMITS[forge_user.subscription_plan],
        "features_enabled": [
            feature.value
            for feature in ForgeFeature
            if forge_security.has_access(forge_user.subscription_plan, feature)
        ],
        "data_retention_days": DATA_RETENTION[forge_user.subscription_plan],
    }
