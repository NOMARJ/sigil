"""
Sigil Forge — Security and Access Control System

Comprehensive security module for plan-based feature gating, team access control,
rate limiting, data isolation, and audit logging for Forge premium features.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from api.config import settings
from api.database import cache, db
from api.models import UserResponse
from api.routers.auth import get_current_user_unified

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Plan and Feature Definitions
# ---------------------------------------------------------------------------


class SigilPlan(str, Enum):
    """Available billing plan tiers."""
    
    FREE = "free"
    PRO = "pro"
    TEAM = "team"
    ENTERPRISE = "enterprise"


class ForgeFeature(str, Enum):
    """Forge premium feature flags."""
    
    # Tool tracking and personal productivity
    TOOL_TRACKING = "tool_tracking"
    PERSONAL_ANALYTICS = "personal_analytics"
    CUSTOM_STACKS = "custom_stacks"
    ALERTS = "alerts"
    EXPORTS = "exports"
    
    # Team collaboration features
    TEAM_ANALYTICS = "team_analytics"
    TEAM_STACKS = "team_stacks"
    TEAM_SHARING = "team_sharing"
    
    # Organization-wide features
    ORGANIZATION_ANALYTICS = "organization_analytics"
    COMPLIANCE_REPORTING = "compliance_reporting"
    
    # API access levels
    API_ACCESS = "api_access"
    WEBHOOKS = "webhooks"
    
    # Advanced features
    AI_RECOMMENDATIONS = "ai_recommendations"
    CUSTOM_CATEGORIES = "custom_categories"
    PRIORITY_SUPPORT = "priority_support"


class TeamRole(str, Enum):
    """Team member roles with hierarchical permissions."""
    
    MEMBER = "member"
    ADMIN = "admin"
    OWNER = "owner"


class OrganizationRole(str, Enum):
    """Organization member roles."""
    
    MEMBER = "member"
    ADMIN = "admin"
    OWNER = "owner"


# ---------------------------------------------------------------------------
# Feature Access Matrix
# ---------------------------------------------------------------------------

FEATURE_ACCESS = {
    SigilPlan.FREE: [
        # Free users can discover tools but can't track
    ],
    SigilPlan.PRO: [
        ForgeFeature.TOOL_TRACKING,
        ForgeFeature.PERSONAL_ANALYTICS,
        ForgeFeature.CUSTOM_STACKS,
        ForgeFeature.ALERTS,
        ForgeFeature.EXPORTS,
        ForgeFeature.API_ACCESS,
        ForgeFeature.AI_RECOMMENDATIONS,
    ],
    SigilPlan.TEAM: [
        # Includes all Pro features plus:
        ForgeFeature.TEAM_ANALYTICS,
        ForgeFeature.TEAM_STACKS,
        ForgeFeature.TEAM_SHARING,
        ForgeFeature.WEBHOOKS,
        ForgeFeature.CUSTOM_CATEGORIES,
    ],
    SigilPlan.ENTERPRISE: [
        # Includes all Team features plus:
        ForgeFeature.ORGANIZATION_ANALYTICS,
        ForgeFeature.COMPLIANCE_REPORTING,
        ForgeFeature.PRIORITY_SUPPORT,
    ]
}

# API rate limits per plan (requests per hour)
RATE_LIMITS = {
    SigilPlan.FREE: 100,      # 100 requests/hour
    SigilPlan.PRO: 1000,      # 1000 requests/hour
    SigilPlan.TEAM: 5000,     # 5000 requests/hour
    SigilPlan.ENTERPRISE: 25000  # 25000 requests/hour
}

# Data retention limits per plan (days)
DATA_RETENTION = {
    SigilPlan.FREE: 7,        # 1 week
    SigilPlan.PRO: 90,        # 3 months
    SigilPlan.TEAM: 365,      # 1 year
    SigilPlan.ENTERPRISE: -1  # Unlimited
}


# ---------------------------------------------------------------------------
# Extended User Model with Subscription Info
# ---------------------------------------------------------------------------


class ForgeUser(BaseModel):
    """Extended user model with subscription and team information."""
    
    id: str
    email: str
    name: str = ""
    created_at: datetime
    
    # Subscription information
    subscription_plan: SigilPlan = SigilPlan.FREE
    subscription_status: str = "active"
    subscription_expires: Optional[datetime] = None
    
    # Team/Organization membership
    team_id: Optional[str] = None
    team_role: Optional[TeamRole] = None
    organization_id: Optional[str] = None
    org_role: Optional[OrganizationRole] = None
    
    # Usage tracking
    api_calls_this_period: int = 0
    last_api_call: Optional[datetime] = None
    
    # Feature flags (for custom overrides)
    enabled_features: List[ForgeFeature] = Field(default_factory=list)
    disabled_features: List[ForgeFeature] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Access Control Functions
# ---------------------------------------------------------------------------


def has_forge_access(user_plan: SigilPlan, feature: ForgeFeature) -> bool:
    """Check if a plan includes access to a specific Forge feature."""
    
    # Build cumulative feature list (higher plans include all lower features)
    available_features = []
    plan_hierarchy = [SigilPlan.FREE, SigilPlan.PRO, SigilPlan.TEAM, SigilPlan.ENTERPRISE]
    
    for plan in plan_hierarchy:
        available_features.extend(FEATURE_ACCESS.get(plan, []))
        if plan == user_plan:
            break
    
    return feature in available_features


def get_plans_with_feature(feature: ForgeFeature) -> List[str]:
    """Get list of plans that include a specific feature."""
    plans = []
    plan_hierarchy = [SigilPlan.FREE, SigilPlan.PRO, SigilPlan.TEAM, SigilPlan.ENTERPRISE]
    cumulative_features = []
    
    for plan in plan_hierarchy:
        cumulative_features.extend(FEATURE_ACCESS.get(plan, []))
        if feature in cumulative_features:
            plans.append(plan.value)
    
    return plans


async def get_user_subscription_info(user_id: str) -> Dict[str, Any]:
    """Fetch user's subscription and team information from database."""
    
    # Get user with team information
    query = """
        SELECT u.*, t.plan as team_plan, t.name as team_name, 
               t.id as team_id, u.role as team_role
        FROM users u
        LEFT JOIN teams t ON u.team_id = t.id
        WHERE u.id = :user_id
    """
    user_data = await db.select_one_raw(query, {"user_id": user_id})
    
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Determine effective plan (user plan or team plan, whichever is higher)
    user_plan = SigilPlan(user_data.get("subscription_plan", "free").lower())
    team_plan = SigilPlan(user_data.get("team_plan", "free").lower()) if user_data.get("team_id") else SigilPlan.FREE
    
    # Use the higher of the two plans
    plan_hierarchy = [SigilPlan.FREE, SigilPlan.PRO, SigilPlan.TEAM, SigilPlan.ENTERPRISE]
    effective_plan = team_plan if plan_hierarchy.index(team_plan) > plan_hierarchy.index(user_plan) else user_plan
    
    return {
        "subscription_plan": effective_plan,
        "team_id": user_data.get("team_id"),
        "team_role": TeamRole(user_data.get("team_role", "member")) if user_data.get("team_id") else None,
        "team_name": user_data.get("team_name"),
    }


# ---------------------------------------------------------------------------
# Dependency Functions
# ---------------------------------------------------------------------------


async def get_forge_user(
    current_user: UserResponse = Depends(get_current_user_unified)
) -> ForgeUser:
    """Get current user with Forge subscription information."""
    
    # Fetch subscription and team info
    sub_info = await get_user_subscription_info(current_user.id)
    
    # Get API usage from cache
    usage_key = f"api_usage:{current_user.id}:{datetime.utcnow().strftime('%Y-%m-%d-%H')}"
    api_calls = await cache.get(usage_key) or 0
    
    return ForgeUser(
        id=current_user.id,
        email=current_user.email,
        name=current_user.name,
        created_at=current_user.created_at,
        subscription_plan=sub_info["subscription_plan"],
        team_id=sub_info.get("team_id"),
        team_role=sub_info.get("team_role"),
        api_calls_this_period=int(api_calls),
    )


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------


def requires_forge_feature(feature: ForgeFeature):
    """Decorator to enforce Forge feature access."""
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract user from function parameters
            forge_user = None
            for key, value in kwargs.items():
                if isinstance(value, ForgeUser):
                    forge_user = value
                    break
            
            if not forge_user:
                # Try to get from positional args
                for arg in args:
                    if isinstance(arg, ForgeUser):
                        forge_user = arg
                        break
            
            if not forge_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Check if user has custom override for this feature
            if feature in forge_user.disabled_features:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Feature {feature.value} has been disabled for your account"
                )
            
            if feature in forge_user.enabled_features:
                # User has explicit access override
                return await func(*args, **kwargs)
            
            # Check plan-based access
            if not has_forge_access(forge_user.subscription_plan, feature):
                required_plans = get_plans_with_feature(feature)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "feature_not_available",
                        "feature": feature.value,
                        "current_plan": forge_user.subscription_plan.value,
                        "required_plans": required_plans,
                        "upgrade_url": f"{settings.cors_origins[0]}/upgrade?feature={feature.value}"
                    }
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def requires_team_role(required_role: TeamRole = TeamRole.MEMBER):
    """Decorator to enforce team access with specific role."""
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            forge_user = None
            for key, value in kwargs.items():
                if isinstance(value, ForgeUser):
                    forge_user = value
                    break
            
            if not forge_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            if not forge_user.team_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You must be part of a team to access this resource"
                )
            
            # Check role hierarchy
            if forge_user.team_role:
                role_hierarchy = [TeamRole.MEMBER, TeamRole.ADMIN, TeamRole.OWNER]
                user_level = role_hierarchy.index(forge_user.team_role)
                required_level = role_hierarchy.index(required_role)
                
                if user_level < required_level:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Requires {required_role.value} role or higher"
                    )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def apply_rate_limit(request: Request, forge_user: ForgeUser):
    """Apply plan-based rate limiting (non-decorator for flexibility)."""
    
    rate_limit = RATE_LIMITS.get(forge_user.subscription_plan, 100)
    
    # Track in cache with hourly window
    usage_key = f"api_usage:{forge_user.id}:{datetime.utcnow().strftime('%Y-%m-%d-%H')}"
    
    async def check_and_increment():
        current = await cache.get(usage_key) or 0
        if int(current) >= rate_limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "rate_limit_exceeded",
                    "limit": rate_limit,
                    "period": "hour",
                    "retry_after": 3600 - (datetime.utcnow().minute * 60 + datetime.utcnow().second),
                    "upgrade_url": f"{settings.cors_origins[0]}/upgrade"
                }
            )
        
        # Increment counter
        await cache.incr(usage_key, ttl=3600)
        return int(current) + 1
    
    return check_and_increment()


# ---------------------------------------------------------------------------
# Data Access Filters
# ---------------------------------------------------------------------------


class DataAccessFilter:
    """Ensure users can only access their authorized data."""
    
    @staticmethod
    def apply_user_filter(query: str, user_id: str) -> str:
        """Add user ID filter to SQL queries."""
        # Ensure query has WHERE clause
        if "WHERE" in query.upper():
            return f"{query} AND user_id = :user_id"
        else:
            return f"{query} WHERE user_id = :user_id"
    
    @staticmethod
    def apply_team_filter(query: str, team_id: Optional[str]) -> str:
        """Add team ID filter for team-scoped queries."""
        if not team_id:
            # No team access
            if "WHERE" in query.upper():
                return f"{query} AND 1=0"  # Return no results
            else:
                return f"{query} WHERE 1=0"
        
        if "WHERE" in query.upper():
            return f"{query} AND team_id = :team_id"
        else:
            return f"{query} WHERE team_id = :team_id"
    
    @staticmethod
    def apply_org_filter(query: str, org_id: Optional[str]) -> str:
        """Add organization ID filter."""
        if not org_id:
            if "WHERE" in query.upper():
                return f"{query} AND 1=0"
            else:
                return f"{query} WHERE 1=0"
        
        if "WHERE" in query.upper():
            return f"{query} AND organization_id = :org_id"
        else:
            return f"{query} WHERE organization_id = :org_id"
    
    @staticmethod
    async def filter_results(results: List[Dict], forge_user: ForgeUser, scope: str = "user") -> List[Dict]:
        """Filter results based on user's access level."""
        if scope == "user":
            return [r for r in results if r.get("user_id") == forge_user.id]
        elif scope == "team":
            if not forge_user.team_id:
                return []
            return [r for r in results if r.get("team_id") == forge_user.team_id]
        elif scope == "organization":
            if not forge_user.organization_id:
                return []
            return [r for r in results if r.get("organization_id") == forge_user.organization_id]
        
        return results


# ---------------------------------------------------------------------------
# Audit Logging
# ---------------------------------------------------------------------------


class AuditAction(str, Enum):
    """Audit event types."""
    
    # Forge tool actions
    TOOL_TRACKED = "tool_tracked"
    TOOL_UNTRACKED = "tool_untracked"
    TOOL_REVIEWED = "tool_reviewed"
    
    # Stack actions
    STACK_CREATED = "stack_created"
    STACK_UPDATED = "stack_updated"
    STACK_DELETED = "stack_deleted"
    STACK_SHARED = "stack_shared"
    
    # Team actions
    TEAM_MEMBER_ADDED = "team_member_added"
    TEAM_MEMBER_REMOVED = "team_member_removed"
    TEAM_ROLE_CHANGED = "team_role_changed"
    
    # Settings and configuration
    SETTINGS_CHANGED = "settings_changed"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    
    # Data operations
    DATA_EXPORTED = "data_exported"
    DATA_IMPORTED = "data_imported"
    
    # Security events
    PERMISSION_DENIED = "permission_denied"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class AuditLogger:
    """Audit logging for Enterprise customers."""
    
    @staticmethod
    async def log_action(
        user_id: str,
        action: AuditAction,
        resource_type: str,
        resource_id: str,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> None:
        """Log an audit event (Enterprise only)."""
        
        # Check if user has Enterprise plan
        sub_info = await get_user_subscription_info(user_id)
        if sub_info["subscription_plan"] != SigilPlan.ENTERPRISE:
            # Only log for Enterprise customers
            return
        
        audit_event = {
            "user_id": user_id,
            "action": action.value,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "metadata": metadata or {},
            "ip_address": ip_address,
            "user_agent": user_agent,
            "timestamp": datetime.utcnow()
        }
        
        # Store in database
        await db.insert("audit_logs", audit_event)
        
        # Also log to application logger for monitoring
        logger.info(
            "AUDIT: User %s performed %s on %s/%s",
            user_id,
            action.value,
            resource_type,
            resource_id,
            extra={"audit_event": audit_event}
        )
    
    @staticmethod
    async def get_audit_logs(
        forge_user: ForgeUser,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        action: Optional[AuditAction] = None,
        resource_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Retrieve audit logs (Enterprise only)."""
        
        if forge_user.subscription_plan != SigilPlan.ENTERPRISE:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Audit logs are only available for Enterprise customers"
            )
        
        query = "SELECT * FROM audit_logs WHERE 1=1"
        params = {}
        
        # Apply filters based on user's role
        if forge_user.org_role == OrganizationRole.OWNER:
            # Can see all organization logs
            query = DataAccessFilter.apply_org_filter(query, forge_user.organization_id)
            params["organization_id"] = forge_user.organization_id
        elif forge_user.team_role in [TeamRole.OWNER, TeamRole.ADMIN]:
            # Can see team logs
            query = DataAccessFilter.apply_team_filter(query, forge_user.team_id)
            params["team_id"] = forge_user.team_id
        else:
            # Can only see own logs
            query = DataAccessFilter.apply_user_filter(query, forge_user.id)
            params["user_id"] = forge_user.id
        
        # Apply date filters
        if start_date:
            query += " AND timestamp >= :start_date"
            params["start_date"] = start_date
        
        if end_date:
            query += " AND timestamp <= :end_date"
            params["end_date"] = end_date
        
        # Apply action filter
        if action:
            query += " AND action = :action"
            params["action"] = action.value
        
        # Apply resource type filter
        if resource_type:
            query += " AND resource_type = :resource_type"
            params["resource_type"] = resource_type
        
        # Order and limit
        query += " ORDER BY timestamp DESC"
        query += f" LIMIT {limit}"
        
        results = await db.fetch_all_raw(query, params)
        return [dict(row) for row in results]


def audit_action(action: AuditAction, resource_type: str):
    """Decorator to automatically log actions for Enterprise users."""
    
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            result = await func(request, *args, **kwargs)
            
            # Log action for Enterprise customers
            forge_user = None
            for key, value in kwargs.items():
                if isinstance(value, ForgeUser):
                    forge_user = value
                    break
            
            if forge_user and forge_user.subscription_plan == SigilPlan.ENTERPRISE:
                # Extract resource ID from result or kwargs
                resource_id = "unknown"
                if isinstance(result, dict):
                    resource_id = result.get("id", resource_id)
                elif hasattr(result, "id"):
                    resource_id = str(result.id)
                
                # Get request metadata
                ip_address = request.client.host if request.client else None
                user_agent = request.headers.get("User-Agent")
                
                # Log the action
                await AuditLogger.log_action(
                    user_id=forge_user.id,
                    action=action,
                    resource_type=resource_type,
                    resource_id=str(resource_id),
                    ip_address=ip_address,
                    user_agent=user_agent
                )
            
            return result
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------


async def add_security_headers(request: Request, call_next):
    """Add security headers to all Forge API responses."""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Content Security Policy for API responses
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    
    # HSTS (if using HTTPS in production)
    if not settings.debug:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
    
    return response


# ---------------------------------------------------------------------------
# Export Security Context
# ---------------------------------------------------------------------------


class ForgeSecurityContext:
    """Container for all Forge security components."""
    
    plans = SigilPlan
    features = ForgeFeature
    roles = TeamRole
    
    # Access control
    has_access = has_forge_access
    get_required_plans = get_plans_with_feature
    
    # Decorators
    require_feature = requires_forge_feature
    require_team_role = requires_team_role
    
    # Data filters
    filters = DataAccessFilter
    
    # Audit logging
    audit = AuditLogger
    audit_action_decorator = audit_action
    
    # Rate limiting
    check_rate_limit = apply_rate_limit
    
    # Dependencies
    get_user = get_forge_user


# Export main security context
forge_security = ForgeSecurityContext()