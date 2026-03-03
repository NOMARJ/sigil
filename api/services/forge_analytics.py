"""
Forge Analytics Service

Handles event tracking, caching, and analytics data aggregation for Forge premium features.
Supports real-time analytics with Redis caching and plan-based feature gating.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import aioredis
from fastapi import HTTPException

from api.database import db
from api.models import (
    ForgeAnalyticsEvent,
    ForgeEventType,
    PersonalAnalyticsResponse,
    TeamAnalyticsResponse,
    OrganizationAnalyticsResponse,
)

logger = logging.getLogger(__name__)


class ForgeAnalyticsService:
    """Service for tracking and aggregating Forge analytics events."""

    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis: Optional[aioredis.Redis] = None
        self.cache_ttl = 300  # 5 minutes default cache TTL

    async def initialize(self):
        """Initialize Redis connection."""
        try:
            self.redis = await aioredis.from_url(
                self.redis_url, encoding="utf-8", decode_responses=True
            )
            logger.info("Analytics service Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed, using in-memory cache: {e}")
            self.redis = None

    async def track_event(
        self,
        user_id: str,
        event_type: ForgeEventType,
        event_data: Dict[str, Any],
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> bool:
        """Track a Forge analytics event."""
        try:
            # Create event record
            event = ForgeAnalyticsEvent(
                user_id=user_id,
                event_type=event_type,
                event_data=event_data,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            # Store in database
            await db.insert(
                "forge_analytics_events",
                {
                    "user_id": event.user_id,
                    "event_type": event.event_type.value,
                    "event_data": json.dumps(event.event_data),
                    "session_id": event.session_id,
                    "ip_address": event.ip_address,
                    "user_agent": event.user_agent,
                    "timestamp": event.timestamp,
                },
            )

            # Update real-time caches
            await self._update_realtime_caches(event)

            # Handle specific event types
            await self._process_event_side_effects(event)

            return True

        except Exception as e:
            logger.error(f"Failed to track event {event_type}: {e}")
            return False

    async def track_events_batch(
        self,
        user_id: str,
        events: List[Tuple[ForgeEventType, Dict[str, Any]]],
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> int:
        """Track multiple events in batch for better performance."""
        success_count = 0

        try:
            # Prepare batch inserts
            batch_records = []
            for event_type, event_data in events:
                batch_records.append(
                    {
                        "user_id": user_id,
                        "event_type": event_type.value,
                        "event_data": json.dumps(event_data),
                        "session_id": session_id,
                        "ip_address": ip_address,
                        "user_agent": user_agent,
                        "timestamp": datetime.utcnow(),
                    }
                )

            # Batch insert to database
            await db.insert_batch("forge_analytics_events", batch_records)

            # Update caches for each event
            for record in batch_records:
                event = ForgeAnalyticsEvent(
                    **{
                        **record,
                        "event_type": ForgeEventType(record["event_type"]),
                        "event_data": json.loads(record["event_data"]),
                    }
                )
                await self._update_realtime_caches(event)
                await self._process_event_side_effects(event)

            success_count = len(batch_records)

        except Exception as e:
            logger.error(f"Failed to track batch events: {e}")

        return success_count

    async def get_personal_analytics(
        self,
        user_id: str,
        days_back: int = 30,
        categories: Optional[List[str]] = None,
        ecosystems: Optional[List[str]] = None,
    ) -> PersonalAnalyticsResponse:
        """Get personal analytics for Pro+ users."""

        # Check cache first
        cache_key = f"analytics:personal:{user_id}:{days_back}"
        if categories:
            cache_key += f":cat:{','.join(sorted(categories))}"
        if ecosystems:
            cache_key += f":eco:{','.join(sorted(ecosystems))}"

        cached = await self._get_cached(cache_key)
        if cached:
            return PersonalAnalyticsResponse(**cached)

        try:
            # Calculate date range
            start_date = datetime.utcnow() - timedelta(days=days_back)

            # Build filters
            filters = {"user_id": user_id, "timestamp__gte": start_date}

            # Get events
            events = await db.select(
                "forge_analytics_events",
                filters,
                order_by="timestamp",
                order_desc=True,
                limit=10000,
            )

            # Aggregate analytics data
            analytics_data = await self._aggregate_personal_analytics(
                events, days_back, categories, ecosystems
            )

            # Cache results
            await self._set_cached(cache_key, analytics_data.model_dump(), 600)

            return analytics_data

        except Exception as e:
            logger.error(f"Failed to get personal analytics: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    async def get_team_analytics(
        self, team_id: str, days_back: int = 30
    ) -> TeamAnalyticsResponse:
        """Get team analytics for Team+ users."""

        cache_key = f"analytics:team:{team_id}:{days_back}"
        cached = await self._get_cached(cache_key)
        if cached:
            return TeamAnalyticsResponse(**cached)

        try:
            # Get team members
            team_members = await db.select("users", {"team_id": team_id})
            if not team_members:
                raise HTTPException(status_code=404, detail="Team not found")

            member_ids = [m["id"] for m in team_members]

            # Calculate date range
            start_date = datetime.utcnow() - timedelta(days=days_back)

            # Get team events
            team_events = []
            for member_id in member_ids:
                events = await db.select(
                    "forge_analytics_events",
                    {"user_id": member_id, "timestamp__gte": start_date},
                    limit=5000,
                )
                team_events.extend(events)

            # Get team tools and stacks
            team_tools = await db.select(
                "forge_user_tools", {"user_id": member_ids[0] if member_ids else None}
            )

            team_stacks = await db.select("forge_user_stacks", {"team_id": team_id})

            # Aggregate team analytics
            analytics_data = await self._aggregate_team_analytics(
                team_events, team_tools, team_stacks, team_id, days_back
            )

            # Cache results
            await self._set_cached(cache_key, analytics_data.model_dump(), 300)

            return analytics_data

        except Exception as e:
            logger.error(f"Failed to get team analytics: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    async def get_organization_analytics(
        self, organization_id: str
    ) -> OrganizationAnalyticsResponse:
        """Get organization analytics for Enterprise users."""

        cache_key = f"analytics:org:{organization_id}"
        cached = await self._get_cached(cache_key)
        if cached:
            return OrganizationAnalyticsResponse(**cached)

        try:
            # Get organization teams
            org_teams = await db.select("teams", {"organization_id": organization_id})
            if not org_teams:
                raise HTTPException(status_code=404, detail="Organization not found")

            # Aggregate data across all teams
            departments = []
            total_tools = 0
            risk_scores = []

            for team in org_teams:
                team_analytics = await self.get_team_analytics(team["id"])
                departments.append(
                    {
                        "team_id": team["id"],
                        "team_name": team["name"],
                        "active_members": team_analytics.active_members,
                        "tools_tracked": team_analytics.total_tools_tracked,
                        "security_score": team_analytics.security_compliance_score,
                    }
                )
                total_tools += team_analytics.total_tools_tracked
                risk_scores.append(team_analytics.security_compliance_score)

            # Calculate organization-level metrics
            analytics_data = OrganizationAnalyticsResponse(
                organization_id=organization_id,
                departments=departments,
                total_tools_in_use=total_tools,
                estimated_monthly_costs=await self._calculate_cost_estimates(org_teams),
                cost_optimization_opportunities=await self._identify_cost_optimizations(
                    org_teams
                ),
                organization_risk_score=sum(risk_scores) / len(risk_scores)
                if risk_scores
                else 100.0,
                high_risk_tools=await self._get_high_risk_tools(org_teams),
                compliance_metrics=await self._get_compliance_metrics(org_teams),
                security_trends=await self._get_security_trends(org_teams),
            )

            # Cache results
            await self._set_cached(cache_key, analytics_data.model_dump(), 600)

            return analytics_data

        except Exception as e:
            logger.error(f"Failed to get organization analytics: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    async def invalidate_user_cache(self, user_id: str):
        """Invalidate all cached analytics for a user."""
        if not self.redis:
            return

        try:
            # Get all cache keys for this user
            pattern = f"analytics:*:{user_id}:*"
            keys = await self.redis.keys(pattern)

            if keys:
                await self.redis.delete(*keys)

        except Exception as e:
            logger.error(f"Failed to invalidate user cache: {e}")

    async def invalidate_team_cache(self, team_id: str):
        """Invalidate all cached analytics for a team."""
        if not self.redis:
            return

        try:
            pattern = f"analytics:team:{team_id}:*"
            keys = await self.redis.keys(pattern)

            if keys:
                await self.redis.delete(*keys)

        except Exception as e:
            logger.error(f"Failed to invalidate team cache: {e}")

    # Private helper methods

    async def _update_realtime_caches(self, event: ForgeAnalyticsEvent):
        """Update real-time analytics caches."""
        if not self.redis:
            return

        try:
            # Update daily activity counter
            today = datetime.utcnow().strftime("%Y-%m-%d")
            await self.redis.hincrby(
                f"analytics:daily:{today}",
                f"user:{event.user_id}:{event.event_type.value}",
                1,
            )

            # Set expiry for daily counters
            await self.redis.expire(f"analytics:daily:{today}", 86400 * 7)  # 7 days

            # Update tool popularity counters
            if event.event_type in [
                ForgeEventType.TOOL_VIEWED,
                ForgeEventType.TOOL_TRACKED,
            ]:
                tool_id = event.event_data.get("tool_id")
                if tool_id:
                    await self.redis.zincrby(
                        "analytics:tool_popularity:30d",
                        1,
                        f"{tool_id}:{event.event_data.get('ecosystem', '')}",
                    )
                    await self.redis.expire("analytics:tool_popularity:30d", 86400 * 30)

        except Exception as e:
            logger.error(f"Failed to update real-time caches: {e}")

    async def _process_event_side_effects(self, event: ForgeAnalyticsEvent):
        """Process side effects for specific event types."""
        try:
            if event.event_type == ForgeEventType.TOOL_TRACKED:
                await self._update_user_tools_table(event)
            elif event.event_type == ForgeEventType.STACK_CREATED:
                await self._update_user_stacks_table(event)

        except Exception as e:
            logger.error(f"Failed to process event side effects: {e}")

    async def _update_user_tools_table(self, event: ForgeAnalyticsEvent):
        """Update forge_user_tools table when tool is tracked."""
        tool_data = event.event_data

        if not all(k in tool_data for k in ["tool_id", "ecosystem", "tool_name"]):
            return

        # Check if tool is already tracked
        existing = await db.select_one(
            "forge_user_tools",
            {
                "user_id": event.user_id,
                "tool_id": tool_data["tool_id"],
                "ecosystem": tool_data["ecosystem"],
            },
        )

        if existing:
            # Update existing record
            await db.update(
                "forge_user_tools",
                {"id": existing["id"]},
                {
                    "last_viewed": event.timestamp,
                    "view_count": existing["view_count"] + 1,
                },
            )
        else:
            # Insert new record
            await db.insert(
                "forge_user_tools",
                {
                    "user_id": event.user_id,
                    "tool_id": tool_data["tool_id"],
                    "ecosystem": tool_data["ecosystem"],
                    "tool_name": tool_data["tool_name"],
                    "category": tool_data.get("category"),
                    "tracked_at": event.timestamp,
                    "last_viewed": event.timestamp,
                    "view_count": 1,
                },
            )

    async def _update_user_stacks_table(self, event: ForgeAnalyticsEvent):
        """Update forge_user_stacks table when stack is created."""
        stack_data = event.event_data

        if not all(k in stack_data for k in ["name", "tools"]):
            return

        await db.insert(
            "forge_user_stacks",
            {
                "user_id": event.user_id,
                "team_id": stack_data.get("team_id"),
                "name": stack_data["name"],
                "description": stack_data.get("description"),
                "tools": json.dumps(stack_data["tools"]),
                "use_case": stack_data.get("use_case"),
                "is_public": stack_data.get("is_public", False),
            },
        )

    async def _aggregate_personal_analytics(
        self,
        events: List[Dict[str, Any]],
        days_back: int,
        categories: Optional[List[str]],
        ecosystems: Optional[List[str]],
    ) -> PersonalAnalyticsResponse:
        """Aggregate personal analytics from events."""

        # Initialize counters
        total_tool_views = 0
        total_tools_tracked = 0
        total_searches = 0
        total_stacks_created = 0

        most_viewed_tools = {}
        most_tracked_tools = {}
        discovery_sources = {}
        category_preferences = {}
        ecosystem_usage = {}
        daily_activity = {str(i): 0 for i in range(7)}  # Day of week
        hourly_activity = {str(i): 0 for i in range(24)}  # Hour of day

        # Process events
        for event in events:
            event_type = event["event_type"]
            event_data = json.loads(event["event_data"])
            timestamp = event["timestamp"]

            # Apply filters
            if categories and event_data.get("category") not in categories:
                continue
            if ecosystems and event_data.get("ecosystem") not in ecosystems:
                continue

            # Count events by type
            if event_type == "tool_viewed":
                total_tool_views += 1
                tool_key = f"{event_data.get('tool_id')}:{event_data.get('ecosystem')}"
                most_viewed_tools[tool_key] = most_viewed_tools.get(tool_key, 0) + 1
            elif event_type == "tool_tracked":
                total_tools_tracked += 1
                tool_key = f"{event_data.get('tool_id')}:{event_data.get('ecosystem')}"
                most_tracked_tools[tool_key] = most_tracked_tools.get(tool_key, 0) + 1
            elif event_type == "search_performed":
                total_searches += 1
                source = event_data.get("source", "unknown")
                discovery_sources[source] = discovery_sources.get(source, 0) + 1
            elif event_type == "stack_created":
                total_stacks_created += 1

            # Category and ecosystem usage
            if "category" in event_data:
                cat = event_data["category"]
                category_preferences[cat] = category_preferences.get(cat, 0) + 1

            if "ecosystem" in event_data:
                eco = event_data["ecosystem"]
                ecosystem_usage[eco] = ecosystem_usage.get(eco, 0) + 1

            # Activity patterns
            if isinstance(timestamp, datetime):
                weekday = str(timestamp.weekday())
                hour = str(timestamp.hour)
                daily_activity[weekday] = daily_activity.get(weekday, 0) + 1
                hourly_activity[hour] = hourly_activity.get(hour, 0) + 1

        # Convert tool counters to lists
        most_viewed_list = [
            {"tool_key": k, "count": v}
            for k, v in sorted(
                most_viewed_tools.items(), key=lambda x: x[1], reverse=True
            )[:10]
        ]
        most_tracked_list = [
            {"tool_key": k, "count": v}
            for k, v in sorted(
                most_tracked_tools.items(), key=lambda x: x[1], reverse=True
            )[:10]
        ]

        return PersonalAnalyticsResponse(
            period_days=days_back,
            total_tool_views=total_tool_views,
            total_tools_tracked=total_tools_tracked,
            total_searches=total_searches,
            total_stacks_created=total_stacks_created,
            most_viewed_tools=most_viewed_list,
            most_tracked_tools=most_tracked_list,
            discovery_sources=discovery_sources,
            category_preferences=category_preferences,
            ecosystem_usage=ecosystem_usage,
            trust_score_trends=[],  # TODO: Implement trust score trends
            security_findings_timeline=[],  # TODO: Implement security findings
            daily_activity=daily_activity,
            hourly_activity=hourly_activity,
        )

    async def _aggregate_team_analytics(
        self,
        events: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        stacks: List[Dict[str, Any]],
        team_id: str,
        days_back: int,
    ) -> TeamAnalyticsResponse:
        """Aggregate team analytics from events and data."""

        # Get unique active members
        active_members = len(set(e["user_id"] for e in events))

        # Count tools and stacks
        total_tools_tracked = len(tools)
        total_stacks_shared = len([s for s in stacks if s.get("is_public")])

        # Calculate security compliance
        security_score = await self._calculate_team_security_score(team_id)

        return TeamAnalyticsResponse(
            period_days=days_back,
            team_id=team_id,
            active_members=active_members,
            total_tools_tracked=total_tools_tracked,
            total_stacks_shared=total_stacks_shared,
            total_scans_performed=0,  # TODO: Get from scans table
            most_popular_tools=[],  # TODO: Aggregate from tools
            shared_tool_stacks=[s for s in stacks if s.get("is_public")],
            member_activity=[],  # TODO: Aggregate member activity
            tool_adoption_timeline=[],  # TODO: Calculate adoption timeline
            category_distribution={},  # TODO: Calculate from tools
            ecosystem_distribution={},  # TODO: Calculate from tools
            security_compliance_score=security_score,
            security_findings_summary={},  # TODO: Get from scans
            tools_needing_review=[],  # TODO: Get high-risk tools
        )

    async def _calculate_team_security_score(self, team_id: str) -> float:
        """Calculate team security compliance score."""
        try:
            # Use the SQL function we created
            result = await db.execute_raw(
                "SELECT dbo.fn_get_security_compliance_score(?) as score", (team_id,)
            )
            if result:
                return float(result[0]["score"])
            return 100.0
        except Exception:
            return 100.0

    async def _calculate_cost_estimates(
        self, teams: List[Dict[str, Any]]
    ) -> Dict[str, float]:
        """Calculate estimated monthly costs by category."""
        # Placeholder implementation
        return {"database": 150.0, "api": 200.0, "security": 100.0, "devops": 300.0}

    async def _identify_cost_optimizations(
        self, teams: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Identify cost optimization opportunities."""
        return [
            {
                "category": "Duplicate Tools",
                "description": "Multiple teams using similar database connectors",
                "potential_savings": 50.0,
            }
        ]

    async def _get_high_risk_tools(
        self, teams: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Get high-risk tools across organization."""
        return []  # TODO: Implement based on public_scans

    async def _get_compliance_metrics(
        self, teams: List[Dict[str, Any]]
    ) -> Dict[str, float]:
        """Get compliance metrics across organization."""
        return {
            "overall_compliance": 85.0,
            "teams_with_policies": 75.0,
            "tools_with_recent_scans": 90.0,
        }

    async def _get_security_trends(
        self, teams: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Get security trends across organization."""
        return []  # TODO: Implement based on trust score history

    async def _get_cached(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached data."""
        if not self.redis:
            return None

        try:
            data = await self.redis.get(key)
            return json.loads(data) if data else None
        except Exception:
            return None

    async def _set_cached(self, key: str, data: Dict[str, Any], ttl: int = None):
        """Set cached data."""
        if not self.redis:
            return

        try:
            await self.redis.set(
                key, json.dumps(data, default=str), ex=ttl or self.cache_ttl
            )
        except Exception as e:
            logger.error(f"Failed to set cache: {e}")


# Global analytics service instance
analytics_service = ForgeAnalyticsService()


async def track_forge_event(
    user_id: str,
    event_type: ForgeEventType,
    event_data: Dict[str, Any],
    session_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> bool:
    """Convenience function to track Forge analytics event."""
    return await analytics_service.track_event(
        user_id=user_id,
        event_type=event_type,
        event_data=event_data,
        session_id=session_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )
