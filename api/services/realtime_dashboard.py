"""
Real-time Dashboard Service

Handles real-time data updates, cache invalidation, and dashboard synchronization
for Forge analytics and premium features.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import WebSocket, WebSocketDisconnect
import redis.asyncio as aioredis

from api.database import db
from api.services.forge_analytics import analytics_service

logger = logging.getLogger(__name__)


class RealTimeDashboardService:
    """Service for managing real-time dashboard updates and WebSocket connections."""

    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis: Optional[aioredis.Redis] = None
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_subscriptions: Dict[
            str, List[str]
        ] = {}  # user_id -> [subscription_types]

    async def initialize(self):
        """Initialize Redis connection and pub/sub."""
        try:
            self.redis = await aioredis.from_url(
                self.redis_url, encoding="utf-8", decode_responses=True
            )
            logger.info("Real-time dashboard Redis connection established")

            # Start background task for processing updates
            asyncio.create_task(self._process_updates())

        except Exception as e:
            logger.warning(f"Redis connection failed, real-time updates disabled: {e}")
            self.redis = None

    async def connect_websocket(
        self, websocket: WebSocket, user_id: str, subscriptions: List[str]
    ):
        """Connect a user's WebSocket for real-time updates."""
        await websocket.accept()

        connection_id = f"{user_id}:{id(websocket)}"
        self.active_connections[connection_id] = websocket
        self.user_subscriptions[user_id] = subscriptions

        logger.info(
            f"WebSocket connected: {connection_id} with subscriptions {subscriptions}"
        )

        try:
            # Send initial dashboard data
            await self._send_initial_data(websocket, user_id, subscriptions)

            # Keep connection alive and handle incoming messages
            while True:
                try:
                    # Receive any client messages (ping/pong, subscription updates)
                    data = await websocket.receive_text()
                    await self._handle_client_message(websocket, user_id, data)
                except WebSocketDisconnect:
                    break

        except Exception as e:
            logger.error(f"WebSocket error for {connection_id}: {e}")
        finally:
            # Clean up connection
            if connection_id in self.active_connections:
                del self.active_connections[connection_id]
            if user_id in self.user_subscriptions:
                del self.user_subscriptions[user_id]
            logger.info(f"WebSocket disconnected: {connection_id}")

    async def broadcast_update(
        self,
        update_type: str,
        data: Dict[str, Any],
        target_users: Optional[List[str]] = None,
    ):
        """Broadcast real-time update to connected users."""
        if not self.redis:
            return

        update_message = {
            "type": update_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
            "target_users": target_users,
        }

        try:
            # Publish update to Redis channel
            await self.redis.publish("dashboard_updates", json.dumps(update_message))

            # Also send directly to connected WebSockets
            await self._send_to_websockets(update_message)

        except Exception as e:
            logger.error(f"Failed to broadcast update: {e}")

    async def invalidate_user_dashboard(self, user_id: str):
        """Invalidate dashboard cache and push fresh data to user."""
        try:
            # Invalidate analytics cache
            await analytics_service.invalidate_user_cache(user_id)

            # Get fresh data
            fresh_data = await self._get_fresh_dashboard_data(user_id)

            # Broadcast to user's connections
            await self.broadcast_update(
                update_type="dashboard_refresh", data=fresh_data, target_users=[user_id]
            )

        except Exception as e:
            logger.error(f"Failed to invalidate dashboard for user {user_id}: {e}")

    async def invalidate_team_dashboard(self, team_id: str):
        """Invalidate dashboard cache and push fresh data to team members."""
        try:
            # Get team members
            team_members = await db.select("users", {"team_id": team_id})
            user_ids = [m["id"] for m in team_members]

            # Invalidate team analytics cache
            await analytics_service.invalidate_team_cache(team_id)

            # Get fresh team data
            fresh_data = await self._get_fresh_team_data(team_id)

            # Broadcast to team members
            await self.broadcast_update(
                update_type="team_dashboard_refresh",
                data=fresh_data,
                target_users=user_ids,
            )

        except Exception as e:
            logger.error(f"Failed to invalidate team dashboard for team {team_id}: {e}")

    async def push_notification(self, user_id: str, notification: Dict[str, Any]):
        """Push real-time notification to user."""
        await self.broadcast_update(
            update_type="notification", data=notification, target_users=[user_id]
        )

    async def push_security_alert(self, team_id: str, alert: Dict[str, Any]):
        """Push security alert to team members."""
        try:
            team_members = await db.select("users", {"team_id": team_id})
            user_ids = [m["id"] for m in team_members]

            await self.broadcast_update(
                update_type="security_alert", data=alert, target_users=user_ids
            )

        except Exception as e:
            logger.error(f"Failed to push security alert: {e}")

    # Private helper methods

    async def _send_initial_data(
        self, websocket: WebSocket, user_id: str, subscriptions: List[str]
    ):
        """Send initial dashboard data to newly connected client."""
        try:
            initial_data = {
                "type": "initial_data",
                "data": {},
                "timestamp": datetime.utcnow().isoformat(),
            }

            # Load data based on subscriptions
            if "personal_analytics" in subscriptions:
                try:
                    personal = await analytics_service.get_personal_analytics(
                        user_id, 7
                    )
                    initial_data["data"]["personal_analytics"] = personal.model_dump()
                except Exception:
                    pass

            if "dashboard_stats" in subscriptions:
                initial_data["data"][
                    "dashboard_stats"
                ] = await self._get_dashboard_stats(user_id)

            if "realtime_events" in subscriptions:
                initial_data["data"]["recent_events"] = await self._get_recent_events(
                    user_id
                )

            await websocket.send_text(json.dumps(initial_data))

        except Exception as e:
            logger.error(f"Failed to send initial data: {e}")

    async def _handle_client_message(
        self, websocket: WebSocket, user_id: str, message: str
    ):
        """Handle incoming WebSocket messages from client."""
        try:
            data = json.loads(message)
            msg_type = data.get("type")

            if msg_type == "ping":
                await websocket.send_text(
                    json.dumps(
                        {"type": "pong", "timestamp": datetime.utcnow().isoformat()}
                    )
                )

            elif msg_type == "subscribe":
                # Update user subscriptions
                subscriptions = data.get("subscriptions", [])
                self.user_subscriptions[user_id] = subscriptions

            elif msg_type == "refresh":
                # Force refresh dashboard data
                await self.invalidate_user_dashboard(user_id)

        except Exception as e:
            logger.error(f"Failed to handle client message: {e}")

    async def _send_to_websockets(self, update_message: Dict[str, Any]):
        """Send update to relevant WebSocket connections."""
        if not self.active_connections:
            return

        update_type = update_message["type"]
        target_users = update_message.get("target_users")

        # Determine which connections to send to
        target_connections = []

        for connection_id, websocket in self.active_connections.items():
            user_id = connection_id.split(":")[0]

            # Check if this user should receive this update
            should_send = False

            if not target_users:
                should_send = True  # Broadcast to all
            elif user_id in target_users:
                should_send = True

            # Check subscription preferences
            user_subs = self.user_subscriptions.get(user_id, [])
            if (
                update_type in ["personal_analytics", "team_analytics"]
                and "analytics" not in user_subs
            ):
                should_send = False

            if should_send:
                target_connections.append((connection_id, websocket))

        # Send to target connections
        for connection_id, websocket in target_connections:
            try:
                await websocket.send_text(json.dumps(update_message))
            except Exception as e:
                logger.error(
                    f"Failed to send WebSocket message to {connection_id}: {e}"
                )
                # Remove failed connection
                if connection_id in self.active_connections:
                    del self.active_connections[connection_id]

    async def _process_updates(self):
        """Background task to process Redis pub/sub updates."""
        if not self.redis:
            return

        try:
            pubsub = self.redis.pubsub()
            await pubsub.subscribe("dashboard_updates")

            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        update_data = json.loads(message["data"])
                        await self._send_to_websockets(update_data)
                    except Exception as e:
                        logger.error(f"Failed to process update: {e}")

        except Exception as e:
            logger.error(f"Redis pub/sub processing failed: {e}")

    async def _get_fresh_dashboard_data(self, user_id: str) -> Dict[str, Any]:
        """Get fresh dashboard data for user."""
        try:
            # Get basic stats
            dashboard_data = {
                "user_id": user_id,
                "refreshed_at": datetime.utcnow().isoformat(),
                "stats": await self._get_dashboard_stats(user_id),
                "recent_events": await self._get_recent_events(user_id),
            }

            # Add analytics if user has access
            try:
                personal = await analytics_service.get_personal_analytics(user_id, 7)
                dashboard_data["analytics"] = personal.model_dump()
            except Exception:
                pass

            return dashboard_data

        except Exception as e:
            logger.error(f"Failed to get fresh dashboard data: {e}")
            return {}

    async def _get_fresh_team_data(self, team_id: str) -> Dict[str, Any]:
        """Get fresh team dashboard data."""
        try:
            team_data = {
                "team_id": team_id,
                "refreshed_at": datetime.utcnow().isoformat(),
            }

            # Add team analytics if available
            try:
                team_analytics = await analytics_service.get_team_analytics(team_id, 7)
                team_data["analytics"] = team_analytics.model_dump()
            except Exception:
                pass

            return team_data

        except Exception as e:
            logger.error(f"Failed to get fresh team data: {e}")
            return {}

    async def _get_dashboard_stats(self, user_id: str) -> Dict[str, Any]:
        """Get basic dashboard statistics for user."""
        try:
            # Get user's recent scans
            recent_scans = await db.select(
                "scans",
                {"user_id": user_id},
                order_by="created_at",
                order_desc=True,
                limit=10,
            )

            # Calculate basic stats
            stats = {
                "total_scans": len(recent_scans),
                "avg_risk_score": sum(s.get("risk_score", 0) for s in recent_scans)
                / max(len(recent_scans), 1),
                "high_risk_count": len(
                    [s for s in recent_scans if s.get("risk_score", 0) > 50]
                ),
                "last_scan": recent_scans[0].get("created_at")
                if recent_scans
                else None,
            }

            return stats

        except Exception as e:
            logger.error(f"Failed to get dashboard stats: {e}")
            return {}

    async def _get_recent_events(self, user_id: str) -> List[Dict[str, Any]]:
        """Get recent events for user."""
        try:
            # Get recent analytics events
            recent_events = await db.select(
                "forge_analytics_events",
                {"user_id": user_id},
                order_by="timestamp",
                order_desc=True,
                limit=20,
            )

            # Format for frontend
            formatted_events = []
            for event in recent_events:
                formatted_events.append(
                    {
                        "type": event.get("event_type"),
                        "data": json.loads(event.get("event_data", "{}")),
                        "timestamp": event.get("timestamp"),
                    }
                )

            return formatted_events

        except Exception as e:
            logger.error(f"Failed to get recent events: {e}")
            return []


# Global service instance
dashboard_service = RealTimeDashboardService()


# Convenience functions for triggering updates
async def trigger_user_dashboard_update(user_id: str):
    """Trigger real-time dashboard update for user."""
    await dashboard_service.invalidate_user_dashboard(user_id)


async def trigger_team_dashboard_update(team_id: str):
    """Trigger real-time dashboard update for team."""
    await dashboard_service.invalidate_team_dashboard(team_id)


async def send_security_notification(
    user_id: str, message: str, severity: str = "medium"
):
    """Send security notification to user."""
    notification = {
        "id": f"security_{datetime.utcnow().timestamp()}",
        "type": "security",
        "severity": severity,
        "message": message,
        "timestamp": datetime.utcnow().isoformat(),
        "user_id": user_id,
    }

    await dashboard_service.push_notification(user_id, notification)


async def send_team_security_alert(team_id: str, alert_data: Dict[str, Any]):
    """Send security alert to team."""
    alert = {
        "id": f"alert_{datetime.utcnow().timestamp()}",
        "type": "team_security_alert",
        "team_id": team_id,
        "timestamp": datetime.utcnow().isoformat(),
        **alert_data,
    }

    await dashboard_service.push_security_alert(team_id, alert)
