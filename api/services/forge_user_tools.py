"""
Forge User Tools Service

Handles user tool tracking, trust score monitoring, and recommendation logic
for Forge premium features.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from api.database import db

logger = logging.getLogger(__name__)


class ForgeUserToolsService:
    """Service for managing user tool tracking and recommendations."""
    
    def __init__(self):
        self.trust_score_cache = {}
        self.cache_ttl = 300  # 5 minutes
    
    async def get_trust_score(self, ecosystem: str, package_name: str) -> float:
        """Get trust score for a tool from public scans with caching."""
        
        cache_key = f"{ecosystem}:{package_name}"
        
        # Check cache first
        if cache_key in self.trust_score_cache:
            cached_data = self.trust_score_cache[cache_key]
            if datetime.now(timezone.utc) - cached_data["timestamp"] < timedelta(seconds=self.cache_ttl):
                return cached_data["trust_score"]
        
        # Fetch from database
        scan = await db.select_one("public_scans", {
            "ecosystem": ecosystem,
            "package_name": package_name
        })
        
        trust_score = 50.0  # Default neutral score
        if scan:
            risk_score = scan.get("risk_score", 0.0)
            trust_score = max(0.0, 100.0 - (risk_score * 5))
        
        # Cache the result
        self.trust_score_cache[cache_key] = {
            "trust_score": trust_score,
            "timestamp": datetime.now(timezone.utc)
        }
        
        return trust_score
    
    async def get_user_tool_recommendations(
        self,
        user_id: str,
        category: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get personalized tool recommendations based on user's tracked tools."""
        
        try:
            # Get user's tracked tools to understand preferences
            tracked_tools = await db.select("forge_user_tools", {"user_id": user_id})
            
            if not tracked_tools:
                # New user - return popular tools
                return await self._get_popular_tools(category, limit)
            
            # Analyze user preferences
            user_ecosystems = set(tool["ecosystem"] for tool in tracked_tools)
            user_categories = set()
            
            # Get categories for tracked tools
            for tool in tracked_tools:
                classification = await db.select_one("forge_classification", {
                    "ecosystem": tool["ecosystem"],
                    "package_name": tool["tool_id"]
                })
                if classification:
                    user_categories.add(classification["category"])
            
            # Build recommendation filters
            filters = {}
            if category:
                filters["category"] = category
            elif user_categories:
                # Filter by user's preferred categories
                filters["category"] = list(user_categories)[0]  # Simplified
            
            # Get tools user hasn't tracked yet
            tracked_tool_ids = {f"{t['ecosystem']}:{t['tool_id']}" for t in tracked_tools}
            
            candidates = await db.select(
                "forge_classification",
                filters,
                order_by="confidence_score",
                order_desc=True,
                limit=limit * 3  # Get more to filter
            )
            
            # Filter out already tracked tools and score recommendations
            recommendations = []
            for candidate in candidates:
                tool_key = f"{candidate['ecosystem']}:{candidate['package_name']}"
                if tool_key not in tracked_tool_ids:
                    trust_score = await self.get_trust_score(
                        candidate["ecosystem"],
                        candidate["package_name"]
                    )
                    
                    # Calculate recommendation score
                    rec_score = self._calculate_recommendation_score(
                        candidate,
                        user_ecosystems,
                        user_categories,
                        trust_score
                    )
                    
                    recommendations.append({
                        "tool_id": candidate["package_name"],
                        "ecosystem": candidate["ecosystem"],
                        "category": candidate["category"],
                        "confidence_score": candidate.get("confidence_score", 0.0),
                        "trust_score": trust_score,
                        "recommendation_score": rec_score,
                        "reason": self._get_recommendation_reason(
                            candidate, user_ecosystems, user_categories
                        )
                    })
            
            # Sort by recommendation score and return top N
            recommendations.sort(key=lambda x: x["recommendation_score"], reverse=True)
            return recommendations[:limit]
            
        except Exception as e:
            logger.error(f"Failed to get recommendations for user {user_id}: {e}")
            return await self._get_popular_tools(category, limit)
    
    async def get_trust_score_trends(
        self,
        user_id: str,
        days_back: int = 30
    ) -> List[Dict[str, Any]]:
        """Get trust score trends for user's tracked tools."""
        
        try:
            # Get user's tracked tools
            tracked_tools = await db.select("forge_user_tools", {"user_id": user_id})
            
            if not tracked_tools:
                return []
            
            trends = []
            
            for tool in tracked_tools:
                # Get recent scan history for this tool
                # This is simplified - in production you'd track score changes over time
                current_score = await self.get_trust_score(
                    tool["ecosystem"],
                    tool["tool_id"]
                )
                
                trends.append({
                    "tool_id": tool["tool_id"],
                    "ecosystem": tool["ecosystem"],
                    "current_score": current_score,
                    "score_change": 0.0,  # Would be calculated from historical data
                    "trend": "stable",    # Would be "improving", "declining", "stable"
                    "last_checked": datetime.now(timezone.utc).isoformat()
                })
            
            return trends
            
        except Exception as e:
            logger.error(f"Failed to get trust score trends for user {user_id}: {e}")
            return []
    
    async def check_security_alerts(
        self,
        user_id: str
    ) -> List[Dict[str, Any]]:
        """Check for security alerts on user's tracked tools."""
        
        try:
            # Get user's tracked tools
            tracked_tools = await db.select("forge_user_tools", {"user_id": user_id})
            
            if not tracked_tools:
                return []
            
            alerts = []
            
            for tool in tracked_tools:
                # Get recent scans for this tool
                recent_scans = await db.select(
                    "public_scans",
                    {
                        "ecosystem": tool["ecosystem"],
                        "package_name": tool["tool_id"]
                    },
                    order_by="scanned_at",
                    order_desc=True,
                    limit=5
                )
                
                for scan in recent_scans:
                    # Check if scan has high-risk findings
                    risk_score = scan.get("risk_score", 0.0)
                    if risk_score > 70:  # High risk threshold
                        alerts.append({
                            "tool_id": tool["tool_id"],
                            "ecosystem": tool["ecosystem"],
                            "alert_type": "high_risk_detected",
                            "risk_score": risk_score,
                            "scan_date": scan.get("scanned_at"),
                            "findings_count": scan.get("findings_count", 0),
                            "severity": "high" if risk_score > 85 else "medium"
                        })
            
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to check security alerts for user {user_id}: {e}")
            return []
    
    async def get_usage_statistics(
        self,
        user_id: str,
        days_back: int = 30
    ) -> Dict[str, Any]:
        """Get usage statistics for a user's tool tracking activity."""
        
        try:
            # Get user's tracked tools
            tracked_tools = await db.select("forge_user_tools", {"user_id": user_id})
            
            # Get analytics events for user
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)
            
            # This would use proper SQL in production
            events = await db.select("forge_analytics_events", {
                "user_id": user_id
            })
            
            # Filter events by date (simplified)
            recent_events = [
                e for e in events 
                if e.get("timestamp", cutoff_date) >= cutoff_date
            ]
            
            # Calculate statistics
            stats = {
                "total_tools_tracked": len(tracked_tools),
                "tools_starred": len([t for t in tracked_tools if t.get("is_starred", False)]),
                "total_events": len(recent_events),
                "event_breakdown": {},
                "ecosystem_distribution": {},
                "category_distribution": {}
            }
            
            # Event breakdown
            for event in recent_events:
                event_type = event.get("event_type", "unknown")
                stats["event_breakdown"][event_type] = stats["event_breakdown"].get(event_type, 0) + 1
            
            # Ecosystem distribution
            for tool in tracked_tools:
                ecosystem = tool["ecosystem"]
                stats["ecosystem_distribution"][ecosystem] = stats["ecosystem_distribution"].get(ecosystem, 0) + 1
            
            # Category distribution (would need to join with classifications)
            # Simplified for now
            stats["category_distribution"] = {"unknown": len(tracked_tools)}
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get usage statistics for user {user_id}: {e}")
            return {}
    
    def _calculate_recommendation_score(
        self,
        candidate: Dict[str, Any],
        user_ecosystems: set,
        user_categories: set,
        trust_score: float
    ) -> float:
        """Calculate a recommendation score for a tool candidate."""
        
        score = 0.0
        
        # Ecosystem match bonus
        if candidate["ecosystem"] in user_ecosystems:
            score += 30.0
        
        # Category match bonus
        if candidate["category"] in user_categories:
            score += 25.0
        
        # Trust score component (0-40 points)
        score += (trust_score / 100.0) * 40.0
        
        # Confidence score component (0-5 points)
        score += candidate.get("confidence_score", 0.0)
        
        return min(100.0, score)
    
    def _get_recommendation_reason(
        self,
        candidate: Dict[str, Any],
        user_ecosystems: set,
        user_categories: set
    ) -> str:
        """Generate a human-readable reason for the recommendation."""
        
        reasons = []
        
        if candidate["ecosystem"] in user_ecosystems:
            reasons.append(f"matches your {candidate['ecosystem']} preference")
        
        if candidate["category"] in user_categories:
            reasons.append(f"similar to your {candidate['category']} tools")
        
        if not reasons:
            reasons.append("popular in the community")
        
        return f"Recommended because it {' and '.join(reasons)}"
    
    async def _get_popular_tools(
        self,
        category: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get popular tools as fallback recommendations."""
        
        try:
            filters = {}
            if category:
                filters["category"] = category
            
            tools = await db.select(
                "forge_classification",
                filters,
                order_by="confidence_score",
                order_desc=True,
                limit=limit
            )
            
            results = []
            for tool in tools:
                trust_score = await self.get_trust_score(
                    tool["ecosystem"],
                    tool["package_name"]
                )
                
                results.append({
                    "tool_id": tool["package_name"],
                    "ecosystem": tool["ecosystem"],
                    "category": tool["category"],
                    "confidence_score": tool.get("confidence_score", 0.0),
                    "trust_score": trust_score,
                    "recommendation_score": 50.0,  # Neutral score
                    "reason": "Popular in the community"
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to get popular tools: {e}")
            return []


# Global service instance
forge_user_tools_service = ForgeUserToolsService()