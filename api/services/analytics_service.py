"""
Analytics Service for Sigil Pro Usage Tracking

Handles comprehensive tracking of LLM usage, threat discoveries, and user engagement
metrics to support business intelligence, cost optimization, and churn prediction.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, date
from decimal import Decimal
from typing import Dict, List, Optional, Any

from api.database import db
from usage_metrics import (
    DailyUsageReport,
    ChurnRiskMetrics,
    UserUsageStats,
    AnalyticsConfig,
)


logger = logging.getLogger(__name__)


class AnalyticsService:
    """Service for tracking Pro feature usage and generating business insights."""

    def __init__(self):
        self.config = AnalyticsConfig()

        # LLM cost estimates per 1K tokens (in cents)
        self._llm_costs = {
            "gpt-4": Decimal("3.0"),
            "gpt-4-turbo": Decimal("1.0"),
            "gpt-4o": Decimal("0.5"),
            "claude-3-opus": Decimal("1.5"),
            "claude-3-sonnet": Decimal("0.3"),
            "claude-3-haiku": Decimal("0.025"),
            "gemini-pro": Decimal("0.5"),
            "llama-2-70b": Decimal("0.065"),
        }

    # -------------------------------------------------------------------------
    # Usage Tracking Methods
    # -------------------------------------------------------------------------

    async def track_llm_usage(
        self,
        user_id: str,
        scan_id: str,
        model_used: str,
        tokens_used: int,
        processing_time_ms: int,
        insights_generated: List[Dict[str, Any]],
        cache_hit: bool = False,
        fallback_used: bool = False,
        cost_override: Optional[Decimal] = None,
    ) -> bool:
        """Track LLM API usage for cost and performance analytics."""

        try:
            cost_cents = cost_override or self._calculate_llm_cost(
                model_used, tokens_used
            )

            # Analyze insights to extract metrics
            threats_found = sum(
                1
                for insight in insights_generated
                if insight.get("confidence", 0) > 0.7
            )
            confidence_avg = (
                sum(insight.get("confidence", 0) for insight in insights_generated)
                / len(insights_generated)
                if insights_generated
                else 0.0
            )

            usage_details = {
                "scan_id": scan_id,
                "model_used": model_used,
                "tokens_used": tokens_used,
                "processing_time_ms": processing_time_ms,
                "cost_cents": float(cost_cents),
                "insights_generated": insights_generated,
                "threats_found": threats_found,
                "confidence_avg": confidence_avg,
                "cache_hit": cache_hit,
                "fallback_used": fallback_used,
            }

            await db.execute_procedure("sp_TrackLLMUsage", usage_details)
            return True
        except Exception as e:
            logger.exception(f"Failed to track LLM usage for user {user_id}: {e}")
            return False

    async def track_threat_discovery(
        self,
        user_id: str,
        threat_type: str,
        severity: str,
        confidence: float,
        scan_id: Optional[str] = None,
        file_path: Optional[str] = None,
        is_zero_day: bool = False,
        threat_pattern: Optional[str] = None,
        analysis_type: str = "llm_analysis",
        evidence_snippet: Optional[str] = None,
        remediation_steps: Optional[List[str]] = None,
    ) -> bool:
        """Track individual threat discoveries for trend analysis."""

        try:
            usage_details = {
                "user_id": user_id,
                "threat_type": threat_type,
                "severity": severity,
                "confidence": confidence,
                "scan_id": scan_id,
                "file_path": file_path,
                "is_zero_day": is_zero_day,
                "analysis_type": analysis_type,
                "evidence_snippet": evidence_snippet,
                "remediation_steps": json.dumps(remediation_steps or []),
            }

            await db.execute_procedure("sp_TrackThreatDiscovery", usage_details)
            return True
        except Exception as e:
            logger.exception(
                f"Failed to track threat discovery for user {user_id}: {e}"
            )
            return False

    async def track_pro_feature_usage(
        self,
        user_id: str,
        feature_type: str,
        usage_details: dict[str, Any],
        session_id: str | None = None,
    ) -> bool:
        try:
            payload = {
                "user_id": user_id,
                "feature_type": feature_type,
                "usage_details": json.dumps(usage_details),
                "session_id": session_id,
            }
            await db.execute_procedure("sp_TrackProFeatureUsage", payload)
            return True
        except Exception as exc:
            logger.exception("Failed to track pro feature usage: %s", exc)
            return False

    async def get_user_analytics_summary(
        self,
        user_id: str,
        start_date: datetime,
        end_date: datetime,
    ) -> dict[str, Any] | None:
        try:
            rows = await db.execute_procedure(
                "sp_GetUserAnalyticsSummary",
                {"user_id": user_id, "start_date": start_date, "end_date": end_date},
            )
            return rows[0] if rows else None
        except Exception as exc:
            logger.exception("Failed to get user analytics summary: %s", exc)
            return None

    async def get_threat_discovery_trends(
        self,
        user_id: str,
        threat_type: str,
        days: int = 7,
    ) -> list[dict[str, Any]]:
        try:
            return await db.execute_procedure(
                "sp_GetThreatDiscoveryTrends",
                {"user_id": user_id, "threat_type": threat_type, "days": days},
            )
        except Exception as exc:
            logger.exception("Failed to get threat discovery trends: %s", exc)
            return []

    async def track_api_performance(
        self,
        endpoint: str,
        method: str,
        response_time_ms: int,
        status_code: int,
        user_id: str | None = None,
        user_tier: str = "pro",
        features_used: list[str] | None = None,
        payload_size_bytes: int | None = None,
        timestamp: datetime | None = None,
    ) -> bool:
        try:
            payload = {
                "endpoint": endpoint,
                "method": method,
                "response_time_ms": response_time_ms,
                "status_code": status_code,
                "user_id": user_id,
                "user_tier": user_tier,
                "features_used": json.dumps(features_used or []),
                "payload_size_bytes": payload_size_bytes,
                "timestamp": timestamp or datetime.utcnow(),
            }
            await db.execute_procedure("sp_TrackAPIPerformance", payload)
            return True
        except Exception as exc:
            logger.exception("Failed to track API performance: %s", exc)
            return False

    async def get_performance_statistics(
        self,
        endpoint: str,
        hours: int = 24,
    ) -> list[dict[str, Any]]:
        try:
            return await db.execute_procedure(
                "sp_GetPerformanceStatistics",
                {"endpoint": endpoint, "hours": hours},
            )
        except Exception as exc:
            logger.exception("Failed to get performance statistics: %s", exc)
            return []

    async def anonymize_user_analytics(self, user_id: str) -> bool:
        try:
            await db.execute_procedure(
                "sp_AnonymizeUserAnalytics", {"user_id": user_id}
            )
            return True
        except Exception as exc:
            logger.exception("Failed to anonymize analytics: %s", exc)
            return False

    async def purge_expired_analytics(self, retention_days: int = 365) -> bool:
        try:
            await db.execute_procedure(
                "sp_PurgeExpiredAnalytics", {"retention_days": retention_days}
            )
            return True
        except Exception as exc:
            logger.exception("Failed to purge analytics: %s", exc)
            return False

    async def export_user_analytics(self, user_id: str) -> list[dict[str, Any]]:
        try:
            return await db.execute_procedure(
                "sp_ExportUserAnalytics", {"user_id": user_id}
            )
        except Exception as exc:
            logger.exception("Failed to export analytics: %s", exc)
            return []

    async def get_platform_statistics(self) -> dict[str, Any]:
        rows = await db.execute_procedure("sp_GetPlatformStatistics", {})
        return rows[0] if rows else {}

    async def generate_monthly_report(self, month: str) -> dict[str, Any]:
        rows = await db.execute_procedure("sp_GenerateMonthlyReport", {"month": month})
        return rows[0] if rows else {"month": month}

    async def process_analytics_batch(self, events: list[dict[str, Any]]) -> bool:
        try:
            for event in events:
                event_type = event.get("type")
                data = event.get("data", {})
                await db.execute_procedure(
                    "sp_ProcessAnalyticsEvent", {"type": event_type, **data}
                )
            return True
        except Exception as exc:
            logger.exception("Failed to process analytics batch: %s", exc)
            return False

    async def health_check(self) -> dict[str, Any]:
        rows = await db.execute_procedure("sp_AnalyticsHealthCheck", {})
        return rows[0] if rows else {"status": "unknown"}

    async def track_event(
        self,
        user_id: str,
        event_type: str,
        event_data: Optional[Dict[str, Any]] = None,
        tier: str = "pro",
    ) -> None:
        """Track general analytics events for business intelligence."""

        if not self.config.track_individual_events:
            return

        try:
            await db.execute(
                """
                INSERT INTO user_analytics (user_id, event_type, event_data, tier)
                VALUES (?, ?, ?, ?)
            """,
                (
                    user_id,
                    event_type,
                    json.dumps(event_data) if event_data else None,
                    tier,
                ),
            )

            logger.debug(f"Tracked event {event_type} for user {user_id}")

        except Exception as e:
            logger.exception(
                f"Failed to track event {event_type} for user {user_id}: {e}"
            )

    # -------------------------------------------------------------------------
    # Reporting and Analytics Methods
    # -------------------------------------------------------------------------

    async def get_daily_usage_report(
        self,
        start_date: datetime,
        end_date: datetime,
        user_ids: Optional[List[str]] = None,
    ) -> DailyUsageReport:
        """Generate comprehensive daily usage report for business intelligence."""

        try:
            # Base query for LLM usage stats
            user_filter = ""
            params = [start_date, end_date]

            if user_ids:
                placeholders = ",".join("?" * len(user_ids))
                user_filter = f"AND user_id IN ({placeholders})"
                params.extend(user_ids)

            # Get LLM usage statistics
            llm_stats = await db.fetch_one(
                f"""
                SELECT 
                    COUNT(*) as total_scans,
                    COUNT(DISTINCT user_id) as active_users,
                    SUM(tokens_used) as total_tokens,
                    SUM(cost_cents) as total_cost_cents,
                    AVG(CAST(processing_time_ms AS FLOAT)) as avg_processing_time,
                    SUM(insights_generated) as total_insights,
                    SUM(threats_found) as total_threats,
                    COUNT(CASE WHEN cache_hit = 1 THEN 1 END) as cache_hits,
                    COUNT(CASE WHEN fallback_used = 1 THEN 1 END) as fallbacks_used
                FROM llm_usage_metrics
                WHERE created_at BETWEEN ? AND ?
                {user_filter}
            """,
                params,
            )

            # Get zero-day discoveries
            zero_day_stats = await db.fetch_one(
                f"""
                SELECT COUNT(*) as zero_day_count
                FROM threat_discoveries
                WHERE created_at BETWEEN ? AND ? AND is_zero_day = 1
                {user_filter}
            """,
                params,
            )

            # Calculate rates
            total_scans = llm_stats.get("total_scans", 0) or 0
            cache_hit_rate = (
                (llm_stats.get("cache_hits", 0) or 0) / total_scans * 100
                if total_scans > 0
                else 0
            )
            fallback_rate = (
                (llm_stats.get("fallbacks_used", 0) or 0) / total_scans * 100
                if total_scans > 0
                else 0
            )

            return DailyUsageReport(
                date_range=(start_date, end_date),
                active_users=llm_stats.get("active_users", 0) or 0,
                llm_scans=total_scans,
                total_tokens=llm_stats.get("total_tokens", 0) or 0,
                total_cost=Decimal(str(llm_stats.get("total_cost_cents", 0) or 0))
                / 100,
                avg_processing_time=llm_stats.get("avg_processing_time", 0.0) or 0.0,
                insights_generated=llm_stats.get("total_insights", 0) or 0,
                threats_detected=llm_stats.get("total_threats", 0) or 0,
                zero_day_discoveries=zero_day_stats.get("zero_day_count", 0) or 0,
                cache_hit_rate=cache_hit_rate,
                fallback_rate=fallback_rate,
            )

        except Exception as e:
            logger.exception(f"Failed to generate daily usage report: {e}")
            return DailyUsageReport(
                date_range=(start_date, end_date),
                active_users=0,
                llm_scans=0,
                total_tokens=0,
                total_cost=Decimal("0.00"),
                avg_processing_time=0.0,
                insights_generated=0,
                threats_detected=0,
                zero_day_discoveries=0,
                cache_hit_rate=0.0,
                fallback_rate=0.0,
            )

    async def get_user_churn_risk(self, user_id: str) -> ChurnRiskMetrics:
        """Calculate comprehensive churn risk indicators for a Pro user."""

        try:
            # Get usage in last 30 days
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)

            usage_stats = await db.fetch_one(
                """
                SELECT 
                    COUNT(*) as scan_count,
                    MAX(created_at) as last_scan,
                    AVG(CASE WHEN threats_found > 0 THEN 1.0 ELSE 0.0 END) as threat_hit_rate,
                    AVG(CAST(processing_time_ms AS FLOAT)) / 1000 as avg_processing_time_sec
                FROM llm_usage_metrics
                WHERE user_id = ? AND created_at > ?
            """,
                (user_id, thirty_days_ago),
            )

            # Get engagement metrics
            engagement_stats = await db.fetch_one(
                """
                SELECT 
                    AVG(CAST(session_duration_minutes AS FLOAT)) as avg_session_duration,
                    COUNT(DISTINCT features_used) as unique_features_used
                FROM user_engagement_metrics
                WHERE user_id = ? AND date_tracked >= ?
            """,
                (user_id, thirty_days_ago.date()),
            )

            # Calculate risk score (0-100, higher = more risk)
            risk_score = 0
            risk_category = "HEALTHY"

            scan_count = usage_stats.get("scan_count", 0) or 0
            last_scan = usage_stats.get("last_scan")
            threat_hit_rate = usage_stats.get("threat_hit_rate", 0.0) or 0.0
            avg_session_duration = (
                engagement_stats.get("avg_session_duration", 0.0) or 0.0
            )

            # No usage in 30 days = high risk
            if scan_count == 0:
                risk_score = 90
                risk_category = "HIGH_RISK"
            else:
                # Low usage frequency (< 1 scan per week)
                if scan_count < 4:
                    risk_score += 25

                # No recent usage
                if last_scan:
                    days_since_last = (datetime.utcnow() - last_scan).days
                    if days_since_last > 14:
                        risk_score += 35
                    elif days_since_last > 7:
                        risk_score += 20

                # Low threat discovery rate indicates poor value perception
                if threat_hit_rate < 0.1:
                    risk_score += 20

                # Short session duration indicates low engagement
                if avg_session_duration < 5:
                    risk_score += 15

                # Determine risk category
                if risk_score >= 60:
                    risk_category = "HIGH_RISK"
                elif risk_score >= 35:
                    risk_category = "MEDIUM_RISK"
                elif threat_hit_rate < 0.2:
                    risk_category = "LOW_ENGAGEMENT"

            # Calculate feature adoption score
            unique_features = engagement_stats.get("unique_features_used", 0) or 0
            feature_adoption_score = min(
                unique_features / 5.0, 1.0
            )  # Assume 5 main features

            return ChurnRiskMetrics(
                user_id=user_id,
                risk_score=min(risk_score, 100),
                risk_category=risk_category,
                last_scan_date=last_scan,
                monthly_scans=scan_count,
                threat_hit_rate=threat_hit_rate,
                avg_session_duration=avg_session_duration,
                feature_adoption_score=feature_adoption_score,
            )

        except Exception as e:
            logger.exception(f"Failed to calculate churn risk for user {user_id}: {e}")
            return ChurnRiskMetrics(
                user_id=user_id,
                risk_score=50,  # Default to medium risk
                risk_category="UNKNOWN",
                last_scan_date=None,
                monthly_scans=0,
                threat_hit_rate=0.0,
                avg_session_duration=0.0,
                feature_adoption_score=0.0,
            )

    async def get_user_usage_stats(
        self, user_id: str, days: int = 30
    ) -> UserUsageStats:
        """Get personal usage statistics for user dashboard."""

        try:
            start_date = datetime.utcnow() - timedelta(days=days)
            period_start = start_date.date()

            # Get aggregated stats for the period
            period_stats = await db.fetch_one(
                """
                SELECT 
                    COUNT(*) as scans,
                    SUM(tokens_used) as tokens,
                    SUM(cost_cents) as cost_cents,
                    SUM(insights_generated) as insights,
                    SUM(threats_found) as threats
                FROM llm_usage_metrics
                WHERE user_id = ? AND created_at > ?
            """,
                (user_id, start_date),
            )

            # Get zero-day discoveries
            zero_days = await db.fetch_one(
                """
                SELECT COUNT(*) as zero_days
                FROM threat_discoveries
                WHERE user_id = ? AND created_at > ? AND is_zero_day = 1
            """,
                (user_id, start_date),
            )

            # Get daily breakdown
            daily_usage = await db.fetch_all(
                """
                SELECT 
                    CAST(created_at AS DATE) as scan_date,
                    COUNT(*) as scans,
                    SUM(tokens_used) as tokens,
                    SUM(insights_generated) as insights,
                    SUM(threats_found) as threats
                FROM llm_usage_metrics
                WHERE user_id = ? AND created_at > ?
                GROUP BY CAST(created_at AS DATE)
                ORDER BY scan_date DESC
            """,
                (user_id, start_date),
            )

            # Get top threat categories
            top_threats = await db.fetch_all(
                """
                SELECT 
                    threat_type,
                    COUNT(*) as count,
                    AVG(confidence) as avg_confidence
                FROM threat_discoveries
                WHERE user_id = ? AND created_at > ?
                GROUP BY threat_type
                ORDER BY count DESC
                LIMIT 5
            """,
                (user_id, start_date),
            )

            # Format results
            usage_by_day = [
                {
                    "date": row.get("scan_date"),
                    "scans": row.get("scans", 0),
                    "tokens": row.get("tokens", 0),
                    "insights": row.get("insights", 0),
                    "threats": row.get("threats", 0),
                }
                for row in daily_usage
            ]

            top_threat_categories = [
                {
                    "threat_type": row.get("threat_type"),
                    "count": row.get("count", 0),
                    "avg_confidence": round(row.get("avg_confidence", 0.0), 2),
                }
                for row in top_threats
            ]

            # TODO: Get actual plan limits from subscription service
            plan_limits = {
                "max_scans_per_month": 1000,
                "max_tokens_per_month": 100000,
                "max_cost_per_month": 50.00,
            }

            return UserUsageStats(
                user_id=user_id,
                current_period_start=period_start,
                scans_this_period=period_stats.get("scans", 0) or 0,
                tokens_used=period_stats.get("tokens", 0) or 0,
                cost_this_period=Decimal(str(period_stats.get("cost_cents", 0) or 0))
                / 100,
                threats_discovered=period_stats.get("threats", 0) or 0,
                zero_days_found=zero_days.get("zero_days", 0) or 0,
                plan_limits=plan_limits,
                usage_by_day=usage_by_day,
                top_threat_categories=top_threat_categories,
            )

        except Exception as e:
            logger.exception(f"Failed to get usage stats for user {user_id}: {e}")
            return UserUsageStats(
                user_id=user_id,
                current_period_start=date.today(),
                scans_this_period=0,
                tokens_used=0,
                cost_this_period=Decimal("0.00"),
                threats_discovered=0,
                zero_days_found=0,
                plan_limits={},
                usage_by_day=[],
                top_threat_categories=[],
            )

    # -------------------------------------------------------------------------
    # Private Helper Methods
    # -------------------------------------------------------------------------

    def _calculate_llm_cost(self, model: str, tokens: int) -> Decimal:
        """Calculate estimated cost for LLM usage in cents."""
        # Get cost per 1K tokens, default to reasonable estimate
        cost_per_1k = self._llm_costs.get(model, Decimal("1.0"))
        return cost_per_1k * tokens / 1000

    async def _update_daily_engagement(
        self, user_id: str, metrics: Dict[str, Any]
    ) -> None:
        """Update daily engagement metrics for a user."""

        if not self.config.aggregate_daily_metrics:
            return

        try:
            today = date.today()

            # Use upsert pattern for MSSQL
            await db.execute(
                """
                MERGE user_engagement_metrics AS target
                USING (VALUES (?, ?)) AS source (user_id, date_tracked)
                ON target.user_id = source.user_id AND target.date_tracked = source.date_tracked
                WHEN MATCHED THEN
                    UPDATE SET 
                        scans_performed = scans_performed + ?,
                        threats_discovered = threats_discovered + ?,
                        zero_days_found = zero_days_found + ?,
                        llm_tokens_used = llm_tokens_used + ?
                WHEN NOT MATCHED THEN
                    INSERT (user_id, date_tracked, scans_performed, threats_discovered, zero_days_found, llm_tokens_used)
                    VALUES (?, ?, ?, ?, ?, ?);
            """,
                (
                    user_id,
                    today,
                    metrics.get("scans_performed", 0),
                    metrics.get("threats_discovered", 0),
                    metrics.get("zero_days_found", 0),
                    metrics.get("llm_tokens_used", 0),
                    user_id,
                    today,
                    metrics.get("scans_performed", 0),
                    metrics.get("threats_discovered", 0),
                    metrics.get("zero_days_found", 0),
                    metrics.get("llm_tokens_used", 0),
                ),
            )

        except Exception as e:
            logger.exception(
                f"Failed to update daily engagement for user {user_id}: {e}"
            )


# Global service instance
analytics_service = AnalyticsService()
