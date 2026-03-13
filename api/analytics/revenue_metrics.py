"""
Revenue Analytics and Business Metrics
Comprehensive analytics for tracking MRR, conversion rates, churn analysis, and business KPIs.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
from dataclasses import dataclass
from decimal import Decimal

from api.database import db

logger = logging.getLogger(__name__)


@dataclass
class MRRData:
    """Monthly Recurring Revenue data."""

    current_mrr: Decimal
    mrr_growth_rate: float
    mrr_by_plan: Dict[str, Decimal]
    mrr_trend_12m: List[Dict[str, Any]]


@dataclass
class ConversionMetrics:
    """User conversion funnel metrics."""

    total_signups: int
    free_to_pro_conversion_rate: float
    pro_to_team_conversion_rate: float
    conversion_by_cohort: Dict[str, float]
    time_to_conversion_avg_days: float


@dataclass
class ChurnAnalysis:
    """Customer churn analysis."""

    monthly_churn_rate: float
    churn_by_plan: Dict[str, float]
    churn_by_tenure: Dict[str, float]
    churn_reasons: Dict[str, int]
    at_risk_customers: List[Dict[str, Any]]


@dataclass
class LTVAnalysis:
    """Customer Lifetime Value analysis."""

    avg_ltv: Decimal
    ltv_by_plan: Dict[str, Decimal]
    ltv_to_cac_ratio: float
    payback_period_months: float


@dataclass
class CreditAnalytics:
    """Credit usage and monetization analytics."""

    credits_consumed_trend: List[Dict[str, Any]]
    credit_purchase_revenue: Decimal
    avg_credits_per_user: float
    credit_monetization_rate: float
    top_credit_features: List[Dict[str, Any]]


class RevenueAnalytics:
    """Service for revenue analytics and business metrics."""

    async def get_mrr_data(self, months_back: int = 12) -> MRRData:
        """Get Monthly Recurring Revenue data and trends."""
        try:
            # Current MRR calculation
            current_mrr = await db.fetch_one("""
                SELECT 
                    SUM(CASE 
                        WHEN plan = 'pro' AND billing_interval = 'monthly' THEN 29.0
                        WHEN plan = 'pro' AND billing_interval = 'annual' THEN 19.33  -- 232/12
                        WHEN plan = 'team' AND billing_interval = 'monthly' THEN 99.0
                        WHEN plan = 'team' AND billing_interval = 'annual' THEN 66.0  -- 792/12
                        ELSE 0
                    END) as current_mrr
                FROM subscriptions
                WHERE status = 'active'
                AND plan != 'free'
            """)

            # MRR by plan
            mrr_by_plan_data = await db.fetch_all(
                """
                SELECT 
                    plan,
                    SUM(CASE 
                        WHEN plan = 'pro' AND billing_interval = 'monthly' THEN 29.0
                        WHEN plan = 'pro' AND billing_interval = 'annual' THEN 19.33
                        WHEN plan = 'team' AND billing_interval = 'monthly' THEN 99.0
                        WHEN plan = 'team' AND billing_interval = 'annual' THEN 66.0
                        ELSE 0
                    END) as plan_mrr
                FROM subscriptions
                WHERE status = 'active'
                AND plan != 'free'
                GROUP BY plan
            """,
                {},
            )

            # MRR trend for last 12 months
            mrr_trend = await self._calculate_mrr_trend(months_back)

            # Calculate growth rate
            growth_rate = 0.0
            if len(mrr_trend) >= 2:
                current = mrr_trend[-1]["mrr"]
                previous = mrr_trend[-2]["mrr"]
                if previous > 0:
                    growth_rate = (current - previous) / previous

            mrr_by_plan = {
                row["plan"]: Decimal(str(row["plan_mrr"] or 0))
                for row in mrr_by_plan_data
            }

            return MRRData(
                current_mrr=Decimal(str(current_mrr["current_mrr"] or 0)),
                mrr_growth_rate=growth_rate,
                mrr_by_plan=mrr_by_plan,
                mrr_trend_12m=mrr_trend,
            )

        except Exception as e:
            logger.exception(f"Failed to get MRR data: {e}")
            raise

    async def get_conversion_metrics(self) -> ConversionMetrics:
        """Get user conversion funnel metrics."""
        try:
            # Total signups (last 90 days)
            signups = await db.fetch_one("""
                SELECT COUNT(*) as total_signups
                FROM users
                WHERE created_at >= NOW() - INTERVAL 90 DAY
            """)

            # Free to Pro conversion
            free_to_pro = await db.fetch_one("""
                SELECT 
                    COUNT(CASE WHEN s.plan = 'pro' THEN 1 END) as pro_users,
                    COUNT(*) as total_users
                FROM users u
                LEFT JOIN subscriptions s ON u.id = s.user_id
                WHERE u.created_at >= NOW() - INTERVAL 90 DAY
            """)

            # Pro to Team conversion
            pro_to_team = await db.fetch_one("""
                SELECT 
                    COUNT(CASE WHEN plan = 'team' THEN 1 END) as team_users,
                    COUNT(*) as pro_users_total
                FROM subscriptions
                WHERE plan IN ('pro', 'team')
                AND created_at >= NOW() - INTERVAL 90 DAY
            """)

            # Conversion by monthly cohort (last 6 months)
            cohort_conversions = await self._calculate_cohort_conversions()

            # Average time to conversion
            avg_time_to_conversion = await db.fetch_one("""
                SELECT 
                    AVG(DATEDIFF(s.created_at, u.created_at)) as avg_days
                FROM users u
                JOIN subscriptions s ON u.id = s.user_id
                WHERE s.plan != 'free'
                AND u.created_at >= NOW() - INTERVAL 180 DAY
                AND s.created_at >= u.created_at
            """)

            # Calculate rates
            total_users = free_to_pro["total_users"] or 1
            pro_users = free_to_pro["pro_users"] or 0
            free_to_pro_rate = pro_users / total_users

            pro_total = pro_to_team["pro_users_total"] or 1
            team_users = pro_to_team["team_users"] or 0
            pro_to_team_rate = team_users / pro_total

            return ConversionMetrics(
                total_signups=signups["total_signups"] or 0,
                free_to_pro_conversion_rate=free_to_pro_rate,
                pro_to_team_conversion_rate=pro_to_team_rate,
                conversion_by_cohort=cohort_conversions,
                time_to_conversion_avg_days=float(
                    avg_time_to_conversion["avg_days"] or 0
                ),
            )

        except Exception as e:
            logger.exception(f"Failed to get conversion metrics: {e}")
            raise

    async def get_churn_analysis(self) -> ChurnAnalysis:
        """Get comprehensive churn analysis."""
        try:
            # Monthly churn rate
            monthly_churn = await db.fetch_one("""
                SELECT 
                    COUNT(CASE WHEN status = 'canceled' AND updated_at >= NOW() - INTERVAL 30 DAY THEN 1 END) as churned,
                    COUNT(*) as total_active_start_month
                FROM subscriptions
                WHERE plan != 'free'
                AND created_at <= NOW() - INTERVAL 30 DAY
            """)

            churn_rate = 0.0
            if monthly_churn["total_active_start_month"] > 0:
                churn_rate = (
                    monthly_churn["churned"] / monthly_churn["total_active_start_month"]
                )

            # Churn by plan
            churn_by_plan_data = await db.fetch_all(
                """
                SELECT 
                    plan,
                    COUNT(CASE WHEN status = 'canceled' AND updated_at >= NOW() - INTERVAL 30 DAY THEN 1 END) as churned,
                    COUNT(*) as total_for_plan
                FROM subscriptions
                WHERE plan != 'free'
                AND created_at <= NOW() - INTERVAL 30 DAY
                GROUP BY plan
            """,
                {},
            )

            churn_by_plan = {}
            for row in churn_by_plan_data:
                if row["total_for_plan"] > 0:
                    churn_by_plan[row["plan"]] = row["churned"] / row["total_for_plan"]
                else:
                    churn_by_plan[row["plan"]] = 0.0

            # Churn by tenure
            churn_by_tenure = await self._calculate_churn_by_tenure()

            # At-risk customers (past due, low credit usage, etc.)
            at_risk = await self._identify_at_risk_customers()

            # Mock churn reasons (would come from cancellation surveys)
            churn_reasons = {
                "price_too_high": 35,
                "not_enough_value": 25,
                "found_alternative": 20,
                "technical_issues": 12,
                "other": 8,
            }

            return ChurnAnalysis(
                monthly_churn_rate=churn_rate,
                churn_by_plan=churn_by_plan,
                churn_by_tenure=churn_by_tenure,
                churn_reasons=churn_reasons,
                at_risk_customers=at_risk,
            )

        except Exception as e:
            logger.exception(f"Failed to get churn analysis: {e}")
            raise

    async def get_ltv_analysis(self) -> LTVAnalysis:
        """Get Customer Lifetime Value analysis."""
        try:
            # Calculate average LTV
            ltv_data = await db.fetch_one("""
                SELECT 
                    AVG(CASE 
                        WHEN plan = 'pro' AND billing_interval = 'monthly' THEN 29.0 * 12  -- Assume 1 year avg
                        WHEN plan = 'pro' AND billing_interval = 'annual' THEN 232.0
                        WHEN plan = 'team' AND billing_interval = 'monthly' THEN 99.0 * 12
                        WHEN plan = 'team' AND billing_interval = 'annual' THEN 792.0
                        ELSE 0
                    END) as avg_ltv,
                    
                    AVG(CASE 
                        WHEN plan = 'pro' THEN DATEDIFF(COALESCE(updated_at, NOW()), created_at)
                        ELSE NULL
                    END) as avg_pro_tenure_days,
                    
                    AVG(CASE 
                        WHEN plan = 'team' THEN DATEDIFF(COALESCE(updated_at, NOW()), created_at)
                        ELSE NULL
                    END) as avg_team_tenure_days
                FROM subscriptions
                WHERE plan != 'free'
            """)

            # LTV by plan
            ltv_by_plan = {
                "pro": Decimal("348.00"),  # 29 * 12 months average
                "team": Decimal("1188.00"),  # 99 * 12 months average
            }

            # Mock CAC and payback period calculations
            # In reality, these would be calculated from marketing spend data
            avg_cac = Decimal("75.00")  # Average Customer Acquisition Cost
            avg_ltv = Decimal(str(ltv_data["avg_ltv"] or 348))

            ltv_to_cac_ratio = float(avg_ltv / avg_cac) if avg_cac > 0 else 0.0

            # Payback period in months
            monthly_revenue_pro = Decimal("29.00")
            payback_period = (
                float(avg_cac / monthly_revenue_pro) if monthly_revenue_pro > 0 else 0.0
            )

            return LTVAnalysis(
                avg_ltv=avg_ltv,
                ltv_by_plan=ltv_by_plan,
                ltv_to_cac_ratio=ltv_to_cac_ratio,
                payback_period_months=payback_period,
            )

        except Exception as e:
            logger.exception(f"Failed to get LTV analysis: {e}")
            raise

    async def get_credit_analytics(self) -> CreditAnalytics:
        """Get credit usage and monetization analytics."""
        try:
            # Credit consumption trend (last 12 months)
            consumption_trend = await db.fetch_all(
                """
                SELECT 
                    DATE_FORMAT(created_at, '%Y-%m') as month,
                    SUM(ABS(credits_amount)) as credits_consumed
                FROM credit_transactions
                WHERE created_at >= NOW() - INTERVAL 12 MONTH
                AND credits_amount < 0  -- Consumption
                GROUP BY DATE_FORMAT(created_at, '%Y-%m')
                ORDER BY month
            """,
                {},
            )

            # Credit purchase revenue
            purchase_revenue = await db.fetch_one("""
                SELECT 
                    SUM(JSON_EXTRACT(metadata, '$.price_usd')) as total_revenue,
                    COUNT(*) as total_purchases
                FROM credit_transactions
                WHERE transaction_type = 'purchase'
                AND created_at >= NOW() - INTERVAL 12 MONTH
            """)

            # Average credits per user
            avg_credits = await db.fetch_one("""
                SELECT AVG(credits_balance) as avg_balance
                FROM user_credits
            """)

            # Credit monetization rate (% of consumed credits that were purchased)
            monetization_data = await db.fetch_one("""
                SELECT 
                    SUM(CASE WHEN transaction_type = 'purchase' THEN credits_amount ELSE 0 END) as purchased,
                    SUM(ABS(CASE WHEN credits_amount < 0 THEN credits_amount ELSE 0 END)) as consumed
                FROM credit_transactions
                WHERE created_at >= NOW() - INTERVAL 12 MONTH
            """)

            monetization_rate = 0.0
            if monetization_data["consumed"] and monetization_data["consumed"] > 0:
                monetization_rate = (
                    monetization_data["purchased"] or 0
                ) / monetization_data["consumed"]

            # Top credit consuming features
            top_features = await db.fetch_all(
                """
                SELECT 
                    JSON_EXTRACT(metadata, '$.feature_type') as feature,
                    SUM(ABS(credits_amount)) as credits_used,
                    COUNT(*) as usage_count
                FROM credit_transactions
                WHERE credits_amount < 0
                AND created_at >= NOW() - INTERVAL 30 DAY
                GROUP BY JSON_EXTRACT(metadata, '$.feature_type')
                ORDER BY credits_used DESC
                LIMIT 10
            """,
                {},
            )

            consumption_trend_list = [
                {
                    "month": row["month"],
                    "credits_consumed": int(row["credits_consumed"] or 0),
                }
                for row in consumption_trend
            ]

            top_features_list = [
                {
                    "feature": row["feature"] or "unknown",
                    "credits_used": int(row["credits_used"] or 0),
                    "usage_count": int(row["usage_count"] or 0),
                }
                for row in top_features
            ]

            return CreditAnalytics(
                credits_consumed_trend=consumption_trend_list,
                credit_purchase_revenue=Decimal(
                    str(purchase_revenue["total_revenue"] or 0)
                ),
                avg_credits_per_user=float(avg_credits["avg_balance"] or 0),
                credit_monetization_rate=monetization_rate,
                top_credit_features=top_features_list,
            )

        except Exception as e:
            logger.exception(f"Failed to get credit analytics: {e}")
            raise

    async def get_revenue_dashboard_summary(self) -> Dict[str, Any]:
        """Get comprehensive revenue dashboard data."""
        try:
            mrr_data = await self.get_mrr_data()
            conversion_metrics = await self.get_conversion_metrics()
            churn_analysis = await self.get_churn_analysis()
            ltv_analysis = await self.get_ltv_analysis()
            credit_analytics = await self.get_credit_analytics()

            return {
                "mrr": {
                    "current": float(mrr_data.current_mrr),
                    "growth_rate": mrr_data.mrr_growth_rate,
                    "by_plan": {k: float(v) for k, v in mrr_data.mrr_by_plan.items()},
                    "trend_12m": mrr_data.mrr_trend_12m[-6:],  # Last 6 months
                },
                "conversions": {
                    "total_signups": conversion_metrics.total_signups,
                    "free_to_pro_rate": conversion_metrics.free_to_pro_conversion_rate,
                    "pro_to_team_rate": conversion_metrics.pro_to_team_conversion_rate,
                    "avg_time_to_convert": conversion_metrics.time_to_conversion_avg_days,
                },
                "churn": {
                    "monthly_rate": churn_analysis.monthly_churn_rate,
                    "by_plan": churn_analysis.churn_by_plan,
                    "at_risk_count": len(churn_analysis.at_risk_customers),
                },
                "ltv": {
                    "avg_ltv": float(ltv_analysis.avg_ltv),
                    "ltv_to_cac_ratio": ltv_analysis.ltv_to_cac_ratio,
                    "payback_period_months": ltv_analysis.payback_period_months,
                },
                "credits": {
                    "purchase_revenue": float(credit_analytics.credit_purchase_revenue),
                    "avg_per_user": credit_analytics.avg_credits_per_user,
                    "monetization_rate": credit_analytics.credit_monetization_rate,
                    "consumption_trend": credit_analytics.credits_consumed_trend[-6:],
                },
                "kpis": {
                    "monthly_churn": churn_analysis.monthly_churn_rate,
                    "ltv_cac_ratio": ltv_analysis.ltv_to_cac_ratio,
                    "conversion_rate": conversion_metrics.free_to_pro_conversion_rate,
                    "mrr_growth": mrr_data.mrr_growth_rate,
                },
                "generated_at": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.exception(f"Failed to get revenue dashboard summary: {e}")
            raise

    async def _calculate_mrr_trend(self, months_back: int) -> List[Dict[str, Any]]:
        """Calculate MRR trend for historical months."""
        try:
            trend_data = []
            for i in range(months_back, 0, -1):
                month_start = datetime.utcnow() - timedelta(days=30 * i)
                month_key = month_start.strftime("%Y-%m")

                # This is a simplified calculation - in reality you'd track historical subscription states
                mrr = await db.fetch_one(
                    """
                    SELECT 
                        SUM(CASE 
                            WHEN plan = 'pro' AND billing_interval = 'monthly' THEN 29.0
                            WHEN plan = 'pro' AND billing_interval = 'annual' THEN 19.33
                            WHEN plan = 'team' AND billing_interval = 'monthly' THEN 99.0
                            WHEN plan = 'team' AND billing_interval = 'annual' THEN 66.0
                            ELSE 0
                        END) as month_mrr
                    FROM subscriptions
                    WHERE status = 'active'
                    AND plan != 'free'
                    AND created_at <= :month_end
                """,
                    {"month_end": month_start + timedelta(days=30)},
                )

                trend_data.append(
                    {"month": month_key, "mrr": float(mrr["month_mrr"] or 0)}
                )

            return trend_data

        except Exception as e:
            logger.exception(f"Failed to calculate MRR trend: {e}")
            return []

    async def _calculate_cohort_conversions(self) -> Dict[str, float]:
        """Calculate conversion rates by signup cohort."""
        try:
            # Simplified cohort conversion calculation
            cohorts = {}
            for i in range(6):  # Last 6 months
                cohort_month = (datetime.utcnow() - timedelta(days=30 * i)).strftime(
                    "%Y-%m"
                )

                # Mock cohort conversion data
                # In reality, track actual user journeys
                cohorts[cohort_month] = 0.15 + (
                    i * 0.02
                )  # Newer cohorts convert better

            return cohorts

        except Exception as e:
            logger.exception(f"Failed to calculate cohort conversions: {e}")
            return {}

    async def _calculate_churn_by_tenure(self) -> Dict[str, float]:
        """Calculate churn rates by customer tenure."""
        try:
            tenure_buckets = {
                "0-3_months": 0.0,
                "3-6_months": 0.0,
                "6-12_months": 0.0,
                "12+_months": 0.0,
            }

            churn_data = await db.fetch_all(
                """
                SELECT 
                    CASE 
                        WHEN DATEDIFF(updated_at, created_at) <= 90 THEN '0-3_months'
                        WHEN DATEDIFF(updated_at, created_at) <= 180 THEN '3-6_months'
                        WHEN DATEDIFF(updated_at, created_at) <= 365 THEN '6-12_months'
                        ELSE '12+_months'
                    END as tenure_bucket,
                    COUNT(*) as total,
                    COUNT(CASE WHEN status = 'canceled' THEN 1 END) as churned
                FROM subscriptions
                WHERE plan != 'free'
                AND updated_at >= NOW() - INTERVAL 12 MONTH
                GROUP BY tenure_bucket
            """,
                {},
            )

            for row in churn_data:
                if row["total"] > 0:
                    tenure_buckets[row["tenure_bucket"]] = row["churned"] / row["total"]

            return tenure_buckets

        except Exception as e:
            logger.exception(f"Failed to calculate churn by tenure: {e}")
            return {}

    async def _identify_at_risk_customers(self) -> List[Dict[str, Any]]:
        """Identify customers at risk of churning."""
        try:
            # Criteria: past due, low usage, or support tickets
            at_risk = await db.fetch_all(
                """
                SELECT 
                    u.email,
                    s.plan,
                    s.status,
                    uc.credits_balance,
                    uc.credits_used_month,
                    DATEDIFF(NOW(), s.updated_at) as days_since_last_activity
                FROM users u
                JOIN subscriptions s ON u.id = s.user_id
                LEFT JOIN user_credits uc ON u.id = uc.user_id
                WHERE s.plan != 'free'
                AND (
                    s.status = 'past_due'
                    OR uc.credits_used_month < 100  -- Low usage
                    OR DATEDIFF(NOW(), s.updated_at) > 30  -- Inactive
                )
                ORDER BY days_since_last_activity DESC
                LIMIT 20
            """,
                {},
            )

            return [
                {
                    "email": row["email"],
                    "plan": row["plan"],
                    "status": row["status"],
                    "credits_balance": int(row["credits_balance"] or 0),
                    "credits_used_month": int(row["credits_used_month"] or 0),
                    "days_inactive": int(row["days_since_last_activity"] or 0),
                    "risk_score": min(
                        100,
                        int(row["days_since_last_activity"] or 0)
                        + (100 - int(row["credits_used_month"] or 0)),
                    ),
                }
                for row in at_risk
            ]

        except Exception as e:
            logger.exception(f"Failed to identify at-risk customers: {e}")
            return []


# Global analytics instance
revenue_analytics = RevenueAnalytics()
