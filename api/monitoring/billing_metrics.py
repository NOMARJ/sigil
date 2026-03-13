"""
Billing Metrics and Monitoring
Comprehensive monitoring for billing operations, subscription health, and payment processing.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

from api.database import db
from api.config import settings

logger = logging.getLogger(__name__)


class AlertLevel(Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class BillingAlert:
    """Billing alert information."""

    level: AlertLevel
    title: str
    description: str
    metric_value: float
    threshold: float
    timestamp: datetime
    resolution: Optional[str] = None


@dataclass
class SubscriptionMetrics:
    """Subscription health metrics."""

    total_active: int
    total_canceled: int
    total_past_due: int
    new_subscriptions_24h: int
    churn_rate_30d: float
    revenue_mrr: float
    average_revenue_per_user: float


@dataclass
class PaymentMetrics:
    """Payment processing metrics."""

    successful_payments_24h: int
    failed_payments_24h: int
    success_rate: float
    failed_payment_recovery_rate: float
    total_revenue_24h: float
    webhook_processing_success_rate: float


@dataclass
class CreditMetrics:
    """Credit usage and purchase metrics."""

    total_credits_consumed_24h: int
    total_credits_purchased_24h: int
    average_credits_per_user: float
    top_credit_consumers: List[Dict[str, Any]]
    credit_purchase_revenue_24h: float


class BillingMonitor:
    """Service for monitoring billing operations and generating alerts."""

    def __init__(self):
        self.alert_thresholds = {
            "payment_success_rate": 0.95,  # 95%
            "webhook_processing_rate": 0.99,  # 99%
            "subscription_churn_rate": 0.10,  # 10%
            "failed_payment_spike": 10,  # 10 failures in an hour
        }

    async def get_subscription_metrics(self) -> SubscriptionMetrics:
        """Get current subscription health metrics."""
        try:
            # Get current subscription counts
            subscription_stats = await db.fetch_one("""
                SELECT 
                    COUNT(CASE WHEN status = 'active' THEN 1 END) as active_count,
                    COUNT(CASE WHEN status = 'canceled' THEN 1 END) as canceled_count,
                    COUNT(CASE WHEN status = 'past_due' THEN 1 END) as past_due_count
                FROM subscriptions
                WHERE plan != 'free'
            """)

            # Get new subscriptions in last 24 hours
            new_subs_24h = await db.fetch_one("""
                SELECT COUNT(*) as new_count
                FROM subscriptions
                WHERE created_at >= NOW() - INTERVAL 24 HOUR
                AND plan != 'free'
            """)

            # Calculate churn rate (last 30 days)
            churn_data = await db.fetch_one("""
                SELECT 
                    COUNT(CASE WHEN status = 'canceled' AND updated_at >= NOW() - INTERVAL 30 DAY THEN 1 END) as churned,
                    COUNT(CASE WHEN status IN ('active', 'canceled') THEN 1 END) as total
                FROM subscriptions
                WHERE plan != 'free'
                AND created_at <= NOW() - INTERVAL 30 DAY
            """)

            # Calculate MRR
            mrr_data = await db.fetch_one("""
                SELECT 
                    SUM(CASE 
                        WHEN plan = 'pro' AND billing_interval = 'monthly' THEN 29.0
                        WHEN plan = 'pro' AND billing_interval = 'annual' THEN 19.33  -- 232/12
                        WHEN plan = 'team' AND billing_interval = 'monthly' THEN 99.0
                        WHEN plan = 'team' AND billing_interval = 'annual' THEN 66.0  -- 792/12
                        ELSE 0
                    END) as mrr
                FROM subscriptions
                WHERE status = 'active'
                AND plan != 'free'
            """)

            churn_rate = 0.0
            if churn_data["total"] > 0:
                churn_rate = churn_data["churned"] / churn_data["total"]

            active_count = subscription_stats["active_count"] or 0
            mrr = mrr_data["mrr"] or 0.0
            arpu = mrr / active_count if active_count > 0 else 0.0

            return SubscriptionMetrics(
                total_active=active_count,
                total_canceled=subscription_stats["canceled_count"] or 0,
                total_past_due=subscription_stats["past_due_count"] or 0,
                new_subscriptions_24h=new_subs_24h["new_count"] or 0,
                churn_rate_30d=churn_rate,
                revenue_mrr=mrr,
                average_revenue_per_user=arpu,
            )

        except Exception as e:
            logger.exception(f"Failed to get subscription metrics: {e}")
            raise

    async def get_payment_metrics(self) -> PaymentMetrics:
        """Get payment processing metrics."""
        try:
            # Get payment events from last 24 hours
            payment_stats = await db.fetch_one("""
                SELECT 
                    COUNT(CASE WHEN transaction_type = 'subscription' AND credits_amount > 0 THEN 1 END) as successful,
                    COUNT(CASE WHEN transaction_status = 'failed' THEN 1 END) as failed
                FROM credit_transactions
                WHERE created_at >= NOW() - INTERVAL 24 HOUR
                AND transaction_type IN ('subscription', 'purchase')
            """)

            # Calculate success rate
            total_attempts = (payment_stats["successful"] or 0) + (
                payment_stats["failed"] or 0
            )
            success_rate = 1.0
            if total_attempts > 0:
                success_rate = (payment_stats["successful"] or 0) / total_attempts

            # Calculate recovery rate for failed payments (payments that later succeeded)
            recovery_rate = await self._calculate_payment_recovery_rate()

            # Get revenue for last 24 hours
            revenue_24h = await db.fetch_one("""
                SELECT 
                    SUM(CASE 
                        WHEN s.plan = 'pro' AND s.billing_interval = 'monthly' THEN 29.0
                        WHEN s.plan = 'pro' AND s.billing_interval = 'annual' THEN 232.0
                        WHEN s.plan = 'team' AND s.billing_interval = 'monthly' THEN 99.0
                        WHEN s.plan = 'team' AND s.billing_interval = 'annual' THEN 792.0
                        ELSE 0
                    END) as revenue
                FROM credit_transactions ct
                JOIN subscriptions s ON ct.user_id = s.user_id
                WHERE ct.created_at >= NOW() - INTERVAL 24 HOUR
                AND ct.transaction_type = 'subscription'
                AND ct.credits_amount > 0
            """)

            # Mock webhook processing success rate (would be tracked separately)
            webhook_success_rate = 0.999  # Would come from actual webhook logs

            return PaymentMetrics(
                successful_payments_24h=payment_stats["successful"] or 0,
                failed_payments_24h=payment_stats["failed"] or 0,
                success_rate=success_rate,
                failed_payment_recovery_rate=recovery_rate,
                total_revenue_24h=revenue_24h["revenue"] or 0.0,
                webhook_processing_success_rate=webhook_success_rate,
            )

        except Exception as e:
            logger.exception(f"Failed to get payment metrics: {e}")
            raise

    async def get_credit_metrics(self) -> CreditMetrics:
        """Get credit usage and purchase metrics."""
        try:
            # Credits consumed in last 24 hours
            consumption_data = await db.fetch_one("""
                SELECT SUM(ABS(credits_amount)) as total_consumed
                FROM credit_transactions
                WHERE created_at >= NOW() - INTERVAL 24 HOUR
                AND credits_amount < 0  -- Negative amounts are consumption
            """)

            # Credits purchased in last 24 hours
            purchase_data = await db.fetch_one("""
                SELECT 
                    SUM(credits_amount) as total_purchased,
                    SUM(JSON_EXTRACT(metadata, '$.price_usd')) as purchase_revenue
                FROM credit_transactions
                WHERE created_at >= NOW() - INTERVAL 24 HOUR
                AND transaction_type = 'purchase'
                AND credits_amount > 0
            """)

            # Average credits per user
            avg_credits = await db.fetch_one("""
                SELECT AVG(credits_balance) as avg_balance
                FROM user_credits
            """)

            # Top credit consumers (last 7 days)
            top_consumers = await db.fetch_all(
                """
                SELECT 
                    u.email,
                    SUM(ABS(ct.credits_amount)) as credits_consumed,
                    COUNT(ct.id) as transactions
                FROM credit_transactions ct
                JOIN users u ON ct.user_id = u.id
                WHERE ct.created_at >= NOW() - INTERVAL 7 DAY
                AND ct.credits_amount < 0
                GROUP BY ct.user_id, u.email
                ORDER BY credits_consumed DESC
                LIMIT 10
            """,
                {},
            )

            top_consumers_list = [
                {
                    "email": row["email"],
                    "credits_consumed": int(row["credits_consumed"] or 0),
                    "transactions": int(row["transactions"] or 0),
                }
                for row in top_consumers
            ]

            return CreditMetrics(
                total_credits_consumed_24h=int(consumption_data["total_consumed"] or 0),
                total_credits_purchased_24h=int(purchase_data["total_purchased"] or 0),
                average_credits_per_user=float(avg_credits["avg_balance"] or 0),
                top_credit_consumers=top_consumers_list,
                credit_purchase_revenue_24h=float(
                    purchase_data["purchase_revenue"] or 0
                ),
            )

        except Exception as e:
            logger.exception(f"Failed to get credit metrics: {e}")
            raise

    async def check_billing_health(self) -> List[BillingAlert]:
        """Check billing system health and return alerts."""
        alerts = []

        try:
            # Check payment success rate
            payment_metrics = await self.get_payment_metrics()
            if (
                payment_metrics.success_rate
                < self.alert_thresholds["payment_success_rate"]
            ):
                alerts.append(
                    BillingAlert(
                        level=AlertLevel.ERROR,
                        title="Low Payment Success Rate",
                        description=f"Payment success rate ({payment_metrics.success_rate:.1%}) is below threshold ({self.alert_thresholds['payment_success_rate']:.1%})",
                        metric_value=payment_metrics.success_rate,
                        threshold=self.alert_thresholds["payment_success_rate"],
                        timestamp=datetime.utcnow(),
                        resolution="Check Stripe API status and payment method issues",
                    )
                )

            # Check webhook processing rate
            if (
                payment_metrics.webhook_processing_success_rate
                < self.alert_thresholds["webhook_processing_rate"]
            ):
                alerts.append(
                    BillingAlert(
                        level=AlertLevel.CRITICAL,
                        title="Webhook Processing Failures",
                        description=f"Webhook success rate ({payment_metrics.webhook_processing_success_rate:.1%}) is below threshold",
                        metric_value=payment_metrics.webhook_processing_success_rate,
                        threshold=self.alert_thresholds["webhook_processing_rate"],
                        timestamp=datetime.utcnow(),
                        resolution="Check webhook endpoint availability and Stripe configuration",
                    )
                )

            # Check subscription churn rate
            subscription_metrics = await self.get_subscription_metrics()
            if (
                subscription_metrics.churn_rate_30d
                > self.alert_thresholds["subscription_churn_rate"]
            ):
                alerts.append(
                    BillingAlert(
                        level=AlertLevel.WARNING,
                        title="High Subscription Churn Rate",
                        description=f"30-day churn rate ({subscription_metrics.churn_rate_30d:.1%}) is above threshold ({self.alert_thresholds['subscription_churn_rate']:.1%})",
                        metric_value=subscription_metrics.churn_rate_30d,
                        threshold=self.alert_thresholds["subscription_churn_rate"],
                        timestamp=datetime.utcnow(),
                        resolution="Review customer feedback and pricing strategy",
                    )
                )

            # Check for failed payment spikes
            if (
                payment_metrics.failed_payments_24h
                > self.alert_thresholds["failed_payment_spike"]
            ):
                alerts.append(
                    BillingAlert(
                        level=AlertLevel.WARNING,
                        title="Failed Payment Spike",
                        description=f"High number of failed payments in 24h: {payment_metrics.failed_payments_24h}",
                        metric_value=payment_metrics.failed_payments_24h,
                        threshold=self.alert_thresholds["failed_payment_spike"],
                        timestamp=datetime.utcnow(),
                        resolution="Check for payment method expirations or Stripe issues",
                    )
                )

            return alerts

        except Exception as e:
            logger.exception(f"Failed to check billing health: {e}")
            return [
                BillingAlert(
                    level=AlertLevel.CRITICAL,
                    title="Billing Monitoring System Error",
                    description=f"Unable to check billing health: {str(e)}",
                    metric_value=0.0,
                    threshold=1.0,
                    timestamp=datetime.utcnow(),
                    resolution="Check database connectivity and monitoring service",
                )
            ]

    async def get_billing_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive billing data for dashboard."""
        try:
            subscription_metrics = await self.get_subscription_metrics()
            payment_metrics = await self.get_payment_metrics()
            credit_metrics = await self.get_credit_metrics()
            alerts = await self.check_billing_health()

            return {
                "subscriptions": {
                    "total_active": subscription_metrics.total_active,
                    "total_canceled": subscription_metrics.total_canceled,
                    "total_past_due": subscription_metrics.total_past_due,
                    "new_24h": subscription_metrics.new_subscriptions_24h,
                    "churn_rate_30d": subscription_metrics.churn_rate_30d,
                    "mrr": subscription_metrics.revenue_mrr,
                    "arpu": subscription_metrics.average_revenue_per_user,
                },
                "payments": {
                    "successful_24h": payment_metrics.successful_payments_24h,
                    "failed_24h": payment_metrics.failed_payments_24h,
                    "success_rate": payment_metrics.success_rate,
                    "recovery_rate": payment_metrics.failed_payment_recovery_rate,
                    "revenue_24h": payment_metrics.total_revenue_24h,
                    "webhook_success_rate": payment_metrics.webhook_processing_success_rate,
                },
                "credits": {
                    "consumed_24h": credit_metrics.total_credits_consumed_24h,
                    "purchased_24h": credit_metrics.total_credits_purchased_24h,
                    "avg_per_user": credit_metrics.average_credits_per_user,
                    "purchase_revenue_24h": credit_metrics.credit_purchase_revenue_24h,
                    "top_consumers": credit_metrics.top_credit_consumers[
                        :5
                    ],  # Top 5 only
                },
                "alerts": [
                    {
                        "level": alert.level.value,
                        "title": alert.title,
                        "description": alert.description,
                        "metric_value": alert.metric_value,
                        "threshold": alert.threshold,
                        "timestamp": alert.timestamp.isoformat(),
                        "resolution": alert.resolution,
                    }
                    for alert in alerts
                ],
                "system_health": {
                    "overall_status": "healthy"
                    if not any(
                        a.level in [AlertLevel.ERROR, AlertLevel.CRITICAL]
                        for a in alerts
                    )
                    else "degraded",
                    "stripe_configured": settings.stripe_configured,
                    "webhook_secret_configured": bool(settings.stripe_webhook_secret),
                    "last_updated": datetime.utcnow().isoformat(),
                },
            }

        except Exception as e:
            logger.exception(f"Failed to get billing dashboard data: {e}")
            raise

    async def _calculate_payment_recovery_rate(self) -> float:
        """Calculate the rate at which failed payments are later recovered."""
        try:
            # This would require tracking payment attempts and recoveries
            # For now, return a mock value
            return 0.75  # 75% recovery rate

        except Exception as e:
            logger.exception(f"Failed to calculate payment recovery rate: {e}")
            return 0.0

    async def log_billing_event(
        self,
        event_type: str,
        user_id: str,
        details: Dict[str, Any],
        severity: str = "info",
    ) -> None:
        """Log billing events for audit and monitoring."""
        try:
            # Log to application logs
            if severity == "error":
                logger.error(f"Billing event: {event_type} - {details}")
            elif severity == "warning":
                logger.warning(f"Billing event: {event_type} - {details}")
            else:
                logger.info(f"Billing event: {event_type} - {details}")

            # Could also store in dedicated billing events table
            # event_data = {
            #     "event_type": event_type,
            #     "user_id": user_id,
            #     "details": details,
            #     "severity": severity,
            #     "timestamp": datetime.utcnow().isoformat(),
            #     "source": "billing_monitor"
            # }
            # await db.insert("billing_events", event_data)

        except Exception as e:
            logger.exception(f"Failed to log billing event: {e}")


# Global monitor instance
billing_monitor = BillingMonitor()
