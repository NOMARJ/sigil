"""
Subscription Service for Pro tier management
Handles subscription checks, upgrades, and Pro feature gating.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from api.database import db
from api.models import PlanTier


logger = logging.getLogger(__name__)


class SubscriptionService:
    """Service for managing user subscriptions and Pro tier features."""
    
    async def get_user_subscription(self, user_id: str) -> dict[str, Any]:
        """Get detailed subscription information for a user."""
        try:
            # Use stored procedure to get subscription with computed fields
            result = await db.execute_procedure("sp_GetUserSubscription", {"user_id": user_id})
            if result:
                return result[0]  # First row
            else:
                # Return default free tier subscription
                return {
                    "id": None,
                    "user_id": user_id,
                    "plan": "free",
                    "status": "active",
                    "billing_interval": "monthly",
                    "stripe_customer_id": None,
                    "stripe_subscription_id": None,
                    "current_period_end": None,
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow(),
                    "is_active": True,
                    "has_pro_features": False,
                }
        except Exception as e:
            logger.exception(f"Failed to get subscription for user {user_id}: {e}")
            # Fallback to basic database query
            return await db.get_subscription(user_id) or self._default_free_subscription(user_id)
    
    async def check_pro_access(self, user_id: str) -> bool:
        """Check if user has access to Pro features."""
        subscription = await self.get_user_subscription(user_id)
        return subscription.get("has_pro_features", False)
    
    async def get_user_tier(self, user_id: str) -> PlanTier:
        """Get user's plan tier enum."""
        subscription = await self.get_user_subscription(user_id)
        plan_str = subscription.get("plan", "free")
        
        try:
            return PlanTier(plan_str)
        except ValueError:
            logger.warning(f"Invalid plan tier '{plan_str}' for user {user_id}, defaulting to FREE")
            return PlanTier.FREE
    
    async def create_pro_subscription(
        self,
        user_id: str,
        stripe_customer_id: str,
        stripe_subscription_id: str,
        billing_interval: str = "monthly",
        current_period_end: datetime | None = None
    ) -> dict[str, Any]:
        """Create or upgrade user to Pro subscription."""
        try:
            result = await db.execute_procedure(
                "sp_CreateProSubscription",
                {
                    "user_id": user_id,
                    "stripe_customer_id": stripe_customer_id,
                    "stripe_subscription_id": stripe_subscription_id,
                    "billing_interval": billing_interval,
                    "current_period_end": current_period_end,
                }
            )
            
            if result:
                logger.info(f"Successfully created Pro subscription for user {user_id}")
                return result[0]
            else:
                raise Exception("No result returned from sp_CreateProSubscription")
                
        except Exception as e:
            logger.exception(f"Failed to create Pro subscription for user {user_id}: {e}")
            
            # Fallback to direct database upsert
            return await db.upsert_subscription(
                user_id=user_id,
                plan="pro",
                status="active",
                stripe_customer_id=stripe_customer_id,
                stripe_subscription_id=stripe_subscription_id,
                current_period_end=current_period_end,
                billing_interval=billing_interval,
            )
    
    async def cancel_pro_subscription(
        self,
        user_id: str,
        cancellation_reason: str = "user_cancelled"
    ) -> dict[str, Any]:
        """Cancel Pro subscription and downgrade to free tier."""
        try:
            result = await db.execute_procedure(
                "sp_CancelProSubscription",
                {
                    "user_id": user_id,
                    "cancellation_reason": cancellation_reason,
                }
            )
            
            if result:
                logger.info(f"Successfully cancelled Pro subscription for user {user_id}")
                return result[0]
            else:
                raise Exception("No result returned from sp_CancelProSubscription")
                
        except Exception as e:
            logger.exception(f"Failed to cancel Pro subscription for user {user_id}: {e}")
            
            # Fallback to direct database update
            return await db.upsert_subscription(
                user_id=user_id,
                plan="free",
                status="cancelled",
                current_period_end=None,
            )
    
    async def track_pro_feature_usage(
        self,
        user_id: str,
        feature_type: str,
        usage_data: dict[str, Any] | None = None
    ) -> bool:
        """Track usage of Pro features for analytics and billing."""
        try:
            # Convert usage_data to JSON string
            usage_json = None
            if usage_data:
                import json
                usage_json = json.dumps(usage_data)
            
            result = await db.execute_procedure(
                "sp_TrackProFeatureUsage",
                {
                    "user_id": user_id,
                    "feature_type": feature_type,
                    "usage_data": usage_json,
                }
            )
            
            if result and result[0].get("records_inserted", 0) > 0:
                logger.debug(f"Tracked {feature_type} usage for user {user_id}")
                return True
            else:
                logger.warning(f"Failed to track {feature_type} usage for user {user_id}")
                return False
                
        except Exception as e:
            logger.exception(f"Error tracking Pro feature usage: {e}")
            return False
    
    async def get_pro_feature_usage_stats(
        self,
        user_id: str,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        feature_type: str | None = None
    ) -> list[dict[str, Any]]:
        """Get Pro feature usage statistics for a user."""
        try:
            result = await db.execute_procedure(
                "sp_GetProFeatureUsage",
                {
                    "user_id": user_id,
                    "start_date": start_date,
                    "end_date": end_date,
                    "feature_type": feature_type,
                }
            )
            return result or []
            
        except Exception as e:
            logger.exception(f"Failed to get Pro feature usage stats: {e}")
            return []
    
    def _default_free_subscription(self, user_id: str) -> dict[str, Any]:
        """Return default free tier subscription."""
        return {
            "id": None,
            "user_id": user_id,
            "plan": "free",
            "status": "active",
            "billing_interval": "monthly",
            "stripe_customer_id": None,
            "stripe_subscription_id": None,
            "current_period_end": None,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "is_active": True,
            "has_pro_features": False,
        }


class ProFeatureGate:
    """Decorator and utility for Pro feature gating."""
    
    def __init__(self, subscription_service: SubscriptionService):
        self.subscription_service = subscription_service
    
    async def require_pro_access(self, user_id: str) -> None:
        """Raise exception if user doesn't have Pro access."""
        has_access = await self.subscription_service.check_pro_access(user_id)
        if not has_access:
            from fastapi import HTTPException, status
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail={
                    "error": "pro_subscription_required",
                    "message": "This feature requires a Pro subscription",
                    "upgrade_url": "https://app.sigilsec.ai/upgrade",
                    "feature": "llm_analysis",
                }
            )
    
    async def check_and_track_usage(
        self,
        user_id: str,
        feature_type: str,
        usage_data: dict[str, Any] | None = None
    ) -> None:
        """Check Pro access and track feature usage."""
        await self.require_pro_access(user_id)
        await self.subscription_service.track_pro_feature_usage(
            user_id, feature_type, usage_data
        )


# Global service instances
subscription_service = SubscriptionService()
pro_feature_gate = ProFeatureGate(subscription_service)