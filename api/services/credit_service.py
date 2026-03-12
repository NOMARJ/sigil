"""
Credit Management Service for LLM Token Usage
Implements Windsurf-style credit system for Pro tier features
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Literal

from api.database import db
from api.models import SubscriptionTier
from api.exceptions import InsufficientCreditsError, CreditTransactionError

logger = logging.getLogger(__name__)

# Credit conversion rates (credits per 1K tokens)
CREDIT_RATES = {
    "claude-3-haiku-20240307": 1,      # Most efficient
    "claude-3-sonnet-20240229": 10,    # Balanced
    "claude-3-opus-20240229": 40,      # Premium
    "gpt-3.5-turbo": 2,                # Budget option
    "gpt-4-turbo": 20,                 # High quality
    "gpt-4": 30,                        # Legacy
}

# Monthly credit allocations by tier
MONTHLY_CREDITS = {
    SubscriptionTier.ANONYMOUS: 0,        # No LLM access
    SubscriptionTier.FREE: 50,            # Minimal for logged-in users
    SubscriptionTier.PRO: 5000,           # Standard professional
    SubscriptionTier.ELITE: 15000,        # Advanced power users
    SubscriptionTier.TEAM: 50000,         # Team collaboration
    SubscriptionTier.ENTERPRISE: 999999,  # Effectively unlimited
}

# Feature credit costs
SCAN_COSTS = {
    "quick_scan": 8,           # Basic 8K token scan
    "deep_analysis": 32,       # Comprehensive 32K scan
    "interactive_session": 2,   # Per Q&A exchange
    "bulk_scan": 100,          # Full repository scan
    "investigate_finding": 4,   # Deep-dive on specific issue
    "remediation_suggest": 6,   # Generate fix code
}

TransactionType = Literal[
    "scan", "interactive", "investigate", "remediation",
    "subscription", "purchase", "bonus", "refund"
]

class CreditService:
    """Manages user credits for LLM usage."""

    async def get_balance(self, user_id: str) -> int:
        """Get current credit balance for user."""
        try:
            result = await db.fetch_one(
                """
                SELECT credits_balance 
                FROM user_credits 
                WHERE user_id = :user_id
                """,
                {"user_id": user_id}
            )
            
            if not result:
                # Initialize credits for new user
                await self.initialize_user_credits(user_id)
                return await self.get_balance(user_id)
            
            return result["credits_balance"]
            
        except Exception as e:
            logger.exception(f"Failed to get credit balance for {user_id}: {e}")
            raise CreditTransactionError(f"Could not retrieve credit balance: {e}")

    async def has_credits(self, user_id: str, amount: int) -> bool:
        """Check if user has sufficient credits."""
        balance = await self.get_balance(user_id)
        return balance >= amount

    async def deduct_credits(
        self,
        user_id: str,
        amount: int,
        transaction_type: TransactionType,
        scan_id: Optional[str] = None,
        session_id: Optional[str] = None,
        model_used: Optional[str] = None,
        tokens_used: Optional[int] = None,
        metadata: Optional[Dict] = None,
    ) -> int:
        """
        Deduct credits from user balance.
        
        Returns:
            New balance after deduction
            
        Raises:
            InsufficientCreditsError: If user doesn't have enough credits
        """
        try:
            # Execute stored procedure
            result = await db.execute_procedure(
                "sp_DeductCredits",
                {
                    "UserId": user_id,
                    "Amount": amount,
                    "TransactionType": transaction_type,
                    "ScanId": scan_id,
                    "SessionId": session_id,
                    "ModelUsed": model_used,
                    "TokensUsed": tokens_used,
                    "Metadata": json.dumps(metadata) if metadata else None,
                }
            )
            
            if result:
                new_balance = result[0]["new_balance"]
                logger.info(
                    f"Deducted {amount} credits from {user_id} for {transaction_type}. "
                    f"New balance: {new_balance}"
                )
                return new_balance
            
            raise CreditTransactionError("Failed to deduct credits")
            
        except db.DatabaseError as e:
            if "Insufficient credits" in str(e):
                raise InsufficientCreditsError(
                    f"User {user_id} has insufficient credits ({amount} required)"
                )
            elif "User credits not found" in str(e):
                # Initialize and retry
                await self.initialize_user_credits(user_id)
                return await self.deduct_credits(
                    user_id, amount, transaction_type, scan_id, 
                    session_id, model_used, tokens_used, metadata
                )
            else:
                logger.exception(f"Credit deduction failed for {user_id}: {e}")
                raise CreditTransactionError(f"Failed to process credit transaction: {e}")

    async def add_credits(
        self,
        user_id: str,
        amount: int,
        transaction_type: Literal["subscription", "purchase", "bonus", "refund"],
        metadata: Optional[Dict] = None,
    ) -> int:
        """
        Add credits to user balance.
        
        Returns:
            New balance after addition
        """
        try:
            result = await db.execute_procedure(
                "sp_AddCredits",
                {
                    "UserId": user_id,
                    "Amount": amount,
                    "TransactionType": transaction_type,
                    "Metadata": json.dumps(metadata) if metadata else None,
                }
            )
            
            if result:
                new_balance = result[0]["new_balance"]
                logger.info(
                    f"Added {amount} credits to {user_id} via {transaction_type}. "
                    f"New balance: {new_balance}"
                )
                return new_balance
            
            raise CreditTransactionError("Failed to add credits")
            
        except Exception as e:
            logger.exception(f"Credit addition failed for {user_id}: {e}")
            raise CreditTransactionError(f"Failed to add credits: {e}")

    async def initialize_user_credits(self, user_id: str) -> None:
        """Initialize credits for a new user based on their subscription tier."""
        try:
            # Get user's subscription tier
            user = await db.fetch_one(
                "SELECT subscription_tier FROM users WHERE id = :user_id",
                {"user_id": user_id}
            )
            
            if not user:
                raise ValueError(f"User {user_id} not found")
            
            tier = SubscriptionTier(user["subscription_tier"])
            initial_credits = MONTHLY_CREDITS.get(tier, 100)
            
            # Create credit record
            await db.execute(
                """
                INSERT INTO user_credits (
                    user_id, credits_balance, subscription_credits, reset_date
                ) VALUES (
                    :user_id, :credits, :credits, :reset_date
                )
                """,
                {
                    "user_id": user_id,
                    "credits": initial_credits,
                    "reset_date": datetime.utcnow() + timedelta(days=30),
                }
            )
            
            logger.info(f"Initialized {initial_credits} credits for user {user_id} ({tier.value})")
            
        except Exception as e:
            logger.exception(f"Failed to initialize credits for {user_id}: {e}")
            # Don't raise - allow graceful degradation

    async def reset_monthly_credits(self) -> int:
        """
        Reset monthly credits for all users.
        Called by scheduled job.
        
        Returns:
            Number of users reset
        """
        try:
            result = await db.execute_procedure("sp_ResetMonthlyCredits", {})
            users_reset = result[0]["users_reset"] if result else 0
            logger.info(f"Reset monthly credits for {users_reset} users")
            return users_reset
            
        except Exception as e:
            logger.exception(f"Failed to reset monthly credits: {e}")
            raise

    async def calculate_token_cost(
        self, 
        model: str, 
        tokens: int
    ) -> int:
        """Calculate credit cost for token usage."""
        rate = CREDIT_RATES.get(model, 10)  # Default to mid-tier rate
        # Convert tokens to credits (1 credit per 1K tokens * rate)
        credits = max(1, int((tokens / 1000) * rate))
        return credits

    async def get_transaction_history(
        self,
        user_id: str,
        limit: int = 50,
        transaction_type: Optional[str] = None
    ) -> list[Dict]:
        """Get credit transaction history for user."""
        try:
            query = """
                SELECT 
                    transaction_id,
                    credits_amount,
                    credits_balance_after,
                    transaction_type,
                    transaction_status,
                    scan_id,
                    session_id,
                    model_used,
                    tokens_used,
                    metadata,
                    created_at
                FROM credit_transactions
                WHERE user_id = :user_id
            """
            
            params = {"user_id": user_id}
            
            if transaction_type:
                query += " AND transaction_type = :transaction_type"
                params["transaction_type"] = transaction_type
            
            query += " ORDER BY created_at DESC LIMIT :limit"
            params["limit"] = limit
            
            results = await db.fetch_all(query, params)
            
            return [
                {
                    "id": str(row["transaction_id"]),
                    "amount": row["credits_amount"],
                    "balance_after": row["credits_balance_after"],
                    "type": row["transaction_type"],
                    "status": row["transaction_status"],
                    "scan_id": row["scan_id"],
                    "session_id": row["session_id"],
                    "model": row["model_used"],
                    "tokens": row["tokens_used"],
                    "metadata": json.loads(row["metadata"]) if row["metadata"] else None,
                    "timestamp": row["created_at"].isoformat(),
                }
                for row in results
            ]
            
        except Exception as e:
            logger.exception(f"Failed to get transaction history for {user_id}: {e}")
            return []

    async def get_usage_analytics(self, user_id: str) -> Dict:
        """Get credit usage analytics for user."""
        try:
            result = await db.fetch_one(
                """
                SELECT 
                    credits_balance,
                    credits_used_month,
                    subscription_credits,
                    bonus_credits,
                    reset_date,
                    scans_last_30_days,
                    interactive_sessions_last_30_days,
                    total_credits_consumed_month
                FROM vw_credit_analytics
                WHERE user_id = :user_id
                """,
                {"user_id": user_id}
            )
            
            if not result:
                return {
                    "balance": 0,
                    "used_this_month": 0,
                    "monthly_allocation": 0,
                    "bonus_credits": 0,
                    "reset_date": None,
                    "usage_stats": {
                        "scans": 0,
                        "interactive_sessions": 0,
                        "total_consumed": 0
                    }
                }
            
            return {
                "balance": result["credits_balance"],
                "used_this_month": result["credits_used_month"],
                "monthly_allocation": result["subscription_credits"],
                "bonus_credits": result["bonus_credits"],
                "reset_date": result["reset_date"].isoformat() if result["reset_date"] else None,
                "usage_stats": {
                    "scans": result["scans_last_30_days"] or 0,
                    "interactive_sessions": result["interactive_sessions_last_30_days"] or 0,
                    "total_consumed": result["total_credits_consumed_month"] or 0
                }
            }
            
        except Exception as e:
            logger.exception(f"Failed to get usage analytics for {user_id}: {e}")
            return {}

    async def purchase_credits(
        self,
        user_id: str,
        package_id: int,
        stripe_payment_intent_id: str
    ) -> Dict:
        """Process credit package purchase."""
        try:
            # Get package details
            package = await db.fetch_one(
                """
                SELECT credits_amount, price_usd, package_name
                FROM credit_packages
                WHERE package_id = :package_id AND is_active = 1
                """,
                {"package_id": package_id}
            )
            
            if not package:
                raise ValueError(f"Invalid package ID: {package_id}")
            
            # Add credits
            new_balance = await self.add_credits(
                user_id=user_id,
                amount=package["credits_amount"],
                transaction_type="purchase",
                metadata={
                    "package_id": package_id,
                    "package_name": package["package_name"],
                    "price_usd": float(package["price_usd"]),
                    "stripe_payment_intent": stripe_payment_intent_id,
                }
            )
            
            return {
                "success": True,
                "credits_added": package["credits_amount"],
                "new_balance": new_balance,
                "package_name": package["package_name"],
            }
            
        except Exception as e:
            logger.exception(f"Failed to process credit purchase for {user_id}: {e}")
            raise CreditTransactionError(f"Failed to process credit purchase: {e}")


# Global service instance
credit_service = CreditService()