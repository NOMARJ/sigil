"""
Credit Management Service for LLM Token Usage
Implements Windsurf-style credit system for Pro tier features
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Literal

import pyodbc

from api.database import db
from api.models import PlanTier as SubscriptionTier


# Define custom exceptions
class InsufficientCreditsError(Exception):
    """Raised when user doesn't have enough credits"""

    pass


class CreditTransactionError(Exception):
    """Raised when credit transaction fails"""

    pass


logger = logging.getLogger(__name__)

# Credit conversion rates (credits per 1K tokens), proportional to verified
# Anthropic pricing: haiku $1/$5 · opus 4.8 $5/$25 · fable 5 $10/$50 per MTok
CREDIT_RATES = {
    "claude-haiku-4-5": 1,
    "claude-opus-4-8": 5,
    "claude-fable-5": 10,
}

# Monthly credit allocations by tier
MONTHLY_CREDITS = {
    SubscriptionTier.ANONYMOUS: 0,  # No LLM access
    SubscriptionTier.FREE: 50,  # Free teaser (~10 typical analysis calls)
    SubscriptionTier.PRO: 5000,  # Standard professional
    SubscriptionTier.ELITE: 15000,  # Advanced power users
    SubscriptionTier.TEAM: 50000,  # Team collaboration
    SubscriptionTier.ENTERPRISE: 999999,  # Effectively unlimited
}

UPGRADE_URL = os.getenv("SIGIL_UPGRADE_URL", "https://www.sigilsec.ai/pricing")


def monthly_allowance(tier: SubscriptionTier) -> int:
    """Monthly credit allocation for a tier; FREE is env-overridable."""
    if tier == SubscriptionTier.FREE:
        return int(os.getenv("LLM_FREE_MONTHLY_CREDITS", "50"))
    return MONTHLY_CREDITS.get(tier, 100)

# Feature credit costs (optimized for constrained launch)
SCAN_COSTS = {
    "quick_investigation": 4,  # Fast finding analysis (Haiku)
    "thorough_investigation": 8,  # Detailed analysis (Sonnet)
    "exhaustive_investigation": 16,  # Complete analysis (Opus)
    "false_positive_check": 4,  # Context verification (Haiku/Sonnet)
    "chat_message": 2,  # Per interactive message
    "remediation_suggest": 6,  # Generate fix code (hidden in launch)
    "bulk_scan": 20,  # Bulk analysis (hidden in launch)
    "compliance_mapping": 3,  # Regulatory mapping (hidden in launch)
}

TransactionType = Literal[
    "scan",
    "interactive",
    "investigate",
    "remediation",
    "subscription",
    "purchase",
    "bonus",
    "refund",
]


class CreditService:
    """Manages user credits for LLM usage."""

    async def get_balance(self, user_id: str) -> int:
        """Get current credit balance for user."""
        try:
            result = await db.select_one("user_credits", {"user_id": user_id})

            if not result:
                # Initialize credits for new user, then re-read once (no
                # recursion: if init silently failed, fall back to 0).
                await self.initialize_user_credits(user_id)
                result = await db.select_one("user_credits", {"user_id": user_id})
                return int(result["credits_balance"]) if result else 0

            return int(result["credits_balance"])

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
        _retry: bool = True,
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
                },
            )

            if result:
                new_balance = result[0]["new_balance"]
                logger.info(
                    f"Deducted {amount} credits from {user_id} for {transaction_type}. "
                    f"New balance: {new_balance}"
                )
                return new_balance

            raise CreditTransactionError("Failed to deduct credits")

        except pyodbc.Error as e:
            if "Insufficient credits" in str(e):
                raise InsufficientCreditsError(
                    f"User {user_id} has insufficient credits ({amount} required)"
                )
            elif "User credits not found" in str(e):
                if not _retry:
                    # initialize_user_credits ran but the row still isn't there
                    # — surface instead of recursing forever.
                    logger.error(
                        f"Credit init did not create a row for {user_id}; "
                        "cannot deduct."
                    )
                    raise CreditTransactionError(
                        "Could not initialize user credits"
                    )
                await self.initialize_user_credits(user_id)
                return await self.deduct_credits(
                    user_id,
                    amount,
                    transaction_type,
                    scan_id,
                    session_id,
                    model_used,
                    tokens_used,
                    metadata,
                    _retry=False,
                )
            else:
                logger.exception(f"Credit deduction failed for {user_id}: {e}")
                raise CreditTransactionError(
                    f"Failed to process credit transaction: {e}"
                )

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
                },
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
            # Tier lives in the subscriptions table (via get_user_plan), not on
            # users — the users table has no subscription_tier column.
            from api.gates import get_user_plan

            tier = await get_user_plan(user_id)
            initial_credits = monthly_allowance(tier)

            # Create credit record (SQL Server implicitly converts the GUID
            # string user_id to the UNIQUEIDENTIFIER column).
            await db.insert(
                "user_credits",
                {
                    "user_id": user_id,
                    "credits_balance": initial_credits,
                    "subscription_credits": initial_credits,
                    "reset_date": datetime.utcnow() + timedelta(days=30),
                },
            )

            logger.info(
                f"Initialized {initial_credits} credits for user {user_id} ({tier.value})"
            )

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

    async def check_llm_allowance(
        self, user_id: str, credits_required: int = 1
    ) -> Dict:
        """Check whether a user may make an LLM call right now.

        Returns a structured decision — never raises on exhaustion, so callers
        can turn the denial into a 402 with an upgrade path.
        """
        balance = await self.get_balance(user_id)
        if balance >= credits_required:
            return {"allowed": True, "balance": balance}

        analytics = await self.get_usage_analytics(user_id)
        return {
            "allowed": False,
            "reason": "allowance_exhausted",
            "balance": balance,
            "credits_required": credits_required,
            "reset_date": analytics.get("reset_date"),
            "upgrade_url": UPGRADE_URL,
        }

    async def record_llm_usage(
        self,
        user_id: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        feature: str,
        scan_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> int:
        """Meter one LLM call against the user's credits.

        Returns the new balance. Features outside the known TransactionType
        values are recorded as "scan".
        """
        total_tokens = input_tokens + output_tokens
        credits = await self.calculate_token_cost(model, total_tokens)
        feature_to_transaction: Dict[str, TransactionType] = {
            "investigate": "investigate",
            "remediation": "remediation",
            "interactive": "interactive",
            "chat": "interactive",
        }
        transaction_type: TransactionType = feature_to_transaction.get(feature, "scan")
        return await self.deduct_credits(
            user_id=user_id,
            amount=credits,
            transaction_type=transaction_type,
            scan_id=scan_id,
            session_id=session_id,
            model_used=model,
            tokens_used=total_tokens,
            metadata={
                "feature": feature,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            },
        )

    async def calculate_token_cost(self, model: str, tokens: int) -> int:
        """Calculate credit cost for token usage."""
        rate = CREDIT_RATES.get(model, 10)  # Default to mid-tier rate
        # Convert tokens to credits (1 credit per 1K tokens * rate)
        credits = max(1, int((tokens / 1000) * rate))
        return credits

    async def get_transaction_history(
        self, user_id: str, limit: int = 50, transaction_type: Optional[str] = None
    ) -> list[Dict]:
        """Get credit transaction history for user."""
        try:
            # T-SQL: TOP (?) instead of LIMIT; positional ? params.
            query = (
                "SELECT TOP (?) transaction_id, credits_amount, "
                "credits_balance_after, transaction_type, transaction_status, "
                "scan_id, session_id, model_used, tokens_used, metadata, "
                "created_at FROM credit_transactions WHERE user_id = ?"
            )
            params: list[Any] = [limit, user_id]
            if transaction_type:
                query += " AND transaction_type = ?"
                params.append(transaction_type)
            query += " ORDER BY created_at DESC"

            results = await db.execute_raw_sql(query, tuple(params))

            def _iso(v):
                return v.isoformat() if hasattr(v, "isoformat") else v

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
                    "metadata": json.loads(row["metadata"])
                    if row["metadata"]
                    else None,
                    "timestamp": _iso(row["created_at"]),
                }
                for row in results
            ]

        except Exception as e:
            logger.exception(f"Failed to get transaction history for {user_id}: {e}")
            return []

    async def get_usage_analytics(self, user_id: str) -> Dict:
        """Get credit usage analytics for user.

        Reads ``user_credits`` directly — the ``vw_credit_analytics`` view is
        not provisioned (it depends on ``interactive_sessions`` and a
        ``users.subscription_tier`` column that do not exist in this schema).
        """
        try:
            result = await db.select_one("user_credits", {"user_id": user_id})

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
                        "total_consumed": 0,
                    },
                }

            reset = result.get("reset_date")
            return {
                "balance": result["credits_balance"],
                "used_this_month": result["credits_used_month"],
                "monthly_allocation": result["subscription_credits"],
                "bonus_credits": result["bonus_credits"],
                "reset_date": reset.isoformat() if hasattr(reset, "isoformat") else reset,
                "usage_stats": {
                    "scans": result["credits_used_month"] or 0,
                    "interactive_sessions": 0,
                    "total_consumed": result["credits_used_month"] or 0,
                },
            }

        except Exception as e:
            logger.exception(f"Failed to get usage analytics for {user_id}: {e}")
            return {}

# NOTE: a former `purchase_credits` method here read the `credit_packages`
# table via the asyncpg-style `db.fetch_one` API that MssqlClient does not
# implement, and the table is not provisioned. It had no callers — the live
# credit-purchase flow is `api/routers/billing.py` (the `CREDIT_PACKAGES`
# constant + Stripe checkout + the webhook calling `add_credits`). Removed
# rather than ported, to avoid carrying dead code against a phantom table.


# Global service instance
credit_service = CreditService()
