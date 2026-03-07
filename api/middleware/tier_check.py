"""
Tier checking middleware for Pro features
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, HTTPException, status
from typing_extensions import Annotated

from models import PlanTier
from routers.auth import get_current_user_unified, UserResponse
from services.subscription_service import subscription_service, pro_feature_gate


logger = logging.getLogger(__name__)


async def get_user_tier(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> PlanTier:
    """Get the current user's plan tier."""
    try:
        return await subscription_service.get_user_tier(current_user.id)
    except Exception as e:
        logger.exception(f"Failed to get user tier for {current_user.id}: {e}")
        return PlanTier.FREE


async def require_pro_tier(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> UserResponse:
    """Require Pro tier or higher, raise 402 if not."""
    try:
        await pro_feature_gate.require_pro_access(current_user.id)
        return current_user
    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    except Exception as e:
        logger.exception(f"Error checking Pro access for {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to verify subscription status",
        )


async def check_llm_analysis_access(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> dict[str, Any]:
    """Check if user can access LLM analysis features."""
    user_tier = await get_user_tier(current_user)
    has_pro_access = user_tier in (PlanTier.PRO, PlanTier.TEAM, PlanTier.ENTERPRISE)

    return {
        "user_id": current_user.id,
        "user_tier": user_tier.value,
        "has_pro_access": has_pro_access,
        "can_use_llm": has_pro_access,
    }


async def get_scan_capabilities(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> dict[str, Any]:
    """Get user's scanning capabilities based on their tier."""
    tier_info = await check_llm_analysis_access(current_user)

    capabilities = {
        "static_analysis": True,  # Available to all users
        "llm_analysis": tier_info["has_pro_access"],
        "contextual_analysis": tier_info["has_pro_access"],
        "zero_day_detection": tier_info["has_pro_access"],
        "advanced_remediation": tier_info["has_pro_access"],
        "tier": tier_info["user_tier"],
        "upgrade_required": not tier_info["has_pro_access"],
    }

    return capabilities
