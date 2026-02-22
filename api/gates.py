"""
Sigil API — Plan Tier Feature Gates

Provides FastAPI dependencies for enforcing plan-tier access control and
monthly scan quotas.  All feature gating is centralised here so routers
remain declarative and easy to audit.

Usage in a route:

    from api.gates import require_plan, check_scan_quota
    from api.models import PlanTier

    # Hard gate — 403 if user is below PRO:
    @router.get("/my-route")
    async def my_route(
        current_user: Annotated[UserResponse, Depends(get_current_user)],
        _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
    ): ...

    # Quota gate — checked before scan runs, incremented after success:
    async def submit_scan(
        current_user: Annotated[UserResponse, Depends(require_auth_and_quota)],
    ): ...
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status

from api.models import PlanTier

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tier ordering & quota limits
# ---------------------------------------------------------------------------

# Monthly scan limits per tier.  0 = unlimited (ENTERPRISE).
PLAN_LIMITS: dict[PlanTier, int] = {
    PlanTier.FREE: 50,
    PlanTier.PRO: 500,
    PlanTier.TEAM: 5_000,
    PlanTier.ENTERPRISE: 0,
}

_TIER_ORDER: list[PlanTier] = [
    PlanTier.FREE,
    PlanTier.PRO,
    PlanTier.TEAM,
    PlanTier.ENTERPRISE,
]


def _tier_rank(tier: PlanTier) -> int:
    try:
        return _TIER_ORDER.index(tier)
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# Custom exception for plan gating (handled in main.py)
# ---------------------------------------------------------------------------


class PlanGateException(Exception):
    """Raised when the user's plan does not meet the route's minimum tier."""

    def __init__(self, required_plan: PlanTier, current_plan: PlanTier) -> None:
        self.required_plan = required_plan
        self.current_plan = current_plan
        super().__init__(
            f"Requires {required_plan.value} plan; user is on {current_plan.value}"
        )


# ---------------------------------------------------------------------------
# Helper: fetch a user's current plan from the database
# ---------------------------------------------------------------------------


async def get_user_plan(user_id: str) -> PlanTier:
    """Return the current plan tier for *user_id*.

    Defaults to FREE if no subscription record exists.
    """
    from api.database import db

    sub = await db.get_subscription(user_id)
    if sub is None:
        return PlanTier.FREE
    plan_str = sub.get("plan", "free")
    try:
        return PlanTier(plan_str)
    except ValueError:
        logger.warning(
            "Unknown plan value '%s' for user %s — defaulting to FREE",
            plan_str,
            user_id,
        )
        return PlanTier.FREE


# ---------------------------------------------------------------------------
# require_plan — dependency factory for tier gating
# ---------------------------------------------------------------------------


def require_plan(minimum_tier: PlanTier):
    """Return a FastAPI dependency that enforces a minimum plan tier.

    Raises ``PlanGateException`` (caught by the handler in ``main.py`` and
    converted to a 403 ``GateError`` JSON response) if the authenticated
    user's plan is below *minimum_tier*.

    Because this dependency itself depends on ``get_current_user_unified``, it also
    enforces authentication — unauthenticated requests are rejected with 401
    before the tier check even runs.

    Note: The import of ``get_current_user_unified`` is deferred into the factory
    body (called at decoration time) to avoid circular imports at module
    load time.  By the time any router module calls ``require_plan()``,
    ``api.routers.auth`` is already fully initialised.

    Uses the unified auth function to support both Supabase Auth and custom JWT
    without dependency injection conflicts.
    """
    from api.routers.auth import get_current_user_unified, UserResponse

    async def _gate(
        current_user: UserResponse = Depends(get_current_user_unified),
    ) -> None:
        current_tier = await get_user_plan(current_user.id)
        if _tier_rank(current_tier) < _tier_rank(minimum_tier):
            raise PlanGateException(minimum_tier, current_tier)

    return _gate


# ---------------------------------------------------------------------------
# check_scan_quota — quota enforcement helper (not a dependency itself)
# ---------------------------------------------------------------------------


async def check_scan_quota(user_id: str, current_tier: PlanTier) -> None:
    """Check whether the user has remaining quota for the current month.

    Raises HTTP 429 if the monthly limit is exceeded.
    Does NOT increment the counter — call ``db.increment_scan_usage()`` after
    the scan succeeds so that failed scans do not consume quota.

    ENTERPRISE tier (limit == 0) is always allowed without any DB work.
    """
    limit = PLAN_LIMITS[current_tier]
    if limit == 0:
        return  # ENTERPRISE — unlimited

    from api.database import db

    year_month = datetime.now(timezone.utc).strftime("%Y-%m")
    current_count = await db.get_scan_usage(user_id, year_month)

    if current_count >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "detail": (
                    f"Monthly scan limit of {limit} reached for your "
                    f"{current_tier.value} plan. Upgrade to scan more."
                ),
                "limit": limit,
                "used": current_count,
                "current_plan": current_tier.value,
                "upgrade_url": "https://app.sigilsec.ai/upgrade",
            },
            headers={"Retry-After": "2592000"},  # ~30 days in seconds
        )
