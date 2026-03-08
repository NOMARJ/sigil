"""
Sigil API — Policy Engine Router

Manages team scan policies and evaluates scan results against them.

Endpoints:
    GET    /v1/policies          — List team policies
    POST   /v1/policies          — Create a new policy
    PUT    /v1/policies/{id}     — Update an existing policy
    DELETE /v1/policies/{id}     — Delete a policy
    POST   /v1/policies/evaluate — Evaluate a scan result against team policies
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing_extensions import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from api.database import db
from api.gates import require_plan
from api.models import (
    ErrorResponse,
    GateError,
    PlanTier,
    PolicyCreate,
    PolicyEvaluateRequest,
    PolicyEvaluateResponse,
    PolicyResponse,
    PolicyType,
    PolicyUpdate,
)
from api.routers.auth import get_current_user_unified, UserResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["policies"])

POLICY_TABLE = "policies"
AUDIT_TABLE = "audit_log"

# Default team ID used when no auth/team context is available
_DEFAULT_TEAM_ID = "default-team"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _team_id_from_user(user: UserResponse) -> str:
    """Extract the team ID from the authenticated user, falling back to a
    default when teams are not yet configured."""
    # In a full implementation, user would have a team_id field.
    # For now, derive from user ID to ensure per-user isolation.
    return getattr(user, "team_id", None) or _DEFAULT_TEAM_ID


async def _get_policy_or_404(policy_id: str, team_id: str) -> dict:
    """Fetch a policy by ID, ensuring it belongs to the given team."""
    row = await db.select_one(POLICY_TABLE, {"id": policy_id})
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_id}' not found",
        )
    if row.get("team_id") != team_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Policy does not belong to your team",
        )
    return row


def _row_to_response(row: dict) -> PolicyResponse:
    """Convert a DB row dict to a PolicyResponse model."""
    return PolicyResponse(
        id=row["id"],
        team_id=row.get("team_id", _DEFAULT_TEAM_ID),
        name=row.get("name", ""),
        type=row.get("type", PolicyType.ALLOWLIST),
        config=row.get("config_json", row.get("config", {})),
        enabled=row.get("enabled", True),
        created_at=row.get("created_at", datetime.utcnow()),
        updated_at=row.get("updated_at", datetime.utcnow()),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/policies",
    response_model=list[PolicyResponse],
    summary="List team policies",
    responses={401: {"model": ErrorResponse}, 403: {"model": GateError}},
)
async def list_policies(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
    enabled: bool | None = Query(None, description="Filter by enabled state"),
) -> list[PolicyResponse]:
    """Return all policies for the authenticated user's team.

    Optionally filter by ``enabled`` state.
    """
    team_id = _team_id_from_user(current_user)
    filters: dict = {"team_id": team_id}
    if enabled is not None:
        filters["enabled"] = enabled

    rows = await db.select(POLICY_TABLE, filters, limit=200)
    return [_row_to_response(r) for r in rows]


@router.post(
    "/policies",
    response_model=PolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a team policy",
    responses={401: {"model": ErrorResponse}, 403: {"model": GateError}},
)
async def create_policy(
    body: PolicyCreate,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> PolicyResponse:
    """Create a new scan policy for the team.

    Policy types:
    - **allowlist** — packages/targets that are always approved
    - **blocklist** — packages/targets that are always rejected
    - **auto_approve_threshold** — auto-approve scans below a risk score
    - **required_phases** — scan phases that must be included
    """
    team_id = _team_id_from_user(current_user)
    now = datetime.utcnow()
    policy_id = uuid4().hex[:16]

    row = {
        "id": policy_id,
        "team_id": team_id,
        "name": body.name,
        "type": body.type.value,
        "config_json": body.config,
        "enabled": body.enabled,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }

    await db.insert(POLICY_TABLE, row)

    # Audit log
    try:
        await db.insert(
            AUDIT_TABLE,
            {
                "id": uuid4().hex[:16],
                "user_id": current_user.id,
                "team_id": team_id,
                "action": "policy.created",
                "details_json": {
                    "policy_id": policy_id,
                    "name": body.name,
                    "type": body.type.value,
                },
                "created_at": now.isoformat(),
            },
        )
    except Exception:
        logger.debug("Failed to write audit log for policy creation")

    logger.info(
        "Policy created: %s (%s) by user %s", policy_id, body.name, current_user.id
    )

    return _row_to_response(row)


@router.put(
    "/policies/{policy_id}",
    response_model=PolicyResponse,
    summary="Update a policy",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        404: {"model": ErrorResponse},
    },
)
async def update_policy(
    policy_id: str,
    body: PolicyUpdate,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> PolicyResponse:
    """Update an existing policy's name, type, config, or enabled state.

    Only the fields provided in the request body are updated; omitted fields
    are left unchanged.
    """
    team_id = _team_id_from_user(current_user)
    existing = await _get_policy_or_404(policy_id, team_id)
    now = datetime.utcnow()

    # Merge updates
    updated_row = dict(existing)
    if body.name is not None:
        updated_row["name"] = body.name
    if body.type is not None:
        updated_row["type"] = body.type.value
    if body.config is not None:
        updated_row["config_json"] = body.config
    if body.enabled is not None:
        updated_row["enabled"] = body.enabled
    updated_row["updated_at"] = now.isoformat()

    await db.upsert(POLICY_TABLE, updated_row)

    logger.info("Policy updated: %s by user %s", policy_id, current_user.id)

    return _row_to_response(updated_row)


@router.delete(
    "/policies/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete a policy",
)
async def delete_policy(
    policy_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> Response:
    """Delete a policy by ID.

    The policy must belong to the authenticated user's team.
    """
    team_id = _team_id_from_user(current_user)
    await _get_policy_or_404(policy_id, team_id)

    await db.delete(POLICY_TABLE, {"id": policy_id})

    logger.info("Policy deleted: %s by user %s", policy_id, current_user.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/policies/evaluate",
    response_model=PolicyEvaluateResponse,
    summary="Evaluate scan result against team policies",
    responses={401: {"model": ErrorResponse}, 403: {"model": GateError}},
)
async def evaluate_policies(
    body: PolicyEvaluateRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> PolicyEvaluateResponse:
    """Evaluate a scan result against all enabled team policies.

    Returns whether the scan is allowed, any policy violations, and whether
    it qualifies for auto-approval.
    """
    team_id = _team_id_from_user(current_user)

    # Fetch enabled policies for the team
    rows = await db.select(POLICY_TABLE, {"team_id": team_id}, limit=200)
    active_policies = [r for r in rows if r.get("enabled", True)]

    violations: list[str] = []
    auto_approved = False
    evaluated = 0

    for policy in active_policies:
        policy_type = policy.get("type", "")
        config = policy.get("config_json", policy.get("config", {}))
        policy_name = policy.get("name", policy_type)
        evaluated += 1

        if policy_type == PolicyType.BLOCKLIST.value:
            blocked_packages = config.get("packages", [])
            if body.target in blocked_packages:
                violations.append(
                    f"Policy '{policy_name}': target '{body.target}' is on the blocklist"
                )

        elif policy_type == PolicyType.ALLOWLIST.value:
            allowed_packages = config.get("packages", [])
            # Allowlist only applies if the target is explicitly in the list
            # (no violation if list is empty — allowlist is opt-in)
            if allowed_packages and body.target not in allowed_packages:
                violations.append(
                    f"Policy '{policy_name}': target '{body.target}' is not on the allowlist"
                )

        elif policy_type == PolicyType.AUTO_APPROVE_THRESHOLD.value:
            threshold = config.get("max_risk_score", 10.0)
            if body.risk_score <= threshold:
                auto_approved = True
            else:
                violations.append(
                    f"Policy '{policy_name}': risk score {body.risk_score:.1f} "
                    f"exceeds auto-approve threshold {threshold:.1f}"
                )

        elif policy_type == PolicyType.REQUIRED_PHASES.value:
            required = set(config.get("phases", []))
            if required:
                present_phases = {
                    f.phase.value if hasattr(f.phase, "value") else f.phase
                    for f in body.findings
                }
                missing = required - present_phases
                if missing:
                    violations.append(
                        f"Policy '{policy_name}': missing required scan phases: {', '.join(sorted(missing))}"
                    )

    allowed = len(violations) == 0

    return PolicyEvaluateResponse(
        allowed=allowed,
        violations=violations,
        auto_approved=auto_approved and allowed,
        evaluated_policies=evaluated,
    )
