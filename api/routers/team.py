"""
Sigil API — Team Management Router

Manages team membership, invitations, and role assignments.

Endpoints:
    GET    /team                        — Get current user's team with members
    POST   /team/invite                 — Invite a member to the team by email
    DELETE /team/members/{user_id}      — Remove a member from the team
    PATCH  /team/members/{user_id}/role — Update a member's role
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from typing_extensions import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response, status

from api.database import db
from api.gates import require_plan
from api.models import (
    ErrorResponse,
    GateError,
    PlanTier,
    RoleUpdateRequest,
    TeamInviteRequest,
    TeamInviteResponse,
    TeamMember,
    TeamResponse,
)
from api.routers.auth import get_current_user_unified, UserResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/team", tags=["team"])

TEAM_TABLE = "teams"
USER_TABLE = "users"
AUDIT_TABLE = "audit_log"

_VALID_ROLES = {"member", "admin", "owner"}
_DEFAULT_TEAM_ID = "default-team"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _get_or_create_team(user: UserResponse) -> dict[str, Any]:
    """Return the team for the given user, creating a default if needed."""
    user_row = await db.select_one(USER_TABLE, {"id": user.id})
    team_id = None
    if user_row:
        team_id = user_row.get("team_id")

    if team_id:
        team = await db.select_one(TEAM_TABLE, {"id": team_id})
        if team is not None:
            return team

    # No team found — create a default personal team
    now = datetime.utcnow()
    team_id = uuid4().hex[:16]
    team_row = {
        "id": team_id,
        "name": f"{user.name or user.email}'s Team",
        "owner_id": user.id,
        "plan": "free",
        "created_at": now.isoformat(),
    }
    await db.insert(TEAM_TABLE, team_row)

    # Assign the user to this team
    if user_row:
        user_row["team_id"] = team_id
        user_row["role"] = "owner"
        await db.upsert(USER_TABLE, user_row)

    return team_row


async def _get_team_members(team_id: str) -> list[dict[str, Any]]:
    """Fetch all users belonging to a team."""
    rows = await db.select(USER_TABLE, {"team_id": team_id}, limit=500)
    return rows


def _user_to_member(row: dict[str, Any]) -> TeamMember:
    """Convert a user DB row to a TeamMember model."""
    return TeamMember(
        id=row.get("id", ""),
        email=row.get("email", ""),
        name=row.get("name", ""),
        role=row.get("role", "member"),
        created_at=row.get("created_at", datetime.utcnow()),
    )


def _require_admin_or_owner(user_row: dict[str, Any] | None) -> None:
    """Raise 403 if the user is not an admin or owner of their team."""
    role = "member"
    if user_row:
        role = user_row.get("role", "member")
    if role not in ("admin", "owner"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only team admins or owners can perform this action",
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=TeamResponse,
    summary="Get current user's team with members",
    responses={401: {"model": ErrorResponse}, 403: {"model": GateError}},
)
async def get_team(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.TEAM))],
) -> TeamResponse:
    """Return the team for the authenticated user, including the members list.

    If the user has no team, a default personal team is created.
    """
    team = await _get_or_create_team(current_user)
    team_id = team.get("id", _DEFAULT_TEAM_ID)
    members = await _get_team_members(team_id)

    return TeamResponse(
        id=team_id,
        name=team.get("name", ""),
        owner_id=team.get("owner_id"),
        plan=team.get("plan", "free"),
        members=[_user_to_member(m) for m in members],
        created_at=team.get("created_at", datetime.utcnow()),
    )


@router.post(
    "/invite",
    response_model=TeamInviteResponse,
    summary="Invite a member to the team",
    responses={401: {"model": ErrorResponse}, 403: {"model": GateError}},
)
async def invite_member(
    body: TeamInviteRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.TEAM))],
) -> TeamInviteResponse:
    """Invite a user to join the team by email.

    Only admins and owners can invite new members.  If the invited user
    already has an account, they are added directly.  Otherwise the
    invite is recorded for when they register.
    """
    # Validate role
    if body.role not in _VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role '{body.role}'. Must be one of: {', '.join(sorted(_VALID_ROLES))}",
        )

    # Check caller's permissions
    caller_row = await db.select_one(USER_TABLE, {"id": current_user.id})
    _require_admin_or_owner(caller_row)

    team = await _get_or_create_team(current_user)
    team_id = team.get("id", _DEFAULT_TEAM_ID)

    # Check if user with this email already exists
    existing_user = await db.select_one(USER_TABLE, {"email": body.email})
    if existing_user is not None:
        # Already on this team?
        if existing_user.get("team_id") == team_id:
            return TeamInviteResponse(
                success=True,
                message="User is already a member of this team",
                email=body.email,
                role=existing_user.get("role", "member"),
            )

        # Add to team
        existing_user["team_id"] = team_id
        existing_user["role"] = body.role
        await db.upsert(USER_TABLE, existing_user)

        logger.info(
            "User %s added to team %s with role %s by %s",
            existing_user["id"],
            team_id,
            body.role,
            current_user.id,
        )

        return TeamInviteResponse(
            success=True,
            message=f"User '{body.email}' added to the team",
            email=body.email,
            role=body.role,
        )

    # User doesn't exist yet — record a pending invite
    try:
        await db.insert(
            AUDIT_TABLE,
            {
                "id": uuid4().hex[:16],
                "user_id": current_user.id,
                "team_id": team_id,
                "action": "team.invite",
                "details_json": {"email": body.email, "role": body.role},
                "created_at": datetime.utcnow().isoformat(),
            },
        )
    except Exception:
        logger.debug("Failed to write audit log for team invite")

    logger.info(
        "Invite sent to %s for team %s with role %s by %s",
        body.email,
        team_id,
        body.role,
        current_user.id,
    )

    return TeamInviteResponse(
        success=True,
        message=f"Invitation sent to '{body.email}'",
        email=body.email,
        role=body.role,
    )


@router.delete(
    "/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Remove a member from the team",
)
async def remove_member(
    user_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.TEAM))],
) -> Response:
    """Remove a member from the team.

    Only admins and owners can remove members.  The team owner cannot be
    removed.  A user cannot remove themselves through this endpoint.
    """
    # Check caller's permissions
    caller_row = await db.select_one(USER_TABLE, {"id": current_user.id})
    _require_admin_or_owner(caller_row)

    # Cannot remove yourself
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove yourself from the team",
        )

    target_user = await db.select_one(USER_TABLE, {"id": user_id})
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found",
        )

    # Cannot remove the team owner
    team = await _get_or_create_team(current_user)
    if team.get("owner_id") == user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot remove the team owner",
        )

    # Remove from team by clearing team_id
    target_user["team_id"] = None
    target_user["role"] = "member"
    await db.upsert(USER_TABLE, target_user)

    logger.info(
        "User %s removed from team %s by %s",
        user_id,
        team.get("id"),
        current_user.id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.patch(
    "/members/{user_id}/role",
    response_model=TeamMember,
    summary="Update a member's role",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        404: {"model": ErrorResponse},
    },
)
async def update_member_role(
    user_id: str,
    body: RoleUpdateRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.TEAM))],
) -> TeamMember:
    """Update a team member's role.

    Only admins and owners can change roles.  The ``owner`` role can only
    be assigned by the current owner (effectively transferring ownership).
    """
    if body.role not in _VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role '{body.role}'. Must be one of: {', '.join(sorted(_VALID_ROLES))}",
        )

    # Check caller's permissions
    caller_row = await db.select_one(USER_TABLE, {"id": current_user.id})
    _require_admin_or_owner(caller_row)

    # Only the owner can assign the owner role
    if body.role == "owner":
        caller_role = caller_row.get("role", "member") if caller_row else "member"
        if caller_role != "owner":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the current owner can transfer ownership",
            )

    target_user = await db.select_one(USER_TABLE, {"id": user_id})
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found",
        )

    # Verify the target is on the same team
    team = await _get_or_create_team(current_user)
    team_id = team.get("id")
    if target_user.get("team_id") != team_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User is not a member of your team",
        )

    target_user["role"] = body.role
    await db.upsert(USER_TABLE, target_user)

    logger.info(
        "Role updated for user %s to '%s' in team %s by %s",
        user_id,
        body.role,
        team_id,
        current_user.id,
    )

    return _user_to_member(target_user)
