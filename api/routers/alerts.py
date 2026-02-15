"""
Sigil API — Alert / Notification Router

Manages notification channel configurations and sends test alerts.

Endpoints:
    GET    /v1/alerts      — List alert configurations for the team
    POST   /v1/alerts      — Create a new alert channel
    PUT    /v1/alerts/{id}  — Update an alert channel configuration
    DELETE /v1/alerts/{id}  — Remove an alert channel
    POST   /v1/alerts/test  — Send a test notification
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.database import db
from api.models import (
    AlertCreate,
    AlertResponse,
    AlertTestRequest,
    AlertTestResponse,
    AlertUpdate,
    ChannelType,
    ErrorResponse,
)
from api.routers.auth import get_current_user, UserResponse
from api.services.notifications import send_notification

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["alerts"])

ALERT_TABLE = "alerts"
AUDIT_TABLE = "audit_log"

_DEFAULT_TEAM_ID = "default-team"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _team_id_from_user(user: UserResponse) -> str:
    """Extract team ID from user, with fallback."""
    return getattr(user, "team_id", None) or _DEFAULT_TEAM_ID


async def _get_alert_or_404(alert_id: str, team_id: str) -> dict:
    """Fetch an alert config by ID, ensuring it belongs to the team."""
    row = await db.select_one(ALERT_TABLE, {"id": alert_id})
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert channel '{alert_id}' not found",
        )
    if row.get("team_id") != team_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Alert channel does not belong to your team",
        )
    return row


def _row_to_response(row: dict) -> AlertResponse:
    """Convert a DB row dict to an AlertResponse model."""
    return AlertResponse(
        id=row["id"],
        team_id=row.get("team_id", _DEFAULT_TEAM_ID),
        channel_type=row.get("channel_type", ChannelType.WEBHOOK),
        channel_config=row.get("channel_config_json", row.get("channel_config", {})),
        enabled=row.get("enabled", True),
        created_at=row.get("created_at", datetime.utcnow()),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/alerts",
    response_model=list[AlertResponse],
    summary="List alert channel configurations",
    responses={401: {"model": ErrorResponse}},
)
async def list_alerts(
    current_user: Annotated[UserResponse, Depends(get_current_user)],
    enabled: bool | None = Query(None, description="Filter by enabled state"),
) -> list[AlertResponse]:
    """Return all configured alert channels for the authenticated user's team."""
    team_id = _team_id_from_user(current_user)
    filters: dict = {"team_id": team_id}
    if enabled is not None:
        filters["enabled"] = enabled

    rows = await db.select(ALERT_TABLE, filters, limit=100)
    return [_row_to_response(r) for r in rows]


@router.post(
    "/alerts",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an alert channel",
    responses={401: {"model": ErrorResponse}},
)
async def create_alert(
    body: AlertCreate,
    current_user: Annotated[UserResponse, Depends(get_current_user)],
) -> AlertResponse:
    """Create a new notification channel for the team.

    Supported channel types:
    - **slack** — requires ``webhook_url`` in config
    - **email** — requires ``recipients`` (list of email addresses) in config
    - **webhook** — requires ``webhook_url`` in config; optionally ``headers``
    """
    team_id = _team_id_from_user(current_user)
    now = datetime.utcnow()
    alert_id = uuid4().hex[:16]

    # Validate required config fields
    _validate_channel_config(body.channel_type, body.channel_config)

    row = {
        "id": alert_id,
        "team_id": team_id,
        "channel_type": body.channel_type.value,
        "channel_config_json": body.channel_config,
        "enabled": body.enabled,
        "created_at": now.isoformat(),
    }

    await db.insert(ALERT_TABLE, row)

    # Audit log
    try:
        await db.insert(
            AUDIT_TABLE,
            {
                "id": uuid4().hex[:16],
                "user_id": current_user.id,
                "team_id": team_id,
                "action": "alert.created",
                "details_json": {
                    "alert_id": alert_id,
                    "channel_type": body.channel_type.value,
                },
                "created_at": now.isoformat(),
            },
        )
    except Exception:
        logger.debug("Failed to write audit log for alert creation")

    logger.info(
        "Alert channel created: %s (%s) by user %s",
        alert_id,
        body.channel_type.value,
        current_user.id,
    )

    return _row_to_response(row)


@router.put(
    "/alerts/{alert_id}",
    response_model=AlertResponse,
    summary="Update an alert channel",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def update_alert(
    alert_id: str,
    body: AlertUpdate,
    current_user: Annotated[UserResponse, Depends(get_current_user)],
) -> AlertResponse:
    """Update an existing alert channel's type, configuration, or enabled state.

    Only the fields provided in the request body are updated.
    """
    team_id = _team_id_from_user(current_user)
    existing = await _get_alert_or_404(alert_id, team_id)

    updated_row = dict(existing)
    if body.channel_type is not None:
        updated_row["channel_type"] = body.channel_type.value
    if body.channel_config is not None:
        channel_type = body.channel_type or ChannelType(
            existing.get("channel_type", "webhook")
        )
        _validate_channel_config(channel_type, body.channel_config)
        updated_row["channel_config_json"] = body.channel_config
    if body.enabled is not None:
        updated_row["enabled"] = body.enabled

    await db.upsert(ALERT_TABLE, updated_row)

    logger.info("Alert channel updated: %s by user %s", alert_id, current_user.id)

    return _row_to_response(updated_row)


@router.delete(
    "/alerts/{alert_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove an alert channel",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def delete_alert(
    alert_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user)],
) -> None:
    """Delete an alert channel by ID.

    The channel must belong to the authenticated user's team.
    """
    team_id = _team_id_from_user(current_user)
    await _get_alert_or_404(alert_id, team_id)

    # In-memory fallback: remove from the store
    from api.database import _memory_store

    store = _memory_store.get(ALERT_TABLE, {})
    store.pop(alert_id, None)

    # Supabase
    if db.connected and db._client is not None:
        try:
            db._client.table(ALERT_TABLE).delete().eq("id", alert_id).execute()
        except Exception:
            logger.exception("Failed to delete alert %s from Supabase", alert_id)

    logger.info("Alert channel deleted: %s by user %s", alert_id, current_user.id)


@router.post(
    "/alerts/test",
    response_model=AlertTestResponse,
    summary="Send a test notification",
    responses={401: {"model": ErrorResponse}},
)
async def test_alert(
    body: AlertTestRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user)],
) -> AlertTestResponse:
    """Send a test notification through the specified channel.

    This does not require the channel to be saved — it uses the provided
    configuration directly for a one-off test delivery.
    """
    _validate_channel_config(body.channel_type, body.channel_config)

    success = await send_notification(
        channel_type=body.channel_type.value,
        channel_config=body.channel_config,
        title="Sigil Test Notification",
        message=(
            "This is a test notification from Sigil. "
            "If you are receiving this, your alert channel is configured correctly."
        ),
    )

    if success:
        return AlertTestResponse(
            success=True,
            message="Test notification sent successfully",
        )
    else:
        return AlertTestResponse(
            success=False,
            message=(
                "Test notification could not be delivered. "
                "Check your channel configuration and try again."
            ),
        )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_channel_config(channel_type: ChannelType, config: dict) -> None:
    """Validate that required configuration keys are present for the channel type."""
    if channel_type == ChannelType.SLACK:
        if not config.get("webhook_url"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Slack channel requires 'webhook_url' in channel_config",
            )
    elif channel_type == ChannelType.EMAIL:
        recipients = config.get("recipients", [])
        if not recipients:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Email channel requires 'recipients' (list of email addresses) in channel_config",
            )
    elif channel_type == ChannelType.WEBHOOK:
        if not config.get("webhook_url"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Webhook channel requires 'webhook_url' in channel_config",
            )
