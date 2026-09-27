"""
Sigil API — Website Change Monitoring Router

HTTP surface for the change-monitoring queue implemented in
``api.services.change_monitor``. Sigil scans an upstream artifact once; when the
content at that URL later changes, what users receive is no longer what we
vetted. These endpoints manage the watch list and expose the resulting queue.

POST   /api/monitor/sources                    — register a URL to watch
GET    /api/monitor/sources                    — list watched sources (paginated)
GET    /api/monitor/sources/{source_id}        — one source plus recent events
PATCH  /api/monitor/sources/{source_id}        — enable/disable, change interval
DELETE /api/monitor/sources/{source_id}        — stop watching (removes events)
GET    /api/monitor/queue                      — change events awaiting rescan
GET    /api/monitor/status                     — queue counters
POST   /api/monitor/sources/{source_id}/check  — force one poll now

Every value returned here is read back from the datastore or computed from a
real observation. Nothing on this router synthesises a source, an event, a hash
or a count; when the database layer is running in its in-memory fallback the
responses reflect that store's true contents rather than a placeholder.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any
from typing_extensions import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from api.database import db
from api.models import ErrorResponse
from api.permissions import require_review_role
from api.rate_limit import RateLimiter
from api.routers.auth import get_current_user_unified, UserResponse
from api.services import change_monitor as cm

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/monitor", tags=["change-monitor"])

#: ``monitored_sources.url`` is NVARCHAR(450) (900 bytes, the maximum key size
#: for the UNIQUE index on it), which is tighter than the service's own
#: MAX_URL_LENGTH of 2048. Reject over-long URLs here rather than letting the
#: insert truncate or fail downstream.
MAX_URL_COLUMN_CHARS = 450
#: ``monitored_sources.ref_id`` is NVARCHAR(200).
MAX_REF_ID_CHARS = 200
#: Upper bound on a poll interval — 30 days. Anything slower is effectively
#: unmonitored, and the value has to stay inside INT.
MAX_CHECK_INTERVAL_MINUTES = 43_200
#: Ceiling on the serialised ``metadata_json`` payload a caller may attach.
MAX_METADATA_CHARS = 8_000
#: How many recent events the source-detail endpoint returns by default.
DEFAULT_EVENT_HISTORY = 20


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class MonitoredSourceCreate(BaseModel):
    """Request body for registering a URL to watch."""

    url: str = Field(
        ...,
        min_length=1,
        max_length=MAX_URL_COLUMN_CHARS,
        description="Absolute http(s) URL to poll. Validated against the SSRF guard.",
    )
    source_type: str = Field(
        "other",
        description=(
            "One of: mcp_server, registry_listing, package_page, marketplace, other"
        ),
    )
    ref_id: str | None = Field(
        None,
        max_length=MAX_REF_ID_CHARS,
        description=(
            "Optional logical link to what this URL represents, "
            'e.g. an mcp_servers.repo_name or "npm:left-pad@1.3.0"'
        ),
    )
    check_interval_minutes: int = Field(
        cm.DEFAULT_CHECK_INTERVAL_MINUTES,
        ge=cm.MIN_CHECK_INTERVAL_MINUTES,
        le=MAX_CHECK_INTERVAL_MINUTES,
        description="Minimum minutes between polls, before failure backoff.",
    )
    enabled: bool = Field(True, description="Whether the poller should pick this up.")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form JSON stored alongside the source.",
    )


class MonitoredSourceUpdate(BaseModel):
    """Request body for changing a source's schedule or enabled state.

    Every field is optional; omitted fields are left untouched. The URL itself
    is deliberately immutable — a different URL is a different thing to watch,
    and reusing the row would carry the old content hash across to content that
    was never compared against it.
    """

    enabled: bool | None = Field(None, description="Enable or disable polling.")
    check_interval_minutes: int | None = Field(
        None,
        ge=cm.MIN_CHECK_INTERVAL_MINUTES,
        le=MAX_CHECK_INTERVAL_MINUTES,
        description="New minimum minutes between polls.",
    )


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class MonitoredSourceResponse(BaseModel):
    """One watched URL and its current polling state."""

    id: str
    url: str
    source_type: str
    ref_id: str | None = None
    enabled: bool = True
    check_interval_minutes: int = cm.DEFAULT_CHECK_INTERVAL_MINUTES

    last_checked_at: datetime | None = None
    last_changed_at: datetime | None = None
    last_status_code: int | None = None
    content_hash: str | None = None
    etag: str | None = None
    last_modified: str | None = None
    consecutive_failures: int = 0

    # Derived from the stored row by the service's pure scheduling functions —
    # the same predicates the poller itself uses, not a separate estimate.
    effective_interval_minutes: int = cm.DEFAULT_CHECK_INTERVAL_MINUTES
    next_check_due_at: datetime | None = None
    is_due: bool = False

    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ChangeEventResponse(BaseModel):
    """One recorded observation of a watched URL."""

    id: str
    source_id: str
    change_kind: str  # content | etag | first_seen | gone | error | unchanged
    detected_at: datetime | None = None
    previous_hash: str | None = None
    new_hash: str | None = None
    http_status: int | None = None
    bytes_before: int | None = None
    bytes_after: int | None = None
    notes: str = ""
    queued_for_rescan: bool = False
    rescan_enqueued_at: datetime | None = None


class SourceRegistrationResponse(BaseModel):
    """Result of a registration request.

    ``created`` is False when the URL was already being watched — registration
    is idempotent, and the pre-existing row is returned untouched rather than
    duplicated or reset.
    """

    created: bool
    source: MonitoredSourceResponse


class MonitoredSourceListResponse(BaseModel):
    """A page of watched sources.

    There is no ``total``: an exact count needs a COUNT(*) that the database
    layer's in-memory fallback cannot serve, and reporting an estimate as a
    total would be inventing a number. ``has_more`` is measured by fetching one
    row beyond the page.
    """

    items: list[MonitoredSourceResponse] = Field(default_factory=list)
    page: int = 1
    per_page: int = 20
    returned: int = 0
    has_more: bool = False


class SourceDetailResponse(BaseModel):
    """One source together with its most recent change events."""

    source: MonitoredSourceResponse
    recent_events: list[ChangeEventResponse] = Field(default_factory=list)
    event_count_returned: int = 0


class PendingQueueResponse(BaseModel):
    """Change events that are still waiting to be turned into a rescan."""

    items: list[ChangeEventResponse] = Field(default_factory=list)
    returned: int = 0
    limit: int = cm.DEFAULT_BATCH_SIZE


class QueueStatusResponse(BaseModel):
    """Live counters over the monitored_sources / source_change_events tables."""

    total_sources: int = 0
    enabled_sources: int = 0
    due_now: int = 0
    failing_sources: int = 0
    pending_rescans: int = 0
    as_of: str = ""


class ForceCheckResponse(BaseModel):
    """Outcome of an operator-triggered poll.

    The three booleans are deliberately distinct, because "something happened"
    and "the content changed" are not the same claim. ``recorded`` means an
    event row was written (anything other than ``unchanged``, including a
    failure). ``content_changed`` is true only when the normalised body actually
    differed from the stored hash — an ``error``, ``gone`` or ``etag`` outcome
    is not a content change and must not be reported as one.

    These booleans are only ever sent for a poll whose outcome was persisted: a
    failed write raises out of ``process_source`` and the request fails with a
    500 instead of reporting an event row that was not written.
    """

    source: MonitoredSourceResponse
    event: ChangeEventResponse
    recorded: bool = False
    content_changed: bool = False
    rescan_queued: bool = False


class DeleteSourceResponse(BaseModel):
    """Confirmation that a source and its event history were removed."""

    deleted: str
    events_deleted: int


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _source_response(
    source: cm.MonitoredSource, *, now: datetime | None = None
) -> MonitoredSourceResponse:
    """Project a service dataclass onto the wire model.

    The schedule fields are recomputed with ``cm.backoff_minutes`` /
    ``cm.next_check_due_at`` / ``cm.is_due`` so that what a caller sees is
    exactly what the poller will do with this row.
    """
    reference = now or cm.utcnow()
    return MonitoredSourceResponse(
        id=source.id,
        url=source.url,
        source_type=source.source_type,
        ref_id=source.ref_id,
        enabled=source.enabled,
        check_interval_minutes=source.check_interval_minutes,
        last_checked_at=source.last_checked_at,
        last_changed_at=source.last_changed_at,
        last_status_code=source.last_status_code,
        content_hash=source.content_hash,
        etag=source.etag,
        last_modified=source.last_modified,
        consecutive_failures=source.consecutive_failures,
        effective_interval_minutes=cm.backoff_minutes(
            source.check_interval_minutes, source.consecutive_failures
        ),
        next_check_due_at=cm.next_check_due_at(source, now=reference),
        is_due=cm.is_due(source, now=reference),
        metadata=source.metadata,
        created_at=source.created_at,
        updated_at=source.updated_at,
    )


def _event_response(event: cm.ChangeEvent) -> ChangeEventResponse:
    """Project a service change event onto the wire model."""
    return ChangeEventResponse(
        id=event.id,
        source_id=event.source_id,
        change_kind=event.change_kind,
        detected_at=event.detected_at,
        previous_hash=event.previous_hash,
        new_hash=event.new_hash,
        http_status=event.http_status,
        bytes_before=event.bytes_before,
        bytes_after=event.bytes_after,
        notes=event.notes,
        queued_for_rescan=event.queued_for_rescan,
        rescan_enqueued_at=event.rescan_enqueued_at,
    )


async def _load_source_or_404(source_id: str) -> cm.MonitoredSource:
    """Fetch a source by id or raise a 404."""
    source = await cm.get_source(source_id)
    if source is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Monitored source {source_id} not found",
        )
    return source


def _validate_source_type(source_type: str) -> str:
    """Reject a source_type the CK constraint would reject at insert time."""
    if source_type not in cm.SOURCE_TYPES:
        allowed = ", ".join(sorted(cm.SOURCE_TYPES))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown source_type '{source_type}'. Allowed: {allowed}",
        )
    return source_type


# ---------------------------------------------------------------------------
# Source management
# ---------------------------------------------------------------------------


@router.post(
    "/sources",
    response_model=SourceRegistrationResponse,
    status_code=status.HTTP_200_OK,
    summary="Register a URL for change monitoring",
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        429: {"description": "Rate limit exceeded"},
    },
    dependencies=[Depends(RateLimiter(max_requests=20, window=60))],
)
async def register_monitored_source(
    body: MonitoredSourceCreate,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> SourceRegistrationResponse:
    """Add a URL to the change-monitoring watch list.

    The URL is put through ``change_monitor.assert_safe_url`` before anything is
    written. That guard rejects non-http(s) schemes, embedded credentials,
    non-web ports, single-label and ``.internal``-style hostnames, and any
    literal that resolves to a non-global address — loopback, RFC1918, CGNAT and
    the 169.254.0.0/16 link-local range that carries the cloud instance metadata
    endpoint. A URL that fails is rejected with 400 and never reaches the table,
    so the poller cannot be aimed at internal infrastructure.

    Registration is idempotent: if the URL is already watched, the existing row
    is returned with ``created: false`` and is left exactly as it was. Its
    schedule is changed through PATCH, not by re-registering.

    Requires a reviewer, admin or owner role — a monitored source is shared
    infrastructure that causes the server to make outbound requests.
    """
    require_review_role(current_user)
    _validate_source_type(body.source_type)

    if body.metadata:
        try:
            serialised = json.dumps(body.metadata)
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"metadata is not JSON-serialisable: {exc}",
            ) from exc
        if len(serialised) > MAX_METADATA_CHARS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"metadata exceeds {MAX_METADATA_CHARS} serialised characters",
            )

    try:
        safe_url = cm.assert_safe_url(body.url)
    except cm.UnsafeURLError as exc:
        logger.warning(
            "Rejected unsafe monitored-source URL from user %s: %s",
            current_user.id,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsafe URL: {exc}",
        ) from exc

    if len(safe_url) > MAX_URL_COLUMN_CHARS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Normalised URL exceeds {MAX_URL_COLUMN_CHARS} characters",
        )

    try:
        existing = await cm.get_source_by_url(safe_url)
        if existing is not None:
            return SourceRegistrationResponse(
                created=False, source=_source_response(existing)
            )

        source = await cm.register_source(
            safe_url,
            body.source_type,
            ref_id=body.ref_id,
            check_interval_minutes=body.check_interval_minutes,
            enabled=body.enabled,
            metadata=body.metadata,
        )
    except cm.UnsafeURLError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsafe URL: {exc}",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to register monitored source %s: %s", safe_url, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to register monitored source: {str(e)}",
        )

    logger.info(
        "User %s registered monitored source %s (%s)",
        current_user.id,
        source.id,
        source.source_type,
    )
    return SourceRegistrationResponse(created=True, source=_source_response(source))


@router.get(
    "/sources",
    response_model=MonitoredSourceListResponse,
    status_code=status.HTTP_200_OK,
    summary="List monitored sources",
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        429: {"description": "Rate limit exceeded"},
    },
    dependencies=[Depends(RateLimiter(max_requests=60, window=60))],
)
async def list_monitored_sources(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    enabled: bool | None = Query(None, description="Filter by enabled state"),
    source_type: str | None = Query(
        None,
        description=(
            "Filter by type: mcp_server, registry_listing, package_page, "
            "marketplace, other"
        ),
    ),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
) -> MonitoredSourceListResponse:
    """Return a page of watched sources, newest registration first.

    ``enabled`` and ``source_type`` are optional equality filters. Paging is the
    page/per_page form used by the registry and threat routers; ``has_more`` is
    determined by asking the datastore for one row beyond the page, so it is a
    measured fact rather than an inferred one.
    """
    filters: dict[str, Any] = {}
    if enabled is not None:
        filters["enabled"] = enabled
    if source_type is not None:
        filters["source_type"] = _validate_source_type(source_type)

    offset = (page - 1) * per_page
    try:
        rows = await db.select(
            cm.MONITORED_SOURCES_TABLE,
            filters or None,
            limit=per_page + 1,
            offset=offset,
            order_by="created_at",
            order_desc=True,
        )
    except Exception as e:
        logger.exception("Failed to list monitored sources: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list monitored sources: {str(e)}",
        )

    has_more = len(rows) > per_page
    page_rows = rows[:per_page]
    now = cm.utcnow()
    items = [
        _source_response(cm.MonitoredSource.from_row(row), now=now) for row in page_rows
    ]
    return MonitoredSourceListResponse(
        items=items,
        page=page,
        per_page=per_page,
        returned=len(items),
        has_more=has_more,
    )


@router.get(
    "/sources/{source_id}",
    response_model=SourceDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get one monitored source with its recent change events",
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        429: {"description": "Rate limit exceeded"},
    },
    dependencies=[Depends(RateLimiter(max_requests=60, window=60))],
)
async def get_monitored_source(
    source_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    event_limit: int = Query(
        DEFAULT_EVENT_HISTORY,
        ge=1,
        le=200,
        description="How many recent change events to include, newest first",
    ),
) -> SourceDetailResponse:
    """Return one watched source plus its most recent change events.

    The event list is the recorded history for this source — only observations
    the poller actually classified as something other than "unchanged" are
    written, so an empty list means the URL has been stable (or has never been
    polled), not that data is missing.
    """
    try:
        source = await _load_source_or_404(source_id)
        events = await cm.source_events(source_id, limit=event_limit)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to load monitored source %s: %s", source_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load monitored source: {str(e)}",
        )

    event_models = [_event_response(event) for event in events]
    return SourceDetailResponse(
        source=_source_response(source),
        recent_events=event_models,
        event_count_returned=len(event_models),
    )


@router.patch(
    "/sources/{source_id}",
    response_model=MonitoredSourceResponse,
    status_code=status.HTTP_200_OK,
    summary="Enable, disable or reschedule a monitored source",
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        429: {"description": "Rate limit exceeded"},
    },
    dependencies=[Depends(RateLimiter(max_requests=20, window=60))],
)
async def update_monitored_source(
    source_id: str,
    body: MonitoredSourceUpdate,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> MonitoredSourceResponse:
    """Change a source's enabled state and/or its polling interval.

    Only ``enabled`` and ``check_interval_minutes`` are mutable. The URL is not:
    pointing an existing row at different content would leave the stored content
    hash describing bytes the new URL was never compared against, and the first
    poll afterwards would report a change that did not happen.

    Sending neither field is a 400 rather than a silent no-op. Content hash,
    validators and the failure counter are owned by the poller and are not
    touched here.

    Requires a reviewer, admin or owner role.
    """
    require_review_role(current_user)

    payload: dict[str, Any] = {}
    if body.enabled is not None:
        payload["enabled"] = body.enabled
    if body.check_interval_minutes is not None:
        payload["check_interval_minutes"] = body.check_interval_minutes
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide at least one of: enabled, check_interval_minutes",
        )

    try:
        await _load_source_or_404(source_id)
        payload["updated_at"] = cm.utcnow().isoformat()
        # db.update signature is update(table, filters, data) — filters first.
        await db.update(cm.MONITORED_SOURCES_TABLE, {"id": source_id}, payload)
        updated = await _load_source_or_404(source_id)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to update monitored source %s: %s", source_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update monitored source: {str(e)}",
        )

    logger.info(
        "User %s updated monitored source %s (%s)",
        current_user.id,
        source_id,
        ", ".join(sorted(k for k in payload if k != "updated_at")),
    )
    return _source_response(updated)


@router.delete(
    "/sources/{source_id}",
    response_model=DeleteSourceResponse,
    status_code=status.HTTP_200_OK,
    summary="Stop monitoring a source",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        429: {"description": "Rate limit exceeded"},
    },
    dependencies=[Depends(RateLimiter(max_requests=10, window=60))],
)
async def delete_monitored_source(
    source_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> DeleteSourceResponse:
    """Remove a source from the watch list, along with its change events.

    The event rows are deleted too: ``source_change_events`` carries no foreign
    key (matching the house style of the other migrations), so leaving them
    behind would strand rows whose ``source_id`` resolves to nothing — including
    rows still flagged ``queued_for_rescan``, which a worker would then keep
    picking up forever. ``events_deleted`` is the count that was actually read
    back before deletion, not an estimate.

    Requires a reviewer, admin or owner role.
    """
    require_review_role(current_user)

    try:
        await _load_source_or_404(source_id)
        existing_events = await db.select(
            cm.SOURCE_CHANGE_EVENTS_TABLE, {"source_id": source_id}
        )
        await db.delete(cm.SOURCE_CHANGE_EVENTS_TABLE, {"source_id": source_id})
        await db.delete(cm.MONITORED_SOURCES_TABLE, {"id": source_id})
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to delete monitored source %s: %s", source_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete monitored source: {str(e)}",
        )

    logger.info(
        "User %s deleted monitored source %s (%d events)",
        current_user.id,
        source_id,
        len(existing_events),
    )
    return DeleteSourceResponse(deleted=source_id, events_deleted=len(existing_events))


# ---------------------------------------------------------------------------
# Queue
# ---------------------------------------------------------------------------


@router.get(
    "/queue",
    response_model=PendingQueueResponse,
    status_code=status.HTTP_200_OK,
    summary="List change events awaiting rescan",
    responses={
        401: {"model": ErrorResponse},
        429: {"description": "Rate limit exceeded"},
    },
    dependencies=[Depends(RateLimiter(max_requests=30, window=60))],
)
async def get_pending_queue(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    limit: int = Query(
        cm.DEFAULT_BATCH_SIZE,
        ge=1,
        le=200,
        description="Maximum events to return, oldest first",
    ),
) -> PendingQueueResponse:
    """Return the change events still waiting to be turned into a rescan.

    Queue semantics come from the service: ``queued_for_rescan = 1`` means
    *outstanding*. A worker calls ``mark_rescan_enqueued`` once it has handed
    the event to a scanner, which clears the flag and stamps
    ``rescan_enqueued_at`` — so an event disappearing from this list means it
    was picked up, not that it was dropped.

    Only ``content`` and ``first_seen`` events are queued. An ``etag`` event
    means the validators moved while the normalised body did not, and ``error``
    or ``gone`` mean no content was obtained at all; none of those are evidence
    that anything needs rescanning.
    """
    try:
        events = await cm.pending_rescan_events(limit=limit)
    except Exception as e:
        logger.exception("Failed to load pending rescan queue: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load pending rescan queue: {str(e)}",
        )

    items = [_event_response(event) for event in events]
    return PendingQueueResponse(items=items, returned=len(items), limit=limit)


@router.get(
    "/status",
    response_model=QueueStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Change-monitor queue counters",
    responses={
        401: {"model": ErrorResponse},
        429: {"description": "Rate limit exceeded"},
    },
    dependencies=[Depends(RateLimiter(max_requests=30, window=60))],
)
async def get_monitor_status(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> QueueStatusResponse:
    """Return live counters over the monitoring tables.

    Every number is a real row count taken at request time: total and enabled
    sources, how many are due for a poll right now under the same backoff-aware
    predicate the poller uses, how many are in a failure streak, and the depth
    of the pending rescan queue. If the counters cannot be computed the request
    fails with a 500 rather than returning zeros that would read as "nothing to
    do".
    """
    try:
        counters = await cm.get_queue_status()
    except Exception as e:
        logger.exception("Failed to compute change-monitor status: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compute change-monitor status: {str(e)}",
        )

    if "error" in counters:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compute change-monitor status: {counters['error']}",
        )

    return QueueStatusResponse(
        total_sources=int(counters.get("total_sources", 0)),
        enabled_sources=int(counters.get("enabled_sources", 0)),
        due_now=int(counters.get("due_now", 0)),
        failing_sources=int(counters.get("failing_sources", 0)),
        pending_rescans=int(counters.get("pending_rescans", 0)),
        as_of=str(counters.get("as_of", "")),
    )


# ---------------------------------------------------------------------------
# Forced poll
# ---------------------------------------------------------------------------


@router.post(
    "/sources/{source_id}/check",
    response_model=ForceCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Poll a monitored source immediately",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        429: {"description": "Rate limit exceeded"},
    },
    dependencies=[Depends(RateLimiter(max_requests=5, window=300))],
)
async def force_check_source(
    source_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> ForceCheckResponse:
    """Run one real poll of a source now, ignoring its schedule.

    This makes an actual outbound conditional GET through the service's
    ``default_fetcher``: stored ETag / Last-Modified are replayed, a 304
    short-circuits with no body transfer, redirects are followed manually with
    the SSRF guard re-applied at every hop, and the body is size-capped. The
    result is persisted exactly as a scheduled poll would persist it — source
    counters updated, a change event written when the observation is not
    "unchanged", and the rescan queue updated when the change warrants it.

    A failed fetch comes back as an ``error`` event with the failure counter
    incremented and backoff extended. It is never reported as a content change,
    and no hash is produced for content that was not received.

    A disabled source can still be checked this way — the schedule is what
    ``enabled`` governs, and an explicit operator poll is not the schedule.

    Deliberately the tightest rate limit on this router (5 per 5 minutes,
    per caller) because it is the one endpoint that lets a request trigger an
    outbound network call. Requires a reviewer, admin or owner role.
    """
    require_review_role(current_user)

    try:
        source = await _load_source_or_404(source_id)
        event = await cm.process_source(source)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(
            "Forced check failed for monitored source %s: %s", source_id, e
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Forced check failed: {str(e)}",
        )

    logger.info(
        "User %s forced a check of source %s -> %s (HTTP %s)",
        current_user.id,
        source_id,
        event.change_kind,
        event.http_status,
    )
    return ForceCheckResponse(
        source=_source_response(source),
        event=_event_response(event),
        recorded=event.is_change,
        content_changed=event.change_kind == "content",
        rescan_queued=bool(event.queued_for_rescan),
    )
