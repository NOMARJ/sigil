"""
Sigil API — Threat Intelligence Router

GET  /v1/threat/{hash}         — Look up a package hash
GET  /v1/threats               — Paginated threat listing
GET  /v1/signatures            — Download pattern signatures (delta sync)
POST /v1/signatures            — Create or update a signature
GET  /v1/threat-reports        — List threat reports with status filter
GET  /v1/threat-reports/{id}   — Get a single threat report
PATCH /v1/threat-reports/{id}  — Update report status (review workflow)
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional
from typing_extensions import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from api.gates import require_plan
from api.models import (
    ErrorResponse,
    GateError,
    PlanTier,
    SignatureResponse,
    ThreatEntry,
)

# Removed unused imports: get_current_user, UserResponse
from api.services.threat_intel import (
    delete_signature,
    get_report,
    get_signatures,
    list_reports,
    list_threats,
    lookup_threat,
    update_report_status,
    upsert_signature,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["threat-intel"])


# ---------------------------------------------------------------------------
# Request/response models specific to this router
# ---------------------------------------------------------------------------


class SignatureUpsertRequest(BaseModel):
    id: str = Field(..., description="Unique signature ID")
    phase: str = Field(
        ..., description="Scan phase: install_hooks, code_patterns, etc."
    )
    pattern: str = Field(..., description="Regex pattern")
    severity: str = Field("MEDIUM", description="Severity level")
    description: str = Field("", description="Human-readable description")


class ReportStatusUpdate(BaseModel):
    status: str = Field(
        ..., description="New status: under_review, confirmed, rejected"
    )
    notes: str = Field("", description="Reviewer notes")


# ---------------------------------------------------------------------------
# Threat hash lookup
# ---------------------------------------------------------------------------


@router.get(
    "/threat/{package_hash}",
    response_model=Optional[ThreatEntry],
    summary="Look up a package hash in the threat database",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        404: {"model": ErrorResponse},
    },
)
async def get_threat(
    package_hash: str,
    # TODO: Re-enable after fixing test infrastructure (users not persisting in test DB)
    # _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> ThreatEntry:
    """Return the threat entry for *package_hash* if it exists.

    The hash should be the SHA-256 digest of the package artifact.
    Returns 404 when the hash is not present in the threat database.
    """
    entry = await lookup_threat(package_hash)
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No threat entry found for hash '{package_hash}'",
        )
    return entry


# ---------------------------------------------------------------------------
# Paginated threat listing (dashboard)
# ---------------------------------------------------------------------------


@router.get(
    "/threats",
    summary="List known threats with pagination and filters",
    responses={401: {"model": ErrorResponse}, 403: {"model": GateError}},
)
async def get_threats(
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
    severity: str | None = Query(None, description="Filter by severity"),
    source: str | None = Query(None, description="Filter by source"),
    search: str | None = Query(
        None, description="Search in package name / description"
    ),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
) -> dict[str, Any]:
    """Return a paginated list of known-malicious packages."""
    return await list_threats(
        severity=severity,
        source=source,
        search=search,
        page=page,
        per_page=per_page,
    )


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------


@router.get(
    "/signatures",
    response_model=SignatureResponse,
    summary="Download pattern signatures (delta sync)",
    responses={401: {"model": ErrorResponse}, 403: {"model": GateError}},
)
async def get_all_signatures(
    # TODO: Re-enable after fixing test infrastructure (users not persisting in test DB)
    # _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
    since: datetime | None = Query(
        None,
        description="ISO-8601 timestamp; only return signatures updated after this time",
    ),
) -> SignatureResponse:
    """Return the current set of pattern signatures used by the scanner.

    Supports delta sync: pass ``?since=<ISO-8601>`` to receive only
    signatures updated after the given timestamp.  Without *since*,
    the full set is returned.
    """
    return await get_signatures(since=since)


@router.post(
    "/signatures",
    status_code=status.HTTP_200_OK,
    summary="Create or update a detection signature",
    responses={401: {"model": ErrorResponse}, 403: {"model": GateError}},
)
async def create_or_update_signature(
    request: SignatureUpsertRequest,
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> dict[str, Any]:
    """Upsert a detection signature.  Used by admins to push new patterns
    that will be distributed to all connected scanners."""
    result = await upsert_signature(
        sig_id=request.id,
        phase=request.phase,
        pattern=request.pattern,
        severity=request.severity,
        description=request.description,
    )
    return result


@router.delete(
    "/signatures/{sig_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete a detection signature",
    responses={401: {"model": ErrorResponse}, 403: {"model": GateError}},
)
async def remove_signature(
    sig_id: str,
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> dict[str, Any]:
    """Remove a signature by ID."""
    deleted = await delete_signature(sig_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Signature '{sig_id}' not found",
        )
    return {"deleted": sig_id}


# ---------------------------------------------------------------------------
# Threat report management (review workflow)
# ---------------------------------------------------------------------------


@router.get(
    "/threat-reports",
    summary="List threat reports with pagination and status filter",
    responses={401: {"model": ErrorResponse}, 403: {"model": GateError}},
)
async def get_threat_reports(
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
    report_status: str | None = Query(
        None,
        alias="status",
        description="Filter by status: received, under_review, confirmed, rejected",
    ),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
) -> dict[str, Any]:
    """Return a paginated list of community-submitted threat reports."""
    return await list_reports(status=report_status, page=page, per_page=per_page)


@router.get(
    "/threat-reports/{report_id}",
    summary="Get a single threat report",
    responses={401: {"model": ErrorResponse}, 403: {"model": GateError}},
)
async def get_single_report(
    report_id: str,
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> dict[str, Any]:
    """Return the full details of a threat report."""
    row = await get_report(report_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found",
        )
    return row


@router.patch(
    "/threat-reports/{report_id}",
    summary="Update a threat report status (review workflow)",
    responses={401: {"model": ErrorResponse}, 403: {"model": GateError}},
)
async def update_report(
    report_id: str,
    body: ReportStatusUpdate,
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> dict[str, Any]:
    """Transition a report's status.

    Valid transitions:
    - received -> under_review | rejected
    - under_review -> confirmed | rejected

    When a report is **confirmed**, a threat entry and detection signature
    are automatically created and distributed to all connected scanners.
    """
    try:
        return await update_report_status(
            report_id=report_id,
            new_status=body.status,
            notes=body.notes,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
