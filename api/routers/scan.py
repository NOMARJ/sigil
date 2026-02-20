"""
Sigil API — Scan Router

POST /v1/scan         — Accept scan results, enrich with threat intelligence,
                        compute risk scores, and persist to the database.
GET  /scans           — List scans with pagination and filtering.
GET  /scans/{id}      — Get a single scan by ID.
GET  /scans/{id}/findings — Get findings for a scan.
POST /scans/{id}/approve  — Approve a quarantined scan.
POST /scans/{id}/reject   — Reject a quarantined scan.
POST /scans           — Submit a new scan (dashboard alias).
GET  /dashboard/stats — Aggregate dashboard statistics.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any
from typing_extensions import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.database import db
from api.gates import check_scan_quota, get_user_plan, require_plan
from api.models import (
    DashboardStats,
    ErrorResponse,
    GateError,
    PlanTier,
    ScanDetail,
    ScanListItem,
    ScanListResponse,
    ScanRequest,
    ScanResponse,
)
from api.routers.auth import get_current_user, UserResponse
from api.services.scoring import compute_verdict
from api.services.threat_intel import (
    lookup_threats_for_hashes,
    update_publisher_from_scan,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["scan"])

# Dashboard-facing router (no /v1 prefix)
dashboard_router = APIRouter(tags=["scan"])

SCAN_TABLE = "scans"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _row_to_list_item(row: dict[str, Any]) -> ScanListItem:
    """Convert a DB row to a ScanListItem."""
    return ScanListItem(
        id=row.get("id", ""),
        target=row.get("target", ""),
        target_type=row.get("target_type", "directory"),
        files_scanned=row.get("files_scanned", 0),
        findings_count=row.get("findings_count", 0),
        risk_score=row.get("risk_score", 0.0),
        verdict=row.get("verdict", "CLEAN"),
        threat_hits=row.get("threat_hits", 0),
        metadata=row.get("metadata_json", {}),
        created_at=row.get("created_at", datetime.utcnow()),
    )


def _row_to_detail(row: dict[str, Any]) -> ScanDetail:
    """Convert a DB row to a ScanDetail."""
    findings = row.get("findings_json", [])
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except (json.JSONDecodeError, TypeError):
            findings = []
    metadata = row.get("metadata_json", {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except (json.JSONDecodeError, TypeError):
            metadata = {}
    return ScanDetail(
        id=row.get("id", ""),
        target=row.get("target", ""),
        target_type=row.get("target_type", "directory"),
        files_scanned=row.get("files_scanned", 0),
        findings_count=row.get("findings_count", 0),
        risk_score=row.get("risk_score", 0.0),
        verdict=row.get("verdict", "CLEAN"),
        threat_hits=row.get("threat_hits", 0),
        findings_json=findings,
        metadata_json=metadata,
        created_at=row.get("created_at", datetime.utcnow()),
    )


async def _get_scan_or_404(scan_id: str) -> dict[str, Any]:
    """Fetch a scan by ID or raise 404."""
    row = await db.select_one(SCAN_TABLE, {"id": scan_id})
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found",
        )
    return row


# ---------------------------------------------------------------------------
# Core scan submission (existing endpoint)
# ---------------------------------------------------------------------------


async def _submit_scan_impl(
    request: ScanRequest, user_id: str | None = None
) -> ScanResponse:
    """Shared implementation for scan submission."""
    scan_id = uuid4().hex[:16]

    # --- 1. Compute risk score & verdict ------------------------------------
    risk_score, verdict = compute_verdict(request.findings)

    # --- 2. Threat intelligence enrichment ----------------------------------
    hashes: list[str] = []
    if "hashes" in request.metadata:
        hashes = request.metadata["hashes"]
    elif "hash" in request.metadata:
        hashes = [request.metadata["hash"]]

    threat_hits = await lookup_threats_for_hashes(hashes) if hashes else []

    if threat_hits:
        threat_bonus = sum(10.0 for _ in threat_hits)
        risk_score += threat_bonus
        from api.services.scoring import score_to_verdict

        verdict = score_to_verdict(risk_score)

    # --- 3. Build response --------------------------------------------------
    now = datetime.utcnow()
    response = ScanResponse(
        scan_id=scan_id,
        target=request.target,
        target_type=request.target_type,
        files_scanned=request.files_scanned,
        findings=request.findings,
        risk_score=round(risk_score, 2),
        verdict=verdict,
        threat_intel_hits=threat_hits,
        created_at=now,
    )

    # --- 4. Persist scan result ---------------------------------------------
    findings_data = [f.model_dump(mode="json") for f in request.findings]
    try:
        row_data: dict[str, Any] = {
            "id": scan_id,
            "target": request.target,
            "target_type": request.target_type,
            "files_scanned": request.files_scanned,
            "findings_count": len(request.findings),
            "risk_score": response.risk_score,
            "verdict": verdict.value,
            "threat_hits": len(threat_hits),
            "findings_json": findings_data,
            "metadata_json": request.metadata,
            "created_at": now.isoformat(),
        }
        if user_id:
            row_data["user_id"] = user_id
        await db.insert(SCAN_TABLE, row_data)
    except Exception:
        logger.exception("Failed to persist scan %s", scan_id)

    # --- 4b. Increment scan quota usage (only for authenticated users) ------
    if user_id:
        try:
            year_month = datetime.now(timezone.utc).strftime("%Y-%m")
            await db.increment_scan_usage(user_id, year_month)
        except Exception:
            logger.exception("Failed to increment scan usage for user %s", user_id)

    logger.info(
        "Scan %s completed: target=%s score=%.1f verdict=%s findings=%d",
        scan_id,
        request.target,
        risk_score,
        verdict.value,
        len(request.findings),
    )

    # --- 5. Publisher reputation enrichment --------------------------------
    publisher_id = request.metadata.get("publisher_id") or request.metadata.get(
        "publisher"
    )
    if publisher_id:
        is_flagged = verdict.value in ("HIGH_RISK", "CRITICAL")
        try:
            await update_publisher_from_scan(publisher_id, is_flagged=is_flagged)
        except Exception:
            logger.exception(
                "Failed to update publisher reputation for %s", publisher_id
            )

    return response


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit scan results for enrichment",
    responses={
        401: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        429: {"description": "Monthly scan quota exceeded"},
    },
)
async def submit_scan(
    request: ScanRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user)],
) -> ScanResponse:
    """Accept raw scan findings, enrich them with threat intelligence,
    compute an aggregate risk score and verdict, and persist the result.

    The response includes:
    - The original findings
    - A weighted risk score
    - A verdict (CLEAN / LOW_RISK / MEDIUM_RISK / HIGH_RISK / CRITICAL)
    - Any matching entries from the threat intelligence database

    Requires authentication. Monthly scan limits apply per plan tier.
    """
    current_tier = await get_user_plan(current_user.id)
    await check_scan_quota(current_user.id, current_tier)
    return await _submit_scan_impl(request, user_id=current_user.id)


# ---------------------------------------------------------------------------
# Dashboard scan endpoints (on dashboard_router, no /v1 prefix)
# ---------------------------------------------------------------------------


@dashboard_router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit scan results (dashboard path)",
    responses={
        401: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        429: {"description": "Monthly scan quota exceeded"},
    },
)
async def submit_scan_dashboard(
    request: ScanRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user)],
) -> ScanResponse:
    """Dashboard-compatible alias for scan submission at POST /scans."""
    current_tier = await get_user_plan(current_user.id)
    await check_scan_quota(current_user.id, current_tier)
    return await _submit_scan_impl(request, user_id=current_user.id)


@dashboard_router.get(
    "/scans",
    response_model=ScanListResponse,
    summary="List scans with pagination",
    responses={401: {"model": ErrorResponse}},
)
async def list_scans(
    current_user: Annotated[UserResponse, Depends(get_current_user)],
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    verdict: str | None = Query(None, description="Filter by verdict"),
    source: str | None = Query(None, description="Filter by target_type"),
    search: str | None = Query(None, description="Search in target name"),
) -> ScanListResponse:
    """Return a paginated list of scans for the authenticated user.

    Supports filtering by verdict, source (target_type), and free-text
    search in the target name.

    Free plan users receive an empty list with an upgrade message.
    PRO plan and above receive full scan history.
    """
    # Soft-gate: FREE tier gets empty list + upgrade prompt
    current_tier = await get_user_plan(current_user.id)
    if current_tier == PlanTier.FREE:
        return ScanListResponse(
            items=[],
            total=0,
            page=page,
            per_page=per_page,
            upgrade_message=(
                "Scan history is available on the Pro plan and above. "
                "Upgrade at https://app.sigilsec.ai/upgrade"
            ),
        )

    filters: dict[str, Any] = {}
    if verdict:
        filters["verdict"] = verdict
    if source:
        filters["target_type"] = source

    # Fetch a generous batch for in-memory pagination/filtering
    rows = await db.select(SCAN_TABLE, filters if filters else None, limit=1000)

    # Apply text search filter in-memory
    if search:
        search_lower = search.lower()
        rows = [r for r in rows if search_lower in r.get("target", "").lower()]

    # Sort by created_at descending
    rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)

    total = len(rows)
    start = (page - 1) * per_page
    end = start + per_page
    page_rows = rows[start:end]

    return ScanListResponse(
        items=[_row_to_list_item(r) for r in page_rows],
        total=total,
        page=page,
        per_page=per_page,
    )


@dashboard_router.get(
    "/scans/{scan_id}",
    response_model=ScanDetail,
    summary="Get a single scan by ID",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        404: {"model": ErrorResponse},
    },
)
async def get_scan(
    scan_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> ScanDetail:
    """Return the full details of a scan by its ID."""
    row = await _get_scan_or_404(scan_id)
    return _row_to_detail(row)


@dashboard_router.get(
    "/scans/{scan_id}/findings",
    response_model=list[dict[str, Any]],
    summary="Get findings for a scan",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        404: {"model": ErrorResponse},
    },
)
async def get_scan_findings(
    scan_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> list[dict[str, Any]]:
    """Return the findings extracted from a scan's findings_json field."""
    row = await _get_scan_or_404(scan_id)
    findings = row.get("findings_json", [])
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except (json.JSONDecodeError, TypeError):
            findings = []
    return findings


@dashboard_router.post(
    "/scans/{scan_id}/approve",
    response_model=dict[str, Any],
    summary="Approve a quarantined scan",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        404: {"model": ErrorResponse},
    },
)
async def approve_scan(
    scan_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> dict[str, Any]:
    """Approve a scan, marking it as safe in the metadata."""
    row = await _get_scan_or_404(scan_id)

    metadata = row.get("metadata_json", {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except (json.JSONDecodeError, TypeError):
            metadata = {}

    metadata["approved"] = True
    metadata["approved_by"] = current_user.id
    metadata["approved_at"] = datetime.utcnow().isoformat()
    metadata.pop("rejected", None)
    metadata.pop("rejected_by", None)
    metadata.pop("rejected_at", None)

    row["metadata_json"] = metadata
    await db.upsert(SCAN_TABLE, row)

    logger.info("Scan %s approved by user %s", scan_id, current_user.id)

    return {"scan_id": scan_id, "status": "approved", "approved_by": current_user.id}


@dashboard_router.post(
    "/scans/{scan_id}/reject",
    response_model=dict[str, Any],
    summary="Reject a quarantined scan",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        404: {"model": ErrorResponse},
    },
)
async def reject_scan(
    scan_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> dict[str, Any]:
    """Reject a scan, marking it as blocked in the metadata."""
    row = await _get_scan_or_404(scan_id)

    metadata = row.get("metadata_json", {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except (json.JSONDecodeError, TypeError):
            metadata = {}

    metadata["rejected"] = True
    metadata["rejected_by"] = current_user.id
    metadata["rejected_at"] = datetime.utcnow().isoformat()
    metadata.pop("approved", None)
    metadata.pop("approved_by", None)
    metadata.pop("approved_at", None)

    row["metadata_json"] = metadata
    await db.upsert(SCAN_TABLE, row)

    logger.info("Scan %s rejected by user %s", scan_id, current_user.id)

    return {"scan_id": scan_id, "status": "rejected", "rejected_by": current_user.id}


# ---------------------------------------------------------------------------
# Dashboard stats
# ---------------------------------------------------------------------------


@dashboard_router.get(
    "/dashboard/stats",
    response_model=DashboardStats,
    summary="Get aggregate dashboard statistics",
    responses={401: {"model": ErrorResponse}, 403: {"model": GateError}},
)
async def get_dashboard_stats(
    current_user: Annotated[UserResponse, Depends(get_current_user)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> DashboardStats:
    """Return aggregate statistics for the dashboard overview page.

    Computes totals and trends from the scans table.
    """
    rows = await db.select(SCAN_TABLE, None, limit=10000)

    total_scans = len(rows)
    threats_blocked = sum(
        1 for r in rows if r.get("verdict") in ("HIGH_RISK", "CRITICAL")
    )
    packages_approved = sum(
        1
        for r in rows
        if r.get("metadata_json", {}).get("approved") is True
        or (
            isinstance(r.get("metadata_json"), dict)
            and r["metadata_json"].get("approved") is True
        )
    )
    critical_findings = sum(1 for r in rows if r.get("verdict") == "CRITICAL")

    return DashboardStats(
        total_scans=total_scans,
        threats_blocked=threats_blocked,
        packages_approved=packages_approved,
        critical_findings=critical_findings,
        scans_trend=0.0,
        threats_trend=0.0,
        approved_trend=0.0,
        critical_trend=0.0,
    )
