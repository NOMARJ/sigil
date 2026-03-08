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
import re
from datetime import datetime, timezone
from typing import Any
from typing_extensions import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.database import db
from api.rate_limit import RateLimiter
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
from api.routers.auth import get_current_user_unified, UserResponse
from api.services.scoring import compute_verdict
from api.services.threat_intel import (
    lookup_threats_for_hashes,
    update_publisher_from_scan,
)
from api.services.forge_analytics import track_forge_event
from api.models import ForgeEventType
from api.middleware.tier_check import get_scan_capabilities
from scanner.scanner_engine import scanner_engine
from api.services.subscription_service import subscription_service

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
        verdict=row.get("verdict", "LOW_RISK"),
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
        verdict=row.get("verdict", "LOW_RISK"),
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

    # Basic input hardening for user-controlled target values
    raw_target = request.target or ""
    safe_target = re.sub(r"(?is)<script.*?>.*?</script>", "", raw_target)
    safe_target = re.sub(r"(?i)javascript:", "", safe_target)
    safe_target = re.sub(r"[;|&`$<>]", "", safe_target).strip()
    if not safe_target:
        safe_target = "sanitized-target"

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
        from services.scoring import score_to_verdict

        verdict = score_to_verdict(risk_score)

    # --- 3. Build response --------------------------------------------------
    now = datetime.utcnow()
    response = ScanResponse(
        scan_id=scan_id,
        target=safe_target,
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
            "target": safe_target,
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
        await db.store_scan(row_data)
    except Exception:
        logger.exception("Failed to persist scan %s", scan_id)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Internal error",
        )

    # --- 4b. Increment scan quota usage (only for authenticated users) ------
    if user_id:
        try:
            year_month = datetime.now(timezone.utc).strftime("%Y-%m")
            await db.increment_scan_usage(user_id, year_month)
        except Exception:
            logger.exception("Failed to increment scan usage for user %s", user_id)

        # --- 4c. Track analytics event ----------------------------------------
        try:
            await track_forge_event(
                user_id=user_id,
                event_type=ForgeEventType.SCAN_COMPLETED,
                event_data={
                    "scan_id": scan_id,
                    "target": safe_target,
                    "target_type": request.target_type,
                    "risk_score": response.risk_score,
                    "verdict": verdict.value,
                    "findings_count": len(request.findings),
                    "threat_hits": len(threat_hits),
                    "files_scanned": request.files_scanned,
                },
            )
        except Exception:
            logger.exception("Failed to track scan analytics for user %s", user_id)

    logger.info(
        "Scan %s completed: target=%s score=%.1f verdict=%s findings=%d",
        scan_id,
        safe_target,
        risk_score,
        verdict.value,
        len(request.findings),
    )

    # --- 5. Publisher reputation enrichment --------------------------------
    publisher_id = request.metadata.get("publisher_id") or request.metadata.get(
        "publisher"
    )
    if publisher_id:
        is_flagged = verdict.value in ("HIGH_RISK", "CRITICAL_RISK")
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
        429: {"description": "Rate limit or monthly scan quota exceeded"},
    },
    dependencies=[Depends(RateLimiter(max_requests=30, window=60))],
)
async def submit_scan(
    request: ScanRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> ScanResponse:
    """Accept raw scan findings, enrich them with threat intelligence,
    compute an aggregate risk score and verdict, and persist the result.

    The response includes:
    - The original findings
    - A weighted risk score
    - A verdict (LOW_RISK / MEDIUM_RISK / HIGH_RISK / CRITICAL_RISK)
    - Any matching entries from the threat intelligence database

    Requires authentication. Monthly scan limits apply per plan tier.
    """
    current_tier = await get_user_plan(current_user.id)
    await check_scan_quota(current_user.id, current_tier)
    return await _submit_scan_impl(request, user_id=current_user.id)


@router.post(
    "/scans",
    response_model=dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Submit scan results (legacy /v1/scans compatibility)",
    dependencies=[Depends(RateLimiter(max_requests=30, window=60))],
)
async def submit_scan_v1_scans(
    request: ScanRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> dict[str, Any]:
    current_tier = await get_user_plan(current_user.id)
    await check_scan_quota(current_user.id, current_tier)
    response = await _submit_scan_impl(request, user_id=current_user.id)
    payload = response.model_dump(mode="json")
    payload["id"] = response.scan_id
    verdict_to_classification = {
        "LOW_RISK": "SUSPICIOUS",
        "MEDIUM_RISK": "RISKY",
        "HIGH_RISK": "MALICIOUS",
        "CRITICAL_RISK": "MALICIOUS",
    }
    payload["classification"] = verdict_to_classification.get(
        response.verdict.value, "SUSPICIOUS"
    )
    payload["score"] = response.risk_score
    return payload


@router.post(
    "/scan-enhanced",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Enhanced scan with Pro features (LLM analysis)",
    responses={
        401: {"model": ErrorResponse},
        402: {"description": "Pro subscription required for enhanced features"},
        422: {"model": ErrorResponse},
        429: {"description": "Rate limit or monthly scan quota exceeded"},
    },
    dependencies=[Depends(RateLimiter(max_requests=20, window=60))],
)
async def submit_enhanced_scan(
    request: ScanRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    capabilities: Annotated[dict[str, Any], Depends(get_scan_capabilities)],
) -> ScanResponse:
    """
    Enhanced scan with AI-powered analysis for Pro users.

    Performs both static analysis (Phases 1-8) and LLM analysis (Phase 9)
    for users with Pro, Team, or Enterprise subscriptions.

    For Free users, returns static analysis results with upgrade prompts.
    """
    current_tier = await get_user_plan(current_user.id)
    await check_scan_quota(current_user.id, current_tier)

    # Start with basic scan implementation
    basic_response = await _submit_scan_impl(request, user_id=current_user.id)

    # If user doesn't have Pro access, return basic response with upgrade message
    if not capabilities["llm_analysis"]:
        # Add Pro features information to metadata
        enhanced_metadata = (
            basic_response.metadata if hasattr(basic_response, "metadata") else {}
        )
        enhanced_metadata.update(
            {
                "pro_features_available": False,
                "upgrade_required": True,
                "upgrade_message": "Upgrade to Pro for AI-powered threat detection, zero-day analysis, and contextual insights",
                "upgrade_url": "https://app.sigilsec.ai/upgrade",
                "missing_features": [
                    "LLM-powered threat analysis",
                    "Zero-day vulnerability detection",
                    "Obfuscation pattern analysis",
                    "Contextual threat correlation",
                    "Advanced remediation suggestions",
                ],
            }
        )

        logger.info(
            f"Enhanced scan completed for Free user {current_user.id}: static analysis only"
        )
        return basic_response

    # Pro user - perform LLM analysis
    try:
        # Prepare file contents from request metadata for LLM analysis
        file_contents = {}
        if "file_contents" in request.metadata:
            file_contents = request.metadata["file_contents"]
        elif "content" in request.metadata and "filename" in request.metadata:
            # Single file scan
            file_contents = {request.metadata["filename"]: request.metadata["content"]}

        if file_contents:
            logger.info(
                f"Starting enhanced LLM analysis for Pro user {current_user.id}"
            )

            # Use scanner engine for comprehensive analysis
            enhanced_findings = await scanner_engine.scan_with_pro_features(
                content=None,  # No directory path
                repository_context=request.metadata,
                user_tier=current_tier.value,
            )

            # Track Pro feature usage
            await subscription_service.track_pro_feature_usage(
                user_id=current_user.id,
                feature_type="llm_analysis",
                usage_data={
                    "scan_id": basic_response.scan_id,
                    "files_analyzed": len(file_contents),
                    "enhanced_findings": len(
                        [
                            f
                            for f in enhanced_findings
                            if f.phase.value == "llm_analysis"
                        ]
                    ),
                    "total_findings": len(enhanced_findings),
                },
            )

            # Merge LLM findings with basic findings
            all_findings = basic_response.findings + [
                f
                for f in enhanced_findings
                if f.phase.value == "llm_analysis"  # Only add new LLM findings
            ]

            # Recalculate risk score with LLM findings
            from services.scoring import compute_verdict

            enhanced_risk_score, enhanced_verdict = compute_verdict(all_findings)

            # Update response with enhanced results
            enhanced_response = ScanResponse(
                scan_id=basic_response.scan_id,
                target=basic_response.target,
                target_type=basic_response.target_type,
                files_scanned=basic_response.files_scanned,
                findings=all_findings,
                risk_score=round(enhanced_risk_score, 2),
                verdict=enhanced_verdict,
                threat_intel_hits=basic_response.threat_intel_hits,
                created_at=basic_response.created_at,
                metadata={
                    "pro_features_used": True,
                    "llm_analysis_performed": True,
                    "enhanced_findings_count": len(
                        [
                            f
                            for f in enhanced_findings
                            if f.phase.value == "llm_analysis"
                        ]
                    ),
                    "original_risk_score": basic_response.risk_score,
                    "enhanced_risk_score": enhanced_risk_score,
                    "user_tier": current_tier.value,
                },
            )

            logger.info(
                f"Enhanced scan completed for Pro user {current_user.id}: "
                f"{len(all_findings)} total findings, "
                f"risk score {basic_response.risk_score} -> {enhanced_risk_score}"
            )

            return enhanced_response

        else:
            logger.warning(
                f"No file contents provided for LLM analysis for user {current_user.id}"
            )
            # Return basic response with Pro metadata
            basic_response.metadata = {
                "pro_features_used": False,
                "llm_analysis_performed": False,
                "reason": "No file contents provided for analysis",
                "user_tier": current_tier.value,
            }
            return basic_response

    except Exception as e:
        logger.exception(f"Enhanced scan failed for Pro user {current_user.id}: {e}")
        # Return basic response with error information
        basic_response.metadata = {
            "pro_features_used": False,
            "llm_analysis_performed": False,
            "llm_error": str(e),
            "fallback_to_static": True,
            "user_tier": current_tier.value,
        }
        return basic_response


@router.get(
    "/scan-capabilities",
    response_model=dict[str, Any],
    summary="Get user's scanning capabilities based on subscription tier",
    responses={401: {"model": ErrorResponse}},
)
async def get_user_scan_capabilities(
    capabilities: Annotated[dict[str, Any], Depends(get_scan_capabilities)],
) -> dict[str, Any]:
    """
    Return the scanning capabilities available to the current user.

    Includes information about:
    - Available analysis types (static, LLM, contextual)
    - Subscription tier
    - Upgrade requirements for additional features
    """
    return capabilities


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
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
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
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
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
    # Soft-gate: FREE tier gets limited preview (last 5) + upgrade prompt
    current_tier = await get_user_plan(current_user.id)
    is_free = current_tier == PlanTier.FREE

    filters: dict[str, Any] = {}
    if verdict:
        filters["verdict"] = verdict
    if source:
        filters["target_type"] = source

    # Fetch a generous batch for in-memory pagination/filtering
    rows = await db.select(SCAN_TABLE, filters if filters else None, limit=1000)

    # Exclude ERROR scans unless explicitly requested via verdict filter
    if not verdict:
        rows = [r for r in rows if r.get("verdict") != "ERROR"]

    # Apply text search filter in-memory
    if search:
        search_lower = search.lower()
        rows = [r for r in rows if search_lower in r.get("target", "").lower()]

    # Sort by created_at descending
    rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)

    total = len(rows)

    # FREE tier: limit to most recent 5 scans with upgrade prompt
    if is_free:
        rows = rows[:5]
        total = min(total, 5)

    start = (page - 1) * per_page
    end = start + per_page
    page_rows = rows[start:end]

    return ScanListResponse(
        items=[_row_to_list_item(r) for r in page_rows],
        total=total,
        page=page,
        per_page=per_page,
        upgrade_message=(
            "Free plan shows your 5 most recent scans. "
            "Upgrade to Pro for full scan history: https://app.sigilsec.ai/upgrade"
        )
        if is_free
        else None,
    )


@router.get(
    "/scans",
    response_model=ScanListResponse,
    summary="List scans (legacy /v1/scans compatibility)",
)
async def list_scans_v1(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    verdict: str | None = Query(None, description="Filter by verdict"),
    source: str | None = Query(None, description="Filter by target_type"),
    search: str | None = Query(None, description="Search in target name"),
) -> ScanListResponse:
    return await list_scans(
        current_user=current_user,
        page=page,
        per_page=per_page,
        verdict=verdict,
        source=source,
        search=search,
    )


@router.get(
    "/scans/{scan_id}",
    response_model=ScanDetail,
    summary="Get scan detail (legacy /v1/scans/{id} compatibility)",
)
async def get_scan_v1(
    scan_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> ScanDetail:
    row = await _get_scan_or_404(scan_id)
    return _row_to_detail(row)


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
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
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
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
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
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> dict[str, Any]:
    """Approve a scan, marking it as reviewed in the metadata."""
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
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
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
    responses={401: {"model": ErrorResponse}},
)
async def get_dashboard_stats(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> DashboardStats:
    """Return aggregate statistics for the dashboard overview page.

    Computes totals and trends from the scans table.
    """
    rows = await db.select(SCAN_TABLE, None, limit=10000)

    # Exclude ERROR scans from statistics — they represent failed scans, not results
    rows = [r for r in rows if r.get("verdict") != "ERROR"]

    total_scans = len(rows)
    threats_blocked = sum(
        1 for r in rows if r.get("verdict") in ("HIGH_RISK", "CRITICAL_RISK")
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
    critical_findings = sum(1 for r in rows if r.get("verdict") == "CRITICAL_RISK")

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
