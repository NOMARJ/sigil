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
from api.middleware.tier_check import get_scan_capabilities
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
from api.schemas.scan import ScanResponseV2
from api.routers.auth import get_current_user_unified, UserResponse
from api.scanner.scanner_engine import scanner_engine
from api.services.scoring import compute_verdict
from api.services.subscription_service import subscription_service
from api.services.threat_intel import (
    lookup_threats_for_hashes,
    update_publisher_from_scan,
)
from api.services.scanner_v2 import (
    calculate_confidence_summary,
    get_current_scanner_version,
    is_scanner_v2_enabled
)
from api.services.scanner_selector import (
    get_scanner_capabilities,
    validate_scanner_configuration
)
# from api.services.forge_analytics import track_forge_event  # Forge archived
# from api.models import ForgeEventType  # Forge archived


# Stub for forge analytics to prevent errors during Forge sunset
async def track_forge_event(user_id, event_type, event_data):
    pass


class ForgeEventType:
    SCAN_COMPLETED = "scan_completed"


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
    request: ScanRequest, user_id: str | None = None, use_v2: bool = None
) -> ScanResponse | ScanResponseV2:
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
        from api.services.scoring import score_to_verdict

        verdict = score_to_verdict(risk_score)

    # --- 3. Build response --------------------------------------------------
    now = datetime.utcnow()
    
    # Determine if we should use v2 format
    if use_v2 is None:
        use_v2 = is_scanner_v2_enabled()
    
    if use_v2:
        # Build v2 response with enhanced tracking
        confidence_summary = calculate_confidence_summary(request.findings)
        scanner_version = get_current_scanner_version()
        
        response = ScanResponseV2(
            scan_id=scan_id,
            scanner_version=scanner_version,
            target=safe_target,
            target_type=request.target_type,
            files_scanned=request.files_scanned,
            findings=request.findings,
            risk_score=round(risk_score, 2),
            verdict=verdict,
            confidence_summary=confidence_summary,
            threat_intel_hits=threat_hits,
            created_at=now,
            metadata={
                "scanner_features": {
                    "false_positive_reduction": True,
                    "context_aware_analysis": True,
                    "confidence_scoring": True
                }
            }
        )
    else:
        # Build legacy v1 response
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
        
        # Add v2 fields if using scanner v2
        if use_v2 and hasattr(response, 'scanner_version'):
            v2_response = response  # type: ScanResponseV2
            row_data.update({
                "scanner_version": v2_response.scanner_version,
                "confidence_level": v2_response.confidence_summary.average_confidence,
                "context_weight": v2_response.context_weight,
            })
        else:
            # Default values for v1 scans
            row_data.update({
                "scanner_version": "1.0.0",
                "confidence_level": None,
                "context_weight": 1.0,
            })
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
    "/scan/v2",
    response_model=ScanResponseV2,
    status_code=status.HTTP_200_OK,
    summary="Submit scan results with v2 features (scanner version tracking)",
    responses={
        401: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        429: {"description": "Rate limit or monthly scan quota exceeded"},
    },
    dependencies=[Depends(RateLimiter(max_requests=30, window=60))],
)
async def submit_scan_v2(
    request: ScanRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> ScanResponseV2:
    """
    Submit scan results with Scanner v2 enhancements.
    
    This endpoint provides:
    - Scanner version tracking 
    - Confidence summary with false positive estimates
    - Enhanced metadata with feature flags
    - Backward compatible with existing scan format
    
    Part of the Scanner v2 migration for progressive enhancement.
    """
    current_tier = await get_user_plan(current_user.id)
    await check_scan_quota(current_user.id, current_tier)
    response = await _submit_scan_impl(request, user_id=current_user.id, use_v2=True)
    
    # Ensure we return ScanResponseV2 type
    if not isinstance(response, ScanResponseV2):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create v2 response format"
        )
    
    return response


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
            from api.services.scoring import compute_verdict

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


@router.get(
    "/scanner/status",
    response_model=dict[str, Any],
    summary="Get scanner configuration and capabilities",
    responses={401: {"model": ErrorResponse}},
)
async def get_scanner_status(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
) -> dict[str, Any]:
    """
    Return current scanner configuration, capabilities, and validation status.
    
    Useful for debugging scanner version issues and understanding
    which features are available in the current configuration.
    """
    validation_result = validate_scanner_configuration()
    capabilities = get_scanner_capabilities()
    
    return {
        "configuration": {
            "active_version": get_current_scanner_version(),
            "v2_enabled": is_scanner_v2_enabled(),
            "validation": validation_result,
        },
        "capabilities": capabilities,
        "endpoints": {
            "v1_scan": "/v1/scan",
            "v2_scan": "/v1/scan/v2",
            "enhanced_scan": "/v1/scan-enhanced",
            "rescan": "/api/rescan/{scan_id}",
        },
        "environment": {
            "scanner_version_env": get_current_scanner_version(),
            "fallback_available": validation_result["capabilities"]["v1_enabled"],
        }
    }


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
    source: str | None = Query(None, description="Filter by target_type / ecosystem"),
    search: str | None = Query(None, description="Search in target name"),
    scope: str | None = Query(
        None, description="Scope: own | public | community | all (default: all)"
    ),
) -> ScanListResponse:
    """Return a paginated list of scans.

    scope=own        — only this user's scans (scans table)
    scope=public     — bot-scanned public packages (public_scans table)
    scope=community  — alias for public
    scope=all        — merge own + public (default)

    Supports filtering by verdict, source (target_type/ecosystem), and
    free-text search in the target name.
    """
    current_tier = await get_user_plan(current_user.id)
    is_free = current_tier == PlanTier.FREE

    # ---- helpers -----------------------------------------------------------

    def _public_row_to_list_item(r: dict[str, Any]) -> ScanListItem:
        """Map a public_scans row to ScanListItem."""
        return ScanListItem(
            id=str(r.get("id", "")),
            target=r.get("package_name", ""),
            target_type=r.get("ecosystem", "pip"),
            files_scanned=r.get("files_scanned", 0),
            findings_count=r.get("findings_count", 0),
            risk_score=r.get("risk_score", 0.0),
            verdict=r.get("verdict", "LOW_RISK"),
            threat_hits=0,
            metadata={},
            created_at=r.get("scanned_at") or r.get("created_at") or datetime.utcnow(),
        )

    def _apply_common_filters(
        rows: list[dict[str, Any]],
        target_field: str,
        type_field: str,
    ) -> list[dict[str, Any]]:
        if verdict:
            rows = [r for r in rows if r.get("verdict") == verdict]
        else:
            rows = [r for r in rows if r.get("verdict") not in ("ERROR", None)]
        if source:
            rows = [r for r in rows if r.get(type_field, "").lower() == source.lower()]
        if search:
            sl = search.lower()
            rows = [r for r in rows if sl in r.get(target_field, "").lower()]
        return rows

    # ---- fetch rows by scope -----------------------------------------------
    resolved_scope = (scope or "all").lower()

    own_rows: list[dict[str, Any]] = []
    pub_rows: list[dict[str, Any]] = []

    if resolved_scope in ("own", "all"):
        own_rows = await db.select(SCAN_TABLE, {"user_id": current_user.id}, limit=500)
        own_rows = _apply_common_filters(own_rows, "target", "target_type")

    if resolved_scope in ("public", "community", "all"):
        pub_rows = await db.select(
            "public_scans", None, limit=500, order_by="scanned_at", order_desc=True
        )
        pub_rows = _apply_common_filters(pub_rows, "package_name", "ecosystem")

    # Merge and sort
    all_rows_merged = [("own", r) for r in own_rows] + [("public", r) for r in pub_rows]

    def _sort_key(pair: tuple[str, dict[str, Any]]) -> str:
        _, r = pair
        ts = r.get("created_at") or r.get("scanned_at") or ""
        return str(ts)

    all_rows_merged.sort(key=_sort_key, reverse=True)

    total = len(all_rows_merged)

    # FREE tier: limit preview
    if is_free:
        all_rows_merged = all_rows_merged[:10]
        total = min(total, 10)

    start = (page - 1) * per_page
    page_pairs = all_rows_merged[start : start + per_page]

    items = []
    for origin, row in page_pairs:
        if origin == "own":
            items.append(_row_to_list_item(row))
        else:
            items.append(_public_row_to_list_item(row))

    return ScanListResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        upgrade_message=(
            "Free plan shows your 10 most recent scans. "
            "Upgrade to Pro for full scan history."
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
    scope: str | None = Query(
        None, description="Scope: own | public | community | all"
    ),
) -> ScanListResponse:
    return await list_scans(
        current_user=current_user,
        page=page,
        per_page=per_page,
        verdict=verdict,
        source=source,
        search=search,
        scope=scope,
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
