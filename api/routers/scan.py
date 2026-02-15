"""
Sigil API — Scan Router

POST /v1/scan — Accept scan results, enrich with threat intelligence,
compute risk scores, and persist to the database.
"""

from __future__ import annotations

import logging
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status

from api.database import db
from api.models import (
    ErrorResponse,
    Finding,
    ScanRequest,
    ScanResponse,
)
from api.services.scoring import compute_verdict
from api.services.threat_intel import lookup_threats_for_hashes

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["scan"])


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit scan results for enrichment",
    responses={422: {"model": ErrorResponse}},
)
async def submit_scan(request: ScanRequest) -> ScanResponse:
    """Accept raw scan findings, enrich them with threat intelligence,
    compute an aggregate risk score and verdict, and persist the result.

    The response includes:
    - The original findings
    - A weighted risk score
    - A verdict (CLEAN / LOW_RISK / MEDIUM_RISK / HIGH_RISK / CRITICAL)
    - Any matching entries from the threat intelligence database
    """
    scan_id = uuid4().hex[:16]

    # --- 1. Compute risk score & verdict ------------------------------------
    risk_score, verdict = compute_verdict(request.findings)

    # --- 2. Threat intelligence enrichment ----------------------------------
    # Pull hashes from metadata if provided (e.g. artifact SHA-256 hashes)
    hashes: list[str] = []
    if "hashes" in request.metadata:
        hashes = request.metadata["hashes"]
    elif "hash" in request.metadata:
        hashes = [request.metadata["hash"]]

    threat_hits = await lookup_threats_for_hashes(hashes) if hashes else []

    # If threat intel found hits, bump the score
    if threat_hits:
        threat_bonus = sum(10.0 for _ in threat_hits)
        risk_score += threat_bonus
        # Recompute verdict with updated score
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
    try:
        await db.insert(
            "scans",
            {
                "id": scan_id,
                "target": request.target,
                "target_type": request.target_type,
                "files_scanned": request.files_scanned,
                "findings_count": len(request.findings),
                "risk_score": response.risk_score,
                "verdict": verdict.value,
                "threat_hits": len(threat_hits),
                "created_at": now.isoformat(),
            },
        )
    except Exception:
        logger.exception("Failed to persist scan %s", scan_id)
        # Non-fatal — the scan result is still returned to the caller

    logger.info(
        "Scan %s completed: target=%s score=%.1f verdict=%s findings=%d",
        scan_id,
        request.target,
        risk_score,
        verdict.value,
        len(request.findings),
    )

    return response
