"""
Sigil API — Marketplace Verification Router

POST /v1/verify — Verify a package for a marketplace trust badge.
"""

from __future__ import annotations

import logging
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, status

from api.database import db
from api.models import (
    Verdict,
    VerifyRequest,
    VerifyResponse,
)
from api.services.scoring import score_to_verdict
from api.services.threat_intel import lookup_threat

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["verify"])

# Badge URL template — in production this would point to a CDN-hosted SVG
_BADGE_URL_TEMPLATE = "https://sigil.dev/badges/{verdict}/{package}.svg"


@router.post(
    "/verify",
    response_model=VerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify a package for a marketplace badge",
)
async def verify_package(request: VerifyRequest) -> VerifyResponse:
    """Submit a package for Sigil verification.

    The verification process:
    1. Checks the artifact hash against the threat intelligence database.
    2. Reviews the publisher's reputation.
    3. Returns a verdict and (if clean) a badge URL that can be displayed
       in marketplace listings.

    Only packages that receive a ``CLEAN`` or ``LOW_RISK`` verdict are
    granted the Sigil-verified badge.
    """
    now = datetime.utcnow()
    risk_score = 0.0
    findings_parts: list[str] = []

    # --- 1. Threat intel check ----------------------------------------------
    if request.artifact_hash:
        threat = await lookup_threat(request.artifact_hash)
        if threat is not None:
            risk_score += 50.0  # Instant CRITICAL
            findings_parts.append(
                f"Known threat: {threat.description or threat.package_name} "
                f"(severity={threat.severity.value})"
            )

    # --- 2. Publisher reputation check --------------------------------------
    if request.publisher_id:
        from api.services.threat_intel import get_publisher_reputation

        pub = await get_publisher_reputation(request.publisher_id)
        if pub is not None:
            flagged = pub.get("flagged_count", 0)
            trust = pub.get("trust_score", 50.0)
            if flagged > 0:
                risk_score += flagged * 5.0
                findings_parts.append(
                    f"Publisher has {flagged} flagged package(s), trust={trust}"
                )
            if trust < 30:
                risk_score += 10.0
                findings_parts.append(f"Low publisher trust score: {trust}")

    verdict = score_to_verdict(risk_score)
    verified = verdict == Verdict.LOW_RISK

    badge_url: str | None = None
    if verified:
        safe_name = (
            f"{request.ecosystem}-{request.package_name}-{request.package_version}"
        )
        badge_url = _BADGE_URL_TEMPLATE.format(
            verdict=verdict.value.lower(),
            package=safe_name,
        )

    summary = "; ".join(findings_parts) if findings_parts else "No issues found."

    # --- 3. Persist verification record -------------------------------------
    try:
        await db.insert(
            "verifications",
            {
                "id": uuid4().hex[:16],
                "package_name": request.package_name,
                "package_version": request.package_version,
                "ecosystem": request.ecosystem,
                "publisher_id": request.publisher_id,
                "artifact_hash": request.artifact_hash,
                "risk_score": round(risk_score, 2),
                "verdict": verdict.value,
                "verified": verified,
                "created_at": now.isoformat(),
            },
        )
    except Exception:
        logger.exception("Failed to persist verification record")

    return VerifyResponse(
        package_name=request.package_name,
        package_version=request.package_version,
        verified=verified,
        verdict=verdict,
        risk_score=round(risk_score, 2),
        badge_url=badge_url,
        findings_summary=summary,
        verified_at=now,
    )
