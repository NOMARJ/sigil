"""
Sigil API — Threat Intelligence Router

GET /v1/threat/{hash}   — Look up a package hash against the threat database
GET /v1/signatures      — Download latest pattern signatures (delta sync)
"""

from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, status

from api.models import ErrorResponse, SignatureResponse, ThreatEntry
from api.services.threat_intel import get_signatures, lookup_threat

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["threat-intel"])


@router.get(
    "/threat/{package_hash}",
    response_model=ThreatEntry | None,
    summary="Look up a package hash in the threat database",
    responses={404: {"model": ErrorResponse}},
)
async def get_threat(package_hash: str) -> ThreatEntry:
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


@router.get(
    "/signatures",
    response_model=SignatureResponse,
    summary="Download pattern signatures (delta sync)",
)
async def list_signatures(
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
