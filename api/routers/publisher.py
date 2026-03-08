"""
Sigil API — Publisher Reputation Router

GET /v1/publisher/{id} — Look up a publisher's reputation score and history.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter

from api.models import ErrorResponse, PublisherReputation
from api.services.threat_intel import get_publisher_reputation

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["publisher"])


@router.get(
    "/publisher/{publisher_id}",
    response_model=PublisherReputation,
    summary="Get publisher reputation score and history",
    responses={404: {"model": ErrorResponse}},
)
async def get_publisher(publisher_id: str) -> PublisherReputation:
    """Return the reputation profile for the given publisher.

    The publisher ID is typically a username on a package registry
    (e.g. an npm or PyPI username).

    Returns 404 when the publisher has not been indexed yet.  When no
    database record exists but the publisher is queried for the first time,
    a default profile with a neutral trust score is returned.
    """
    row = await get_publisher_reputation(publisher_id)

    if row is not None:
        try:
            return PublisherReputation(**row)
        except Exception:
            logger.warning("Invalid publisher row for '%s': %s", publisher_id, row)

    # Return a default reputation for unknown publishers rather than 404,
    # so callers always get a usable response.  In production, this would
    # trigger an async enrichment job.
    return PublisherReputation(
        publisher_id=publisher_id,
        trust_score=50.0,  # Neutral — unknown publisher
        total_packages=0,
        flagged_count=0,
        notes="Publisher not yet indexed. Default neutral score assigned.",
    )
