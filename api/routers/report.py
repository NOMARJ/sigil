"""
Sigil API — Threat Report Router

POST /v1/report — Accept user-submitted threat reports for review.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, status

from api.models import ThreatReport, ThreatReportResponse
from api.services.threat_intel import submit_report

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["report"])


@router.post(
    "/report",
    response_model=ThreatReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a threat report",
)
async def create_report(report: ThreatReport) -> ThreatReportResponse:
    """Submit a threat report for a suspicious package.

    Community-submitted reports are queued for review by the Sigil team.
    Confirmed threats are added to the threat intelligence database and
    distributed to all connected scanners via the signature sync endpoint.

    Fields:
    - **package_name** (required): The name of the suspicious package.
    - **reason** (required): Why the reporter believes the package is malicious.
    - **evidence** (optional): Supporting evidence such as URLs, code snippets,
      or references to CVEs.
    - **reporter_email** (optional): Contact email for follow-up.
    """
    return await submit_report(report)
