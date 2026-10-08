"""
Sigil API — Threat Report Router

POST /v1/report — Accept user-submitted threat reports for review.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request, status

from api.models import ThreatReport, ThreatReportResponse, UserResponse
from api.routers.auth import get_current_user_unified
from api.services.threat_intel import submit_report

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["report"])


async def _signed_in_reporter(request: Request) -> UserResponse | None:
    """The user whose valid bearer token the request carries, else ``None``.

    POST /v1/report needs no token (the dashboard and CLI 1.3.7 users may be
    logged out), so a missing or invalid token files the report anonymously
    rather than refusing it. A valid one is recorded with the report.
    """
    if not request.headers.get("Authorization"):
        return None
    # Resolved through the app's overrides so the test suite's stand-in for
    # Auth0 applies here as it does to a `Depends(get_current_user_unified)`.
    resolve = request.app.dependency_overrides.get(
        get_current_user_unified, get_current_user_unified
    )
    try:
        return await resolve(request)
    except HTTPException:
        return None


@router.post(
    "/report",
    response_model=ThreatReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a threat report",
)
async def create_report(report: ThreatReport, request: Request) -> ThreatReportResponse:
    """Submit a threat report for a suspicious package.

    Community-submitted reports are queued for review by the Sigil team.
    Confirmed threats are added to the threat intelligence database and
    distributed to all connected scanners via the signature sync endpoint.
    A report is anonymous unless the request carries a valid bearer token, in
    which case the reporting account is recorded with it.

    Fields:
    - **package_name** (required): The name of the suspicious package.
    - **reason** (required): Why the reporter believes the package is malicious.
    - **evidence** (optional): Supporting evidence such as URLs, code snippets,
      or references to CVEs.
    - **reporter_email** (optional): Contact email for follow-up.
    """
    reporter = await _signed_in_reporter(request)
    return await submit_report(
        report, reporter_user_id=reporter.id if reporter is not None else None
    )
