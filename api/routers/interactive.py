"""
Sigil API — Interactive LLM Analysis Router

POST /v1/interactive/investigate   — Investigate specific security finding
POST /v1/interactive/false-positive — Analyze if finding is false positive
POST /v1/interactive/remediate     — Generate secure code remediation
GET  /v1/interactive/sessions      — List user's interactive sessions
GET  /v1/interactive/sessions/{id} — Get specific session details
POST /v1/interactive/sessions      — Create new interactive session
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional
from typing_extensions import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from api.gates import require_plan
from api.models import ErrorResponse, GateError, PlanTier
from api.routers.auth import get_current_user_unified, UserResponse
from api.services.finding_investigator import (
    finding_investigator,
    FindingInvestigationRequest,
    FindingInvestigationResponse,
)
from api.services.false_positive_analyzer import (
    false_positive_analyzer,
    FalsePositiveAnalysisRequest,
    FalsePositiveAnalysisResponse,
)
from api.services.remediation_generator import (
    remediation_generator,
    RemediationRequest,
    RemediationResponse,
)
from api.exceptions import InsufficientCreditsError
from api.database import db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/interactive", tags=["interactive-analysis"])


# ---------------------------------------------------------------------------
# Request/response models specific to this router
# ---------------------------------------------------------------------------


class InvestigateRequest(BaseModel):
    """Request to investigate a specific finding."""

    scan_id: str = Field(..., description="Scan ID containing the finding")
    finding_id: str = Field(..., description="Finding to investigate")
    depth: str = Field(
        default="thorough",
        description="Investigation depth: quick, thorough, exhaustive",
    )
    context_files: Optional[list[str]] = Field(
        default=None, description="Additional files for context"
    )
    session_id: Optional[str] = Field(
        default=None, description="Interactive session ID"
    )


class FalsePositiveRequest(BaseModel):
    """Request to analyze false positive likelihood."""

    scan_id: str = Field(..., description="Scan ID containing the finding")
    finding_id: str = Field(..., description="Finding to analyze")
    include_data_flow: bool = Field(
        default=True, description="Include data flow analysis"
    )
    include_context_comparison: bool = Field(
        default=True, description="Compare with similar findings"
    )
    session_id: Optional[str] = Field(
        default=None, description="Interactive session ID"
    )


class RemediateRequest(BaseModel):
    """Request to generate remediation code."""

    scan_id: str = Field(..., description="Scan ID containing the finding")
    finding_id: str = Field(..., description="Finding to remediate")
    fix_preference: str = Field(
        default="secure", description="Fix preference: secure, minimal, performance"
    )
    include_tests: bool = Field(default=True, description="Include unit tests")
    include_alternatives: bool = Field(
        default=True, description="Include alternative approaches"
    )
    session_id: Optional[str] = Field(
        default=None, description="Interactive session ID"
    )


class CreateSessionRequest(BaseModel):
    """Request to create a new interactive session."""

    scan_id: str = Field(..., description="Scan ID to create session for")
    model_preference: str = Field(
        default="claude-3-haiku", description="Preferred LLM model"
    )


class SessionResponse(BaseModel):
    """Interactive session information."""

    session_id: str = Field(..., description="Unique session ID")
    scan_id: str = Field(..., description="Associated scan ID")
    status: str = Field(..., description="Session status")
    total_credits_used: int = Field(..., description="Credits used in this session")
    model_preference: str = Field(..., description="Preferred model")
    started_at: datetime = Field(..., description="Session start time")
    last_activity: datetime = Field(..., description="Last activity time")
    conversation_summary: Optional[dict] = Field(
        default=None, description="Summary of conversation"
    )


class CreditBalanceResponse(BaseModel):
    """User's credit balance information."""

    current_balance: int = Field(..., description="Current credit balance")
    monthly_allocation: int = Field(..., description="Monthly allocation")
    used_this_month: int = Field(..., description="Credits used this month")
    reset_date: Optional[str] = Field(default=None, description="Next reset date")


# ---------------------------------------------------------------------------
# Investigation endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/investigate",
    response_model=FindingInvestigationResponse,
    summary="Investigate a specific security finding with AI analysis",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        402: {"description": "Insufficient credits"},
        404: {"model": ErrorResponse},
    },
)
async def investigate_finding(
    request: InvestigateRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> FindingInvestigationResponse:
    """
    Perform deep-dive analysis of a specific security finding.

    This endpoint uses AI to investigate a finding and determine:
    - Whether it's a real security threat
    - Confidence level in the assessment
    - Evidence supporting the conclusion
    - Potential attack scenarios
    - Remediation priority

    Credit costs vary by depth:
    - Quick: 4 credits (Haiku model)
    - Thorough: 8 credits (Sonnet model)
    - Exhaustive: 24 credits (Opus model)
    """
    try:
        # Validate depth level
        if request.depth not in ["quick", "thorough", "exhaustive"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Depth must be one of: quick, thorough, exhaustive",
            )

        # Create investigation request
        investigation_request = FindingInvestigationRequest(
            user_id=current_user.id,
            scan_id=request.scan_id,
            finding_id=request.finding_id,
            depth=request.depth,  # type: ignore
            context_files=request.context_files,
            session_id=request.session_id,
        )

        # Perform investigation
        result = await finding_investigator.investigate_finding(investigation_request)

        logger.info(
            f"Investigation completed for user {current_user.id}, "
            f"finding {request.finding_id}, result: {result.threat_analysis.is_real_threat}"
        )

        return result

    except InsufficientCreditsError as e:
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.exception(f"Investigation failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Investigation failed due to internal error",
        )


# ---------------------------------------------------------------------------
# False positive analysis endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/false-positive",
    response_model=FalsePositiveAnalysisResponse,
    summary="Analyze if a finding is likely a false positive",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        402: {"description": "Insufficient credits"},
        404: {"model": ErrorResponse},
    },
)
async def analyze_false_positive(
    request: FalsePositiveRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> FalsePositiveAnalysisResponse:
    """
    Analyze whether a security finding is likely a false positive.

    This endpoint uses AI to examine:
    - Code context and usage patterns
    - Data flow analysis (optional)
    - Comparison with similar findings (optional)
    - Defense-in-depth recommendations

    Uses Haiku model for cost efficiency (4 credits).
    """
    try:
        # Create analysis request
        analysis_request = FalsePositiveAnalysisRequest(
            user_id=current_user.id,
            scan_id=request.scan_id,
            finding_id=request.finding_id,
            include_data_flow=request.include_data_flow,
            include_context_comparison=request.include_context_comparison,
            session_id=request.session_id,
        )

        # Perform analysis
        result = await false_positive_analyzer.analyze_false_positive(analysis_request)

        logger.info(
            f"False positive analysis completed for user {current_user.id}, "
            f"finding {request.finding_id}, result: {result.is_false_positive} "
            f"({result.confidence_percentage}% confidence)"
        )

        return result

    except InsufficientCreditsError as e:
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.exception(
            f"False positive analysis failed for user {current_user.id}: {e}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis failed due to internal error",
        )


# ---------------------------------------------------------------------------
# Remediation generation endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/remediate",
    response_model=RemediationResponse,
    summary="Generate secure code remediation for a vulnerability",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        402: {"description": "Insufficient credits"},
        404: {"model": ErrorResponse},
    },
)
async def generate_remediation(
    request: RemediateRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> RemediationResponse:
    """
    Generate secure code remediation for a security vulnerability.

    This endpoint uses AI to generate:
    - Primary fix with working code
    - Alternative fix approaches
    - Unit tests to verify the fix
    - Security validation information
    - Implementation guidance

    Uses Sonnet model for balanced quality/cost (6 credits).
    """
    try:
        # Validate fix preference
        if request.fix_preference not in ["secure", "minimal", "performance"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Fix preference must be one of: secure, minimal, performance",
            )

        # Create remediation request
        remediation_request = RemediationRequest(
            user_id=current_user.id,
            scan_id=request.scan_id,
            finding_id=request.finding_id,
            fix_preference=request.fix_preference,
            include_tests=request.include_tests,
            include_alternatives=request.include_alternatives,
            session_id=request.session_id,
        )

        # Generate remediation
        result = await remediation_generator.generate_remediation(remediation_request)

        logger.info(
            f"Remediation generated for user {current_user.id}, "
            f"finding {request.finding_id}, language: {result.language}, "
            f"alternatives: {len(result.alternative_fixes)}"
        )

        return result

    except InsufficientCreditsError as e:
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.exception(
            f"Remediation generation failed for user {current_user.id}: {e}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Remediation generation failed due to internal error",
        )


# ---------------------------------------------------------------------------
# Session management endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/sessions",
    response_model=SessionResponse,
    summary="Create a new interactive session for a scan",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        404: {"model": ErrorResponse},
    },
)
async def create_session(
    request: CreateSessionRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> SessionResponse:
    """
    Create a new interactive session for analyzing a scan.

    Interactive sessions persist conversation history and allow
    continuing analysis work across multiple requests.
    """
    try:
        # Verify scan exists and belongs to user
        scan_exists = await _verify_scan_access(request.scan_id, current_user.id)
        if not scan_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {request.scan_id} not found or access denied",
            )

        # Generate session ID
        from uuid import uuid4

        session_id = str(uuid4())[:16]

        # Create session in database
        await db.execute(
            """
            INSERT INTO interactive_sessions (
                session_id, user_id, scan_id, status, model_preference, 
                started_at, last_activity
            ) VALUES (
                :session_id, :user_id, :scan_id, 'active', :model_preference,
                :timestamp, :timestamp
            )
            """,
            {
                "session_id": session_id,
                "user_id": current_user.id,
                "scan_id": request.scan_id,
                "model_preference": request.model_preference,
                "timestamp": datetime.utcnow(),
            },
        )

        logger.info(
            f"Created interactive session {session_id} for user {current_user.id}"
        )

        return SessionResponse(
            session_id=session_id,
            scan_id=request.scan_id,
            status="active",
            total_credits_used=0,
            model_preference=request.model_preference,
            started_at=datetime.utcnow(),
            last_activity=datetime.utcnow(),
        )

    except Exception as e:
        logger.exception(f"Session creation failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create session",
        )


@router.get(
    "/sessions",
    response_model=list[SessionResponse],
    summary="List user's interactive sessions",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
    },
)
async def list_sessions(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
    status_filter: Optional[str] = Query(
        None, description="Filter by status: active, completed, expired"
    ),
    limit: int = Query(
        50, ge=1, le=100, description="Maximum number of sessions to return"
    ),
) -> list[SessionResponse]:
    """
    List user's interactive sessions with optional filtering.

    Returns sessions ordered by last activity (most recent first).
    """
    try:
        query = """
            SELECT 
                session_id, scan_id, status, total_credits_used,
                model_preference, started_at, last_activity
            FROM interactive_sessions 
            WHERE user_id = :user_id
        """
        params = {"user_id": current_user.id}

        if status_filter:
            query += " AND status = :status"
            params["status"] = status_filter

        query += " ORDER BY last_activity DESC LIMIT :limit"
        params["limit"] = limit

        results = await db.fetch_all(query, params)

        sessions = []
        for row in results:
            sessions.append(
                SessionResponse(
                    session_id=row["session_id"],
                    scan_id=row["scan_id"],
                    status=row["status"],
                    total_credits_used=row["total_credits_used"],
                    model_preference=row["model_preference"],
                    started_at=row["started_at"],
                    last_activity=row["last_activity"],
                )
            )

        logger.info(f"Retrieved {len(sessions)} sessions for user {current_user.id}")
        return sessions

    except Exception as e:
        logger.exception(f"Session listing failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve sessions",
        )


@router.get(
    "/sessions/{session_id}",
    response_model=dict[str, Any],
    summary="Get detailed session information",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        404: {"model": ErrorResponse},
    },
)
async def get_session(
    session_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> dict[str, Any]:
    """
    Get detailed information about a specific interactive session.

    Includes conversation history and session statistics.
    """
    try:
        result = await db.fetch_one(
            """
            SELECT 
                session_id, scan_id, status, findings_context,
                conversation_history, total_credits_used, model_preference,
                started_at, last_activity, completed_at
            FROM interactive_sessions 
            WHERE session_id = :session_id AND user_id = :user_id
            """,
            {"session_id": session_id, "user_id": current_user.id},
        )

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session {session_id} not found",
            )

        # Parse JSON fields
        import json

        findings_context = json.loads(result["findings_context"] or "{}")
        conversation_history = json.loads(result["conversation_history"] or "[]")

        return {
            "session_id": result["session_id"],
            "scan_id": result["scan_id"],
            "status": result["status"],
            "findings_context": findings_context,
            "conversation_history": conversation_history,
            "total_credits_used": result["total_credits_used"],
            "model_preference": result["model_preference"],
            "started_at": result["started_at"].isoformat(),
            "last_activity": result["last_activity"].isoformat(),
            "completed_at": result["completed_at"].isoformat()
            if result["completed_at"]
            else None,
            "conversation_stats": {
                "total_interactions": len(conversation_history),
                "investigation_count": len(
                    [
                        h
                        for h in conversation_history
                        if h.get("type") == "investigation"
                    ]
                ),
                "false_positive_count": len(
                    [
                        h
                        for h in conversation_history
                        if h.get("type") == "false_positive_analysis"
                    ]
                ),
                "remediation_count": len(
                    [h for h in conversation_history if h.get("type") == "remediation"]
                ),
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Session retrieval failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve session details",
        )


# ---------------------------------------------------------------------------
# Credit balance endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/credits",
    response_model=CreditBalanceResponse,
    summary="Get user's credit balance and usage information",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
    },
)
async def get_credits(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> CreditBalanceResponse:
    """
    Get user's current credit balance and usage statistics.

    Includes monthly allocation, current balance, usage this month,
    and next reset date.
    """
    try:
        from api.services.credit_service import credit_service

        # Get detailed analytics
        analytics = await credit_service.get_usage_analytics(current_user.id)

        return CreditBalanceResponse(
            current_balance=analytics.get("balance", 0),
            monthly_allocation=analytics.get("monthly_allocation", 0),
            used_this_month=analytics.get("used_this_month", 0),
            reset_date=analytics.get("reset_date"),
        )

    except Exception as e:
        logger.exception(
            f"Credit balance retrieval failed for user {current_user.id}: {e}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve credit information",
        )


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


async def _verify_scan_access(scan_id: str, user_id: str) -> bool:
    """Verify that a scan exists and the user has access to it."""
    try:
        result = await db.fetch_one(
            """
            SELECT scan_id 
            FROM scans 
            WHERE scan_id = :scan_id AND user_id = :user_id
            """,
            {"scan_id": scan_id, "user_id": user_id},
        )
        return result is not None

    except Exception as e:
        logger.exception(f"Scan access verification failed: {e}")
        return False
