"""
Sigil API — Interactive LLM Analysis Router

POST /v1/interactive/investigate   — Investigate specific security finding
POST /v1/interactive/false-positive — Analyze if finding is false positive
POST /v1/interactive/remediate     — Generate secure code remediation
POST /v1/interactive/compliance    — Map findings to compliance frameworks
POST /v1/interactive/compliance/export — Export compliance report as markdown
GET  /v1/interactive/sessions      — List user's interactive sessions
GET  /v1/interactive/sessions/{id} — Get specific session details
POST /v1/interactive/sessions      — Create new interactive session
GET  /v1/interactive/credits       — Get user's credit balance
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
from api.services.compliance_mapper import (
    compliance_mapper,
)
from api.services.session_manager import (
    session_manager,
)
from api.services.model_router import (
    model_router,
)
from api.services.pattern_grouper import (
    pattern_grouper,
)
from api.services.bulk_analyzer import (
    bulk_analyzer,
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


class ComplianceRequest(BaseModel):
    """Request to map findings to compliance frameworks."""
    
    findings: list[dict] = Field(..., description="Security findings to analyze")
    frameworks: Optional[list[str]] = Field(
        default=None,
        description="Compliance frameworks to check (default: all)"
    )
    compliance_context: Optional[str] = Field(
        default="general",
        description="Compliance context: general, healthcare, financial, privacy"
    )


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
# Compliance mapping endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/compliance",
    response_model=dict[str, Any],
    summary="Map security findings to compliance frameworks",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        402: {"description": "Insufficient credits"},
    },
)
async def map_compliance(
    request: ComplianceRequest,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> dict[str, Any]:
    """
    Map security findings to compliance frameworks and regulations.
    
    This endpoint analyzes findings against:
    - OWASP Top 10 2021
    - CWE (Common Weakness Enumeration)
    - PCI DSS (Payment Card Industry)
    - HIPAA (Healthcare)
    - GDPR (Privacy)
    - MITRE ATT&CK
    
    Generates compliance report with:
    - Framework violations mapped to findings
    - Compliance scores per framework
    - Remediation priorities
    - Export-ready format for auditors
    
    Uses 3 credits for analysis.
    """
    try:
        # Validate compliance context
        valid_contexts = ["general", "healthcare", "financial", "privacy"]
        if request.compliance_context not in valid_contexts:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Compliance context must be one of: {', '.join(valid_contexts)}",
            )
        
        # Convert findings from dict to Finding objects
        from api.models import Finding
        findings = []
        for f_dict in request.findings:
            finding = Finding(
                id=f_dict.get("id", ""),
                phase=f_dict.get("phase", ""),
                rule=f_dict.get("rule", ""),
                severity=f_dict.get("severity", ""),
                confidence=f_dict.get("confidence", 0),
                file_path=f_dict.get("file_path", ""),
                line_number=f_dict.get("line_number", 0),
                description=f_dict.get("description", ""),
                evidence=f_dict.get("evidence", ""),
                recommendation=f_dict.get("recommendation", "")
            )
            findings.append(finding)
        
        # Perform compliance mapping
        result = await compliance_mapper.map_findings_to_compliance(
            findings=findings,
            user_id=current_user.id,
            frameworks=request.frameworks,
            compliance_context=request.compliance_context
        )
        
        if "error" in result:
            if "Insufficient credits" in result.get("error", ""):
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail=result["error"]
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=result["error"]
                )
        
        # Get remaining credits
        from api.services.credit_service import credit_service
        remaining = await credit_service.get_balance(current_user.id)
        result["credits_remaining"] = remaining
        
        logger.info(
            f"Compliance mapping completed for user {current_user.id}, "
            f"findings: {len(findings)}, frameworks: {request.frameworks}"
        )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Compliance mapping failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Compliance mapping failed due to internal error",
        )


@router.post(
    "/compliance/export",
    response_model=str,
    summary="Export compliance report as markdown",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
    },
)
async def export_compliance_report(
    report: dict[str, Any],
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> str:
    """
    Export a compliance report as markdown format.
    
    Takes a previously generated compliance report and formats it
    as markdown suitable for documentation or audit reports.
    """
    try:
        markdown = await compliance_mapper.generate_compliance_report_markdown(report)
        
        logger.info(
            f"Exported compliance report for user {current_user.id}"
        )
        
        return markdown
        
    except Exception as e:
        logger.exception(f"Compliance export failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export compliance report",
        )


# ---------------------------------------------------------------------------
# Session sharing endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/sessions/shared/{share_token}",
    response_model=dict[str, Any],
    summary="Get shared session by share token",
    responses={
        404: {"model": ErrorResponse},
    },
)
async def get_shared_session(
    share_token: str
) -> dict[str, Any]:
    """
    Get a shared session by its share token.
    
    This endpoint allows anyone with the share token to view
    the session (read-only access). No authentication required.
    """
    try:
        session = await session_manager.get_session(
            share_token=share_token,
            require_ownership=False
        )
        
        logger.info(f"Shared session accessed: {session['session_id']}")
        return session
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.exception(f"Failed to get shared session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve session",
        )


@router.post(
    "/sessions/export",
    response_model=str,
    summary="Export session as markdown",
    responses={
        404: {"model": ErrorResponse},
    },
)
async def export_session(
    request: dict[str, str]
) -> str:
    """
    Export a session as markdown format.
    
    Can export by session_id (requires ownership) or share_token (public).
    """
    try:
        session_id = request.get("session_id")
        share_token = request.get("share_token")
        
        if not session_id and not share_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either session_id or share_token required"
            )
        
        markdown = await session_manager.export_session_markdown(
            session_id=session_id,
            share_token=share_token
        )
        
        logger.info(f"Session exported: {session_id or share_token}")
        return markdown
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.exception(f"Failed to export session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export session",
        )


@router.post(
    "/sessions/{session_id}/continue",
    response_model=SessionResponse,
    summary="Continue an existing session",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        404: {"model": ErrorResponse},
    },
)
async def continue_session(
    session_id: str,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> SessionResponse:
    """
    Continue working with an existing session.
    
    Updates the last activity timestamp and allows resuming
    the conversation from where it left off.
    """
    try:
        # Verify ownership
        session = await session_manager.get_session(
            session_id=session_id,
            user_id=current_user.id,
            require_ownership=True
        )
        
        if session["status"] != "active":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session is not active"
            )
        
        # Update last activity
        await db.execute(
            """
            UPDATE interactive_sessions
            SET last_activity = :now
            WHERE session_id = :session_id AND user_id = :user_id
            """,
            {
                "now": datetime.utcnow(),
                "session_id": session_id,
                "user_id": current_user.id
            }
        )
        
        logger.info(f"Session continued: {session_id} by user {current_user.id}")
        
        return SessionResponse(
            session_id=session["session_id"],
            scan_id=session["scan_id"],
            status=session["status"],
            total_credits_used=session["total_credits_used"],
            model_preference=session["model_preference"],
            started_at=datetime.fromisoformat(session["started_at"]),
            last_activity=datetime.utcnow(),
            conversation_summary=session.get("statistics")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Failed to continue session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to continue session",
        )


# ---------------------------------------------------------------------------
# Model routing endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/routing/preview",
    response_model=dict[str, Any],
    summary="Preview model routing and cost for a task",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
    },
)
async def preview_model_routing(
    request: dict[str, Any],
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> dict[str, Any]:
    """
    Preview model routing and cost estimation for a task.
    
    Shows which model would be selected and the cost difference
    between models. Allows user to make informed choice before
    executing the task.
    """
    try:
        task_type = request.get("task_type", "chat")
        query = request.get("query")
        context = request.get("context", {})
        model_override = request.get("model_override")
        
        # Get routing preview with user context
        routing = await model_router.route_request(
            user_id=current_user.id,
            task_type=task_type,
            query=query,
            context=context,
            model_override=model_override,
            preview_only=True
        )
        
        # Add model options for UI display
        preview = await model_router.preview_routing(
            task_type=task_type,
            query=query,
            context=context
        )
        
        routing["model_options"] = preview["model_options"]
        
        logger.info(
            f"Routing preview for user {current_user.id}: "
            f"{task_type} -> {routing['selected_model']}"
        )
        
        return routing
        
    except Exception as e:
        logger.exception(f"Routing preview failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate routing preview",
        )


@router.get(
    "/routing/stats",
    response_model=dict[str, Any],
    summary="Get model routing usage statistics",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
    },
)
async def get_routing_statistics(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
) -> dict[str, Any]:
    """
    Get model routing usage statistics and savings.
    
    Shows how often each model is used, average confidence,
    and estimated savings from smart routing.
    """
    try:
        stats = await model_router.get_usage_statistics(
            user_id=current_user.id,
            days=days
        )
        
        logger.info(
            f"Retrieved routing stats for user {current_user.id}: "
            f"{stats.get('total_requests', 0)} requests, "
            f"{stats.get('estimated_savings', 0)} credits saved"
        )
        
        return stats
        
    except Exception as e:
        logger.exception(f"Failed to get routing stats for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve routing statistics",
        )


# ---------------------------------------------------------------------------
# Bulk investigation endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/bulk/group",
    response_model=dict[str, Any],
    summary="Group findings by pattern type",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
    },
)
async def group_findings_by_pattern(
    request: dict[str, Any],
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> dict[str, Any]:
    """
    Group security findings by similar patterns.
    
    Analyzes findings to identify common patterns, root causes,
    and opportunities for batch fixes.
    """
    try:
        findings_data = request.get("findings", [])
        
        # Convert to Finding objects
        from api.models import Finding
        findings = []
        for f_dict in findings_data:
            finding = Finding(
                id=f_dict.get("id", ""),
                phase=f_dict.get("phase", ""),
                rule=f_dict.get("rule", ""),
                severity=f_dict.get("severity", ""),
                confidence=f_dict.get("confidence", 0),
                file_path=f_dict.get("file_path", ""),
                line_number=f_dict.get("line_number", 0),
                description=f_dict.get("description", ""),
                evidence=f_dict.get("evidence", ""),
                recommendation=f_dict.get("recommendation", "")
            )
            findings.append(finding)
        
        # Group findings
        groups = pattern_grouper.group_findings(findings)
        
        logger.info(
            f"Grouped {len(findings)} findings into {len(groups)} patterns "
            f"for user {current_user.id}"
        )
        
        return groups
        
    except Exception as e:
        logger.exception(f"Finding grouping failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to group findings",
        )


@router.post(
    "/bulk/analyze",
    response_model=dict[str, Any],
    summary="Perform bulk analysis on similar findings",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
        402: {"description": "Insufficient credits"},
    },
)
async def analyze_findings_bulk(
    request: dict[str, Any],
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
) -> dict[str, Any]:
    """
    Perform bulk analysis on groups of similar findings.
    
    Efficiently analyzes multiple similar security findings together,
    identifying common root causes and suggesting batch fixes.
    
    Credits vary by depth and group count:
    - Quick: 3 credits per group
    - Thorough: 5 credits per group  
    - Exhaustive: 10 credits per group
    """
    try:
        findings_data = request.get("findings", [])
        depth = request.get("investigation_depth", "thorough")
        group_by = request.get("group_by_pattern", True)
        
        # Validate depth
        if depth not in ["quick", "thorough", "exhaustive"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Depth must be one of: quick, thorough, exhaustive",
            )
        
        # Convert to Finding objects
        from api.models import Finding
        findings = []
        for f_dict in findings_data:
            finding = Finding(
                id=f_dict.get("id", ""),
                phase=f_dict.get("phase", ""),
                rule=f_dict.get("rule", ""),
                severity=f_dict.get("severity", ""),
                confidence=f_dict.get("confidence", 0),
                file_path=f_dict.get("file_path", ""),
                line_number=f_dict.get("line_number", 0),
                description=f_dict.get("description", ""),
                evidence=f_dict.get("evidence", ""),
                recommendation=f_dict.get("recommendation", "")
            )
            findings.append(finding)
        
        # Perform bulk analysis
        result = await bulk_analyzer.analyze_bulk(
            user_id=current_user.id,
            findings=findings,
            investigation_depth=depth,
            group_by_pattern=group_by
        )
        
        logger.info(
            f"Bulk analysis completed for user {current_user.id}: "
            f"{len(findings)} findings, {result['credits_used']} credits used"
        )
        
        return result
        
    except InsufficientCreditsError as e:
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Bulk analysis failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Bulk analysis failed due to internal error",
        )


# ---------------------------------------------------------------------------
# Feedback learning endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/feedback",
    summary="Submit feedback on a security finding",
    responses={
        401: {"model": ErrorResponse},
        402: {"model": GateError},
    }
)
async def submit_feedback(
    request: Dict[str, Any],
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)]
) -> Dict[str, Any]:
    """
    Submit user feedback on a finding for learning and suppression.
    
    Body:
    - finding_id: ID of the finding
    - feedback_type: 'true_positive', 'false_positive', or 'uncertain'
    - confidence: Confidence level (0-1)
    - reason: Optional explanation
    - share_with_team: Share with team for collective learning
    - team_id: Team to share with (if share_with_team is true)
    - suppression_scope: 'personal', 'team', or 'project' (for false positives)
    
    Returns:
    - feedback_id: Created feedback ID
    - rule_created: Whether a suppression rule was created
    - stats: Updated feedback statistics
    """
    try:
        from ..services.feedback_processor import FeedbackProcessor
        from ..models.suppression_rules import FeedbackType
        
        processor = FeedbackProcessor()
        
        # Get finding details
        finding_dict = await db.fetch_one(
            """
            SELECT f.*, s.user_id as scan_user_id
            FROM findings f
            JOIN scans s ON f.scan_id = s.scan_id
            WHERE f.finding_id = :finding_id
            """,
            values={"finding_id": request["finding_id"]}
        )
        
        if not finding_dict:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        # Verify access (user must own the scan)
        if finding_dict["scan_user_id"] != current_user.id:
            raise HTTPException(status_code=403, detail="Access denied to this finding")
        
        # Convert to Finding object
        from ..models.scan_results import Finding
        finding = Finding(
            id=finding_dict["finding_id"],
            scan_id=finding_dict["scan_id"],
            pattern_type=finding_dict["pattern_type"],
            rule=finding_dict["rule_name"],
            severity=finding_dict["severity"],
            confidence=finding_dict["confidence"],
            file_path=finding_dict["file_path"],
            line_number=finding_dict["line_number"],
            evidence=finding_dict["evidence"]
        )
        
        # Process feedback
        feedback_type = FeedbackType(request["feedback_type"])
        feedback = await processor.process_feedback(
            user_id=current_user.id,
            finding=finding,
            feedback_type=feedback_type,
            confidence=request.get("confidence", 1.0),
            reason=request.get("reason"),
            share_with_team=request.get("share_with_team", False),
            team_id=request.get("team_id")
        )
        
        # Get updated stats for this pattern
        stats = await processor.get_accuracy_metrics(
            user_id=current_user.id,
            time_period="30d"
        )
        
        return {
            "feedback_id": feedback.feedback_id,
            "rule_created": feedback_type == FeedbackType.FALSE_POSITIVE and feedback.confidence >= 0.8,
            "stats": {
                "totalFeedback": stats.total_feedback,
                "truePositives": int(stats.true_positive_rate * stats.total_feedback),
                "falsePositives": int(stats.false_positive_rate * stats.total_feedback),
                "uncertain": stats.total_feedback - int((stats.true_positive_rate + stats.false_positive_rate) * stats.total_feedback),
                "consensus": stats.f1_score
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Feedback submission failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit feedback"
        )


@router.get(
    "/feedback/stats/{pattern_type}/{rule_name}",
    summary="Get feedback statistics for a pattern/rule",
    responses={
        401: {"model": ErrorResponse},
    }
)
async def get_feedback_stats(
    pattern_type: str,
    rule_name: str,
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)]
) -> Dict[str, Any]:
    """
    Get aggregated feedback statistics for a specific pattern and rule.
    
    Returns community consensus on whether this is typically a true or false positive.
    """
    try:
        # Get feedback statistics from database
        stats = await db.fetch_one(
            """
            SELECT 
                COUNT(*) as total_feedback,
                SUM(CASE WHEN feedback_type = 'true_positive' THEN 1 ELSE 0 END) as true_positives,
                SUM(CASE WHEN feedback_type = 'false_positive' THEN 1 ELSE 0 END) as false_positives,
                SUM(CASE WHEN feedback_type = 'uncertain' THEN 1 ELSE 0 END) as uncertain,
                AVG(confidence) as avg_confidence
            FROM user_feedback
            WHERE pattern_type = :pattern_type AND rule_name = :rule_name
            """,
            values={"pattern_type": pattern_type, "rule_name": rule_name}
        )
        
        if not stats or stats["total_feedback"] == 0:
            return {
                "totalFeedback": 0,
                "truePositives": 0,
                "falsePositives": 0,
                "uncertain": 0,
                "consensus": None
            }
        
        # Calculate consensus (agreement rate)
        max_type = max(
            stats["true_positives"] or 0,
            stats["false_positives"] or 0,
            stats["uncertain"] or 0
        )
        consensus = max_type / stats["total_feedback"] if stats["total_feedback"] > 0 else 0
        
        return {
            "totalFeedback": stats["total_feedback"],
            "truePositives": stats["true_positives"] or 0,
            "falsePositives": stats["false_positives"] or 0,
            "uncertain": stats["uncertain"] or 0,
            "consensus": consensus,
            "avgConfidence": stats["avg_confidence"] or 0
        }
        
    except Exception as e:
        logger.exception(f"Failed to get feedback stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve feedback statistics"
        )


@router.get(
    "/feedback/accuracy",
    summary="Get personal accuracy metrics",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": GateError},
    }
)
async def get_accuracy_metrics(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
    time_period: str = "30d"
) -> Dict[str, Any]:
    """
    Get personal accuracy metrics showing how well the system is learning from your feedback.
    
    Query params:
    - time_period: Time period for metrics (e.g., '7d', '30d', '90d')
    
    Returns detailed accuracy metrics including pattern-specific performance.
    """
    try:
        from ..services.feedback_processor import FeedbackProcessor
        
        processor = FeedbackProcessor()
        metrics = await processor.get_accuracy_metrics(
            user_id=current_user.id,
            time_period=time_period
        )
        
        return {
            "timePeriod": metrics.time_period,
            "totalFindings": metrics.total_findings,
            "totalFeedback": metrics.total_feedback,
            "feedbackRate": metrics.feedback_rate,
            "accuracy": {
                "truePositiveRate": metrics.true_positive_rate,
                "falsePositiveRate": metrics.false_positive_rate,
                "precision": metrics.precision,
                "recall": metrics.recall,
                "f1Score": metrics.f1_score
            },
            "patternAccuracy": metrics.pattern_accuracy,
            "suppression": {
                "rulesCreated": metrics.suppression_rules_created,
                "suppressionsApplied": metrics.suppressions_applied,
                "suppressionsOverridden": metrics.suppressions_overridden,
                "effectiveness": metrics.learning_effectiveness
            },
            "trend": {
                "direction": metrics.accuracy_trend,
                "improvementRate": metrics.improvement_rate
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Failed to get accuracy metrics for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve accuracy metrics"
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
