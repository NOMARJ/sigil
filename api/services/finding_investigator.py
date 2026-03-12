"""
Finding Investigation Service for Interactive LLM Analysis
Provides deep-dive analysis of specific security findings with configurable depth levels.
"""

from __future__ import annotations

import logging
import json
from datetime import datetime
from typing import Dict, Optional, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from api.database import db
from api.services.llm_service import llm_service
from api.services.credit_service import credit_service, SCAN_COSTS
from api.exceptions import InsufficientCreditsError

logger = logging.getLogger(__name__)

DepthLevel = Literal["quick", "thorough", "exhaustive"]


class FindingInvestigationRequest(BaseModel):
    """Request for finding investigation analysis."""

    user_id: str = Field(..., description="User requesting the investigation")
    scan_id: str = Field(..., description="Scan ID containing the finding")
    finding_id: str = Field(..., description="Specific finding to investigate")
    depth: DepthLevel = Field(
        default="thorough", description="Investigation depth level"
    )
    context_files: Optional[list[str]] = Field(
        default=None, description="Additional files for context"
    )
    session_id: Optional[str] = Field(
        default=None, description="Interactive session ID"
    )


class FindingEvidence(BaseModel):
    """Evidence supporting investigation findings."""

    code_snippet: str = Field(..., description="Relevant code snippet")
    file_path: str = Field(..., description="File containing evidence")
    line_number: Optional[int] = Field(
        default=None, description="Line number of evidence"
    )
    explanation: str = Field(..., description="Why this evidence is relevant")


class ThreatAnalysis(BaseModel):
    """Threat analysis results."""

    is_real_threat: bool = Field(
        ..., description="Whether this is a genuine security threat"
    )
    confidence_score: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence in analysis (0-1)"
    )
    false_positive_likelihood: float = Field(
        ..., ge=0.0, le=1.0, description="Likelihood of false positive"
    )
    exploitability: str = Field(
        ..., description="How exploitable this vulnerability is"
    )
    impact_assessment: str = Field(..., description="Potential impact if exploited")


class FindingInvestigationResponse(BaseModel):
    """Response from finding investigation."""

    investigation_id: str = Field(..., description="Unique investigation ID")
    finding_id: str = Field(..., description="Finding that was investigated")
    depth_level: DepthLevel = Field(..., description="Investigation depth used")
    threat_analysis: ThreatAnalysis = Field(..., description="Threat analysis results")
    evidence: list[FindingEvidence] = Field(..., description="Supporting evidence")
    detailed_explanation: str = Field(..., description="Comprehensive explanation")
    attack_scenarios: list[str] = Field(..., description="Possible attack scenarios")
    remediation_priority: str = Field(..., description="Priority level for fixing")
    model_used: str = Field(..., description="LLM model used for analysis")
    credits_used: int = Field(..., description="Credits consumed for investigation")
    processing_time_ms: Optional[int] = Field(
        default=None, description="Processing time"
    )


class FindingInvestigatorService:
    """Service for investigating specific security findings."""

    async def investigate_finding(
        self, request: FindingInvestigationRequest
    ) -> FindingInvestigationResponse:
        """
        Investigate a specific security finding with AI analysis.

        Args:
            request: Investigation request with finding details and depth

        Returns:
            Detailed investigation results with threat analysis

        Raises:
            InsufficientCreditsError: If user lacks credits for investigation
        """
        investigation_id = str(uuid4())[:16]
        start_time = datetime.utcnow()

        try:
            # Determine model and credit cost based on depth
            model, credits_cost = self._get_model_and_cost(request.depth)

            # Check credit availability
            if not await credit_service.has_credits(request.user_id, credits_cost):
                balance = await credit_service.get_balance(request.user_id)
                raise InsufficientCreditsError(
                    f"Insufficient credits for {request.depth} investigation. "
                    f"Required: {credits_cost}, Available: {balance}"
                )

            # Get finding details from database
            finding_data = await self._get_finding_details(
                request.scan_id, request.finding_id
            )
            if not finding_data:
                raise ValueError(
                    f"Finding {request.finding_id} not found in scan {request.scan_id}"
                )

            # Get additional context if specified
            context_files = (
                await self._get_context_files(request.scan_id, request.context_files)
                if request.context_files
                else {}
            )

            # Build analysis prompt
            prompt = self._build_investigation_prompt(
                finding_data, context_files, request.depth
            )

            # Perform LLM analysis
            logger.info(
                f"Starting {request.depth} investigation of finding {request.finding_id}"
            )

            # Use appropriate model for depth level
            llm_response = await self._call_llm_for_investigation(prompt, model)

            # Parse response into structured format
            investigation_result = self._parse_investigation_response(
                llm_response, finding_data, request.depth, model
            )
            investigation_result.investigation_id = investigation_id

            # Calculate processing time
            processing_time = int(
                (datetime.utcnow() - start_time).total_seconds() * 1000
            )
            investigation_result.processing_time_ms = processing_time
            investigation_result.credits_used = credits_cost

            # Deduct credits
            await credit_service.deduct_credits(
                user_id=request.user_id,
                amount=credits_cost,
                transaction_type="investigate",
                scan_id=request.scan_id,
                session_id=request.session_id,
                model_used=model,
                tokens_used=self._estimate_tokens(prompt, llm_response),
                metadata={
                    "investigation_id": investigation_id,
                    "finding_id": request.finding_id,
                    "depth_level": request.depth,
                    "confidence_score": investigation_result.threat_analysis.confidence_score,
                },
            )

            # Store investigation results for session persistence
            if request.session_id:
                await self._store_investigation_in_session(
                    request.session_id, investigation_result
                )

            logger.info(
                f"Completed {request.depth} investigation {investigation_id} "
                f"for finding {request.finding_id} in {processing_time}ms"
            )

            return investigation_result

        except InsufficientCreditsError:
            raise
        except Exception as e:
            logger.exception(
                f"Investigation failed for finding {request.finding_id}: {e}"
            )
            raise

    def _get_model_and_cost(self, depth: DepthLevel) -> tuple[str, int]:
        """Get appropriate model and cost for investigation depth."""
        if depth == "quick":
            return "claude-3-haiku-20240307", SCAN_COSTS["investigate_finding"]
        elif depth == "thorough":
            return "claude-3-sonnet-20240229", SCAN_COSTS["investigate_finding"] * 2
        else:  # exhaustive
            return "claude-3-opus-20240229", SCAN_COSTS["investigate_finding"] * 6

    async def _get_finding_details(
        self, scan_id: str, finding_id: str
    ) -> Optional[Dict]:
        """Retrieve finding details from database."""
        try:
            result = await db.fetch_one(
                """
                SELECT 
                    finding_id,
                    phase,
                    pattern_id,
                    severity,
                    message,
                    file_path,
                    line_number,
                    code_snippet,
                    context_before,
                    context_after,
                    metadata
                FROM scan_findings 
                WHERE scan_id = :scan_id AND finding_id = :finding_id
                """,
                {"scan_id": scan_id, "finding_id": finding_id},
            )

            if result:
                return {
                    "finding_id": result["finding_id"],
                    "phase": result["phase"],
                    "pattern_id": result["pattern_id"],
                    "severity": result["severity"],
                    "message": result["message"],
                    "file_path": result["file_path"],
                    "line_number": result["line_number"],
                    "code_snippet": result["code_snippet"],
                    "context_before": result["context_before"],
                    "context_after": result["context_after"],
                    "metadata": json.loads(result["metadata"])
                    if result["metadata"]
                    else {},
                }

            return None

        except Exception as e:
            logger.exception(f"Failed to get finding details: {e}")
            return None

    async def _get_context_files(
        self, scan_id: str, file_paths: list[str]
    ) -> Dict[str, str]:
        """Get additional context files for investigation."""
        try:
            context_files = {}
            for file_path in file_paths[:5]:  # Limit to 5 files for performance
                result = await db.fetch_one(
                    """
                    SELECT file_content 
                    FROM scan_files 
                    WHERE scan_id = :scan_id AND file_path = :file_path
                    """,
                    {"scan_id": scan_id, "file_path": file_path},
                )
                if result:
                    context_files[file_path] = result["file_content"]

            return context_files

        except Exception as e:
            logger.exception(f"Failed to get context files: {e}")
            return {}

    def _build_investigation_prompt(
        self, finding_data: Dict, context_files: Dict[str, str], depth: DepthLevel
    ) -> str:
        """Build investigation prompt based on finding data and depth level."""

        depth_instructions = {
            "quick": "Provide a focused analysis answering if this is a real threat.",
            "thorough": "Provide comprehensive analysis including attack scenarios and impact assessment.",
            "exhaustive": "Provide extremely detailed analysis with full context, attack chains, and defense strategies.",
        }

        prompt = f"""
You are a senior security engineer investigating a potential vulnerability. Analyze this finding in detail.

INVESTIGATION DEPTH: {depth.upper()}
{depth_instructions[depth]}

FINDING DETAILS:
- ID: {finding_data["finding_id"]}
- Phase: {finding_data["phase"]}
- Severity: {finding_data["severity"]}
- Message: {finding_data["message"]}
- File: {finding_data["file_path"]}
- Line: {finding_data["line_number"]}

CODE SNIPPET:
```
{finding_data.get("context_before", "")}
>>> {finding_data["code_snippet"]} <<<
{finding_data.get("context_after", "")}
```

ADDITIONAL CONTEXT FILES:
{self._format_context_files(context_files)}

METADATA:
{json.dumps(finding_data.get("metadata", {}), indent=2)}

Provide your analysis as a JSON response with the following structure:

{{
    "is_real_threat": boolean,
    "confidence_score": float (0-1),
    "false_positive_likelihood": float (0-1),
    "exploitability": "none|low|medium|high|critical",
    "impact_assessment": "detailed description of potential impact",
    "evidence": [
        {{
            "code_snippet": "relevant code",
            "file_path": "file path",
            "line_number": int or null,
            "explanation": "why this evidence matters"
        }}
    ],
    "detailed_explanation": "comprehensive explanation of the finding",
    "attack_scenarios": ["scenario 1", "scenario 2"],
    "remediation_priority": "low|medium|high|critical"
}}

Focus on:
1. Is this finding a genuine security threat?
2. What evidence supports your conclusion?
3. How could an attacker exploit this?
4. What is the real-world impact?
5. How urgent is remediation?
"""

        return prompt

    def _format_context_files(self, context_files: Dict[str, str]) -> str:
        """Format context files for prompt inclusion."""
        if not context_files:
            return "No additional context files provided."

        formatted = []
        for file_path, content in context_files.items():
            # Truncate very large files
            truncated_content = (
                content[:2000] + "..." if len(content) > 2000 else content
            )
            formatted.append(f"File: {file_path}\n```\n{truncated_content}\n```")

        return "\n\n".join(formatted)

    async def _call_llm_for_investigation(self, prompt: str, model: str) -> str:
        """Call LLM service for investigation analysis."""
        # Use existing LLM service with appropriate model
        from api.llm_models import LLMAnalysisRequest, LLMAnalysisType

        # Create analysis request
        analysis_request = LLMAnalysisRequest(
            file_contents={"investigation_context": prompt},
            analysis_types=[LLMAnalysisType.VULNERABILITY_ANALYSIS],
            max_tokens=4000 if "opus" in model else 2000,
            include_context_analysis=True,
        )

        # Override model in config temporarily
        original_model = (
            llm_service.llm_config.model if hasattr(llm_service, "llm_config") else None
        )
        try:
            if hasattr(llm_service, "llm_config"):
                llm_service.llm_config.model = model

            response = await llm_service.analyze_threat(analysis_request)

            # Extract the actual LLM response content
            if response.insights:
                return response.insights[0].description
            else:
                raise Exception("No insights returned from LLM analysis")

        finally:
            # Restore original model
            if original_model and hasattr(llm_service, "llm_config"):
                llm_service.llm_config.model = original_model

    def _parse_investigation_response(
        self, llm_response: str, finding_data: Dict, depth: DepthLevel, model: str
    ) -> FindingInvestigationResponse:
        """Parse LLM response into structured investigation result."""
        try:
            # Try to extract JSON from response
            response_json = self._extract_json_from_response(llm_response)

            # Parse evidence
            evidence = []
            for ev in response_json.get("evidence", []):
                evidence.append(
                    FindingEvidence(
                        code_snippet=ev.get("code_snippet", ""),
                        file_path=ev.get("file_path", finding_data["file_path"]),
                        line_number=ev.get("line_number"),
                        explanation=ev.get("explanation", ""),
                    )
                )

            # Create threat analysis
            threat_analysis = ThreatAnalysis(
                is_real_threat=response_json.get("is_real_threat", False),
                confidence_score=float(response_json.get("confidence_score", 0.5)),
                false_positive_likelihood=float(
                    response_json.get("false_positive_likelihood", 0.5)
                ),
                exploitability=response_json.get("exploitability", "unknown"),
                impact_assessment=response_json.get(
                    "impact_assessment", "Impact assessment not available"
                ),
            )

            return FindingInvestigationResponse(
                investigation_id="",  # Will be set by caller
                finding_id=finding_data["finding_id"],
                depth_level=depth,
                threat_analysis=threat_analysis,
                evidence=evidence,
                detailed_explanation=response_json.get(
                    "detailed_explanation", "Analysis not available"
                ),
                attack_scenarios=response_json.get("attack_scenarios", []),
                remediation_priority=response_json.get(
                    "remediation_priority", "medium"
                ),
                model_used=model,
                credits_used=0,  # Will be set by caller
            )

        except Exception as e:
            logger.exception(f"Failed to parse investigation response: {e}")

            # Fallback response
            return FindingInvestigationResponse(
                investigation_id="",
                finding_id=finding_data["finding_id"],
                depth_level=depth,
                threat_analysis=ThreatAnalysis(
                    is_real_threat=True,  # Conservative default
                    confidence_score=0.5,
                    false_positive_likelihood=0.5,
                    exploitability="unknown",
                    impact_assessment="Unable to assess impact due to parsing error",
                ),
                evidence=[],
                detailed_explanation=f"Investigation completed but response parsing failed: {str(e)}",
                attack_scenarios=[],
                remediation_priority="medium",
                model_used=model,
                credits_used=0,
            )

    def _extract_json_from_response(self, response: str) -> Dict:
        """Extract JSON from LLM response, handling various formats."""
        import re

        # Try to find JSON block in the response
        json_match = re.search(r"```json\n(.*?)\n```", response, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            # Try to find JSON without code blocks
            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
            else:
                # Fallback - assume entire response is JSON
                json_str = response

        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            logger.warning(f"JSON parsing failed: {e}, response: {response[:200]}...")
            return {}

    def _estimate_tokens(self, prompt: str, response: str) -> int:
        """Estimate token usage for billing."""
        return (len(prompt) + len(response)) // 4

    async def _store_investigation_in_session(
        self, session_id: str, investigation: FindingInvestigationResponse
    ) -> None:
        """Store investigation result in interactive session."""
        try:
            # Get current session data
            session = await db.fetch_one(
                "SELECT conversation_history FROM interactive_sessions WHERE session_id = :session_id",
                {"session_id": session_id},
            )

            if session:
                # Parse existing conversation
                conversation = json.loads(session["conversation_history"] or "[]")

                # Add investigation result
                conversation.append(
                    {
                        "type": "investigation",
                        "timestamp": datetime.utcnow().isoformat(),
                        "investigation_id": investigation.investigation_id,
                        "finding_id": investigation.finding_id,
                        "depth_level": investigation.depth_level,
                        "summary": investigation.detailed_explanation[:200] + "...",
                        "confidence_score": investigation.threat_analysis.confidence_score,
                        "is_real_threat": investigation.threat_analysis.is_real_threat,
                    }
                )

                # Update session
                await db.execute(
                    """
                    UPDATE interactive_sessions 
                    SET conversation_history = :conversation,
                        last_activity = :timestamp,
                        total_credits_used = total_credits_used + :credits
                    WHERE session_id = :session_id
                    """,
                    {
                        "session_id": session_id,
                        "conversation": json.dumps(conversation),
                        "timestamp": datetime.utcnow(),
                        "credits": investigation.credits_used,
                    },
                )

        except Exception as e:
            logger.exception(f"Failed to store investigation in session: {e}")
            # Don't raise - this is non-critical


# Global service instance
finding_investigator = FindingInvestigatorService()
