"""
False Positive Analysis Service for Interactive LLM Analysis
Determines if security findings are likely false positives with detailed explanations.
"""

from __future__ import annotations

import logging
import json
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from api.database import db
from api.services.llm_service import llm_service
from api.services.credit_service import credit_service, SCAN_COSTS
from api.prompts.false_positive_prompts import FalsePositivePrompts
from api.exceptions import InsufficientCreditsError

logger = logging.getLogger(__name__)


class FalsePositiveAnalysisRequest(BaseModel):
    """Request for false positive analysis."""

    user_id: str = Field(..., description="User requesting the analysis")
    scan_id: str = Field(..., description="Scan ID containing the finding")
    finding_id: str = Field(..., description="Finding to analyze for false positive")
    include_data_flow: bool = Field(
        default=True, description="Include data flow analysis"
    )
    include_context_comparison: bool = Field(
        default=True, description="Compare with similar findings"
    )
    session_id: Optional[str] = Field(
        default=None, description="Interactive session ID"
    )


class ContextFactor(BaseModel):
    """Context factor supporting the analysis."""

    factor: str = Field(..., description="Description of the context factor")
    supports_false_positive: bool = Field(
        ..., description="Whether this factor supports false positive conclusion"
    )


class DefenseRecommendation(BaseModel):
    """Defense-in-depth recommendation."""

    recommendation: str = Field(
        ..., description="Specific security improvement recommendation"
    )
    impact: str = Field(..., description="Impact of implementing this recommendation")
    effort: str = Field(..., description="Effort required to implement")


class FalsePositiveAnalysisResponse(BaseModel):
    """Response from false positive analysis."""

    analysis_id: str = Field(..., description="Unique analysis ID")
    finding_id: str = Field(..., description="Finding that was analyzed")
    is_false_positive: bool = Field(
        ..., description="Whether this is likely a false positive"
    )
    confidence_percentage: int = Field(
        ..., ge=0, le=100, description="Confidence in assessment (0-100%)"
    )
    reasoning: str = Field(..., description="Detailed reasoning for the assessment")
    context_factors: List[ContextFactor] = Field(
        ..., description="Factors that influenced the analysis"
    )
    risk_factors: List[str] = Field(
        ..., description="Remaining risk factors even if false positive"
    )
    defense_recommendations: List[DefenseRecommendation] = Field(
        ..., description="Defense-in-depth improvements"
    )
    true_positive_scenarios: List[str] = Field(
        ..., description="Scenarios where this could still be exploited"
    )
    verdict_summary: str = Field(..., description="One-sentence summary of conclusion")
    data_flow_controlled: Optional[bool] = Field(
        default=None, description="Whether data flow is user-controlled"
    )
    context_classification: Optional[str] = Field(
        default=None, description="Classification of code context"
    )
    model_used: str = Field(..., description="LLM model used for analysis")
    credits_used: int = Field(..., description="Credits consumed for analysis")
    processing_time_ms: Optional[int] = Field(
        default=None, description="Processing time"
    )


class FalsePositiveAnalyzerService:
    """Service for analyzing potential false positive security findings."""

    async def analyze_false_positive(
        self, request: FalsePositiveAnalysisRequest
    ) -> FalsePositiveAnalysisResponse:
        """
        Analyze a security finding to determine false positive likelihood.

        Args:
            request: Analysis request with finding details and options

        Returns:
            Detailed false positive analysis with recommendations

        Raises:
            InsufficientCreditsError: If user lacks credits for analysis
        """
        analysis_id = str(uuid4())[:16]
        start_time = datetime.utcnow()

        try:
            # Use efficient Haiku model for false positive analysis
            model = "claude-3-haiku-20240307"
            credits_cost = SCAN_COSTS["investigate_finding"]

            # Check credit availability
            if not await credit_service.has_credits(request.user_id, credits_cost):
                balance = await credit_service.get_balance(request.user_id)
                raise InsufficientCreditsError(
                    f"Insufficient credits for false positive analysis. "
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

            # Get extended code context
            code_context = await self._get_extended_code_context(
                request.scan_id, finding_data["file_path"], finding_data["line_number"]
            )

            # Perform main false positive analysis
            main_analysis = await self._perform_main_analysis(
                finding_data, code_context, model
            )

            # Optional: Data flow analysis
            data_flow_controlled = None
            if request.include_data_flow:
                data_flow_controlled = await self._analyze_data_flow(
                    finding_data, code_context, model
                )

            # Optional: Context classification
            context_classification = None
            if request.include_context_comparison:
                context_classification = await self._classify_context(
                    finding_data["file_path"], code_context, model
                )

            # Calculate processing time
            processing_time = int(
                (datetime.utcnow() - start_time).total_seconds() * 1000
            )

            # Build final response
            response = FalsePositiveAnalysisResponse(
                analysis_id=analysis_id,
                finding_id=request.finding_id,
                is_false_positive=main_analysis["is_false_positive"],
                confidence_percentage=main_analysis["confidence_percentage"],
                reasoning=main_analysis["reasoning"],
                context_factors=[
                    ContextFactor(factor=factor, supports_false_positive=True)
                    for factor in main_analysis.get("context_factors", [])
                ],
                risk_factors=main_analysis.get("risk_factors", []),
                defense_recommendations=[
                    DefenseRecommendation(
                        recommendation=rec,
                        impact="Security improvement",
                        effort="Varies",
                    )
                    for rec in main_analysis.get("defense_recommendations", [])
                ],
                true_positive_scenarios=main_analysis.get(
                    "true_positive_scenarios", []
                ),
                verdict_summary=main_analysis.get(
                    "verdict_summary", "Analysis completed"
                ),
                data_flow_controlled=data_flow_controlled,
                context_classification=context_classification,
                model_used=model,
                credits_used=credits_cost,
                processing_time_ms=processing_time,
            )

            # Deduct credits
            await credit_service.deduct_credits(
                user_id=request.user_id,
                amount=credits_cost,
                transaction_type="investigate",
                scan_id=request.scan_id,
                session_id=request.session_id,
                model_used=model,
                tokens_used=self._estimate_tokens(code_context, str(main_analysis)),
                metadata={
                    "analysis_id": analysis_id,
                    "finding_id": request.finding_id,
                    "analysis_type": "false_positive",
                    "confidence_percentage": main_analysis["confidence_percentage"],
                    "is_false_positive": main_analysis["is_false_positive"],
                },
            )

            # Store in session if provided
            if request.session_id:
                await self._store_analysis_in_session(request.session_id, response)

            logger.info(
                f"Completed false positive analysis {analysis_id} for finding {request.finding_id} "
                f"in {processing_time}ms. Result: {response.is_false_positive} "
                f"({response.confidence_percentage}% confidence)"
            )

            return response

        except InsufficientCreditsError:
            raise
        except Exception as e:
            logger.exception(
                f"False positive analysis failed for finding {request.finding_id}: {e}"
            )
            raise

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
                    "file_extension": self._get_file_extension(result["file_path"]),
                }

            return None

        except Exception as e:
            logger.exception(f"Failed to get finding details: {e}")
            return None

    async def _get_extended_code_context(
        self, scan_id: str, file_path: str, line_number: int
    ) -> str:
        """Get extended code context around the finding."""
        try:
            result = await db.fetch_one(
                """
                SELECT file_content 
                FROM scan_files 
                WHERE scan_id = :scan_id AND file_path = :file_path
                """,
                {"scan_id": scan_id, "file_path": file_path},
            )

            if result and result["file_content"]:
                lines = result["file_content"].split("\n")
                start_line = max(0, line_number - 20)  # 20 lines before
                end_line = min(len(lines), line_number + 20)  # 20 lines after

                context_lines = []
                for i in range(start_line, end_line):
                    prefix = ">>> " if i == line_number else "    "
                    context_lines.append(f"{i + 1:4d}:{prefix}{lines[i]}")

                return "\n".join(context_lines)

            return "Code context not available"

        except Exception as e:
            logger.exception(f"Failed to get extended code context: {e}")
            return "Error retrieving code context"

    async def _perform_main_analysis(
        self, finding_data: Dict, code_context: str, model: str
    ) -> Dict:
        """Perform main false positive analysis."""
        try:
            # Build analysis prompt
            prompt = FalsePositivePrompts.build_false_positive_analysis_prompt(
                finding_data=finding_data, code_context=code_context
            )

            # Call LLM
            response = await self._call_llm_service(prompt, model)

            # Parse JSON response
            return self._parse_json_response(response)

        except Exception as e:
            logger.exception(f"Main analysis failed: {e}")
            return {
                "is_false_positive": False,  # Conservative default
                "confidence_percentage": 50,
                "reasoning": f"Analysis failed due to error: {str(e)}",
                "context_factors": [],
                "risk_factors": ["Analysis error occurred"],
                "defense_recommendations": [],
                "true_positive_scenarios": [],
                "verdict_summary": "Analysis could not be completed",
            }

    async def _analyze_data_flow(
        self, finding_data: Dict, code_context: str, model: str
    ) -> Optional[bool]:
        """Analyze data flow to determine if user input can reach the vulnerable code."""
        try:
            prompt = FalsePositivePrompts.build_data_flow_analysis_prompt(
                finding_data=finding_data, code_context=code_context
            )

            response = await self._call_llm_service(prompt, model)
            parsed = self._parse_json_response(response)

            return parsed.get("user_controlled_input_possible", None)

        except Exception as e:
            logger.warning(f"Data flow analysis failed: {e}")
            return None

    async def _classify_context(
        self, file_path: str, code_context: str, model: str
    ) -> Optional[str]:
        """Classify the context and purpose of the code."""
        try:
            prompt = FalsePositivePrompts.build_context_classification_prompt(
                file_path=file_path,
                code_sample=code_context[:1000],  # Limit for efficiency
            )

            response = await self._call_llm_service(prompt, model)
            parsed = self._parse_json_response(response)

            classification = parsed.get("file_classification", "unknown")
            sensitivity = parsed.get("security_sensitivity", "unknown")

            return f"{classification} ({sensitivity} sensitivity)"

        except Exception as e:
            logger.warning(f"Context classification failed: {e}")
            return None

    async def _call_llm_service(self, prompt: str, model: str) -> str:
        """Call LLM service for analysis."""
        from api.llm_models import LLMAnalysisRequest, LLMAnalysisType

        # Create analysis request
        analysis_request = LLMAnalysisRequest(
            file_contents={"analysis_context": prompt},
            analysis_types=[LLMAnalysisType.VULNERABILITY_ANALYSIS],
            max_tokens=2000,
            include_context_analysis=False,
        )

        # Call LLM service (model will be used based on configuration)
        response = await llm_service.analyze_threat(analysis_request)

        # Extract response content
        if response.insights:
            return response.insights[0].description
        else:
            raise Exception("No insights returned from LLM analysis")

    def _parse_json_response(self, response: str) -> Dict:
        """Parse JSON response from LLM, with error handling."""
        import re

        try:
            # Try to extract JSON block
            json_match = re.search(r"```json\n(.*?)\n```", response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to find JSON object
                json_match = re.search(r"\{.*\}", response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0)
                else:
                    json_str = response

            return json.loads(json_str)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            logger.debug(f"Raw response: {response[:500]}...")
            return {}

    def _get_file_extension(self, file_path: str) -> str:
        """Get file extension for syntax highlighting."""
        if "." in file_path:
            return file_path.split(".")[-1].lower()
        return ""

    def _estimate_tokens(self, prompt: str, response: str) -> int:
        """Estimate token usage for billing."""
        return (len(prompt) + len(response)) // 4

    async def _store_analysis_in_session(
        self, session_id: str, analysis: FalsePositiveAnalysisResponse
    ) -> None:
        """Store analysis result in interactive session."""
        try:
            # Get current session data
            session = await db.fetch_one(
                "SELECT conversation_history FROM interactive_sessions WHERE session_id = :session_id",
                {"session_id": session_id},
            )

            if session:
                # Parse existing conversation
                conversation = json.loads(session["conversation_history"] or "[]")

                # Add analysis result
                conversation.append(
                    {
                        "type": "false_positive_analysis",
                        "timestamp": datetime.utcnow().isoformat(),
                        "analysis_id": analysis.analysis_id,
                        "finding_id": analysis.finding_id,
                        "is_false_positive": analysis.is_false_positive,
                        "confidence_percentage": analysis.confidence_percentage,
                        "verdict_summary": analysis.verdict_summary,
                        "reasoning": analysis.reasoning[:300]
                        + "...",  # Truncated for storage
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
                        "credits": analysis.credits_used,
                    },
                )

        except Exception as e:
            logger.exception(f"Failed to store analysis in session: {e}")


# Global service instance
false_positive_analyzer = FalsePositiveAnalyzerService()
