"""
LLM Service for Sigil Pro - AI-powered threat detection
"""

from __future__ import annotations

import hashlib
import json
import logging
import time

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

from llm_config import llm_config
from database import db
from models.llm_models import (
    LLMAnalysisRequest,
    LLMAnalysisResponse,
    LLMInsight,
    LLMContextAnalysis,
    LLMAnalysisType,
    LLMThreatCategory,
    LLMConfidence,
    confidence_to_level,
)


logger = logging.getLogger(__name__)


class LLMService:
    """Service for AI-powered security analysis."""

    def __init__(self):
        self._session: aiohttp.ClientSession | None = None
        self._rate_limiter = RateLimiter(llm_config.rate_limit_requests_per_minute)

    async def analyze_threat(self, request: LLMAnalysisRequest) -> LLMAnalysisResponse:
        """Perform LLM-powered threat analysis on code."""
        start_time = time.time()
        analysis_id = self._generate_analysis_id(request)

        # Check cache first
        cached_response = await self._get_cached_analysis(analysis_id)
        if cached_response:
            logger.info(f"LLM analysis cache hit for {analysis_id}")
            cached_response.cache_hit = True
            return cached_response

        # Verify configuration
        if not llm_config.is_configured():
            logger.warning("LLM service not configured, using fallback")
            return self._create_fallback_response(
                analysis_id, "LLM service not configured"
            )

        # Rate limiting
        await self._rate_limiter.acquire()

        try:
            # Perform analysis
            response = await self._perform_analysis(request, analysis_id)

            # Cache successful results
            if response.success:
                await self._cache_analysis(analysis_id, response)

                # Track analytics after successful analysis
                await self._track_analysis_analytics(
                    request, response, analysis_id, cached_response is not None
                )

            # Track usage
            processing_time = int((time.time() - start_time) * 1000)
            response.processing_time_ms = processing_time

            return response

        except Exception as e:
            logger.exception(f"LLM analysis failed for {analysis_id}: {e}")

            if llm_config.fallback_to_static:
                return self._create_fallback_response(analysis_id, str(e))
            else:
                raise

    async def _perform_analysis(
        self, request: LLMAnalysisRequest, analysis_id: str
    ) -> LLMAnalysisResponse:
        """Perform the actual LLM analysis."""

        # Prepare prompt based on analysis types
        prompt = await self._build_analysis_prompt(request)

        # Make API request
        llm_response = await self._call_llm_api(prompt, request.max_tokens)

        # Parse response
        insights = self._parse_llm_insights(llm_response, request)
        context_analysis = (
            self._parse_context_analysis(llm_response, request)
            if request.include_context_analysis
            else None
        )

        # Build response
        response = LLMAnalysisResponse(
            analysis_id=analysis_id,
            model_used=llm_config.model,
            insights=insights,
            context_analysis=context_analysis,
            tokens_used=self._estimate_tokens_used(prompt, llm_response),
        )

        # Generate summary statistics
        response.confidence_summary = self._summarize_confidence(insights)
        response.threat_summary = self._summarize_threats(insights)

        return response

    async def _build_analysis_prompt(self, request: LLMAnalysisRequest) -> str:
        """Build the analysis prompt for the LLM using professional templates."""
        from prompts.security_analysis_prompts import SecurityAnalysisPrompts

        # Use the professional prompt builder
        analysis_type_strings = [t.value for t in request.analysis_types]

        return SecurityAnalysisPrompts.build_analysis_prompt(
            analysis_types=analysis_type_strings,
            file_contents=request.file_contents,
            static_findings=request.static_findings,
            repository_context=request.repository_context,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def _call_llm_api(self, prompt: str, max_tokens: int) -> str:
        """Make HTTP request to LLM API with retry logic."""

        if not self._session:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=llm_config.timeout_seconds)
            )

        headers = llm_config.get_headers()
        url = llm_config.get_endpoint_url()

        # Build request payload based on provider
        if llm_config.provider in ("openai", "azure"):
            payload = {
                "model": llm_config.model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "temperature": llm_config.temperature,
                "response_format": {"type": "json_object"},
            }
        elif llm_config.provider == "anthropic":
            payload = {
                "model": llm_config.model,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": llm_config.temperature,
            }
        else:
            raise ValueError(f"Unsupported provider: {llm_config.provider}")

        async with self._session.post(url, headers=headers, json=payload) as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"LLM API error {response.status}: {error_text}")

            result = await response.json()

            # Extract content based on provider
            if llm_config.provider in ("openai", "azure"):
                return result["choices"][0]["message"]["content"]
            elif llm_config.provider == "anthropic":
                return result["content"][0]["text"]
            else:
                raise ValueError(f"Unsupported provider: {llm_config.provider}")

    def _parse_llm_insights(
        self, llm_response: str, request: LLMAnalysisRequest
    ) -> list[LLMInsight]:
        """Parse LLM response into structured insights."""
        try:
            data = json.loads(llm_response)
            insights = []

            for insight_data in data.get("insights", [])[: request.max_insights]:
                try:
                    insight = LLMInsight(
                        analysis_type=LLMAnalysisType(insight_data["analysis_type"]),
                        threat_category=LLMThreatCategory(
                            insight_data["threat_category"]
                        ),
                        confidence=insight_data["confidence"],
                        confidence_level=confidence_to_level(
                            insight_data["confidence"]
                        ),
                        title=insight_data["title"],
                        description=insight_data["description"],
                        reasoning=insight_data["reasoning"],
                        evidence_snippets=insight_data.get("evidence_snippets", []),
                        affected_files=insight_data.get("affected_files", []),
                        severity_adjustment=insight_data.get(
                            "severity_adjustment", 0.0
                        ),
                        false_positive_likelihood=insight_data.get(
                            "false_positive_likelihood", 0.0
                        ),
                        remediation_suggestions=insight_data.get(
                            "remediation_suggestions", []
                        ),
                        mitigation_steps=insight_data.get("mitigation_steps", []),
                    )
                    insights.append(insight)
                except (KeyError, ValueError, TypeError) as e:
                    logger.warning(
                        f"Failed to parse insight: {e}, data: {insight_data}"
                    )
                    continue

            return insights

        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Failed to parse LLM response: {e}")
            return []

    def _parse_context_analysis(
        self, llm_response: str, request: LLMAnalysisRequest
    ) -> LLMContextAnalysis | None:
        """Parse context analysis from LLM response."""
        try:
            data = json.loads(llm_response)
            context_data = data.get("context_analysis")
            if not context_data:
                return None

            return LLMContextAnalysis(
                attack_chain_detected=context_data.get("attack_chain_detected", False),
                coordinated_threat=context_data.get("coordinated_threat", False),
                attack_chain_steps=context_data.get("attack_chain_steps", []),
                correlation_insights=context_data.get("correlation_insights", []),
                overall_intent=context_data.get("overall_intent", ""),
                sophistication_level=context_data.get("sophistication_level", "basic"),
            )
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def _generate_analysis_id(self, request: LLMAnalysisRequest) -> str:
        """Generate unique ID for analysis based on request content."""
        content_hash = hashlib.sha256()

        # Hash file contents and settings
        for filename, content in sorted(request.file_contents.items()):
            content_hash.update(f"{filename}:{content}".encode())

        content_hash.update(f"model:{llm_config.model}".encode())
        content_hash.update(f"types:{sorted(request.analysis_types)}".encode())

        return content_hash.hexdigest()[:16]

    async def _get_cached_analysis(
        self, analysis_id: str
    ) -> LLMAnalysisResponse | None:
        """Retrieve cached analysis result."""
        try:
            cached_data = await db.get_cache(f"llm_analysis:{analysis_id}")
            if cached_data:
                return LLMAnalysisResponse.model_validate(cached_data)
        except Exception as e:
            logger.warning(f"Failed to retrieve cached analysis: {e}")

        return None

    async def _cache_analysis(
        self, analysis_id: str, response: LLMAnalysisResponse
    ) -> None:
        """Cache analysis result."""
        try:
            ttl_seconds = llm_config.cache_ttl_hours * 3600
            await db.set_cache(
                f"llm_analysis:{analysis_id}", response.model_dump(), ttl=ttl_seconds
            )
        except Exception as e:
            logger.warning(f"Failed to cache analysis: {e}")

    def _estimate_tokens_used(self, prompt: str, response: str) -> int:
        """Estimate tokens used (rough approximation)."""
        # Very rough estimation: ~4 characters per token
        return (len(prompt) + len(response)) // 4

    def _summarize_confidence(self, insights: list[LLMInsight]) -> dict[str, int]:
        """Summarize insights by confidence level."""
        summary = {level.value: 0 for level in LLMConfidence}
        for insight in insights:
            summary[insight.confidence_level.value] += 1
        return summary

    def _summarize_threats(self, insights: list[LLMInsight]) -> dict[str, int]:
        """Summarize insights by threat category."""
        summary = {}
        for insight in insights:
            category = insight.threat_category.value
            summary[category] = summary.get(category, 0) + 1
        return summary

    def _create_fallback_response(
        self, analysis_id: str, error_message: str
    ) -> LLMAnalysisResponse:
        """Create fallback response when LLM is unavailable."""
        return LLMAnalysisResponse(
            analysis_id=analysis_id,
            model_used="fallback",
            insights=[],
            context_analysis=None,
            success=False,
            error_message=error_message,
            fallback_used=True,
        )

    async def close(self):
        """Close HTTP session."""
        if self._session:
            await self._session.close()

    async def _track_analysis_analytics(
        self,
        request: LLMAnalysisRequest,
        response: LLMAnalysisResponse,
        analysis_id: str,
        was_cache_hit: bool,
    ) -> None:
        """Track analytics for LLM analysis usage."""
        try:
            # Lazy import to avoid circular imports
            from services.analytics_service import analytics_service

            # Convert insights to dict format for analytics
            insights_data = [
                {
                    "threat_category": insight.threat_category.value,
                    "confidence": insight.confidence,
                    "analysis_type": insight.analysis_type.value,
                    "title": insight.title,
                    "description": insight.description,
                    "severity_adjustment": insight.severity_adjustment,
                }
                for insight in response.insights
            ]

            # Track LLM usage
            await analytics_service.track_llm_usage(
                user_id=getattr(request, "user_id", "unknown"),
                scan_id=analysis_id,
                model_used=response.model_used,
                tokens_used=response.tokens_used,
                processing_time_ms=response.processing_time_ms or 0,
                insights_generated=insights_data,
                cache_hit=was_cache_hit,
                fallback_used=response.fallback_used,
            )

            # Track individual threat discoveries
            for insight in response.insights:
                await analytics_service.track_threat_discovery(
                    user_id=getattr(request, "user_id", "unknown"),
                    threat_type=insight.threat_category.value,
                    severity=insight.confidence_level.value,
                    confidence=insight.confidence,
                    scan_id=analysis_id,
                    is_zero_day=insight.analysis_type
                    == LLMAnalysisType.ZERO_DAY_DETECTION,
                    analysis_type="llm_analysis",
                    evidence_snippet="\n".join(insight.evidence_snippets[:2])
                    if insight.evidence_snippets
                    else None,
                    remediation_steps=insight.remediation_suggestions,
                )

        except Exception as e:
            logger.exception(
                f"Failed to track analytics for analysis {analysis_id}: {e}"
            )
            # Don't let analytics failures break the main functionality


class RateLimiter:
    """Simple in-memory rate limiter."""

    def __init__(self, requests_per_minute: int):
        self.requests_per_minute = requests_per_minute
        self.requests: list[float] = []

    async def acquire(self):
        """Wait if necessary to respect rate limits."""
        import asyncio

        now = time.time()
        # Remove old requests (older than 1 minute)
        self.requests = [t for t in self.requests if now - t < 60]

        if len(self.requests) >= self.requests_per_minute:
            # Calculate wait time
            oldest_request = min(self.requests)
            wait_time = 60 - (now - oldest_request) + 0.1  # Add small buffer
            if wait_time > 0:
                await asyncio.sleep(wait_time)

        self.requests.append(now)


# Global service instance
llm_service = LLMService()
