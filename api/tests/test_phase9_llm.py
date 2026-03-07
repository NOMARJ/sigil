"""
Phase 9 LLM Analysis Tests

Comprehensive test suite for LLM-powered threat detection (Phase 9 of the scanner engine).
Tests AI analysis capabilities, prompt injection detection, zero-day discovery,
and contextual threat correlation for Pro tier users.

Test Coverage:
- LLM service configuration and API integration
- Threat analysis prompt generation and processing
- Zero-day vulnerability detection capabilities
- Context correlation and attack chain analysis
- LLM response parsing and insight extraction
- Caching and performance optimization
- Error handling and fallback mechanisms
- Analytics tracking for LLM usage
"""

from __future__ import annotations

import json
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from services.llm_service import llm_service, LLMService, RateLimiter
from models.llm_models import (
    LLMAnalysisRequest,
    LLMAnalysisResponse,
    LLMInsight,
    LLMAnalysisType,
    LLMThreatCategory,
    LLMConfidence,
    confidence_to_level,
)
from llm_config import llm_config
from scanner.phase9_llm_detector import Phase9LLMDetector


class TestLLMServiceConfiguration:
    """Test LLM service configuration and setup"""

    def test_llm_service_initialization(self):
        """Test LLM service proper initialization"""
        service = LLMService()
        assert service._session is None
        assert service._rate_limiter is not None
        assert isinstance(service._rate_limiter, RateLimiter)

    @pytest.mark.asyncio
    async def test_llm_service_session_creation(self):
        """Test HTTP session creation for LLM API calls"""
        service = LLMService()

        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session

            with patch.object(service, "_call_llm_api") as mock_call:
                mock_call.return_value = '{"insights": []}'

                request = LLMAnalysisRequest(
                    file_contents={"test.py": "print('hello')"}, static_findings=[]
                )

                await service.analyze_threat(request)

                # Session should be created on first call
                mock_session_class.assert_called_once()

    def test_llm_config_validation(self):
        """Test LLM configuration validation"""
        with patch.object(llm_config, "provider", "openai"):
            with patch.object(llm_config, "api_key", "test-key"):
                with patch.object(llm_config, "model", "gpt-4"):
                    assert llm_config.is_configured() is True

        with patch.object(llm_config, "api_key", None):
            assert llm_config.is_configured() is False


class TestLLMAnalysisRequests:
    """Test LLM analysis request processing"""

    @pytest.fixture
    def sample_analysis_request(self):
        """Sample LLM analysis request"""
        return LLMAnalysisRequest(
            file_contents={
                "malicious.py": "import os; os.system(input('Command: '))",
                "helper.py": "def decode_payload(data): return base64.b64decode(data)",
            },
            static_findings=[
                {
                    "phase": "code_patterns",
                    "rule": "code-exec",
                    "severity": "HIGH",
                    "file": "malicious.py",
                    "line": 1,
                    "snippet": "os.system(input('Command: '))",
                    "weight": 1.0,
                }
            ],
            analysis_types=[
                LLMAnalysisType.ZERO_DAY_DETECTION,
                LLMAnalysisType.CONTEXT_CORRELATION,
            ],
            include_context_analysis=True,
            max_insights=10,
            max_tokens=2000,
        )

    @pytest.mark.asyncio
    async def test_successful_llm_analysis(
        self, sample_analysis_request: LLMAnalysisRequest
    ):
        """Test successful LLM analysis with comprehensive insights"""

        mock_llm_response = {
            "insights": [
                {
                    "analysis_type": "zero_day_detection",
                    "threat_category": "code_injection",
                    "confidence": 0.95,
                    "title": "Dynamic code execution with user input",
                    "description": "Direct execution of user-provided commands via os.system",
                    "reasoning": "Combines user input function with system command execution",
                    "evidence_snippets": ["os.system(input('Command: '))"],
                    "affected_files": ["malicious.py"],
                    "severity_adjustment": 0.3,
                    "false_positive_likelihood": 0.05,
                    "remediation_suggestions": [
                        "Replace os.system with subprocess with argument validation",
                        "Implement command whitelist",
                    ],
                    "mitigation_steps": [
                        "Remove direct user input to system commands",
                        "Add input sanitization",
                    ],
                },
                {
                    "analysis_type": "context_correlation",
                    "threat_category": "data_exfiltration",
                    "confidence": 0.78,
                    "title": "Multi-file attack pattern detected",
                    "description": "Base64 decoding helper combined with code execution",
                    "reasoning": "Combination suggests obfuscated payload execution workflow",
                    "evidence_snippets": [
                        "base64.b64decode(data)",
                        "os.system(input('Command: '))",
                    ],
                    "affected_files": ["helper.py", "malicious.py"],
                    "severity_adjustment": 0.15,
                    "false_positive_likelihood": 0.12,
                },
            ],
            "context_analysis": {
                "attack_chain_detected": True,
                "coordinated_threat": True,
                "attack_chain_steps": [
                    "Decode base64 obfuscated payload",
                    "Execute system commands with user input",
                ],
                "correlation_insights": [
                    "Files work together to create a command injection vulnerability",
                    "Pattern indicates deliberate obfuscation and execution chain",
                ],
                "overall_intent": "Remote command execution via obfuscated payloads",
                "sophistication_level": "intermediate",
            },
        }

        with patch.object(llm_service, "_call_llm_api") as mock_call:
            mock_call.return_value = json.dumps(mock_llm_response)

            with patch.object(llm_config, "is_configured", return_value=True):
                response = await llm_service.analyze_threat(sample_analysis_request)

                assert response.success is True
                assert response.model_used == llm_config.model
                assert len(response.insights) == 2
                assert response.context_analysis is not None

                # Verify insights parsing
                first_insight = response.insights[0]
                assert first_insight.analysis_type == LLMAnalysisType.ZERO_DAY_DETECTION
                assert first_insight.threat_category == LLMThreatCategory.CODE_INJECTION
                assert first_insight.confidence == 0.95
                assert first_insight.confidence_level == LLMConfidence.HIGH
                assert "Dynamic code execution" in first_insight.title

                # Verify context analysis
                context = response.context_analysis
                assert context.attack_chain_detected is True
                assert context.coordinated_threat is True
                assert len(context.attack_chain_steps) == 2
                assert context.sophistication_level == "intermediate"

    @pytest.mark.asyncio
    async def test_llm_analysis_caching(
        self, sample_analysis_request: LLMAnalysisRequest
    ):
        """Test LLM analysis response caching"""

        mock_response = LLMAnalysisResponse(
            analysis_id="test_analysis_123",
            model_used="gpt-4",
            insights=[],
            tokens_used=150,
            processing_time_ms=2000,
        )

        with patch.object(llm_service, "_get_cached_analysis") as mock_cache_get:
            mock_cache_get.return_value = mock_response

            response = await llm_service.analyze_threat(sample_analysis_request)

            assert response.cache_hit is True
            assert response.analysis_id == "test_analysis_123"

            # Should not have called LLM API due to cache hit
            with patch.object(llm_service, "_call_llm_api") as mock_api:
                await llm_service.analyze_threat(sample_analysis_request)
                mock_api.assert_not_called()

    @pytest.mark.asyncio
    async def test_llm_analysis_without_configuration(
        self, sample_analysis_request: LLMAnalysisRequest
    ):
        """Test fallback behavior when LLM is not configured"""

        with patch.object(llm_config, "is_configured", return_value=False):
            response = await llm_service.analyze_threat(sample_analysis_request)

            assert response.success is False
            assert response.fallback_used is True
            assert response.error_message == "LLM service not configured"
            assert response.model_used == "fallback"
            assert len(response.insights) == 0


class TestLLMPromptGeneration:
    """Test LLM prompt generation and processing"""

    @pytest.mark.asyncio
    async def test_analysis_prompt_building(
        self, sample_analysis_request: LLMAnalysisRequest
    ):
        """Test building analysis prompts for LLM"""

        with patch(
            "api.prompts.security_analysis_prompts.SecurityAnalysisPrompts.build_analysis_prompt"
        ) as mock_prompt:
            mock_prompt.return_value = "Test analysis prompt"

            prompt = await llm_service._build_analysis_prompt(sample_analysis_request)

            assert prompt == "Test analysis prompt"
            mock_prompt.assert_called_once()

            # Verify prompt builder called with correct parameters
            call_args = mock_prompt.call_args[1]
            assert "zero_day_detection" in call_args["analysis_types"]
            assert "context_correlation" in call_args["analysis_types"]
            assert call_args["file_contents"] == sample_analysis_request.file_contents

    def test_llm_analysis_types_enumeration(self):
        """Test LLM analysis types are properly defined"""

        # Verify all analysis types are available
        assert LLMAnalysisType.ZERO_DAY_DETECTION.value == "zero_day_detection"
        assert LLMAnalysisType.CONTEXT_CORRELATION.value == "context_correlation"
        assert (
            LLMAnalysisType.PROMPT_INJECTION_DETECTION.value
            == "prompt_injection_detection"
        )
        assert LLMAnalysisType.ADVANCED_OBFUSCATION.value == "advanced_obfuscation"

        # Verify threat categories
        assert LLMThreatCategory.CODE_INJECTION.value == "code_injection"
        assert LLMThreatCategory.DATA_EXFILTRATION.value == "data_exfiltration"
        assert LLMThreatCategory.PROMPT_INJECTION.value == "prompt_injection"
        assert LLMThreatCategory.SUPPLY_CHAIN_ATTACK.value == "supply_chain_attack"

        # Verify confidence levels
        assert confidence_to_level(0.9) == LLMConfidence.HIGH
        assert confidence_to_level(0.6) == LLMConfidence.MEDIUM
        assert confidence_to_level(0.3) == LLMConfidence.LOW


class TestLLMResponseParsing:
    """Test parsing and validation of LLM responses"""

    @pytest.mark.asyncio
    async def test_llm_insight_parsing_success(self):
        """Test successful parsing of LLM insights"""

        llm_response = json.dumps(
            {
                "insights": [
                    {
                        "analysis_type": "zero_day_detection",
                        "threat_category": "code_injection",
                        "confidence": 0.87,
                        "title": "Test threat",
                        "description": "Test description",
                        "reasoning": "Test reasoning",
                    }
                ]
            }
        )

        request = LLMAnalysisRequest(
            file_contents={"test.py": "test"}, static_findings=[]
        )

        insights = llm_service._parse_llm_insights(llm_response, request)

        assert len(insights) == 1
        insight = insights[0]
        assert insight.analysis_type == LLMAnalysisType.ZERO_DAY_DETECTION
        assert insight.threat_category == LLMThreatCategory.CODE_INJECTION
        assert insight.confidence == 0.87
        assert insight.confidence_level == LLMConfidence.HIGH

    @pytest.mark.asyncio
    async def test_llm_insight_parsing_invalid_data(self):
        """Test handling of invalid LLM insight data"""

        # Invalid JSON
        insights = llm_service._parse_llm_insights("Invalid JSON", None)
        assert len(insights) == 0

        # Missing required fields
        llm_response = json.dumps(
            {
                "insights": [
                    {
                        "analysis_type": "invalid_type",  # Invalid analysis type
                        "confidence": "not_a_number",  # Invalid confidence
                        # Missing required fields
                    }
                ]
            }
        )

        request = LLMAnalysisRequest(file_contents={}, static_findings=[])
        insights = llm_service._parse_llm_insights(llm_response, request)
        assert len(insights) == 0  # Should skip invalid insights

    @pytest.mark.asyncio
    async def test_context_analysis_parsing(self):
        """Test parsing of context analysis from LLM response"""

        llm_response = json.dumps(
            {
                "context_analysis": {
                    "attack_chain_detected": True,
                    "coordinated_threat": False,
                    "attack_chain_steps": ["Step 1", "Step 2"],
                    "correlation_insights": ["Insight 1"],
                    "overall_intent": "Malicious intent",
                    "sophistication_level": "advanced",
                }
            }
        )

        request = LLMAnalysisRequest(file_contents={}, static_findings=[])
        context = llm_service._parse_context_analysis(llm_response, request)

        assert context is not None
        assert context.attack_chain_detected is True
        assert context.coordinated_threat is False
        assert len(context.attack_chain_steps) == 2
        assert context.overall_intent == "Malicious intent"
        assert context.sophistication_level == "advanced"


class TestLLMProviderIntegration:
    """Test integration with different LLM providers"""

    @pytest.mark.asyncio
    async def test_openai_api_integration(self):
        """Test OpenAI API integration"""

        with patch.object(llm_config, "provider", "openai"):
            with patch.object(llm_config, "model", "gpt-4"):
                with patch("aiohttp.ClientSession.post") as mock_post:
                    mock_response = MagicMock()
                    mock_response.status = 200
                    mock_response.json = AsyncMock(
                        return_value={
                            "choices": [{"message": {"content": '{"insights": []}'}}]
                        }
                    )
                    mock_post.return_value.__aenter__.return_value = mock_response

                    service = LLMService()
                    result = await service._call_llm_api("test prompt", 1000)

                    assert result == '{"insights": []}'

                    # Verify OpenAI-specific payload format
                    call_args = mock_post.call_args[1]
                    payload = call_args["json"]
                    assert payload["model"] == "gpt-4"
                    assert payload["messages"][0]["content"] == "test prompt"
                    assert "response_format" in payload

    @pytest.mark.asyncio
    async def test_anthropic_api_integration(self):
        """Test Anthropic Claude API integration"""

        with patch.object(llm_config, "provider", "anthropic"):
            with patch.object(llm_config, "model", "claude-3-sonnet"):
                with patch("aiohttp.ClientSession.post") as mock_post:
                    mock_response = MagicMock()
                    mock_response.status = 200
                    mock_response.json = AsyncMock(
                        return_value={"content": [{"text": '{"insights": []}'}]}
                    )
                    mock_post.return_value.__aenter__.return_value = mock_response

                    service = LLMService()
                    result = await service._call_llm_api("test prompt", 1000)

                    assert result == '{"insights": []}'

                    # Verify Anthropic-specific payload format
                    call_args = mock_post.call_args[1]
                    payload = call_args["json"]
                    assert payload["model"] == "claude-3-sonnet"
                    assert payload["messages"][0]["content"] == "test prompt"
                    assert (
                        "response_format" not in payload
                    )  # Anthropic doesn't use this

    @pytest.mark.asyncio
    async def test_api_error_handling(self):
        """Test API error handling for LLM providers"""

        with patch("aiohttp.ClientSession.post") as mock_post:
            # Test HTTP error response
            mock_response = MagicMock()
            mock_response.status = 429  # Rate limited
            mock_response.text = AsyncMock(return_value="Rate limit exceeded")
            mock_post.return_value.__aenter__.return_value = mock_response

            service = LLMService()

            with pytest.raises(Exception) as exc_info:
                await service._call_llm_api("test prompt", 1000)

            assert "LLM API error 429" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_unsupported_provider_error(self):
        """Test error for unsupported LLM provider"""

        with patch.object(llm_config, "provider", "unsupported_provider"):
            service = LLMService()

            with pytest.raises(ValueError) as exc_info:
                await service._call_llm_api("test prompt", 1000)

            assert "Unsupported provider: unsupported_provider" in str(exc_info.value)


class TestRateLimiting:
    """Test LLM service rate limiting"""

    @pytest.mark.asyncio
    async def test_rate_limiter_basic_functionality(self):
        """Test basic rate limiting functionality"""

        rate_limiter = RateLimiter(requests_per_minute=3)

        # First 3 requests should succeed immediately
        start_time = asyncio.get_event_loop().time()

        await rate_limiter.acquire()
        await rate_limiter.acquire()
        await rate_limiter.acquire()

        elapsed = asyncio.get_event_loop().time() - start_time
        assert elapsed < 1.0  # Should be fast

        assert len(rate_limiter.requests) == 3

    @pytest.mark.asyncio
    async def test_rate_limiter_cleanup(self):
        """Test rate limiter cleans up old requests"""
        import time

        rate_limiter = RateLimiter(requests_per_minute=5)

        # Add some old requests manually
        old_time = time.time() - 120  # 2 minutes ago
        rate_limiter.requests = [old_time, old_time, old_time]

        # New request should clean up old ones
        await rate_limiter.acquire()

        # Only the new request should remain
        assert len(rate_limiter.requests) == 1
        assert all(req > old_time for req in rate_limiter.requests)


class TestPhase9Integration:
    """Test Phase 9 LLM detector integration with scanner engine"""

    @pytest.fixture
    def phase9_detector(self):
        """Phase 9 LLM detector instance"""
        return Phase9LLMDetector()

    @pytest.mark.asyncio
    async def test_phase9_detector_execution(self, phase9_detector):
        """Test Phase 9 detector execution with LLM analysis"""

        scan_context = {
            "file_contents": {"suspicious.py": "eval(base64.b64decode(payload))"},
            "static_findings": [
                {
                    "phase": "code_patterns",
                    "rule": "code-eval",
                    "severity": "HIGH",
                    "file": "suspicious.py",
                    "snippet": "eval(base64.b64decode(payload))",
                }
            ],
            "user_tier": "pro",
        }

        with patch.object(llm_service, "analyze_threat") as mock_analyze:
            mock_analyze.return_value = LLMAnalysisResponse(
                analysis_id="test_123",
                model_used="gpt-4",
                insights=[
                    LLMInsight(
                        analysis_type=LLMAnalysisType.ZERO_DAY_DETECTION,
                        threat_category=LLMThreatCategory.CODE_INJECTION,
                        confidence=0.92,
                        confidence_level=LLMConfidence.HIGH,
                        title="Obfuscated code injection",
                        description="Base64 encoded payload execution",
                        reasoning="Combines base64 decoding with eval execution",
                    )
                ],
                tokens_used=500,
                processing_time_ms=1500,
            )

            findings = await phase9_detector.scan(scan_context)

            assert len(findings) == 1
            finding = findings[0]
            assert finding["phase"] == "llm_analysis"
            assert finding["rule"] == "llm-zero-day-detection"
            assert finding["severity"] == "CRITICAL"  # High confidence LLM finding
            assert "Obfuscated code injection" in finding["description"]

    @pytest.mark.asyncio
    async def test_phase9_detector_free_tier_skip(self, phase9_detector):
        """Test Phase 9 detector skips analysis for free tier users"""

        scan_context = {
            "file_contents": {"test.py": "print('hello')"},
            "static_findings": [],
            "user_tier": "free",
        }

        findings = await phase9_detector.scan(scan_context)

        # Should return empty findings for free users
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_phase9_detector_error_handling(self, phase9_detector):
        """Test Phase 9 detector error handling"""

        scan_context = {
            "file_contents": {"test.py": "test code"},
            "static_findings": [],
            "user_tier": "pro",
        }

        with patch.object(llm_service, "analyze_threat") as mock_analyze:
            mock_analyze.side_effect = Exception("LLM service error")

            # Should not crash on LLM errors
            findings = await phase9_detector.scan(scan_context)
            assert len(findings) == 0  # Returns empty on error


class TestLLMAnalyticsTracking:
    """Test analytics tracking for LLM usage"""

    @pytest.mark.asyncio
    async def test_llm_usage_analytics_tracking(self):
        """Test tracking of LLM usage analytics"""

        analysis_request = LLMAnalysisRequest(
            file_contents={"test.py": "eval(input())"},
            static_findings=[],
            user_id="analytics_test_user",
        )

        with patch(
            "api.services.analytics_service.analytics_service.track_llm_usage"
        ) as mock_track_llm:
            with patch(
                "api.services.analytics_service.analytics_service.track_threat_discovery"
            ) as mock_track_threat:
                with patch.object(llm_service, "_call_llm_api") as mock_call:
                    mock_call.return_value = json.dumps(
                        {
                            "insights": [
                                {
                                    "analysis_type": "zero_day_detection",
                                    "threat_category": "code_injection",
                                    "confidence": 0.85,
                                    "title": "Test threat",
                                    "description": "Test description",
                                    "reasoning": "Test reasoning",
                                }
                            ]
                        }
                    )

                    response = await llm_service.analyze_threat(analysis_request)

                    # Verify LLM usage tracking
                    mock_track_llm.assert_called_once()
                    llm_call_args = mock_track_llm.call_args[1]
                    assert llm_call_args["user_id"] == "analytics_test_user"
                    assert llm_call_args["model_used"] == response.model_used
                    assert "processing_time_ms" in llm_call_args

                    # Verify threat discovery tracking
                    mock_track_threat.assert_called_once()
                    threat_call_args = mock_track_threat.call_args[1]
                    assert threat_call_args["user_id"] == "analytics_test_user"
                    assert threat_call_args["threat_type"] == "code_injection"
                    assert threat_call_args["is_zero_day"] is True
