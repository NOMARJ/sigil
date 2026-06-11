"""US-109: remediation generator + attack-chain tracer modernized."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from api.llm_config import llm_config
from api.llm_models import (
    LLMAnalysisRequest,
    LLMAnalysisResponse,
    LLMAnalysisType,
    LLMConfidence,
    LLMInsight,
    LLMThreatCategory,
)
from api.models import Finding, ScanPhase, Severity
from api.services.attack_chain_tracer import attack_chain_tracer
from api.services.credit_service import credit_service
from api.services.llm_service import llm_service
from api.services.remediation_generator import remediation_generator

API_DIR = Path(__file__).resolve().parents[1]


def _fake_response(model_used: str) -> LLMAnalysisResponse:
    return LLMAnalysisResponse(
        insights=[
            LLMInsight(
                analysis_type=LLMAnalysisType.BEHAVIORAL_PATTERN,
                threat_category=LLMThreatCategory.CODE_INJECTION,
                confidence=0.7,
                confidence_level=LLMConfidence.HIGH,
                title="step",
                description='{"steps": []}',
                reasoning="r",
            )
        ],
        analysis_id="a1",
        model_used=model_used,
    )


class TestNoRetiredModelIds:
    @pytest.mark.parametrize(
        "relpath",
        [
            "services/remediation_generator.py",
            "services/attack_chain_tracer.py",
        ],
    )
    def test_no_retired_ids(self, relpath):
        source = (API_DIR / relpath).read_text()
        assert "claude-3" not in source
        assert "gpt-4" not in source and "gpt-3" not in source


class TestRemediationModel:
    @pytest.mark.asyncio
    async def test_call_llm_service_threads_model(self):
        captured: list[LLMAnalysisRequest] = []

        async def fake_analyze(request: LLMAnalysisRequest) -> LLMAnalysisResponse:
            captured.append(request)
            return _fake_response(request.model or "unset")

        with patch.object(llm_service, "analyze_threat", fake_analyze):
            await remediation_generator._call_llm_service(
                "fix this", llm_config.model
            )

        assert len(captured) == 1
        assert captured[0].model == llm_config.model
        # enum member must actually exist (VULNERABILITY_ANALYSIS does not)
        assert captured[0].analysis_types[0] in LLMAnalysisType


class TestAttackChainModel:
    @pytest.mark.asyncio
    async def test_trace_uses_deep_model(self):
        finding = Finding(
            phase=ScanPhase.CODE_PATTERNS,
            rule="code-eval",
            severity=Severity.HIGH,
            file="x.py",
            line=1,
            snippet="eval(x)",
        )

        captured: list[LLMAnalysisRequest] = []

        async def fake_analyze(request: LLMAnalysisRequest) -> LLMAnalysisResponse:
            captured.append(request)
            return _fake_response(request.model or "unset")

        with patch.object(
            credit_service, "has_credits", new_callable=AsyncMock
        ) as has_credits, patch.object(
            credit_service, "deduct_credits", new_callable=AsyncMock
        ) as deduct, patch.object(
            llm_service, "analyze_threat", fake_analyze
        ):
            has_credits.return_value = True
            deduct.return_value = 100
            await attack_chain_tracer.trace_attack_chain(
                finding=finding, scan_id="s1", user_id="u1"
            )

        # deducted against the deep model, not a retired ID
        assert deduct.await_args.kwargs["model_used"] == llm_config.deep_model
        # the LLM request itself carries the deep model and the custom prompt
        assert len(captured) == 1
        assert captured[0].model == llm_config.deep_model
        assert captured[0].custom_prompt


class TestCustomPrompt:
    @pytest.mark.asyncio
    async def test_build_analysis_prompt_honours_custom_prompt(self):
        request = LLMAnalysisRequest(
            file_contents={"a.py": "x"}, custom_prompt="USE EXACTLY THIS"
        )
        prompt = await llm_service._build_analysis_prompt(request)
        assert prompt == "USE EXACTLY THIS"

    @pytest.mark.asyncio
    async def test_perform_analysis_reports_request_model(self):
        request = LLMAnalysisRequest(
            file_contents={"a.py": "x"},
            model=llm_config.deep_model,
            max_tokens=500,
        )
        with patch.object(
            llm_service, "call_llm_api", new_callable=AsyncMock
        ) as mock_call:
            mock_call.return_value = "no threats found"
            response = await llm_service._perform_analysis(request, "an-1")

        assert response.model_used == llm_config.deep_model
