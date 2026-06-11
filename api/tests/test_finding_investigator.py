"""US-108: finding_investigator modernized — config-driven models, no retired IDs."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from api.llm_config import llm_config
from api.llm_models import LLMAnalysisRequest, LLMAnalysisResponse
from api.services.finding_investigator import SCAN_COSTS, finding_investigator
from api.services.llm_service import llm_service

API_DIR = Path(__file__).resolve().parents[1]


class TestDepthModelMapping:
    def test_quick_uses_fast_model(self):
        model, cost = finding_investigator._get_model_and_cost("quick")
        assert model == llm_config.fast_model
        assert cost == SCAN_COSTS["quick_investigation"]

    def test_thorough_uses_standard_model(self):
        model, cost = finding_investigator._get_model_and_cost("thorough")
        assert model == llm_config.model
        assert cost == SCAN_COSTS["thorough_investigation"]

    def test_exhaustive_uses_deep_model(self):
        model, cost = finding_investigator._get_model_and_cost("exhaustive")
        assert model == llm_config.deep_model
        assert cost == SCAN_COSTS["exhaustive_investigation"]


class TestNoRetiredModelIds:
    @pytest.mark.parametrize(
        "relpath",
        [
            "services/finding_investigator.py",
            "services/explanations.py",
            "routers/interactive.py",
        ],
    )
    def test_no_retired_ids(self, relpath):
        source = (API_DIR / relpath).read_text()
        assert "claude-3" not in source
        assert "gpt-4" not in source and "gpt-3" not in source


class TestModelPassthrough:
    @pytest.mark.asyncio
    async def test_investigation_call_does_not_mutate_global_config(self):
        """The model override must travel with the request, not via config mutation."""
        captured: list[LLMAnalysisRequest] = []
        original_model = llm_config.model

        async def fake_analyze(request: LLMAnalysisRequest) -> LLMAnalysisResponse:
            captured.append(request)
            # If the investigator still mutates global config, this assertion
            # fires while the mutation is live.
            assert llm_config.model == original_model
            from api.llm_models import (
                LLMAnalysisType,
                LLMConfidence,
                LLMInsight,
                LLMThreatCategory,
            )

            return LLMAnalysisResponse(
                insights=[
                    LLMInsight(
                        analysis_type=LLMAnalysisType.BEHAVIORAL_PATTERN,
                        threat_category=LLMThreatCategory.CODE_INJECTION,
                        confidence=0.5,
                        confidence_level=LLMConfidence.MEDIUM,
                        title="test",
                        description="VERDICT: FALSE_POSITIVE",
                        reasoning="test reasoning",
                    )
                ],
                analysis_id="a1",
                model_used=request.model or "unset",
            )

        with patch.object(llm_service, "analyze_threat", fake_analyze):
            result = await finding_investigator._call_llm_for_investigation(
                "test prompt", llm_config.deep_model
            )

        assert result
        assert llm_config.model == original_model
        assert len(captured) == 1
        assert captured[0].model == llm_config.deep_model

    @pytest.mark.asyncio
    async def test_perform_analysis_threads_request_model(self):
        """llm_service._perform_analysis must pass request.model to call_llm_api."""
        request = LLMAnalysisRequest(
            file_contents={"a.py": "print(1)"},
            model=llm_config.deep_model,
            max_tokens=1000,
        )

        with patch.object(
            llm_service, "call_llm_api", new_callable=AsyncMock
        ) as mock_call:
            mock_call.return_value = "no threats found"
            await llm_service._perform_analysis(request, "analysis-1")

        mock_call.assert_awaited_once()
        assert mock_call.await_args.kwargs.get("model") == llm_config.deep_model

    def test_request_model_defaults_to_none(self):
        request = LLMAnalysisRequest(file_contents={"a.py": ""})
        assert request.model is None
