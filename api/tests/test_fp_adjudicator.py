"""US-106: FP adjudication service — Fable 5, structured verdict, no free-text parsing."""

import json

import pytest

from api.llm_config import llm_config
from api.services.fp_adjudicator import (
    ADJUDICATION_SCHEMA,
    AdjudicationError,
    FPAdjudicator,
)
from api.services.llm_service import llm_service
from api.tests.test_llm_refusal_fallback import FakeSession, ok_payload

FINDING = {
    "rule": "CODE-001",
    "phase": "CodePatterns",
    "severity": "High",
    "file": "src/util.py",
    "line": 42,
    "snippet": "eval(user_input)",
    "provenance": "packs/core/v1/code_patterns.json",
}

VALID_VERDICT = {
    "classification": "benign_dual_use",
    "confidence": 0.82,
    "rationale": "eval here parses a trusted config literal; no taint path from network input.",
}


def make_adjudicator(monkeypatch, raw_response: str, captured: dict):
    adjudicator = FPAdjudicator()

    async def fake_call(prompt, max_tokens, model=None, output_config=None):
        captured.update(
            prompt=prompt,
            max_tokens=max_tokens,
            model=model,
            output_config=output_config,
        )
        return raw_response

    monkeypatch.setattr(llm_service, "call_llm_api", fake_call)
    return adjudicator


class TestAdjudicate:
    @pytest.mark.asyncio
    async def test_valid_verdict_round_trip(self, monkeypatch):
        captured = {}
        adjudicator = make_adjudicator(monkeypatch, json.dumps(VALID_VERDICT), captured)
        verdict = await adjudicator.adjudicate(FINDING, "def f():\n    eval(x)")

        assert verdict["classification"] == "benign_dual_use"
        assert verdict["confidence"] == 0.82
        assert verdict["rationale"]

    @pytest.mark.asyncio
    async def test_uses_deep_model_with_schema(self, monkeypatch):
        captured = {}
        adjudicator = make_adjudicator(monkeypatch, json.dumps(VALID_VERDICT), captured)
        await adjudicator.adjudicate(FINDING, "code")

        assert captured["model"] == llm_config.deep_model
        assert captured["output_config"] == {
            "format": {"type": "json_schema", "schema": ADJUDICATION_SCHEMA}
        }

    @pytest.mark.asyncio
    async def test_prompt_carries_finding_and_provenance(self, monkeypatch):
        captured = {}
        adjudicator = make_adjudicator(monkeypatch, json.dumps(VALID_VERDICT), captured)
        await adjudicator.adjudicate(FINDING, "code ctx")

        prompt = captured["prompt"]
        assert "CODE-001" in prompt
        assert "packs/core/v1/code_patterns.json" in prompt
        assert "src/util.py" in prompt
        assert "code ctx" in prompt

    @pytest.mark.asyncio
    async def test_code_context_is_bounded(self, monkeypatch):
        captured = {}
        adjudicator = make_adjudicator(monkeypatch, json.dumps(VALID_VERDICT), captured)
        await adjudicator.adjudicate(FINDING, "A" * 50_000)

        assert len(captured["prompt"]) < 20_000
        assert "[context truncated]" in captured["prompt"]

    @pytest.mark.asyncio
    async def test_invalid_classification_raises(self, monkeypatch):
        bad = dict(VALID_VERDICT, classification="totally_fine_bro")
        adjudicator = make_adjudicator(monkeypatch, json.dumps(bad), {})
        with pytest.raises(AdjudicationError):
            await adjudicator.adjudicate(FINDING, "code")

    @pytest.mark.asyncio
    async def test_unparseable_response_raises(self, monkeypatch):
        adjudicator = make_adjudicator(monkeypatch, "not json at all", {})
        with pytest.raises(AdjudicationError):
            await adjudicator.adjudicate(FINDING, "code")

    @pytest.mark.asyncio
    async def test_confidence_out_of_range_raises(self, monkeypatch):
        bad = dict(VALID_VERDICT, confidence=1.7)
        adjudicator = make_adjudicator(monkeypatch, json.dumps(bad), {})
        with pytest.raises(AdjudicationError):
            await adjudicator.adjudicate(FINDING, "code")


class TestOutputConfigPassthrough:
    """The additive call_llm_api output_config param reaches the Anthropic payload."""

    @pytest.mark.asyncio
    async def test_payload_contains_output_config(self, monkeypatch):
        monkeypatch.setattr(llm_config, "provider", "anthropic")
        monkeypatch.setattr(llm_config, "api_key", "k")
        monkeypatch.setattr(llm_config, "api_base", None)

        from api.services.llm_service import LLMService

        service = LLMService()
        service._session = FakeSession([ok_payload('{"x": 1}')])
        schema_config = {
            "format": {"type": "json_schema", "schema": ADJUDICATION_SCHEMA}
        }
        await service.call_llm_api(
            "p", 100, model="claude-fable-5", output_config=schema_config
        )

        payload = service._session.posted[0]
        assert payload["output_config"] == schema_config

    @pytest.mark.asyncio
    async def test_payload_omits_output_config_when_absent(self, monkeypatch):
        monkeypatch.setattr(llm_config, "provider", "anthropic")
        monkeypatch.setattr(llm_config, "api_key", "k")
        monkeypatch.setattr(llm_config, "api_base", None)

        from api.services.llm_service import LLMService

        service = LLMService()
        service._session = FakeSession([ok_payload()])
        await service.call_llm_api("p", 100, model="claude-fable-5")

        assert "output_config" not in service._session.posted[0]
