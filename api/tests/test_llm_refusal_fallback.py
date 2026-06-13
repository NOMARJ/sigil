"""US-103: Fable 5 refusal handling + Opus 4.8 fallback in llm_service.

All Anthropic responses are mocked — no network. Cases:
1. pre-output refusal (empty content) on the deep model -> one retry on llm_config.model
2. mid-stream refusal (partial content present) -> partial discarded, fallback answer returned
3. fallback success -> fallback text returned, exactly 2 calls
4. refusal on the fallback model too -> LLMRefusalError, no tenacity re-retry storm
"""

import pytest

from api.llm_config import llm_config
from api.services.llm_service import LLMRefusalError, LLMService


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status = status

    async def json(self):
        return self._payload

    async def text(self):
        return str(self._payload)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    """Queues responses; records every payload posted."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.posted = []
        self.closed = False

    def post(self, url, headers=None, json=None):
        self.posted.append(json)
        return FakeResponse(self._responses.pop(0))

    async def close(self):
        self.closed = True


def refusal_payload(content=None, category="cyber"):
    return {
        "stop_reason": "refusal",
        "stop_details": {"category": category},
        "content": content or [],
    }


def ok_payload(text="fallback answer"):
    return {"stop_reason": "end_turn", "content": [{"type": "text", "text": text}]}


@pytest.fixture
def anthropic_env(monkeypatch):
    monkeypatch.setattr(llm_config, "provider", "anthropic")
    monkeypatch.setattr(llm_config, "api_key", "test-key")
    monkeypatch.setattr(llm_config, "api_base", None)
    monkeypatch.setattr(llm_config, "model", "claude-opus-4-8")
    monkeypatch.setattr(llm_config, "deep_model", "claude-fable-5")
    monkeypatch.setattr(llm_config, "fast_model", "claude-haiku-4-5")
    yield


def make_service(responses):
    service = LLMService()
    service._session = FakeSession(responses)
    return service


@pytest.mark.asyncio
async def test_pre_output_refusal_falls_back_to_opus(anthropic_env):
    service = make_service([refusal_payload(), ok_payload("opus says hi")])
    result = await service.call_llm_api("prompt", 100, model="claude-fable-5")

    assert result == "opus says hi"
    session = service._session
    assert len(session.posted) == 2
    assert session.posted[0]["model"] == "claude-fable-5"
    assert session.posted[1]["model"] == "claude-opus-4-8"


@pytest.mark.asyncio
async def test_mid_stream_refusal_discards_partial(anthropic_env):
    partial = [{"type": "text", "text": "PARTIAL-MUST-NOT-LEAK"}]
    service = make_service([refusal_payload(content=partial), ok_payload("clean")])
    result = await service.call_llm_api("prompt", 100, model="claude-fable-5")

    assert result == "clean"
    assert "PARTIAL" not in result


@pytest.mark.asyncio
async def test_refusal_on_fallback_raises_typed_error(anthropic_env):
    service = make_service([refusal_payload(), refusal_payload()])
    with pytest.raises(LLMRefusalError) as exc_info:
        await service.call_llm_api("prompt", 100, model="claude-fable-5")

    assert exc_info.value.category == "cyber"
    # refusals are terminal: no tenacity retry storm — exactly 2 HTTP calls
    assert len(service._session.posted) == 2


@pytest.mark.asyncio
async def test_refusal_on_non_deep_model_raises_immediately(anthropic_env):
    service = make_service([refusal_payload(category=None)])
    with pytest.raises(LLMRefusalError):
        await service.call_llm_api("prompt", 100, model="claude-opus-4-8")

    assert len(service._session.posted) == 1


@pytest.mark.asyncio
async def test_anthropic_payload_omits_sampling_and_thinking(anthropic_env):
    service = make_service([ok_payload()])
    await service.call_llm_api("prompt", 100, model="claude-fable-5")

    payload = service._session.posted[0]
    assert "temperature" not in payload
    assert "thinking" not in payload
    assert "top_p" not in payload
    assert payload["max_tokens"] == 100


@pytest.mark.asyncio
async def test_text_block_selected_when_thinking_blocks_precede(anthropic_env):
    """Fable 5 always thinks: content[0] is a thinking block, not text.

    Found live (2026-06-12): naive content[0]["text"] raised KeyError on every
    real Fable 5 response. The text block must be selected by type.
    """
    payload = {
        "stop_reason": "end_turn",
        "content": [
            {"type": "thinking", "thinking": "", "signature": "sig"},
            {"type": "text", "text": "the actual answer"},
        ],
    }
    service = make_service([payload])
    result = await service.call_llm_api("prompt", 100, model="claude-fable-5")
    assert result == "the actual answer"


@pytest.mark.asyncio
async def test_no_text_block_raises_not_keyerror(anthropic_env):
    payload = {
        "stop_reason": "end_turn",
        "content": [{"type": "thinking", "thinking": ""}],
    }
    service = make_service([payload, payload, payload])
    with pytest.raises(Exception) as exc_info:
        await service.call_llm_api("prompt", 100, model="claude-opus-4-8")
    assert "No text block" in str(exc_info.value)
