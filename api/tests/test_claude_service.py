"""Sigil API — claude_service + LLMService.call_llm_api regression (US-002 / F-003 / F1.7).

ADR-0003 accepted Branch A: claude_service is a thin wrapper that delegates to
LLMService.call_llm_api with the model threaded through as a parameter
(no global llm_config.model mutation — that pattern would race under
concurrent coroutines). These tests pin the contract:

1. LLMService.call_llm_api is the public name (rename from _call_llm_api).
2. When model is None, the HTTP payload uses llm_config.model (default).
3. When model is provided, the HTTP payload uses the override.
4. claude_service.analyze_with_claude threads model through to call_llm_api.
5. Two concurrent claude_service calls with different model overrides each
   see their own model parameter — pins the wrapper's parameter-threading
   contract end-to-end. Note: the no-global-mutation property is enforced
   by construction in call_llm_api (local read of llm_config.model, never
   a write) and by ADR-0003 review, not directly by this test.

These tests use the in-memory ASGI test client only via the import side-effect;
the actual HTTP layer is mocked at the aiohttp.ClientSession.post boundary so
no network traffic and no provider keys are required.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest


class _MockResponse:
    """Stand-in for aiohttp ClientResponse — minimum surface used by call_llm_api."""

    def __init__(self, payload_json: dict[str, Any], status_code: int = 200) -> None:
        self.status = status_code
        self._payload = payload_json

    async def text(self) -> str:
        return "ok"

    async def json(self) -> dict[str, Any]:
        return self._payload


class _MockPostCM:
    """Async context manager wrapping a single mocked POST call."""

    def __init__(self, captured: dict[str, Any], response: _MockResponse) -> None:
        self._captured = captured
        self._response = response

    async def __aenter__(self) -> _MockResponse:
        return self._response

    async def __aexit__(self, *args: Any) -> None:
        return None


class _MockSession:
    """Stand-in for aiohttp.ClientSession — captures the json kwarg of post()."""

    def __init__(self, response_payload: dict[str, Any]) -> None:
        self.captured: dict[str, Any] = {}
        self._response_payload = response_payload

    def post(self, url: str, headers: dict[str, str] | None = None, json: dict[str, Any] | None = None):  # noqa: A002
        self.captured["url"] = url
        self.captured["headers"] = headers
        self.captured["json"] = json
        return _MockPostCM(self.captured, _MockResponse(self._response_payload))


def _provider_response_for_text(provider: str, text: str) -> dict[str, Any]:
    """Build the minimal JSON the call_llm_api parser expects, per provider."""
    if provider in ("openai", "azure"):
        return {"choices": [{"message": {"content": text}}]}
    # anthropic
    return {"content": [{"text": text}]}


# ---------------------------------------------------------------------------
# LLMService.call_llm_api (rename + optional model parameter)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_call_llm_api_uses_default_model_when_none() -> None:
    """When model=None, the HTTP payload uses llm_config.model (default)."""
    from api.services.llm_service import LLMService
    from api.llm_config import llm_config

    service = LLMService()
    expected_model = llm_config.model
    mock_session = _MockSession(
        _provider_response_for_text(llm_config.provider, "default-resp")
    )
    service._session = mock_session  # type: ignore[assignment]

    result = await service.call_llm_api("hello", 100)

    assert result == "default-resp"
    assert mock_session.captured["json"]["model"] == expected_model, (
        f"expected payload model = llm_config.model ({expected_model!r}), "
        f"got {mock_session.captured['json'].get('model')!r}"
    )


@pytest.mark.asyncio
async def test_call_llm_api_uses_override_model_when_provided() -> None:
    """When model is passed, the HTTP payload uses that override.

    Also asserts llm_config.model is unchanged after the call returns. NOTE:
    this post-call assertion alone does NOT prove the absence of an
    llm_config.model save/set/restore pattern — such a pattern would also
    pass this test. Concurrency safety is enforced by construction
    (call_llm_api uses `effective_model = model or llm_config.model` as a
    local read, never `llm_config.model = ...` as a write) and validated
    end-to-end by test_concurrent_claude_calls_do_not_share_model_state.
    """
    from api.services.llm_service import LLMService
    from api.llm_config import llm_config

    service = LLMService()
    pre_call_global_model = llm_config.model
    override = "claude-3-opus-test-fixture"
    mock_session = _MockSession(
        _provider_response_for_text(llm_config.provider, "override-resp")
    )
    service._session = mock_session  # type: ignore[assignment]

    result = await service.call_llm_api("hello", 100, model=override)

    assert result == "override-resp"
    assert mock_session.captured["json"]["model"] == override, (
        f"expected payload model = override ({override!r}), "
        f"got {mock_session.captured['json'].get('model')!r}"
    )
    assert llm_config.model == pre_call_global_model, (
        "llm_config.model must equal pre-call value after call returns. "
        "(Note: full no-mutation contract is enforced by construction and "
        "by ADR-0003 review, not by this single-coroutine assertion.)"
    )


# ---------------------------------------------------------------------------
# claude_service wrapper
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_claude_service_threads_model_through() -> None:
    """claude_service.analyze_with_claude must forward model to call_llm_api."""
    from api.services.claude_service import claude_service
    from api.services import claude_service as cs_module

    fake = AsyncMock(return_value="threaded-resp")
    with patch.object(cs_module.llm_service, "call_llm_api", fake):
        result = await claude_service.analyze_with_claude(
            "p", model="m-via-wrapper", max_tokens=123
        )

    assert result == "threaded-resp"
    fake.assert_awaited_once()
    args, kwargs = fake.call_args
    # Tolerate either positional or kw threading; verify all three pieces are there.
    bound = {"prompt": None, "max_tokens": None, "model": None}
    if args:
        if len(args) >= 1:
            bound["prompt"] = args[0]
        if len(args) >= 2:
            bound["max_tokens"] = args[1]
        if len(args) >= 3:
            bound["model"] = args[2]
    bound.update({k: v for k, v in kwargs.items() if k in bound})
    assert bound["prompt"] == "p"
    assert bound["max_tokens"] == 123
    assert bound["model"] == "m-via-wrapper"


@pytest.mark.asyncio
async def test_concurrent_claude_calls_do_not_share_model_state() -> None:
    """Two concurrent analyze_with_claude calls with different model overrides
    must each observe their own model parameter end-to-end through the wrapper.

    SCOPE — what this test pins:
      The wrapper's parameter-threading contract: each concurrent caller sees
      its own `model` argument arriving at call_llm_api, with a deliberate
      `await asyncio.sleep(0.01)` interleave between capture and return.

    SCOPE — what this test does NOT pin:
      It does NOT directly catch a save/set/await/restore mutation of
      `llm_config.model`, because the fake reads `model` from the parameter
      it was called with, not from `llm_config.model`. A naive
      save/set/restore implementation could still pass this test by setting
      `llm_config.model` before forwarding the parameter. The
      no-global-mutation property is enforced by construction in
      call_llm_api (local read of llm_config.model, never a write) and by
      ADR-0003 review.
    """
    from api.services.claude_service import claude_service
    from api.services import claude_service as cs_module

    seen: list[tuple[str, str | None]] = []

    async def fake_call_llm_api(
        prompt: str, max_tokens: int, model: str | None = None
    ) -> str:
        # Yield to scheduler so the other coroutine can interleave between the
        # parameter capture and the return — exposes any global-mutation race.
        await asyncio.sleep(0.01)
        seen.append((prompt, model))
        return f"resp-for-{model}"

    with patch.object(cs_module.llm_service, "call_llm_api", fake_call_llm_api):
        results = await asyncio.gather(
            claude_service.analyze_with_claude("p-A", model="model-alpha", max_tokens=10),
            claude_service.analyze_with_claude("p-B", model="model-beta", max_tokens=10),
        )

    assert sorted(results) == ["resp-for-model-alpha", "resp-for-model-beta"]
    assert sorted(seen) == [("p-A", "model-alpha"), ("p-B", "model-beta")], (
        f"each concurrent call must see its own model; got {seen!r}"
    )
