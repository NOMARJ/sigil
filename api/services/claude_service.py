"""Sigil API — claude_service thin wrapper.

ADR-0003 (accepted, Branch A): expose a string-in / string-out wrapper over
LLMService.call_llm_api so that bulk_analyzer.py and feedback_processor.py
can import `from api.services.claude_service import claude_service` (and
`ClaudeService`) without `interactive.router` failing at module load.

The wrapper is provider-agnostic — it delegates to LLMService, which routes
to whichever provider llm_config has selected (Anthropic by default,
OpenAI/Azure if configured). The "claude" name is preserved for source
compatibility with the two existing callers.

Concurrency: model overrides are threaded through as a parameter. NEVER
mutate llm_config.model — that pattern races under concurrent coroutines
(one call's "restore" can clobber another call's "set" mid-await).
"""

from __future__ import annotations

import logging

from api.services.llm_service import llm_service

logger = logging.getLogger(__name__)


class ClaudeService:
    """String-in / string-out wrapper over LLMService.call_llm_api."""

    async def analyze_with_claude(
        self,
        prompt: str,
        model: str | None = None,
        max_tokens: int = 2000,
    ) -> str:
        return await llm_service.call_llm_api(prompt, max_tokens, model=model)


claude_service = ClaudeService()
