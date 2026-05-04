---
id: ADR-0003
title: "claude_service is a thin wrapper over LLMService's HTTP primitive — not a refactor of bulk_analyzer, not a route deletion"
status: accepted
date: 2026-05-04
venture: sigil
tags: [llm, claude, refactor, story-002, f-003, f1.7]
outcome: pending
---

## Context

`api/services/claude_service.py` does not exist on `main`. Two service files import it:

- `api/services/bulk_analyzer.py:17` — `from ..services.claude_service import claude_service` (module-level import); `bulk_analyzer.py:147` calls `await claude_service.analyze_with_claude(prompt=prompt, model=model, max_tokens=2000)`.
- `api/services/feedback_processor.py:22, 33` — `from api.services.claude_service import ClaudeService` and `self.claude_service = ClaudeService()` (class instantiation).

`api/routers/interactive.py:55-57` does a module-level import of `bulk_analyzer`. Python's module loader fails at the first missing import, so a `ModuleNotFoundError` on `claude_service` cascades up: `interactive.router` fails to load, `api/main.py` cannot register it, and **33 Pro-gated routes return 404 in production**. These are the headline features the pricing page advertises (AI Investigation Assistant, False Positive Verification, Interactive Security Chat, Attack chain tracing, Compliance mapping). Paid Pro customers see 404s when they reach for what they paid for.

A separate service does exist: `api/services/llm_service.py` exposes a `LLMService` class whose primary surface is `analyze_threat(LLMAnalysisRequest) -> LLMAnalysisResponse` — a structured pipeline that takes `file_contents` (dict), `static_findings`, `analysis_types`, etc., and returns parsed insights. Its lowest layer, `_call_llm_api(prompt: str, max_tokens: int) -> str`, makes the actual provider HTTP request (Anthropic / OpenAI / Azure) using `llm_config` for the endpoint, model, and headers, with `tenacity`-based retry and a `RateLimiter`.

The signature `bulk_analyzer` and `feedback_processor` expect — `analyze_with_claude(prompt: str, model: str, max_tokens: int) -> str` — does not match `analyze_threat`. It does match `_call_llm_api` plus a `model` override. That gap is the core question this ADR resolves.

Three branches were captured in `evidence/F-003/F1.7-BLOCKED.md`. This ADR enumerates them and recommends one.

## Decision

**Branch A — implement `claude_service` as a thin wrapper over `LLMService`'s HTTP primitive. 14 days reversibility window before any migration is committed to.**

Specifically:

1. New file `api/services/claude_service.py` exporting:
   - A `ClaudeService` class with method `async def analyze_with_claude(self, prompt: str, model: str | None = None, max_tokens: int = 2000) -> str`.
   - A module-level singleton `claude_service = ClaudeService()`.
2. The `analyze_with_claude` method delegates to `LLMService.call_llm_api(prompt, max_tokens, model=model)` — reusing the existing rate limiter, retry policy, provider abstraction, and `llm_config` (single source of truth for API keys, endpoints, and the default model). The `model` argument flows through to the payload dict built inside `call_llm_api`. **No global mutation of `llm_config.model`** — that pattern would race under concurrent coroutines (two callers can interleave `save → set → await → restore` and corrupt the global), so it is explicitly rejected.
3. As a precondition for (2), US-002 renames `LLMService._call_llm_api` → `LLMService.call_llm_api` (one-word public rename) and adds an optional `model: str | None = None` parameter. When set, the local payload dict uses `model` instead of `llm_config.model`; when `None`, behaviour is identical to today. This is the smallest possible change to `LLMService` to support a per-call model override safely. `_call_llm_api` is `LLMService`'s only existing call site (`api/services/llm_service.py:97`), so the rename is local-scope. `claude_service` is the first external caller and earns the public name.
4. No changes to `bulk_analyzer.py`. No changes to `feedback_processor.py`. No changes to `interactive.py` route surface.
5. `api/main.py` adds `app.include_router(interactive.router)` (the line that has been blocked since F1.7).
6. `api/tests/test_interactive_router_registered.py` removes both `@pytest.mark.skip` decorators; both regression tests must pass.

### Why not Branch B (refactor bulk_analyzer to use LLMService directly)

`bulk_analyzer` builds raw prompts via `BulkAnalysisPromptBuilder.build_bulk_analysis_prompt(...)` and treats the LLM as a string-in / string-out primitive. `LLMService.analyze_threat` takes a structured `LLMAnalysisRequest` (`file_contents` dict, `static_findings`, `analysis_types`) and returns a structured `LLMAnalysisResponse` with parsed insights. To use it directly, the bulk path would need to either pack synthesised file_contents to satisfy the request shape (a hack) or expose `_call_llm_api` publicly (which is approximately what Branch A does anyway, just less explicitly). Branch B has higher churn — it touches `bulk_analyzer.py` and `feedback_processor.py` simultaneously — without producing a meaningfully cleaner architecture. Worth doing later as a deliberate refactor, not now under closeout pressure.

### Why not Branch C (drop bulk-analyze endpoints from interactive.py)

`bulk_analyzer` is reached by 2 of 33 routes (`POST /v1/interactive/bulk/group`, `POST /v1/interactive/bulk/analyze`). Dropping these would require:

1. Removing `from api.services.bulk_analyzer import (bulk_analyzer,)` and the two `@router.post("/bulk/...")` blocks in `interactive.py` (~140 LOC removed).
2. Still providing `claude_service` for `feedback_processor.py` — otherwise the `POST /v1/interactive/feedback` route returns 500 at runtime on the local import inside `submit_feedback` (line 1256: `from ..services.feedback_processor import FeedbackProcessor`). This handler is a Pro-gated route. Branch C "drop bulk routes" therefore does not eliminate the need for `claude_service` — it only narrows the breakage to a different paid endpoint.
3. Verifying no pricing page or marketing copy references "bulk analysis" (as of 2026-05-04, the public-facing Pro features list does not mention bulk — but commercial copy is not the only reason a feature ships; the routes exist because earlier work intended them).

Branch C is reasonable IF Branch A is found infeasible. It is not the smallest viable path here.

### Why Branch A is the right default for this PRD

- **Smallest reversible change.** One new file, ~80 LOC. No existing files modified except `api/main.py` (one line) and the test skip decorators. Git revert is trivial.
- **No commitment to long-term architecture.** If we later decide bulk_analyzer should use `LLMService` directly (Branch B) or the bulk routes should be dropped (Branch C), the wrapper is a one-file deletion away.
- **Preserves paid functionality.** All 33 Pro routes remain reachable. No paying customer regression.
- **Single source of truth for provider config.** Reuses `llm_config` and `_call_llm_api`'s rate limiter / retry. We do not introduce a parallel HTTP client, parallel auth path, or parallel provider abstraction.
- **Honest about what this is.** A shim, named as a shim, scoped as a shim. Not pretending to be the long-term LLM service architecture.

## Consequences

**Positive**

- F1.7 unblocks. STORY-104 closes (interactive router mounts). 33 Pro routes return 401/422 instead of 404 — the gating contract becomes provable end-to-end.
- US-005 (test-mode round-trip canary `POST /v1/interactive/investigate`) gains a real route to call.
- ADR-0003 is small enough to review in 10 minutes.

**Negative / trade-offs**

- One more layer between the bulk path and the actual provider call. Adds a tiny call-stack frame; no measurable latency cost.
- Two service indirections (`claude_service` and `llm_service`) that both ultimately call the same Anthropic/OpenAI endpoint. This is conceptual debt — paid for by the speed of unblocking. Branch B is the long-term fix when someone has the budget for it.
- US-002 renames `LLMService._call_llm_api` → `call_llm_api` (drops the private-by-convention underscore). The wrapper depends on the public name; if a future refactor removes or signature-changes `call_llm_api`, the wrapper breaks. The wrapper test should pin the contract.

**Operator follow-up (CHARTER II — flagged, not auto-actioned)**

- After implementation, smoke-test in production: `curl -sS -o /dev/null -w '%{http_code}' -X POST https://api.sigilsec.ai/v1/interactive/investigate -H 'Content-Type: application/json' -d '{}'` should return 401 (auth) or 422 (validation), never 404.
- Monitor for new errors in the bulk path and feedback path after deploy — a behaviour difference between the missing-module ImportError (deterministic 500) and the new wrapper (real upstream calls) is the first place a regression would surface.

## Reversibility

Reverting Branch A requires:

1. Deleting `api/services/claude_service.py`.
2. Reverting the one-line `app.include_router(interactive.router)` add in `api/main.py`.
3. Restoring the two `@pytest.mark.skip` decorators in `api/tests/test_interactive_router_registered.py`.
4. Renaming `LLMService.call_llm_api` back to `_call_llm_api` and removing the optional `model` parameter (single internal caller at `_perform_analysis` updated in the same diff).

The rename in step 4 is the only "load-bearing" piece of the revert — all other changes are localised to the new file and a single registration line. The optional `model` parameter on `call_llm_api` is backwards-compatible by construction (defaults to `None`, which preserves prior behaviour), so step 4 is a stylistic reversal rather than a functional one. Net: this is still the cheapest reversibility profile of the three branches by a wide margin.

If the team later decides Branch A was wrong and wants Branch B (refactor) or Branch C (drop), the migration is straightforward because the wrapper is small, isolated, and named honestly. Branch A does not lock anyone in.

## Implementation Sketch (for US-002 review)

Two files, one rename. **No global state mutation** — the buggy "save / set / await / restore" pattern on `llm_config.model` would race under concurrent coroutines, so model override is threaded as a parameter instead.

```python
# api/services/llm_service.py — minimal change
# 1. Rename _call_llm_api → call_llm_api (drop the convention-private underscore).
# 2. Add an optional model parameter. When set, the payload uses it; when None,
#    behaviour is identical to today (falls back to llm_config.model).

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10), reraise=True)
async def call_llm_api(self, prompt: str, max_tokens: int, model: str | None = None) -> str:
    """Make HTTP request to LLM API with retry logic.

    Args:
        prompt: user-content string for the model.
        max_tokens: completion token cap.
        model: optional per-call model override (e.g. "claude-3-haiku-20240307");
            None falls back to llm_config.model.
    """
    if not self._session:
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=llm_config.timeout_seconds)
        )

    headers = llm_config.get_headers()
    url = llm_config.get_endpoint_url()
    effective_model = model or llm_config.model

    if llm_config.provider in ("openai", "azure"):
        payload = {
            "model": effective_model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": llm_config.temperature,
            "response_format": {"type": "json_object"},
        }
    elif llm_config.provider == "anthropic":
        payload = {
            "model": effective_model,
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
        if llm_config.provider in ("openai", "azure"):
            return result["choices"][0]["message"]["content"]
        elif llm_config.provider == "anthropic":
            return result["content"][0]["text"]
        else:
            raise ValueError(f"Unsupported provider: {llm_config.provider}")
```

Update the one existing internal caller — `_perform_analysis` at `api/services/llm_service.py:97` — to call the new public name (`await self.call_llm_api(prompt, request.max_tokens)`). No behaviour change.

```python
# api/services/claude_service.py — new file
from __future__ import annotations

import logging

from api.services.llm_service import llm_service

logger = logging.getLogger(__name__)


class ClaudeService:
    """Thin wrapper exposing prompt-string -> response-string against the
    configured LLM provider (Anthropic by default, OpenAI/Azure if configured
    via llm_config). Reuses LLMService's HTTP primitive, rate limiter, and
    retry policy.

    Naming kept as `claude_service` for compatibility with the two existing
    callers (api/services/bulk_analyzer.py:17, api/services/feedback_processor.py:22)
    that expect this module path. The wrapper is provider-agnostic in
    practice; the underlying call_llm_api delegates to whichever provider
    llm_config has selected.
    """

    async def analyze_with_claude(
        self,
        prompt: str,
        model: str | None = None,
        max_tokens: int = 2000,
    ) -> str:
        # Pure delegation. No global state mutation — model is threaded
        # through as a parameter so concurrent calls cannot interleave.
        return await llm_service.call_llm_api(prompt, max_tokens, model=model)


claude_service = ClaudeService()
```

Test surface (must exist before US-002 closes):

1. `test_call_llm_api_uses_default_model_when_none` — mock the HTTP layer, assert payload contains `llm_config.model` when `model=None` (regression guard for the rename).
2. `test_call_llm_api_uses_override_model_when_provided` — mock the HTTP layer, assert payload contains the override when `model="claude-3-opus"` is passed.
3. `test_claude_service_threads_model_through` — mock `LLMService.call_llm_api`, assert `claude_service.analyze_with_claude("x", model="m", max_tokens=100)` calls it once with `("x", 100, model="m")`.
4. `test_concurrent_claude_calls_do_not_share_model_state` — kick off two concurrent `analyze_with_claude` calls with different `model=` overrides; assert each call's payload sees its own model. Pins the no-global-mutation contract.
5. The two existing (currently skipped) tests in `test_interactive_router_registered.py` flip to PASS once the skip is removed.

## Evidence

- `evidence/F-003/F1.7-BLOCKED.md` — original triage of the three branches.
- `api/services/bulk_analyzer.py:17, 147` — call site fixing the `analyze_with_claude(prompt, model, max_tokens) -> str` signature.
- `api/services/feedback_processor.py:22, 33` — second call site (`ClaudeService` class + instance both required).
- `api/services/llm_service.py:141-184` — `_call_llm_api` is the HTTP primitive being wrapped; provider-agnostic via `llm_config.provider`.
- `api/routers/interactive.py:55-57` — module-level import of `bulk_analyzer` is the load-bearing line that breaks the whole router today.
- `api/tests/test_interactive_router_registered.py` — two regression tests already in place, currently skipped, ready to flip.
