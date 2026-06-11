"""FP Adjudication Service (F-009 US-106).

LLM-judges dual-use findings — eval/exec/pickle/child_process patterns that
popular legitimate packages genuinely contain. This is the discriminator the
F-008 eval identified: pattern scanning alone cannot tell these from malice
(residual 70% FP@High). Verdicts come back as API-enforced structured output
(json_schema) — no free-text parsing.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

from api.llm_config import llm_config
from api.services.llm_service import llm_service

logger = logging.getLogger(__name__)

CLASSIFICATIONS = ("benign_dual_use", "suspicious", "malicious")

MAX_CONTEXT_CHARS = 8_000

ADJUDICATION_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "classification": {"type": "string", "enum": list(CLASSIFICATIONS)},
        "confidence": {"type": "number"},
        "rationale": {"type": "string"},
    },
    "required": ["classification", "confidence", "rationale"],
    "additionalProperties": False,
}

_PROMPT_TEMPLATE = """You are a security analyst adjudicating a static-analysis finding \
from the Sigil scanner. Decide whether this specific occurrence is a benign dual-use \
pattern, suspicious, or malicious. Judge only this occurrence in its context — not the \
pattern class in general.

Finding:
- rule: {rule} (provenance: {provenance})
- phase: {phase}
- severity: {severity}
- location: {file}:{line}
- matched snippet: {snippet}

Surrounding code context:
{code_context}

Classify as one of: benign_dual_use (legitimate use of a dangerous-looking API), \
suspicious (cannot rule out malice; needs human review), malicious (clear malicious \
intent). Confidence is 0.0-1.0. The rationale must reference the actual code."""


class AdjudicationError(Exception):
    """The model's verdict was missing, unparseable, or out of contract."""


class FPAdjudicator:
    """Adjudicates individual findings via the deep model with structured output."""

    async def adjudicate(
        self, finding: Dict[str, Any], code_context: str
    ) -> Dict[str, Any]:
        """Return a validated verdict dict for one finding.

        Raises AdjudicationError on contract violations. LLMRefusalError from
        the underlying service (refused on deep model AND fallback) propagates
        to the caller — a refusal is not a verdict.
        """
        if len(code_context) > MAX_CONTEXT_CHARS:
            code_context = code_context[:MAX_CONTEXT_CHARS] + "\n[context truncated]"

        prompt = _PROMPT_TEMPLATE.format(
            rule=finding.get("rule", "unknown"),
            provenance=finding.get("provenance", "unknown"),
            phase=finding.get("phase", "unknown"),
            severity=finding.get("severity", "unknown"),
            file=finding.get("file", "unknown"),
            line=finding.get("line", "?"),
            snippet=finding.get("snippet", ""),
            code_context=code_context,
        )

        raw = await llm_service.call_llm_api(
            prompt,
            llm_config.max_tokens_per_scan,
            model=llm_config.deep_model,
            output_config={
                "format": {"type": "json_schema", "schema": ADJUDICATION_SCHEMA}
            },
        )

        verdict = self._validate(raw)
        # Rough ~4 chars/token estimates for metering; the raw HTTP path does
        # not surface the API usage object. Marked as estimates downstream.
        verdict["_usage"] = {
            "input_tokens_est": len(prompt) // 4,
            "output_tokens_est": len(raw) // 4,
        }
        return verdict

    def _validate(self, raw: str) -> Dict[str, Any]:
        try:
            verdict = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as e:
            raise AdjudicationError(f"Unparseable adjudication response: {e}")

        classification = verdict.get("classification")
        if classification not in CLASSIFICATIONS:
            raise AdjudicationError(
                f"Classification '{classification}' outside contract {CLASSIFICATIONS}"
            )

        confidence = verdict.get("confidence")
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            raise AdjudicationError(f"Confidence {confidence!r} outside [0, 1]")

        if not verdict.get("rationale"):
            raise AdjudicationError("Verdict missing rationale")

        return {
            "classification": classification,
            "confidence": float(confidence),
            "rationale": verdict["rationale"],
        }


# Global service instance
fp_adjudicator = FPAdjudicator()
