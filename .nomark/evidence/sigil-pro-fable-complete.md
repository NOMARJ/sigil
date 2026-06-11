# Feature Verification: F-009 — Sigil Pro tier + Fable integration

**PRD:** `tasks/prd-sigil-pro-fable.json`
**Date:** 2026-06-11
**Branch:** `feature/sigil-pro-fable`
**Stories:** 11/12 DONE (1 owner-gated: US-112)
**Result:** PARTIAL — US-110 completed 2026-06-12 after owner restored Anthropic billing; only US-112 (ops verification) remains

## Acceptance Criteria

| # | Story | Criterion | Evidence | Status |
|---|-------|-----------|----------|--------|
| 1 | US-101 | Anthropic-first defaults (opus-4-8 / fable-5 deep / haiku-4-5 fast), env-overridable | `test_llm_config.py` 15 passed; grep gpt-4 empty | PASS |
| 2 | US-102 | MODELS registry = exactly 3 current IDs, $1/$5 · $5/$25 · $10/$50; downgrade→haiku | `test_model_router.py` 12 passed | PASS |
| 3 | US-103 | stop_reason checked before content; Fable refusal → one Opus 4.8 retry; refusals terminal (no tenacity retry); no thinking/temperature on payloads | `test_llm_refusal_fallback.py` 5 passed | PASS |
| 4 | US-104 | check_llm_allowance + record_llm_usage on existing tables (no schema change); structured denial | `test_llm_metering.py` 11 passed | PASS |
| 5 | US-105 | require_llm_access: Pro+ always pass, FREE metered, 402 structured (owner-approved) | tier_gating TestRequireLlmAccess 5 passed (extended flag) | PASS |
| 6 | US-106 | FPAdjudicator: deep model + json_schema output_config, enum-locked verdict, bounded context, provenance in prompt | `test_fp_adjudicator.py` 9 passed | PASS |
| 7 | US-107 | Adjudicate endpoint: gated, persists to findings_json (no schema change), idempotent, refusal→422 unmetered | `test_adjudicate_endpoint.py` 7 passed | PASS |
| 8 | US-108 | investigator/explanations config-driven, no retired IDs, routes gated | `-k "investigator or explanations"` 9 passed; grep empty | PASS |
| 9 | US-109 | remediation=standard model, attack-chain=deep model, no retired IDs | `-k "remediation or attack_chain"` 8 passed/1 skipped | PASS |
| 10 | US-110 | Honest FP-adjudication eval, real data, both directions, ship/no-ship | 168 real Fable 5 verdicts: FP@High 70%→30%, recall retention 24/25 by verdict; SHIP — `evidence/F-009/fp-adjudication-eval.md` | PASS |
| 11 | US-111 | sigil explain: API-only (D6), 402→upgrade message, transcript | `cargo test explain` 3+4 passed; `evidence/F-009/US-111-cli-explain.md` | PASS |
| 12 | US-112 | Ops verification (env snapshot, retention, live smoke) | — | **PENDING** (owner/operator-gated) |
| 13 | Feature | No retired model IDs anywhere in api non-test code | guard test `test_no_retired_ids_anywhere_in_api` passed; repo grep clean | PASS |

## Test Results (final integration run, 2026-06-11)

```
$ python3 -m pytest api/tests -q
299 passed, 346 skipped, 6 warnings          # baseline at feature start: 276
$ cargo test --manifest-path cli/Cargo.toml
132 passed (unit) + 4 passed (integration)   # baseline: 123
```

Per-story AC commands all re-run fresh in the final pass — outputs in this file's
Acceptance Criteria table and per-story evidence (`.nomark/evidence/US-101..109.md`,
`evidence/F-009/US-111-cli-explain.md`).

## Latent bugs fixed en route (all verified by new tests)

The claude-3-era LLM feature layer was substantially non-functional; modernization
surfaced and fixed six crashes that had never been exercised by tests:

1. `SCAN_COSTS["investigate_finding"]` — key never existed (investigator, KeyError)
2. `LLMAnalysisType.VULNERABILITY_ANALYSIS` — enum member never existed (investigator, remediation, fp_analyzer)
3. `llm_service.llm_config` hasattr-guarded mutation — attribute never existed, so depth model never applied (investigator)
4. `analysis_request.custom_prompt =` post-construction — undefined Pydantic field, ValueError; every attack-chain trace returned the fallback chain (tracer)
5. `analysis_request.model_override =` — same class of crash (context_expander)
6. `http_exception_handler` stringified dict details — flattened the owner-approved structured 402 contract at the app boundary (main.py)

## Remaining Stories

- **US-110**: RESOLVED 2026-06-12 — owner restored billing; eval ran with 168 real
  Fable 5 verdicts (commit `3f768ce`). First live call also exposed and fixed the
  thinking-block extraction bug (`e5b340c`): Fable 5 responses lead with a thinking
  block, so `content[0]["text"]` raised KeyError on every real deep-model response.
- **US-112** (ops verification): requires live Azure + Anthropic org access (owner/operator).

## Security

No client-side LLM or key handling in the CLI (D6). No schema changes. No secrets in
evidence files. Auth change (gates.py) owner-approved per CHARTER II.5 before edit.
