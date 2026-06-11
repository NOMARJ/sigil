# Autopilot Plan: F-009 Sigil Pro Tier + Fable Integration

> **PRD:** `tasks/prd-sigil-pro-fable.json` (status: approved, owner 2026-06-11)
> **Mode:** dry-run (2026-06-11) — plan only, no build
> **Decomposition source:** `/plan_feature sigil-pro-fable` (same session, owner-approved scope); stories already seeded in progress.md. Phase 1 validated the existing decomposition rather than re-decomposing.

## Precondition status (at dry-run)

| # | Gate | Status |
|---|------|--------|
| 1 | PRD exists/readable | PASS |
| 2 | PRD status approved | PASS |
| 3 | SOLUTION.md Feature entry (F-009) | PASS |
| 4 | tasks/lessons.md read | PASS |
| 5 | .nomark/resources.json exists | PASS |
| 6 | Git working tree clean | **FAIL — hard blocker for the build run** |

Tree dirt at dry-run: `progress.md` (F-009 stories + F-010 live status), `sigil-skill/*` edits, `.nomark/*` telemetry, untracked `tasks/prd-sigil-pro-fable.json`. The F-009 PRD and progress.md story block must be committed before `/autopilot --skip-plan`.

## Stories: 12 (0 trivial / 7 moderate / 5 complex)

Estimated exchanges: ~90 (moderate≈6, complex≈10) → expect 1–2 relay handoffs (compact_max_remaining_stories=2).

## Dependency DAG / execution waves

```
Wave 1: US-101 (config foundation)
Wave 2: US-102, US-103, US-104        ← parallel candidates (no mutual deps)
Wave 3: US-105 (←104) , US-106 (←103) ← parallel candidates
Wave 4: US-107 (←105,106), US-108 (←105), US-109 (←105) ← parallel candidates
Wave 5: US-110 (←106), US-111 (←107)  ← parallel candidates
Wave 6: US-112 (←107,108) — owner/operator-gated, not agent-executable
```

## TDD anchors

| Story | Anchor |
|---|---|
| US-101 | api/tests/test_llm_config.py — defaults assert anthropic + claude-opus-4-8/claude-fable-5/claude-haiku-4-5 |
| US-102 | api/tests/test_model_router.py — registry contains exactly 3 current IDs, downgrade→haiku |
| US-103 | api/tests/test_llm_refusal_fallback.py — 4 mocked cases (pre-output/mid-stream refusal, fallback success/refusal) |
| US-104 | api/tests/test_llm_metering.py — allowance check/record/exhaustion-denial |
| US-105 | api/tests/test_tier_gating.py — 401/402/free-pass/pro-pass matrix |
| US-106 | api/tests/test_fp_adjudicator.py — structured verdict schema round-trip |
| US-107 | api/tests/test_adjudicate_endpoint.py — gate + persistence + idempotency |
| US-108 | pytest -k "investigator or explanations" + claude-3 grep empty |
| US-109 | pytest -k "remediation or attack_chain" |
| US-110 | evidence/F-009/fp-adjudication-eval.md — real-data before/after with disclosure |
| US-111 | cli/tests/explain.rs — cargo test explain |
| US-112 | evidence/F-009/US-112-ops-verification.md (manual, operator) |

## Risk flags

1. **Tree-clean gate fails today** — and a concurrent F-010 session is actively committing; sequence the build after F-010 lands or on a dedicated branch from a clean tree.
2. **File collision with F-010:** US-111 touches `cli/src/main.rs`; F-010 US-H2 touches `cli/src/main.rs` + `cli/src/scanner/mod.rs`. Do not run both builds concurrently.
3. **US-105 modifies `api/gates.py` (authorization logic)** — CHARTER II.5: present the diff and await owner approval mid-build. Planned escalation, not a surprise.
4. **anthropic SDK version:** requirements pin `anthropic>=0.40.0`; refusal `stop_details`, structured outputs `messages.parse`, and fallback middleware likely need a newer release → `requirements.lock` change = dependency escalation (reversibility check) + fresh-venv test run per US-A2 precedent.
5. **US-104 metering must reuse existing tables** — if a clean implementation genuinely needs schema, STOP and escalate (CHARTER II.5), do not improvise.
6. **ANTHROPIC_API_KEY not in resources graph** (resources.json last touched 2026-06-08) — verify on sigil-api Container App and add to graph before US-112; never guess the secretRef name.
7. **Fable 5 cyber-classifier refusals on security content are expected in normal operation** — US-103's fallback is load-bearing; US-110 eval should record refusal/fallback rates as a measured output.
8. **Trust score / probation restrictions** — recent sessions ran under probation (trust 0). Check `.nomark/metrics/trust/score.json` at build start; restricted autonomy changes dispatch (no autonomous subagents).

## Escalation boundaries (planned operator touchpoints)

- US-105 gates.py diff (authorization) — approval before edit
- anthropic SDK version bump (requirements.txt + lock) — approval before install
- Any schema pressure from US-104 — stop and present
- US-112 entirely operator-driven (live Azure + Anthropic org)
- Commit of PRD + progress.md story block to clean the tree (pre-build)

## Lessons applied (tasks/lessons.md)

- Env vars consumed by endpoints go through the Settings class (pydantic-settings), not raw os.getenv — applies to ANTHROPIC_API_KEY wiring in US-101.
- Python 3.9 compat: `Union[T, None]` over `T | None` in any file that doesn't already use new syntax (llm_service already uses `str | None`; prod is 3.11 — verify per file).
- SAFE_DOMAINS already allowlists api.anthropic.com — scanner won't flag the integration's own egress (D6 self-scan stays green); confirm in US-110 self-scan.
- SIGIL_BIN must be pinned in eval harnesses (homebrew v1.0.4 shadowing incident).
