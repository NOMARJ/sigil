# Discovery Pack — Human-Centered Design for NOMARK

Evidence before code. Who is this for — human and agent — and how do you know?

## What This Pack Does

Adds the DISCOVER capability to the NOMARK lifecycle. Based on IDEO's Field Guide to Human-Centered Design (57 methods), extended with dual-consumer lens (human + AI agent consumers) and structural anti-bias mechanisms.

**Lightweight layer (always active after install):** SOLUTION.md template gets an evidence-aware "Who It Serves" section, an Insight Registry, and a Silence Check. Every Epic gets an evidence column. The template makes the question unavoidable without making the process heavy.

**Heavyweight layer (owner-invoked):** `/discover` runs the full Empathy Engine — persona panels, synthetic interviews, hostile critic, silence audit, HMW generation. Takes hours. Worth it for new products and major pivots.

## Contents

| Type | Name | Purpose |
|------|------|---------|
| Agent | empathy-researcher | DISCOVER facilitation — Opus tier |
| Agent | agent-experience-mapper | AI agent consumer simulation — Sonnet tier |
| Command | /discover | Full DISCOVER phase |
| Command | /empathy | Quick Suri test (5 min) |
| Command | /silence-audit | Who's missing from evidence? |
| Command | /hmw | Generate How Might We variants |
| Skill | empathy-engine | Persona panel + synthetic interviews |
| Skill | silence-audit | Bias detection and mitigation |
| Skill | hmw-generator | Insight → opportunity bridge |
| Skill | hostile-critic | Mandatory adversarial persona |
| Template | solution-who-it-serves | SOLUTION.md Part I patch |
| Template | insight-registry | SOLUTION.md Part I.5 patch |
| Template | persona-profile | Individual persona template |
| Template | agent-persona-profile | AI agent persona template |

## Install

```bash
/install discovery
```

Or manually:
```bash
cp -r packs/discovery/agents/* .claude/agents/
cp -r packs/discovery/skills/* .claude/skills/
cp -r packs/discovery/commands/* .claude/commands/
```

Then apply the SOLUTION.md templates manually:
1. Replace "Who It Serves" section using `templates/solution-who-it-serves.md`
2. Insert Part I.5 using `templates/insight-registry.md`
3. Add Evidence column to Epic Registry
4. Update traceability rule

## CHARTER.md Change (Recommended)

Add Jane Fulton Suri to the Governance Board (Article III). This is a minor version bump (2.0.0 → 2.1.0). See `templates/insight-registry.md` for the Board addition text.

No immutable principles changed. No CHARTER v3 required.

## Enforcement Gradient

```
Lightest:  SOLUTION.md template forces the question (3 min)
           (who, evidence, missing)
                ↓
Medium:    Governance Board Suri test at ambiguous decisions
           (auto-triggered when board fires)
                ↓
Heaviest:  /discover for full Empathy Engine (hours)
           (persona panel, synthetic interviews, agent sims)
```

## Confidence Rules

| Evidence Type | Max Confidence |
|--------------|---------------|
| Synthetic-only (from /discover) | MED ceiling |
| Direct operator experience (documented) | HIGH eligible |
| Synthetic + one real-world corroboration | HIGH eligible |
| Assumption with no evidence | LOW — mark HYPOTHESIS |

## When to Run Full DISCOVER

- New product or venture
- Major pivot affecting who you serve
- Entering a market you don't personally understand
- Epic marked HYPOTHESIS for >30 days
- Governance Board Suri test fails

## When NOT to Run Full DISCOVER

- Bug fixes, tech debt, incremental features
- You ARE the user (document your experience instead)
- Use `/empathy` for quick checks

## Token Impact

Low passive impact. 2 agent definitions + 4 commands + 4 skills, all loaded on demand. Skills are invoked by commands, not preloaded into every session. The SOLUTION.md template changes add ~200 tokens to session start reads.

## Methodology Attribution

- IDEO.org, *The Field Guide to Human-Centered Design*, 2015 (57 methods, CC BY-NC-ND 3.0)
- PersonaCite (CHI 2026) — evidence-bounded AI personas
- Original NOMARK concepts: hostile critic persona, silence audit, AI agent consumer personas, dual D/F/V lens, confidence ceiling, principal empathy (all unvalidated, treat as working hypotheses)

## Anti-Patterns

| Anti-Pattern | Why It Fails |
|---|---|
| Fill "Who It Serves" without evidence | Orphan Epics — building for ghosts |
| Treat synthetic research as conclusion | Hypothesis ≠ validation. MED ceiling. |
| Skip the Silence Check | Confident about a biased evidence base |
| Only human personas for agent-facing products | Invisible to AI consumers |
| Run full DISCOVER for every bug fix | Process overhead kills velocity |
| Believe the Hostile Critic is always right | They surface objections, not truth |
