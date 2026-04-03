---
name: hmw-generator
description: "Bridges insight statements to opportunity questions. Use when generating How Might We variants from insight statements, problem descriptions, or during brainstorming prep. Triggered by '/hmw', 'how might we', 'reframe as opportunities', 'generate HMW', 'opportunity framing'. Produces scoped variants for both human and AI agent consumers."
---

# HMW Generator — From Understanding to Opportunity

## Purpose

"How Might We" is IDEO's single highest-leverage method. It is the bridge between "I understand the problem" and "I'm generating solutions." It encodes the person into the solution prompt itself, preventing solutioning that ignores the human or agent consumer.

A well-framed HMW invites multiple solutions. A badly-framed one either constrains too early (implies a solution) or expands too far (provides no traction).

## Input

One of:
- An insight statement from the Insight Registry: `INS-XXX: [Who] needs [what] because [why]`
- A raw problem description: `"Users struggle with..."`
- A persona frustration from a synthetic interview transcript

## Process

### 1. Extract the Core Elements

From the input, identify:
- **Who** — the specific person or agent type
- **Need** — what they're trying to accomplish
- **Barrier** — what prevents them
- **Context** — circumstances that shape the problem

### 2. Generate Variants at Different Scopes

| Scope | Template | Example |
|-------|----------|---------|
| **Systemic** | HMW change the system so [who] doesn't face [barrier]? | HMW redesign the onboarding flow so new users don't need to read documentation? |
| **Experience** | HMW make [activity] feel [desired state] for [who]? | HMW make account setup feel effortless for non-technical users? |
| **Friction** | HMW remove [specific friction] from [who]'s [activity]? | HMW eliminate the 6-step verification process for returning users? |
| **Reframe** | HMW turn [barrier] into an advantage for [who]? | HMW use the mandatory compliance step as a trust signal? |
| **Inversion** | HMW prevent [who] from ever experiencing [pain]? | HMW ensure users never see an error page during checkout? |

### 3. Scope Test Each Variant

For each HMW, apply the IDEO scope test:

- **Too broad?** Can you generate 5 solutions in 2 minutes? If not → narrow it
- **Too narrow?** Does it imply only one solution? If yes → broaden it
- **Implies a solution?** Does it contain a feature name or technology? If yes → remove it and reframe as need

### 4. Generate Agent Variants (if --dual)

For AI agent consumers, different HMW patterns apply:

| Pattern | Template |
|---------|----------|
| **Discoverability** | HMW make our [product/data] findable by agents without human guidance? |
| **Parseability** | HMW structure our [content/data] so agents can evaluate it against alternatives? |
| **Transactability** | HMW enable agents to complete [action] without human handoff? |
| **Fidelity** | HMW ensure the agent's recommendation matches what the human principal actually wanted? |
| **Failure Grace** | HMW help agents recover when our [API/data/service] is unavailable? |

### 5. Recommend for Brainstorming

Mark 2-3 HMW variants as recommended starting points for brainstorming.
Choose: mid-scope (experience or friction level) variants that are specific enough
for traction but broad enough for creative solutions.

## Output

```
SOURCE: INS-XXX — [Insight statement]
CONSUMER: Human / AI Agent / Both

HOW MIGHT WE...

HUMAN:
  HMW-001: [Systemic scope] ← BROAD
  HMW-002: [Experience scope] ← RECOMMENDED
  HMW-003: [Friction scope] ← RECOMMENDED
  HMW-004: [Reframe scope]
  HMW-005: [Inversion scope]

AI AGENT (if applicable):
  HMW-006: [Discoverability]
  HMW-007: [Parseability]
  HMW-008: [Transactability]

RECOMMENDED FOR BRAINSTORMING: HMW-002, HMW-003
```

## Rules

1. **The person stays in the question.** Every HMW names who it serves.
2. **No implied solutions.** "HMW add a chatbot" is not a HMW.
3. **Link to evidence.** Every HMW traces to an INS-XXX.
4. **Minimum 5 variants.** Breadth before depth.
5. **Confidence inherits.** If the source insight is LOW, the HMW is LOW.

## Save Location

`.nomark/research/hmw.md`

Proposes updates to SOLUTION.md Part I.5 "How Might We Questions" table.
