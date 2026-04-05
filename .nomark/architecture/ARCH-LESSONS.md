# Architecture Lessons Schema

> NOMARK Level 1 — Universal. Defines the format for capturing architecture outcomes.
> Architecture lessons are the feedback loop: ADR decision → implementation → outcome → lesson.

---

## What Is an Architecture Lesson

An architecture lesson captures what happened after an ADR was implemented. ADRs record decisions. Lessons record outcomes. Together they close the loop so future ventures learn from past ones.

Lessons are to ventures what instincts are to sessions — structured learning that compounds over time.

## Format

Each lesson is a markdown file with YAML frontmatter in `docs/arch-lessons/`.

```yaml
---
id: AL-001
venture: "{venture-name}"
date: YYYY-MM-DD
category: database | auth | deployment | data-pipeline | integration | infrastructure | cost | scaling | ops | incident
pattern: "{NOMARK pattern name}" | none
adr: ADR-NNNN
outcome: success | partial | failure | reverted
tags: []
---
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| id | string | `AL-NNN` — sequential per venture |
| venture | string | Venture name |
| date | string | ISO date lesson was captured |
| category | string | Architecture domain (see values above) |
| pattern | string | NOMARK pattern used, or `none` if novel approach |
| adr | string | Linked ADR ID |
| outcome | string | `success`, `partial`, `failure`, or `reverted` |
| tags | string[] | Technology, approach, or domain tags |

### Body Sections

```markdown
## What we did
[One paragraph: what was implemented per the ADR]

## What happened
[Measurable outcome: latency, cost, ops burden, user impact]

## What we'd do differently
[Hindsight: what would change if starting over]

## Recommendation
[Action for NOMARK: promote to Tier 1, add to pattern, warn against, etc.]
```

## Agent Protocol

1. **Capture trigger:** After an ADR has been accepted for 90+ days, prompt the owner for outcome
2. **On capture:** Create the lesson file, update the ADR's outcome fields, add graph nodes
3. **On sync:** Lessons sync to portfolio via DATA mode for cross-venture analysis
4. **On init:** Portfolio surfaces relevant lessons when a new venture starts

## Storage

- Venture lessons: `docs/arch-lessons/AL-NNN.md`
- Synced to portfolio: `projects/{venture}/arch-lessons/`
- Graph nodes: type `al` in `.nomark/graph.json`
