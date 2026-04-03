---
name: silence-audit
description: "Bias detection — identifies who is missing from the evidence base and what that absence means. Auto-triggered during /discover after persona panel construction. Also triggered by 'who is missing', 'silence audit', 'blind spots', 'bias check', 'who aren't we hearing from', 'who did we miss'. Cannot be skipped during full DISCOVER."
---

# Silence Audit — Who Is Missing and Why

## Purpose

Public internet evidence systematically over-represents certain populations and under-represents others. This skill makes that bias visible. It does not eliminate it — it names it, assesses its impact, and proposes mitigation.

A persona panel without a Silence Audit will confidently represent the internet's majority voice and mistake it for the whole picture. That is the opposite of empathy.

## When to Run

- **Mandatory:** After Step 3 (persona construction) in every full DISCOVER run
- **Optional:** Standalone via `/silence-audit` to check existing evidence
- **Cannot be skipped** during full DISCOVER

## The Protocol

### 1. Identify Evidence Sources Present

List every source type used in the persona panel's evidence chains:
- [ ] Product reviews
- [ ] Forum discussions
- [ ] Support threads
- [ ] Social media
- [ ] Published interviews
- [ ] Job postings
- [ ] Academic/industry research
- [ ] Government/census data
- [ ] Analytics data
- [ ] Direct user conversations

### 2. Check for Systematic Over-Representation

These groups dominate public internet evidence:

| Over-Represented | Why |
|-----------------|-----|
| English speakers | Internet content skews English |
| Tech-literate users | They write reviews, post on forums |
| Affluent consumers | They buy products worth reviewing |
| Vocal extremes | Strong opinions get posted; mild ones don't |
| Younger demographics | Higher social media activity |
| Urban populations | Better internet access, more digital services |

**Ask:** Does my persona panel disproportionately reflect these groups?

### 3. Check for Systematic Under-Representation

These groups are typically absent from public internet evidence:

| Under-Represented | Why |
|-------------------|-----|
| Non-English speakers | Content in other languages wasn't searched |
| Older adults (65+) | Lower digital presence, fewer reviews |
| Low-income users | Don't buy products to review, less digital access |
| People with disabilities | Unless product targets accessibility specifically |
| Regulated industry users | Can't discuss work publicly (finance, defence, healthcare) |
| Silent satisfied | Use the product daily, never post about it |
| Silent churn | Tried it, left, said nothing |
| Rural populations | Less digital infrastructure, fewer online communities |
| Non-binary/minority groups | Under-represented in training data and review platforms |

**Ask:** Which of these groups are relevant to our design challenge but absent from our evidence?

### 4. Assess Material Impact

For each absent group, ask: does their absence change the answer?

| Impact Level | Meaning |
|-------------|---------|
| **HIGH** | This group is core to the design challenge. Their absence means our evidence base is fundamentally incomplete. |
| **MED** | This group is adjacent. Their absence limits our understanding but doesn't invalidate the core findings. |
| **LOW** | This group is tangential. Their absence is noted but doesn't affect current design decisions. |

### 5. Determine Mitigation

For each HIGH or MED impact absence:

| Mitigation | When to Use |
|-----------|-------------|
| **Accept and label** | Group is real but evidence is genuinely unavailable. Label all related findings as LIMITED and note the gap. |
| **Seek alternative evidence** | Use non-internet sources: government data, census, academic ethnographies, NGO reports, accessibility audits, industry body research. |
| **Flag for fieldwork** | This group MUST be included in real-world research. Synthetic panel cannot represent them. Add to Feature acceptance criteria. |

### 6. Assign Blind Spot Rating

| Rating | Criteria | Consequence |
|--------|----------|-------------|
| **MINOR** | Missing groups are tangential to the challenge | Proceed normally. Note in SOLUTION.md. |
| **MODERATE** | Missing groups are relevant but not primary | Feature DONE criteria should include at least one check. |
| **SEVERE** | Missing groups are core to the challenge | ALL findings are provisional. Features require real-user validation before DONE. |

## Output Format

```
SILENCE AUDIT
Scope: [SOLUTION.md / EP-XXX / persona panel dated YYYY-MM-DD]
Date: [today]

EVIDENCE SOURCES PRESENT: [list]
EVIDENCE SOURCES MISSING: [list]

WHO IS MISSING:

1. [Group]
   Why absent: [reason]
   Material impact: HIGH / MED / LOW
   Mitigation: Accept / Alt. evidence / Fieldwork priority

2. [Group]
   ...

BLIND SPOT RATING: MINOR / MODERATE / SEVERE

[If SEVERE]: All Features derived from this evidence must include
real-user validation as acceptance criteria before DONE.
```

## Save Location

`.nomark/research/silence-audit.md`

Proposes updates to SOLUTION.md "Who Is Missing (Silence Check)" table.
