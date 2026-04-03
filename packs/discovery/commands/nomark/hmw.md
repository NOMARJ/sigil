# /hmw

Generate How Might We variants from insight statements or problem descriptions.

## Usage

```
/hmw                          # Generate from Insight Registry in SOLUTION.md
/hmw INS-001                  # Generate from a specific insight
/hmw "users struggle with..." # Generate from a raw problem statement
/hmw --dual                   # Generate for both human and agent consumers
```

## What It Does

Transforms understanding into opportunity. HMW questions are the bridge between
"we learned X about people" and "how might we address X with a solution."

### From Insight Statement

Input: `[Who] needs [what] because [why]`
Output: 5-8 HMW variants at different scope levels

### Scope Calibration

Each HMW is tested against three filters (from IDEO Method #1):

- **Too broad?** "How might we fix healthcare?" → No traction, too many directions
- **Too narrow?** "How might we add a button to page 3?" → Predetermined solution
- **Just right?** "How might we help patients track their recovery at home?" → Invites multiple solutions

### Output Format

```
INSIGHT: INS-001 — [Insight statement]

HOW MIGHT WE...

HUMAN CONSUMER:
  HMW-001: [Broadest scope — systemic opportunity]
  HMW-002: [Mid scope — experience-level opportunity]
  HMW-003: [Focused scope — specific friction point]
  HMW-004: [Reframed — same need, different angle]
  HMW-005: [Inverted — address the opposite problem]

AI AGENT CONSUMER (if --dual):
  HMW-006: [How might agents discover this more effectively?]
  HMW-007: [How might agents evaluate this against alternatives?]
  HMW-008: [How might agents complete transactions without human handoff?]

RECOMMENDED FOR BRAINSTORMING: [HMW-002, HMW-003]
(Mid and focused scope generate the most actionable ideas)
```

## Rules

1. **Every HMW encodes the person.** Not "How might we improve speed?" but "How might we help [who] do [what] faster?" The person stays in the question.

2. **Never imply a solution.** "How might we add AI search?" is a feature request, not a HMW. "How might we help users find what they need without knowing what to search for?" is a HMW.

3. **Generate breadth.** At least 5 variants. The best HMW is rarely the first one.

4. **Link to evidence.** Every HMW traces to an INS-XXX. No orphan questions.

5. **Flag assumptions.** If the HMW contains an assumption (e.g. "users want speed" when the evidence says they want accuracy), note it.

## Save Location

`.nomark/research/hmw.md`

Also proposes updates to SOLUTION.md Part I.5 "How Might We Questions" table.

## Integration with THINK Phase

HMW output feeds directly into `/think` and the brainstorming skill.
The brainstorming skill should accept HMW questions as starting prompts
for ideation sessions.
