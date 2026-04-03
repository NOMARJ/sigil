# /silence-audit

Identify who is NOT represented in your evidence base and what that means.

## Usage

```
/silence-audit                # Audit current SOLUTION.md evidence
/silence-audit EP-001         # Audit a specific Epic's evidence
/silence-audit --research     # Audit .nomark/research/ persona panel
```

## What It Does

Examines the evidence sources behind your "Who It Serves" section (or persona panel if `--research`) and asks: whose voice is absent?

### Systematic Over-Representation Check

Public internet data systematically over-represents:
- English-speaking populations
- Tech-literate, digitally active users
- Affluent consumers who buy products worth reviewing
- Vocal complainers and enthusiastic advocates (sentiment extremes)
- Younger demographics who dominate social platforms

### Systematic Under-Representation Check

And systematically under-represents:
- Non-English speakers and non-Western cultures
- Older adults with lower digital presence
- Low-income users who don't leave reviews
- People with disabilities (unless the product targets accessibility)
- Users in regulated environments who can't discuss work publicly
- The "silent satisfied" — daily users who never post
- Silent churn — people who tried, left, and said nothing

## Output

```
┌──────────────────────────────────────────────────┐
│ SILENCE AUDIT                                     │
├──────────────────────────────────────────────────┤
│ Scope: [SOLUTION.md / EP-XXX / persona panel]    │
│                                                   │
│ EVIDENCE SOURCES REVIEWED:                       │
│ [List of source types present in the evidence]   │
│                                                   │
│ WHO IS MISSING:                                  │
│                                                   │
│ 1. [Group]                                       │
│    Why absent: [reason]                          │
│    Material impact: [HIGH / MED / LOW]           │
│    Action: [Accept / Seek alt. evidence / Field] │
│                                                   │
│ 2. [Group]                                       │
│    Why absent: [reason]                          │
│    Material impact: [HIGH / MED / LOW]           │
│    Action: [Accept / Seek alt. evidence / Field] │
│                                                   │
│ BLIND SPOT RATING:                               │
│ [MINOR / MODERATE / SEVERE]                      │
│                                                   │
│ MINOR: Missing groups are tangential             │
│ MODERATE: Missing groups are relevant            │
│ SEVERE: Missing groups are core — treat all      │
│         findings as provisional until real        │
│         research covers them                     │
└──────────────────────────────────────────────────┘
```

## Actions by Rating

- **MINOR:** Proceed normally. Note gaps in SOLUTION.md Silence Check section.
- **MODERATE:** Add missing groups to fieldwork priority list. Feature DONE criteria should include at least one check against the gap.
- **SEVERE:** All Features derived from this evidence must include real-user validation as a Feature-level acceptance criterion before DONE.

## Save Location

`.nomark/research/silence-audit.md`

Also proposes updates to the "Who Is Missing" table in SOLUTION.md Part I.
