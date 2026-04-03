# /discover

Run the full DISCOVER phase for a product or Epic.

## Usage

```
/discover                    # Full discovery for current SOLUTION.md
/discover EP-001             # Discovery scoped to a specific Epic
/discover --quick            # Quick empathy check (same as /empathy)
/discover --agents           # Include AI agent consumer personas
/discover --refresh          # Refresh stale research (>90 days)
```

## What It Does

1. Reads SOLUTION.md (Product Vision + Who It Serves)
2. Invokes the `empathy-researcher` agent (Opus tier)
3. Agent harvests evidence from web search (reviews, forums, support, social, research)
4. Constructs persona panel (6-9 human personas including Hostile Critic)
5. Runs Silence Audit (who's missing from the evidence?)
6. If `--agents` flag: constructs AI agent persona panel via `agent-experience-mapper`
7. Conducts synthetic interviews with each persona (evidence-bounded)
8. Extracts insight statements: "[Who] needs [what] because [why]"
9. Generates HMW variants for human needs (+ agent needs if `--agents`)
10. Saves all outputs to `.nomark/research/`
11. Proposes updates to SOLUTION.md Part I "Who It Serves" and Part I.5 "Insight Registry"
12. Owner reviews and approves

## Output Location

```
.nomark/research/
├── personas/
│   ├── panel-YYYY-MM-DD.md
│   ├── hostile-critic.md
│   └── agent-panel-YYYY-MM-DD.md    (if --agents)
├── silence-audit.md
├── insights.md
├── hmw.md
└── agent-experience/                 (if --agents)
    └── [agent-type].md
```

## When to Run

- New product or venture
- Major pivot affecting who you serve
- Entering a market you don't personally understand
- Epic marked HYPOTHESIS for >30 days with no validation
- Governance Board Suri test fails
- Owner judgment: "I don't know enough about these people"

## When NOT to Run

- Bug fixes, tech debt, incremental features within validated Epics
- You ARE the user and can document your direct experience
- Use `/empathy` for quick checks instead

## Governed By

- CHARTER.md Article III — Governance Board (Suri: The Empathy Test)
- SOLUTION.md Part I "Who It Serves" — evidence basis requirement
- SOLUTION.md Part I.5 "Insight Registry" — where insights are stored

## Confidence Rules

- Synthetic-only evidence: **MED ceiling**
- Synthetic + real-world corroboration: **HIGH eligible**
- Direct operator experience documented: **HIGH eligible**
- Assumption with no evidence: **LOW — mark HYPOTHESIS**

## Header on All Outputs

Every DISCOVER output begins with:

> *This is preparation for research, not research itself.
> Synthetic evidence has a confidence ceiling of MED.
> HIGH confidence requires at least one real-world data point.*
