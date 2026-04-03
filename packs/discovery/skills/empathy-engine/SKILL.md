---
name: empathy-engine
description: "Full Empathy Engine — evidence-grounded persona panel construction, synthetic interviews, and insight extraction. Use when the owner runs /discover, asks 'who is this for', 'build personas', 'create the panel', 'who should we interview', 'run discovery', 'empathy engine', or when a new product/Epic needs evidence-grounded understanding of human and AI agent consumers. NOT for bug fixes, tech debt, or incremental features within validated Epics. This is the heavyweight DISCOVER tool — for quick checks use /empathy instead."
---

# Empathy Engine — Evidence-Grounded Persona Panels

*This is preparation for research, not research itself.
Synthetic evidence has a confidence ceiling of MED.
HIGH confidence requires at least one real-world data point.*

## Purpose

Construct a panel of synthetic personas grounded in real human experiences shared online, then conduct structured interviews to extract insight statements. Produces the evidence root for the NOMARK traceability chain: Person → Insight → Epic → Feature → Story.

Based on IDEO Field Guide to Human-Centered Design (57 methods). Extended with dual-consumer lens (human + AI agent) and structural anti-bias mechanisms (Hostile Critic, Silence Audit).

## The Protocol

### Step 1: Define the Research Frame

Read SOLUTION.md. Extract or construct:

```
RESEARCH FRAME
Challenge: [HMW statement or "What This Is" from SOLUTION.md]
Domain: [industry/sector]
Geography: [target markets]
Consumer type: [B2C end user / B2B buyer / operator / etc.]
Extremes to include: [power users, non-users, workaround inventors, reluctant adopters]
```

If SOLUTION.md "Who It Serves" already has entries, use them as starting hypotheses to investigate — not as conclusions.

### Step 2: Harvest Evidence

Search for real human voices. Every piece retains its source URL.

| Source Type | What It Reveals | Search Approach |
|-------------|----------------|-----------------|
| Product reviews | Pain points, delight, unmet needs | Search [product/category] + "review" on G2, Capterra, Trustpilot, Reddit |
| Forum discussions | Workarounds, tribal knowledge, emotion | Search [problem space] on Reddit, Stack Exchange, niche communities |
| Support threads | Failure modes, confusion, feature gaps | Search [product] + "issue" or "problem" or "help" |
| Social media | Sentiment, complaints, aspirational use | Search [product/category] on Twitter/X, LinkedIn |
| Published interviews | Expert perspectives, named experiences | Search [domain] + "interview" or "podcast" |
| Job postings | Workflow context, tool expectations | Search roles that use this type of product |
| Academic/industry research | Statistics, demographics, validated findings | Search [domain] + "research" or "report" or "study" |

**Minimum evidence threshold:** At least 3 different source types must be represented. If fewer than 3 are findable, flag this as LOW confidence overall.

### Step 3: Construct Persona Panel (6-9 Personas)

Each persona is a composite of real evidence, NOT an invention.

| Type | IDEO Method | Purpose | Required? |
|------|------------|---------|-----------|
| Power User | Extreme (high) | Advanced needs, feature ceiling | Recommended |
| Reluctant Adopter | Extreme (resistance) | Barriers, fears, switching costs | Recommended |
| Workaround Inventor | Extreme (creative) | Unmet needs solved badly | Recommended |
| Mainstream User | Mainstream | Baseline expectations | Required |
| Non-User | Extreme (non-adoption) | Category rejection reasons | Recommended |
| Adjacent User | Analogous inspiration | Structural parallels from other domains | Optional |
| Buyer (not User) | Stakeholder | Purchase decision without daily use | Recommended for B2B |
| Affected Bystander | Community context | Impacted without decision power | Optional |
| **Hostile Critic** | **Adversarial** | **Breaks sycophancy bias** | **MANDATORY** |

**Minimum panel:** Mainstream User + Hostile Critic + 2 others = 4 personas.
**Full panel:** All 9 types.

For each persona, use the persona-profile template (see `templates/persona-profile.md`).

### Step 4: Silence Audit (MANDATORY)

Invoke the `silence-audit` skill. Cannot be skipped.

Before proceeding to interviews, stop and ask: who is NOT in this panel? See `skills/silence-audit/SKILL.md` for full protocol.

### Step 5: Conduct Synthetic Interviews

For each persona, run a structured interview. Rules:

1. **Evidence-bounded.** Respond only from the persona's evidence chain. If evidence doesn't cover it: *"I don't have strong views on that — it hasn't come up in my experience."*

2. **Language fidelity.** Use the language patterns of real users from the harvested data. Sound like a person, not a marketing summary.

3. **Disagree when evidence supports it.** If data shows frustration, express frustration. No sycophancy.

4. **Surface contradictions.** Real people are contradictory. Include both sides.

5. **Flag confidence.** Every substantive claim: *[HIGH/MED/LOW confidence]*

6. **Hostile Critic gets special rules.** See `skills/hostile-critic/SKILL.md`.

**Interview guide per persona:**
- 5 open-ended questions derived from the research frame
- 3 "why behind the why" follow-ups (ask "why" five times — IDEO Method #6)
- 1 provocation / conversation starter (sacrificial concept to test reaction — IDEO Method #10)

### Step 6: Extract Insights

From interview transcripts, identify non-obvious truths:

**Format:** `[Who] needs [what] because [why]`

**Rules:**
- The insight must contain "because" — it explains the WHY behind behaviour
- It must be non-obvious (if everyone already knows it, it's not an insight)
- It must be grounded in evidence (cite the sources)
- It must be actionable (a design team can do something with it)

**Assign IDs:** INS-001, INS-002, etc.

### Step 7: Generate HMW Variants

Invoke the `hmw-generator` skill. Each insight produces 3-5 HMW variants at different scope levels.

### Step 8: Save and Propose

Save all outputs to `.nomark/research/`. Propose updates to SOLUTION.md:
- "Who It Serves" table entries with evidence basis and confidence
- Part I.5 Insight Registry entries
- Part I.5 HMW Questions
- Part I.5 DISCOVER Run Log entry
- Epic Registry evidence column updates

Owner reviews and approves all changes.

## Integration Points

| NOMARK Phase | How DISCOVER Feeds It |
|-------------|----------------------|
| THINK | Insights and HMW questions become inputs to brainstorming |
| PLAN | Persona panel informs story acceptance criteria |
| BUILD | Persona reference guides UX/copy/API design decisions |
| VERIFY | Dual D/F/V check (human + agent desirability) at Feature level |

## What This Skill Does NOT Do

- Replace real user research
- Produce HIGH confidence findings without real-world corroboration
- Make product decisions (it surfaces needs; owner decides solutions)
- Run automatically (owner must invoke `/discover`)
- Work without web search capability
