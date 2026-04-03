---
name: business-context
description: >
  Foundation skill. Loads project context from SOLUTION.md, BUSINESS-CONTEXT.md,
  and GTM specs. Auto-invoked by all growth and business-strategy skills before
  doing anything. Provides product identity, brand voice, buyer context, and
  GTM motion to every downstream skill. Never hardcodes business knowledge.
---

# Business Context — Foundation Skill

You are the foundation layer. Every growth and business-strategy skill invokes you first.

## What you do

1. Find and read the project's SOLUTION.md (primary context)
2. Identify the target product from the user's request
3. Read `.nomark/gtm/<product>.md` if it exists (GTM supplement)
4. Fall back to `BUSINESS-CONTEXT.md` if no SOLUTION.md found (portfolio level)
5. Return a compact context summary for use by the calling skill

## Context search order

```
1. SOLUTION.md        ← per-project, highest priority
2. .nomark/gtm/<product>.md  ← GTM specifics
3. BUSINESS-CONTEXT.md       ← portfolio-level fallback
4. User input                ← last resort
```

## Context summary format

```
Project: <name>
Product: <product name from SOLUTION.md Part I or BUSINESS-CONTEXT.md>
Stage: <status from SOLUTION.md or inferred>
Motion: <primary GTM motion>
Buyer: <specific buyer description>
Channel: <primary channel>
Core message: <one sentence>
Brand voice: <from BUSINESS-CONTEXT.md or SOLUTION.md>
Constraints: <from SOLUTION.md Part VI or BUSINESS-CONTEXT.md>
Fixed specs: <non-negotiable items from SOLUTION.md Part II>
Variable specs: <open questions / assumptions still being tested>
Context source: SOLUTION.md / BUSINESS-CONTEXT.md / user-provided
GTM spec: [present / not yet created]
```

## If SOLUTION.md doesn't exist

Check for BUSINESS-CONTEXT.md. If found, extract the relevant product section and flag:
"No SOLUTION.md for this project. Using portfolio-level context from BUSINESS-CONTEXT.md.
For sharper results, create a SOLUTION.md — I can generate one from what you tell me."

## If neither exists

Tell the user: "No project context found. I need to know what you're building before
running growth work. Give me a quick summary and I'll load context from that — or I
can generate a SOLUTION.md template for you to fill in."

## If GTM spec doesn't exist for this product

Return the context from SOLUTION.md / BUSINESS-CONTEXT.md and flag:
"No GTM spec for <product>. Recommend running `/growth:gtm <product>` before executing.
Proceeding with available context only."

## What you don't do

You don't generate content, outreach, or strategy. You just load context.
Other skills use your output to stay anchored to what's actually true about this project.

You never hardcode business knowledge. If the context files change, your output changes.
