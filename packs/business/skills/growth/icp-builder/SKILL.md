---
name: icp-builder
description: >
  Builds a precise Ideal Customer Profile for a product. Reads the GTM spec and
  BUSINESS-CONTEXT.md, then produces a detailed ICP document. Use before outreach,
  content, or launch work. Auto-invoked by outreach-engine.
---

# ICP Builder

## Pre-requisites

Invoke `business-context` skill first. Requires a GTM spec for this product.

## What you build

A specific, usable ICP — not a persona cartoon. Something you can
filter a LinkedIn search with. Something you can hand to an outreach sequence.

---

## ICP Document Structure

### Firmographic (company)

```
Industry:        [specific vertical — not "tech"]
Company size:    [headcount or ARR range]
Geography:       [country/region — be specific]
Stage:           [startup/scaleup/enterprise — not all three]
Tech indicators: [tools they use that signal fit]
Anti-fit:        [company types that look right but never buy]
```

### Demographic (person)

```
Title:           [exact job titles — 2-3, not 10]
Seniority:       [IC / manager / director / VP / C-suite]
Department:      [function they sit in]
Reports to:      [who they answer to]
Owns budget:     [yes/no — or "influences"]
Decision maker:  [yes/no — or "champion"]
```

### Psychographic (mindset)

```
Pain they feel daily:     [specific, not generic]
Fear they won't say out loud: [what keeps them up]
What success looks like:  [measurable for them]
What they read/watch:     [where they get information]
Who they trust:           [peers, analysts, communities]
```

### Trigger events

```
Trigger 1: [event that makes them go looking — be specific]
Trigger 2: [another event]
Signal:    [how we would know this trigger just happened]
```

### Disqualifiers

```
- [reason this company/person will never buy even if they look like ICP]
- [another disqualifier]
```

---

## Per-product ICP notes

### Sigil
The buyer is not the CISO. The CISO approves budgets. The buyer is the
security engineer or DevSecOps lead who:
- Just had an incident involving an AI agent or MCP server
- Is being asked by their CISO to "do something about AI security"
- Has never had a tool specifically for auditing AI agent code

Trigger: company adopts Claude Code / Cursor / agentic workflows in production.
Signal: GitHub shows active Claude Code use, MCP server repos, agent frameworks.

### Operable
The buyer is not a CTO. The buyer is the operations lead or fund manager who:
- Runs data reconciliation manually across 3+ platforms every month
- Knows what SimCorp/Bloomberg/Asgard/Netwealth cost and is skeptical of yet another system
- Has APRA audit obligations that manual processes barely satisfy

Trigger: new platform rollout (Asgard → Hub24 migration), new hire who expects automation,
failed audit finding around data reconciliation.
Signal: job posting for "investment operations analyst" at a boutique fund manager.

### InstaIndex
The buyer is an SEO manager or technical founder who:
- Just published content that isn't getting indexed
- Heard about AI search and doesn't know if their site appears in it
- Is frustrated that Google Search Console doesn't cover AI indexing

Trigger: new site launch, Google indexing lag complaint, competitor ranking in AI search.
Signal: Google Search Console connected, active blog publishing, technical site.

---

## Output

Save to `.nomark/growth/<product>/icp.md`. Commit with:
```bash
git add .nomark/growth/<product>/icp.md
git commit -m "growth: <product> ICP — $(date '+%Y-%m-%d')"
```
