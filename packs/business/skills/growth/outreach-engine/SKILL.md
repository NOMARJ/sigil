---
name: outreach-engine
description: >
  Produces B2B outreach sequences calibrated to the product's GTM motion and ICP.
  Reads business context, GTM spec, and ICP before writing a single word.
  Refuses to produce cold outreach for relationship-led motions (Operable, Smart Settle).
  Use for Sigil developer outreach, InstaIndex SEO community outreach.
---

# Outreach Engine

## Pre-requisites

Invoke `business-context` skill. Requires GTM spec and ICP doc for this product.

## Motion check (hard gate)

```
If motion = "relationship-led":
  STOP. Output:
  "<Product> uses a relationship-led motion. Cold outreach will not work and
  will damage the brand. The right path is warm introduction via [specific network].
  Run /growth:pipeline to identify warm paths."
  EXIT.
```

This gate is non-negotiable. Operable and Smart Settle never get cold sequences.

---

## Sequence Design Principles

**Max 3 touches.** Buyers are busy. More than 3 unreplied messages is spam.

**Trigger-aware.** Reference the trigger event from the ICP. Generic messages get deleted.

**Specific proof.** One concrete fact, not "industry-leading." The 97.96% exists for a reason.

**No pitch in message 1.** Message 1 is pattern-interrupt + genuine value. Pitch is message 2 at earliest.

**Short.** Under 5 sentences per message. Mobile-readable. Busy people skim.

**Australian tone.** Understated. Not American hype. No "I hope this finds you well."

---

## Sequence Format

```markdown
## Outreach Sequence — <Product> / <Channel> / <ICP segment>
**Trigger:** [the event that qualifies this prospect right now]
**Channel:** [email / LinkedIn / community DM]

### Message 1 — Pattern interrupt (send day 1)
Subject: [specific, not clever]

[Body — 3-4 sentences max]
[Reference their trigger or a specific observation]
[One question or one value offer — not a pitch]

### Message 2 — Proof + ask (send day 5 if no reply)
Subject: Re: [same thread]

[Body — 3-4 sentences]
[The specific proof point — detection rate, customer result, data source]
[Clear, low-friction ask]

### Message 3 — Close or exit (send day 12 if no reply)
Subject: Re: [same thread]

[Body — 2-3 sentences]
[Acknowledge they're busy]
[Leave the door open — no guilt]
[Your value in one line for their future reference]
```

---

## Sigil-specific outreach

**Target:** Security engineers, DevSecOps leads at companies actively using AI agents in production.

**Trigger signal:** Public GitHub repos with Claude Code config, MCP servers, agent frameworks.

**Message 1 hook:** "Noticed [company] has [specific tool/pattern] in production — we built
an audit CLI specifically for that surface area."

**Proof to use:** "Validated against Azure scan baseline — 97.96% detection rate.
The data is in the repo, not a marketing claim."

**Community alternative to cold outreach:**
Post the responsible disclosure paper to security Slack communities.
Let the content do the outreach.

---

## InstaIndex-specific outreach

**Target:** SEO managers at content-heavy sites who've complained about indexing lag.

**Trigger signal:** Reddit/Twitter posts about indexing problems, Google Search Console questions.

**Channel:** Community reply (Reddit, SEO Twitter) — not cold email.

**Format:** Helpful answer to their public complaint + mention of the tool.
This is content-led outreach, not cold sequence.

---

## Output

Save sequences to `.nomark/growth/<product>/outreach-<segment>-<date>.md`.

Track sends in the pipeline doc. Log replies and outcomes.
