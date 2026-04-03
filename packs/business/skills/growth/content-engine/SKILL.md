---
name: content-engine
description: >
  Produces content strategy and individual content pieces calibrated to a product's
  GTM motion. Covers SEO (traditional), AEO (AI search optimisation), and distribution.
  Reads business context and GTM spec first. Use for blog posts, LinkedIn content,
  GitHub documentation, technical write-ups, community posts.
---

# Content Engine

## Pre-requisites

Invoke `business-context` skill. Read GTM spec for this product.

---

## Content ↔ Motion mapping

| Motion | Content priority | Output type |
|---|---|---|
| Developer-led (Sigil) | Technical depth + honest data | GitHub README, write-ups, responsible disclosure, HN posts |
| Content-led (InstaIndex) | SEO + AEO — compound over time | Blog posts targeting questions, AI-optimised answers |
| Community-led | Helpfulness first, product second | Reddit answers, Slack community posts, forum replies |
| Relationship-led (Operable) | Thought leadership + proof | LinkedIn posts, industry event talk abstracts, case studies |

---

## AEO Framework (AI Engine Optimisation)

InstaIndex's own AEO is a proof-of-concept. Apply this to every content piece.

### What AI search engines want

1. **Direct answers** — lead with the answer, not the context
2. **Structured format** — headers, short paragraphs, numbered steps
3. **Specificity** — dates, numbers, named tools, exact processes
4. **Authority signals** — cited data, named sources, verifiable claims
5. **Question-answer pairing** — match the query format buyers use

### AEO checklist for every piece

- [ ] Does the title match a question someone would ask an AI?
- [ ] Does the first paragraph answer the question directly?
- [ ] Are there H2/H3 headers that match related questions?
- [ ] Are claims backed by specific numbers or named sources?
- [ ] Is there a clear unique insight (not just a summary of known facts)?
- [ ] Is the content scannable in 30 seconds?

### AEO question targets per product

**Sigil:**
- "how do I audit AI agent code for security vulnerabilities"
- "MCP server security risks"
- "Claude Code security audit"
- "AI agent supply chain risk"

**InstaIndex:**
- "why is my website not indexed by AI search engines"
- "how to get indexed by ChatGPT search"
- "IndexNow vs Google Search Console"
- "how to speed up Google indexing 2025"
- "AEO vs SEO difference"

**PolicyPA:**
- "how to choose private health insurance Australia"
- "best health insurance comparison site Australia"
- "how do health insurance comparison sites make money"

---

## Content formats by channel

### Blog posts (InstaIndex, Sigil)

Structure:
1. **Question hook** — title is the question, or title answers the question
2. **Direct answer** — first 2 sentences answer it completely
3. **Why it matters** — context for people who need more
4. **The specific detail** — what makes this post uniquely useful
5. **One thing to do** — actionable close

Target: 800-1200 words for AEO focus. 2000+ for deep technical credibility (Sigil).

### LinkedIn posts (Operable, Reece personal brand)

Format: insight → proof → implication → call to action
- No hashtag spam
- Dry voice — "most funds are still doing X manually. here's what the data says"
- Investment operations specificity — not generic fintech

### GitHub README (Sigil)

The README is the top-of-funnel. It must:
- State the specific problem in line 1
- Show the detection rate in the first screen
- Have a working example in under 5 commands
- Link to the responsible disclosure paper

### HN posts (Sigil)

"Show HN: Sigil — automated security audit for AI agent code"
- Lead with what makes it interesting technically (37 vector patterns, 97.96% validated)
- Acknowledge what it doesn't do
- Invite critique — security community respects honesty

---

## Content calendar framework

**Sigil:** 1 technical post per month (GitHub, cross-post to security blogs)
**InstaIndex:** 2 AEO-optimised posts per week (compound SEO)
**Operable:** 1 LinkedIn post per week (thought leadership, investment ops specific)
**PolicyPA:** 1 media pitch per month once product is live

---

## Output

Save content pieces to `.nomark/growth/<product>/content-<date>-<slug>.md`.
Include:
- Headline
- AEO question targeted
- Full draft
- Distribution plan (channel + timing)
- Success metric (views, shares, ranking signal)
