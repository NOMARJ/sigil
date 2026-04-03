---
name: product-marketing-context
description: "When the user wants to create or update their product marketing context document. Also use when the user mentions 'product context,' 'marketing context,' 'set up context,' 'positioning,' 'who is my target audience,' 'describe my product,' 'ICP,' or 'ideal customer profile.' Use at the start of any new project before using other marketing skills — it creates the GTM context file that all other skills reference."
metadata:
  version: 1.0.0
---

# Product Marketing Context

You help users create and maintain product marketing context documents. This captures foundational positioning and messaging information that other marketing/growth/SEO skills reference, so users don't repeat themselves.

## File Locations

The context document integrates into the NOMARK context hierarchy:

1. **Per-product GTM context**: `.nomark/gtm/<product>.md` — lives in the project repo
2. **Portfolio-level context**: `BUSINESS-CONTEXT.md` — portfolio strategy and brand voice
3. **Project-level context**: `SOLUTION.md` — product-specific positioning

This skill creates/updates the per-product GTM context file.

---

## Workflow

### Step 1: Check for Existing Context

Check for existing context files in this order:
1. `.nomark/gtm/<product>.md` (current standard)
2. `.agents/product-marketing-context.md` (legacy location)
3. `.claude/product-marketing-context.md` (older legacy)

If found in legacy location, offer to migrate to `.nomark/gtm/`.

### Step 2: Gather Information

**Option 1 — Auto-draft from codebase** (recommended):
Study the repo — README, landing pages, marketing copy, package.json, docs — and draft a V1. The user reviews, corrects, and fills gaps.

**Option 2 — Start from scratch**:
Walk through each section conversationally, one at a time.

Push for verbatim customer language — exact phrases are more valuable than polished descriptions.

### Step 3: Create the Document

---

## Sections to Capture

### 1. Product Overview
- One-line description
- What it does (2–3 sentences)
- Product category
- Product type (SaaS, marketplace, service, etc.)
- Business model and pricing

### 2. Target Audience
- Target company type (industry, size, stage)
- Target decision-makers (roles, departments)
- Primary use case
- Jobs to be done (2–3)
- Specific use cases or scenarios

### 3. Personas (B2B)
For each stakeholder: User, Champion, Decision Maker, Financial Buyer, Technical Influencer — what they care about, their challenge, and the value you promise them.

### 4. Problems & Pain Points
- Core challenge before finding you
- Why current solutions fall short
- What it costs them (time, money, opportunities)
- Emotional tension

### 5. Competitive Landscape
- **Direct competitors**: Same solution, same problem
- **Secondary competitors**: Different solution, same problem
- **Indirect competitors**: Conflicting approach
- How each falls short

### 6. Differentiation
- Key differentiators
- How you solve it differently
- Why that's better
- Why customers choose you over alternatives

### 7. Objections & Anti-Personas
- Top 3 objections and responses
- Who is NOT a good fit

### 8. Switching Dynamics (JTBD Four Forces)
- **Push**: Frustrations with current solution
- **Pull**: What attracts them to you
- **Habit**: What keeps them stuck
- **Anxiety**: What worries them about switching

### 9. Customer Language
- How they describe the problem (verbatim)
- How they describe your solution (verbatim)
- Words/phrases to use
- Words/phrases to avoid
- Glossary of product-specific terms

### 10. Brand Voice
- Tone
- Communication style
- Brand personality (3–5 adjectives)

### 11. Proof Points
- Key metrics or results
- Notable customers/logos
- Testimonial snippets
- Value themes with supporting evidence

### 12. Goals
- Primary business goal
- Key conversion action
- Current metrics (if known)

---

## Document Template

```markdown
# Product Marketing Context — [Product Name]

*Last updated: [date]*

## Product Overview
**One-liner:**
**What it does:**
**Product category:**
**Product type:**
**Business model:**

## Target Audience
**Target companies:**
**Decision-makers:**
**Primary use case:**
**Jobs to be done:**
-
**Use cases:**
-

## Personas
| Persona | Cares about | Challenge | Value we promise |
|---------|-------------|-----------|------------------|
| | | | |

## Problems & Pain Points
**Core problem:**
**Why alternatives fall short:**
-
**What it costs them:**
**Emotional tension:**

## Competitive Landscape
**Direct:** [Competitor] — falls short because...
**Secondary:** [Approach] — falls short because...
**Indirect:** [Alternative] — falls short because...

## Differentiation
**Key differentiators:**
-
**How we do it differently:**
**Why that's better:**
**Why customers choose us:**

## Objections
| Objection | Response |
|-----------|----------|
| | |

**Anti-persona:**

## Switching Dynamics
**Push:**
**Pull:**
**Habit:**
**Anxiety:**

## Customer Language
**How they describe the problem:**
- "[verbatim]"
**How they describe us:**
- "[verbatim]"
**Words to use:**
**Words to avoid:**

## Brand Voice
**Tone:**
**Style:**
**Personality:**

## Proof Points
**Metrics:**
**Customers:**
**Testimonials:**
> "[quote]" — [who]

## Goals
**Business goal:**
**Conversion action:**
**Current metrics:**
```

---

## Step 4: Confirm and Save

- Show the completed document
- Ask if anything needs adjustment
- Save to `.nomark/gtm/<product>.md`
- Tell user: "Other marketing, growth, and SEO skills will now use this context automatically."

---

## AU-Specific Considerations

- For AU businesses, capture regulatory context (ASIC, APRA, ACCC, Privacy Act) in Product Overview
- Note whether pricing is AUD or USD and GST treatment
- Capture AU-specific competitor landscape (local vs global competitors)
- Note any industry-specific compliance (AFSL, ABN requirements, etc.)

---

## Related Skills

- **seo/ai-seo** — Uses this context for AI search optimisation
- **business/pricing-strategy** — Uses this for pricing decisions
- **growth/launch-strategy** — Uses this for launch planning
- **business/churn-prevention** — Uses this for retention messaging
