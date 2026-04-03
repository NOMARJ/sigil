---
name: second-opinion
description: "Multi-model independent security review — routes code to a second LLM for review without sharing the primary model's analysis. Part of the Nomark Method Layer 3 verification. Use for security-critical changes (auth, payment, PII, crypto, infra), when someone asks for 'second opinion', 'independent review', 'multi-model check', or when Layer 1/2 findings flag critical issues."
---

# Second Opinion — Multi-Model Review

Adapted from Trail of Bits' second-opinion skill. The insight: every LLM has training-specific blind spots. A vulnerability that Claude misses, Codex might catch — and vice versa. Layer 3 exploits this by running an independent review on a separate model without sharing the first model's findings.

## Why Independence Matters

If you show Model B the findings from Model A, Model B's review is contaminated — it will anchor on what Model A found and confirm or deny, rather than doing its own analysis. True independent review means:

1. Model B receives the code and a security review prompt
2. Model B does NOT receive Model A's findings
3. The findings are compared AFTER both reviews complete
4. Disagreements are the most valuable output

## When to Use

Layer 3 is triggered for changes that touch:
- Authentication or authorization logic
- Payment or financial transaction processing
- PII or sensitive data handling
- Cryptographic operations
- Infrastructure or deployment configuration
- Any change flagged CRITICAL by Layer 1 or Layer 2

## Protocol

### Step 1: Prepare the Review Package
Extract from the codebase:
- The changed files (full diff)
- Surrounding context (the files the changes interact with)
- The project's security model (auth patterns, trust boundaries)
- Any relevant architecture documentation

Do NOT include: Layer 1/2 findings, the primary model's analysis, or any hints about what to look for.

### Step 2: Route to Independent Model
If available, use external LLM CLIs:

```bash
# Using OpenAI Codex CLI
codex --model o4-mini --prompt "Review this code for security vulnerabilities..." < review-package.md

# Using Google Gemini CLI
gemini --prompt "Security review of the following code changes..." < review-package.md
```

If external CLIs aren't available, simulate independence by:
- Starting a fresh context (new session) with no reference to prior analysis
- Using a different system prompt focused purely on security
- Treating the code as if you've never seen the project before

### Step 3: Compare Findings

Create a comparison matrix:

| Finding | Primary Model | Second Model | Agreement |
|---------|--------------|--------------|-----------|
| SQL injection in user search | ✅ Found | ✅ Found | AGREE — high confidence TP |
| Missing rate limit on /api/auth | ✅ Found | ❌ Missed | DISAGREE — investigate |
| CSRF on state-changing GET | ❌ Missed | ✅ Found | DISAGREE — investigate |
| eval() in template engine | ✅ Found (FP) | ✅ Found (TP) | DISAGREE on classification |

### Step 4: Investigate Disagreements

Disagreements require human judgment:
- **Primary found, Second missed:** Might be a genuine finding that Second's training didn't cover. Verify independently.
- **Second found, Primary missed:** Most valuable output — this is a blind spot in the primary model. Investigate thoroughly.
- **Different classification:** Both saw the code but reached different conclusions. Examine the reasoning of each.

### Step 5: Document

```markdown
# Multi-Model Security Review — [change ID]

## Models Used
- Primary: [model name and version]
- Secondary: [model name and version]

## Agreement Summary
- Agreed findings: [count]
- Primary-only findings: [count]
- Secondary-only findings: [count]
- Classification disagreements: [count]

## Disagreement Analysis
### [Finding]
**Primary assessment:** [what and why]
**Secondary assessment:** [what and why]
**Resolution:** [which is correct and why]

## Final Verdict: [VERIFIED | CONCERNS REMAIN]
```

## Fallback When External Models Unavailable

If you can't route to an external model, the next best thing is a structured adversarial review:
1. Adopt the mindset of a penetration tester who has never seen this codebase
2. Start from the public attack surface and work inward
3. Focus on: "If I were trying to exploit this change, what would I try?"
4. Document your adversarial analysis separately from your standard review
