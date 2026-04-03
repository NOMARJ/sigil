---
name: differential-review
description: "Security-focused differential code review analyzing git diffs in context of the broader codebase. Part of the Nomark Method Layer 2 security verification. Use whenever reviewing a PR, preparing to merge, or someone asks for a 'security review of this diff', 'review these changes for security', or 'is this PR safe to merge'."
---

# Differential Security Review

Adapted from Trail of Bits' differential-review skill. Layer 2 analysis — runs on PRs and merges, examining not just what changed but what the change means in context.

## How This Differs from Layer 1

Layer 1 scans look at code in isolation — "is this line dangerous?" Layer 2 looks at the change in context — "does this change create a new attack surface, alter the security model, or introduce a vulnerability path that didn't exist before?"

## Review Methodology

### 1. Change Classification
Before diving into code, classify the change:
- **Security-critical:** Touches auth, authz, crypto, PII, payment, or infrastructure
- **Security-adjacent:** Touches input handling, API endpoints, data storage, or external integrations
- **Security-neutral:** UI changes, documentation, refactoring with no behavioral change

This classification determines review depth. Security-critical changes get line-by-line analysis. Security-neutral changes get a quick scan for accidental security regressions.

### 2. Attack Surface Analysis
For every change, ask:
- **New endpoints?** Every new route/endpoint is a new entry point for attackers
- **New data flows?** Does data move to a new destination? Does sensitive data reach a new component?
- **Changed trust boundaries?** Does this change what code is trusted vs. untrusted?
- **Changed permissions?** Does this alter who can do what?
- **New dependencies?** (Feeds into supply-chain audit)

### 3. Contextual Analysis
Read the diff in context of surrounding code:
- Does the changed function handle user input upstream?
- Are the changed values used in security-sensitive operations downstream?
- Does this change alter assumptions that other code relies on?
- Does the git history show this area has been fixed for security issues before? (Recurrence pattern)

### 4. Common Differential Vulnerabilities
Changes that look innocent but aren't:
- Adding a new API field that exposes internal data
- Changing a default value from deny to allow
- Adding a code path that bypasses existing validation
- Refactoring that removes a security check as "dead code"
- Adding logging that captures sensitive data
- Changing error handling from fail-closed to fail-open

### 5. Confidence Scoring

Every finding MUST receive a confidence score from 1-10:

| Score | Meaning | Action |
|---|---|---|
| 9-10 | Certain exploit path identified | Report as-is |
| 8 | Clear vulnerability pattern with known exploitation methods | Report as-is |
| 7 | Suspicious pattern requiring specific conditions | Include only with documented exploit path |
| 4-6 | Medium confidence, needs investigation | Flag for manual review, do not block |
| 1-3 | Low confidence, likely noise | Exclude from report |

**Hard threshold: ≥ 8.** Findings below 8 are excluded from the final report and do not contribute to the verdict. This prevents theoretical issues from blocking merges.

Run each finding through the `fp-check` skill's hard exclusion rules before scoring. Auto-excluded findings don't need a confidence score.

### 6. Review Artifact

```markdown
# Differential Security Review — PR #[number]

## Change Classification: [Security-critical | Security-adjacent | Security-neutral]

## Attack Surface Changes
- [New endpoints, data flows, trust boundary changes]

## Findings (confidence ≥ 8 only)
### [Finding title]
**File:** [path:line]
**Severity:** [CRITICAL | HIGH | MEDIUM | LOW]
**Confidence:** [8-10]
**Description:** [What the vulnerability is]
**Context:** [Why this matters given the broader codebase]
**Exploit Scenario:** [Concrete attack path]
**Recommendation:** [How to fix it]

## Excluded Findings
[Count] findings excluded by hard exclusion rules
[Count] findings excluded by confidence threshold (< 8)

## Security Checklist
- [ ] No new unauthenticated endpoints
- [ ] Input validation on all new user inputs
- [ ] No sensitive data in logs
- [ ] Error messages don't expose internals
- [ ] New dependencies reviewed
- [ ] Rate limiting on new endpoints (if applicable)
- [ ] RBAC/permissions verified for new operations
- [ ] Tenant isolation maintained (multi-tenant systems)
- [ ] AU Privacy Act / APPs compliance (if PII involved)

## Verdict: [APPROVE | REQUEST CHANGES | BLOCK]
Findings with confidence ≥ 8: [count]
Highest severity: [CRITICAL | HIGH | MEDIUM | NONE]
```
