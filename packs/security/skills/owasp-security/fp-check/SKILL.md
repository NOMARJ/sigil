---
name: fp-check
description: "Mandatory false positive gate review for security findings. Part of the Nomark Method Layer 2 verification. Use after security scans produce findings, when triaging vulnerability reports, or when someone asks 'is this a real issue', 'false positive check', 'triage these findings'."
---

# False Positive Gate Review

Adapted from Trail of Bits' fp-check skill. Every security finding must pass through this gate — no exceptions. Untriaged findings are worse than no findings, because they train the team to ignore alerts.

## Why This Exists

Security scanners produce noise. When the noise-to-signal ratio gets too high, teams start ignoring findings entirely. The fp-check gate ensures every finding is classified, justified, and documented. The result is a security findings list where everything on it is real, and everything not on it was explicitly triaged and justified.

## Hard Exclusion Rules

Before manual triage, automatically exclude findings matching these patterns. These are categories with near-zero signal in practice:

| # | Category | Exclude If |
|---|---|---|
| 1 | DOS / Resource Exhaustion | Finding describes denial of service, resource exhaustion, unbounded loops, or memory/CPU overload |
| 2 | Rate Limiting | Finding recommends adding rate limits without a concrete exploit path |
| 3 | Resource Leaks | Unclosed files, connections, or memory leaks — not security vulnerabilities |
| 4 | Open Redirects | Unless extremely high confidence with a concrete phishing scenario |
| 5 | Regex Injection / ReDoS | Injecting into a regex or regex DOS — not exploitable in practice |
| 6 | Memory Safety in Safe Languages | Buffer overflow, use-after-free, etc. in Rust, Go, Python, JS/TS, Java, C# |
| 7 | Test-Only Files | Findings in unit tests, test fixtures, or test helpers |
| 8 | Markdown / Documentation | Findings in .md files |
| 9 | SSRF (path-only) | SSRF that only controls the URL path, not host or protocol |
| 10 | Prompt Injection | User content in AI system prompts — not a code vulnerability |
| 11 | Log Spoofing | Unsanitized user input in logs (unless it logs secrets/PII) |
| 12 | Missing Audit Logs | Absence of logging is not a vulnerability |
| 13 | Outdated Dependencies | Managed by dependency scanning tools, not code review |
| 14 | Client-Side Auth | Missing permission checks in JS/TS client code — backend handles it |
| 15 | GitHub Action Workflow | Unless a concrete untrusted-input attack path exists |
| 16 | Shell Script Injection | Unless untrusted input provably reaches the injection point |
| 17 | Env Vars / CLI Flags | Treated as trusted values — attacks requiring their control are invalid |

**Precedents (context-dependent keeps):**
- Logging secrets/passwords/PII in plaintext → **keep** (real vulnerability)
- React/Angular XSS → **exclude** unless using `dangerouslySetInnerHTML` or `bypassSecurityTrustHtml`
- Subtle web vulns (tabnabbing, XS-Leaks, prototype pollution) → **exclude** unless extremely high confidence
- Notebook (.ipynb) vulns → **exclude** unless concrete untrusted-input path

Any finding that matches a hard exclusion gets classified as **FP — Auto-Excluded** with the matching rule number as justification. No manual triage needed.

## Confidence Gate

Every finding that survives hard exclusions must receive a confidence score (1-10):
- **1-3**: Low confidence, likely false positive → auto-classify as FP
- **4-6**: Medium confidence, needs investigation → manual triage required
- **7**: Suspicious but conditional → include only if concrete exploit path documented
- **8-10**: High confidence, likely true vulnerability → proceed to classification

**Hard threshold: findings with confidence < 8 do not enter the triage backlog.** They are logged for audit but not actioned.

## Triage Protocol

For each finding that passes hard exclusions AND the confidence gate:

### Step 1: Reproduce
Can you demonstrate the vulnerability? Try to exploit it:
- For injection: can you craft input that triggers the flaw?
- For credential exposure: is this a real secret or a placeholder?
- For configuration: does this setting actually apply in the relevant environment?

### Step 2: Classify

**True Positive (TP)** — The finding is real and exploitable.
- Action: Fix it. Create a test that captures the security requirement. Enter TDD cycle.
- Priority: Based on severity and exploitability.

**False Positive (FP)** — The finding is not a real vulnerability in this context.
- Action: Document WHY it's a false positive. Add to allowlist with justification.
- Example justification: "This `eval()` call only receives output from our internal compiler, never user input. Input validation is enforced at [file:line]."
- Bad justification: "We don't think this is a problem." (Not specific enough.)

**Accepted Risk (AR)** — The finding is real but the business has decided to accept it.
- Action: Document the risk, the business justification, the mitigation (if any), and who approved it.
- Example: "This endpoint is rate-limited but not authenticated. Accepted because it serves public data, and adding auth would break existing integrations. Mitigated by rate limiting and monitoring. Approved by [name] on [date]."
- Requires: Explicit sign-off. Cannot be self-approved by the person who wrote the code.

### Step 3: Document

Every finding produces a triage record:

```json
{
  "finding_id": "layer1-insecure-defaults-001",
  "file": "src/auth/middleware.ts",
  "line": 47,
  "scanner": "insecure-defaults",
  "classification": "FP",
  "justification": "The catch block defaults to authenticated=false (deny), not true. Scanner misread the negation logic.",
  "triaged_by": "agent",
  "date": "2026-03-20",
  "added_to_allowlist": true
}
```

### Step 4: Update Allowlist

False positives go into `.nomark/security/allowlist.json` so they don't get re-flagged:

```json
{
  "allowlist": [
    {
      "pattern": "eval() in src/compiler/transform.ts",
      "reason": "Internal compiler output only — no user input path exists",
      "added": "2026-03-20",
      "review_by": "2026-06-20"
    }
  ]
}
```

Every allowlist entry has a `review_by` date. False positives don't stay on the allowlist forever — they get re-verified periodically because code changes and today's false positive might become tomorrow's real vulnerability.

## Output Format

```
FP-CHECK TRIAGE — [timestamp]
Findings reviewed: [count]

TP  — [1] findings confirmed real → fix required
FP  — [2] findings classified as false positive → allowlisted
AR  — [0] findings accepted as risk
OPEN — [0] findings still need triage

Triage complete: YES | NO (if NO, merge is blocked)
```
