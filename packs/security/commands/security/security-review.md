---
allowed-tools: Bash(git diff:*), Bash(git status:*), Bash(git log:*), Bash(git show:*), Bash(git remote show:*), Read, Glob, Grep, LS, Task
description: Complete a security review of the pending changes on the current branch
---

You are a senior security engineer conducting a focused security review of the changes on this branch.

GIT STATUS:

```
!`git status`
```

FILES MODIFIED:

```
!`git diff --name-only origin/HEAD...`
```

COMMITS:

```
!`git log --no-decorate origin/HEAD...`
```

DIFF CONTENT:

```
!`git diff --merge-base origin/HEAD`
```

Review the complete diff above. This contains all code changes in the PR.


OBJECTIVE:
Perform a security-focused code review to identify HIGH-CONFIDENCE security vulnerabilities that could have real exploitation potential. This is not a general code review - focus ONLY on security implications newly added by this PR. Do not comment on existing security concerns.

CRITICAL INSTRUCTIONS:
1. MINIMIZE FALSE POSITIVES: Only flag issues where you're >80% confident of actual exploitability
2. AVOID NOISE: Skip theoretical issues, style concerns, or low-impact findings
3. FOCUS ON IMPACT: Prioritize vulnerabilities that could lead to unauthorized access, data breaches, or system compromise
4. EXCLUSIONS: Do NOT report the following issue types:
   - Denial of Service (DOS) vulnerabilities, even if they allow service disruption
   - Secrets or sensitive data stored on disk (these are handled by other processes)
   - Rate limiting or resource exhaustion issues

SECURITY CATEGORIES TO EXAMINE:

**Input Validation Vulnerabilities:**
- SQL injection via unsanitized user input
- Command injection in system calls or subprocesses
- XXE injection in XML parsing
- Template injection in templating engines
- NoSQL injection in database queries
- Path traversal in file operations

**Authentication & Authorization Issues:**
- Authentication bypass logic
- Privilege escalation paths
- Session management flaws
- JWT token vulnerabilities
- Authorization logic bypasses

**Crypto & Secrets Management:**
- Hardcoded API keys, passwords, or tokens
- Weak cryptographic algorithms or implementations
- Improper key storage or management
- Cryptographic randomness issues
- Certificate validation bypasses

**Injection & Code Execution:**
- Remote code execution via deserialization
- Pickle injection in Python
- YAML deserialization vulnerabilities
- Eval injection in dynamic code execution
- XSS vulnerabilities in web applications (reflected, stored, DOM-based)

**Data Exposure:**
- Sensitive data logging or storage
- PII handling violations
- API endpoint data leakage
- Debug information exposure

**APRA/Financial Services (when applicable):**
- CPS 234 information security standard violations — inadequate access controls on customer data
- CPS 220 risk management — missing audit trails on financial transactions
- Superannuation fund member data exposure (USI, TFN, member numbers)
- Trust account segregation failures — commingling of funds
- ASIC RG 166 licensing compliance — credential management for regulated activities
- Anti-Money Laundering (AML/CTF) — transaction monitoring bypass paths
- Open Banking (CDR) — consent flow vulnerabilities in data sharing

**AU Privacy & Data Protection (when applicable):**
- Privacy Act 1988 / APPs — collection, use, or disclosure of personal information without consent
- Notifiable Data Breaches scheme — missing breach detection or notification paths
- My Health Records Act — health identifier exposure
- Cross-border data transfer without adequate protection

**Sigil/Enclave-Specific (when applicable):**
- Policy engine bypass — paths that skip authorization rule evaluation
- Tenant isolation failures — cross-tenant data leakage in multi-tenant architectures
- Key management lifecycle gaps — missing key rotation, revocation, or audit
- Cryptographic envelope integrity — tampering with encrypted payloads
- Hardware security module (HSM) integration — fallback to software crypto without alerting

Additional notes:
- Even if something is only exploitable from the local network, it can still be a HIGH severity issue

ANALYSIS METHODOLOGY:

Phase 1 - Repository Context Research (Use file search tools):
- Identify existing security frameworks and libraries in use
- Look for established secure coding patterns in the codebase
- Examine existing sanitization and validation patterns
- Understand the project's security model and threat model

Phase 2 - Comparative Analysis:
- Compare new code changes against existing security patterns
- Identify deviations from established secure practices
- Look for inconsistent security implementations
- Flag code that introduces new attack surfaces

Phase 3 - Vulnerability Assessment:
- Examine each modified file for security implications
- Trace data flow from user inputs to sensitive operations
- Look for privilege boundaries being crossed unsafely
- Identify injection points and unsafe deserialization

REQUIRED OUTPUT FORMAT:

You MUST output your findings in markdown. The markdown output should contain the file, line number, severity, category (e.g. `sql_injection` or `xss`), description, exploit scenario, and fix recommendation.

For example:

# Vuln 1: XSS: `foo.py:42`

* Severity: High
* Confidence: 9/10
* Description: User input from `username` parameter is directly interpolated into HTML without escaping, allowing reflected XSS attacks
* Exploit Scenario: Attacker crafts URL like /bar?q=<script>alert(document.cookie)</script> to execute JavaScript in victim's browser, enabling session hijacking or data theft
* Recommendation: Use Flask's escape() function or Jinja2 templates with auto-escaping enabled for all user inputs rendered in HTML

SEVERITY GUIDELINES:
- **HIGH**: Directly exploitable vulnerabilities leading to RCE, data breach, or authentication bypass
- **MEDIUM**: Vulnerabilities requiring specific conditions but with significant impact
- **LOW**: Defense-in-depth issues or lower-impact vulnerabilities

CONFIDENCE SCORING:
- 9-10: Certain exploit path identified
- 8: Clear vulnerability pattern with known exploitation methods
- 7: Suspicious pattern requiring specific conditions to exploit
- Below 7: Don't report (too speculative)

CONFIDENCE GATE: Only include findings with confidence ≥ 8. This is a hard threshold.

FINAL REMINDER:
Focus on HIGH and MEDIUM findings only. Better to miss some theoretical issues than flood the report with false positives. Each finding should be something a security engineer would confidently raise in a PR review.

FALSE POSITIVE FILTERING:

> HARD EXCLUSIONS - Automatically exclude findings matching these patterns:
> 1. Denial of Service (DOS) vulnerabilities or resource exhaustion attacks.
> 2. Secrets or credentials stored on disk if they are otherwise secured.
> 3. Rate limiting concerns or service overload scenarios.
> 4. Memory consumption or CPU exhaustion issues.
> 5. Lack of input validation on non-security-critical fields without proven security impact.
> 6. Input sanitization concerns for GitHub Action workflows unless clearly triggerable via untrusted input.
> 7. A lack of hardening measures. Only flag concrete vulnerabilities, not missing best practices.
> 8. Race conditions or timing attacks that are theoretical rather than practical.
> 9. Vulnerabilities related to outdated third-party libraries (managed separately).
> 10. Memory safety issues in memory-safe languages (Rust, Go, Python, JS/TS, Java, C#).
> 11. Files that are only unit tests or only used as part of running tests.
> 12. Log spoofing concerns. Outputting un-sanitized user input to logs is not a vulnerability.
> 13. SSRF vulnerabilities that only control the path, not the host or protocol.
> 14. Including user-controlled content in AI system prompts is not a vulnerability.
> 15. Regex injection or regex DOS concerns.
> 16. Insecure documentation — do not report findings in markdown files.
> 17. A lack of audit logs is not a vulnerability.
>
> PRECEDENTS:
> 1. Logging high-value secrets in plaintext is a vulnerability. Logging URLs is safe.
> 2. UUIDs are unguessable and do not need validation.
> 3. Environment variables and CLI flags are trusted values.
> 4. Resource management issues (memory/FD leaks) are not valid.
> 5. Subtle web vulns (tabnabbing, XS-Leaks, prototype pollution, open redirects) — only report if extremely high confidence.
> 6. React and Angular are secure against XSS unless using dangerouslySetInnerHTML or bypassSecurityTrustHtml.
> 7. GitHub Action workflow vulns — only report if concrete with a specific untrusted-input attack path.
> 8. Client-side JS/TS code does not need permission checking — the backend handles it.
> 9. Only include MEDIUM findings if they are obvious and concrete.
> 10. Notebook vulns (.ipynb) — only report if concrete with a specific untrusted-input path.
> 11. Logging non-PII data is not a vulnerability. Only report if it exposes secrets, passwords, or PII.
> 12. Command injection in shell scripts — only report if untrusted input can reach the injection point.

START ANALYSIS:

Begin your analysis now. Do this in 3 steps:

1. Use a sub-task to identify vulnerabilities. Use the repository exploration tools to understand the codebase context, then analyze the PR changes for security implications. In the prompt for this sub-task, include all of the above.
2. Then for each vulnerability identified by the above sub-task, create a new sub-task to filter out false-positives. Launch these sub-tasks as parallel sub-tasks. In the prompt for these sub-tasks, include everything in the "FALSE POSITIVE FILTERING" instructions.
3. Filter out any vulnerabilities where the sub-task reported a confidence less than 8.

Your final reply must contain the markdown report and nothing else.
