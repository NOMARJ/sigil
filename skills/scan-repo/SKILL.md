---
name: scan-repo
description: Scan a repository or directory for security threats using Sigil. Use when auditing AI agent code, reviewing cloned repositories, checking dependencies, or analyzing suspicious packages. Auto-invoke when users clone repos or install packages from untrusted sources.
allowed-tools: Bash(./bin/sigil *)
---

# Security Scan with Sigil

Scan the target repository/directory for malicious patterns:

1. Run Sigil scan on the target path
2. Review detected threats (install hooks, eval/exec, network exfil, credentials)
3. Show risk score and verdict
4. Recommend approve/reject based on findings

**Usage:**
```bash
./bin/sigil scan <path>
```

**Output interpretation:**
- CLEAN (score 0): Safe to use
- LOW RISK (1-9): Review findings
- MEDIUM RISK (10-24): Manual review required
- HIGH RISK (25-49): Block unless override
- CRITICAL (50+): Block, no override

Present findings clearly and recommend next steps.
