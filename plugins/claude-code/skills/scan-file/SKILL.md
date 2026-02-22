---
description: Scan a specific file or code selection for security threats
---

# Scan File with Sigil

Analyze a specific file for security vulnerabilities:

Target: "$ARGUMENTS"

Run: `sigil scan <file-path>` on the specified file.

Check for:
1. **Code Patterns** - eval, exec, pickle, subprocess
2. **Network Access** - HTTP requests, webhooks, socket connections
3. **Credential Exposure** - API keys, tokens, hardcoded secrets
4. **Obfuscation** - base64 encoding, hex strings, charCode
5. **Dangerous Imports** - suspicious modules or libraries

Present findings with:
- Severity level (CLEAN, LOW, MEDIUM, HIGH, CRITICAL)
- Line numbers and code snippets
- Risk explanation
- Remediation recommendations

If the file is CRITICAL or HIGH risk, explain the specific threat and recommend quarantine.
