---
name: scan-file
description: "Scan a specific file or code selection for security threats using Sigil. Use when reviewing a single script, config, skill manifest, or MCP server file before running or installing it. Trigger phrases (English): 'is this safe to install', 'scan this skill', 'vet this MCP server', 'check this package before installing', 'is this file safe', 'scan this file'. Trigger phrases (Chinese): '安全扫描', '这个插件安全吗', '这个技能安全吗', '扫描一下', '安装前检查'."
allowed-tools: Bash(sigil *)
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
