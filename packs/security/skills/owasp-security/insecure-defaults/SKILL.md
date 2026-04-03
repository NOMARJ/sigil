---
name: insecure-defaults
description: "Detect insecure default configurations, hardcoded credentials, fail-open security patterns, and dangerous defaults in code and config files. Part of the Nomark Method Layer 1 security scanning. Use whenever code is committed, config files change, or someone says 'check for secrets', 'credential scan', 'security defaults check', or 'are there any hardcoded keys'."
---

# Insecure Defaults Scanner

Adapted from Trail of Bits' insecure-defaults skill. Layer 1 automated scan — runs on every change, zero human intervention.

## What You're Looking For

### Hardcoded Credentials
- API keys, tokens, passwords in source code
- Connection strings with embedded passwords
- Private keys, certificates, or secrets committed to repo
- `.env` files or secret configs in version control
- Base64-encoded credentials (people think encoding = hiding)

### Fail-Open Patterns
- Authentication that defaults to "allow" on error
- Authorization checks with catch-all `true` returns
- CORS set to `*` in production configs
- Security middleware that can be bypassed with specific headers
- Feature flags that default to "enabled" for premium features

### Dangerous Defaults
- Debug mode enabled in production configs
- Verbose error messages exposing internals
- Default admin credentials still active
- HTTPS not enforced (HTTP fallback allowed)
- Session tokens with excessive lifetimes
- Missing rate limiting on authentication endpoints
- Permissive Content-Security-Policy headers

### Configuration Issues
- Production configs committed alongside development configs
- Secrets in docker-compose files, Kubernetes manifests, or CI configs
- Database connections without SSL/TLS enforcement
- Logging configuration that captures sensitive data (PII, tokens, passwords)

## Scan Protocol

```
1. Identify all files in the change set
2. For each file, apply pattern matching:
   - Regex patterns for common secret formats (AWS keys, JWT tokens, etc.)
   - AST analysis for authentication/authorization logic patterns
   - Config file analysis for dangerous settings
3. Classify findings:
   - CRITICAL: Hardcoded secret or credential → Block commit
   - WARNING: Fail-open pattern or dangerous default → Flag for review
   - INFO: Potential issue, needs context → Log
4. Output findings in structured format
```

## Common False Positives

These look like secrets but usually aren't — verify before flagging:
- Example/placeholder values in documentation or tests (`sk_test_...`, `AKIAIOSFODNN7EXAMPLE`)
- Hash constants (SHA-256 of known values)
- Base64-encoded non-secret data
- Environment variable references (`process.env.SECRET` is fine; the actual value is not)

When flagging, always check: is this a reference to a secret (safe) or the secret itself (dangerous)?

## Output Format

```
INSECURE-DEFAULTS SCAN — [timestamp]
Files scanned: [count]

🔴 CRITICAL — [file:line] Hardcoded AWS access key detected
   Pattern: AKIA[0-9A-Z]{16}
   Action: Remove credential, rotate key immediately, add to .gitignore

🟡 WARNING — [file:line] Authentication defaults to allow on exception
   Pattern: catch block returns `authenticated = true`
   Action: Review — fail-closed is the safe default

🟢 CLEAN — No additional findings
```
