---
name: generate-policy
description: Generate a Sigil sandbox policy YAML from scan results for secure agent execution
allowed-tools: Bash(./bin/sigil *), Read, Write, Glob
---

# Generate Sandbox Policy

Generate a Sigil security policy YAML file based on scan results. The policy controls filesystem, network, process, and credential access for sandboxed agent execution.

## Process

1. **Scan the target** — Run `./bin/sigil scan <path>` to get findings
2. **Analyze findings** — Map each finding to a policy restriction:
   - Phase 1 (Install Hooks) → Filesystem restrictions (read-only paths)
   - Phase 3 (Network) → Network allowlist (only permit known-good endpoints)
   - Phase 4 (Credentials) → Credential policy (restrict env var access)
   - Phase 5 (Obfuscation) → Process restrictions (sandboxed user)
3. **Generate policy YAML** with the following structure:

```yaml
version: "1.0"
name: "<project-name>-policy"
description: "Auto-generated from Sigil scan on <date>"

filesystem:
  read_only:
    - /usr
    - /lib
    - /etc
  read_write:
    - /tmp
  include_workdir: true

network:
  default_action: deny
  rules:
    - name: "<endpoint-name>"
      host: "<hostname>"
      port: 443
      access: read-only
      enforcement: enforce

process:
  run_as_user: sandbox
  run_as_group: sandbox
  deny_syscall_categories:
    - privilege_escalation

credentials:
  allowed_env:
    - TERM
    - PATH
    - HOME
  denied_env: []
  providers: []
```

4. **Write the policy** to `sigil-policy.yaml` in the project root
5. **Explain the policy** — For each section, explain what it restricts and why

## Policy Severity Mapping

| Scan Verdict | Network Policy | Credential Policy | Process Policy |
|-------------|---------------|-------------------|----------------|
| CLEAN | permissive | allow common | standard |
| LOW RISK | standard endpoints | allow declared | standard |
| MEDIUM RISK | strict allowlist | minimal | sandboxed user |
| HIGH RISK | deny all | deny all | full restrictions |
| CRITICAL | deny all + log | deny all | full restrictions |

## Rules
- Always explain WHY each restriction exists (reference the specific finding)
- For CLEAN scans, still generate a minimal security policy
- Include comments in the YAML explaining each rule
- Suggest the user review and customize before applying
