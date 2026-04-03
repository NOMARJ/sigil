---
description: 'Spawn an agent team for infrastructure changes'
---

# Team: Infrastructure Change

Create an agent team for this infrastructure task. Spawn teammates:

1. **infra-specialist**: Owns Terraform and Azure resource changes in `devops-agent/terraform/`. Review existing configs before making changes. Run `terraform validate` and `terraform fmt` before marking tasks complete.

2. **security-reviewer**: Run SIGIL scan (`sigil scan .` or MCP `sigil_scan`) on all changes first. Then audit infrastructure changes for security compliance — check NSG rules, RBAC assignments, Key Vault references, network exposure, and Terraform-specific patterns (public access, permissive security groups, missing encryption). Run supplementary scanners if available (semgrep, trufflehog). Report combined SIGIL + Claude findings with severity ratings. Block completion if SIGIL score >= 26 or critical issues found.

3. **qa-verifier**: Run full verification stack after changes. Validate Terraform, check shell script syntax, ensure no secrets are hardcoded. Generate a verification report.

## Coordination Rules

- infra-specialist must get plan approval before making changes
- security-reviewer reviews changes as they're made
- qa-verifier runs final verification before any task is marked complete
- All teammates message each other when their work has cross-cutting impact

## Task Breakdown

Break the work into atomic tasks:

1. Research current state and identify what needs to change
2. Plan the implementation approach
3. Implement infrastructure changes
4. Security review of changes
5. Full verification pass
6. Documentation updates

$ARGUMENTS
