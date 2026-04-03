---
description: 'Spawn an agent team for parallel code review'
---

# Team: Parallel Code Review

Create an agent team to review changes across the DevOps stack. Spawn reviewers:

1. **security-reviewer**: Run SIGIL scan (`sigil scan .` or MCP `sigil_scan`) for supply chain and code injection analysis. Then run Claude security checks — OWASP top 10, language-specific vulnerability patterns, secrets detection. Also review credential handling, network exposure, RBAC, and auth flows. Report combined SIGIL risk score + Claude findings with severity.

2. **mcp-developer**: Review Python code quality, MCP tool implementation patterns, type safety, error handling, and test coverage in `devops-mcp/`.

3. **infra-specialist**: Review Terraform changes for best practices, cost implications, naming conventions, and resource configuration in `devops-agent/terraform/`.

4. **qa-verifier**: Run the full verification stack (black, ruff, pytest, terraform validate, shell syntax). Report pass/fail for each component.

## Review Process

Each reviewer works independently on their domain then shares findings. The lead synthesizes a final review summary.

Have reviewers challenge each other's findings where domains overlap (e.g., security implications of infrastructure choices).

## Output

Produce a consolidated review report with:

- **SIGIL scan results** — risk score, quarantined files, supply chain findings
- **Claude security analysis** — OWASP checks, language-specific findings, secrets status
- Component-level pass/fail
- Security findings by severity (combined SIGIL + Claude)
- Code quality observations
- Verification results
- Final recommendation: APPROVE / REQUEST CHANGES / BLOCK

$ARGUMENTS
