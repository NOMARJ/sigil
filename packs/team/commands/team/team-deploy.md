---
description: 'Spawn an agent team for deployment preparation'
---

# Team: Deployment Preparation

Create an agent team to prepare for deployment. Spawn teammates:

1. **qa-verifier**: Run complete verification stack across all components. Generate a verification report. Block if any checks fail.

2. **security-reviewer**: Run SIGIL scan (`sigil scan .` or MCP `sigil_scan`) first for supply chain and code injection analysis. Then run Claude security checks (OWASP top 10, language-specific, secrets detection). Check for exposed secrets, open ports, missing auth, and Key Vault references. Generate combined SIGIL + Claude security sign-off with risk score.

3. **infra-specialist**: Run `terraform plan` to preview infrastructure changes. Review the plan output for unexpected changes. Verify resource sizing and cost implications.

4. **workflow-builder**: Verify n8n workflow JSON validity. Check webhook endpoints and notification pipelines are correctly configured. Verify Ralph agent script is up to date.

## Deployment Checklist

Each teammate validates their domain and reports ready/not-ready:

- [ ] All tests pass (qa-verifier)
- [ ] SIGIL scan risk score < 26 (security-reviewer)
- [ ] No Claude security findings above Medium (security-reviewer)
- [ ] No quarantined files remain unresolved (security-reviewer)
- [ ] Terraform plan shows expected changes only (infra-specialist)
- [ ] Workflows and integrations validated (workflow-builder)
- [ ] No uncommitted changes on any branch
- [ ] All tasks in shared list are complete

## Security Gate (SIGIL + Claude)

SIGIL scan is a **hard gate** for deployment:

- **Score 0-25**: PASS — deploy allowed
- **Score 26-49**: BLOCK — remediation required before deploy
- **Score 50+**: CRITICAL BLOCK — quarantine files, notify lead, no deploy

Claude security checks are a **soft gate**:

- Critical/High findings: BLOCK — must fix before deploy
- Medium findings: WARNING — fix recommended but not blocking
- Low findings: NOTE — track for improvement

The lead should NOT approve deployment unless all teammates report ready and both security gates pass.

$ARGUMENTS
