# DevOps Agent Teams

Skill for orchestrating Claude Code agent teams on DevOps tasks with NOMARK discipline.

## NOMARK Integration

Teams are the **execution model**. NOMARK is the **discipline**. Every teammate follows NOMARK.

### Pipeline Decision Points

```
/think (solo)
    │
/plan  (solo + code-explorer, or team-explore for multi-component)
    │
    ├─ Single component? → /build (solo NOMARK)
    ├─ Multi component?  → /team-build (parallel, each teammate follows NOMARK)
    │
/verify or /team-review
    │
/commit → /pr
```

### When to Use Teams vs Solo

| Signal                            | Use  | Command        |
| --------------------------------- | ---- | -------------- |
| All stories touch same files      | Solo | `/build`       |
| Stories span 2+ components        | Team | `/team-build`  |
| Bug in one component              | Solo | `/bugfix`      |
| Bug spans infra + code + workflow | Team | `/team-bugfix` |
| Pre-PR check, single component    | Solo | `/verify`      |
| Pre-PR check, multi component     | Team | `/team-review` |
| Deployment readiness              | Team | `/team-deploy` |

## When to Use Teams

Use agent teams when the task involves **parallel, independent work** across multiple components:

| Scenario                     | Team Structure                                       |
| ---------------------------- | ---------------------------------------------------- |
| Infrastructure + MCP changes | infra-specialist + mcp-developer                     |
| Security audit               | security-reviewer + infra-specialist + mcp-developer |
| New integration (end-to-end) | workflow-builder + mcp-developer + qa-verifier       |
| Major refactor               | mcp-developer + qa-verifier + security-reviewer      |
| Full release prep            | all 5 roles                                          |
| Cross-component bug          | relevant specialists + qa-verifier                   |

## Story-to-Teammate Routing

When `/team-build` analyzes PRD stories, route by file ownership:

| Story Touches                                    | Assign To                      |
| ------------------------------------------------ | ------------------------------ |
| `devops-agent/terraform/`, `*.tf` files          | infra-specialist               |
| `devops-mcp/devops_mcp/`, Python MCP code        | mcp-developer                  |
| `devops-agent/n8n-workflows/`, Slack integration | workflow-builder               |
| Security config, Key Vault, RBAC, NSG            | security-reviewer              |
| Multiple components / unclear                    | Lead decomposes into sub-tasks |

**Dependency ordering:** If Story B depends on Story A (e.g., schema before API):

1. Story A teammate completes first
2. qa-verifier validates Story A
3. Story B teammate starts
4. Remaining independent stories run in parallel

## Team NOMARK Discipline

**EVERY teammate MUST follow this protocol:**

### Before Starting

1. Read `tasks/lessons.md` — follow ALL correction rules
2. Read `CLAUDE.md` — use project verification commands (NOT npm defaults)
3. Read `progress.md` Codebase Patterns section

### During Work

4. Implement following existing codebase patterns
5. ONLY modify files you own (see File Ownership)
6. Run your component's verification after each change

### After Completing

7. Commit with conventional message: `feat(<story-id>): <title>`
8. Append learnings to `progress.md` (don't overwrite teammates)
9. Note new patterns for lead to consolidate

### If Blocked

10. Output "BLOCKED: [reason]"
11. Message lead with what's needed

## Team Spawn Templates

### Infrastructure Change

```
Create an agent team for this infrastructure change. Spawn:
- An infra-specialist to modify the Terraform and Azure resources
- A security-reviewer to audit the changes for compliance
- A qa-verifier to validate everything passes
All teammates: read tasks/lessons.md first, use CLAUDE.md verification commands.
Require plan approval for the infra-specialist before they make changes.
```

### New MCP Tool

```
Create an agent team to add a new MCP tool. Spawn:
- An mcp-developer to implement the tool handler and tests
- A workflow-builder to create n8n workflow integration
- A qa-verifier to run the full test suite
All teammates: read tasks/lessons.md first, use CLAUDE.md verification commands.
```

### Security Audit

```
Create an agent team for a security audit. Spawn:
- A security-reviewer to scan for vulnerabilities and credential issues
- An infra-specialist to review network exposure and Azure RBAC
- A mcp-developer to review OAuth and API auth implementation
All teammates: read tasks/lessons.md first.
Have them share and challenge each other's findings.
```

### Cross-Component Bugfix

```
Create an agent team to diagnose: [bug description]. Spawn:
- Specialists for each potentially affected component
- A qa-verifier to reproduce and verify the fix
All teammates: read tasks/lessons.md for similar past bugs.
Each investigates independently, reports FOUND or CLEAR to lead.
```

## File Ownership

To prevent conflicts, teammates should own distinct file sets:

| Role              | Owns                                                    | Verification                                 |
| ----------------- | ------------------------------------------------------- | -------------------------------------------- |
| infra-specialist  | `devops-agent/terraform/`, `devops-agent/scripts/`      | `terraform fmt -check && terraform validate` |
| mcp-developer     | `devops-mcp/devops_mcp/`, `devops-mcp/tests/`           | `black --check . && ruff check . && pytest`  |
| security-reviewer | Read-only across all (reports findings)                 | Secret scanning, RBAC review                 |
| workflow-builder  | `devops-agent/n8n-workflows/`, `nomark-method/scripts/` | JSON validation, webhook checks              |
| qa-verifier       | Read-only across all (runs verification)                | Full cross-component stack                   |

## Escalation Paths

During team execution, the lead handles escalations:

| Discovery                | Escalate To                   | Action                                    |
| ------------------------ | ----------------------------- | ----------------------------------------- |
| Security vulnerability   | security-reviewer             | Spawn if not on team, block deployment    |
| Architecture concern     | code-architect (NOMARK agent) | Consult before continuing                 |
| Cross-component conflict | Lead resolves                 | Pause conflicting teammate, sequence work |
| Story too big            | Lead re-plans                 | Return to `/plan`, break into sub-tasks   |
| Bug found during build   | qa-verifier                   | Diagnose, may trigger `/team-bugfix`      |

## Skills Library

Teammates should reference `flowmetrics-skills/` for reusable patterns:

| Teammate         | Relevant Skills                                             |
| ---------------- | ----------------------------------------------------------- |
| infra-specialist | `patterns/terraform/`, `integrations/azure/`                |
| mcp-developer    | `patterns/python/`, `integrations/n8n/`                     |
| workflow-builder | `integrations/n8n/`, `workflows/`, `integrations/metabase/` |
| qa-verifier      | `data/validation/`                                          |

## Task Sizing

- 5-6 tasks per teammate keeps everyone productive
- Each task should produce a clear deliverable
- Dependencies should be explicit (schema before API, API before workflow)
- Lead sequences dependent work, parallelizes independent work

## Team Consolidation

After all teammates complete, the lead MUST:

1. Update `prd.json` — set `passes: true` for completed stories
2. Consolidate `progress.md` — merge entries from all teammates
3. Merge lessons into `tasks/lessons.md` — deduplicate, resolve conflicts
4. Run `/team-review` if changes are significant
5. Report: X/Y stories complete, Z blocked, new patterns discovered
