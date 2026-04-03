---
description: 'Execute atomic stories in parallel via agent team with integrity checks'
---

# Team Build Mode — Parallel Atomic Story Execution

Execute multiple atomic stories from progress.md in parallel using specialized agents, each following integrity protocols.

## When to Use

- Stories span **2+ components** (e.g., Terraform + Python + n8n)
- Stories are **independent** and can run in parallel
- Feature requires **cross-cutting changes** with clear ownership boundaries

**Don't use when:** Stories are sequential dependencies or touch the same files.

## Pre-Flight Check

```bash
# Check progress.md exists with stories
cat progress.md || echo "⚠️ Create progress.md with /plan first"

# Check for TODO stories that can parallelize
grep -c "TODO" progress.md || echo "No TODO stories available"

# Check session health before spawning team
echo "Exchange count: [current]"
```

If exchange count > 20, consider completing current work and /clear first.

## Process

### 1. Load Context

```
1. Read progress.md (source of truth for stories)
2. Read CLAUDE.md (project conventions + verification)
3. Read tasks/lessons.md (correction rules)
4. Read progress.md (codebase patterns)
```

### 2. Analyze Stories for Team Assignment

**Review TODO stories from progress.md:**

```bash
grep -A5 "TODO" progress.md
```

For each TODO story, determine the **primary component**:

> **⚠️ CUSTOMIZATION REQUIRED**: The table below is an example for the Enclave project. You must customize the Component Match patterns and agent names for your project before using team-build mode.

| Component Match                      | Assign To        | File Ownership            |
| ------------------------------------ | ---------------- | ------------------------- |
| `devops-agent/terraform/`, `*.tf`    | infra-specialist | Terraform, Azure config   |
| `devops-mcp/`, `*.py` (MCP tools)    | mcp-developer    | Python MCP implementation |
| `devops-agent/n8n-workflows/`, Slack | workflow-builder | n8n, integrations         |
| Spans multiple / unclear             | Lead handles     | Requires sequential       |

**Dependency check:** If Story B depends on Story A's output (e.g., schema before API), Story A must complete first. Group dependent stories into sequential chains.

### 3. Build Team Composition

Only spawn teammates that have stories assigned:

```
Create an agent team for parallel atomic story execution.

## Team Integrity Protocol

EVERY teammate MUST follow this protocol:

### Before Starting
1. Read progress.md — get assigned story details
2. Update story status: IN PROGRESS 🔧
3. Read tasks/lessons.md — follow ALL correction rules
4. Read CLAUDE.md — use exact verification commands
5. Note the story's "Done when" condition

### During Implementation
6. Focus on ONE story only — no scope creep
7. Track "Current state" in progress.md
8. If editing same file 3+ times, flag to lead
9. Keep changes minimal to story requirements

### Verification Protocol
10. Run the story's "Done when" command
11. Capture full output (not summary)
12. Run project verification from CLAUDE.md
13. NEVER claim "done" without evidence

### After Completing
14. Update progress.md:
    - Status: DONE ✅
    - Evidence: [paste verification output]
    - Notes: [any gotchas]
15. Commit: git commit -m "feat: [STORY-XXX] title"
16. Report learnings to lead

### If Blocked
17. Update progress.md:
    - Status: BLOCKED 🚫
    - Blockers: [specific reason]
    - Notes: [approaches tried]
18. Message lead with unblock needs

## Teammates

### infra-specialist: [STORY-XXX, STORY-YYY]
- Own: devops-agent/terraform/, devops-agent/scripts/
- Verify: cd devops-agent/terraform && terraform fmt -check && terraform validate
- Context limit: Monitor for degradation, request checkpoint if needed

### mcp-developer: [STORY-XXX]
- Own: devops-mcp/devops_mcp/, devops-mcp/tests/
- Verify: cd devops-mcp && black --check . && ruff check . && pytest -v
- Context limit: Monitor for degradation, request checkpoint if needed

### workflow-builder: [STORY-XXX]
- Own: devops-agent/n8n-workflows/, nomark-method/scripts/
- Verify: JSON syntax check, webhook endpoint validation
- Context limit: Monitor for degradation, request checkpoint if needed

### qa-verifier: Continuous verification
- Monitor all teammates' progress.md updates
- Run verification after each DONE claim
- Flag any missing evidence immediately
- Run /tc quick on teammates showing degradation
```

### 4. Spawn Team

Spawn the team. The lead:

- Monitors teammate progress
- Resolves cross-team dependencies (if Story A must complete before Story B)
- Handles escalations (security concerns → security-reviewer, architecture → code-architect)
- Consolidates results when all teammates finish

### 5. Consolidate Results

After all teammates complete:

```bash
# 1. Check all story statuses in progress.md
grep -E "(DONE|BLOCKED|IN PROGRESS)" progress.md

# 2. Verify all DONE stories have evidence
grep -A3 "DONE" progress.md | grep "Evidence" || echo "⚠️ Missing evidence!"

# 3. Move completed stories to archive
# Update progress.md: move DONE stories to "Completed Stories Archive"

# 4. Consolidate learnings
# Append teammate discoveries to progress.md
# Update tasks/lessons.md with corrections

# 5. Final verification
npm run typecheck && npm run lint && npm test

# 6. Report
echo "TEAM COMPLETE: X stories DONE, Y BLOCKED"
```

## Escalation Paths

During team execution, the lead can escalate:

| Discovery                | Escalate To       | Action                                      |
| ------------------------ | ----------------- | ------------------------------------------- |
| Security concern in code | security-reviewer | Spawn as additional teammate                |
| Architecture question    | code-architect    | Consult before continuing                   |
| Cross-component conflict | Lead resolves     | Pause conflicting teammate, resolve, resume |
| Story too big            | Lead re-plans     | Break story, reassign sub-tasks             |

## Stop Conditions

**All stories complete:**

```
All assigned stories have passes: true
→ Output: "TEAM COMPLETE - X/Y stories implemented"
→ Run consolidated verification
```

**Partial completion:**

```
Some stories blocked or failed
→ Output: "PARTIAL - X completed, Y blocked: [reasons]"
→ Do NOT mark blocked stories as passes: true
```

**Re-plan trigger:**

```
Team discovers fundamental design issue, or
3+ stories are blocked by the same root cause
→ STOP team. Return to /plan. Re-plan with new knowledge.
```

## Team Integrity Rules

### MUST DO
- ✅ Every teammate updates progress.md in real-time
- ✅ Every teammate shows verification evidence
- ✅ qa-verifier checks for session degradation
- ✅ Lead monitors exchange counts across team
- ✅ Checkpoint if any teammate hits context limits
- ✅ Stories stay atomic (no scope expansion)

### NEVER DO
- ❌ Mark DONE without evidence in progress.md
- ❌ Let teammates continue past 30 exchanges
- ❌ Mix stories (one story per teammate at a time)
- ❌ Skip verification between stories
- ❌ Commit failing code
- ❌ Modify files outside assigned ownership

### Context Management

**Lead monitors for team degradation:**
- Teammate editing same file repeatedly
- Teammate claiming "done" without proof
- Teammate stuck in retry loops
- Exchange count approaching limits

**Action when degradation detected:**
1. Pause affected teammate
2. Have them update progress.md
3. Checkpoint their work
4. Consider spawning fresh teammate

### Conflict Resolution

If two teammates need same file:
1. Check if stories are truly independent
2. If not, sequence them (A completes, then B)
3. If yes, split file ownership by sections
4. Update progress.md with coordination notes
