---
description: 'Diagnose and fix cross-component bugs with a specialized team'
---

# Team Bugfix Mode

Spawn a diagnostic team for bugs that span multiple components. No PRD required.

## When to Use

- Bug symptom appears in one component but root cause may be in another
- Error traces cross infrastructure → application → workflow boundaries
- Multiple related bugs that may share a root cause
- Production incident requiring parallel investigation

**Don't use when:** Bug is clearly isolated to one component — use `/bugfix` instead.

## Process

### 1. Gather Evidence

```
1. Read the bug report / error message / incident description
2. Read tasks/lessons.md for similar past bugs
3. Identify which components COULD be involved
4. Collect: logs, stack traces, error messages, failing tests
```

### 2. Triage — Determine Team Composition

| Symptom Pattern             | Likely Components     | Team                                           |
| --------------------------- | --------------------- | ---------------------------------------------- |
| API errors + infra timeouts | MCP + Azure           | mcp-developer + infra-specialist               |
| Workflow fails silently     | n8n + Slack + MCP     | workflow-builder + mcp-developer               |
| Auth/permission denied      | OAuth + RBAC + NSG    | security-reviewer + infra-specialist           |
| Tests pass but prod fails   | Config + Infra + Code | qa-verifier + infra-specialist + mcp-developer |
| Everything broken           | Full stack            | All teammates                                  |

### 3. Spawn Diagnostic Team

```
Create an agent team to diagnose and fix: [bug description]

## Bug Evidence
[Paste error messages, logs, stack traces]

## Team NOMARK Discipline

EVERY teammate MUST:
1. Read tasks/lessons.md FIRST — check for known similar bugs
2. Read CLAUDE.md for project verification commands
3. Diagnose root cause — don't fix symptoms
4. Run verification after applying fix
5. Document finding in tasks/lessons.md format

## Diagnostic Teammates

### [Role]: Investigate [component]
- Search for: [specific error patterns, file paths, config issues]
- Check: [what to validate in this component]
- Report: Root cause finding OR "Not in my component"

### qa-verifier: Reproduce and verify
- Reproduce the bug with a test case if possible
- After fixes applied, run full verification stack
- Confirm the original bug is resolved
- Check for regressions
```

### 4. Parallel Investigation

Each teammate investigates their component independently:

```
Teammate finds root cause
  → Messages lead with: FOUND: [component]:[file]:[line] — [explanation]
  → Lead coordinates fix (may involve multiple teammates)

Teammate rules out their component
  → Messages lead with: CLEAR: [component] — [evidence why it's not here]
  → Lead narrows search to remaining components
```

### 5. Coordinated Fix

Once root cause is found:

```
1. Lead assigns fix to the teammate who owns the affected files
2. If fix spans components:
   a. Sequence the changes (schema → API → workflow)
   b. Each teammate fixes their part
   c. qa-verifier validates after each step
3. Fixing teammate runs component verification
4. qa-verifier runs cross-component verification
```

### 6. Document and Close

```
1. Commit: git commit -m "fix: [brief description of what was wrong]"
2. Update tasks/lessons.md:
   - [Date] Bug: [symptom] → Root: [actual cause in component:file]
   - → Fix: [what we changed] → Rule: [how to prevent]
3. Update progress.md if reusable pattern discovered
4. If bug revealed an architectural issue → flag for /plan
```

## Escalation Within Team

| During Investigation                      | Action                                                           |
| ----------------------------------------- | ---------------------------------------------------------------- |
| Teammate finds security vulnerability     | Immediately notify security-reviewer (spawn if not on team)      |
| Root cause is architectural (design flaw) | STOP fix. Flag for /plan with /think first principles analysis   |
| Bug is in external dependency             | Document workaround, file upstream issue                         |
| Can't reproduce                           | qa-verifier creates minimal reproduction, team investigates that |

## Rules

- EVERY teammate reads tasks/lessons.md FIRST
- Diagnose root cause — NEVER fix symptoms
- Use project verification commands from CLAUDE.md
- Document the bug and fix in tasks/lessons.md ALWAYS
- If the bug reveals a design flaw, escalate to /plan — don't patch over it
- One commit for the fix, clear message explaining what was wrong
- qa-verifier must confirm the original bug is gone AND no regressions
