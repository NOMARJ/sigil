# Team Coordination Protocol

Rules for how teammates communicate, share memory, and handle conflicts.

## Shared Memory Model

Teams share state through files. Each file has ownership rules:

### Write Rules

| File               | Who Writes    | How                                       |
| ------------------ | ------------- | ----------------------------------------- |
| `prd.json`         | Lead only     | After teammate reports story complete     |
| `progress.md`     | All teammates | Append only, include teammate role prefix |
| `tasks/lessons.md` | All teammates | Append only, lead consolidates at end     |
| `tasks/todo.md`    | Lead only     | Tracks team-level task assignment         |
| `CLAUDE.md`        | Lead only     | After team consolidation                  |

### Progress Entry Format (Teammates)

```markdown
## [Date] - [Story ID] (by [role])

- What was implemented
- Files changed
- **Learnings:**
  - Patterns discovered
  - Gotchas encountered

---
```

### Lessons Entry Format (Teammates)

```markdown
- [Date] [role]: [what happened] → [what we learned] → Rule: [prevention]
```

## Dependency Management

### Declaring Dependencies

When a story depends on another teammate's output:

```
Lead identifies dependency chain:
  US-001 (infra-specialist): Create database schema
  US-002 (mcp-developer): Build API on top of schema  ← DEPENDS ON US-001
  US-003 (workflow-builder): Wire n8n to API           ← DEPENDS ON US-002
  US-004 (infra-specialist): Configure NSG rules       ← INDEPENDENT
```

### Execution Order

```
Phase 1 (parallel): US-001 + US-004 (independent stories)
  ↓ qa-verifier validates
Phase 2: US-002 (now US-001 is complete)
  ↓ qa-verifier validates
Phase 3: US-003 (now US-002 is complete)
  ↓ qa-verifier validates all
```

### Handoff Protocol

When teammate A completes work that teammate B depends on:

1. Teammate A commits and messages lead: "DONE: [story-id] — [files changed]"
2. Lead notifies teammate B: "UNBLOCKED: [story-id] complete, you can start [dependent-story]"
3. Teammate B reads the committed files and proceeds

## Conflict Resolution

### File Conflicts

If two teammates need to modify the same file:

1. **Prevention:** Lead assigns file ownership before team starts
2. **Detection:** If discovered mid-work, the second teammate stops
3. **Resolution:** Lead sequences the work — teammate A finishes first, teammate B goes after
4. **Git conflicts:** Lead resolves, not individual teammates

### Disagreements

If teammates have conflicting findings (e.g., security-reviewer says "block" but infra-specialist says "it's fine"):

1. Both document their reasoning
2. Lead evaluates both positions
3. Default to the more conservative position (security wins ties)
4. Document the decision in `tasks/lessons.md`

## Communication Format

### Status Messages

Teammates communicate with the lead using these formats:

```
DONE: [story-id] — [brief summary of what was completed]
BLOCKED: [story-id] — [what's blocking and what's needed]
FOUND: [component]:[file]:[line] — [what was discovered]
CLEAR: [component] — [why this component is not the issue]
NEED: [what's needed from another teammate]
WARN: [non-blocking concern that lead should know about]
```

### When to Message

- After completing a story → DONE
- When blocked on dependency → BLOCKED
- When finding bugs during build → FOUND
- When ruling out a component (bugfix) → CLEAR
- When needing another teammate's output → NEED
- When seeing a concern that's not your domain → WARN

## Session End Protocol

When a team session ends (all stories done or context limit):

### Lead Consolidation Steps

1. **Collect results** — Get DONE/BLOCKED status from each teammate
2. **Update prd.json** — Mark completed stories as `passes: true`
3. **Merge progress.md** — Consolidate all teammate entries, resolve duplicates
4. **Merge lessons.md** — Deduplicate, resolve conflicts, add team-level lessons
5. **Update patterns** — Graduate any new reusable patterns to progress.md header
6. **Run final verification** — qa-verifier does full cross-component check
7. **Report** — Summary of what was done, what's blocked, what's next

### For Next Session

If work continues in a new session:

1. New lead reads `tasks/todo.md` for remaining work
2. Reads `progress.md` for what was completed
3. Reads `tasks/lessons.md` for correction rules
4. Spawns team for remaining stories
