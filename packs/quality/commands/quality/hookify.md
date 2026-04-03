---
description: Create hook rules from conversation patterns or explicit instructions to prevent unwanted behaviors
argument-hint: Optional description of behavior to prevent (e.g. "don't use rm -rf without asking")
---

# Hookify — Create Hooks from Unwanted Behaviors

Analyze conversation patterns or explicit instructions to generate hook rule files that prevent problematic behaviors. Rules take effect immediately — no restart needed.

## Process

### Step 1: Gather Behavior Information

**If $ARGUMENTS is provided:**
- User has given specific instructions: `$ARGUMENTS`
- Also scan recent conversation (last 10–15 user messages) for additional context
- Look for examples of the behavior happening

**If $ARGUMENTS is empty:**
- Launch a subagent to analyze conversation for problematic behaviors
- Scan user messages for:
  - Explicit requests to avoid something ("don't do X", "stop doing Y")
  - Corrections or reversions (user fixing Claude's actions)
  - Frustrated reactions ("why did you do X?", "I didn't ask for that")
  - Repeated issues (same problem multiple times)
- For each issue, extract: tool used, pattern, why problematic, severity

### Step 2: Present Findings

Present detected behaviors to user. For each:
- Short description (e.g. "Block rm -rf")
- Why it's problematic
- Recommended action: **warn** (shows message, allows) or **block** (prevents execution)

Ask user which behaviors to hookify and what action for each.

### Step 3: Generate Rule Files

For each confirmed behavior, create a rule file.

**Rule naming:** kebab-case, descriptive, starts with action verb:
`hookify.block-dangerous-rm.local.md`, `hookify.warn-console-log.local.md`

**File format:**
```markdown
---
name: {rule-name}
enabled: true
event: {bash|file|stop|prompt|all}
pattern: {regex pattern}
action: {warn|block}
---

{Message to show when rule triggers}
```

**Event types:**
- `bash` — Matches Bash tool commands
- `file` — Matches Edit, Write, MultiEdit tools
- `stop` — Matches when agent wants to stop (use for completion checks)
- `prompt` — Matches user prompt submissions
- `all` — Matches all events

**Action values:**
- `warn` — Show message but allow operation (default)
- `block` — Prevent the operation

### Step 4: Write Files

**IMPORTANT**: Rule files go in the project's `.claude/` directory (current working directory), NOT a plugin directory.

1. Check if `.claude/` exists in current working directory — create if not
2. Write each `.claude/hookify.{name}.local.md` file
3. Show user what was created
4. Confirm: "Rules are active immediately — no restart needed!"

## Pattern Writing Tips

**Bash patterns:**
- Dangerous commands: `rm\s+-rf|chmod\s+777|dd\s+if=`
- Specific tools: `npm\s+install\s+|pip\s+install`
- Force flags: `--force|--hard|-f\s`

**File patterns:**
- Code anti-patterns: `console\.log\(|eval\(|innerHTML\s*=`
- Sensitive files: `\.env$|\.git/|credentials`
- Debug leftovers: `debugger;|TODO:|FIXME:`

**Stop patterns:**
- Check for missing steps (verify completion criteria in transcript)

## Common Recipes

**Block dangerous deletes:**
```markdown
---
name: block-dangerous-rm
enabled: true
event: bash
pattern: rm\s+(-rf|--recursive.*--force|--force.*--recursive)
action: block
---
⛔ Blocked: rm -rf detected. Verify the target path manually before proceeding.
```

**Warn on console.log in production code:**
```markdown
---
name: warn-console-log
enabled: true
event: file
pattern: console\.log\(
action: warn
---
⚠️ console.log detected. Use the project's logging utility instead. Remove before committing.
```

**Warn on .env modifications:**
```markdown
---
name: warn-env-edit
enabled: true
event: file
pattern: \.env
action: warn
---
⚠️ Editing .env file. Ensure no secrets are hardcoded. Check .gitignore includes this file.
```

Instructions: $ARGUMENTS
