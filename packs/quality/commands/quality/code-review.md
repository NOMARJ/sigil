---
allowed-tools: Bash(gh issue view:*), Bash(gh search:*), Bash(gh issue list:*), Bash(gh pr comment:*), Bash(gh pr diff:*), Bash(gh pr view:*), Bash(gh pr list:*), Bash(git diff:*), Bash(git log:*), Bash(git blame:*)
description: Code review a pull request with parallel agents and confidence-based scoring
argument-hint: PR number or branch name. Add --comment to post as PR comment.
---

# Code Review — Confidence-Scored Multi-Agent Review

Provide a thorough code review using 4 parallel agents with independent confidence scoring. Only surfaces issues scoring ≥80/100 confidence to eliminate false positives.

**Agent assumptions (applies to all agents and subagents):**
- All tools are functional. Do not test tools or make exploratory calls.
- Only call a tool if required. Every tool call should have a clear purpose.

## Process

### Step 1: Pre-flight Checks

Launch a haiku subagent to check if any of the following are true:
- The pull request is closed
- The pull request is a draft
- The PR does not need code review (e.g. automated PR, trivial change obviously correct)
- Claude has already commented on this PR (check `gh pr view <PR> --comments`)

If any condition is true, stop and explain why.

Note: Still review Claude-generated PRs.

### Step 2: Gather Guidelines

Launch a haiku subagent to find all relevant CLAUDE.md files:
- Root CLAUDE.md (or claude/CLAUDE.md)
- Any CLAUDE.md files in directories containing modified files
- SOLUTION.md fixed specifications (non-negotiable constraints)

### Step 3: Summarize the PR

Launch a sonnet subagent to view the PR diff and return a summary of changes.

### Step 4: Parallel Review (4 agents)

Launch 4 agents in parallel. Each returns a list of issues with description and reason.

**Agents 1 + 2: CLAUDE.md Compliance (sonnet)**
Audit changes for CLAUDE.md compliance in parallel (redundant for consensus). Only consider CLAUDE.md files scoped to the modified file paths.

**Agent 3: Bug Detection (opus)**
Scan for obvious bugs. Focus only on the diff itself. Flag only significant bugs; ignore nitpicks and likely false positives. Do not flag issues you cannot validate without extra context.

**Agent 4: Context-Aware Bug Detection (opus)**
Look for problems in introduced code — security issues, incorrect logic, silent failures, error handling gaps. Use git blame and history for context.

**CRITICAL: HIGH SIGNAL ONLY.** Flag issues where:
- Code will fail to compile or parse (syntax errors, type errors, missing imports)
- Code will definitely produce wrong results regardless of inputs (clear logic errors)
- Clear, unambiguous CLAUDE.md violations (quote the exact rule broken)
- Security vulnerabilities in changed code
- Silent failures — errors caught and swallowed without logging or user feedback

Do NOT flag:
- Code style or quality concerns
- Potential issues depending on specific inputs or state
- Subjective suggestions or improvements
- Issues a linter will catch
- Pre-existing issues not introduced in this PR

### Step 5: Independent Validation

For each issue found in Step 4 by agents 3 and 4, launch a parallel subagent to validate. The validator gets the PR context and issue description, and confirms whether the issue is real with high confidence.

Use opus subagents for bugs/logic issues, sonnet for CLAUDE.md violations.

### Step 6: Confidence Scoring

For each validated issue, score 0–100:

| Score | Meaning |
|-------|---------|
| 0–25 | Likely false positive |
| 25–50 | Might be real, not worth flagging |
| 50–75 | Real but minor |
| 75–90 | Real and important |
| 90–100 | Certain, must fix |

**Filter out everything below 80.**

### Step 7: Output

**Terminal output (always):**
```markdown
## Code Review — [PR title]

Found [N] issues (confidence ≥80):

1. [Issue description] (confidence: [score])
   File: [path]#L[start]-L[end]
   Reason: [CLAUDE.md rule / bug type / security]

2. ...

---
Issues filtered (below threshold): [N]
Agents: 4 parallel reviewers + [N] validators
```

If no issues found: "No issues found. Checked for bugs, CLAUDE.md compliance, and security."

**If `--comment` was NOT provided**: Stop here.

**If `--comment` was provided and no issues**: Post summary via `gh pr comment`.

**If `--comment` was provided and issues found**: Post inline comments via `gh pr comment` or inline comment tool. Each comment includes: brief description, confidence score, and for small self-contained fixes a suggestion block.

## False Positive Exclusion List

Do NOT flag (these are known false positives):
- Pre-existing issues not introduced in this PR
- Something that appears buggy but is actually correct
- Pedantic nitpicks a senior engineer would not flag
- Issues a linter will catch
- General quality concerns unless required by CLAUDE.md
- Issues silenced via lint-ignore comments

Pull request: $ARGUMENTS
