# ECOSYSTEM.md — Complementary Tools & Integration Guide

NOMARK is a governance and discipline layer. It does not replace codebase indexing, session parallelization, CI/CD review, or IDE integration. Use the best tool for each job.

---

## Recommended Stack

| Need | Tool | Why | Install |
|------|------|-----|---------|
| **Codebase context** | [Repomix](https://github.com/yamadashy/repomix) | 70% token reduction, XML output optimized for Claude. Eliminates hallucinated file paths. | `npx repomix --mcp` |
| **Large codebase exploration** | [jcodemunch-mcp](https://github.com/jcodemunch/jcodemunch-mcp) | Token-efficient AST-level code exploration as a live MCP query tool. Fills the gap between Repomix (full dump) and grep (blind search) for large codebases. | MCP server |
| **Parallel sessions** | [Claude Squad](https://github.com/smtg-ai/claude-squad) | Git worktree isolation, tmux-based session management. 3-5x throughput on parallelizable work. | `brew install claude-squad` |
| **CI/CD review** | [claude-code-action](https://github.com/anthropics/claude-code-action) | Automated PR review. Anthropic reports 16%→54% substantive review coverage. | GitHub Action |
| **Long sessions** | [context-mode](https://github.com/mksglu/context-mode) | 98% context reduction via sandboxing. Extends sessions from ~30min to ~3hrs. Does not replace auto-clear — it raises the ceiling, not removes the discipline. | Plugin marketplace |
| **Cross-model review** | [claude-review-loop](https://github.com/hamelsmu/claude-review-loop) | Claude writes, a different model reviews. Catches errors same-model review misses. | Plugin marketplace |
| **GitHub API** | [github-mcp-server](https://github.com/github/github-mcp-server) | Direct GitHub API access via MCP for advanced operations beyond `gh` CLI (webhooks, complex GraphQL, rich API surfaces). Most teams won't need this — `gh` covers 95% of workflows. | MCP server |
| **Issue tracking** | [Linear MCP](https://linear.app) | Bidirectional story sync between progress.md and Linear. `/linear` command syncs statuses, creates issues, pulls new work. Maps: Epic→Initiative, Feature→Project, Story→Issue. | MCP server (via Claude.ai) |
| **Security scanning** | [Sigil](https://github.com/NOMARJ/sigil) | 8-phase security analysis with risk scoring. Pre-installation scanning, quarantine management, and threat intelligence. NOMARK's core MCP — configured in settings.json by default. | MCP server |
| **Security config** | [Trail of Bits config](https://github.com/trailofbits/claude-code-config) | Battle-tested settings.json and CLAUDE.md template from a top security firm. v2's settings.json adapts this with NOMARK-specific additions (memory hooks, Sigil, agent teams). | Copy and adapt |

## What NOMARK Does NOT Replace

| Capability | Why External is Better |
|-----------|----------------------|
| **Codebase indexing** | Repomix/GitNexus build AST-level structural maps. NOMARK has no equivalent. |
| **Session multiplexing** | Claude Squad/tmux manage OS-level process orchestration. NOMARK governs what happens inside a session. |
| **CI/CD automation** | claude-code-action runs in GitHub Actions infrastructure. NOMARK runs in the terminal. |
| **IDE integration** | VS Code, Cursor, Roo Code provide visual feedback. NOMARK is terminal-native. |
| **Deep code exploration** | jcodemunch/Repomix build AST-level structural understanding. NOMARK's code-explorer agent uses these tools, not replaces them. |

## What NOMARK Provides That Others Don't

| Capability | Why It Matters |
|-----------|---------------|
| **CHARTER + Governance Board** | Immutable integrity principles + decision framework. No other tool has governance. |
| **SOLUTION.md → prd → progress → Linear traceability** | Product-scoped specification governance with Linear sync. Features can't exist without a registry entry. Stories link to Linear issues via `linear_id`. |
| **Session integrity** (auto-clear, trust-agent, progress.md) | Prevents context drift and hallucinated work in long sessions. |
| **Discipline skills** (TDD, verification, debugging) | Structured methodology that constrains Claude to systematic behavior. |

---

## Hooks vs Skills — The Critical Distinction

From the Compass ecosystem assessment: the most important architectural concept for operators.

| | Hooks | Skills |
|---|---|---|
| **Execution** | Deterministic — always fire at lifecycle events | Probabilistic — Claude decides when to apply |
| **Use for** | Branch protection, secret scanning, pre-commit gates, formatting | Coding standards, review processes, workflow patterns |
| **Failure mode** | Can block actions (exit code 2) | Can be skipped if Claude judges them irrelevant |
| **NOMARK examples** | memory-session-start, memory-session-end, pre-commit | TDD, verification, debugging, brainstorming |

**Rule:** Use hooks for security-critical checks that must execute 100% of the time. Use skills for methodology that benefits from Claude's judgment about when to apply.

---

## Native Capabilities

### Conductor (Multi-Session Tracked Work)

For features spanning 5+ sessions, NOMARK includes the Conductor subsystem (available as an optional pack):

```
/conductor:setup       → Initialize project context
/conductor:new-track   → Create tracked feature/bug/refactor
/conductor:implement   → Execute track tasks
/conductor:status      → Project progress overview
/conductor:revert      → Git-aware undo by track/phase/task
```

Use Conductor when: multiple features in flight, context needs to survive across many sessions, or you need track-level rollback. This is complementary to Claude Squad — Squad parallelizes sessions, Conductor tracks persistent state across them.

### Agent Teams (Parallel Subtask Execution)

Claude Code's native Agent Teams feature (experimental) allows parallel subtask execution within a session. NOMARK's `subagent-dispatch` skill governs how to use this effectively:

- Match model tier to task complexity
- One agent per independent domain
- Focused prompts with exact file paths
- Review and integrate results after completion

---

## Integration Patterns

### NOMARK + Repomix
Run `npx repomix` to generate codebase context before starting a feature. This gives Claude accurate structural awareness, reducing the #1 failure class (hallucinated file paths and APIs).

### NOMARK + Claude Squad
Use Claude Squad for parallel feature development on independent stories. Each Squad session runs its own NOMARK discipline: `/build` in each worktree, progress tracked per-session.

### NOMARK + claude-code-action
Configure claude-code-action for automated PR review on your repo. NOMARK's `/pr` command creates PRs with structured descriptions that claude-code-action can review effectively.

### NOMARK + claude-review-loop
Run claude-review-loop after `/pr` for cross-model verification. This complements the `trust-agent` skill: trust-agent catches *intra-session* integrity drift, review-loop catches errors that same-model review misses at the PR level.

**Why NOMARK doesn't bundle cross-model review:** Cross-model verification requires external model access (Codex, GPT) and API keys that NOMARK cannot assume. The trust-agent provides same-model session integrity checking; claude-review-loop provides the adversarial cross-model layer. Use both for defense in depth.

### NOMARK + jcodemunch-mcp
For large codebases where Repomix's full-context dump is too expensive, use jcodemunch as a live exploration MCP. The `code-explorer` agent can leverage it for targeted AST queries instead of brute-force grep. Use Repomix for initial orientation, jcodemunch for ongoing exploration.

### NOMARK + Sigil
Sigil is NOMARK's default security MCP, configured in settings.json. The `/scan` command invokes it for 8-phase security analysis. Sigil runs *within* the session; claude-code-action runs *in CI* — use both for defense in depth.

### Token Budget Awareness
Every tool, skill, agent, and MCP server consumes context tokens. The Compass assessment warns: **keep under 10 MCP servers and 80 tools**. NOMARK v2 core loads 10 agents + 22 commands + 12 skills to stay well within this budget. Add packs selectively based on project needs.
