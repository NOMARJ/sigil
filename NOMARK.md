# NOMARK Method

> Governed by CHARTER.md — that document takes precedence.
> Philosophy and method live here. Constitutional authority lives in CHARTER.

**Architecture First. Outcomes Over Hype. Simple Wins.**

---

## Philosophy

1. **Architecture First** — Think before you code. A good plan executed beats perfect code improvised.
2. **Outcomes Over Hype** — Ship what matters. No feature creep, no over-engineering, no cargo cult.
3. **Simple Wins** — The best code is code you don't write. The best abstraction is no abstraction.

When the rules run out: apply the Governance Board (CHARTER Article III).

---

## Document Hierarchy

```
CHARTER.md              ← constitutional (immutable principles, governance board)
NOMARK.md               ← methodology (this file — lifecycle, discipline)
CLAUDE.md               ← operational (session protocol, code style, integrity rules)
BUSINESS-CONTEXT.md     ← portfolio identity (operator context for growth/strategy)
SOLUTION.md             ← product intent (vision, locked specs, feature registry)
  └── prd.json / PRD    ← active feature scope (stories, acceptance criteria)
        └── progress.md ← session tracking (execution state, evidence)
              └── tasks/lessons.md ← correction rules (from mistakes)
```

### Traceability Rule

Every story in progress.md must link to a Feature in SOLUTION.md. Every Feature must link to an Epic. No work exists outside this hierarchy.

If asked to do work with no Feature entry: flag it, propose a Feature Registry entry, wait for owner approval.

---

## The Lifecycle

```
THINK → PLAN → BUILD → VERIFY → SHIP
```

Skills auto-activate at every phase transition. This is a pipeline, not a menu.

### THINK

Before touching code, challenge assumptions. Use brainstorming skill for interactive design refinement.

1. Define the problem (what are we actually solving?)
2. Surface assumptions (what do we take for granted?)
3. Question each one (physics/logic or just convention?)
4. Identify fundamentals (what's truly non-negotiable?)
5. Rebuild from scratch (if we started today...)

**Command:** `/nomark:think`
**Skills:** brainstorming (interactive), inverted-thinking (risk check)

### PLAN

Design the solution before implementation. Enter plan mode for 3+ step tasks.

1. Ensure a SOLUTION.md Feature entry exists (create one if not)
2. Generate a PRD linked to the Feature (`/nomark:prd`)
3. Explore the codebase — understand existing patterns
4. Break into atomic stories — each completable in one session
5. Get approval, then execute

**The traceability chain:** SOLUTION.md Feature → PRD (`tasks/prd-*.md`) → progress.md stories. No work exists outside this hierarchy.

Each story must be: **Atomic** (one outcome), **Ordered** (dependencies first), **Verifiable** (concrete done condition).

**Command:** `/nomark:plan`
**Skills:** tdd (test strategy), git-worktrees (if parallel), conductor (if multi-track)

### BUILD

Execute one story at a time with fresh context.

```
For each story:
  1. Read tasks/lessons.md (correction rules FIRST)
  2. Implement the single story using TDD (Red → Green → Refactor)
  3. Run verification (typecheck, lint, test)
  4. If passes: commit, update progress.md, move to next
  5. If stuck: apply systematic-debugging (4-phase root cause)
  6. If 3 failures: STOP, write BLOCKED, escalate
```

**Command:** `/nomark:build`
**Skills:** tdd (Red-Green-Refactor), systematic-debugging (if stuck), subagent-dispatch (if parallel)

### VERIFY

Non-negotiable. The Iron Law: **no completion claims without fresh verification evidence.**

```
Layer 1: Static Analysis     — typecheck + format + lint
Layer 2: Automated Tests     — unit + integration
Layer 3: Security Scan       — SIGIL supply chain + OWASP review
Layer 4: Browser / Manual    — visual confirmation (UI) or plan review (infra)
Layer 5: Simplification      — /nomark:simplify, remove accidental complexity
```

Three-tier security: Tier 1 (static, every change) → Tier 2 (differential review, every PR) → Tier 3 (multi-model review, critical changes to auth/payments/PII/crypto).

**Command:** `/nomark:verify`
**Skills:** verification-before-completion (Iron Law), owasp-security, receiving-code-review

### SHIP

Govern the deployment decision. NOMARK doesn't deploy — it governs the decision to deploy and verifies the outcome.

1. Generate CI pipeline from project context (`/nomark:ci`)
2. Pre-flight checklist (verification, attestation, clean tree, branch, CI)
3. Attestation gate — RED = blocked, override with reason (logged)
4. Environment promotion — non-prod default, `--env prod` explicit
5. Post-deploy health check — verify deploy worked
6. Rollback governance — confirmation required, reason logged

**Commands:** `/nomark:ci`, `/nomark:ship`
**Skills:** deploy-pack (provider interface), verification-before-completion (pre-flight)

---

## Skill-Chained Lifecycle

Skills activate automatically at each phase. Check before every significant action.

```
THINK  → brainstorming, inverted-thinking, governance-board (if ambiguous)
PLAN   → tdd (test strategy), git-worktrees (if parallel), governance-board (if trade-offs)
BUILD  → tdd-red → tdd-green → tdd-refactor, systematic-debugging (if stuck)
VERIFY → verification-before-completion (Iron Law), receiving-code-review (if reviewed)
SHIP   → deploy-pack (provider execution), verification-before-completion (pre-flight + post-deploy)
```

**Triggers:**
| Trigger | Skill |
|---------|-------|
| "I want to build..." | brainstorming |
| Planning any non-trivial task | tdd (test strategy) |
| Any test failure during BUILD | systematic-debugging |
| About to claim "done" | verification-before-completion |
| Dispatching 2+ parallel agents | subagent-dispatch |
| Receiving review feedback | receiving-code-review |
| Ambiguous decision point | inverted-thinking |
| "Last time we...", "do you remember" | memory-recall (forked context) |
| Ambiguous judgment, trade-off, escalation unclear | governance-board |
| "Who is this for?" / "Are we building the right thing?" | empathy-engine |
| New product or major pivot | empathy-engine (recommended) |
| Epic is HYPOTHESIS, needs validation | empathy-engine (lightweight) |

---

## TDD Pipeline

Primary workflow for features:

```
/nomark:plan       → atomic stories with test acceptance criteria
      ↓
RED                → write failing test from acceptance criteria
      ↓
GREEN              → implement minimum code to pass
      ↓
REFACTOR           → clean up without breaking tests
      ↓
/nomark:verify     → 5-layer check
      ↓
[FAIL] → fix → verify again
[PASS] → /nomark:simplify → /nomark:commit → /nomark:ship
```

**Rules:** No production code without a failing test. Coverage ≥ 80% for modified files. A story is never DONE without a passing test.

---

## Systematic Debugging

When bugs arise, follow the 4-phase root cause methodology:

1. **Investigate** — read full error, reproduce consistently, check recent changes, trace data flow
2. **Analyse patterns** — find working code, compare working vs broken, map dependencies
3. **Hypothesise and test** — one minimal change at a time, verify before stacking guesses
4. **Implement** — failing test first, single fix for root cause, full suite verification

**Three-strike rule (CHARTER II.4):** After 3 failed attempts, STOP. Write BLOCKED. The architecture is wrong, not your fix.

**NO FIXES WITHOUT ROOT CAUSE INVESTIGATION FIRST.**

---

## Escalation Boundaries

**Proceed autonomously:**
- Bug fix with clear root cause and isolated change
- Story implementation following the plan
- Verification failures — fix and retry
- Code simplification that doesn't change behavior

**Stop and ask:**
- Change affects auth, authorization, or data integrity
- Fix requires database schema changes
- Story reveals a design flaw not in the plan
- More than 3 files outside planned scope
- Any change to CI/CD, deployment, or infrastructure
- Uncertainty > 50%

Default: **ask if in doubt.** Cost of asking is low.

---

## Memory System

NOMARK uses git as its memory engine with a dual-layer architecture: human-readable markdown with YAML frontmatter, and machine-queryable JSON indexes.

```
.nomark/
├── memory/
│   ├── 2026-03-27.md     ← YAML frontmatter + markdown (human + machine readable)
│   └── 2026-03-26.md
├── index.json             ← search index (auto-rebuilt from frontmatter by session-end hook)
└── graph.json             ← traceability graph (epic → feature → story → session → commit)
```

### Memory file format

```markdown
---
type: session
date: 2026-03-27
feature: F-001
stories: [US-001, US-002]
decisions:
  - topic: auth approach
    choice: JWT with RS256
tags: [auth, architecture]
---

## Session Summary
[What was done, decisions, what's next]
```

### Three data layers

| Layer | Format | Purpose | Query |
|-------|--------|---------|-------|
| `progress.md` | Markdown | Active task state (what to do next) | Read whole file |
| `.nomark/memory/` | YAML frontmatter + MD | Decision history (why we did it) | Index search + grep |
| `.nomark/graph.json` | JSON | Traceability (how everything connects) | Traverse edges |
| `.nomark/index.json` | JSON | Search index (auto-maintained) | Structured queries |
| `tasks/lessons.md` | Markdown | Correction rules (what not to repeat) | Read whole file |

### Commands

| Command | Action |
|---------|--------|
| `/nomark:memory save` | Write session with frontmatter |
| `/nomark:memory <query>` | Index search + full-text search |
| `/nomark:memory graph` | Show traceability chain |
| `/nomark:lessons add` | Capture correction rule |
| `/nomark:progress` | Status overview |

The session-end hook automatically: commits memory files, parses YAML frontmatter, rebuilds `index.json`. Zero manual maintenance.

---

## Parallel Execution

### In-session (subagent dispatch)

When 3+ independent tasks with no shared state:
1. Identify independent domains — no file overlap
2. Create focused prompts — self-contained, scoped, verifiable
3. Dispatch in parallel — all agents simultaneously
4. Review and integrate — check conflicts, run full test suite

**Model tier selection:** Opus for architecture, Sonnet for standard work, Haiku for mechanical tasks.

### Multi-session (git worktrees)

For large features: `git worktree add .worktrees/<feature> -b feature/<name>`. Each session works in its own worktree. Clean up after merge.

---

## Core Reference

### 26 Commands (`nomark:`)

| Command | Purpose |
|---------|---------|
| `think` | First principles analysis |
| `plan` | Atomic story decomposition |
| `prd` | Generate PRD linked to SOLUTION.md Feature |
| `build` | Execute next story (TDD) |
| `verify` | 5-layer verification |
| `commit` | Stage, verify, commit, push |
| `bugfix` | Autonomous bug fixing |
| `simplify` | Code simplification |
| `scan` | Security scan |
| `pr` | Create pull request |
| `trust-agent` | Session integrity monitor (/tc) |
| `lessons` | Manage correction rules |
| `progress` | Manage progress tracking |
| `memory` | Git-native session memory |
| `solution-amend` | Controlled spec amendment |
| `audit` | Verify NOMARK config against CHARTER |
| `build-all` | Execute all stories sequentially |
| `assess` | Technical feasibility analysis |
| `synthesize` | Cross-MCP context search |
| `install` | Install plugin packs |
| `ecosystem-setup` | Install/configure ecosystem tools |
| `board` | Governance Board evaluation |
| `discover` | Run Empathy Engine (full persona panel + synthetic interviews) |
| `empathy` | Quick empathy check (Suri test against current Feature) |
| `ci` | Generate/maintain CI pipeline config (GitHub Actions) |
| `ship` | Governed deployment (pre-flight, attestation gate, promotion, rollback) |

### 11 Agents

| Agent | Purpose | Tier |
|-------|---------|------|
| code-architect | Architecture decisions | Opus |
| code-reviewer | Code review | Sonnet |
| tdd-specialist | TDD enforcement | Sonnet |
| debugger | Systematic debugging | Sonnet |
| qa-verifier | Verification & quality | Sonnet |
| code-explorer | Codebase exploration (read-only) | Sonnet |
| code-simplifier | Simplification | Sonnet |
| security-auditor | Security review | Opus |
| solution-architect | SOLUTION.md facilitation | Opus |
| test-automator | Test generation | Sonnet |
| empathy-researcher | DISCOVER phase facilitation | Opus |

### 14 Skills

| Skill | Key Principle |
|-------|---------------|
| skill-activation | Check the chain. Load the skill. Follow the process. |
| verification-before-completion | No claims without fresh evidence |
| systematic-debugging | No fixes without investigation first |
| brainstorming | Don't plan until the design is approved |
| tdd | No production code without a failing test |
| subagent-dispatch | One agent per independent domain |
| git-worktrees | One feature per worktree |
| inverted-thinking | How would this fail catastrophically? |
| receiving-code-review | Technical correctness over social comfort |
| trust-agent | Is this session still operating reliably? |
| memory-recall | Forked-context search — doesn't pollute main session |
| governance-board | When the rules run out, interrogate the decision through 5 lenses |
| empathy-engine | Evidence before code. Who is this for — human and agent? |
| deploy-pack | Provider interface contract for governed deployments |

---

## Anti-Patterns

| Anti-Pattern | Why It Fails |
|---|---|
| Big stories | Run out of context, produce broken code |
| Skip verification | 1x quality instead of 3x |
| Ignore lessons.md | Repeat the same mistakes |
| Over-engineer | More code = more bugs |
| Skip planning | Rework costs 10x more |
| Push through broken approach | Compounds errors, wastes context |
| Guess-and-check debugging | Root cause investigation is faster |
| Claim done without evidence | "Should work" is not evidence |
| Performative review responses | "Great catch!" is not a fix |
| Parallelize interconnected tasks | Creates merge conflicts |
| Skip brainstorming | Building the wrong thing fast is still wrong |
| Write tests after code | Tests shaped by implementation verify nothing new |
| Fill "Who It Serves" without evidence | Orphan Epics — building for ghosts |
| Treat synthetic research as conclusion | Hypothesis ≠ validation. MED ceiling. |
| Skip the Silence Check | Confident about a biased evidence base |

---

**Simple. Efficient. Wins.**
