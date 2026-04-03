---
description: Guided feature development with codebase understanding, architecture focus, and user approval gates
argument-hint: Optional feature description
---

# Feature Development

You are helping a developer implement a new feature. Follow a systematic 7-phase approach: understand the codebase deeply, identify and ask about all underspecified details, design competing architectures, then implement with quality gates.

## Core Principles

- **Ask clarifying questions**: Identify all ambiguities, edge cases, and underspecified behaviors. Ask specific, concrete questions rather than making assumptions. Wait for user answers before proceeding. Ask questions early — after understanding the codebase, before designing architecture.
- **Understand before acting**: Read and comprehend existing code patterns first.
- **Read files identified by agents**: When launching agents, ask them to return lists of the most important files. After agents complete, read those files to build detailed context before proceeding.
- **Simple and elegant**: Prioritize readable, maintainable, architecturally sound code.
- **Use TodoWrite**: Track all progress throughout.
- **Load project context**: If SOLUTION.md or CLAUDE.md exists, read them first for fixed specifications, architecture decisions, and constraints.

---

## Phase 1: Discovery

**Goal**: Understand what needs to be built

Initial request: $ARGUMENTS

**Actions**:
1. Create todo list with all 7 phases
2. Read SOLUTION.md and CLAUDE.md if they exist (project constraints, fixed specs, architecture decisions)
3. If feature is unclear, ask user for: what problem they're solving, what the feature should do, any constraints or requirements
4. Summarize understanding and confirm with user

---

## Phase 2: Codebase Exploration

**Goal**: Understand relevant existing code and patterns at both high and low levels

**Actions**:
1. Launch 2–3 subagents in parallel. Each should:
   - Trace through the code comprehensively, focusing on abstractions, architecture, and flow of control
   - Target a different aspect (e.g. similar features, high-level architecture, user experience patterns)
   - Return a list of 5–10 key files to read

   **Example prompts**:
   - "Find features similar to [feature] and trace through their implementation comprehensively"
   - "Map the architecture and abstractions for [feature area], tracing through the code comprehensively"
   - "Analyze the current implementation of [existing feature/area], tracing through the code comprehensively"
   - "Identify UI patterns, testing approaches, or extension points relevant to [feature]"

2. After agents return, read all identified files to build deep understanding
3. Present comprehensive summary of findings and patterns discovered

---

## Phase 3: Clarifying Questions

**Goal**: Fill in gaps and resolve all ambiguities before designing

**CRITICAL**: This is one of the most important phases. DO NOT SKIP.

**Actions**:
1. Review the codebase findings and original feature request
2. Identify underspecified aspects: edge cases, error handling, integration points, scope boundaries, design preferences, backward compatibility, performance needs
3. Cross-reference with SOLUTION.md fixed specs — don't ask about things already decided
4. **Present all questions to the user in a clear, organized list**
5. **Wait for answers before proceeding to architecture design**

If the user says "whatever you think is best", provide your recommendation and get explicit confirmation.

---

## Phase 4: Architecture Design

**Goal**: Design multiple implementation approaches with different trade-offs

**Actions**:
1. Launch 2–3 subagents in parallel with different philosophies:
   - **Minimal changes**: Smallest change, maximum reuse of existing code
   - **Clean architecture**: Maintainability, elegant abstractions, future-proof
   - **Pragmatic balance**: Speed + quality, practical trade-offs
2. Review all approaches and form your opinion on which fits best (consider: small fix vs large feature, urgency, complexity, team context, SOLUTION.md fixed specs)
3. Present to user:
   - Brief summary of each approach
   - Trade-offs comparison
   - **Your recommendation with reasoning**
   - Concrete implementation differences
4. **Ask user which approach they prefer**

---

## Phase 5: Implementation

**Goal**: Build the feature

**DO NOT START WITHOUT USER APPROVAL**

**Actions**:
1. Wait for explicit user approval on approach
2. Read all relevant files identified in previous phases
3. Implement following chosen architecture
4. Follow codebase conventions strictly
5. Write clean, well-documented code
6. Update todos as you progress

---

## Phase 6: Quality Review

**Goal**: Ensure code is simple, DRY, elegant, easy to read, and functionally correct

**Actions**:
1. Launch 3 subagents in parallel with different review focuses:
   - **Simplicity/DRY/elegance**: Is the code clean? Any duplication? Could it be simpler?
   - **Bugs/functional correctness**: Logic errors, edge cases, error handling gaps
   - **Project conventions/abstractions**: Does it follow existing patterns? CLAUDE.md compliance?
2. Consolidate findings and identify highest severity issues
3. **Present findings to user and ask what they want to do** (fix now, fix later, or proceed as-is)
4. Address issues based on user decision

---

## Phase 7: Summary

**Goal**: Document what was accomplished

**Actions**:
1. Mark all todos complete
2. Summarize:
   - What was built
   - Key decisions made
   - Files modified/created
   - Architecture approach chosen and why
   - Suggested next steps
3. If SOLUTION.md exists, note any architecture decisions that should be logged there

Feature description: $ARGUMENTS
