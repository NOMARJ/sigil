# Sigil — OpenShell-Inspired Features

> **Source:** `docs/OPENSHELL-RESEARCH.md`
> **Branch:** `claude/sigil-openshell-research-pxLv2`
> **Started:** 2026-04-02

---

## Phase 1: Policy Foundation & Scanner Enhancements

### STORY-001: Define Sigil Policy YAML Schema
- **Status:** DONE ✅
- **Goal:** Design and document the declarative YAML policy format for Sigil sandbox enforcement
- **Done when:** A `SigilPolicy` struct exists in `cli/src/policy/mod.rs` that deserializes a YAML policy file with filesystem (read_only, read_write paths), network (allowed endpoints with host/port/access), process (run_as_user, allowed_syscalls), and credential (allowed_env_vars) sections. Unit tests validate parsing of a sample policy YAML.
- **Files:** `cli/src/policy/mod.rs` (new), `cli/src/policy/schema.rs` (new), `docs/policy-schema.md` (new)
- **Notes:** Inspired by OpenShell's static/dynamic policy split. Keep filesystem+process immutable, network hot-reloadable. Use `serde` + `serde_yaml` for deserialization. Add `serde_yaml` to Cargo.toml.

### STORY-002: `sigil policy generate` — Auto-Generate Policies from Scan Results
- **Status:** DONE ✅
- **Goal:** Add a CLI command that runs a scan and translates findings into a recommended policy YAML
- **Done when:** `sigil policy generate <path>` outputs a valid policy YAML to stdout (or `--output file.yaml`). Phase 3 findings → network deny rules, Phase 4 → credential restrictions, Phase 1 → filesystem lockdowns. The generated policy is parseable by the schema from STORY-001.
- **Files:** `cli/src/main.rs` (add Policy subcommand), `cli/src/policy/generate.rs` (new)
- **Notes:** Depends on STORY-001. Maps each phase's findings to the corresponding policy section. Start with conservative defaults (deny-all network, minimal filesystem access).

### STORY-003: Add Phase 10 — Inference Security Detection (Rust CLI)
- **Status:** DONE ✅
- **Goal:** Add a new scan phase that detects LLM API misuse patterns (hardcoded endpoints, secrets in prompts, credential injection in model clients)
- **Done when:** `Phase::InferenceSecurity` variant added to enum, detection patterns implemented in `phases.rs`, at least 5 rules covering: hardcoded non-standard base_url in OpenAI/Anthropic clients, env vars interpolated into prompt strings, API key overrides in client config, model endpoint redirection, prompt exfiltration via custom endpoints. Self-scan of test fixtures validates detection.
- **Files:** `cli/src/scanner/mod.rs` (add phase variant), `cli/src/scanner/phases.rs` (add rules), `cli/src/scanner/scoring.rs` (add weight — 5x)
- **Notes:** Inspired by OpenShell's Privacy Router concept. This is static detection of the patterns that a runtime inference router would catch. Weight 5x (High) aligned with Code Patterns phase.

### STORY-004: Add Phases 7-8 to Rust CLI (Prompt Injection & Skill Security)
- **Status:** DONE ✅
- **Goal:** Port Phases 7 (Prompt Injection, 10x) and 8 (Skill Security, 5x) from the API/bash scanner into the Rust CLI
- **Done when:** `Phase::PromptInjection` and `Phase::SkillSecurity` variants exist, detection patterns from `api/services/scanner.py` and `api/services/prompt_scanner.py` are ported, scoring weights match (10x and 5x). Rust CLI `sigil scan` reports findings from all 8 phases.
- **Files:** `cli/src/scanner/mod.rs`, `cli/src/scanner/phases.rs`, `cli/src/scanner/scoring.rs`
- **Notes:** These phases already exist in the Python API but not in Rust. Port patterns, not the full Python logic. Prerequisite for complete policy generation (Phase 7 findings inform inference policy).

---

## Phase 2: Runtime Enforcement

### STORY-005: `sigil run` — Sandboxed Execution with Policy Enforcement
- **Status:** DONE ✅
- **Goal:** Add a `sigil run --policy <file> -- <command>` command that executes a command inside an isolated environment with policy enforcement
- **Done when:** Command launches a Docker/Podman container with: filesystem mounts restricted to policy read_only/read_write paths, network egress filtered to allowed endpoints (using container networking), only specified env vars passed through. Exit code of the inner command is propagated. Works with `sigil run --policy strict -- python agent.py`.
- **Files:** `cli/src/main.rs` (add Run subcommand), `cli/src/sandbox/mod.rs` (new), `cli/src/sandbox/container.rs` (new)
- **Notes:** Depends on STORY-001. Start with Docker as the runtime (most widely available). Use `std::process::Command` to invoke `docker run` with appropriate flags. Built-in policy presets: `strict` (no network, minimal fs), `standard` (allow listed endpoints), `permissive` (log-only).

### STORY-006: Credential Provider System
- **Status:** DONE ✅
- **Goal:** Implement named credential bundles that control which env vars are available inside `sigil run`
- **Done when:** `sigil provider create --name github --vars GITHUB_TOKEN,GH_TOKEN` saves a provider to `~/.sigil/providers/`. `sigil run --provider github -- cmd` only passes those env vars to the container. `sigil provider list` shows saved providers. Auto-discovery detects common agent credentials (ANTHROPIC_API_KEY, OPENAI_API_KEY, GITHUB_TOKEN) and suggests provider creation.
- **Files:** `cli/src/main.rs` (add Provider subcommand), `cli/src/provider/mod.rs` (new)
- **Notes:** Inspired by OpenShell's provider system. Credentials stored as JSON in `~/.sigil/providers/<name>.json`, never written to container filesystem — only injected as env vars via `docker run -e`.

### STORY-007: `sigil safe-run` — Scan + Sandbox in One Command
- **Status:** DONE ✅
- **Goal:** Combine scanning and sandboxed execution: scan first, auto-generate policy, run in sandbox
- **Done when:** `sigil safe-run <path> -- <command>` runs a scan, generates a policy from findings, and launches the command in a sandbox with that policy. If scan verdict is CRITICAL_RISK, execution is blocked. If HIGH_RISK, user is prompted for confirmation. LOW/MEDIUM proceed with generated policy.
- **Files:** `cli/src/main.rs` (add SafeRun subcommand), `cli/src/sandbox/safe_run.rs` (new)
- **Notes:** Depends on STORY-002 (policy generate) and STORY-005 (sandbox run). This is the flagship UX — "scan it, then safely run it" in one step.

---

## Phase 3: Skills & SBOM

### STORY-008: `sigil sbom` — Software Bill of Materials Generation
- **Status:** DONE ✅
- **Goal:** Add a CLI command that generates SBOM from project dependency files, cross-referenced against Sigil's known threat database
- **Done when:** `sigil sbom <path>` parses lockfiles (package-lock.json, poetry.lock, Cargo.lock, requirements.txt, go.sum) and outputs CycloneDX JSON. Each component is cross-referenced against `api/data/known_threats.json`. Flagged components are annotated with threat severity. `--format` flag supports `cyclonedx`, `spdx`, `table`.
- **Files:** `cli/src/main.rs` (add Sbom subcommand), `cli/src/sbom/mod.rs` (new), `cli/src/sbom/parsers.rs` (new), `cli/src/sbom/cyclonedx.rs` (new)
- **Notes:** `docs/SBOM.md` documents Sigil's own SBOM but there's no `sigil sbom` command for users. Leverages existing `known_threats.json` (172KB). Start with 3 parsers: package-lock.json, requirements.txt, Cargo.lock.

### STORY-009: Claude Code Skills — `/fix-finding` and `/generate-policy`
- **Status:** DONE ✅
- **Goal:** Add two new Claude Code skills that make scan results actionable
- **Done when:** `/fix-finding` skill accepts a finding (phase, rule, file, line) and proposes a code fix with explanation. `/generate-policy` skill runs `sigil policy generate` and explains the policy to the user. Both follow the existing skill format in `plugins/claude-code/skills/`.
- **Files:** `plugins/claude-code/skills/fix-finding/SKILL.md` (new), `plugins/claude-code/skills/generate-policy/SKILL.md` (new)
- **Notes:** Follows existing skill pattern from `scan-repo/SKILL.md`. `/fix-finding` maps common findings to remediation patterns (e.g., "replace `eval()` with `ast.literal_eval()`", "remove postinstall hook"). `/generate-policy` wraps STORY-002's CLI command.

---

## Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-02 | Start with policy schema before runtime enforcement | Schema is the foundation — generation, validation, and sandbox all depend on it |
| 2026-04-02 | Use Docker/Podman for sandbox, not Landlock/seccomp directly | Broader platform support (macOS, Linux, WSL). OpenShell's Landlock approach is Linux-only |
| 2026-04-02 | Port Phases 7-8 before adding Phase 10 | Phases 7-8 already exist in Python API — port is lower risk than new phase design |
| 2026-04-02 | SBOM in Rust CLI, not Python API | Aligns with Rust CLI strategy; parsing lockfiles is well-suited to Rust |
| 2026-04-02 | 9 stories across 3 phases, not 10+ | Scoped to actionable deliverables; bypass monitoring and OCSF deferred to future phase |


## session-observations

### Session 2026-04-11

**Start:** 2026-04-11T11:40:25.011Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-04-11

**Start:** 2026-04-11T11:40:41.962Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-04-30

**Start:** 2026-04-30T07:51:57.016Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-04-30T07:52:49.979Z
**Outcome:** DONE
**Stories:** 9/9 (0 blocked)

- 4: react, hooks, frontend [confidence: 0.8]



### Session 2026-04-30

**Start:** 2026-04-30T08:00:45.538Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-04-30T08:01:14.695Z
**Outcome:** DONE
**Stories:** 9/9 (0 blocked)

- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-04-30

**Start:** 2026-04-30T09:13:25.238Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-04-30T09:14:00.677Z
**Outcome:** DONE
**Stories:** 9/9 (0 blocked)

- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-04-30

**Start:** 2026-04-30T22:32:20.308Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-04-30

**Start:** 2026-04-30T22:34:02.493Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-04-30T22:42:26.492Z
**Outcome:** DONE
**Stories:** 9/9 (0 blocked)

- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-04-30

**Start:** 2026-04-30T23:12:36.832Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-04-30T23:12:55.006Z
**Outcome:** DONE
**Stories:** 9/9 (0 blocked)

- 4: react, hooks, frontend [confidence: 0.8]

## instinct-health

| ID | Pattern | Injections | Applied | Completions | Fallbacks | Applied Rate | Outcome Rate | Status |
|----|---------|------------|---------|-------------|-----------|-------------|-------------|--------|




