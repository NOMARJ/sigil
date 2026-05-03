# The Three-Layer AI Security Stack: Why One Tool Isn't Enough

*Published: 2026-05-03*
*Author: NOMARK*
*Tags: security-architecture, ai-agents, threat-detection*

---

AI agents ship code you don't write, install packages you didn't vet, and interact with tools you've never reviewed. A single security checkpoint misses entire categories of attacks. This post describes a defense-in-depth model for AI development — and why you need multiple layers to be safe.

## The problem with single-layer security

Most developers rely on one tool: CVE scanners like Snyk or Dependabot. These tools answer one question well: "Do my dependencies have known vulnerabilities?" They match package versions against advisory databases and flag problems with assigned CVE numbers.

But the attacks hitting AI developers aren't CVEs. They're intentionally malicious code published fresh to npm, PyPI, and MCP server marketplaces. A typosquat package named `langchain-utils` (typo of `langchain`) has no CVE because it was never legitimate. The malicious MCP server that exfiltrates credentials via a `postinstall` hook has no CVE because no one knew to report it.

When you scan only for CVEs, you miss the entire category of supply-chain attacks designed to hurt you from day one.

## Introducing the three-layer stack

Comprehensive AI security needs three complementary layers:

### **Layer 1: Pre-Installation Scanning (Sigil)**

Sigil runs BEFORE any code executes. When you run `sigil pip langchain-utils` or `sigil clone <git-url>`, the package is downloaded to an isolated quarantine, scanned with 8 behavioral detection phases, and held until you approve it.

**What it catches:**
- Install hooks that read environment variables or write to webhooks
- Eval/exec patterns that could run arbitrary code
- Obfuscated payloads (base64, hex encoding, charCode tricks)
- Credential file access (`~/.aws/credentials`, `~/.ssh/keys`)
- Outbound network calls to exfiltration targets
- Prompt injection attacks in AI skill documentation
- MCP permission escalation attempts

**The critical advantage:** Quarantine-first means nothing runs until you've reviewed the verdict. No `postinstall` scripts execute. No setup hooks fire. No malicious code touches your system.

### **Layer 2a: Deep Scanning at Install Time (OpenAI Aardvark/Codex Security)**

After you approve a package in Sigil's quarantine, you can opt into deep scanning from OpenAI's Codex Security system. Aardvark provides semantic analysis — not just pattern matching, but understanding of what code actually does. It's slower than Sigil (minutes per package vs. seconds) and focuses on deep vulnerabilities: taint flow, control-flow analysis, data-flow analysis.

**What it catches:**
- Subtle credential leakage through variable chains
- Indirect network exfiltration via third-party APIs
- Business logic manipulation (authorization bypasses)
- Tainted data flowing from untrusted sources to sensitive operations

**Why it's complementary:** Aardvark is strong on deep semantic vulnerabilities that pattern matchers miss. But it's language-specific, slower, and designed for detailed code review — not rapid pre-install screening.

### **Layer 2b: AI-Aware Deep Scanning (Anthropic Claude Code Security)**

Anthropic Claude Code Security, now in open beta, brings AI-specific threat detection to your development environment. Unlike CVE scanners, Claude Code Security understands AI agent behavior: when an agent chains function calls, reads tool outputs, and constructs prompts.

**What it catches:**
- Prompt injection via user input to AI skills
- Instruction jailbreaks in agent tool definitions
- Unsafe third-party tool integrations
- Privilege escalation in skill marketplaces
- Credential exposure in agent memory or logs

**Why it's complementary:** Claude Code Security specializes in AI-specific threats that don't exist in traditional software. It looks at your agent code, your skill definitions, and your integration patterns — not just the underlying packages.

## How the layers work together

Think of the three-layer stack as defense-in-depth:

**Layer 1 (Sigil)** blocks obvious malware before it can run.
```
Attacker publishes malicious npm package with install hook.
↓
You run `sigil pip malware-pkg`
↓
Sigil detects install hook → CRITICAL
↓
Package is quarantined, never reaches your system.
```

**Layer 2a (Aardvark)** catches subtle vulnerabilities you approve in Layer 1.
```
You review Sigil's verdict: "No obvious hooks or patterns."
↓
But you want deeper assurance. You run Aardvark deep scan.
↓
Aardvark detects credential leakage through variable chains → HIGH
↓
You dig into the code, find it's a legitimate logging pattern, or reject the package.
```

**Layer 2b (Claude Code Security)** finds AI-specific threats in your agent code.
```
Your agent uses a third-party tool to search the web.
↓
Claude Code Security scans your agent code + the tool's skill definition.
↓
It detects that the tool outputs unsanitized HTML directly into agent context.
↓
User-controlled input from search results could inject prompts into your agent.
↓
Claude Code Security flags it. You either sandbox the tool or replace it.
```

## Real-world example: The OpenClaw campaign

In February 2026, an attacker published 314 malicious AI skills to ClawHub using a single account created days earlier. The skills were disguised as "crypto analytics" and "finance tracking" tools. Their SKILL.md documentation included social engineering instructions: "Run this script to complete setup." The scripts downloaded Atomic Stealer (AMOS) malware.

### Why CVE-and-dependency tools struggle here

CVE scanners answer "do my dependencies have known vulnerabilities?" — and they answer it well. But OpenClaw was new code, designed to be malicious from publication, with no CVE assigned and no advisory database to match against. Hash-based reputation tools see a file only after enough victims have already encountered it. npm-scope tools don't reach MCP skill marketplaces at all. None of these tools are *failing* at what they're built for — they're solving a different problem from the one OpenClaw represents.

### Where each layer of the stack fits

**Layer 1 — Sigil's pre-install behavioural detection** is designed to spot the patterns OpenClaw used: `curl | bash` instructions in skill documentation, unencrypted HTTP download endpoints, base64-encoded payloads, suspicious publisher provenance (a freshly created account publishing hundreds of skills in a short window). These are exactly the signals Sigil's 8 scan phases look for.

**Layer 2a — Aardvark/Codex Security** is built for semantic reasoning over the package contents themselves. For an OpenClaw-style payload, deeper taint analysis can reach conclusions that rapid pattern matching can't.

**Layer 2b — Claude Code Security** is built for AI-specific threats. A skill that nudges an agent into running external code is exactly the kind of agent-instruction risk this layer is designed to catch.

We can't claim what *would* have happened at scale — we don't have counterfactual data. What we can say is that OpenClaw used techniques that fall squarely inside the design scope of all three layers. That's the case for defense-in-depth: not that any one layer guarantees safety, but that adversaries have to defeat every layer to succeed.

## How to implement the three-layer stack

### Step 1: Add Sigil as your pre-install gate

```bash
# Install — pick whichever fits your environment
brew install nomarj/tap/sigil          # macOS / Linux Homebrew
npm install -g @nomarj/sigil           # any platform with Node
cargo install sigil-cli                # any platform with Rust
curl -sSL https://sigilsec.ai/install.sh | sh   # universal installer

# Before installing any package or cloning any repo
sigil pip some-package
sigil npm some-tool
sigil clone <repository-url>
```

For CI, Sigil is published on the GitHub Marketplace. Drop this into a workflow and every PR gets scanned automatically:

```yaml
# .github/workflows/security.yml
name: Security
on: [pull_request]
jobs:
  sigil:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: nomarj/sigil@v1
        with:
          path: .
          threshold: high
```

For AI agents, Sigil also ships as an MCP server, so an agent can scan a package before it decides to install it.

### Step 2: Sign up for a deep scanner

Both deep-scanner products are in beta. Pick whichever fits your stack:

- **Aardvark / Codex Security** (OpenAI) — currently in private beta. Sign up at [openai.com](https://openai.com).
- **Claude Code Security** (Anthropic) — now in open beta. Sign up at [claude.com/solutions/claude-code-security](https://claude.com/solutions/claude-code-security).

Their CLIs, integrations, and pricing are evolving. We'd rather link you to their canonical docs than freeze details that may change next week.

### Step 3: Wire your deep scanner into your dev loop

Each vendor publishes integration guidance for their own product. Two reasonable defaults:

- Run the deep scanner in CI, on a schedule (nightly is common), against the same repo Sigil is gating at install time.
- Surface findings inline in your IDE so AI-specific risks show up while you're writing the agent code, not three sprints later.

If you're starting from zero today, the highest-leverage move is **Step 1**: get Sigil between you and `npm install` / `pip install` / `git clone`, so nothing untrusted runs before it's been scanned.

## Key principles

**1. Complementary, not competitive.** These tools catch different things. Sigil excels at pre-install behavioral detection. Aardvark excels at semantic analysis. Claude Code Security excels at AI agent threat modeling. Use all three.

**2. Quarantine first.** Nothing should execute until you've decided it's safe. Layer 1 enforces this; Layers 2a and 2b happen *before* you deploy to production.

**3. Layers, not layers of the same tool.** Don't just run Sigil twice. Run Sigil (behavioral), then Aardvark (semantic), then Claude Code Security (AI-specific).

**4. Automate what you can.** In CI/CD, run all three automatically. For development, let your IDE warn you (Claude Code Security) while you pre-screen manually (Sigil).

## Frequently asked questions

**Q: Isn't this overkill?**
A: For a single developer's hobby project, maybe. For AI agents in production, no. One missed CVE in a dependency can be expensive. One missed supply-chain attack can expose your credentials to the internet. Three layers is the baseline for serious security.

**Q: Which layer catches the most issues?**
A: Layer 1 (Sigil) catches the broadest range — install hooks, obfuscation, exfiltration patterns. But all three catch things the others don't. If you skip Layer 2b, you'll miss AI-specific jailbreaks. If you skip Layer 2a, subtle credential leakage slips through. If you skip Layer 1, you don't get quarantine-first defense.

**Q: Do I need all three?**
A: No. You need at least Layer 1 (Sigil) for quarantine-first safety. Layers 2a and 2b are "nice to have" that become "critical for production" as your risk profile increases.

**Q: What about my existing CVE scanner?**
A: Keep it. CVE scanners answer "do I have known vulnerabilities?" and that's still important. But they only cover advisories with assigned CVE numbers. The three-layer stack covers everything else.

## Summary

AI development security isn't binary. It's not "secure" or "not." It's layered:

- **Layer 1:** Pre-install behavioral detection (Sigil) blocks obvious attacks before they run.
- **Layer 2a:** Deep semantic analysis (Aardvark) finds subtle vulnerabilities you approved in Layer 1.
- **Layer 2b:** AI-specific threat modeling (Claude Code Security) finds jailbreaks and prompt injection in your agent code.

Together, they give you defense-in-depth. No single tool is sufficient. No single tool catches everything. But three tools, each specialized for different attack vectors, together raise the cost of attack on you from "trivial" to "not worth it."

---

*Start with Layer 1: [Install Sigil](https://sigilsec.ai) · [Sigil on GitHub](https://github.com/NOMARJ/sigil) · [Sigil on the GitHub Marketplace](https://github.com/marketplace/actions/sigil-security-scan)*
