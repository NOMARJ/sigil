# Sigil Content Plan

**Author:** NOMARK
**Date:** 2026-02-19
**Status:** Draft
**Version:** 1.0

---

## 1. Purpose

This document defines the content strategy for Sigil's documentation site, blog, and supporting pages. It establishes what needs to be written, in what order, and how each piece maps to product goals — converting developers from awareness to adoption to paid plans.

Sigil's content must serve three audiences simultaneously:

1. **Individual developers** who need to get scanning in under 60 seconds
2. **Tech leads and security engineers** who need to evaluate depth, accuracy, and integration surface
3. **AI agent builders** who need MCP/tool integration guides specific to their workflow

---

## 2. Content Inventory — What Exists Today

### Documentation (docs/)

| File | Content | Status | Gap |
|------|---------|--------|-----|
| `getting-started.md` | Install, first scan walkthrough, config | Complete | Needs screenshots, video embed |
| `architecture.md` | Three-layer system, data flow, tech stack | Complete | Good as-is |
| `scan-rules.md` | All 6 phases with patterns and examples | Complete (~14K lines) | Could use a condensed cheat sheet |
| `threat-model.md` | Attack vectors, scoring, limitations | Complete (~15K lines) | Academic tone — needs practitioner summary |
| `api-reference.md` | Full REST API docs | Complete (~26K lines) | Needs interactive examples (curl/httpie) |
| `deployment.md` | Docker, Compose, CI/CD, production config | Complete (~18K lines) | Good as-is |
| `ide-plugins.md` | VS Code, JetBrains, MCP, GitHub Actions | Complete | Thin on MCP — needs dedicated deep-dive |
| `prd-landing-page.md` | Landing page product requirements | Draft | Internal doc, not public |

### Top-Level Docs

| File | Content | Status |
|------|---------|--------|
| `README.md` | Product overview, install, usage, pricing | Complete — strong |
| `ROADMAP.md` | Today / Now / Next / Later | Complete — good structure |
| `CONTRIBUTING.md` | How to contribute, PR process | Complete |
| `CLAUDE.md` | Development guide for AI assistants | Complete |

### What's Missing

- No dedicated CLI command reference (man-page style)
- No standalone MCP integration guide (current coverage is 1 section in ide-plugins.md)
- No configuration deep-dive (env vars, .sigilignore, policies)
- No troubleshooting / FAQ page
- No changelog
- No blog
- No tutorials or how-to guides (e.g., "Scan an MCP server before connecting it")
- No comparison pages (Sigil vs Snyk, Sigil vs Socket, etc.)
- No content for SEO/AEO around "AI agent security" and "supply chain attacks"

---

## 3. Content Priorities

### P0 — Ship Before Public Launch

These are blocking. Without them, developers cannot self-serve.

#### 3.1 Documentation Hub (`/docs`)

A structured, searchable docs site with sidebar navigation. All existing markdown files migrate here with consistent formatting and cross-linking.

**Site structure:**

```
/docs
  /docs/getting-started          ← existing, enhanced
  /docs/cli                      ← NEW: full CLI reference
  /docs/scan-phases              ← existing scan-rules.md, restructured
  /docs/mcp                      ← NEW: dedicated MCP guide
  /docs/ide-plugins              ← existing, split into sub-pages
    /docs/ide-plugins/vscode
    /docs/ide-plugins/jetbrains
  /docs/architecture             ← existing
  /docs/api                      ← existing api-reference.md
  /docs/threat-model             ← existing
  /docs/deployment               ← existing
```

**Sidebar TOC component** — persistent left sidebar with:
- Section grouping (Getting Started, CLI, Integrations, Reference, Advanced)
- Active page highlighting
- Collapsible sub-sections
- Mobile-responsive drawer

#### 3.2 CLI Command Reference (`/docs/cli`) — NEW

Man-page style reference for every `sigil` command and flag. This is the single most important doc for daily users.

**Structure:**

```markdown
## Commands

### sigil scan <path>
Scan a file or directory for security issues.

**Arguments:**
| Arg | Required | Description |
|-----|----------|-------------|
| path | Yes | File or directory to scan |

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| --format | text | Output format: text, json, sarif |
| --phases | all | Comma-separated phase filter |
| --severity | low | Minimum severity threshold |
| --no-color | false | Disable colored output |

**Examples:**
sigil scan .
sigil scan ./vendor --format json --phases install_hooks,code_patterns
sigil scan ./mcp-server --severity high

**Exit codes:**
| Code | Meaning |
|------|---------|
| 0 | CLEAN — no findings |
| 1 | CRITICAL — score 50+ |
| 2 | HIGH — score 25-49 |
| 3 | MEDIUM — score 10-24 |
| 4 | LOW — score 1-9 |
```

**Commands to document:**
- `sigil scan <path>` — scan file/directory
- `sigil clone <url>` — quarantine + scan git repo
- `sigil pip <package>` — download + scan pip package
- `sigil npm <package>` — download + scan npm package
- `sigil fetch <url>` — download + scan URL
- `sigil approve <id>` — approve quarantined item
- `sigil reject <id>` — reject quarantined item
- `sigil list` — show quarantine contents
- `sigil diff` — compare scans
- `sigil config` — show/edit configuration
- `sigil login` / `sigil logout` — authentication
- `sigil install` — full interactive install
- `sigil aliases` — shell alias management
- `sigil hooks` — git hook installation
- `sigil help` — help text

#### 3.3 MCP Integration Guide (`/docs/mcp`) — NEW

Dedicated guide for connecting Sigil to AI agents via MCP. This is a key differentiator — no competitor has this.

**Sections:**

1. **What is MCP and why it matters for security**
   - Brief explainer of Model Context Protocol
   - Why AI agents need security scanning as a tool (agents install packages, clone repos, fetch URLs autonomously)
   - The risk: an agent with `npm install` access and no scanning is a supply chain attack waiting to happen

2. **Quick setup**
   - Install MCP server: `cd plugins/mcp-server && npm install && npm run build`
   - Configure for Claude Code (`~/.claude/claude_desktop_config.json`)
   - Configure for Cursor (MCP settings)
   - Configure for Windsurf (MCP settings)
   - Configure per-project (`.mcp.json`)

3. **Available tools reference**
   - `sigil_scan` — scan file/directory with parameters (path, phases, severity)
   - `sigil_scan_package` — download + scan npm/pip package (manager, package_name, version)
   - `sigil_clone` — clone + scan git repo (url, branch)
   - `sigil_quarantine` — list quarantined items
   - `sigil_approve` — approve quarantined item (quarantine_id)
   - `sigil_reject` — reject quarantined item (quarantine_id)
   - `sigil://docs/phases` — resource providing scan phase documentation

4. **Example workflows**
   - "Scan this project before I deploy"
   - "Is this npm package safe?" (agent uses sigil_scan_package)
   - "Clone and audit this repo" (agent uses sigil_clone)
   - "What's in quarantine? Approve the clean ones" (agent uses sigil_quarantine + sigil_approve)

5. **Advanced: building agents with Sigil as a guardrail**
   - Pattern: agent that auto-scans before every `npm install`
   - Pattern: CI agent that blocks merges on CRITICAL findings
   - Pattern: security review agent that triages findings

6. **Environment variables**
   - `SIGIL_BINARY` — path to CLI binary (default: `sigil`)

---

### P1 — Ship Before Paid Launch

These support conversion from free CLI users to Pro/Team subscribers.

#### 3.4 Configuration Guide (`/docs/configuration`) — NEW

Comprehensive reference for all configuration surfaces.

**Sections:**

1. **Environment variables**
   - `SIGIL_QUARANTINE_DIR` — quarantine directory path
   - `SIGIL_APPROVED_DIR` — approved code directory path
   - `SIGIL_LOG_DIR` — log directory path
   - `SIGIL_REPORT_DIR` — report directory path
   - `SIGIL_CONFIG` — config file path
   - `SIGIL_TOKEN` — auth token file path
   - `SIGIL_API_URL` — API base URL

2. **Config file (`~/.sigil/config`)**
   - Format and supported keys
   - Precedence: env var > config file > default

3. **`.sigilignore` file**
   - Syntax (glob patterns, comments, negation)
   - Default ignores (node_modules, .git, __pycache__, etc.)
   - Per-project vs global ignore

4. **Scan policies (Team tier)**
   - Auto-approve thresholds
   - Required review rules
   - Phase-specific overrides
   - Policy sync across team members

5. **Shell aliases customization**
   - Default aliases and what they do
   - How to customize or disable specific aliases
   - Manual alias installation

6. **Git hooks configuration**
   - Pre-commit hook behavior
   - Bypassing hooks (`--no-verify`)
   - Hook customization

#### 3.5 CI/CD Integration Guide (`/docs/cicd`) — NEW

End-to-end guide for every supported CI system.

**Sections:**

1. **GitHub Actions**
   - Basic setup (`uses: NOMARJ/sigil@main`)
   - All inputs and outputs from `action.yml`
   - Fail-on-findings configuration
   - SARIF upload to GitHub Code Scanning
   - Example: scan on every PR
   - Example: scan only changed files
   - Example: block merge on HIGH+ findings

2. **GitLab CI**
   - Template include syntax
   - Stage configuration
   - Artifact handling
   - Example: `.gitlab-ci.yml` integration

3. **Generic CI (Jenkins, CircleCI, Bitbucket)**
   - Install Sigil in CI environment
   - Run scan with JSON output
   - Parse exit codes for pass/fail
   - Upload SARIF artifacts

4. **Docker-based CI**
   - Use the Sigil Docker image directly
   - Volume mounting for project scanning
   - Multi-stage build integration

5. **Alerts and notifications**
   - Webhook configuration for scan results
   - Slack integration setup
   - Custom webhook payloads

#### 3.6 Changelog (`/changelog`)

Running changelog tracking every release.

**Format:**

```markdown
## v0.9.0 — 2026-02-15
### Added
- Cloud threat intelligence enrichment during scans
- Publisher reputation scoring
- `sigil diff` command for comparing scan baselines

### Changed
- Improved obfuscation detection for hex-encoded payloads
- Reduced false positives in credential scanning phase

### Fixed
- Shell alias installation on Zsh with Oh My Zsh
```

**Requirements:**
- Follow Keep a Changelog format
- Semantic versioning
- Link each version to its GitHub release
- Include migration notes for breaking changes

#### 3.7 Blog (`/blog`)

8 launch posts to establish authority and drive organic search traffic. All posts should be optimized for both traditional SEO and AI answer engine optimization (AEO).

**Post 1: "Why We Built Sigil"** (Founder story)
- The problem: AI agents have unrestricted access to your credentials
- The gap: dependency scanners don't catch intentional malice
- The approach: quarantine-first, scan-everything
- Audience: developers, security community
- CTA: install Sigil, star on GitHub

**Post 2: "Anatomy of a Supply Chain Attack on AI Agents"** (Technical deep-dive)
- Walkthrough of a real attack pattern: malicious MCP server that exfiltrates API keys
- Step-by-step: how the attack works (postinstall hook -> env var harvest -> webhook exfil)
- How Sigil catches each stage (Phase 1: install hooks, Phase 3: network exfil, Phase 4: credentials)
- Audience: security engineers, AI developers
- CTA: scan your MCP servers with Sigil

**Post 3: "The 6 Phases of Malicious Code Detection"** (Educational)
- Explain each scan phase with real-world examples
- Why weighted scoring matters (install hooks are 10x because they run before you see the code)
- How to read a Sigil scan report
- Audience: developers new to supply chain security
- CTA: try `sigil scan .` on your own project

**Post 4: "Securing Your AI Agent Workflow with MCP + Sigil"** (Integration guide)
- Why AI agents need security tools as first-class capabilities
- Step-by-step: set up Sigil MCP server with Claude Code
- Demo: agent autonomously scans packages before installing
- Audience: AI agent builders, Claude Code users
- CTA: configure the MCP server

**Post 5: "Sigil vs Snyk vs Socket.dev: What's Actually Different"** (Comparison)
- Honest comparison of capabilities
- Key differentiators: quarantine workflow, MCP integration, multi-ecosystem, behavioral detection
- When to use Sigil vs when to use the others (they're complementary for CVE scanning)
- Audience: tech leads evaluating tools
- CTA: try the free CLI, compare for yourself

**Post 6: "How to Audit an MCP Server in 30 Seconds"** (Tutorial)
- Practical how-to with terminal screenshots
- `sigil clone <mcp-server-repo>` walkthrough
- Reading the report, understanding findings
- Approve/reject decision framework
- Audience: developers installing MCP servers
- CTA: install Sigil, make it a habit

**Post 7: "Adding Security Scanning to Your CI/CD Pipeline"** (DevOps guide)
- GitHub Actions setup with SARIF upload
- Fail-on-findings thresholds
- Handling false positives in CI
- GitLab CI template
- Audience: DevOps/platform engineers
- CTA: add Sigil to your pipeline

**Post 8: "Community Threat Intelligence: How Sigil Gets Smarter"** (Product explainer)
- How the threat intelligence pipeline works
- What data is shared (metadata only, never source code)
- Publisher reputation scoring
- Signature distribution and delta sync
- Privacy guarantees
- Audience: security-conscious developers, potential Pro/Team subscribers
- CTA: `sigil login` to contribute and benefit from community intel

---

### P2 — Post-Launch Enhancements

#### 3.8 Threat Database Browser (`/threats`)

Public-facing page showing known malicious packages and patterns detected by the community. Serves dual purpose: builds credibility and drives organic traffic from developers searching for package safety.

**Phase 1 — Static list:**
- Table of confirmed malicious packages with name, ecosystem, attack type, detection date
- Each entry links to a detail page with the scan report (redacted)
- Searchable by package name and ecosystem

**Phase 2 — Live feed:**
- Real-time feed of newly detected threats
- RSS/Atom feed for security researchers
- API endpoint for programmatic access

#### 3.9 Troubleshooting & FAQ (`/docs/troubleshooting`) — NEW

Common issues and their solutions.

**Sections:**

1. **Installation issues**
   - `sigil: command not found` — PATH configuration
   - Permission denied on install — use `sudo` or install to user directory
   - Homebrew formula not found — tap the repository first
   - Shell aliases not loading — source your shell config

2. **Scanning issues**
   - False positives — how to report and how to suppress with `.sigilignore`
   - Scan takes too long — check file count, use `.sigilignore` for vendor dirs
   - `sigil scan` exits with error — check tool dependencies
   - External scanner not detected — install semgrep/bandit/trufflehog

3. **Authentication issues**
   - `sigil login` fails — check network, API URL
   - Token expired — re-run `sigil login`
   - Threat intelligence not loading — verify authentication status

4. **CI/CD issues**
   - GitHub Action fails to install — check action version
   - SARIF upload rejected — validate SARIF schema
   - Exit code mapping — what each code means and how to handle

5. **IDE plugin issues**
   - VS Code: extension not activating — check sigil binary path
   - JetBrains: plugin compatibility — check IDE version
   - MCP: server not connecting — verify config file path and binary

#### 3.10 Comparison Pages (`/compare/*`)

Dedicated landing pages for competitive search terms.

- `/compare/sigil-vs-snyk` — CVE scanning vs behavioral detection
- `/compare/sigil-vs-socket` — npm-only vs multi-ecosystem
- `/compare/sigil-vs-semgrep` — pattern engine vs end-to-end workflow
- `/compare/sigil-vs-codeql` — GitHub-hosted vs local-first

Each page follows the same template:
- What [competitor] does well
- Where Sigil differs (quarantine, MCP, multi-ecosystem, community intel)
- Side-by-side feature table
- "Try it yourself" CTA

---

## 4. Shared Components

Content pages share these reusable components (for the docs site / dashboard):

### 4.1 `DocsLayout`
- Persistent sidebar navigation
- Breadcrumb trail
- Previous / Next page links at bottom
- "Edit this page on GitHub" link
- Table of contents (right sidebar on desktop, collapsible on mobile)

### 4.2 `DocsSidebar`
- Grouped sections: Getting Started, CLI, Integrations, Reference, Advanced
- Active page highlighting with visual indicator
- Collapsible section groups
- Badge for new/updated pages
- Mobile: slide-out drawer

### 4.3 `CodeBlock`
- Syntax highlighting (bash, python, javascript, json, yaml, toml)
- Copy-to-clipboard button
- Optional filename/title header
- Line number toggle
- Diff mode for showing changes (green/red highlighting)

### 4.4 `ApiEndpoint`
- Method badge (GET, POST, PUT, DELETE)
- Path with parameter highlighting
- Auth required indicator
- Expandable request/response body with JSON syntax highlighting
- "Try it" button linking to API playground (future)
- Copy as curl button

### 4.5 `ScanPhaseCard`
- Phase name, number, and weight badge
- Severity color coding (critical=red, high=orange, medium=yellow, low=blue)
- Expandable rules list with pattern examples
- Detection count from community data (authenticated)

### 4.6 `TerminalDemo`
- Animated terminal replay showing Sigil commands
- Autoplay on scroll-into-view
- Pause/restart controls
- Light and dark theme support
- Used on landing page hero section and in tutorials

### 4.7 `ComparisonTable`
- Feature comparison matrix with check/cross/partial indicators
- Sticky header row
- Mobile-responsive (horizontal scroll or stacked cards)
- Used on comparison pages and README

### 4.8 `CalloutBox`
- Info, warning, tip, and danger variants
- Icon + colored border styling
- Used throughout docs for important notes, security warnings, and pro tips

---

## 5. Content Calendar

### Week 1-2: P0 Documentation

| Day | Deliverable | Owner |
|-----|-------------|-------|
| D1-2 | Docs site scaffolding (DocsLayout, DocsSidebar, CodeBlock) | Engineering |
| D3-4 | CLI command reference (`/docs/cli`) | Engineering + Technical Writer |
| D5-6 | MCP integration guide (`/docs/mcp`) | Engineering |
| D7-8 | Migrate existing docs to site, add cross-links | Technical Writer |
| D9-10 | Review, QA, fix broken links, test mobile | QA |

### Week 3-4: P1 Content

| Day | Deliverable | Owner |
|-----|-------------|-------|
| D11-12 | Configuration guide (`/docs/configuration`) | Engineering |
| D13-14 | CI/CD integration guide (`/docs/cicd`) | Engineering |
| D15-16 | Changelog page, populate from git history | Engineering |
| D17-18 | Blog posts 1-2 ("Why We Built Sigil", "Anatomy of an Attack") | Founder + Editor |
| D19-20 | Blog posts 3-4 ("6 Phases", "MCP + Sigil") | Technical Writer |

### Week 5-6: P1 Blog + P2 Start

| Day | Deliverable | Owner |
|-----|-------------|-------|
| D21-22 | Blog posts 5-6 ("Sigil vs X", "Audit MCP in 30s") | Technical Writer |
| D23-24 | Blog posts 7-8 ("CI/CD", "Threat Intelligence") | Technical Writer |
| D25-26 | Troubleshooting & FAQ page | Support + Engineering |
| D27-28 | Comparison pages (at least Sigil vs Snyk) | Marketing + Engineering |
| D29-30 | Threat database Phase 1 (static list) | Engineering |

---

## 6. SEO & AEO Strategy

### Target Keywords

**Primary (high intent):**
- "AI agent security scanner"
- "MCP server security audit"
- "supply chain attack detection tool"
- "quarantine code before running"
- "scan npm package for malware"
- "scan pip package for malware"

**Secondary (educational):**
- "how to detect malicious npm packages"
- "AI agent supply chain attacks"
- "MCP server security best practices"
- "python setup.py malware detection"
- "npm postinstall attack"

**Long-tail (comparison):**
- "sigil vs snyk for supply chain"
- "sigil vs socket.dev"
- "alternative to snyk for AI agents"
- "code quarantine tool"

### AEO Optimization

Each content piece should be structured for AI answer engines:

- **Clear question-answer pairs** in headings (H2: "How does Sigil scan for malicious code?")
- **Structured data** — FAQ schema, HowTo schema, SoftwareApplication schema
- **Concise definitive statements** in the first paragraph of each section
- **Comparison tables** with factual, verifiable claims
- **Code examples** that are complete, runnable, and copy-pasteable

---

## 7. Content Quality Standards

### Every documentation page must have:

1. **Clear purpose statement** — first paragraph explains what this page covers and who it's for
2. **Prerequisites** — what the reader needs before starting
3. **Runnable examples** — every concept illustrated with a command or code block
4. **Cross-links** — at least 2 links to related docs pages
5. **Next steps** — footer section pointing to logical next pages

### Every blog post must have:

1. **Hook** — first paragraph creates urgency or curiosity
2. **Scannable structure** — H2/H3 headings, bullet lists, code blocks, tables
3. **Practical takeaway** — reader can do something concrete after reading
4. **CTA** — clear call to action (install, configure, scan, sign up)
5. **Social card** — OG image and meta description for sharing

### Voice and tone:

- **Direct** — "Sigil scans your code" not "Sigil can be used to scan your code"
- **Confident without hype** — state what the tool does, don't oversell
- **Developer-first** — assume the reader writes code; don't explain what a CLI is
- **Security-aware** — acknowledge limitations and false positives honestly
- **Concise** — if a sentence doesn't add information, remove it

---

## 8. Metrics & Success Criteria

| Metric | Target | Measurement |
|--------|--------|-------------|
| Docs page views | 1,000/week within 30 days of launch | Analytics |
| CLI installs from docs | 20% of docs visitors reach install page | Funnel tracking |
| Blog organic traffic | 500 sessions/month by month 3 | Search Console |
| Time on docs page | >3 minutes average | Analytics |
| Support ticket deflection | Troubleshooting page resolves 40% of common issues | Support ticket tagging |
| Docs search usage | Track top 20 search queries weekly | Site search analytics |
| MCP guide engagement | >200 unique visitors/week | Analytics |
| Blog post completion rate | >60% scroll to CTA section | Scroll tracking |

---

## 9. Appendix: File Mapping

How existing files map to the new docs site structure:

| Source File | Destination URL | Action |
|-------------|----------------|--------|
| `docs/getting-started.md` | `/docs/getting-started` | Enhance with screenshots |
| `docs/architecture.md` | `/docs/architecture` | Migrate as-is |
| `docs/scan-rules.md` | `/docs/scan-phases` | Restructure, add cheat sheet |
| `docs/threat-model.md` | `/docs/threat-model` | Add practitioner summary |
| `docs/api-reference.md` | `/docs/api` | Add interactive examples |
| `docs/deployment.md` | `/docs/deployment` | Migrate as-is |
| `docs/ide-plugins.md` | `/docs/ide-plugins/*` | Split into sub-pages |
| — | `/docs/cli` | **NEW** — CLI command reference |
| — | `/docs/mcp` | **NEW** — MCP integration guide |
| — | `/docs/configuration` | **NEW** — Configuration deep-dive |
| — | `/docs/cicd` | **NEW** — CI/CD integration guide |
| — | `/docs/troubleshooting` | **NEW** — Troubleshooting & FAQ |
| `ROADMAP.md` | `/roadmap` | Public roadmap page |
| `CONTRIBUTING.md` | `/docs/contributing` | Migrate |
| — | `/changelog` | **NEW** — Changelog from releases |
| — | `/blog/*` | **NEW** — 8 launch posts |
| — | `/compare/*` | **NEW** — Comparison pages |
| — | `/threats` | **NEW** — Threat database browser |
