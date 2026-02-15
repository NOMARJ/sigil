# Sigil Roadmap

Last updated: 2026-02-15

---

## Delivered

### Core CLI
- [x] `sigil clone <url>` — quarantine + scan git repos
- [x] `sigil pip <pkg>` — download + scan pip packages
- [x] `sigil npm <pkg>` — download + scan npm packages
- [x] `sigil scan <path>` — scan existing directories/files
- [x] `sigil fetch <url>` — download + scan from arbitrary URLs
- [x] `sigil approve / reject <id>` — quarantine management
- [x] `sigil list` — view quarantined items with status
- [x] `sigil diff` — baseline comparison (new/resolved/unchanged)
- [x] `sigil login / logout` — authentication with token storage
- [x] `sigil config --init` — directory structure setup
- [x] `sigil report` — report threats to cloud
- [x] `--format json` and `--format sarif` output modes
- [x] `--no-cache` flag and `clear-cache` command
- [x] `.sigilignore` support

### Six Scan Phases
- [x] Install Hooks (Critical 10x) — setup.py, postinstall, Makefile
- [x] Code Patterns (High 5x) — eval, exec, pickle, child_process, __import__
- [x] Network / Exfil (High 3x) — HTTP, sockets, webhooks, DNS tunnelling
- [x] Credentials (Medium 2x) — ENV vars, .aws, .kube, SSH keys, API keys
- [x] Obfuscation (High 5x) — base64, charCode, hex, minified payloads
- [x] Provenance (Low 1-3x) — git history, binary files, hidden files

### Rust CLI
- [x] Full CLI with all commands (clone, pip, npm, scan, approve, reject, list, diff, login, report, config)
- [x] Scanner engine with all 6 phases
- [x] Scoring engine with severity weighting
- [x] Scan caching with directory hash invalidation
- [x] SARIF 2.1.0 output for GitHub Code Scanning
- [x] Diff/baseline comparison

### Shell Aliases & Git Hooks
- [x] `gclone`, `safepip`, `safenpm`, `safefetch`, `audithere`, `qls`, `qapprove`, `qreject`
- [x] Auto-detection of shell (.bashrc, .zshrc, fish)
- [x] Pre-commit git hook for staged file scanning

### FastAPI Backend
- [x] Auth endpoints (login, register, verify, refresh, logout)
- [x] Scan submission and retrieval
- [x] Threat intelligence lookup (`/v1/threat/{hash}`)
- [x] Signature distribution (`/v1/signatures`)
- [x] Publisher reputation scoring
- [x] Package verification
- [x] Threat reporting
- [x] Team management (create, invite, remove members)
- [x] Custom policy engine (rules, severity thresholds)
- [x] Alert configuration (Slack, webhooks)
- [x] Billing integration (Stripe plans, subscriptions, portal)
- [x] Health checks
- [x] JWT authentication with secure token handling
- [x] Rate limiting with Redis
- [x] CORS middleware

### Next.js Dashboard
- [x] Dashboard home with stats cards and recent scans
- [x] Scan history (paginated list)
- [x] Scan detail view (findings, verdict, phase breakdown)
- [x] Threat intelligence interface
- [x] Team management (members, invites, roles)
- [x] Settings (policies, alerts, billing)
- [x] Login page with auth guard
- [x] Reusable components (FindingsList, ScanTable, VerdictBadge, StatsCard, Sidebar)

### IDE & Agent Integrations
- [x] VS Code / Cursor / Windsurf extension — scan workspace, files, selections, packages; findings in Problems panel; sidebar views
- [x] JetBrains plugin — IntelliJ, WebStorm, PyCharm, etc.; tool window, inline annotations, settings UI
- [x] Claude Code MCP server — 6 tools (scan, scan_package, clone, quarantine, approve, reject) + phase docs resource
- [x] GitHub Action (`action.yml`) — inputs, outputs, composite action

### CI/CD & DevOps
- [x] CI workflow — ShellCheck, ruff, clippy, rustfmt, ESLint, tsc, Gradle build
- [x] Release workflow
- [x] Docker multi-stage build (Rust + Next.js + Python)
- [x] Docker Compose (API, Dashboard, PostgreSQL, Redis)
- [x] Container health checks, non-root user

### Documentation
- [x] README with install, usage, architecture, pricing
- [x] Getting Started guide
- [x] Architecture overview
- [x] Scan rules reference
- [x] Threat model
- [x] Deployment guide
- [x] IDE plugins guide
- [x] Contributing guidelines

---

## In Progress

### Cloud Deployment
- [ ] Hosted PostgreSQL / Supabase integration
- [ ] Production environment provisioning
- [ ] CDN + edge caching for signature distribution

### Threat Intelligence Network
- [ ] Community signature propagation pipeline
- [ ] Automated malicious package reporting
- [ ] Signature versioning and delta updates
- [ ] Reputation scoring based on scan telemetry

---

## Planned

### v0.2 — Distribution & Polish
- [ ] Homebrew tap (`brew install nomarj/tap/sigil`)
- [ ] npm global package (`npm install -g @nomarj/sigil`)
- [ ] curl installer (`curl -sSL https://sigilsec.ai/install.sh | sh`)
- [ ] VS Code Marketplace publishing
- [ ] JetBrains Marketplace publishing
- [ ] Rust binary as default CLI (replace bash script)
- [ ] Auto-update mechanism

### v0.3 — Ecosystem Expansion
- [ ] Docker / OCI image scanning
- [ ] Go module scanning
- [ ] Cargo crate scanning
- [ ] MCP server registry scanning
- [ ] Monorepo support (scan changed packages only)

### v0.4 — Enterprise Features
- [ ] SSO / SAML authentication
- [ ] Audit log with tamper-proof storage
- [ ] Custom scan rule authoring (YAML DSL)
- [ ] Org-wide policy enforcement
- [ ] Role-based access control (RBAC)
- [ ] Scan result retention policies

### v0.5 — Platform Integrations
- [ ] GitLab CI integration
- [ ] Jenkins plugin
- [ ] CircleCI orb
- [ ] Bitbucket Pipelines integration
- [ ] Slack bot for scan notifications
- [ ] PagerDuty / Opsgenie alerts

### Future
- [ ] Marketplace verification API (badge for verified-safe packages)
- [ ] AI-assisted triage (LLM explains findings and suggests fixes)
- [ ] Dependency graph visualization
- [ ] SBOM (Software Bill of Materials) generation
- [ ] VEX (Vulnerability Exploitability eXchange) document output
- [ ] Browser extension for scanning repos before cloning
