# Changelog

All notable changes to Sigil are documented here. This project uses [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- Rust CLI fully compiles and runs (`cli/` — `cargo build --release` produces a working binary)
- VS Code / Cursor / Windsurf extension packaged as `.vsix` (`plugins/vscode/sigil-security-0.1.0.vsix`)
- JetBrains plugin builds with `gradle buildPlugin` — fixed `StatusBarWidget.TextPresentation.getClickConsumer()` nullable return type for IntelliJ Platform 2024.1+
- MCP server (`plugins/mcp-server`) ships with `bin` entry — usable via `npx @nomark/sigil-mcp-server`
- JetBrains CI step re-enabled in `.github/workflows/ci.yml`
- Dockerfile Stage 1 now builds the Rust CLI from source instead of using a busybox placeholder
- VS Code extension icon and Apache 2.0 `LICENSE` added to plugin directory
- Content plan for documentation site, blog, and supporting pages
- CLI command reference documentation
- MCP integration guide
- Configuration deep-dive documentation
- CI/CD integration guide (GitHub Actions, GitLab CI, Jenkins, CircleCI, Bitbucket)
- Troubleshooting & FAQ page
- Comparison pages (Sigil vs Snyk, Socket.dev, Semgrep, CodeQL)
- Blog launch with 8 posts

### Fixed
- Rust clippy warnings treated as errors (`dead_code` on `Signature` / `SignatureResponse`, `too_many_arguments` on `cmd_scan`) — CI `build-rust` and `lint-rust` steps now pass clean

---

## [0.9.0] — 2026-02-15

### Added
- Cloud threat intelligence enrichment during authenticated scans
- Publisher reputation scoring based on community scan data
- Threat signature delta sync with 24-hour local cache
- `sigil diff` command for comparing scan results against a baseline
- Custom domain support for dashboard API URL
- `asyncpg` database client as alternative to Supabase client
- Password reset flow (`POST /v1/auth/forgot-password`, `POST /v1/auth/reset-password`)
- Subscription management endpoints for billing
- Scan usage tracking with monthly quota enforcement
- `.sigilignore` file support for excluding files and directories from scans

### Changed
- Dashboard API URL now uses custom domain (sigilsec.ai)
- CD pipeline triggers on push instead of waiting for CI completion
- Improved credential scanning phase to reduce false positives on common ENV patterns

### Fixed
- Dashboard deployment now uses production build instead of dev server
- Linting errors in Python API and Bash CLI
- Shell alias installation on Zsh with Oh My Zsh frameworks
- Supabase CLI temp directory now ignored in `.gitignore`

---

## [0.8.0] — 2026-02-01

### Added
- Web dashboard (Next.js 14) with scan history, team management, and settings
- Authentication system with JWT tokens (login, register, password reset)
- Scan detail view with findings grouped by phase
- Threat intelligence browser with three tabs: known threats, community reports, detection signatures
- Team management: invite members, assign roles, remove members
- Settings panels: scan policies, alert channels (Slack/Email/Webhook), billing
- Billing integration with Stripe (plan selection, subscription management, usage tracking)
- VerdictBadge, ScanTable, StatsCard, FindingsList components
- Dark theme with custom color palette
- Mobile-responsive sidebar navigation
- Error boundaries and loading states throughout dashboard

### Changed
- API routers restructured for dashboard compatibility (dual path support: `/v1/<path>` and `/<path>`)

---

## [0.7.0] — 2026-01-15

### Added
- FastAPI backend service with 10 API routers
- Authentication router with JWT tokens and password hashing
- Scan submission and storage endpoints
- Threat intelligence endpoints (hash lookup, signature distribution)
- Publisher reputation tracking
- Team management API (invite, roles, remove)
- Billing API with Stripe integration
- Scan policies API (auto-approve thresholds, allowlist, blocklist)
- Alert webhook API (Slack, email, webhook channels)
- Plan-based feature gates (free, pro, team tiers)
- PostgreSQL database schema with Supabase
- Redis caching layer for threat intelligence and rate limiting
- pytest test suite for API endpoints

---

## [0.6.0] — 2026-01-01

### Added
- GitHub Actions integration (`action.yml`)
- CI workflow: lint (shellcheck, Python), test (pytest), build (Docker, npm, Cargo)
- CD workflow: deploy to Azure Container Apps on push
- Release workflow: create GitHub releases with binary artifacts
- GitLab CI template (`.gitlab-ci-template.yml`)
- SARIF output format for GitHub Code Scanning integration
- Docker multi-stage build (Rust CLI, Next.js dashboard, Python API)
- Docker Compose development stack (API, PostgreSQL, Redis)
- Makefile with development workflow targets

### Changed
- Dockerfile uses non-root user (UID 1001) for security
- Rust CLI build stage made optional (disabled by default until implementation complete)

### Fixed
- JetBrains plugin build disabled in CI due to Gradle compatibility issues

---

## [0.5.0] — 2025-12-15

### Added
- IDE plugin scaffolding for VS Code, JetBrains, and MCP server
- VS Code extension manifest with commands: scan workspace, file, selection, package
- JetBrains plugin with Kotlin stubs for scan actions, annotations, tool window, settings
- MCP server with 6 tools (`sigil_scan`, `sigil_scan_package`, `sigil_clone`, `sigil_quarantine`, `sigil_approve`, `sigil_reject`) and 1 resource (`sigil://docs/phases`)
- Rust CLI project scaffolding (`cli/`) with Cargo.toml and command structure

---

## [0.4.0] — 2025-12-01

### Added
- `sigil fetch <url>` command for downloading and scanning files from URLs
- Archive detection and auto-extraction (`.tar.gz`, `.tgz`, `.zip`, `.tar.bz2`)
- `sigil diff` for comparing current scan against a baseline
- Dependency analysis: package count, unpinned version detection
- Permission/scope analysis: Docker privileged mode, GitHub Actions secrets, MCP tool configs
- MCP-specific pattern detection (`mcp_server`, `MCPServer`, `allow_dangerous`, `auto_approve`)

### Changed
- Network exfiltration phase expanded with Discord webhook, Telegram bot, ngrok, and DNS tunneling patterns
- Obfuscation phase improved with hex escape sequence detection

---

## [0.3.0] — 2025-11-15

### Added
- External scanner integration: semgrep, bandit, trufflehog, safety, npm audit
- Cloud threat intelligence (hash lookups via `GET /v1/threat/<hash>`)
- Signature caching (`~/.sigil/signatures.json` with 24-hour TTL)
- `sigil login` and `sigil logout` for API authentication
- JWT token storage and authenticated API requests

---

## [0.2.0] — 2025-11-01

### Added
- `sigil install` interactive installer
- `sigil aliases` shell alias management
- `sigil hooks` pre-commit hook installation
- Shell aliases: `gclone`, `safepip`, `safenpm`, `safefetch`, `audit`, `audithere`, `qls`, `qapprove`, `qreject`
- `.sigilignore` file support
- Path traversal protection on approve/reject
- Input validation for URLs, package names, and quarantine IDs

---

## [0.1.0] — 2025-10-15

### Added
- Initial release of the Sigil CLI (`bin/sigil`)
- Six-phase security scanner with weighted scoring
- Phase 1: Install hook detection (setup.py, npm postinstall, Makefile)
- Phase 2: Code pattern detection (eval, exec, pickle, child_process)
- Phase 3: Network/exfiltration detection (HTTP, webhooks, sockets)
- Phase 4: Credential access detection (ENV vars, API keys, SSH keys)
- Phase 5: Obfuscation detection (base64, charCode, hex)
- Phase 6: Provenance analysis (git history, binaries, hidden files)
- Quarantine-first workflow: clone, pip, npm, scan commands
- Verdict engine: CLEAN, LOW, MEDIUM, HIGH, CRITICAL
- Report generation with file paths and line numbers
- `sigil clone`, `sigil pip`, `sigil npm`, `sigil scan` commands
- `sigil approve`, `sigil reject`, `sigil list` quarantine management
- `sigil config` with `--init` flag

---

[Unreleased]: https://github.com/NOMARJ/sigil/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/NOMARJ/sigil/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/NOMARJ/sigil/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/NOMARJ/sigil/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/NOMARJ/sigil/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/NOMARJ/sigil/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/NOMARJ/sigil/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/NOMARJ/sigil/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/NOMARJ/sigil/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/NOMARJ/sigil/releases/tag/v0.1.0
