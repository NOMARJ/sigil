# Changelog

All notable changes to Sigil are documented here. This project uses [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

Everything here came out of the prism-scanner review
([docs/research/prism-scanner-lessons.md](docs/research/prism-scanner-lessons.md)). Every
detection change was measured on the Datadog malicious-package set and a clean control
set before it was kept; the numbers are in the note.

### ✨ Added

#### CLI
- `sigil residue scan | plan | apply | rollback` — what installed agent tooling left on this machine: shell rc edits, cron/launchd/systemd/autostart/sudoers persistence, git hooks and `core.hooksPath`, credential file modes, leftover tool directories, `/etc/hosts` redirects of API hosts, global agent packages. `apply` backs every target up and `rollback` restores it; system files are reported, never changed
- `--format html`: one self-contained report page, no scripts
- Inline `sigil:ignore RULE-ID -- reason`, `sigil:ignore-next-line` and `sigil:ignore-file` markers; suppressed findings stay in the report (`inline_suppressed`, SARIF `suppressions`)
- `sigil scan <git-url>` clones into quarantine first
- Letter grade, recommendation, behaviour profile and key risks in every output; `summary.grade`, `summary.recommendation`, `summary.platform` and the top-level `profile` object in `--format json` (additive, ADR-0010)
- Rule metadata on findings: `remediation`, `references`, `tags` (JSON, SARIF `help` and `properties`, HTML)
- Correlation rules: `EXFIL-CHAIN-001` fires when a credential read reaches a network send within 20 lines and the value is what is sent
- `TYPOSQUAT-001`: direct dependencies one edit away from a top npm or PyPI name
- `HYGIENE-001..007`: source maps, `.env` files, private keys, `.npmrc`/`.pypirc`/`.netrc`, dumps shipped in a package
- New rules: `PERSIST-001..013` (cron, launchd, systemd, shell rc, authorized_keys, sudoers, hosts, Windows Run keys, git hooks, autostart), `MANIP-001..005` (gaslighting, guilt, authority impersonation, urgency bypass, emotional coercion aimed at an agent), `PROMPT-009..011`, `NET-013` (cloud metadata), `NET-014` (tunnel and dynamic-DNS hosts), `NET-015` (abused TLDs), `NET-017` (miners), `NET-018` (DNS exfiltration), `CRED-013..029` (vendor token shapes), `CRED-030..043` (credential stores, browser and keychain theft, same-line credential-plus-send), `SKILL-007..010` (malformed manifests, wildcard grants, destructive grants, downloader grants), `INSTALL-REF-001` (a lifecycle script runs a local file with findings)
- `CRED-001`/`CRED-002` now cover every `*_KEY`/`*_SECRET`/`*_TOKEN` environment read at Medium (with `NEXT_PUBLIC_`/`REACT_APP_`/`VITE_` excluded)
- `dist/` and `build/` are scanned: in a published package they are the shipped code (230 of the 844 malicious packages in the evaluation set carry files under `dist/`); a git checkout's `.gitignore` still applies
- Prompt-injection rules also cover `.cursorrules`, `.windsurfrules`, `.clinerules`, `AGENTS.md`, `CLAUDE.md`, `.mdx` and `.rst`
- Files past the 10 MB content cap are no longer skipped: the first and last 2 MB are scanned and tail findings carry real line numbers (a 22 MB `setup.py` in the evaluation set hides a dropper behind one byte literal); `PROV-007` flags an install script over 1 MB at High and `PROV-008` a source script over 8 MB at Medium
- `SUPPLY-020`: a Windows executable (MZ header) carried in a string or bytes literal; `MANIP-006`: instruction text telling the agent to act without the user; `PROMPT-011` also covers "override your instinct/judgement/defaults/training"

#### GitHub Action
- `upload-sarif` and `sarif-file` inputs with a guarded `codeql-action/upload-sarif` step; `grade`, `badge` and `sarif-file` outputs; the grade badge in the job summary

#### MCP server
- `sigil_grade`, `sigil_residue_scan`, `sigil_residue_plan` (apply and rollback are deliberately not tools)
- `server.json` and `mcpName` for the official MCP registry (publishing follows the npm release)

#### Packaging and community
- `python/`: `pip install sigilsec`, a standard-library wrapper that downloads the release binary and verifies it against `SHA256SUMS.txt` before running it (`sigil-cli` is taken on PyPI)
- Issue templates (bug, false positive, false negative, new rule, threat report), pull request template, code of conduct, and a CONTRIBUTING rewrite with the rule-authoring guide
- English and Chinese trigger phrases in the skill descriptions; `sigil-skill/skill.json`

### 🎯 Precision

The verdict is what a CI gate reads, and it fired on `requests` and `urllib3`. These
changes are about that; each was measured on the clean control set and the malicious set
before it was kept, and the numbers below are from those runs.

- **Evidence-gated CRITICAL.** New optional rule field `evidence: standalone | corroborate`
  (default `standalone`, additive per ADR-0010). A CRITICAL RISK verdict now needs a
  standalone Critical finding, or two corroborating Criticals from different rules. Marked
  corroborating: `CRED-006` (an embedded private key), `INSTALL-001` (`setup.py cmdclass`),
  `CRED-030` (a credential path named near a home directory) — each one a shape that
  documentation, test fixtures and defensive code produce as readily as malware. Clean
  control packages returning CRITICAL: 6 of 20 → **0 of 20**
- **Score saturation.** At most three findings per `(rule, file)` pair contribute to the
  score; every finding is still reported. One conformance table in `idna` matched a single
  rule 1,680 times, which was 16,800 of the 19,140 points that made the package HIGH RISK
- **`TYPOSQUAT-001` judges the dependency a manifest actually declares.**
  `[project.optional-dependencies]` and `[dependency-groups]` were read as `name = version`
  tables, so a group name became a package (`xml = ['lxml>=5.3.0']` declared "xml") and
  each list item was split on the `=` inside its version specifier, reporting `pytest>` as
  a typosquat of `pytest`. Environment markers supplied stray quotes (`'PyPy'`), and npm
  aliases (`"prettier-2": "npm:prettier@^2"`) were judged by the local label rather than
  the aliased package. On the 300-package clean control set: 82 findings across 35
  packages → **0**
- **`SKILL-003` no longer fires on a manifest that names an interpreter.**
  `"command": "node"` with the script in `args` is how every MCP server is declared,
  including the one this repository ships; a hello-world MCPB manifest was Critical. It now
  requires the value to hand over execution — a shell, inline code (`-c`, `-e`), a pipe or
  chain, or a URL
- **`INSTALL-008` detects `backend-path`** — an in-tree build backend, the shape that runs
  repository code at build time — instead of allowlisting backend names on the matched
  line, which let the audited file silence the rule with a substring or a comment
- **`PROMPT-014` stays out of README and INSTALL files.** `Edit \`.cursor/mcp.json\`` is
  how an MCP server documents its own installation: 25 of 89 real registry packages hit it,
  against 8 of 204 malicious skill samples
- **`SKILL-013` (traversal string) and `SKILL-023` (SSH key name) are Medium.** Across 450
  clean packages they fired on 21, every hit the vocabulary of the domain — paramiko's own
  docs, `"../../../etc/passwd"` inside the test that rejects it
- Typosquat allowlist entries must name a published package. Removed `jquery3`, `eslint4`,
  `reduxs`, `vue3`, `pillow2`, `toml2`, `cffi2` — an entry for a name nobody has published
  pre-authorises whoever registers it next. Added the near-names measured against the clean
  control set: `pathe`, `upath`, `tsd`, `http-proxy-3`, `eclint`, `fake`, `authlib`,
  `psycopg`, `psycopg-binary`, `tomli-w`
- `scripts/rule_precision.py` — the per-rule clean-set precision table, on demand

### ⚡ Performance

- **Two-tier rule matching.** `RegexSet::matches` has to run the NFA simulation to report
  *which* patterns matched, and it ran once per line. Each rule is now searched once
  against the whole file, and only the survivors walk the lines. The 268-sample evaluation
  subset went from 1,040 s to 117 s of scanner time on an unloaded box — **8.9×** — with
  findings identical position-for-position, fingerprints included
- **Per-file scan budget** (`SIGIL_FILE_BUDGET_SECS`, default 30 s) so one pathological
  file cannot hold a scan hostage. Truncation is reported as a Medium finding whatever
  `--phases` selects: a scan that analysed nothing must not read as a scan that found
  nothing
- `SIGIL_TIMING=1` prints per-phase and slowest-file timings to stderr

### 🔍 Skills

- 27 rules for the behaviours the missed samples actually use: weakening access control,
  injecting an override into an auth file, exfiltrating project context to a fixed
  recipient, acting without user confirmation, persisting instructions into agent config
  directories, harvesting application credentials, and — `SKILL-024`/`SKILL-025` — the
  fake-prerequisite install ("download this zip and run the executable", "visit this
  glot.io snippet and execute the command in Terminal"), which no rule covered and which
  0 of 18,554 legitimate files match
- ai-skills bucket on the 268-sample harness, at ≥ High: **48.3% → 90.0%**

### 📦 Distribution

- `.github/workflows/publish-pypi.yml` — PyPI trusted publishing for `sigilsec`, on a
  release tag, no token and no secret. It refuses to publish unless that tag already has a
  published release with assets, since the wrapper's whole job is to download one
- `scripts/check_versions.py` and `make check-versions`: the Cargo, wrapper and plugin
  versions cannot drift apart silently
- `sigil known-good build | merge | install | remove | status`, `scripts/build_known_good.py`,
  and a manifest of the 300-package index (coordinates, sizes, hashes) so it can be rebuilt
  and verified rather than vendored. Drift is only reported when the scanned tree declares
  the indexed coordinate in its own manifest — without that check, the genuine
  registry-signed `semver` 7.7.2 tarball came back CRITICAL RISK against an index built
  from 7.8.5
- `make benchmark`, `evaluation_results/HISTORY.md`, `docs/RELEASING.md`, `docs/benchmarks.md`

### 🐛 Fixed
- MCP server scan tools printed `undefined` for verdict and score: they read the top level while the JSON contract puts the scalars under `summary`
- `NET-015` matched URL *paths* that end in an abused TLD (`/assets/file.download`)
- `sigil diff` rejects a residue document as a baseline instead of failing on a missing field
- The scan cache is keyed on the corpus digest as well as the binary version: a rule update (installed corpus or a rebuild under the same version) no longer serves stale verdicts

### 📝 Documentation
- CLI reference: scan options, host residue, inline suppression, walker policy; ADR-0010 addendum listing the additive keys; research note on prism-scanner with measured comparisons
- Research note on the MCP registry: 99 of 8,127 npm-packaged servers name a package that cannot be installed as listed, and every one of the 44 withdrawn names is unscoped — the kind anyone can claim once it is gone. `scripts/registry_integrity.py` and `scripts/registry_scan.py` reproduce both halves

## [1.3.6] - 2026-08-30

Fixes for every code-level finding of the 2026-08-30 anonymous cold-start audit.

### 🐛 Fixed

#### CLI
- Prompt Injection, Skill Security, and Inference Security findings now render in the default text output (previously scored but never printed)
- `--format json` emits a single valid JSON document (`{"summary", "findings"}`); progress lines go to stderr
- `sigil clone` no longer flags its own shallow clone (PROV-005) and PROV-006 no longer fires on plain directory scans
- Post-scan hint shows the real `sigil explain <scan.json>` usage; `sigil approve` prints where the approved code lives

#### API
- `/forge/search` no longer 500s on fractional trust scores (`ClassifiedTool.trust_score` widened to float)
- `GET /scans?scope=all` no longer hangs 30s and 500s: slim column selection with server-side finding counts, MSSQL string-JSON row mapping fixed, new covering indexes (migration 009)
- Scan submission accepts findings with `"line": null` (unblocks `sigil explain` on real scans)
- Plan/credit rejections return honest 402/403 instead of `401 "Invalid or expired token"`; Auth0 `/userinfo` responses are cached per-token and its outages map to 503

#### Dashboard
- Unverified-email sessions get a "check your inbox" screen instead of a silent redirect loop to /login; login page gained a create-account link
- Scan History has a 15s timeout and a retry-able error state instead of an infinite skeleton
- Free-plan policy settings are disabled behind the plan gate and save errors are surfaced
- Community scan feed labeled honestly with an own-scans empty state; annual-discount badge computed from live prices (33%, was hardcoded 17%); false-positive banner uses the measured 70%→30% figures
- Removed the dead free-tier OnboardingFlow and its fake-key API stubs

#### Release & install
- Linux binaries build on ubuntu-22.04 (glibc 2.35 floor, was 2.38/2.39)
- `install.sh` no longer swallows errors (glibc and checksum failures surface distinctly), falls back to the releases/latest redirect when the GitHub API is rate-limited, honors `SIGIL_VERSION`
- CI action summary is generated from scan JSON (was gated on a never-written report file); footer link fixed to NOMARJ org; macOS release notes use `shasum -a 256`

### 📝 Documentation
- Removed six documented-but-nonexistent commands (`search`, `discover`, `info`, `logout`, `shell-init`, `scan npm:`); corrected verdict thresholds, exit codes, quarantine/approve semantics, install methods, phase counts (8), pricing claims, and API-token instructions (device flow only until key issuance ships)

## [1.1.1] - 2026-03-08

### ✨ Added

#### Trending Tools Backend Infrastructure
- **Registry Statistics Engine**: Background processing of 29,944+ packages across ecosystems
- **Trending Analytics API**: `/v1/registry/trending` endpoint with real-time statistics
- **Enhanced Search API**: Multi-criteria sorting with performance optimization
- **Intelligent Caching**: Database-backed caching with 15-minute update intervals
- **Background Job Processing**: Automated statistics collection every 15 minutes

#### Production Infrastructure
- **Azure Container Apps Integration**: Complete deployment with health monitoring
- **Database Schema**: New `forge_tool_metrics` and `forge_trending_cache` tables
- **Performance Optimization**: Indexed queries for large dataset operations
- **Monitoring & Logging**: Comprehensive health checks and performance tracking

### 🔧 Changed

#### Performance Improvements
- **Statistics Computation**: <1 second processing for 29,000+ packages
- **API Response Times**: <200ms for cached trending queries
- **Background Processing**: 839ms average cache update time
- **Database Efficiency**: Optimized indexes for high-performance queries

#### API Enhancements
- Enhanced registry search with multiple sorting options
- Improved error handling and graceful degradation patterns
- Better caching strategies for high-traffic endpoints
- Real-time statistics computation with automatic refresh

### 🐛 Fixed

#### Critical Production Issues
- **Container Crashes**: Fixed ModuleNotFoundError in Docker environment (#52-#62)
- **Import Paths**: Resolved 39 Python files with 110 import corrections
- **Database Connections**: Enhanced connection handling in containerized environment
- **Scanner Dependencies**: Fixed circular import issues in scanner modules

#### Docker Compatibility
- Updated all relative imports to absolute paths with `api.` prefix
- Fixed function-level imports missed in initial corrections
- Corrected test file imports for consistent CI/CD execution
- Resolved WORKDIR=/app compatibility issues

### 📊 Production Metrics

#### Live Statistics
- **Total Security Scans**: 56,100
- **Unique Packages Analyzed**: 29,944
- **Threats Detected**: 20,541
- **Supported Ecosystems**: 5 (npm, PyPI, RubyGems, Go, Maven)
- **Classification Types**: SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN

#### Performance Benchmarks
- **Registry Computation**: <1 second
- **Health Check Response**: <100ms
- **API Query Response**: <200ms
- **Cache Update Speed**: 839ms
- **Container Uptime**: 100% since deployment

### 🔗 API Changes

#### New Endpoints
```http
GET /v1/registry/trending     # Registry trending statistics
GET /v1/registry/search       # Enhanced search with sorting
GET /health                   # Service health monitoring
```

#### Enhanced Parameters
- Search sorting: `newest`, `threats_desc`, `downloads_desc`
- Trending timeframes: `24h`, `7d`, `30d`
- Performance filtering and pagination support

### 🏗️ Infrastructure

#### Azure Deployment
- **Container**: sigil-api--0000057 (Running)
- **Database**: Azure SQL with optimized schema
- **Background Jobs**: Statistics collection every 15 minutes
- **Monitoring**: Full logging and health checks
- **Endpoints**: All trending APIs operational

#### Database Schema
- Added trending analytics tables with proper indexing
- Migration scripts for production deployment
- Optimized queries for large dataset processing
- Automatic cache refresh and cleanup

### 📚 Documentation

- Complete deployment guide: `docs/internal/DEPLOYMENT_TRENDING_TOOLS.md`
- API documentation for trending endpoints
- Database schema reference for metrics tables
- Performance tuning and monitoring guidelines

### 🔒 Security & Reliability

- All endpoints secured with authentication and authorization
- Rate limiting and quota enforcement for resource protection
- Input validation and sanitization for API parameters
- Circuit breaker patterns for external service dependencies
- Graceful degradation when caching unavailable

---

## [1.0.6] - 2026-03-15

### Fixed
- **Critical false positive remediation** - Addressed product-killing false positive rate where clean repos scored CRITICAL (336 pts) instead of LOW RISK  
- **Unicode boundary crashes** - Fixed Rust CLI panics on multi-byte UTF-8 characters with safe string handling
- **RegExp.exec() false positives** - Context-aware detection now distinguishes JavaScript regex methods from dangerous shell execution
- **Documentation severity** - Files in `docs/`, `*.md`, `README*` now receive appropriately reduced severity (HIGH → LOW)
- **API call filtering** - Legitimate calls to Anthropic, OpenAI, GitHub APIs no longer flagged as suspicious
- **String literal parsing** - eval() references in documentation strings and regex patterns correctly filtered
- **node_modules exclusion** - Vendor directories now skipped by default preventing crashes and noise

### Added
- **Context-aware pattern matching** - Scanner now analyzes code context before flagging potential threats
- **File classification system** - Automatic severity adjustment based on file type (docs, tests, source)
- **Safe domains allowlist** - Known-legitimate API endpoints filtered from network scanning
- **Unicode-safe file processing** - Lossy UTF-8 handling prevents scanner crashes
- **Regression test suite** - Comprehensive false positive prevention testing

### Impact
- **92% reduction** in false positive rate (336 → 27 points for typical client repos)
- **Product trust restoration** - Clean repositories now receive appropriate LOW RISK verdicts
- **Security coverage maintained** - All real threats still detected correctly

Based on client feedback reporting critical trust erosion from false positive scanning results.

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
- Authentication guide with login, token refresh, and troubleshooting
- Claude Code native plugin with 4 skills + 2 security agents
- Dashboard `.env.example` documenting all required Supabase env vars for OAuth

### Fixed — Production Hardening (P1)
- **API: Security headers middleware**: Added `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, and `Strict-Transport-Security` (non-debug) headers
- **API: Health check returns 503 when degraded**: `/health` now returns HTTP 503 with `"status": "degraded"` when database is disconnected
- **API: Docs disabled in production**: `/docs`, `/redoc`, `/openapi.json` are only available when `SIGIL_DEBUG=true`
- **API: Stripe placeholder validation**: Startup warns if Stripe is configured but price IDs still contain placeholder values
- **API: Config cleanup**: Added `frontend_url` setting, fixed `smtp_from_email` to `alerts@sigilsec.ai`
- **Dashboard: AuthGuard fix**: Added `/reset-password` to `PUBLIC_ROUTES` so users can reset passwords without being redirected
- **Dashboard: PaginatedResponse type**: Added `has_more?: boolean` to match API pagination responses
- **Dashboard: Login navigation**: Replaced `window.location.href` with `router.push()` for proper SPA navigation
- **Dashboard: Metadata**: Added favicon icon reference and viewport export for mobile support
- **Dashboard: Console cleanup**: Removed `console.warn` from API client
- **CLI: Version command**: Added `sigil version` / `sigil --version` / `sigil -v` commands
- **CLI: Unknown command handling**: Unknown commands now show error and suggest `sigil help`
- **Docker: Dockerfile.cli runs as non-root**: Added `sigil` user, health check, and `USER sigil` directive
- **Docker: Label consistency**: Standardized all Dockerfile labels to `team@sigilsec.ai` and `github.com/NOMARJ/sigil`
- **Docker: docker-compose dashboard fix**: Removed conflicting `build:` section that was overridden by `image: node:20-slim`
- **CI: Release publish hardening**: Replaced `continue-on-error: true` on npm/cargo publish with inline warnings
- **Docs: SECURITY.md**: Created responsible disclosure policy
- **Docs: Configuration verdict fix**: Changed `"HIGH"` to `"HIGH_RISK"` in policy example
- **Docs: Installation version**: Updated to use `sigil version` command with correct output

### Fixed — Production Readiness (P0)
- **Dashboard type alignment**: `Verdict` enum changed from `"LOW" | "MEDIUM" | "HIGH"` to `"LOW_RISK" | "MEDIUM_RISK" | "HIGH_RISK"` across all dashboard components to match API `Verdict` enum
- **Dashboard `Scan` type alignment**: Frontend fields updated from `package_name`/`source`/`score`/`status` to `target`/`target_type`/`risk_score`/`threat_hits`/`metadata` to match API `ScanListItem`
- **Dashboard `DashboardStats` type alignment**: Changed from `trend_scans`/`trend_threats`/`scans_today` to `scans_trend`/`threats_trend`/`approved_trend`/`critical_trend` to match API
- **Dashboard `PaginatedResponse` alignment**: Changed from `has_more` to computed pagination with `upgrade_message` field
- **VerdictBadge component**: Updated style records for `_RISK` suffixed keys, added `verdictLabel()` display helper and fallback styles
- **ScanTable component**: Updated column mappings and headers (`Package` -> `Target`, `Source` -> `Type`)
- **Scan detail, scans list, threats, settings pages**: All updated for `_RISK` suffixed verdict values
- **API: Dashboard stats unlocked for FREE tier**: Removed `require_plan(PlanTier.PRO)` from `get_dashboard_stats` — aggregate stats now available to all authenticated users
- **API: FREE users get limited scan preview**: Changed from empty list to last 5 scans with `upgrade_message` for FREE users
- **API: JWT secret startup warning**: Added CRITICAL log on startup if default JWT secret is still in use
- **API: CORS tightened**: Changed from `allow_methods=["*"], allow_headers=["*"]` to explicit method and header whitelist
- **API `.env.example` updated**: Added `SIGIL_SUPABASE_JWT_SECRET` with security documentation
- Standardized all URLs to `api.sigilsec.ai` / `app.sigilsec.ai` — removed legacy `api.sigil.nomark.dev` references
- Standardized verdict enum naming in documentation to use `_RISK` suffix (`LOW_RISK`, `MEDIUM_RISK`, `HIGH_RISK`)

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
- Verdict engine: CLEAN, LOW_RISK, MEDIUM_RISK, HIGH_RISK, CRITICAL
- Report generation with file paths and line numbers
- `sigil clone`, `sigil pip`, `sigil npm`, `sigil scan` commands
- `sigil approve`, `sigil reject`, `sigil list` quarantine management
- `sigil config` with `--init` flag

---

[Unreleased]: https://github.com/NOMARJ/sigil/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/NOMARJ/sigil/compare/v0.9.0...v1.1.1
[0.9.0]: https://github.com/NOMARJ/sigil/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/NOMARJ/sigil/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/NOMARJ/sigil/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/NOMARJ/sigil/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/NOMARJ/sigil/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/NOMARJ/sigil/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/NOMARJ/sigil/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/NOMARJ/sigil/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/NOMARJ/sigil/releases/tag/v0.1.0
