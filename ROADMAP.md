# Sigil Roadmap

How Sigil protects you today, and where we're headed next.

Last updated: 2026-02-19

---

## What you can do today

### Scan anything before it touches your project
Install a pip package, clone a repo, pull from npm — Sigil intercepts it, quarantines it, and scans it before any code executes. Nothing runs until you say so.

```bash
sigil pip requests        # download, quarantine, scan — then approve or reject
sigil npm leftpad
sigil clone https://github.com/someone/agent-toolkit
sigil scan ./vendor/       # scan code already on disk
```

Drop-in shell aliases (`safepip`, `safenpm`, `gclone`) make this feel native. A pre-commit hook catches problems before they leave your machine.

### Know exactly what's dangerous and why
Six scan phases catch the patterns that actually matter in supply chain attacks — not just CVEs, but the behavioral signals of malicious code:

- **Install hooks** that execute on `pip install` or `npm install`
- **Dangerous code patterns** like `eval()`, `pickle.loads()`, `child_process`
- **Network exfiltration** — outbound HTTP, webhooks to ngrok/pipedream, raw sockets
- **Credential access** — reads of `.aws/credentials`, SSH keys, API tokens
- **Obfuscation** — base64-encoded payloads, hex strings, charCode tricks
- **Provenance gaps** — missing git history, unexpected binaries, suspicious filenames

Every finding has a severity, a weight, and a snippet showing exactly which line triggered it. The final verdict (CLEAN through CRITICAL) is a single number you can act on.

### Get cloud threat intelligence during scans
When you're logged in, every scan checks your code against a shared database of known-malicious packages. Community-reported threats flow through a review pipeline and, once confirmed, automatically generate detection signatures that propagate to every connected scanner.

Your scans also feed publisher reputation — if a maintainer's packages keep getting flagged, their trust score drops, and future scans from that publisher get higher scrutiny.

### See everything in a dashboard
A web dashboard gives your team visibility into scan history, threat intelligence, and security posture:

- **Scan history** — every scan with verdict, risk score, and drill-down into findings
- **Threat intelligence** — known-malicious packages, community reports (with review workflow), and the full signature database
- **Team management** — invite members, assign roles, manage who can approve quarantined packages
- **Policies & alerts** — auto-approve low-risk packages, require manual review for high-risk, get Slack or webhook notifications when something bad is found

### Use it wherever you work
- **VS Code / Cursor / Windsurf** — packaged `.vsix` available; scan files and packages from the editor, findings in the Problems panel
- **JetBrains** — IntelliJ, WebStorm, PyCharm, GoLand and more; build with `gradle buildPlugin`, inline annotations and tool window
- **Claude Code / AI agents** — MCP server (`npx @nomark/sigil-mcp-server`) exposes scan, approve, and reject as tools your agent can call
- **GitHub Actions** — add `sigil-scan` to your CI pipeline, fail builds on findings, upload SARIF to Code Scanning
- **Any CI system** — JSON and SARIF output work with any pipeline

### Native Rust binary
The Rust CLI compiles and runs as a standalone binary — faster than the bash script with no shell dependency. Build with `cargo build --release` in the `cli/` directory.

### Compare scans over time
`sigil diff` compares your current scan against a baseline and tells you what's new, what's resolved, and what's unchanged. Useful for tracking whether a dependency update introduced new risks.

---

## What we're working on now

### Hosted cloud
Right now the API and dashboard run locally via Docker Compose. We're standing up the hosted version so you can sign up at sigilsec.ai and start scanning without running infrastructure — scan results, threat intel, and team management backed by managed Postgres, with signature distribution through a CDN.

---

## What's next

### Easier to install
The Rust binary and both IDE plugins now build and run. The remaining distribution steps:

- `brew install nomarj/tap/sigil` — Homebrew tap
- `npm install -g @nomarj/sigil` — npm global package
- VS Code Marketplace listing (`.vsix` is built; listing pending)
- JetBrains Marketplace listing (plugin builds; listing pending)

Once on the package managers, `sigil install --update` will handle automatic updates so users always have the latest signatures and scan rules.

### More ecosystems
Sigil currently scans pip, npm, and git repos. We want to cover the package managers where supply chain attacks are growing:

- **Docker / OCI images** — scan layers before running containers
- **Go modules** — `sigil go <module>`
- **Cargo crates** — `sigil cargo <crate>`
- **MCP server registries** — scan AI agent tooling before connecting it

Monorepo support will scan only the packages that changed in a commit, so large repos stay fast.

### Write your own scan rules
A YAML DSL for custom signatures so your team can codify internal policies:

```yaml
- id: my-org-no-telemetry
  phase: network_exfil
  severity: HIGH
  pattern: "analytics\\.track|segment\\.identify|mixpanel\\."
  description: "Telemetry SDK usage requires security review"
```

Rules sync to your team via the cloud, so everyone scans with the same policy.

### Enterprise security
For organizations that need audit trails and access control:

- **SSO / SAML** — sign in with your identity provider
- **Role-based access** — control who can approve, reject, or configure policies
- **Audit log** — tamper-proof record of every scan, approval, and policy change
- **Retention policies** — control how long scan results are stored

### Works in every CI system
GitHub Actions works today. Next:

- **GitLab CI** component
- **Jenkins** plugin
- **CircleCI** orb
- **Bitbucket Pipelines** pipe
- **Slack bot** that posts scan results to a channel
- **PagerDuty / Opsgenie** for critical findings

---

## Further out

Things we're thinking about but haven't committed to timelines:

- **AI-assisted triage** — an LLM explains each finding in plain English and suggests whether it's a real threat or a false positive
- **Marketplace verification badges** — a "Sigil Verified" badge that package registries can display for scanned-clean packages
- **Dependency graph visualization** — see your full dependency tree with risk scores at each node
- **SBOM generation** — produce a Software Bill of Materials in CycloneDX or SPDX format
- **Browser extension** — scan a GitHub repo page before you clone it
