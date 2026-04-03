# SIGIL — Distribution Roadmap & Engineering Spec

**Product:** Sigil by NOMARK (sigilsec.ai)
**Type:** Automated security audit CLI for AI agent code, MCP servers, packages, and repos
**Status:** Bash prototype (`qaudit`) built, PRD complete, Rust CLI planned
**Validated baseline:** 97.96% detection rate (Azure production dataset)
**Date:** 2026-03-29
**Author:** Reece (CTO/Founder, NOMARK)

---

## 1. Distribution thesis

Sigil follows the **open-source CLI → community → commercial** distribution model. No social media. No paid ads. No algorithm games.

The product is the distribution. The research is the marketing. The CI/CD integration is the sales team.

**Evidence base:** Snyk went from 1,000 CLI downloads to 2.5M developers and $343M ARR on this exact model. Sentry, HashiCorp, and Supabase validated the same flywheel. The pattern is proven.

**Compounding loop:**

```
Developer installs CLI
  → scans a repo
  → shares results with team
  → team adds to CI/CD
  → Sigil appears in every PR
  → more developers discover it
  → some work at enterprises
  → enterprise needs dashboard/compliance
  → commercial conversion
  → revenue funds more research
  → better detection
  → more developers trust it
  → repeat
```

---

## 2. Phase overview

| Phase | Name | Timeframe | Objective |
|-------|------|-----------|-----------|
| 1 | Frictionless adoption | Months 1–3 | Single-command install, zero-config scan, ship Rust CLI |
| 2 | Workflow embedding | Months 2–6 | CI/CD integrations, "Scanned by Sigil" branding |
| 3 | Programmatic SEO | Months 2–12 | Automated page generation, long-tail keyword capture |
| 4 | Security research publishing | Months 3–12 | Threat reports, CVE disclosures, credibility engine |
| 5 | Commercial tier | Months 6–18 | Dashboard, team features, compliance, monetisation |

Phases overlap deliberately. SEO and research start before the flywheel is spinning — they create the surface area for discovery.

---

## 3. Phase 1 — Frictionless adoption

### 3.1 Goal

A developer should go from "never heard of Sigil" to "first scan complete" in under 60 seconds.

### 3.2 Atomic network

The smallest viable use case: **one developer scanning one MCP server or AI agent repo on their local machine.** No account. No signup. No telemetry. Just output.

### 3.3 Engineering requirements

#### 3.3.1 Rust CLI binary

| Requirement | Detail |
|-------------|--------|
| Language | Rust (single static binary, no runtime deps) |
| Target platforms | macOS (arm64, x86_64), Linux (x86_64, arm64), Windows (x86_64) |
| Binary size | < 20MB target |
| Startup time | < 200ms to first output |
| Offline-capable | Full scan capability with no network required |

#### 3.3.2 Installation methods

All methods must be documented and tested in CI.

```bash
# macOS
brew install nomark/tap/sigil

# Rust ecosystem
cargo install sigil-cli

# Universal (Linux/macOS)
curl -fsSL https://sigilsec.ai/install.sh | sh

# Node ecosystem (for MCP/agent developers)
npx sigil-cli scan .

# Docker
docker run --rm -v $(pwd):/scan ghcr.io/nomark/sigil scan /scan

# Windows
winget install nomark.sigil
scoop install sigil
```

**Acceptance criteria:** Each method installs and runs a scan in < 60 seconds on a cold machine. Tested weekly in CI.

#### 3.3.3 Zero-config scanning

```bash
# Scan current directory — no flags, no config, no setup
sigil scan .

# Scan a remote repo
sigil scan https://github.com/org/repo

# Scan a specific MCP server
sigil scan --target mcp ./server.ts

# Scan an npm/pip package
sigil scan --pkg @modelcontextprotocol/server-filesystem
```

Default behaviour: scan everything detectable, output human-readable summary to stdout, exit code 0 (clean) or 1 (findings).

#### 3.3.4 Output formats

```bash
sigil scan . --format table    # default: human-readable table
sigil scan . --format json     # machine-readable, CI-friendly
sigil scan . --format sarif    # GitHub Security tab compatible
sigil scan . --format markdown # for PR comments
```

#### 3.3.5 First-run experience

On first scan, output must include:

```
✓ Scanned 47 files in 1.2s
✓ 3 findings (2 high, 1 medium)

┌──────────┬──────────┬─────────────────────────────────┬────────┐
│ Severity │ Rule     │ Description                     │ File   │
├──────────┼──────────┼─────────────────────────────────┼────────┤
│ HIGH     │ SGL-001  │ Unrestricted file system access  │ srv.ts │
│ HIGH     │ SGL-003  │ No input validation on tool args │ srv.ts │
│ MEDIUM   │ SGL-012  │ Verbose error messages           │ srv.ts │
└──────────┴──────────┴─────────────────────────────────┴────────┘

Full report: sigil scan . --format json
Docs: https://sigilsec.ai/rules
```

No marketing. No upsell. No "sign up for more." Just useful output.

### 3.4 Deliverables

- [ ] Rust CLI compiling on all 5 target platforms
- [ ] Homebrew tap (`nomark/tap/sigil`)
- [ ] `cargo install` published to crates.io
- [ ] Install script at `sigilsec.ai/install.sh`
- [ ] Docker image on GHCR
- [ ] npx wrapper package on npm
- [ ] GitHub repo with README showing single-command scan + real output
- [ ] 97.96% detection rate validated against Azure dataset in CI (regression gate)
- [ ] Release automation: GitHub Actions → build → test → publish all channels

### 3.5 Metrics

| Metric | Target (M3) |
|--------|-------------|
| GitHub stars | 500 |
| Unique installs (all channels) | 1,000 |
| Weekly active scanners | 200 |
| Mean time to first scan | < 60s |

---

## 4. Phase 2 — Workflow embedding

### 4.1 Goal

Sigil runs automatically in shared team workflows. One developer adds it; every team member sees it.

### 4.2 CI/CD integrations

#### 4.2.1 GitHub Action

```yaml
# .github/workflows/sigil.yml
name: Sigil Security Scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: nomark/sigil-action@v1
        with:
          format: sarif
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sigil-results.sarif
```

**Key feature:** SARIF upload integrates findings directly into GitHub's Security tab. Developers see findings inline on PRs without leaving GitHub.

#### 4.2.2 GitLab CI template

```yaml
include:
  - remote: 'https://sigilsec.ai/ci/gitlab-template.yml'

sigil-scan:
  extends: .sigil-scan
  variables:
    SIGIL_FAIL_ON: high
```

#### 4.2.3 Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/nomark/sigil
    rev: v0.1.0
    hooks:
      - id: sigil-scan
        args: ['--fail-on', 'high']
```

#### 4.2.4 VS Code extension (Phase 2b)

Real-time scan results as inline diagnostics. Not required for initial flywheel, but accelerates individual developer adoption.

### 4.3 "Scanned by Sigil" branding

Every scan report output (JSON, SARIF, Markdown) includes:

```json
{
  "tool": {
    "name": "Sigil",
    "version": "0.1.0",
    "url": "https://sigilsec.ai"
  }
}
```

Markdown PR comment format:

```markdown
## 🔒 Sigil Security Scan

3 findings (2 high, 1 medium) — [Full report](link)

_Scanned by [Sigil](https://sigilsec.ai) · AI agent security audit_
```

This is the Calendly mechanic. Every PR comment is a product demo visible to the entire team.

### 4.4 Deliverables

- [ ] `nomark/sigil-action` GitHub Action published to Marketplace
- [ ] GitLab CI template hosted at `sigilsec.ai/ci/`
- [ ] Pre-commit hook configuration
- [ ] SARIF output validated against GitHub Security tab
- [ ] Markdown PR comment bot (GitHub App)
- [ ] Documentation: "Add Sigil to your CI in 5 minutes"

### 4.5 Metrics

| Metric | Target (M6) |
|--------|-------------|
| GitHub Action installs | 200 |
| CI/CD pipelines running Sigil | 500 |
| Repos with Sigil in pipeline | 300 |
| GitHub stars | 2,000 |

---

## 5. Phase 3 — Programmatic SEO

### 5.1 Goal

Capture organic search traffic for AI agent security queries. AI agent security is a new category — SEO competition is near-zero. First-mover advantage is massive.

### 5.2 Page templates

Each template is a programmatic page type generated from structured data.

#### 5.2.1 Rule documentation pages

```
URL: sigilsec.ai/rules/SGL-001
Data source: Rule definitions in codebase
Volume: 1 page per rule (50–200+ pages)
Target keywords: "[rule description] mcp security", "ai agent [vulnerability type]"
```

Content: rule description, severity, code examples (vulnerable + fixed), detection logic, references.

#### 5.2.2 Package audit pages

```
URL: sigilsec.ai/audit/@modelcontextprotocol/server-filesystem
Data source: Automated scans of popular MCP packages
Volume: 1 page per scanned package (500+ pages)
Target keywords: "[package name] security", "[package name] vulnerabilities"
```

Content: automated scan results, finding summary, last scanned date, version history.

#### 5.2.3 Comparison pages

```
URL: sigilsec.ai/compare/sigil-vs-snyk
URL: sigilsec.ai/compare/sigil-vs-trivy
URL: sigilsec.ai/compare/sigil-vs-semgrep
Data source: Manual + automated feature comparison
Volume: 10–20 pages
Target keywords: "[tool] vs [tool]", "best mcp security scanner"
```

Content: feature matrix, use case fit, honest assessment. No marketing spin.

#### 5.2.4 Vulnerability database pages

```
URL: sigilsec.ai/vuln/CVE-2026-XXXXX
URL: sigilsec.ai/vuln/SGL-2026-001
Data source: Discovered vulnerabilities, CVE references
Volume: Grows with research output
Target keywords: "[CVE ID]", "[vulnerability description]"
```

Content: description, affected packages/tools, remediation, Sigil detection status.

### 5.3 Technical implementation

```
Stack: Static site generator (Astro or Next.js SSG)
Data: JSON/YAML files in repo, generated by CI
Build: Automated rebuild on data change
Hosting: Cloudflare Pages or Vercel (edge CDN)
```

SEO requirements per page:
- Unique title tag with primary keyword
- Structured data (JSON-LD) for software application and security advisory schemas
- Canonical URL
- Internal linking to related rules/packages
- Last-updated timestamp (freshness signal)

### 5.4 Deliverables

- [ ] Page template system with 4 template types
- [ ] Automated data pipeline: scan results → JSON → static pages
- [ ] `sigilsec.ai/rules/` section live with all rules
- [ ] `sigilsec.ai/audit/` section live with top 50 MCP packages
- [ ] `sigilsec.ai/compare/` section live with top 5 comparisons
- [ ] Google Search Console configured, sitemap submitted
- [ ] Internal linking system between related pages

### 5.5 Metrics

| Metric | Target (M12) |
|--------|-------------|
| Indexed pages | 500+ |
| Monthly organic visitors | 5,000 |
| Keyword rankings (top 10) | 200 |
| Backlinks from programmatic pages | 50 |

---

## 6. Phase 4 — Security research publishing

### 6.1 Goal

Establish Sigil as the authority on AI agent security. Every published report is a lead magnet, a backlink generator, and a credibility builder.

### 6.2 Publication cadence

| Publication | Frequency | Format |
|-------------|-----------|--------|
| State of AI Agent Security report | Quarterly | PDF + web (gated for email) |
| Vulnerability disclosures | As discovered | Blog post + CVE filing |
| Technical deep-dives | Monthly | Blog post |
| MCP attack surface analysis | Bi-annually | Long-form report |

### 6.3 Data sources

All research must use **real data only**. No synthetic data. No fabricated statistics. Reference: CLAUDE.md "No Fake Data, Ever" rule.

Sources:
- Aggregated (anonymised) scan telemetry (opt-in only)
- Public package registry analysis
- GitHub public repository scanning (responsible disclosure)
- Azure production dataset (existing validated baseline)

### 6.4 State of AI Agent Security report spec

Quarterly report structure:

```
1. Executive summary (1 page)
2. Methodology (data sources, scan parameters, date range)
3. Key findings (top 5, with data)
4. Vulnerability trends (quarter-over-quarter)
5. Most common finding categories
6. MCP server security posture (aggregate)
7. Package ecosystem analysis
8. Recommendations
9. Appendix: full data tables
```

Distribution: ungated web version (for SEO) + gated PDF download (for email capture). No aggressive lead nurture. One welcome email, then add to quarterly report list.

### 6.5 Responsible disclosure protocol

```
1. Discovery → internal validation
2. Vendor notification (90-day disclosure window)
3. CVE filing (if applicable)
4. Public disclosure with remediation guidance
5. Sigil rule update (detection for the vulnerability)
6. Blog post with technical analysis
```

### 6.6 Deliverables

- [ ] Blog infrastructure on sigilsec.ai/blog
- [ ] First "State of AI Agent Security" report
- [ ] Responsible disclosure policy page
- [ ] Email capture for report distribution (minimal: email only)
- [ ] 3 technical deep-dives published
- [ ] At least 1 CVE filed or vulnerability disclosed

### 6.7 Metrics

| Metric | Target (M12) |
|--------|-------------|
| Report downloads | 500 |
| Email subscribers | 1,000 |
| Backlinks from research | 100 |
| Media/blog citations | 10 |

---

## 7. Phase 5 — Commercial tier

### 7.1 Goal

Monetise without killing the flywheel. The free CLI stays free forever.

### 7.2 Tier structure

| Feature | Free (CLI) | Team | Enterprise |
|---------|-----------|------|------------|
| Local scanning | ✓ | ✓ | ✓ |
| All rules | ✓ | ✓ | ✓ |
| JSON/SARIF output | ✓ | ✓ | ✓ |
| CI/CD integrations | ✓ | ✓ | ✓ |
| Hosted dashboard | — | ✓ | ✓ |
| Scan history & trends | — | ✓ | ✓ |
| Team management | — | ✓ | ✓ |
| Policy enforcement | — | ✓ | ✓ |
| Compliance reporting | — | — | ✓ |
| SSO/SAML | — | — | ✓ |
| Audit logs | — | — | ✓ |
| Priority rule updates | — | — | ✓ |
| SLA support | — | — | ✓ |
| On-premise deployment | — | — | ✓ |
| Custom rules | — | — | ✓ |

### 7.3 Pricing (indicative)

| Tier | Price |
|------|-------|
| Free | $0 forever |
| Team | $49/month per 10 repos |
| Enterprise | Custom (contact sales) |

Pricing validated during Phase 5. Do not pre-announce.

### 7.4 Critical design principle

**The free tier must be genuinely useful.** Not crippled. Not nagware. Not a demo. A developer using only the free CLI should get real value and never feel pressured to upgrade. The commercial tier sells to a different buyer (security leads, CTOs) solving a different problem (visibility, compliance, governance).

### 7.5 Dashboard engineering requirements

| Requirement | Detail |
|-------------|--------|
| Stack | Web app (React/Next.js), API (Rust or Go) |
| Auth | GitHub OAuth (primary), email/password, SSO/SAML (Enterprise) |
| Data | Scan results uploaded from CLI (opt-in flag: `sigil scan . --upload`) |
| Hosting | Single-tenant option for Enterprise, multi-tenant for Team |
| Privacy | No scan data sent without explicit opt-in. Ever. |

### 7.6 Deliverables

- [ ] Team tier dashboard MVP (scan history, team view, basic policy)
- [ ] `--upload` flag in CLI with auth token
- [ ] Billing integration (Stripe)
- [ ] Pricing page on sigilsec.ai
- [ ] Self-serve signup flow
- [ ] Enterprise tier scoping document

### 7.7 Metrics

| Metric | Target (M18) |
|--------|-------------|
| Free → Team conversion | 2–5% of active teams |
| Team tier MRR | $5K |
| Enterprise pipeline | 3 qualified conversations |
| Net revenue retention | > 120% |

---

## 8. What we do NOT do

Explicit list of activities that are out of scope. If it's not on the roadmap, it doesn't get built.

- **No social media content strategy.** No LinkedIn posts, no Twitter threads, no engagement farming.
- **No paid advertising.** No Google Ads, no sponsored content, no retargeting.
- **No conference circuit** (until Phase 5+ with traction data to present).
- **No enterprise sales team** (until inbound demand justifies it).
- **No telemetry without consent.** The CLI sends nothing home by default.
- **No freemium dark patterns.** No usage limits designed to frustrate. No "you've run out of scans" walls.
- **No fake data in any publication.** Reference: validated 97.96% baseline. All future claims must be reproducible.

---

## 9. Success criteria by milestone

### Month 3 checkpoint

- [ ] Rust CLI shipping on all platforms
- [ ] 500 GitHub stars
- [ ] 1,000 unique installs
- [ ] GitHub Action published
- [ ] Rule documentation pages live
- [ ] First blog post published

### Month 6 checkpoint

- [ ] 2,000 GitHub stars
- [ ] 500 CI/CD pipelines running Sigil
- [ ] 500+ indexed pages on sigilsec.ai
- [ ] First quarterly security report published
- [ ] First inbound enterprise enquiry from organic search
- [ ] 1,000 email subscribers

### Month 12 checkpoint

- [ ] 10,000 GitHub stars
- [ ] 5,000 monthly organic visitors
- [ ] 3 quarterly reports published
- [ ] Team tier dashboard in beta
- [ ] Community contributions to rules (external PRs merged)
- [ ] First paying customers

### Month 18 checkpoint

- [ ] Self-sustaining flywheel (community contributions > internal rule output)
- [ ] $5K+ MRR from Team tier
- [ ] 3 qualified Enterprise conversations
- [ ] Recognised as authority in AI agent security space
- [ ] Conference speaking invitations inbound (not outbound)

---

## 10. Dependencies and risks

| Risk | Mitigation |
|------|------------|
| Rust CLI delays | Ship bash prototype (`qaudit`) as v0.x while Rust builds |
| AI agent security category doesn't grow | Broaden to general supply chain security (npm, pip) |
| GitHub Action marketplace visibility | Programmatic SEO drives discovery, not marketplace ranking |
| No one scans MCP servers | Target broader AI agent code (LangChain, CrewAI, AutoGen) |
| Snyk/Semgrep adds MCP scanning | Speed advantage + specialisation. They're generalists, Sigil is purpose-built |
| Research requires real data | Azure dataset is validated. Expand with opt-in telemetry and public repo scanning |

---

## Appendix A: Reference distribution evidence

| Company | Model | Outcome |
|---------|-------|---------|
| Snyk | Free CLI → enterprise | 2.5M developers, $343M ARR, $8.5B peak valuation |
| HashiCorp | OSS → cloud platform | 100M+ downloads, $14B IPO, $6.4B IBM acquisition |
| Sentry | OSS error tracking → SaaS | $128M+ ARR, 100K+ organisations |
| Supabase | OSS Firebase alternative | $70M ARR, $5B valuation in 5 years |
| Zapier | Programmatic SEO | 50K+ pages, 5.8M monthly organic visits, $100M+ ARR |
| NerdWallet | Programmatic SEO | Started with $800, grew to $245M annual revenue |
| Calendly | PLG viral loop | $276M ARR, 20M users, zero traditional marketing |

---

*This document is the single source of truth for Sigil's distribution strategy. Changes require CTO approval. Last updated: 2026-03-29.*
