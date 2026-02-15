# PRD: sigilsec.ai Landing Page

**Author:** NOMARK
**Date:** 2026-02-15
**Status:** Draft
**Version:** 1.0

---

## 1. Overview

### 1.1 Purpose

This document defines the product requirements for the sigilsec.ai marketing landing page. The page serves as the primary acquisition surface for Sigil — an automated security auditing CLI for AI agent code. It must communicate the product's value proposition, demonstrate credibility, convert visitors into users (free CLI install or paid plan signup), and establish Sigil as the category-defining tool for AI tooling supply chain security.

### 1.2 Background

The AI tooling ecosystem is growing rapidly. Developers routinely clone repos from tutorials, install MCP servers with minimal vetting, and pull agent skills from Discord — all of which get direct access to API keys, databases, and cloud credentials. Traditional dependency scanners (Snyk, Dependabot) catch known CVEs but miss intentionally malicious code. No existing tool combines quarantine-first isolation, multi-ecosystem scanning, and AI agent-specific threat detection in a single workflow.

Sigil fills this gap. The landing page must make that case clearly and drive adoption.

### 1.3 Target URL

`https://sigilsec.ai`

### 1.4 Goals

| Goal | Metric | Target |
|------|--------|--------|
| Primary conversion | CLI installs (curl/brew/npm) | Track copy-to-clipboard events |
| Secondary conversion | Pro/Team signups | Track CTA clicks to /pricing or /signup |
| Awareness | Unique visitors | Baseline + growth month-over-month |
| Engagement | Scroll depth, time on page | >60% reach pricing section |
| Credibility | GitHub stars click-through | Track outbound clicks to repo |

---

## 2. Target Audience

### 2.1 Primary Personas

**1. The AI-Forward Developer**
- Builds with LLM APIs, agent frameworks (LangChain, CrewAI, AutoGen), MCP servers
- Installs packages and clones repos daily from GitHub, npm, PyPI
- Aware of supply chain risk but has no practical workflow to address it
- Values speed, CLI-native tools, minimal friction
- Decision-maker for personal tooling; influencer for team adoption

**2. The Security-Conscious Tech Lead**
- Manages a team shipping AI-powered products
- Responsible for security posture but doesn't want to slow down velocity
- Needs policy enforcement, audit trails, CI/CD integration
- Evaluates tools on breadth of coverage, team features, and compliance support
- Decision-maker for team/enterprise purchases

**3. The Platform/DevOps Engineer**
- Owns CI/CD pipelines and developer tooling
- Needs to gate deployments on security scans
- Values GitHub Action / GitLab CI native integration
- Cares about false positive rates, configurability, and automation

### 2.2 Secondary Personas

- **Open-source maintainers** wanting to scan contributions
- **Security researchers** evaluating AI agent attack surfaces
- **Developer advocates** looking for tools to recommend

---

## 3. Page Structure & Sections

The landing page follows a single-page, scroll-driven layout with a persistent top navigation bar and clear section anchors.

### 3.1 Navigation Bar (Sticky)

| Element | Behavior |
|---------|----------|
| Sigil logo/wordmark | Links to top of page |
| Features | Anchor scroll to Section 3.3 |
| How It Works | Anchor scroll to Section 3.4 |
| Integrations | Anchor scroll to Section 3.6 |
| Pricing | Anchor scroll to Section 3.8 |
| Docs | External link to /docs |
| GitHub | External link to GitHub repo (with star count badge) |
| Get Started (CTA button) | Anchor scroll to install section / opens signup modal |

Mobile: Hamburger menu with same items.

---

### 3.2 Hero Section

**Purpose:** Immediately communicate what Sigil does and why it matters. Drive first conversion (CLI install).

**Content:**

- **Headline:** "Stop malicious code before it runs."
- **Subheadline:** "Sigil quarantines and scans every repo, package, and MCP server you install — so nothing touches your environment until you say so."
- **Primary CTA:** Install command block with copy button:
  ```
  curl -sSL https://sigilsec.ai/install.sh | sh
  ```
- **Secondary CTA:** "View on GitHub" button (with live star count)
- **Tertiary CTA:** "See pricing" text link
- **Visual:** Animated terminal showing a `sigil clone` workflow — quarantine, scan phases ticking through, verdict output. Should feel fast and real. Can be an SVG/CSS animation or a lightweight embedded recording (asciinema/VHS).
- **Trust signals below hero:** "Free and open source. Apache 2.0. All 6 scan phases run locally — no account required."

**Design notes:**
- Dark background (black or near-black) with monospace/terminal aesthetic
- The terminal animation should autoplay on scroll-into-view
- Install command should be selectable and have a visible copy icon

---

### 3.3 Problem Statement Section

**Purpose:** Create urgency by articulating the threat landscape specific to AI agent code.

**Headline:** "The AI tooling ecosystem has a trust problem."

**Content (3 cards or columns):**

| Card | Icon | Title | Body |
|------|------|-------|------|
| 1 | Package icon | **Untrusted packages** | "Developers install MCP servers, agent skills, and LangChain plugins with 12 GitHub stars and no security review. Each one gets full access to your shell, env vars, and credentials." |
| 2 | Shield-off icon | **Invisible install hooks** | "npm postinstall scripts, setup.py cmdclass overrides, and Makefile targets execute arbitrary code the moment you install. By the time you read the source, it's already run." |
| 3 | Alert icon | **Blind spots in existing tools** | "Snyk and Dependabot check for known CVEs in dependency trees. They don't scan source code for intentional malice — backdoors, credential exfiltration, or obfuscated payloads." |

**Closing statement:** "Sigil was built for this moment. Quarantine first, scan everything, approve explicitly."

---

### 3.4 How It Works Section

**Purpose:** Demonstrate the workflow in 3 simple steps. Reduce perceived complexity.

**Headline:** "Three steps. Full protection."

**Layout:** Horizontal 3-step flow with connecting arrows (vertical on mobile).

| Step | Visual | Title | Description |
|------|--------|-------|-------------|
| 1 | Terminal icon | **Run a command** | "Use the commands you already know — `gclone`, `safepip`, `safenpm` — or `sigil scan` directly. Sigil intercepts and quarantines automatically." |
| 2 | Scan/shield icon | **Sigil scans** | "Six analysis phases run in under 3 seconds: install hooks, code patterns, network exfiltration, credentials access, obfuscation, and provenance." |
| 3 | Check/X icon | **You decide** | "Get a clear verdict with a risk score. Approve clean code to your workspace. Reject anything suspicious. Nothing runs until you say so." |

**Below steps:** A compact terminal replay or static screenshot showing actual `sigil clone` output with colored verdict.

---

### 3.5 Six Scan Phases Section

**Purpose:** Communicate depth and technical rigor. This is the differentiation section for technical evaluators.

**Headline:** "Six phases. Every angle covered."

**Layout:** 6 cards in a 3x2 grid (stacked on mobile). Each card has:

| Phase | Icon | Name | Weight | What It Catches |
|-------|------|------|--------|-----------------|
| 1 | Hook icon | **Install Hooks** | Critical (10x) | `setup.py` cmdclass, npm `postinstall`, Makefile install targets that execute on install |
| 2 | Code icon | **Code Patterns** | High (5x) | `eval()`, `exec()`, `pickle.loads`, `subprocess shell=True`, `child_process`, `__import__()` |
| 3 | Globe icon | **Network & Exfiltration** | High (3x) | Outbound HTTP calls, webhooks, socket connections, ngrok tunnels, DNS tunneling |
| 4 | Key icon | **Credentials** | Medium (2x) | ENV variable access, `.aws/`, `.kube/`, SSH keys, API key patterns in code |
| 5 | Eye-off icon | **Obfuscation** | High (5x) | Base64 decoding, hex encoding, `String.fromCharCode`, minified payloads |
| 6 | Git icon | **Provenance** | Low-Medium (1-3x) | Git history depth, author count, binary blobs, hidden files, filesystem manipulation |

**Below grid:** "Plus integration with semgrep, bandit, trufflehog, safety, and npm audit for even deeper analysis."

---

### 3.6 Integrations Section

**Purpose:** Show that Sigil fits into existing workflows — not another isolated tool.

**Headline:** "Works where you work."

**Layout:** Icon grid or carousel with the following integrations, each linking to relevant docs.

| Integration | Icon | Description |
|-------------|------|-------------|
| **Terminal / CLI** | Terminal icon | Bash, Zsh, Fish. Shell aliases make security the default. |
| **VS Code** | VS Code icon | Scan workspace, files, and selections. Works in Cursor and Windsurf. |
| **JetBrains** | JetBrains icon | IntelliJ, WebStorm, PyCharm, GoLand, and more. Inline findings. |
| **Claude Code / MCP** | MCP icon | Native MCP server. AI agents scan before they install. |
| **GitHub Actions** | GitHub icon | Add `sigil-scan` to any workflow. PR gates with configurable thresholds. |
| **GitLab CI** | GitLab icon | Drop-in CI template. Metrics export. Artifact storage. |
| **Git Hooks** | Git icon | Pre-commit scanning. Global clone hooks. |

---

### 3.7 Comparison Section

**Purpose:** Position against known alternatives. Help evaluators make a decision.

**Headline:** "Built for threats existing tools miss."

**Layout:** Comparison table (horizontal scroll on mobile).

| Capability | Sigil | Snyk | Socket.dev | Semgrep | CodeQL |
|-----------|-------|------|-----------|---------|--------|
| Quarantine workflow | Yes | No | No | No | No |
| AI agent / MCP focus | Yes | No | Partial | No | No |
| Install hook scanning | Yes | No | Yes | No | No |
| Credential exfil detection | Yes | No | Partial | Config required | Config required |
| Multi-ecosystem (pip, npm, git, URL) | Yes | Yes | npm only | Any (rules) | GitHub only |
| Community threat intel | Yes | Advisory DB | Yes | Community rules | No |
| Full CLI free | Yes | Limited | Limited | OSS free | Public repos |
| Offline mode | Yes | No | No | Yes | Partial |

**Footer note:** "Sigil isn't a replacement for CVE scanning — it catches what CVE scanners can't: intentionally malicious code."

---

### 3.8 Pricing Section

**Purpose:** Convert interested visitors to paying users. Anchor free tier to drive initial adoption.

**Headline:** "Free to scan. Paid to scale."

**Subheadline:** "The full CLI is free and open source. Paid plans add cloud intelligence, dashboards, and team features."

**Layout:** 3 pricing cards side by side (stacked on mobile). Pro card visually highlighted as recommended.

| | Open Source | Pro — $29/mo | Team — $99/mo |
|---|-----------|-------------|--------------|
| Full CLI (all 6 phases) | Yes | Yes | Yes |
| Scans per month | 50 | 500 | 5,000 |
| Cloud threat intelligence | -- | Yes | Yes |
| Scan history | -- | 90 days | 1 year |
| Web dashboard | -- | Yes | Yes |
| API access | -- | Yes | Yes |
| Custom scan policies | -- | -- | Yes |
| Team management | -- | -- | Up to 25 seats |
| RBAC & audit logs | -- | -- | Yes |
| CI/CD gate integration | -- | -- | Yes |
| Slack / webhook alerts | -- | -- | Yes |
| **CTA** | `curl` install | Start free trial | Start free trial |

**Below table:** "Need more? Enterprise plans with unlimited scans, SSO, SLA, and dedicated support. [Contact us](mailto:enterprise@sigilsec.ai)"

---

### 3.9 Social Proof / Trust Section

**Purpose:** Build credibility through evidence, not claims.

**Headline:** "Trusted by developers building with AI."

**Content (include as available):**

- **GitHub stats:** Star count, fork count, contributor count (pulled live via GitHub API or static with periodic update)
- **Testimonial quotes:** 2-3 developer quotes with name, title, and avatar (collect from early adopters / beta users)
- **Logo bar:** Logos of companies or projects using Sigil (when available)
- **Scan stats:** "X packages scanned" / "Y threats detected" counter (when telemetry supports this)
- **Open source badge:** Apache 2.0 license badge, link to LICENSE file
- **Security posture:** "No source code is ever transmitted. Only pattern match metadata. Fully offline mode available."

**Note:** If testimonials/logos are not yet available at launch, this section should show GitHub stats + the privacy/offline messaging and be updated as social proof becomes available.

---

### 3.10 Developer Experience Section

**Purpose:** Show that Sigil is fast, non-intrusive, and developer-friendly — not enterprise bloatware.

**Headline:** "Security that doesn't slow you down."

**Content (feature cards):**

| Feature | Description |
|---------|-------------|
| **< 3 second scans** | All six phases complete in under 3 seconds for typical packages. No waiting. |
| **Shell aliases** | `gclone`, `safepip`, `safenpm` — use the commands you already know. Security becomes the default. |
| **Zero config** | `curl` install, one command setup. No YAML files, no config repos, no onboarding calls. |
| **Fully offline** | All scan phases run locally. No account, no network, no telemetry required. |
| **Clear verdicts** | CLEAN / LOW / MEDIUM / HIGH / CRITICAL. No ambiguous severity matrices. One score, one decision. |

---

### 3.11 CTA / Install Section (Bottom)

**Purpose:** Final conversion point for visitors who scrolled the full page.

**Headline:** "Start scanning in 30 seconds."

**Content:**

Three install options as tabbed code blocks:

```
# curl
curl -sSL https://sigilsec.ai/install.sh | sh

# Homebrew
brew install nomarj/tap/sigil

# npm
npm install -g @nomarj/sigil
```

**Secondary CTAs:**
- "Read the docs" -> /docs
- "View on GitHub" -> GitHub repo
- "Join the community" -> Discord/community link (if available)

---

### 3.12 Footer

| Column | Items |
|--------|-------|
| **Product** | Features, Pricing, Docs, Changelog, Roadmap |
| **Developers** | Getting Started, API Reference, GitHub, Contributing |
| **Company** | About NOMARK, Blog (if exists), Security, Contact |
| **Legal** | Privacy Policy, Terms of Service, Apache 2.0 License |

Bottom bar: "SIGIL by NOMARK. A protective mark for every line of code."

---

## 4. Functional Requirements

### 4.1 Performance

| Requirement | Target |
|-------------|--------|
| Largest Contentful Paint (LCP) | < 2.5s |
| First Input Delay (FID) | < 100ms |
| Cumulative Layout Shift (CLS) | < 0.1 |
| Total page weight (initial load) | < 500KB (excluding terminal animation) |
| Time to Interactive (TTI) | < 3.5s |
| Lighthouse Performance score | > 90 |

### 4.2 SEO

- Semantic HTML5 with proper heading hierarchy (single H1, structured H2/H3)
- Meta title: "Sigil — Automated Security Auditing for AI Agent Code"
- Meta description: "Quarantine and scan every repo, package, and MCP server before it runs. Free, open source CLI with six-phase analysis. By NOMARK."
- Open Graph and Twitter Card meta tags with branded preview image
- Canonical URL: `https://sigilsec.ai`
- Structured data (JSON-LD): SoftwareApplication schema
- Sitemap.xml and robots.txt
- Alt text on all images

### 4.3 Analytics & Tracking

| Event | Trigger |
|-------|---------|
| `install_copy` | User clicks copy button on any install command |
| `cta_click` | User clicks any CTA button (with label parameter) |
| `section_view` | User scrolls a section into viewport (with section name) |
| `github_click` | User clicks any GitHub link |
| `pricing_view` | User scrolls pricing section into viewport |
| `pricing_cta_click` | User clicks a pricing CTA (with plan parameter) |
| `docs_click` | User clicks any docs link |
| `scroll_depth` | 25%, 50%, 75%, 100% thresholds |

Analytics provider: Plausible, Fathom, or PostHog (privacy-respecting; no cookie banner needed). Avoid Google Analytics for brand alignment with security/privacy positioning.

### 4.4 Responsive Design

| Breakpoint | Layout |
|------------|--------|
| >= 1280px | Full desktop layout |
| 768px - 1279px | Tablet: 2-column grids collapse, nav stays horizontal |
| < 768px | Mobile: single column, hamburger nav, stacked cards, horizontal scroll on comparison table |

### 4.5 Accessibility

- WCAG 2.1 AA compliance
- Keyboard navigation for all interactive elements
- Sufficient color contrast ratios (minimum 4.5:1 for body text)
- Screen reader compatible (ARIA labels, semantic HTML)
- Reduced motion preference respected for animations
- Focus indicators visible on all interactive elements

### 4.6 Internationalization

- English only at launch
- UTF-8 encoding
- No hard-coded strings in components (use content layer for future i18n support)

---

## 5. Design Requirements

### 5.1 Brand Identity

| Element | Specification |
|---------|---------------|
| **Primary color** | Black / near-black (#0A0A0A or similar) |
| **Accent color** | Blue (#3B82F6 or brand blue — align with existing badge color) |
| **Secondary accent** | Green for "clean/approved" states, Red for "critical/rejected" states |
| **Typography** | Monospace for code/terminal elements (JetBrains Mono, Fira Code, or similar). Sans-serif for body text (Inter, system font stack). |
| **Tone** | Technical, direct, no-nonsense. No marketing fluff. Speak developer-to-developer. |
| **Imagery** | Terminal screenshots, code snippets, architectural diagrams. No stock photos. No abstract gradients. |

### 5.2 Visual Style

- Dark mode primary (matches terminal/developer aesthetic and security product positioning)
- Optional light mode toggle (lower priority)
- Terminal-inspired UI elements (command prompts, monospace blocks, scan output formatting)
- Subtle grid/dot background pattern
- Minimal use of illustrations — prefer real product output
- Scan verdict badges should match CLI output colors (green = clean, yellow = low, orange = medium, red = high/critical)

### 5.3 Motion & Animation

- Terminal hero animation: auto-playing scan workflow (quarantine -> phases -> verdict)
- Scroll-triggered fade-in for section entries (subtle, not distracting)
- Copy-to-clipboard feedback (checkmark icon swap, 2s duration)
- Reduced motion: disable all animations when `prefers-reduced-motion` is set

---

## 6. Technical Requirements

### 6.1 Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Framework** | Next.js 14 (App Router) or Astro | SSG for performance; React ecosystem for dashboard consistency |
| **Styling** | Tailwind CSS | Already used in dashboard; consistent design tokens |
| **Hosting** | Vercel or Cloudflare Pages | Edge deployment, fast global CDN, easy preview deploys |
| **Analytics** | Plausible or PostHog | Privacy-respecting, no cookie banner |
| **CMS (optional)** | MDX or Keystatic | For blog/changelog content if needed later |
| **Terminal animation** | asciinema-player, VHS, or custom SVG/CSS | Lightweight, no video hosting dependency |

### 6.2 Repository Structure

The landing page should live within the existing repo or as a subdirectory:

```
landing/                    # or site/, www/
  src/
    app/
      page.tsx             # Main landing page
      layout.tsx           # Root layout
      globals.css          # Tailwind base
    components/
      Hero.tsx
      ProblemStatement.tsx
      HowItWorks.tsx
      ScanPhases.tsx
      Integrations.tsx
      Comparison.tsx
      Pricing.tsx
      SocialProof.tsx
      DevExperience.tsx
      InstallCTA.tsx
      Footer.tsx
      Navbar.tsx
      TerminalAnimation.tsx
      CopyButton.tsx
      PricingCard.tsx
      ComparisonTable.tsx
    lib/
      analytics.ts
      constants.ts
    content/
      copy.ts              # All page copy in one place for easy iteration
  public/
    og-image.png
    favicon.ico
    robots.txt
    sitemap.xml
  package.json
  tailwind.config.ts
  next.config.js           # or astro.config.mjs
```

### 6.3 Deployment

- **Production:** `sigilsec.ai` (apex domain)
- **Preview:** Auto-deploy on PR for review
- **CI checks:** Lighthouse CI, link checker, build verification
- **CDN:** Global edge caching for static assets
- **SSL:** Enforced HTTPS with HSTS

### 6.4 Third-Party Services

| Service | Purpose | Required at Launch |
|---------|---------|-------------------|
| DNS provider | Domain management | Yes |
| Vercel/Cloudflare | Hosting + CDN | Yes |
| Plausible/PostHog | Analytics | Yes |
| GitHub API | Live star count badge | Nice to have |
| Stripe | Pricing CTA redirects | Yes (links only; checkout on dashboard) |

---

## 7. Content Requirements

### 7.1 Copy Principles

1. **Lead with the problem, not the product.** Developers don't wake up wanting a security scanner. They want to not get pwned.
2. **Be specific.** "Six scan phases in under 3 seconds" beats "Fast, comprehensive scanning."
3. **Show, don't tell.** Terminal output > feature bullets. Real scan results > abstract descriptions.
4. **Respect the reader.** No "revolutionizing" or "next-generation." State what it does. Let them judge.
5. **One clear action per section.** Every section should have an obvious next step.

### 7.2 Required Assets

| Asset | Description | Status |
|-------|-------------|--------|
| Terminal recording | `sigil clone` of a repo with findings | Needs creation |
| OG preview image | Branded card for social sharing (1200x630) | Needs creation |
| Favicon | Sigil shield icon, multiple sizes | Needs creation |
| Integration icons | VS Code, JetBrains, GitHub, GitLab, terminal, MCP | Source from Simple Icons or create |
| Phase icons | 6 icons for scan phases | Needs creation or source |
| Comparison table data | Verified claims about competitor capabilities | Verify before publish |

### 7.3 Legal Pages (Required Before Launch)

| Page | Route | Content |
|------|-------|---------|
| Privacy Policy | /privacy | Data collection practices, telemetry, cookie-free analytics |
| Terms of Service | /terms | Usage terms for CLI and cloud services |
| Security | /security | Vulnerability disclosure process, security contact |

---

## 8. Launch Requirements

### 8.1 Pre-Launch Checklist

- [ ] All sections implemented and responsive
- [ ] Terminal animation working on all breakpoints
- [ ] Copy-to-clipboard functional for all install commands
- [ ] All external links verified (GitHub, docs, pricing)
- [ ] Pricing section matches current plan definitions
- [ ] Analytics events firing correctly
- [ ] Lighthouse score > 90 on all metrics
- [ ] WCAG 2.1 AA audit passed
- [ ] OG/Twitter Card previews verified (use opengraph.xyz or similar)
- [ ] DNS configured for sigilsec.ai
- [ ] SSL certificate active and HSTS enabled
- [ ] robots.txt and sitemap.xml deployed
- [ ] Privacy policy and terms of service pages live
- [ ] 404 page styled and functional
- [ ] Mobile testing on iOS Safari and Android Chrome
- [ ] Cross-browser testing: Chrome, Firefox, Safari, Edge

### 8.2 Post-Launch Iteration

| Priority | Enhancement |
|----------|-------------|
| P1 | Add testimonials as they come in from early adopters |
| P1 | Add live scan counter when telemetry supports it |
| P2 | Blog / changelog section for content marketing |
| P2 | Interactive demo (scan a sample repo in-browser) |
| P3 | Light mode toggle |
| P3 | Localization for non-English markets |
| P3 | Case studies from team/enterprise customers |

---

## 9. Success Criteria

### 9.1 Launch Metrics (First 30 Days)

| Metric | Target |
|--------|--------|
| CLI install copy events | > 500 |
| GitHub repo visits from landing page | > 1,000 |
| Pricing section view rate | > 50% of visitors |
| Bounce rate | < 60% |
| Mobile usability issues | 0 critical |

### 9.2 Ongoing Metrics (Monthly)

| Metric | Tracking |
|--------|----------|
| Unique visitors | Plausible/PostHog |
| Install-to-signup conversion | Copy event -> account creation |
| Section engagement | Scroll depth + section view events |
| Pricing CTA click rate | By plan tier |
| SEO ranking | Target keywords: "AI agent security", "MCP server scanner", "supply chain security CLI" |

---

## 10. Out of Scope (v1)

The following are explicitly **not** part of the initial landing page:

- Blog / content marketing pages
- Documentation hosting (separate /docs site)
- Dashboard login/signup flow (redirect to dashboard app)
- Interactive in-browser scanning demo
- Community forum or discussion board
- Marketplace or plugin directory
- Customer case studies (pending customer acquisition)
- Video content or webinars
- Localized versions
- A/B testing infrastructure (implement after baseline data)

---

## 11. Open Questions

| # | Question | Decision Needed By |
|---|----------|-------------------|
| 1 | Next.js vs Astro for landing page? Next.js aligns with dashboard stack; Astro may be lighter for a static marketing site. | Before development starts |
| 2 | Should the landing page live in the same repo (monorepo) or a separate repo? | Before development starts |
| 3 | Domain registrar and hosting provider confirmation? | Before DNS setup |
| 4 | Do we have brand assets (logo, wordmark, icon) finalized? | Before design starts |
| 5 | Stripe pricing page IDs — are Pro and Team products created in Stripe? | Before pricing CTAs go live |
| 6 | Analytics provider selection (Plausible vs PostHog vs other)? | Before launch |
| 7 | Do we want a waitlist/early access flow for Team/Enterprise, or direct signup? | Before pricing section finalized |

---

## Appendix A: SEO Target Keywords

| Priority | Keyword | Search Intent |
|----------|---------|---------------|
| Primary | AI agent security scanner | Product discovery |
| Primary | MCP server security | Problem-aware search |
| Primary | supply chain security CLI | Tool comparison |
| Secondary | scan npm package for malware | Specific use case |
| Secondary | quarantine git clone | Feature-specific |
| Secondary | AI tooling security | Category awareness |
| Secondary | sigil security | Brand search |
| Tertiary | alternative to snyk for AI | Competitor comparison |
| Tertiary | scan pip package before install | Use case search |
| Tertiary | open source security scanner | Discovery |

## Appendix B: Competitor Positioning Notes

**Snyk:** Established brand in dependency vulnerability scanning. Focuses on known CVEs in dependency trees. Does not scan source code for intentional malice. No quarantine workflow. Enterprise-heavy pricing. Position Sigil as complementary ("Snyk catches CVEs; Sigil catches malice") rather than a replacement.

**Socket.dev:** Closest competitor in intent detection. npm-focused. Does not support pip, git repos, or arbitrary URLs. No quarantine workflow. No CLI-first approach. Position Sigil on multi-ecosystem support and quarantine-first workflow.

**Semgrep:** Powerful pattern engine but requires rule authoring for AI-specific threats. Not an end-to-end workflow tool. No quarantine. No threat intelligence. Position Sigil as purpose-built where Semgrep is general-purpose.

**CodeQL:** GitHub-native, powerful but requires GitHub hosting. Heavy setup. No real-time scanning workflow. No quarantine. Position Sigil on accessibility and speed.

## Appendix C: Key Messaging Framework

**One-liner:** "Sigil quarantines and scans AI agent code before it runs."

**Elevator pitch:** "Developers install MCP servers, agent skills, and AI tooling packages without security review — and each one gets full access to credentials, shell, and cloud resources. Sigil intercepts every install, quarantines the code, runs six analysis phases in under 3 seconds, and gives you a clear verdict. Nothing runs until you approve it. Free, open source, fully offline."

**Tagline:** "A protective mark for every line of code."

**Category:** AI Tooling Supply Chain Security
