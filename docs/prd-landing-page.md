# PRD: sigilsec.ai Landing Page

**Author:** NOMARK
**Date:** 2026-02-15
**Status:** Draft
**Version:** 1.1

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
| Blog | Links to /blog (AEO-optimized blog powered by cakewalk.ai) |
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

### 3.11 Blog Preview Section

**Purpose:** Surface recent blog content on the landing page to drive organic traffic, establish thought leadership, and feed AEO (Answer Engine Optimization) signals. The blog is the primary content marketing and AEO engine for sigilsec.ai.

**Headline:** "From the Sigil blog"

**Layout:** 3 most recent blog post cards in a horizontal row (stacked on mobile). Each card shows:

- Post title (linked to full post)
- Publication date
- 2-line excerpt / meta description
- Category tag (e.g., "Threat Intel", "How-To", "Security Research", "Product Update")
- Read time estimate

**CTA:** "Read all posts" button linking to `/blog`

**Data source:** Posts are fetched from cakewalk.ai via API integration at build time (ISR or SSG) so the landing page always shows fresh content without client-side fetching.

**Design notes:**
- Cards use Flowbite Pro blog card component
- Dark theme consistent with rest of page
- Category tags use colored badges matching Flowbite Pro badge component

---

### 3.12 CTA / Install Section (Bottom)

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

### 3.13 Footer

| Column | Items |
|--------|-------|
| **Product** | Features, Pricing, Docs, Changelog, Roadmap |
| **Developers** | Getting Started, API Reference, GitHub, Contributing |
| **Resources** | Blog, Threat Intel Digest, Security Research, Tutorials |
| **Company** | About NOMARK, Security, Contact |
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

### 4.2 SEO & AEO (Answer Engine Optimization)

#### Traditional SEO

- Semantic HTML5 with proper heading hierarchy (single H1, structured H2/H3)
- Meta title: "Sigil — Automated Security Auditing for AI Agent Code"
- Meta description: "Quarantine and scan every repo, package, and MCP server before it runs. Free, open source CLI with six-phase analysis. By NOMARK."
- Open Graph and Twitter Card meta tags with branded preview image
- Canonical URL: `https://sigilsec.ai`
- Structured data (JSON-LD): SoftwareApplication schema
- Sitemap.xml and robots.txt
- Alt text on all images

#### AEO Strategy

AEO ensures Sigil's content is cited by AI answer engines (ChatGPT, Perplexity, Claude, Gemini, Bing Copilot) when users ask questions about AI agent security, supply chain scanning, and MCP server safety.

**Landing page AEO requirements:**

- Question-based H2/H3 headings where appropriate (e.g., "How does Sigil scan for malicious code?", "What threats do existing tools miss?")
- Direct, concise answer in the first paragraph of each section (AI engines extract the opening sentence as the answer)
- FAQ section with `FAQPage` JSON-LD schema markup — covering the top 10-15 questions about AI agent security and Sigil
- `HowTo` JSON-LD schema for the installation and scanning workflow
- `SoftwareApplication` JSON-LD schema with pricing, OS support, and category
- Comparison content structured as clear tabular data (AI engines favor tables for feature comparisons)

**Blog AEO requirements (powered by cakewalk.ai):**

- Every blog post must target a specific question or long-tail query
- Posts use question-phrased headings with direct answers in the first paragraph under each heading
- Structured data generated by cakewalk.ai: `Article`, `FAQPage`, `HowTo`, `TechArticle` schemas as appropriate
- Blog posts include a dedicated FAQ section at the bottom (3-5 related questions per post)
- Author bylines with `Person` schema and E-E-A-T signals (credentials, links to author profiles)
- Freshness: content updated regularly; publication and modification dates visible and in schema
- Internal linking between blog posts and relevant landing page sections
- Category taxonomy aligned with target AEO queries (see Appendix D)

**AEO content pillars for the blog:**

| Pillar | Example Topics | Target Queries |
|--------|---------------|----------------|
| **Threat Intelligence** | New malicious packages discovered, attack pattern breakdowns, supply chain incident analysis | "Is [package] safe to install?", "How to detect malicious npm packages" |
| **How-To Guides** | Setting up Sigil, CI/CD integration, scanning MCP servers, configuring policies | "How to scan npm packages for malware", "How to secure MCP servers" |
| **Security Research** | AI agent attack surfaces, credential exfiltration techniques, obfuscation methods | "What are the security risks of MCP servers?", "Can AI agents steal API keys?" |
| **Product Updates** | New scan phases, integration launches, feature deep-dives | "Sigil vs Snyk", "Best AI agent security tools" |
| **Industry Analysis** | AI tooling ecosystem trends, supply chain security landscape, regulatory changes | "AI supply chain security best practices", "AI agent security standards" |

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
| `blog_view` | User visits a blog post (with slug, category parameters) |
| `blog_listing_view` | User visits /blog listing page (with category filter if active) |
| `blog_cta_click` | User clicks an in-post CTA (install command, pricing link, etc.) |
| `blog_share` | User clicks a share button on a blog post (with platform parameter) |

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

### 5.1 Component System — Flowbite Pro

Flowbite Pro is the base component library for the entire site. All sections should start from a Flowbite Pro template/block and be customized to match brand identity, rather than being built from scratch.

**Flowbite Pro section mapping:**

| Landing Page Section | Flowbite Pro Block Type | Customization |
|---------------------|------------------------|---------------|
| Navbar | Marketing navbar (mega-menu variant) | Add GitHub star badge, blog link |
| Hero | Hero section (dark, centered) | Add terminal animation, install code block |
| Problem Statement | Feature section (3-column cards) | Custom icons, dark card backgrounds |
| How It Works | Timeline / steps section | 3-step horizontal variant |
| Scan Phases | Feature grid (3x2 cards) | Severity weight badges, phase icons |
| Integrations | Logo cloud / icon grid | Integration icons with hover tooltips |
| Comparison | Comparison table section | Checkmark/X styling, sticky first column |
| Pricing | Pricing cards (3-tier) | Highlight Pro as recommended |
| Social Proof | Testimonial section | GitHub stats + privacy messaging |
| Developer Experience | Feature list section | Icon + text pairs |
| Blog Preview | Blog card grid (3-col) | Dark cards, category badges, read time |
| Bottom CTA | CTA section (centered) | Tabbed code blocks |
| Footer | Mega footer (4-column) | NOMARK branding |
| Blog listing | Blog grid page | Category tabs, pagination |
| Blog post | Article page layout | TOC sidebar, author card, FAQ accordion |

### 5.2 Brand Identity

| Element | Specification |
|---------|---------------|
| **Primary color** | Black / near-black (#0A0A0A or similar) |
| **Accent color** | Blue (#3B82F6 or brand blue — align with existing badge color) |
| **Secondary accent** | Green for "clean/approved" states, Red for "critical/rejected" states |
| **Typography** | Monospace for code/terminal elements (JetBrains Mono, Fira Code, or similar). Sans-serif for body text (Inter, system font stack). Flowbite defaults to Inter which aligns well. |
| **Tone** | Technical, direct, no-nonsense. No marketing fluff. Speak developer-to-developer. |
| **Imagery** | Terminal screenshots, code snippets, architectural diagrams. No stock photos. No abstract gradients. |

### 5.3 Visual Style

- Dark mode primary (matches terminal/developer aesthetic and security product positioning)
- Use Flowbite's built-in dark mode support via `ThemeModeScript` in root layout to prevent flash of unstyled content
- Optional light mode toggle (lower priority — Flowbite handles this natively)
- Terminal-inspired UI elements (command prompts, monospace blocks, scan output formatting)
- Subtle grid/dot background pattern
- Minimal use of illustrations — prefer real product output
- Scan verdict badges should match CLI output colors (green = clean, yellow = low, orange = medium, red = high/critical)
- Blog cards and post pages follow the same dark theme; featured images should have consistent aspect ratios

### 5.4 Motion & Animation

- Terminal hero animation: auto-playing scan workflow (quarantine -> phases -> verdict)
- Scroll-triggered fade-in for section entries (subtle, not distracting)
- Copy-to-clipboard feedback (checkmark icon swap, 2s duration) — use Flowbite tooltip component for feedback
- Reduced motion: disable all animations when `prefers-reduced-motion` is set

---

## 6. Technical Requirements

### 6.1 Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Framework** | Next.js 14+ (App Router) | SSG/ISR for performance; React ecosystem aligns with dashboard and Flowbite React; required for cakewalk.ai blog ISR integration |
| **UI Components** | Flowbite Pro + Flowbite React | Pre-built, production-ready Tailwind CSS components. Use Flowbite Pro templates as the base for all page sections (hero, pricing cards, feature grids, comparison tables, blog cards, nav, footer). Reduces custom CSS and accelerates development. |
| **Styling** | Tailwind CSS v4 | Already used in dashboard; Flowbite Pro is built on Tailwind; consistent design tokens |
| **Blog / CMS** | cakewalk.ai | AEO-optimized blog platform. Content authored and managed in cakewalk.ai, fetched via API at build time (ISR). Handles blog post CRUD, scheduling, categories, and AEO structured data generation. |
| **Hosting** | Vercel or Cloudflare Pages | Edge deployment, fast global CDN, easy preview deploys, native Next.js ISR support |
| **Analytics** | Plausible or PostHog | Privacy-respecting, no cookie banner |
| **Terminal animation** | asciinema-player, VHS, or custom SVG/CSS | Lightweight, no video hosting dependency |

### 6.2 Repository Structure

The landing page lives in a **separate repository**: `NOMARJ/sigilsec` (not in the main `sigil` repo). This keeps the marketing site decoupled from the CLI/API/dashboard codebase with independent CI/CD, deploy previews, and release cycles.

```
sigilsec/                      # Separate repo: NOMARJ/sigilsec
  src/
    app/
      page.tsx                # Main landing page
      layout.tsx              # Root layout (Flowbite ThemeModeScript for dark mode)
      globals.css             # Tailwind base + Flowbite Pro imports
      blog/
        page.tsx              # Blog listing page (/blog)
        [slug]/
          page.tsx            # Individual blog post page (/blog/my-post)
      privacy/
        page.tsx              # Privacy policy
      terms/
        page.tsx              # Terms of service
    components/
      Navbar.tsx              # Flowbite Pro navbar with mega-menu
      Hero.tsx                # Flowbite Pro hero section variant
      ProblemStatement.tsx    # Flowbite Pro feature/card section
      HowItWorks.tsx         # Flowbite Pro timeline/steps component
      ScanPhases.tsx         # Flowbite Pro card grid
      Integrations.tsx       # Flowbite Pro logo/icon grid
      Comparison.tsx         # Flowbite Pro comparison table
      Pricing.tsx            # Flowbite Pro pricing cards
      SocialProof.tsx        # Flowbite Pro testimonial section
      DevExperience.tsx      # Flowbite Pro feature list
      BlogPreview.tsx        # Flowbite Pro blog card grid (3 latest posts)
      InstallCTA.tsx         # Flowbite Pro CTA section
      Footer.tsx             # Flowbite Pro mega footer
      TerminalAnimation.tsx  # Custom terminal replay component
      CopyButton.tsx         # Copy-to-clipboard with Flowbite tooltip
    lib/
      analytics.ts           # Event tracking helpers
      constants.ts           # Site-wide constants
      cakewalk.ts            # cakewalk.ai API client (fetch posts, categories, metadata)
    content/
      copy.ts                # All landing page copy in one place
    types/
      blog.ts                # Blog post, category, and AEO schema types
  public/
    og-image.png
    favicon.ico
    robots.txt
    sitemap.xml
  package.json               # flowbite, flowbite-react, next, tailwindcss, etc.
  tailwind.config.ts         # Flowbite plugin + custom theme tokens
  next.config.js
  flowbite.config.ts         # Flowbite Pro theme customization
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
| Vercel/Cloudflare | Hosting + CDN + ISR | Yes |
| Flowbite Pro | UI component library (licensed) | Yes |
| cakewalk.ai | Blog CMS + AEO content platform | Yes |
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
| Flowbite Pro license | Access to Flowbite Pro component library and templates | Needs purchase |
| Terminal recording | `sigil clone` of a repo with findings | Needs creation |
| OG preview image | Branded card for social sharing (1200x630) | Needs creation |
| Blog OG template | Dynamic OG image template for blog posts (post title + category) | Needs creation |
| Favicon | Sigil shield icon, multiple sizes | Needs creation |
| Integration icons | VS Code, JetBrains, GitHub, GitLab, terminal, MCP | Source from Simple Icons or create |
| Phase icons | 6 icons for scan phases | Needs creation or source (Flowbite icons or Heroicons) |
| Comparison table data | Verified claims about competitor capabilities | Verify before publish |
| cakewalk.ai account | API key + project ID for blog integration | Needs setup |
| Initial blog content | 5-10 launch posts across AEO content pillars | Needs creation in cakewalk.ai |
| Author profiles | Name, title, photo, bio for E-E-A-T signals | Needs creation in cakewalk.ai |

### 7.3 Legal Pages (Required Before Launch)

| Page | Route | Content |
|------|-------|---------|
| Privacy Policy | /privacy | Data collection practices, telemetry, cookie-free analytics |
| Terms of Service | /terms | Usage terms for CLI and cloud services |
| Security | /security | Vulnerability disclosure process, security contact |

---

## 8. Launch Requirements

### 8.1 Pre-Launch Checklist

**Landing page:**

- [ ] All sections implemented using Flowbite Pro components and responsive across breakpoints
- [ ] Flowbite Pro dark mode working via `ThemeModeScript` (no flash of unstyled content)
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
- [ ] robots.txt and sitemap.xml deployed (including blog routes)
- [ ] Privacy policy and terms of service pages live
- [ ] 404 page styled and functional
- [ ] Mobile testing on iOS Safari and Android Chrome
- [ ] Cross-browser testing: Chrome, Firefox, Safari, Edge
- [ ] Landing page FAQ section has `FAQPage` JSON-LD schema

**Blog (cakewalk.ai integration):**

- [ ] cakewalk.ai API key and project ID configured in environment
- [ ] `@cakewalk-ai/api` SDK installed and client wrapper (`lib/cakewalk.ts`) working
- [ ] Blog listing page (`/blog`) rendering posts from cakewalk.ai
- [ ] Individual post pages (`/blog/[slug]`) rendering with `body_html` or `structured_content`
- [ ] `generateStaticParams` producing static pages for all published posts
- [ ] ISR revalidation interval configured (300s)
- [ ] On-demand revalidation endpoint (`/api/revalidate`) deployed and tested
- [ ] JSON-LD schemas from `schema_json_ld` field rendering in page head
- [ ] Blog post FAQ sections rendering with Flowbite Pro accordion component
- [ ] Blog preview section on landing page showing 3 latest posts
- [ ] Category filtering working on `/blog` listing page
- [ ] Author cards displaying with E-E-A-T signals (name, title, bio, photo)
- [ ] Minimum 5 blog posts published in cakewalk.ai before go-live
- [ ] Blog sitemap entries included in sitemap.xml
- [ ] OG/Twitter Card meta tags working for individual blog posts

### 8.2 Post-Launch Iteration

| Priority | Enhancement |
|----------|-------------|
| P1 | Add testimonials as they come in from early adopters |
| P1 | Add live scan counter when telemetry supports it |
| P1 | Ramp blog publishing cadence (2-4 posts/week for AEO momentum) |
| P2 | Blog newsletter signup (integrate with email provider) |
| P2 | Interactive demo (scan a sample repo in-browser) |
| P2 | Blog RSS feed for developer audience |
| P2 | AEO performance tracking: monitor AI citation rates (Perplexity, ChatGPT, Gemini) |
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
| Blog traffic | Unique visitors to /blog/* routes |
| Blog-to-install conversion | Blog visit -> install copy event |
| AEO citations | Monitor mentions in ChatGPT, Perplexity, Gemini, Bing Copilot responses (manual + tooling) |
| Blog post frequency | Posts published per week (target: 2-4) |
| Top-performing posts | By traffic, AEO citations, and install conversions |

---

## 10. Blog & cakewalk.ai Integration

### 10.1 Architecture

The blog is a core part of the landing page site (not a separate subdomain). Content is authored and managed in cakewalk.ai and consumed by the Next.js landing page via API at build time using Incremental Static Regeneration (ISR).

```
┌──────────────────┐     Build/ISR      ┌──────────────────┐     CDN Edge      ┌──────────────┐
│   cakewalk.ai    │ ──── API fetch ──▶ │  Next.js (ISR)   │ ──── deploy ───▶ │   Visitors   │
│   (Blog CMS)     │                    │  /blog routes    │                   │              │
│                  │                    │  Static HTML +   │                   │  AI Engines  │
│  - Posts         │     Revalidate     │  JSON-LD schema  │                   │  (crawlers)  │
│  - Categories    │ ◀── every N min ── │                  │                   │              │
│  - Authors       │                    │  Flowbite Pro    │                   │              │
│  - AEO metadata  │                    │  components      │                   │              │
└──────────────────┘                    └──────────────────┘                   └──────────────┘
```

### 10.2 Blog Routes

| Route | Description | Data Source |
|-------|-------------|-------------|
| `/blog` | Blog listing page with category filtering, pagination, and search | cakewalk.ai API — list posts |
| `/blog/[slug]` | Individual blog post with full content, author bio, related posts, FAQ section | cakewalk.ai API — get post by slug |
| `/blog/category/[category]` | Category-filtered listing | cakewalk.ai API — list posts by category |

### 10.3 Blog Page Components (Flowbite Pro)

| Component | Flowbite Pro Base | Customization |
|-----------|-------------------|---------------|
| Blog listing | Blog card grid section | Dark theme, category badges, read time |
| Blog post layout | Article / content section | Table of contents sidebar, author card, related posts grid |
| Category filter | Tabs / pill badges | Horizontal scrollable on mobile |
| Pagination | Pagination component | ISR-friendly static pagination |
| Author card | User / avatar card | E-E-A-T signals: credentials, social links |
| FAQ section | Accordion component | FAQ schema markup auto-generated |
| Share buttons | Button group | Twitter/X, LinkedIn, copy link |

### 10.4 cakewalk.ai API Integration

cakewalk.ai is a headless blog CMS purpose-built for AEO. The official TypeScript SDK (`@cakewalk-ai/api`) provides a zero-dependency client with built-in caching.

**Install:**

```bash
npm install @cakewalk-ai/api
```

**Client setup (`lib/cakewalk.ts`):**

```typescript
import { AEO } from '@cakewalk-ai/api';

export const blog = new AEO.BlogClient({
  apiKey: process.env.CAKEWALK_API_KEY!,       // ck_live_... from app.cakewalk.ai/keys
  projectId: process.env.CAKEWALK_PROJECT_ID!, // proj_... from dashboard
  options: { cacheTtl: 600 },                  // 10 min in-memory cache
});
```

**API Endpoints (via SDK methods):**

| SDK Method | Endpoint | Description |
|------------|----------|-------------|
| `blog.getPosts({ status, category, limit, offset })` | `GET /v1/posts` | Paginated post list with filters |
| `blog.getPostBySlug(slug)` | `GET /v1/posts/slug/{slug}` | Single post by URL slug |
| `blog.getCategories()` | `GET /v1/categories` | All categories for the project |

**Post data model (key fields):**

```typescript
interface Post {
  id: number;
  title: string;
  slug: string;
  status: 'published' | 'planned' | 'writing' | 'review';
  post_type: 'pillar' | 'cluster' | 'standalone';
  post_format: 'ultimate-guide' | 'how-to' | 'comparison' | string;
  category: string | null;
  primary_keyword: string;
  secondary_keywords: string[];
  excerpt: string | null;
  body_markdown: string | null;
  body_html: string | null;
  structured_content: StructuredContent | null;  // Typed AEO sections
  schema_json_ld: object[] | null;               // Pre-generated JSON-LD
  meta_title: string | null;
  meta_description: string | null;
  featured_image_url: string | null;
  ai_summary: string | null;
  faq_questions: Array<{ question: string; answer: string }>;
  author: Author | null;                         // { name, title, photo_url, bio, byline }
  published_at: string | null;
  updated_at: string | null;
}
```

**Structured content sections** (AEO-specific typed blocks):

| Section Type | Schema Mapping | Purpose |
|-------------|----------------|---------|
| `intro` | Article description | Opening paragraph optimized for AI extraction |
| `heading` | Article section | H2/H3 with content |
| `faq` | FAQPage schema | Question/answer pairs auto-included in JSON-LD |
| `how_to_step` | HowTo schema | Numbered steps auto-included in JSON-LD |
| `table` | Table markup | Structured data AI engines favor for comparisons |
| `key_takeaways` | Key facts | Bulleted facts for AI citation |

**Content rendering options:**

Posts are available in three formats, giving full flexibility:
1. `body_html` — Pre-rendered HTML, simplest to embed
2. `body_markdown` — Raw Markdown, render with your own pipeline
3. `structured_content` — Typed section objects for building custom React components with maximum control

### 10.5 ISR Configuration

| Setting | Value | Rationale |
|---------|-------|-----------|
| Revalidation interval | 300 seconds (5 minutes) | Balance between freshness and build load; cakewalk.ai SDK has built-in 5-10 min TTL cache |
| Static generation | All published posts at build time via `generateStaticParams` | Full static for SEO/AEO crawlers |
| On-demand revalidation | Custom `/api/revalidate` route handler | Expose a webhook endpoint; if cakewalk.ai supports outbound webhooks, configure on publish/update events |
| Fallback | `blocking` | New posts SSR on first request, then cached |
| Cache clearing | Call `blog.clearCache()` on revalidation | Ensures stale SDK cache is busted alongside Next.js ISR |

**On-demand revalidation endpoint:**

```typescript
// app/api/revalidate/route.ts
import { revalidatePath } from 'next/cache';
import { blog } from '@/lib/cakewalk';

export async function POST(request: NextRequest) {
  const secret = request.headers.get('x-webhook-secret');
  if (secret !== process.env.REVALIDATION_SECRET) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }
  const { slug } = await request.json();
  blog.clearCache();
  revalidatePath('/blog');
  if (slug) revalidatePath(`/blog/${slug}`);
  return Response.json({ revalidated: true });
}
```

### 10.6 AEO Structured Data Per Blog Post

cakewalk.ai pre-generates JSON-LD schemas per post via the `schema_json_ld` field. These are ready to inject directly into `<script type="application/ld+json">` tags — no manual assembly required.

**Schemas auto-generated by cakewalk.ai:**

| Schema Type | When Generated | Source Data |
|-------------|----------------|-------------|
| `Article` / `BlogPosting` | Always | headline, author, dates, keywords, publisher |
| `FAQPage` | When `faq` sections exist in `structured_content` | `faq_questions[]` array |
| `HowTo` | When `how_to_step` sections exist | Step title + description |
| `Person` | When author is present | Author name, title, photo, bio |
| `Organization` | Always (publisher) | NOMARK project settings |
| `BreadcrumbList` | Always | Navigation path; includes pillar page for cluster posts |

**Additional AEO signals per post:**

- `ai_summary` — AI-generated summary field optimized for citation by answer engines
- `primary_keyword` / `secondary_keywords[]` — Keyword targeting built into the data model
- `post_type` — Pillar/cluster/standalone topology for topic authority building
- `structured_content.citations[]` — Source attribution with `{ text, source_url }` pairs

**Rendering JSON-LD in Next.js:**

```tsx
{post.schema_json_ld?.map((schema, i) => (
  <script
    key={i}
    type="application/ld+json"
    dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
  />
))}
```

---

## 11. Out of Scope (v1)

The following are explicitly **not** part of the initial landing page:

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

## 12. Open Questions

| # | Question | Decision Needed By |
|---|----------|-------------------|
| ~~1~~ | ~~Should the landing page live in the same repo (monorepo) or a separate repo?~~ | **Resolved:** Separate repo `NOMARJ/sigilsec` |
| 2 | Domain registrar and hosting provider confirmation? | Before DNS setup |
| 3 | Do we have brand assets (logo, wordmark, icon) finalized? | Before design starts |
| 4 | Stripe pricing page IDs — are Pro and Team products created in Stripe? | Before pricing CTAs go live |
| 5 | Analytics provider selection (Plausible vs PostHog vs other)? | Before launch |
| 6 | Do we want a waitlist/early access flow for Team/Enterprise, or direct signup? | Before pricing section finalized |
| 7 | Flowbite Pro license tier — which plan covers our usage (Developer, Designer, or Company)? | Before development starts |
| 8 | cakewalk.ai account setup — API key provisioning, webhook configuration, and content model setup? | Before blog development starts |
| 9 | cakewalk.ai API documentation — confirm available endpoints, rate limits, and authentication method? | Before blog development starts |
| 10 | Blog content calendar — who owns content creation? In-house, contractors, or AI-assisted? | Before launch |
| 11 | Initial blog launch corpus — how many posts should be published before go-live? (Recommend 5-10) | Before launch |

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

## Appendix D: Blog Category Taxonomy (cakewalk.ai)

Categories to configure in the cakewalk.ai project dashboard. Each category maps to a content pillar and AEO query cluster.

| Category Slug | Display Name | Content Pillar | Post Types | Example Post Titles |
|---------------|-------------|----------------|------------|---------------------|
| `threat-intel` | Threat Intelligence | Threat Intelligence | cluster, standalone | "Malicious npm package steals AWS credentials via postinstall hook", "Q1 2026 AI supply chain threat report" |
| `how-to` | How-To Guides | How-To Guides | cluster, standalone | "How to scan MCP servers before installing them", "Setting up Sigil CI/CD gates in GitHub Actions" |
| `security-research` | Security Research | Security Research | pillar, cluster | "The anatomy of a credential exfiltration attack in AI agent tools", "Obfuscation techniques in malicious Python packages" |
| `product-updates` | Product Updates | Product Updates | standalone | "Sigil v1.2: JetBrains plugin and GitLab CI support", "New scan phase: DNS tunneling detection" |
| `industry` | Industry Analysis | Industry Analysis | pillar, cluster | "The state of MCP server security in 2026", "Why AI agents need a different security model" |
| `comparisons` | Comparisons | Product Updates | standalone | "Sigil vs Snyk: Which tool catches malicious code?", "5 best tools for AI agent supply chain security" |
| `tutorials` | Tutorials | How-To Guides | cluster | "Scanning your first npm package with Sigil in 60 seconds", "Integrating Sigil with Claude Code via MCP" |

## Appendix E: Environment Variables (Landing Page)

| Variable | Description | Required |
|----------|-------------|----------|
| `CAKEWALK_API_KEY` | cakewalk.ai API key (`ck_live_...`) | Yes |
| `CAKEWALK_PROJECT_ID` | cakewalk.ai project ID (`proj_...`) | Yes |
| `REVALIDATION_SECRET` | Shared secret for on-demand ISR webhook endpoint | Yes |
| `NEXT_PUBLIC_SITE_URL` | `https://sigilsec.ai` — used for canonical URLs and OG meta | Yes |
| `NEXT_PUBLIC_ANALYTICS_ID` | Plausible or PostHog site/project ID | Yes |
| `NEXT_PUBLIC_GITHUB_REPO` | `NOMARJ/sigil` — for live star count badge | Nice to have |
