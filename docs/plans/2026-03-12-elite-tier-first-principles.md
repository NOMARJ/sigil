# Elite Tier First Principles Analysis
Date: 2026-03-12

---

## The Core Question

Before analyzing features, frame the real question: **Why would a developer spend $79/month on a security tool when they already have a $29/month option?**

The answer is never "because we gave them more credits." Credits are a billing mechanism, not a value proposition. The answer lives in psychology, workflow, and — critically for security tools — anxiety reduction.

---

## 1. Consumer Psychology of "Elite" Tiers

### The Identity Effect (Strongest Driver)

"Elite" is not an accident of naming. It signals that the buyer has arrived at a professional level. For developers and security engineers specifically, this maps to a career identity: *I am someone who takes security seriously enough to pay for it properly.*

This matters more than it sounds. Security engineers are often the person in the room saying "we need to slow down and audit this." Paying for Elite signals to themselves and their organization that they have the right instincts. It's self-justifying.

The naming tier sequence — Free → Pro → Elite → Team → Enterprise — positions Elite as the highest individual tier before becoming a team concern. That framing is powerful: it's the ceiling of what one person can do before they need a team. It flatters individual contributors.

### Anxiety Reduction (Most Underrated Driver)

For a security tool, this is the dominant psychological lever and it is almost entirely ignored in SaaS pricing conversations.

A developer scanning AI agent code has a specific fear: *something got through that I missed.* The Pro tier scanning addresses detection. The Elite tier should address confidence. These are different things.

Detection says: "We found X threats."
Confidence says: "We are sure we did not miss anything."

Pro tier users will always wonder if the scan was thorough enough. Elite users need to feel that the scan left no stone unturned — and that if something did slip through, they have evidence of due diligence. This is not paranoia; it is professional liability thinking.

**Takeaway**: Frame Elite features around completeness and confidence, not volume.

### The Productivity Multiplication Effect

At $29/month, Pro is a tool you use. At $79/month, Elite needs to feel like something that works for you when you are not watching. Automation, scheduling, CI/CD hooks, and alerting are not just conveniences — they change the product category from "scan tool" to "security infrastructure."

The moment a user sets up a nightly scheduled scan and gets a Slack alert when something changes, the tool is woven into their workflow. Churn becomes nearly impossible because switching costs are now operational, not just psychological.

### Status and Legitimacy (Secondary, Real)

Security engineers often present findings to non-technical stakeholders. A well-formatted PDF report with a Sigil logo, a compliance summary, and timestamped findings creates an artifact that justifies the user's professional judgment. It makes them look good. That has real value.

---

## 2. What Comparable Products Do at the Mid-Premium Tier

### GitHub Copilot Enterprise (~$39/user/month)

Differentiators at premium: organization-level knowledge (custom fine-tuning on internal codebase), PR summaries, security vulnerability explanations, policy enforcement. The key insight: it stops being *your* assistant and starts being *your organization's* assistant. The data is yours, the model learns your patterns.

**Lesson for Sigil**: Custom scan policies (your org's rules, not just Sigil's defaults) are the equivalent move.

### Snyk Business (~$98/user/month)

At premium: PR gates with automatic fix PRs, SBOM generation, compliance reporting (SOC 2, GDPR references), SSO, audit logs, custom severity thresholds per project. The key: compliance artifacts are a major justification. Security managers buy Snyk Business when they need to show an auditor that vulnerabilities are tracked and remediated systematically.

**Lesson for Sigil**: Audit trails and exportable compliance reports are table-stakes for anyone working in a regulated environment. Even mid-market companies are increasingly subject to SOC 2 audits, and "we scanned our AI agent code" is a legitimate control to document.

### Semgrep Pro (~$40+/user/month)

At premium: custom rules written in their DSL, cross-file analysis, secrets detection, historical tracking of findings across branches. The key: custom rules. Security teams have institutional knowledge about their specific threat models that generic tools cannot encode. Giving users the ability to codify that knowledge inside Sigil is a strong retention mechanism.

**Lesson for Sigil**: Custom pattern libraries or the ability to add/suppress rules per project would be a genuine differentiator.

### Socket.dev Pro (~$20+/user/month)

At premium: automated PR blocking, deeper supply chain analysis, organization-level dashboards, policy files. Socket's key insight is that the tool gets better the more repos you connect — network effects within an account. They also make security blocking automatic rather than advisory.

**Lesson for Sigil**: The shift from advisory to automatic (blocking, gating, alerting) is the qualitative upgrade that justifies a price jump. If Pro tells you there's a problem and Elite stops the problem from progressing, that is a fundamentally different value proposition.

### Vercel Pro (~$20/user/month)

At premium: team features, increased limits, analytics, SLA. Notably, Vercel Pro is relatively weak on qualitative differentiation — it is largely a quantitative tier. This is a cautionary tale. Vercel survives because they are a development platform with high lock-in. Sigil cannot rely on lock-in alone and must compete on features.

### Linear Pro (~$8/user/month)

At premium: Git integration, SLA, more automation. Linear's insight: their paid features make the tool smarter about your workflow, not just bigger. Automation that reduces manual work is the pitch.

### Cursor Business (~$40/user/month)

At premium: privacy mode (code never sent to third parties), admin controls, centralized billing, SSO, usage analytics. The privacy/compliance angle is significant — many enterprise users cannot use the consumer tier due to data handling policies. Business tier unlocks an entirely different buyer category.

**Lesson for Sigil**: A "private scan mode" or "no-telemetry mode" where scan results are never stored on Sigil's servers could unlock compliance-sensitive buyers who currently cannot use Pro at all.

---

## 3. First Principles: What Does a Security Developer Actually Need at $79?

Strip away convention. Ask: *what is the actual job this person is trying to do, and what prevents them from doing it on Pro?*

The job: **continuously ensure that AI agent code they ship and depend on does not contain malicious or dangerous patterns, and demonstrate that assurance to themselves and others.**

Breaking that down:

**"Continuously ensure"** → They need automation. Manual scans are not continuous. Pro requires them to initiate scans. Elite should scan without them.

**"AI agent code they ship and depend on"** → Two categories: code they write (covered by scan), and code they consume (packages, MCP servers, repos). The latter grows over time and changes without warning.

**"Demonstrate assurance"** → They need records. Not just "we scanned it" but "here is what we scanned, when, what we found, and what we did about it." This is the compliance artifact problem.

**"To themselves"** → Confidence, not just detection. Completeness guarantees. Audit trails for their own reference.

**"And others"** → Exportable reports, shareable findings, integration with the tools their team already uses (Slack, GitHub, Jira).

None of this is about credits. Credits are a false proxy for value.

---

## 4. Psychological Pricing: $79 vs $29

The 2.7x price jump needs to feel like a category change, not an upgrade. Here is the mental math a buyer runs:

**$29 → $79 feels justified if Elite feels like a different product category.**

Specific mental models that justify the gap:

| Mental Model | What Triggers It |
|---|---|
| "This is infrastructure, not a tool" | Scheduled scans, CI/CD integration, always-on monitoring |
| "This protects me professionally" | Audit trails, compliance exports, evidence of due diligence |
| "This works when I'm not looking" | Alerting, automated gating, drift detection |
| "This is tuned to my context" | Custom rules, project-level configuration, suppression management |
| "This gives me information I couldn't get otherwise" | Deeper LLM analysis, historical trending, dependency graphs |

**What does NOT justify the gap:**
- More credits (quantitative, not qualitative)
- Priority support (invisible until needed)
- "Claude Sonnet access" (meaningless to most buyers without context on why it matters)

The current Elite differentiators (priority support, Claude Sonnet, API access, custom integrations) are all invisible or abstract. None of them are features the user encounters in their daily workflow.

---

## 5. The Middle Tier Trap

### The Gravitational Pull of Pro

Pro users stay because:
- 5,000 credits is enough for most workflows
- The price is not painful enough to justify evaluating alternatives
- The upgrade friction is non-trivial

Pro users churn or upgrade when:
- They hit credit limits repeatedly
- They have a security incident and feel they needed more
- Their team grows and they start needing team features

### The Gravitational Pull of Team

Team users ($199/month) come from Elite when:
- They need multiple seats (Elite is implicitly single-user)
- They need centralized billing and admin controls
- They need audit features at an org level, not just individual level

### The Elite Trap

Elite fails when it is positioned as "more Pro" rather than "one step before Team." Users ask themselves: "Why not just stay on Pro and expense the difference later?" or "If I'm spending $79, why not just upgrade to Team?"

**Elite needs a clear identity**: It is the tier for the solo security practitioner, consultant, or senior engineer who operates with team-level responsibility but not team-level headcount. They make security decisions alone. They need tools that let them act like a team of one.

This framing unlocks the feature set. A team of one needs:
- Automation (because there is no one to delegate to)
- Complete audit trails (because they are the only one accountable)
- Exportable reports (because they present to others)
- CI/CD integration (because they set up the pipeline alone)
- Higher-fidelity analysis (because they cannot afford to miss things with no backup)

---

## 6. Feature Recommendations

Ranked by: **Psychological Impact / Implementation Cost / Differentiation Value**

### Tier 1: High Impact, Medium Cost, High Differentiation

**1. Scheduled Scans + Drift Alerting**
- *What it does*: Run scans on a cron schedule; alert when new findings appear or risk score changes
- *Why it matters*: This is the "infrastructure" mental shift. The tool now works without user action. Dependencies change without warning — a package that was clean last week may have received a malicious update. This catches that.
- *Psychological trigger*: Anxiety reduction, "works when I'm not watching"
- *Implementation cost*: Medium — requires job scheduler, notification pipeline, state diffing logic
- *Differentiation*: High — none of the current Elite differentiators do this

**2. CI/CD Integration (GitHub Actions, GitLab CI)**
- *What it does*: Native GitHub Action that runs Sigil on PRs; optional blocking on critical findings
- *Why it matters*: This embeds Sigil into the developer's existing workflow. Churn becomes operationally painful. It also means Sigil is visible to the team even on an individual plan — social proof and potential expansion.
- *Psychological trigger*: Productivity multiplication, "infrastructure not a tool"
- *Implementation cost*: Medium — GitHub Actions marketplace listing, API key auth, configurable thresholds
- *Differentiation*: High — this is a specific gap in current Elite offering

**3. Scan History + Risk Trending**
- *What it does*: Persist scan results; show risk score over time per repo/package; highlight new vs resolved findings
- *Why it matters*: Without history, every scan is a point-in-time fact with no context. With history, users can see if their security posture is improving or degrading. This is a fundamentally more valuable product.
- *Psychological trigger*: Confidence, professional legitimacy, "I can show this to a manager"
- *Implementation cost*: Medium — requires storage layer for scan results, query API, visualization
- *Differentiation*: High — directly enables compliance use cases

### Tier 2: High Impact, Lower Cost, Medium Differentiation

**4. Exportable Compliance Reports (PDF/JSON)**
- *What it does*: Generate a formatted report from a scan with executive summary, finding details, remediation guidance, and timestamp attestation
- *Why it matters*: Security engineers presenting to CTOs, compliance teams, or auditors need an artifact. A PDF report with Sigil branding and a timestamped finding list is a professional deliverable they cannot produce from raw CLI output.
- *Psychological trigger*: Status, professional legitimacy, "makes me look good"
- *Implementation cost*: Low-Medium — PDF templating (reportlab, WeasyPrint), structured JSON export endpoint
- *Differentiation*: Medium — Snyk does this well, but Sigil would be first in AI agent security category

**5. Full Audit Trail**
- *What it does*: Log every scan, result, approval, and rejection with timestamp, user, and context. Immutable, exportable.
- *Why it matters*: For anyone subject to SOC 2 or similar compliance, "we have an audit log of all security scans" is a literal checkbox. This unlocks buyers who currently cannot justify the tool purchase because they need documented evidence.
- *Psychological trigger*: Anxiety reduction, professional liability protection
- *Implementation cost*: Low — structured logging to append-only store; UI to browse/export
- *Differentiation*: High within AI security category, table-stakes in enterprise security generally

**6. Slack Notifications**
- *What it does*: Push scan results, new findings, and risk score changes to a Slack channel
- *Why it matters*: Slack is where developers live. Pulling findings into Slack means security is ambient rather than something requiring a login. It also creates visibility — teammates see alerts even if they are not Sigil users, driving organic expansion.
- *Psychological trigger*: "Works when I'm not watching," low-friction awareness
- *Implementation cost*: Low — Slack webhook integration, configurable alert thresholds
- *Differentiation*: Medium — common feature, but absence is a gap

### Tier 3: Medium Impact, Varies, Strong Differentiation

**7. Custom Scan Policies**
- *What it does*: Let users define project-level rules: suppress known-safe findings, add custom patterns, adjust severity thresholds, configure which phases to run
- *Why it matters*: Generic tools generate noise. Teams develop institutional knowledge about what matters in their specific context. Custom policies let users encode that knowledge into Sigil, making it increasingly accurate to their environment over time.
- *Psychological trigger*: "Tuned to my context," identity (expert user who customizes their tools)
- *Implementation cost*: Medium-High — policy DSL, per-project config storage, rule inheritance model
- *Differentiation*: Very High — this is what separates a tool from infrastructure

**8. MCP Server Catalog + Reputation Scores**
- *What it does*: Maintain a database of known MCP servers with community-reported scan results and reputation scores; Elite users get access to the full catalog and can submit servers
- *Why it matters*: AI agent developers face a specific and growing threat: malicious MCP servers. A community reputation layer (similar to Socket.dev's package health scores) gives Elite users intelligence they cannot get anywhere else.
- *Psychological trigger*: Exclusive intelligence, "information I couldn't get otherwise"
- *Implementation cost*: Medium — requires catalog infrastructure, reputation algorithm, submission workflow
- *Differentiation*: Extremely High — no one else is doing this for MCP servers specifically

**9. Dependency Monitoring (Watchlist)**
- *What it does*: Users add packages, repos, or MCP servers to a watchlist; Sigil re-scans them on a schedule and alerts on changes
- *Why it matters*: The supply chain threat is ongoing, not point-in-time. A package that was clean at installation can receive a malicious update. Users need to know when their existing dependencies change risk profile.
- *Psychological trigger*: "Works when I'm not watching," anxiety reduction about ongoing exposure
- *Implementation cost*: Medium — requires job scheduler, change detection, notification pipeline
- *Differentiation*: High — addresses a gap that Pro completely ignores

**10. Private Scan Mode (No Server-Side Storage)**
- *What it does*: Option to run scans where findings and code snippets are never persisted on Sigil servers; results returned in-memory only
- *Why it matters*: Many companies — financial services, healthcare, defense contractors — have policies prohibiting sending code to third-party services. Private scan mode makes Sigil usable for this buyer category, which is currently completely locked out.
- *Psychological trigger*: Compliance unlock, trust
- *Implementation cost*: Medium — architectural change to scan pipeline; requires stateless processing path
- *Differentiation*: Very High — this unlocks a buyer segment that cannot currently use Sigil at all

---

## 7. What to Drop or Deprioritize

**"Priority Support"** — Invisible until needed, and when needed it often disappoints. Users don't upgrade for this. It should be included but never featured as a primary differentiator.

**"Claude Sonnet Access"** — Meaningless marketing unless explained as "deeper analysis that catches things GPT-3.5 misses, specifically: [examples]." Feature the outcome, not the model name.

**"API Access"** — Table stakes for any developer tool. Should not be a differentiator at this tier. Consider moving to Pro or even Free.

**"Custom Integrations"** — Vague. Replace with specific named integrations (GitHub Actions, Slack, Jira) so the user can evaluate whether they care.

---

## 8. Recommended Elite Tier Composition

Based on this analysis, Elite should ship with:

**Core Elite Identity: "Security Infrastructure for the Solo Practitioner"**

| Feature | Tier | Priority |
|---|---|---|
| Scheduled scans (daily/weekly cron) | Elite exclusive | Ship first |
| Slack + email alerting on new findings | Elite exclusive | Ship first |
| GitHub Actions native integration | Elite exclusive | Ship first |
| Scan history + risk trending (90 days) | Elite exclusive | Ship first |
| Exportable PDF/JSON compliance reports | Elite exclusive | Ship second |
| Full audit trail (immutable, exportable) | Elite exclusive | Ship second |
| Dependency watchlist (up to 50 items) | Elite exclusive | Ship second |
| Custom scan policies (rule suppression, severity overrides) | Elite exclusive | Ship third |
| MCP server reputation catalog access | Elite exclusive | Ship third |
| Private scan mode | Elite exclusive | Ship third |
| 15K credits | Quantitative | Already planned |
| Claude Sonnet analysis (with outcome explained) | Quality signal | Already planned |

**What stays Pro-only**: On-demand scans, 5K credits, Haiku analysis, basic API access, scan reports (raw JSON only)

**What moves to Team**: Multi-seat management, centralized billing, org-level dashboards, SSO, team audit trails

---

## 9. The Pitch, Rewritten

Current pitch (implicit): "Elite gives you more credits and better AI analysis."

Recommended pitch: "Elite turns Sigil from a tool you run into a security system that runs for you. Set it up once, and Sigil watches your repos and dependencies continuously — alerting you when risk changes, blocking bad code in PRs, and generating the audit trail you need to prove your security posture."

That pitch answers the anxiety question, the automation question, and the professional legitimacy question simultaneously. It is a fundamentally different product story than "more credits."

---

## Conclusion

The $79 Elite tier is currently positioned as quantitatively better than Pro. It needs to be qualitatively different. The psychological gap between "I scan code" and "my security posture is continuously monitored" is where the 2.7x price increase lives.

The three features with the highest leverage — highest psychological impact relative to implementation cost — are:

1. **Scheduled scans + drift alerting** (infrastructure shift, anxiety reduction)
2. **GitHub Actions integration** (workflow lock-in, always-on feel)
3. **Scan history + risk trending** (compliance artifact, confidence signal)

These three alone would justify the Elite price point for a significant portion of the target market. Everything else in the recommended list adds depth and defensibility over time.

The MCP server reputation catalog is the long-term moat. No one else is building this. It takes time to accumulate the data, but once it exists, it is uniquely valuable and extremely difficult to replicate.
