# sigilsec.ai — Frontend Implementation Spec

**Status:** Required before public launch
**Audience:** Whoever builds the sigilsec.ai marketing site + public scan database frontend
**Backend repo:** NOMARJ/sigil (this repo)
**Frontend repo:** Separate — sigilsec.ai (Vercel / Next.js)

---

## What This Document Is

The Sigil backend (this repo) implements an API, a dashboard, a CLI, an MCP server, and a GitHub App. The `sigilsec.ai` marketing site is a **separate repo** that serves as the public face of the product. This spec defines exactly what `sigilsec.ai` must implement, what API surfaces it consumes, and what legal/liability requirements it must meet before the scan database goes public.

The dashboard in this repo (`dashboard/`) is the **authenticated internal dashboard** for logged-in users. The `sigilsec.ai` site is the **public-facing site** — marketing pages, public scan database browser, badge rendering, and legal pages.

---

## Architecture Overview

```
sigilsec.ai (this spec)              API (this repo)
========================             ====================
Marketing pages          ──────────> (no API needed)
/scans (public browser)  ──────────> GET /registry/search
/scans/{eco}/{pkg}       ──────────> GET /registry/{eco}/{pkg}
/scans/{eco}/{pkg}/{ver}  ─────────> GET /registry/{eco}/{pkg}/{ver}
/badge/{eco}/{pkg}.svg   ──────────> GET /badge/{eco}/{pkg}
/terms                   ──────────> (static content)
/privacy                 ──────────> (static content)
/methodology             ──────────> (static content)
/login (redirect)        ──────────> Dashboard at app.sigilsec.ai or /dashboard
```

**Key distinction:** The public site hits **only unauthenticated registry and badge endpoints**. It never touches `/v1/scan`, `/scans`, `/v1/auth`, or any authenticated endpoint. Those belong to the dashboard.

---

## 1. Required Pages

### 1.1 Marketing / Landing Page (`/`)

Standard product marketing page. Content is outside this spec's scope, but it must:

- Never use the word "safe", "clean", or "certified" to describe scan results
- Never display star ratings, assurance scores, or certification-style graphics
- Link to `/terms`, `/privacy`, and `/methodology` in the footer
- Include `security@nomark.ai` as a contact

### 1.2 Public Scan Database (`/scans`)

**API:** `GET /registry/search?q=&ecosystem=&verdict=&page=&per_page=`
**API:** `GET /registry/stats`

Browse all publicly scanned packages. This is the main SEO/AEO surface.

**Required elements:**

**Persistent banner at top of page (not dismissible, not behind a toggle):**

```
Sigil scans packages across ClawHub, PyPI, npm, and GitHub using automated
static analysis. Results indicate detected patterns, not certified safety
status. See our Terms of Service for full details.
```

- Link "Terms of Service" to `/terms`
- Banner must be visible without scrolling on mobile

**Filters:** Ecosystem (all, clawhub, pypi, npm, github, mcp), Verdict (all, LOW_RISK, MEDIUM_RISK, HIGH_RISK, CRITICAL_RISK)

**Search:** Free-text search by package name

**Per-result card shows:**
- Package name, ecosystem, version
- Verdict badge (color-coded, see Section 7)
- Risk score
- Findings count
- Scan date
- Link to detail page

**Stats header** (from `/registry/stats`):
- Total packages scanned
- Breakdown by ecosystem
- Breakdown by verdict

### 1.3 Scan Report Page (`/scans/{ecosystem}/{slug}`)

**API:** `GET /registry/{ecosystem}/{package_name}`

This is the page that badges link to. It's the most legally sensitive surface.

**Required elements:**

**Header:**
- Package name, ecosystem, version
- Verdict badge (color-coded)
- Risk score
- Scan date (prominent — this is a point-in-time result)
- Files scanned count
- Findings count

**Risk breakdown:** Group findings by scan phase, show weighted severity per phase.

**Findings list:** Expandable list of findings with:
- Phase
- Rule name
- Severity
- File path + line number
- Code snippet

**Badge embed section** with this disclaimer text above the copy-paste code:

```
The Sigil badge reflects the result of an automated point-in-time scan.
It is not an endorsement, certification, or guarantee of safety. Results
may change between versions. Package authors who display this badge are
responsible for keeping their scanned version current.
```

Badge markdown for copy:
```
[![Scanned by Sigil](https://sigilsec.ai/badge/{ecosystem}/{package_name}.svg)](https://sigilsec.ai/scans/{ecosystem}/{package_name})
```

**Dispute link:**
```
Believe this result is incorrect? Request a review or see our Terms of
Service and Methodology.
```
- "Request a review" links to `mailto:security@nomark.ai`
- "Terms of Service" links to `/terms`
- "Methodology" links to `/methodology`

**Full disclaimer (as `<aside>`, visible on page load without scrolling past content, not behind a toggle or accordion):**

```
DISCLAIMER: This scan was performed by automated static analysis. A LOW
RISK verdict means no known malicious patterns were detected at the time
of scanning — it does not certify that this package is safe, free from
vulnerabilities, or suitable for any purpose. Risk classifications reflect
the output of automated analysis based on defined detection criteria and
are statements of algorithmic opinion, not assertions of malicious intent
by any author or publisher. Scan results may contain false positives or
false negatives. Always review source code before installing or executing
any package. NOMARK Pty Ltd provides this information "as is" without
warranty of any kind and accepts no liability for any loss or damage
arising from reliance on these results.
```

**Styling:** Muted text, `<aside>` element. Not hidden. Must be visible on page load.

### 1.4 Versioned Report Page (`/scans/{ecosystem}/{slug}/{version}`)

**API:** `GET /registry/{ecosystem}/{package_name}/{version}`

Same layout as 1.3 but for a specific version. Important for badge versioning — a badge for v1.2.0 should link here, not to the "latest" page.

### 1.5 Terms of Service (`/terms`)

**API:** None (static content)

Must exist at `sigilsec.ai/terms` before public launch. The following 15 clauses are required. The exact text below is directional — a lawyer must review the final wording.

**Header:** "Terms of Service" — Last updated: {date} — NOMARK Pty Ltd — Queensland, Australia

**Clauses:**

1. **No Warranty** — Scan results provided "as is" and "as available" without warranties of any kind, express or implied, including merchantability, fitness for purpose, accuracy, or non-infringement.

2. **Australian Consumer Law** — Nothing in these Terms excludes, restricts or modifies any consumer guarantee, right or remedy available under the Australian Consumer Law (Schedule 2 of the *Competition and Consumer Act 2010* (Cth)) that cannot be excluded. *This clause is mandatory for AU jurisdiction.*

3. **Information-Only Purpose** — The Service provides general information only and does not constitute professional security, technical, or risk advice.

4. **No Certification** — A scan result (including LOW RISK or any other verdict) does not constitute a security certification, endorsement, or recommendation. Verdicts reflect automated pattern matching at a specific point in time against a specific version.

5. **Algorithmic Opinion** — Risk classifications reflect the output of automated analysis based on defined detection criteria and are statements of algorithmic opinion, not assertions of malicious intent by any author or publisher. *Critical for defamation defence.*

6. **No-Reliance** — Users must not rely solely on Sigil scan results when making security, operational, or commercial decisions.

7. **Limitation of Liability** — NOMARK not liable for damages from: reliance on results, false negatives, false positives, actions taken based on results, third-party badge/report use.

8. **No Continuous Monitoring** — NOMARK does not monitor packages continuously. Not responsible for changes after a scan.

9. **Badge Usage** — Badge is informational only. Display does not create endorsement relationship. Does not imply approval, partnership, monitoring, or ongoing assessment. Results may change without notice on rescan. Authors responsible for their own code security regardless of Sigil results.

10. **False Positive / Dispute Process** — Authors can contact `security@nomark.ai` or use scan report dispute link. NOMARK reserves right to maintain/modify/remove results. Dispute does not guarantee verdict change.

11. **Automated Scanning** — Packages scanned automatically without author consent from public registries. Authors may request removal via `security@nomark.ai`. NOMARK reserves right to continue scanning public packages.

12. **Data Accuracy** — Reasonable efforts but no guarantee results are error-free, complete, or current. Third-party metadata may be inaccurate.

13. **Redistribution / API Protection** — Users must not present Sigil data as their own certification, guarantee, or assessment. Disclaimer and attribution must be preserved when redistributing.

14. **Indemnification** — Users who rely on results, embed badges, or distribute scan data agree to indemnify NOMARK.

15. **Governing Law** — Queensland, Australia. Exclusive jurisdiction of Queensland courts.

**Footer note:** "These Terms will be reviewed by qualified external counsel before the Service is made publicly available. Contact legal@nomark.ai."

### 1.6 Privacy Policy (`/privacy`)

**API:** None (static content)

Must exist at `sigilsec.ai/privacy` before public launch.

**Required sections:**

- **Data Sources** — Public package registries (PyPI, npm, ClawHub), public GitHub repositories/profiles, public MCP server registries. No private sources.
- **Purpose** — Security transparency. Enabling developers to assess risk before installing packages.
- **Lawful Basis** — Legitimate interest (GDPR Article 6(1)(f)). Public data, community security purpose.
- **Data Minimisation** — Only publicly available data. No unnecessary personal data. Author names from public registries only.
- **User Rights** — Right to access, object, removal. Contact: `security@nomark.ai`.
- **Data Retention** — Scan results indefinite. Personal data removed within 30 days on valid request.
- **Cookies & Analytics** — Essential cookies only. No third-party advertising or cross-site tracking.
- **Contact** — NOMARK Pty Ltd, `security@nomark.ai`.

### 1.7 Methodology (`/methodology`)

**API:** None (static content)

Must exist at `sigilsec.ai/methodology` before public launch. Critical for defamation defence — without a documented methodology, publishing risk verdicts on named packages is indefensible.

**Required sections:**

- **Static Analysis Only** — Automated pattern analysis. No code execution, no manual audit, no penetration testing.
- **Pattern / Signature Detection** — Rules targeting known malicious patterns from supply chain attack research.
- **Point-in-Time Analysis** — Each scan = specific version at specific time. Results don't reflect post-scan changes.
- **No Continuous Monitoring** — No real-time package watching. Rescans on schedule or on-demand.
- **False Positive & False Negative Risk** — Automated analysis is imperfect. Legitimate patterns may be flagged; novel attacks may be missed.

**Detection Criteria table — all 8 scan phases:**

| Phase | Weight | Detects |
|-------|--------|---------|
| Install Hooks | 10x | setup.py cmdclass, npm preinstall/postinstall |
| Code Patterns | 5x | eval(), exec(), pickle.loads, child_process, Function() |
| Network / Exfil | 3x | Outbound HTTP, webhooks, DNS exfiltration |
| Credentials | 2x | ENV vars, API keys, SSH key paths, .aws/credentials |
| Obfuscation | 5x | base64, String.fromCharCode, hex-encoded strings |
| Provenance | 1-3x | Git history, binary executables, hidden/large files |
| Prompt Injection | 10x | AI agent instruction injection, system prompt overrides |
| Skill Security | 5x | MCP permission escalation, undeclared tool capabilities |

**Risk classification scale:**

| Score | Verdict | Meaning |
|-------|---------|---------|
| 0-9 | LOW RISK | No known malicious patterns detected at time of scanning |
| 10-24 | MEDIUM RISK | Patterns consistent with suspicious behaviour; manual review recommended |
| 25-49 | HIGH RISK | Multiple risk indicators; do not install without thorough review |
| 50+ | CRITICAL RISK | Strong risk indicators across multiple phases |

*"Risk levels indicate detection results only and are not safety ratings or certifications."*

- **External Scanner Integration** — Semgrep, Bandit, TruffleHog, npm audit, Safety when available.
- **Dispute Process** — `security@nomark.ai` or report page link. 48-hour response target.

**Links:** Cross-link to `/terms` and `/privacy`.

---

## 2. API Endpoints Consumed

The public site only uses **unauthenticated** registry and badge endpoints.

### 2.1 Registry API (base: `https://api.sigilsec.ai`)

**`GET /registry/search`**
```
Query params:
  q           string    Search query (package name or keyword)
  ecosystem   string?   Filter: clawhub | pypi | npm | github | mcp
  verdict     string?   Filter: LOW_RISK | MEDIUM_RISK | HIGH_RISK | CRITICAL_RISK
  page        int       Page number (>= 1)
  per_page    int       Results per page (1-100)

Response 200:
{
  "items": PublicScanSummary[],
  "total": int,
  "page": int,
  "per_page": int,
  "query": string
}
```

**`GET /registry/stats`**
```
Response 200:
{
  "total_packages": int,
  "total_scans": int,
  "threats_found": int,
  "ecosystems": { "clawhub": int, "npm": int, ... },
  "verdicts": { "LOW_RISK": int, "HIGH_RISK": int, ... }
}
```

**`GET /registry/{ecosystem}`**
```
Query: page, per_page, sort ("recent" | "risk" | "name")
Response 200: Same shape as /registry/search
```

**`GET /registry/{ecosystem}/{package_name}`**
```
Response 200: PublicScanDetail (most recent scan for this package)
Response 404: Not found
```

**`GET /registry/{ecosystem}/{package_name}/{version}`**
```
Response 200: PublicScanDetail (specific version)
Response 404: Not found
```

### 2.2 Response Models

**PublicScanSummary:**
```json
{
  "disclaimer": "Automated static analysis result. Not a security certification. Provided as-is without warranty. See sigilsec.ai/terms for full terms.",
  "id": "uuid",
  "ecosystem": "clawhub",
  "package_name": "my-skill",
  "package_version": "1.0.0",
  "risk_score": 12.5,
  "verdict": "MEDIUM_RISK",
  "findings_count": 3,
  "files_scanned": 47,
  "badge_url": "https://sigilsec.ai/badge/clawhub/my-skill.svg",
  "report_url": "https://sigilsec.ai/scans/clawhub/my-skill",
  "scanned_at": "2026-02-27T10:30:00Z"
}
```

**PublicScanDetail** (extends PublicScanSummary):
```json
{
  "disclaimer": "...",
  "id": "uuid",
  "ecosystem": "clawhub",
  "package_name": "my-skill",
  "package_version": "1.0.0",
  "risk_score": 12.5,
  "verdict": "MEDIUM_RISK",
  "findings_count": 3,
  "files_scanned": 47,
  "findings": [
    {
      "phase": "code_patterns",
      "rule": "eval-usage",
      "severity": "HIGH",
      "file": "src/main.py",
      "line": 42,
      "snippet": "eval(user_input)",
      "weight": 5.0
    }
  ],
  "metadata": {},
  "badge_url": "https://sigilsec.ai/badge/clawhub/my-skill.svg",
  "report_url": "https://sigilsec.ai/scans/clawhub/my-skill",
  "scanned_at": "2026-02-27T10:30:00Z"
}
```

**Every response includes the `disclaimer` field.** The frontend should render it or at minimum not strip it.

### 2.3 Badge Endpoints

**`GET /badge/{ecosystem}/{package_name}`** — SVG badge for the latest scan
**`GET /badge/scan/{scan_id}`** — SVG badge for a specific scan
**`GET /badge/shield/{verdict}`** — Generic static verdict badge

Badges are SVG images served with `Cache-Control: public, max-age=3600`.

Badge format: three-segment shields.io style:
```
[sigil | LOW RISK (0) | v1.2.0]
[sigil | HIGH RISK (32) | 2026-02-27]
```

- Segment 1: "sigil" (dark gray)
- Segment 2: verdict + score (colored by verdict)
- Segment 3: version (`v{version}`) or scan date (`YYYY-MM-DD`) (dark gray)

The third segment is the point-in-time indicator required by the liability spec. Without it, badges imply ongoing certification.

Badge SVG includes:
- `aria-label="Sigil automated scan result: {verdict} — not a security certification"`
- `<title>Automated scan by Sigil. This is not a security certification. Click for full report.</title>`

---

## 3. Verdict Visual System

### 3.1 Colors

| Verdict | Badge Color | Hex | Tailwind |
|---------|------------|-----|----------|
| LOW_RISK | Green | #22C55E | green-500 |
| MEDIUM_RISK | Yellow | #EAB308 | yellow-500 |
| HIGH_RISK | Orange | #F97316 | orange-500 |
| CRITICAL_RISK | Red | #EF4444 | red-500 |
| NOT_SCANNED | Gray | #6B7280 | gray-500 |

### 3.2 Labels

Always display as `LOW RISK`, `MEDIUM RISK`, `HIGH RISK`, `CRITICAL RISK`. The enum values use underscores (`LOW_RISK`) but the display text uses spaces.

### 3.3 No Certification Styling

Per the liability spec:
- No green checkmarks or shields that imply "approved" or "certified"
- No star ratings or assurance scores
- No "SAFE" labels
- No certification-style graphics (seals, stamps, certificates)

A colored dot or pill badge is fine. A green shield with a checkmark is not.

---

## 4. Language Rules

These rules apply to **every surface** — page copy, meta descriptions, OG images, alt text, tooltips, error messages, blog posts, marketing.

**Always use:**
- "Patterns consistent with malicious behaviour detected"
- "Automated analysis identified risk indicators"
- "No known malicious patterns detected at time of scanning"
- "Not a guarantee of safety"

**Never use:**
- "This package is malicious" (assert intent)
- "This package is safe" / "This package is clean" (assert safety)
- "Compromised developer" (assert intent about a person)
- "Certified" / "certification" (except in disclaimers denying it)
- "SAFE" as a label, verdict, or UI element
- Star ratings, assurance scores, trust percentages

**Rationale:** Sigil publishes verdicts against named packages by named authors. A false positive creates defamation exposure. A false negative creates liability. The language must frame everything as "automated detection of patterns" not "assertion of fact about code or people."

---

## 5. SEO / AEO Requirements

The scan database is the primary SEO/AEO surface. Each scan report page should be indexable and structured for search engines and AI assistants.

**URL structure:**
```
sigilsec.ai/scans/{ecosystem}/{package_name}
sigilsec.ai/scans/{ecosystem}/{package_name}/{version}
```

**Meta tags per report page:**
```html
<title>Sigil Scan: {package_name} ({ecosystem}) — {VERDICT}</title>
<meta name="description" content="Automated security scan of {ecosystem}/{package_name}. Verdict: {VERDICT}. Risk score: {score}. {findings_count} findings detected. This is an automated analysis, not a security certification.">
```

**Structured data (JSON-LD):** Consider `SoftwareApplication` schema with review/rating mapped to risk score. However, do NOT use `Review` schema — it implies human review. Use `TechArticle` or custom schema instead.

**Sitemap:** Generate from `/registry/search` with all scanned packages.

**robots.txt:** Allow all public scan pages. Block `/dashboard/`, `/api/` paths.

---

## 6. Footer (Global)

Every page on sigilsec.ai must include a footer with:

```
NOMARK Pty Ltd — Queensland, Australia
Terms of Service · Privacy Policy · Methodology · security@nomark.ai
```

All links functional. Contact email must be real and monitored.

---

## 7. Operational Requirements

These must be in place before launching the public scan database:

| Requirement | Why |
|------------|-----|
| `security@nomark.ai` monitored | Dispute process, removal requests, privacy rights |
| Dispute response within 48 hours | Defamation defence requires timely review capability |
| Detection rules documented internally | Evidence of methodology (not public, but must exist) |
| Scan logs stored per result | Evidence that the scan actually ran |
| Terms of Service reviewed by AU lawyer | ACL carve-out, defamation, GDPR |
| Privacy Policy reviewed by AU lawyer | GDPR legitimate interest basis |

---

## 8. Implementation Checklist

### Pages

- [ ] Landing page (`/`) — no "safe"/"clean"/"certified" language
- [ ] Public scan database (`/scans`) — with persistent banner
- [ ] Scan report page (`/scans/{eco}/{pkg}`) — with full disclaimer, badge embed, dispute link
- [ ] Versioned report page (`/scans/{eco}/{pkg}/{ver}`)
- [ ] Terms of Service (`/terms`) — all 15 clauses
- [ ] Privacy Policy (`/privacy`)
- [ ] Methodology (`/methodology`) — all 8 phases, risk scale, dispute process

### Liability Controls

- [ ] Disclaimer visible on every report page without scrolling
- [ ] Disclaimer not behind toggle/accordion
- [ ] Badge embed section includes point-in-time disclaimer
- [ ] Dispute link on every report page (`mailto:security@nomark.ai`)
- [ ] No "SAFE" labels, green checkmarks, certification graphics
- [ ] No star ratings or assurance scores
- [ ] Verdict labels use "RISK" language only (LOW RISK, not LOW)
- [ ] All meta descriptions include "automated analysis, not certification"
- [ ] Footer links to /terms, /privacy, /methodology on every page

### API Integration

- [ ] Consuming `/registry/search` for database browser
- [ ] Consuming `/registry/{eco}/{pkg}` for report pages
- [ ] Consuming `/registry/stats` for database stats
- [ ] Rendering `disclaimer` field from API responses
- [ ] Badge URLs resolve correctly to `/badge/{eco}/{pkg}`
- [ ] Report URLs match format `sigilsec.ai/scans/{eco}/{pkg}`

### Legal (Pre-Launch Blockers)

- [ ] Terms of Service at `/terms` — reviewed by external counsel
- [ ] ACL carve-out present (Section 2 of ToS)
- [ ] Algorithmic opinion clause present (Section 5 of ToS)
- [ ] Privacy Policy at `/privacy` — reviewed by external counsel
- [ ] Methodology at `/methodology` — live and accurate
- [ ] `security@nomark.ai` monitored with 48-hour SLA
- [ ] Dispute process operational

---

## 9. What Already Exists in This Repo

The `dashboard/` directory in this repo already contains implementations of:

- `/terms` page (15 clauses) — at `dashboard/src/app/terms/page.tsx`
- `/privacy` page — at `dashboard/src/app/privacy/page.tsx`
- `/methodology` page — at `dashboard/src/app/methodology/page.tsx`
- Scan detail disclaimer — at `dashboard/src/app/scans/[id]/page.tsx`
- Scans index banner — at `dashboard/src/app/scans/page.tsx`
- VerdictBadge component — at `dashboard/src/components/VerdictBadge.tsx`

These can be copied and adapted for the public site. The content (especially legal text) should be identical between the dashboard and the public site.

The API returns the `disclaimer` field on every `PublicScanSummary` and `PublicScanDetail` response. The frontend should use this field rather than hardcoding the text, so updates propagate from one place.

---

## 10. Contact

- Legal: `legal@nomark.ai`
- Security/Disputes: `security@nomark.ai`
- Product: `hello@sigilsec.ai`
