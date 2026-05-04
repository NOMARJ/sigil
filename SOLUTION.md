# SOLUTION.md
# Product Vision · Solution Intent · Strategic Roadmap

> Governed by CHARTER.md — constitutional authority over all documents.
> Methodology: NOMARK.md · Operations: CLAUDE.md
> This document answers two questions: *what exactly are we building* and *how will we build it.*
> It is the source of truth above prd.json and progress.md.

**Project:** Sigil
**Owner:** Reece Frazier
**Version:** 0.1.0
**Last updated:** 2026-03-29
**Status:** ACTIVE

---

## Document Hierarchy

```
CHARTER.md          ← constitutional layer (immutable principles, governance board)
NOMARK.md           ← methodology (THINK → PLAN → BUILD → VERIFY)
CLAUDE.md           ← operational rules (agents, models, session protocol)
SOLUTION.md         ← you are here (vision, intent, roadmap, traceability)
  └── prd.json      ← active feature scope (current sprint stories)
        └── progress.md       ← session story tracking
              └── tasks/lessons.md    ← correction rules
```

Agents read this document at session start after CLAUDE.md.
They do not modify it without owner instruction.
All roadmap changes are owner-initiated, agent-assisted.

---

## Part I — Product Vision

*Fixed. Changes require owner decision and version bump.*

### What This Is

Sigil is an automated security auditing CLI for AI agent code. It scans repos, packages, MCP servers, and installed skills for malicious patterns using an eight-phase analysis: install hooks, dangerous code patterns, network exfiltration, credential access, obfuscation, provenance, prompt injection, and skill security. It enforces a quarantine-first workflow where nothing executes until scanned and approved.

### Who It Serves

#### Human Consumers

| Principal | Need | Success Looks Like | Evidence Basis | Confidence |
|-----------|------|--------------------|----------------|------------|
| Solo developer using AI agents | Pre-installation security scanning | Catches malicious packages before they run — no manual review needed | Direct usage, open source community | HIGH |
| Security-conscious team lead | Automated scanning in CI/CD pipeline | Every dependency scanned before merge, audit trail for compliance | API + GitHub Actions integration | MED |
| Claude Code power user | MCP server for inline security scanning | `sigil scan` available as a tool inside Claude sessions | MCP server implementation | HIGH |

#### AI Agent Consumers

| Agent Type | What It Does With Our Product | What It Needs From Us | Evidence Basis | Confidence |
|-----------|------------------------------|----------------------|----------------|------------|
| Claude Code sessions | Uses sigil MCP server for inline scanning | MCP server running, structured scan results | Direct experience | HIGH |
| CI/CD pipelines | Runs sigil in non-interactive mode | CLI with exit codes, JSON output, configurable thresholds | GitHub Actions usage | MED |

#### Who Is Missing (Silence Check)

| Missing Group | Why They're Missing | Does It Matter? |
|--------------|--------------------|--------------------|
| Enterprise SOC teams | No SIEM integration yet | MED — would need log shipping, alert format standardization |
| Non-Python/Node ecosystems | Scanner rules focus on pip/npm | MED — Rust/Go/Java packages have different threat surfaces |

### What It Is Not

- Not a general-purpose SAST/DAST tool — it's specifically for AI agent supply chain security
- Not a runtime monitor — it scans before execution, not during
- Not a replacement for CVE databases — it detects behavioral patterns, not known vulnerabilities

### Strategic Alignment

- **Venture:** NOMARK (security infrastructure)
- **Revenue model:** Open source CLI, commercial API for teams, enterprise self-hosted
- **Horizon:** v1 shipped, v2 scanner migration complete (March 2026)
- **Dependencies:** Python (API), Node.js (dashboard), Rust (future CLI)

---

## Part I.5 — Insight Registry

### Insight Statements

| ID | Insight | Source | Confidence | Linked Epics |
|----|---------|--------|------------|-------------|
| INS-001 | False positive rate is the adoption killer — 36% FP rate in v1 made scanner unusable; v2 migration targeted <5% | Scanner v2 migration PR #84 | HIGH | EP-001 |
| INS-002 | Quarantine-first workflow prevents the "scan later" anti-pattern that lets malicious code run before review | Direct experience — users skip post-install scans | HIGH | EP-001 |
| INS-003 | Synthetic evaluation data presented as production data destroys trust permanently — March 14 incident | Incident report | HIGH | — |

### How Might We Questions

| ID | How Might We... | Source Insight | Consumer |
|----|----------------|---------------|----------|
| HMW-001 | Keep false positive rate below 5% as new threat patterns are added? | INS-001 | Human |
| HMW-002 | Make quarantine workflow fast enough that developers don't bypass it? | INS-002 | Human |

### DISCOVER Run Log

| Date | Scope | Method | Key Finding | Status |
|------|-------|--------|-------------|--------|
| — | — | — | — | — |

---

## Part II — Solution Intent

### Fixed Specifications

| Spec | Value | Rationale |
|------|-------|-----------|
| **CLI runtime** | Bash (current), Rust (future) | Bash for portability, Rust for performance |
| **API runtime** | Python FastAPI | Scanner rules are Python, FastAPI for async performance |
| **Dashboard** | Next.js | Team visibility, web-based management |
| **Database** | MSSQL | Owner decision — not Supabase |
| **Scan phases** | 8-phase weighted severity | Comprehensive coverage with risk-proportional scoring |
| **Governance** | CHARTER.md with immutable principles | Integrity is load-bearing |

### Variable Specifications

| Spec | Current assumption | Confidence | Open questions |
|------|-------------------|------------|----------------|
| Rust CLI timeline | Future — no date set | Low | When does bash CLI become the bottleneck? |
| MCP server protocol | Current MCP spec | Med | MCP spec may evolve |
| Forge integration | Background caching + SQL filtering | Med | Scaling with registry growth |

### Non-Functional Requirements

| NFR | Target | Current | Status |
|-----|--------|---------|--------|
| False positive rate | < 5% | < 5% (post v2 migration) | OK |
| Scan time (avg repo) | < 30 seconds | ~10-15 seconds | OK |
| CLI startup | < 2 seconds | ~1 second | OK |

### Architecture Decisions Log

| Date | Decision | Rationale | Alternatives rejected | Owner |
|------|----------|-----------|----------------------|-------|
| 2026-03-29 | MSSQL not Supabase | Owner decision | Supabase | Reece |
| 2026-03-17 | Separate sigil-infra repo | Protect sensitive subscription/deployment details | Monorepo with infra | Reece |
| 2026-03 | Scanner v2 with SQL filtering | Reduce false positives from 36% to <5% | Tuning v1 rules — too fragile | Reece |
| 2026-05-04 | 14-day Pro/Team trial via Checkout Session, gated to first-time Stripe customers (ADR-0001) | Match advertised pricing-page free-trial copy without re-creating Stripe Prices; cancel/resubscribe abuse blocked by `is_new_customer` gate | Remove trial copy (Branch A); set `recurring.trial_period_days` on the Price (Branch B, requires new Price objects) | Reece |
| 2026-05-04 | Password reset delegated to Auth0 Universal Login; legacy MSSQL-token reset flow removed (ADR-0002) | Auth0 owns identity post-migration; MSSQL `password_hash=""` made the legacy flow structurally non-functional (writes to MSSQL, login still hits Auth0) | Restore the legacy flow (would still be broken without Management API integration); add Auth0 Management API password update on top of legacy flow (Branch B in original triage) | Reece |
| 2026-05-04 | claude_service is a thin wrapper over LLMService HTTP primitive (ADR-0003) | Smallest reversible unblock for F1.7; preserves all 33 advertised Pro routes; single-file shim with `model` threaded as parameter (no global mutation, concurrency-safe); requires renaming `LLMService._call_llm_api` → `call_llm_api`; trivially swappable for Branch B (refactor) or Branch C (drop bulk routes) later | Refactor bulk_analyzer to use llm_service directly (Branch B, higher churn, awkward request-shape mapping); drop bulk-analyze routes from interactive.py (Branch C, 4 routes lost AND still requires fixing feedback_processor) | Reece |

---

## Part III — Strategic Roadmap

### Epic Registry

| ID | Epic | Status | Target | Features | Evidence |
|----|------|--------|--------|----------|----------|
| EP-001 | Scanner v2 — false positive reduction | DONE | Q1 2026 | F-001 | INS-001, PR #84 |
| EP-002 | Forge stats + registry search optimization | DONE | Q1 2026 | F-002 | Background caching, SQL filtering |
| EP-003 | Sigil Pro commercial launch | ACTIVE | Q2 2026 | F-003, F-004, F-005 | `docs/plans/2026-05-03-sigil-pro-launch-readiness-first-principles.md` |
| EP-004 | Brand & Identity System | ACTIVE | Q2 2026 | F-006 | `dashboard/public/brand/Sigil Brand Brief.html` v1.0 |

---

## Part IV — Feature Registry

---

### F-001 · Scanner v2 Migration

**Epic:** EP-001
**Status:** DONE
**Started:** 2026-03
**Shipped:** 2026-03

**What it delivers:**
Scanner false positive rate reduced from 36% to <5% through SQL-based filtering and improved pattern matching.

**Acceptance criteria (feature level):**
- [x] False positive rate < 5%
- [x] All 8 scan phases working with weighted severity
- [x] Backward compatible CLI interface

---

### F-002 · Forge Stats and Registry Search

**Epic:** EP-002
**Status:** DONE
**Started:** 2026-03
**Shipped:** 2026-03

**What it delivers:**
Optimized Forge stats and registry search with background caching and SQL filtering for improved performance.

**Acceptance criteria (feature level):**
- [x] Background caching for registry data
- [x] SQL-based filtering for search
- [x] PostHog analytics integration

---

### F-003 · Pro Billing + Tier Gating Verification

**Epic:** EP-003
**Status:** BUILT — pending end-to-end verification
**Started:** 2026-03
**Shipped:** —

**What it delivers:**
Verified, money-flowing Pro subscription path: signup → 403 on Pro endpoint → Stripe Checkout → webhook → MSSQL tier update → 200 on Pro endpoint → portal cancellation reverses access. Code paths exist (`api/routers/billing.py`, `api/gates.py`, 18 routes with `require_plan(PlanTier.PRO)`); verification loop has not been executed against live mode.

**Acceptance criteria (feature level):**
- [ ] Stripe test-mode round-trip: signup → 403 → checkout → webhook → tier flip → 200 → cancel → 403
- [ ] Stripe live-mode round-trip with one real $29 payment (refunded after)
- [ ] `stripe_price_pro` and `stripe_price_pro_annual` confirmed as live-mode Price IDs in Container Apps env
- [ ] Webhook registered in Stripe Dashboard with `customer.subscription.{created,updated,deleted}`, `invoice.{paid,payment_failed}`, `checkout.session.completed`
- [ ] Free trial behavior verified or removed from pricing page
- [ ] Stripe customer portal cancellation flips `users.subscription_tier` to `free`
- [ ] Dead `dashboard/src/app/api/billing/create-checkout/route.ts` deleted or wired to real backend

---

### F-004 · Distribution Surface

**Epic:** EP-003
**Status:** PARTIAL — pipelines merged, listings unverified
**Started:** 2026-04
**Shipped:** —

**What it delivers:**
Sigil installable from every channel a target developer would use to discover security tooling for AI agent code. Pipelines for Homebrew (NOM-29) and JetBrains Marketplace (NOM-31) are merged; listings and install paths are unverified.

**Acceptance criteria (feature level):**
- [ ] `brew install sigil` succeeds on a clean macOS machine
- [ ] JetBrains Marketplace listing is published and discoverable by name
- [ ] VS Code / Cursor / Windsurf extension status confirmed (published or explicitly deferred)
- [ ] MCP server registry/listing status confirmed
- [ ] Install instructions on sigilsec.ai resolve to working downloads/commands
- [ ] CDN cache for www.sigilsec.ai serves current build (21-day stale `age` header investigated and resolved)

---

### F-005 · Public Launch

**Epic:** EP-003
**Status:** PLANNED
**Started:** —
**Shipped:** —

**What it delivers:**
Coordinated public launch: threat report from existing 17,937-tool corpus, in-CLI upgrade trigger when SKILL.md detected (Phase 7 LLM gate), launch announcement on HN/Reddit/MCP community, post-launch soak. Distribution and billing must be verified before this feature opens.

**Acceptance criteria (feature level):**
- [ ] Threat report published from `api/data/known_threats.json` corpus with disclosed sample size and limitations (per CLAUDE.md no-fake-data rules)
- [ ] In-CLI upgrade trigger fires on SKILL.md detection during `sigil scan`
- [ ] Launch announcement post merged from `docs/internal/LAUNCH-ANNOUNCEMENT.md` to public channel
- [ ] HN/Reddit/MCP-community posts published
- [ ] 24-hour post-launch soak: error rates, webhook delivery, signup→checkout funnel reviewed; visible breakages fixed
- [ ] First paid customer (other than internal) recorded in MSSQL with active Pro tier

---

### F-006 · Brand v1.0 Rollout

**Epic:** EP-004
**Status:** ACTIVE
**Started:** 2026-05-04
**Shipped:** —

**What it delivers:**
Rolls Brand v1.0 across every Sigil surface in this repo: dashboard, CLI, API email templates, docs, and the brand brief HTML itself. Replaces blue accents with the brand greens. Unifies the verdict taxonomy on the 5-tier scale (CLEAN / LOW / MEDIUM / HIGH / CRITICAL) — the existing per-finding severity collapses cleanly into this scale (0=CLEAN, 1-9=LOW, 10-24=MEDIUM, 25-49=HIGH, 50+=CRITICAL). Enforces the strict liability stance: scrubs "Safe to install" / "Verified safe" / "Sigil guarantees" / "Malware-free" wording from product, docs, and the brand brief; replaces with attestation-only phrasing. Loads JetBrains Mono. Replaces the sidebar's hardcoded `S` letter with the Brace SVG. Points favicon at brand SVG. Adds `SealVerdict` component (gated on the four missing Seal SVG variants landing).

**Authoritative source:** the directive issued 2026-05-04 supersedes `dashboard/public/brand/Sigil Brand Brief.html` v1.0 §06 demo copy. In any conflict, the directive wins. Brief HTML must be updated to match.

**Acceptance criteria (feature level):**
- [ ] `globals.css` surface tokens match `#0A0A0A → #262626`; brand greens match (`#196C2E/#238636/#3FB950/#56D364`); verdict palette is 5-tier (`#22C55E / #EAB308 / #F97316 / #EF4444 / #DC2626`)
- [ ] `tailwind.config.ts` exposes `brand`, `surface`, and `verdict` palettes whose values match the directive
- [ ] `<head>` loads both Inter and JetBrains Mono
- [ ] Favicon resolves to `/brand/favicon/favicon.svg`
- [ ] Sidebar header renders Brace SVG, not a CSS letter
- [ ] No `#3B82F6` / `#2563EB` / `#1D4ED8` / `rgba(59,130,246,*)` remains in active code paths (`dashboard/src/`, `dashboard/tailwind.config.ts`, `api/templates/`, `bin/sigil`, `plugins/`, top-level `docs/`). Excludes `archive/`, `packs/` placeholders, third-party `docs/internal/flowbite-ui-files/`
- [ ] No "Safe to install" / "Verified safe" / "Sigil guarantees" / "Malware-free" copy remains anywhere in the repo (verified by grep)
- [ ] CLI (`bin/sigil`) banner uses the brand wordmark style; verdict words are paired with status glyphs (●/◐/○) per directive §6
- [ ] API email templates (`api/templates/email/`) use brand greens, not blue
- [ ] Brand brief HTML §06 demo copy updated: "Safe to install" → "8/8 phases passed"; verdict family expanded to 5-tier with all SVG filenames listed
- [x] `SealVerdict.tsx` exists and renders 5 Seal variants — closed via colour-instantiation of the currentcolor template; owner-authorised
- [x] `SealVerdict` mounted on scan-detail page header
- [x] Brand asset directory tracked in git ✓ (closed in commit `4c9a46b`)
