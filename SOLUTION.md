# SOLUTION.md
# Product Vision · Solution Intent · Strategic Roadmap

> Governed by CHARTER.md — constitutional authority over all documents.
> Methodology: NOMARK.md · Operations: CLAUDE.md
> This document answers two questions: *what exactly are we building* and *how will we build it.*
> It is the source of truth above prd.json and progress.md.

**Project:** Sigil  
**Owner:** Reece Frazier  
**Version:** 0.2.0  
**Last updated:** 2026-07-07  
**Status:** ACTIVE  
**Strategic position:** Trust Engine for Intelligent Systems

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

Sigil is the trust engine for intelligent systems.

It establishes whether an AI artifact, tool, skill, MCP server, package, repository, model adapter, prompt pack, workflow, or agent should be trusted before it is allowed to act — and then keeps that trust continuously verifiable after approval.

The original scanner remains the first capability. The product is no longer limited to static security scanning.

Sigil now exists to answer four questions:

1. **Can this artifact be trusted?**
2. **Why can it be trusted?**
3. **What changed after trust was granted?**
4. **What evidence supports the decision to allow, block, revoke, or monitor it?**

Security is one mechanism. Trust is the product.

### Strategic Thesis

Modern AI systems do not only execute code. They follow instructions, read documentation, call tools, invoke MCP servers, install skills, remember context, and act across connected systems.

Traditional supply-chain security asks whether code is vulnerable or malicious.

Sigil asks whether the full instruction-and-execution surface is trustworthy.

This includes:

- source code
- install hooks
- package metadata
- dependencies
- release provenance
- skill manifests
- prompt files
- external documentation
- linked domains
- MCP tool contracts
- agent permissions
- identity and publisher history
- runtime behaviour
- approval evidence
- drift after approval

The category is **AI trust infrastructure**, not generic SAST, dependency scanning, or runtime-only agent security.

### Category Positioning

**Primary positioning:** Trust Engine for Intelligent Systems  
**Developer positioning:** Quarantine-first trust for AI tools, skills, packages, repos, and MCP servers  
**Enterprise positioning:** Governed trust decisions for AI software supply chains  
**NOMARK alignment:** Trust infrastructure for non-deterministic intelligence work

### Product Promise

Sigil does not claim that software is safe.

Sigil produces evidence-backed trust decisions.

Allowed language:

- "8/8 phases passed"
- "No high-risk findings detected"
- "Approved under policy X"
- "Trusted until drift, expiry, or policy change"
- "Trust evidence attached"

Forbidden language:

- "Safe to install"
- "Verified safe"
- "Malware-free"
- "Guaranteed secure"
- "Sigil guarantees"

### Who It Serves

#### Human Consumers

| Principal | Need | Success Looks Like | Evidence Basis | Confidence |
|-----------|------|--------------------|----------------|------------|
| Solo developer using AI agents | Pre-installation trust check | Malicious or untrusted tooling is quarantined before use | Direct usage, open-source workflow | HIGH |
| Claude Code / Cursor / Windsurf power user | Scan skills, MCPs, repos, and agent tooling inline | Trust result is available inside the working loop | MCP + plugin integrations | HIGH |
| Security-conscious team lead | Policy-based trust workflow in CI/CD | Every artifact has a decision, evidence, and expiry | API + GitHub Actions integration | MED |
| Enterprise platform owner | Governed AI artifact approval | Skills, tools, MCP servers, models, and prompts are approved, monitored, revoked, and evidenced | Product direction | MED |
| SOC / GRC team | Trust evidence and auditability | Every allow/block/revoke decision can be reconstructed | Trust ledger + evidence model | MED |

#### AI Agent Consumers

| Agent Type | What It Does With Sigil | What It Needs From Sigil | Evidence Basis | Confidence |
|-----------|--------------------------|---------------------------|----------------|------------|
| Coding agents | Requests scan / trust result before cloning, installing, or invoking tools | Structured verdict, explainability, safe failure modes | Current MCP direction | HIGH |
| CI/CD agents | Blocks untrusted packages, repos, and workflows | Deterministic CLI exit codes, JSON output, policy thresholds | GitHub Actions usage | HIGH |
| Enterprise workflow agents | Requests permission to use tools, domains, secrets, and external docs | Trust certificate, permission manifest, expiry, runtime policy | Product direction | MED |

#### Who Is Missing (Silence Check)

| Missing Group | Why They're Missing | Does It Matter? |
|--------------|--------------------|--------------------|
| Enterprise SOC teams | No SIEM / SOAR integration yet | HIGH — trust decisions need log shipping and incident workflow |
| GRC / audit teams | Evidence exists but is not packaged as formal control evidence | HIGH — this is central to trust infrastructure |
| Model governance teams | Current scope is tools/artifacts, not models and model adapters | MED — future expansion path |
| Non-Python/Node ecosystems | Scanner rules focus on pip/npm and repo patterns | MED — Rust/Go/Java packages have different threat surfaces |

### What It Is Not

- Not a generic SAST/DAST tool.
- Not only a dependency scanner.
- Not a CVE database replacement.
- Not a runtime-only agent security platform.
- Not a guarantee of safety.
- Not a bypass around human accountability.

### Strategic Alignment

- **Venture:** NOMARK trust infrastructure
- **Revenue model:** Open-source CLI, commercial API for teams, enterprise trust control plane
- **Horizon:** v1 scanner shipped; v2 scanner migration complete; v3 trust engine expansion begins July 2026
- **Core dependencies:** Rust CLI, Python FastAPI, Next.js dashboard, MSSQL trust ledger, signed evidence artifacts

---

## Part I.5 — Insight Registry

### Insight Statements

| ID | Insight | Source | Confidence | Linked Epics |
|----|---------|--------|------------|-------------|
| INS-001 | False positive rate is the adoption killer — 36% FP rate in v1 made scanner unusable; v2 migration targeted <5% | Scanner v2 migration PR #84 | HIGH | EP-001 |
| INS-002 | Quarantine-first workflow prevents the "scan later" anti-pattern that lets malicious code run before review | Direct experience — users skip post-install scans | HIGH | EP-001 |
| INS-003 | Synthetic evaluation data presented as production data destroys trust permanently — March 14 incident | Incident report | HIGH | ALL |
| INS-004 | Static local scans are insufficient for AI skills because the instruction surface can live outside the artifact | Skill / external-doc attack pattern review | HIGH | EP-005, EP-006 |
| INS-005 | Approved artifacts can become untrusted after approval through documentation drift, dependency drift, domain changes, release swaps, or permission expansion | Trust-ledger and skill-security analysis | HIGH | EP-006 |
| INS-006 | Trust is broader than security: identity, provenance, behaviour, policy, evidence, and expiry all affect whether intelligence should be allowed to act | NOMARK trust thesis | HIGH | EP-005, EP-007 |

### How Might We Questions

| ID | How Might We... | Source Insight | Consumer |
|----|----------------|---------------|----------|
| HMW-001 | Keep false positive rate below 5% as new threat patterns are added? | INS-001 | Human |
| HMW-002 | Make quarantine workflow fast enough that developers don't bypass it? | INS-002 | Human |
| HMW-003 | Seal the full instruction surface of a skill, not just local files? | INS-004 | Human + Agent |
| HMW-004 | Detect when a previously approved artifact becomes untrustworthy? | INS-005 | Enterprise |
| HMW-005 | Produce audit-ready evidence for every trust decision? | INS-006 | SOC / GRC |

### DISCOVER Run Log

| Date | Scope | Method | Key Finding | Status |
|------|-------|--------|-------------|--------|
| 2026-07-07 | Sigil repositioning | Product strategy review | Scanner becomes a capability; Trust Engine becomes the product | ACTIVE |

---

## Part II — Solution Intent

### Fixed Specifications

| Spec | Value | Rationale |
|------|-------|-----------|
| **Product class** | Trust engine for intelligent systems | Expands scanner into a durable infrastructure category |
| **CLI runtime** | Rust primary, Bash compatibility wrapper where needed | Rust is the single detection engine direction and supports reliable distribution |
| **API runtime** | Python FastAPI | Existing API surface and async service model |
| **Dashboard** | Next.js | Team visibility, evidence review, trust graph, approvals |
| **Database** | MSSQL | Owner decision — not Supabase |
| **Trust model** | Multidimensional score + evidence-backed verdict | Trust cannot collapse to one static malware score |
| **Governance** | CHARTER.md with immutable principles | Integrity is load-bearing |
| **Safety language** | Attestation-only, no guarantee phrasing | Avoids false assurance and liability leakage |

### Variable Specifications

| Spec | Current assumption | Confidence | Open questions |
|------|-------------------|------------|----------------|
| Runtime enforcement | Phase 2 after seal/watch | MED | Local shim, MCP proxy, endpoint agent, or cloud control plane? |
| Trust graph storage | MSSQL first; graph abstraction in service layer | MED | Do we need a native graph DB later? |
| Domain intelligence | Start with DNS/WHOIS/TLS/redirect metadata | MED | Which external enrichment providers are acceptable? |
| MCP permission manifest | Sigil-defined schema first | MED | Align to emerging MCP permission standards if they stabilize |
| Enterprise evidence export | JSON + markdown first | HIGH | Later: SOC2/ISO/AuditBoard/Jira/GRC mappings |

### Trust Dimensions

Every artifact receives a trust profile across dimensions.

| Dimension | Question | Example Signals |
|----------|----------|-----------------|
| Identity | Who created or published this? | verified org, signing key, maintainer history, namespace ownership |
| Provenance | Where did it come from and how was it built? | git history, release tags, SBOM, SLSA, reproducible build, package registry metadata |
| Behaviour | What does it do or request? | shell, network, filesystem, secrets, browser, email, calendar, cloud access |
| Intent | Do claims match behaviour? | README vs code mismatch, skill description vs tool permissions |
| Instruction Surface | What instructions can the agent read or follow? | SKILL.md, prompt files, README, docs, external URLs, redirects |
| Reputation | What does the ecosystem know about it? | age, downloads, stars, forks, issue history, maintainer churn |
| Policy | Is it allowed in this organisation? | allowed registries, denied domains, required review, expiry rules |
| Evidence | Can the decision be reconstructed? | findings, hashes, snapshots, reviewer, timestamp, policy version |
| Drift | Has anything changed since approval? | content hash, DNS, TLS, dependency, release, docs, permissions |

### Trust Verdicts

Sigil keeps the existing verdict language but upgrades the semantics.

| Verdict | Meaning | Default Action |
|--------|---------|----------------|
| CLEAN | No material findings under active policy | Allow or auto-approve if configured |
| LOW | Minor findings or incomplete metadata | Allow with review |
| MEDIUM | Meaningful uncertainty or dual-use behaviour | Manual review required |
| HIGH | Strong risk indicators or policy violation | Block unless explicitly overridden |
| CRITICAL | Malicious, exfiltrating, deceptive, or non-overridable policy breach | Block, no override by default |
| UNTRUSTED | Trust cannot be established due to missing evidence, unreachable instruction surface, drift, or identity failure | Block until resolved |
| EXPIRED | Prior approval is past validity window | Re-scan and re-approve |
| REVOKED | Previously trusted artifact is no longer trusted | Block and alert |

### Non-Functional Requirements

| NFR | Target | Current | Status |
|-----|--------|---------|--------|
| False positive rate | < 5% on declared eval corpus | < 5% post v2 migration; later eval showed residual FP on dual-use patterns | WATCH |
| Scan time (avg repo) | < 30 seconds | ~10-15 seconds | OK |
| CLI startup | < 2 seconds | ~1 second | OK |
| Trust certificate generation | < 5 seconds after scan result | Not built | NEW |
| External instruction snapshot | < 60 seconds for normal skill docs | Not built | NEW |
| Trust drift detection | Daily watch for approved artifacts | Not built | NEW |
| Evidence reproducibility | 100% of approvals reconstructable from stored evidence | Partial via ledger | NEW |

### Architecture Decisions Log

| Date | Decision | Rationale | Alternatives rejected | Owner |
|------|----------|-----------|----------------------|-------|
| 2026-03-29 | MSSQL not Supabase | Owner decision | Supabase | Reece |
| 2026-03-17 | Separate sigil-infra repo | Protect sensitive subscription/deployment details | Monorepo with infra | Reece |
| 2026-03 | Scanner v2 with SQL filtering | Reduce false positives from 36% to <5% | Tuning v1 rules — too fragile | Reece |
| 2026-05-04 | 14-day Pro/Team trial via Checkout Session, gated to first-time Stripe customers (ADR-0001) | Match advertised pricing-page free-trial copy without re-creating Stripe Prices; cancel/resubscribe abuse blocked by `is_new_customer` gate | Remove trial copy; set `recurring.trial_period_days` on the Price | Reece |
| 2026-05-04 | Password reset delegated to Auth0 Universal Login; legacy MSSQL-token reset flow removed (ADR-0002) | Auth0 owns identity post-migration | Restore legacy flow; add Auth0 Management API on top of legacy flow | Reece |
| 2026-05-04 | claude_service is a thin wrapper over LLMService HTTP primitive (ADR-0003) | Smallest reversible unblock for F1.7 | Larger refactor; dropping routes | Reece |
| 2026-07-07 | Sigil repositioned from scanner to Trust Engine | Scanner is a feature; trust establishment, evidence, drift, and governance are the product | Compete as generic AI security scanner | Reece |
| 2026-07-07 | Instruction surface becomes first-class scan target | AI artifacts can delegate behaviour to external docs, prompts, and URLs after approval | Scan only local files | Reece |
| 2026-07-07 | Trust decisions require expiry, evidence, and drift rules | Approval without expiry becomes stale trust | Permanent allowlist | Reece |

---

## Part II.5 — Target Architecture

### Conceptual Model

Everything Sigil evaluates is a trust entity.

```
Publisher
  owns Repository
    publishes Release
      contains Package
        installs Hook
        declares Dependency
        bundles Skill
          references Prompt
          references External URL
          requests Tool Permission
        exposes MCP Server
          exposes Tool
          requests Secret
          calls Domain
```

The Trust Engine builds and evaluates this graph.

### Core Domain Entities

| Entity | Description | Required Fields |
|--------|-------------|-----------------|
| TrustSubject | Thing being evaluated | type, locator, digest, source, version |
| TrustFinding | Evidence item discovered during analysis | rule_id, severity, phase, path/url, explanation |
| TrustSignal | Non-finding signal used in scoring | dimension, value, source, confidence |
| TrustDecision | Allow/block/revoke/monitor decision | subject, verdict, policy, evidence, reviewer, expiry |
| TrustCertificate | Signed decision artifact | subject digest, score, verdict, evidence hash, signature |
| TrustPolicy | Organisation or user rules | thresholds, allowed behaviours, denied behaviours, expiry |
| InstructionSurface | All instructions an agent may read/follow | local files, external URLs, redirects, prompt text, docs |
| ContentPin | Immutable approved content hash | digest, source, timestamp, approved_by |
| DriftEvent | Difference detected after approval | subject, old hash, new hash, impact, action |
| PermissionRequest | Capability requested by an artifact or agent | capability, scope, reason, default action |

### Trust Pipeline

```
Acquire
  → Quarantine
  → Enumerate subjects
  → Build instruction surface
  → Resolve external references
  → Hash and snapshot
  → Static scan
  → Provenance analysis
  → Behaviour analysis
  → Policy evaluation
  → Trust score
  → Decision
  → Certificate
  → Watch
  → Revoke / renew / retain
```

### Product Modules

| Module | Purpose | Status |
|--------|---------|--------|
| Sigil Scan | Static scanning of repos, packages, MCPs, skills, files | EXISTS |
| Sigil Verify | Identity, publisher, provenance, signing, registry verification | NEW |
| Sigil Seal | Immutable approval certificate over content + instruction surface | NEW |
| Sigil Watch | Continuous drift monitoring for approved artifacts | NEW |
| Sigil Policy | Organisation/user trust policy enforcement | PARTIAL |
| Sigil Runtime | Runtime capability enforcement and agent permission guardrails | FUTURE |
| Sigil Graph | Trust entity graph and relationship analysis | NEW |
| Sigil Evidence | Exportable evidence packs for decisions, audits, and incidents | PARTIAL |
| Sigil Intelligence | LLM-assisted FP adjudication, explanation, attack-chain narrative | PLANNED |

---

## Part III — Strategic Roadmap

### Epic Registry

| ID | Epic | Status | Target | Features | Evidence |
|----|------|--------|--------|----------|----------|
| EP-001 | Scanner v2 — false positive reduction | DONE | Q1 2026 | F-001 | INS-001, PR #84 |
| EP-002 | Forge stats + registry search optimization | DONE | Q1 2026 | F-002 | Background caching, SQL filtering |
| EP-003 | Sigil Pro commercial launch | ACTIVE | Q2 2026 | F-003, F-004, F-005, F-007, F-009, F-010 | `docs/plans/2026-05-03-sigil-pro-launch-readiness-first-principles.md` |
| EP-004 | Brand & Identity System | ACTIVE | Q2 2026 | F-006 | `dashboard/public/brand/Sigil Brand Brief.html` v1.0 |
| EP-005 | Trust Engine Foundation | PLANNED | Q3 2026 | F-011, F-012, F-013 | This document v0.2.0 |
| EP-006 | Instruction Surface Sealing + Drift Watch | PLANNED | Q3 2026 | F-014, F-015, F-016 | INS-004, INS-005 |
| EP-007 | Enterprise Trust Control Plane | PLANNED | Q4 2026 | F-017, F-018, F-019 | NOMARK trust infrastructure thesis |
| EP-008 | Runtime Trust Enforcement | FUTURE | 2027 | F-020, F-021 | Requires EP-005/006 |

### Roadmap Sequence

1. Finish launch blockers and commercial verification.
2. Stabilize scanner and Pro explanation layer.
3. Add TrustSubject / TrustDecision / TrustCertificate primitives.
4. Seal full instruction surface for skills and MCPs.
5. Add watch mode for approved artifacts and external resources.
6. Add enterprise policy and evidence export.
7. Add runtime permission enforcement.

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
Sigil installable from every channel a target developer would use to discover security tooling for AI agent code. Pipelines for Homebrew and JetBrains Marketplace are merged; listings and install paths are unverified.

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
Coordinated public launch: threat report from existing corpus, in-CLI upgrade trigger when SKILL.md detected, launch announcement on HN/Reddit/MCP community, post-launch soak. Distribution and billing must be verified before this feature opens.

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
Rolls Brand v1.0 across every Sigil surface in this repo: dashboard, CLI, API email templates, docs, and the brand brief HTML itself. Replaces blue accents with the brand greens. Unifies the verdict taxonomy on the 5-tier scale (CLEAN / LOW / MEDIUM / HIGH / CRITICAL). Enforces strict liability stance: scrubs "Safe to install" / "Verified safe" / "Sigil guarantees" / "Malware-free" wording and replaces with attestation-only phrasing.

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

---

### F-007 · Launch Readiness Remediation

**Epic:** EP-003  
**Status:** IN PROGRESS (agent-buildable subset complete 2026-06-08; gated stories pending)  
**Started:** 2026-06-08  
**Shipped:** —

**Source:** `docs/launch-readiness-report.md` (2026-06-08, verdict: NOT READY)

**What it delivers:**  
Launch-gate umbrella that closes blockers in the 2026-06-08 launch-readiness report so the public-launch verdict can move from NOT READY to READY. F-007 is a tracker over remediation, not a clean-slate build.

**Acceptance criteria (feature level):**
- [ ] CRITICAL-001: `curl -I https://app.sigilsec.ai/signup` resolves to a working signup entry (200 or intentional 302 to Auth0 signup), owner-approved auth-flow change (owner-gated)
- [ ] CRITICAL-002: pricing page matches billing API (Team $99, trial copy reconciled) — closed via F-003 STORY-107/111/112 (cross-ref)
- [ ] CRITICAL-003: `curl https://www.sigilsec.ai/install.sh` serves the real installer, not the private-development copy — closed via F-004 + CDN fresh-deploy root cause (cross-ref)
- [ ] CRITICAL-004: `python3 -m pytest api/tests -q` exits 0 (or all residual failures are owner-accepted, documented protected-scope items with evidence)
- [ ] HIGH-001: `cd dashboard && npm audit --audit-level=high --omit=dev` exits 0 after a planned Next.js upgrade (operator-gated)
- [x] HIGH-002: Rust CLI is verifiable — `cargo test` passes in CI. Evidence: `evidence/launch-readiness/US-009-rust-verification.md`
- [ ] Launch-readiness report re-run shows verdict READY with refreshed evidence

---

### F-009 · Sigil Pro Tier + Fable Integration

**Epic:** EP-003  
**Status:** PLANNED (owner-approved 2026-06-11; PRD `tasks/prd-sigil-pro-fable.json`)  
**Started:** —  
**Shipped:** —

**What it delivers:**  
Modernized Anthropic-only LLM layer powering Pro-gated AI analysis: false-positive adjudication, finding triage/explanation/remediation, attack-chain narratives, and a `sigil explain` CLI surface. Gating: free tier gets a small monthly credit allowance; Pro gets full access with fair-use metering on existing credit/tier infrastructure.

**Acceptance criteria (feature level):**
- [ ] No retired or non-Anthropic model ID remains in active LLM code paths (`grep -rn "gpt-4\|claude-3-" api/services/ api/llm_config.py` clean, excluding comments/tests-as-fixtures)
- [ ] A refusal (`stop_reason: "refusal"`) on Fable 5 is handled and retried on `claude-opus-4-8` — proven by unit test with mocked refusal response
- [ ] FP adjudication measurably reduces FP@High on the F-008 eval corpus with recall held — real measurement, disclosed sample size and limitations, no fabricated metrics
- [ ] Free tier exhausts its credit allowance → 402/upgrade path; Pro tier passes — proven by tier-gating tests
- [ ] `sigil explain` (Rust CLI) returns an LLM explanation for a finding via the API, with a clear auth/upgrade error for free-tier exhaustion
- [ ] LLM usage is metered per user and visible via the existing usage-stats path
- [ ] Capability-minimal constraint holds: LLM calls are opt-in, outbound only to the configured LLM API, and finding content sent is disclosed in docs

---

### F-010 · Trust-Ledger Allowlisting

**Epic:** EP-003  
**Status:** DONE (evidence: `.nomark/evidence/F-010-trust-ledger-allowlisting-complete.md`)  
**Started:** 2026-06-11  
**Shipped:** 2026-06-11

**What it delivers:**  
Scan-time suppression of findings for ledger-approved known-good packages. When scanned content exactly matches an approved `ContentPin.artifact_digest`, findings are marked `suppressed_by` and excluded from score/verdict. Drifted content is never suppressed.

**Acceptance criteria (feature level):**
- [x] Digest-matched approved content → findings suppressed from score/verdict, visible in JSON output with result-level `suppressed_by` attribution
- [x] Drifted content never suppressed; RUGPULL-001 unaffected
- [x] `--ignore-ledger` restores unsuppressed behavior
- [x] Eval `--ledger-warm`: recall per-sample identical cold vs warm; warm control FP 0% at every threshold; TRUE-BY-CONSTRUCTION disclosure in report
- [x] `cd cli && cargo test` green — 129/129 (2026-06-11)

---

### F-011 · Trust Engine Domain Model

**Epic:** EP-005  
**Status:** PLANNED  
**Started:** —  
**Shipped:** —

**What it delivers:**  
Introduces first-class trust entities across CLI, API, DB, and dashboard: `TrustSubject`, `TrustFinding`, `TrustSignal`, `TrustDecision`, `TrustCertificate`, `TrustPolicy`, `InstructionSurface`, `ContentPin`, `DriftEvent`, and `PermissionRequest`.

This is the foundation that turns Sigil from a scanner into a trust engine.

**Technical work:**
- [ ] Add DB schema migrations for trust entities and relationships
- [ ] Add API models/schemas for trust subjects, decisions, certificates, and evidence
- [ ] Update CLI JSON output to include `trust_subject`, `trust_profile`, and `decision_id`
- [ ] Backfill existing scan results into the new trust-subject structure where possible
- [ ] Add dashboard trust-subject detail page
- [ ] Add tests proving existing scan output remains backward compatible or has a documented version bump

**Acceptance criteria (feature level):**
- [ ] Every scan result creates or references a `TrustSubject`
- [ ] Every approval creates a `TrustDecision`
- [ ] Every decision records policy version, evidence hash, reviewer/actor, timestamp, expiry, and subject digest
- [ ] CLI `--json` exposes the new trust fields without breaking existing consumers unless versioned
- [ ] Dashboard can show a subject, findings, decision history, and current trust state

---

### F-012 · Trust Certificate Generation

**Epic:** EP-005  
**Status:** PLANNED  
**Started:** —  
**Shipped:** —

**What it delivers:**  
A signed, exportable trust certificate for each approval or block decision.

A certificate states what was evaluated, what evidence was used, which policy was applied, what decision was made, who/what made it, when it expires, and what invalidates it.

**Technical work:**
- [ ] Define certificate JSON schema
- [ ] Add local CLI certificate generation for offline scan/approve flows
- [ ] Add API certificate generation for authenticated team flows
- [ ] Sign certificates with configured signing key
- [ ] Store certificate hash in MSSQL
- [ ] Add `sigil cert show`, `sigil cert verify`, and `sigil cert export`
- [ ] Add dashboard certificate view and export

**Acceptance criteria (feature level):**
- [ ] Certificate verification fails if content digest, policy hash, evidence hash, or signature changes
- [ ] Certificate includes expiry and revocation status
- [ ] Certificate can be exported as JSON and markdown
- [ ] Certificate avoids guarantee language and uses attestation-only wording

---

### F-013 · Multidimensional Trust Score

**Epic:** EP-005  
**Status:** PLANNED  
**Started:** —  
**Shipped:** —

**What it delivers:**  
Replaces single weighted severity as the only decision signal with a multidimensional trust profile across identity, provenance, behaviour, intent, instruction surface, reputation, policy, evidence, and drift.

**Technical work:**
- [ ] Add trust-dimension scoring schema
- [ ] Map existing scanner phases into dimensions
- [ ] Add explicit uncertainty scoring for missing evidence
- [ ] Add `UNTRUSTED`, `EXPIRED`, and `REVOKED` trust states
- [ ] Update CLI and dashboard to show dimension-level scores
- [ ] Add policy thresholds by dimension

**Acceptance criteria (feature level):**
- [ ] A clean local scan can still be `UNTRUSTED` if identity/provenance/instruction evidence is missing under strict policy
- [ ] Dimension scores are explainable and trace to evidence
- [ ] Policy can block one dimension even when aggregate score is acceptable
- [ ] Existing 5-tier verdicts remain usable for simple users

---

### F-014 · Instruction Surface Scanner

**Epic:** EP-006  
**Status:** PLANNED  
**Started:** —  
**Shipped:** —

**What it delivers:**  
Scans the full instruction surface of AI artifacts, not just local code. Applies especially to skills, MCP servers, prompt packs, agent plugins, and repos that route users or agents to external docs.

**Technical work:**
- [ ] Detect instruction-bearing files: `SKILL.md`, `README.md`, prompts, rules, agents, MCP manifests, plugin manifests, docs directories
- [ ] Extract external URLs from instruction-bearing files
- [ ] Resolve redirects and canonical URLs
- [ ] Fetch external docs in quarantine
- [ ] Hash and store external content snapshots
- [ ] Detect risky instruction language: role override, hidden instruction, tool coercion, external execution, secret request, unverifiable claim
- [ ] Add config for offline mode and denied external fetches
- [ ] Add CLI output section for instruction surface coverage

**Acceptance criteria (feature level):**
- [ ] A skill with a clean `SKILL.md` but risky external docs is not marked clean
- [ ] A skill that requires the agent to follow external docs is at least MEDIUM unless the docs are fetched, hashed, and policy-approved
- [ ] Redirect chains and unreachable docs are captured as evidence
- [ ] External content is never executed during scan
- [ ] All fetched external docs are stored as content pins or evidence artifacts

---

### F-015 · Sigil Seal

**Epic:** EP-006  
**Status:** PLANNED  
**Started:** —  
**Shipped:** —

**What it delivers:**  
Creates immutable approval over the complete artifact plus its instruction surface. Seal binds local files, external docs, dependency lockfiles, permission manifest, policy, and evidence into one trust certificate.

**Technical work:**
- [ ] Add `sigil seal <path|url|package>` command
- [ ] Generate manifest of all local and external content included in the seal
- [ ] Store seal manifest and hash in ledger
- [ ] Add seal invalidation rules: content drift, external-doc drift, dependency drift, permission expansion, policy change, expiry
- [ ] Add dashboard seal view
- [ ] Add `sigil verify-seal` command

**Acceptance criteria (feature level):**
- [ ] Re-running `verify-seal` passes when all content and policy inputs are unchanged
- [ ] Re-running `verify-seal` fails when any sealed external doc changes
- [ ] Seal manifest clearly lists what is and is not covered
- [ ] Seal does not imply safety; it attests that approved content matches sealed evidence

---

### F-016 · Sigil Watch

**Epic:** EP-006  
**Status:** PLANNED  
**Started:** —  
**Shipped:** —

**What it delivers:**  
Continuous trust monitoring for approved artifacts.

Watches approved repos, packages, releases, external docs, linked domains, DNS, TLS certificates, redirects, dependency metadata, and permission manifests for drift after approval.

**Technical work:**
- [ ] Add watch registry for approved subjects and sealed instruction surfaces
- [ ] Add scheduled worker for drift checks
- [ ] Add drift event model and API endpoints
- [ ] Add CLI `sigil watch`, `sigil drift`, `sigil revoke`, `sigil renew`
- [ ] Add dashboard drift inbox
- [ ] Add notification hooks for email/webhook/SIEM later
- [ ] Add policy-driven automatic revoke or require-review behaviour

**Acceptance criteria (feature level):**
- [ ] Approved artifact changing content creates a drift event
- [ ] External doc hash change creates a drift event
- [ ] Domain redirect or ownership metadata change creates a review event where detectable
- [ ] Critical drift can revoke trust automatically under policy
- [ ] Watch mode never silently updates an approved seal

---

### F-017 · Enterprise Trust Policy

**Epic:** EP-007  
**Status:** PLANNED  
**Started:** —  
**Shipped:** —

**What it delivers:**  
Organisation-level policies that define what intelligent systems may trust.

**Technical work:**
- [ ] Add policy schema with allow/deny/review rules
- [ ] Add policy versioning and hash
- [ ] Add default policies: Solo, Team, Enterprise Strict, Offline, Regulated
- [ ] Add per-dimension thresholds
- [ ] Add expiry rules by artifact type
- [ ] Add reviewer requirements for high-risk approvals
- [ ] Add policy simulation mode

**Acceptance criteria (feature level):**
- [ ] Policy hash is recorded on every trust decision
- [ ] Changing policy can expire or revoke prior decisions
- [ ] Strict policy can block missing provenance even with no code findings
- [ ] Policy simulation shows what would change before enforcement

---

### F-018 · Evidence Pack Export

**Epic:** EP-007  
**Status:** PLANNED  
**Started:** —  
**Shipped:** —

**What it delivers:**  
Audit-ready evidence packs for security review, procurement, vendor onboarding, incident response, and compliance.

**Technical work:**
- [ ] Add evidence-pack JSON schema
- [ ] Add markdown export
- [ ] Include subject, policy, findings, signals, screenshots/metadata where applicable, hashes, certificate, decision, expiry, drift history
- [ ] Add dashboard export action
- [ ] Add CLI `sigil evidence export <decision_id|subject>`

**Acceptance criteria (feature level):**
- [ ] Evidence pack reconstructs why a decision was made
- [ ] Evidence pack can be verified against certificate hashes
- [ ] Evidence pack labels unknowns and unavailable external resources explicitly
- [ ] Evidence pack contains no fabricated metrics or unsupported safety claims

---

### F-019 · Trust Graph UI

**Epic:** EP-007  
**Status:** PLANNED  
**Started:** —  
**Shipped:** —

**What it delivers:**  
Visual trust graph showing how publishers, repos, packages, skills, MCP servers, external docs, domains, permissions, decisions, and drift events connect.

**Technical work:**
- [ ] Add API graph endpoint for trust-subject relationships
- [ ] Add dashboard graph view
- [ ] Add filters by artifact type, verdict, policy, expiry, and drift
- [ ] Add graph evidence drawer
- [ ] Add risk path explanation: why a subject became high-risk or untrusted

**Acceptance criteria (feature level):**
- [ ] User can trace from a skill to every external instruction URL it relies on
- [ ] User can trace from a domain to all approved artifacts referencing it
- [ ] User can trace from a revoked subject to affected approvals
- [ ] Graph data matches ledger data, not a separate unverified model

---

### F-020 · Runtime Permission Guard

**Epic:** EP-008  
**Status:** FUTURE  
**Started:** —  
**Shipped:** —

**What it delivers:**  
Runtime enforcement layer that blocks or prompts when an agent attempts a capability outside its approved trust certificate or permission manifest.

**Technical work:**
- [ ] Define permission model: filesystem, network, shell, package install, browser, email, calendar, database, cloud, secrets
- [ ] Add local policy proxy/shim investigation
- [ ] Add MCP tool proxy investigation
- [ ] Add runtime event logging
- [ ] Add block/warn/allow modes
- [ ] Add enterprise policy integration

**Acceptance criteria (feature level):**
- [ ] Agent execution of unapproved shell/network/package commands can be blocked in supported integration mode
- [ ] Runtime events attach to trust subject and decision where possible
- [ ] Runtime block reasons are explainable to the user
- [ ] Runtime mode fails closed under strict policy

---

### F-021 · Agent Trust Attestation

**Epic:** EP-008  
**Status:** FUTURE  
**Started:** —  
**Shipped:** —

**What it delivers:**  
Agent-level attestation: what agent acted, under what identity, with what approved tools, under what policy, and with what evidence.

**Technical work:**
- [ ] Define agent identity model
- [ ] Bind agent sessions to trust policy and approved tools
- [ ] Record agent decisions and tool-use evidence
- [ ] Integrate with NOMARK Decision ontology where available
- [ ] Add audit export for agent actions

**Acceptance criteria (feature level):**
- [ ] Agent action can be linked to approved trust subject and policy
- [ ] Tool use outside approval creates policy event
- [ ] Agent attestation can be exported as evidence
- [ ] Decision linkage is explicit where implemented and labelled absent where not

---

## Part V — Implementation Workstreams

### Workstream A — Keep Launch Path Honest

Do not let Trust Engine expansion mask launch blockers.

Immediate work remains:

- F-003 billing verification
- F-004 distribution verification
- F-007 launch readiness remediation
- F-009 Pro explanation layer
- F-010 ledger already shipped

### Workstream B — Trust Primitives

Build the minimum durable substrate:

1. TrustSubject
2. TrustDecision
3. TrustCertificate
4. TrustPolicy
5. Evidence hash
6. Expiry/revoke semantics

No graph UI before this exists.

### Workstream C — Instruction Surface

This is the strategic wedge.

Priority order:

1. `SKILL.md` detection
2. local prompt/docs extraction
3. external URL extraction
4. external doc fetch/hash/snapshot
5. risky instruction detection
6. seal generation
7. drift watch

### Workstream D — Evidence and Governance

Every trust decision needs evidence.

Build:

- evidence pack export
- policy hash
- decision reason
- reviewer/actor
- expiry
- revocation history
- explicit unknowns

### Workstream E — Enterprise Control Plane

Only after A-D have enough substance:

- policy management
- team approvals
- dashboard graph
- SIEM/webhook integrations
- SSO/org roles
- procurement/audit evidence exports

---

## Part VI — Operating Rules

### Rules for Agents Working This Repo

1. Do not describe Sigil as guaranteeing safety.
2. Do not fabricate scan metrics, threat counts, customer counts, performance numbers, or corpus sizes.
3. Preserve launch blockers until verified with evidence.
4. Treat trust decisions as governed decisions, not marketing copy.
5. Every new trust feature must include evidence, expiry, and revocation semantics.
6. Every external fetch must be quarantined and non-executing.
7. Every approval path must be auditable.
8. If evidence is missing, label it missing. Do not infer.

### Technical Priorities

| Priority | Work | Why |
|----------|------|-----|
| P0 | Do not regress scanner, CLI, billing, or launch readiness | Existing product still needs to ship |
| P1 | TrustSubject / TrustDecision / TrustCertificate | Foundation for trust engine |
| P1 | Instruction surface scanner | Differentiated AI-specific trust wedge |
| P1 | Seal and drift detection | Converts static approval into continuous trust |
| P2 | Policy engine | Enterprise control layer |
| P2 | Evidence export | GRC/SOC value |
| P3 | Runtime guard | Strong future moat, but only after trust substrate exists |

---

## Part VII — Success Metrics

Metrics must be real, sourced, and reproducible.

| Metric | Target | Evidence Required |
|--------|--------|------------------|
| Scanner FP rate | < 5% on declared corpus, or openly disclosed if not met | Eval report with corpus size and method |
| Trust certificate coverage | 100% of approvals produce certificate | DB + CLI/API tests |
| Instruction surface coverage | 100% of detected skill files include local + external instruction inventory | Fixture tests |
| External doc drift detection | Change detected within configured watch interval | Watcher tests |
| Evidence reconstruction | 100% of decisions reconstructable from evidence pack | E2E tests |
| Launch readiness | READY verdict only after blocker evidence | Updated launch-readiness report |

---

## Part VIII — Strategic Summary

Sigil started as a scanner.

Sigil becomes the trust engine.

The scanner asks:

> Is this suspicious?

The trust engine asks:

> Should this intelligent system be allowed to act, under what policy, with what evidence, for how long, and what happens if anything changes?

That is the product.
