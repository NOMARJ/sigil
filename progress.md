# Sigil — OpenShell-Inspired Features

> **Source:** `docs/OPENSHELL-RESEARCH.md`
> **Branch:** `claude/sigil-openshell-research-pxLv2`
> **Started:** 2026-04-02

---

## Phase 1: Policy Foundation & Scanner Enhancements

### STORY-001: Define Sigil Policy YAML Schema
- **Status:** DONE ✅
- **Goal:** Design and document the declarative YAML policy format for Sigil sandbox enforcement
- **Done when:** A `SigilPolicy` struct exists in `cli/src/policy/mod.rs` that deserializes a YAML policy file with filesystem (read_only, read_write paths), network (allowed endpoints with host/port/access), process (run_as_user, allowed_syscalls), and credential (allowed_env_vars) sections. Unit tests validate parsing of a sample policy YAML.
- **Files:** `cli/src/policy/mod.rs` (new), `cli/src/policy/schema.rs` (new), `docs/policy-schema.md` (new)
- **Notes:** Inspired by OpenShell's static/dynamic policy split. Keep filesystem+process immutable, network hot-reloadable. Use `serde` + `serde_yaml` for deserialization. Add `serde_yaml` to Cargo.toml.

### STORY-002: `sigil policy generate` — Auto-Generate Policies from Scan Results
- **Status:** DONE ✅
- **Goal:** Add a CLI command that runs a scan and translates findings into a recommended policy YAML
- **Done when:** `sigil policy generate <path>` outputs a valid policy YAML to stdout (or `--output file.yaml`). Phase 3 findings → network deny rules, Phase 4 → credential restrictions, Phase 1 → filesystem lockdowns. The generated policy is parseable by the schema from STORY-001.
- **Files:** `cli/src/main.rs` (add Policy subcommand), `cli/src/policy/generate.rs` (new)
- **Notes:** Depends on STORY-001. Maps each phase's findings to the corresponding policy section. Start with conservative defaults (deny-all network, minimal filesystem access).

### STORY-003: Add Phase 10 — Inference Security Detection (Rust CLI)
- **Status:** DONE ✅
- **Goal:** Add a new scan phase that detects LLM API misuse patterns (hardcoded endpoints, secrets in prompts, credential injection in model clients)
- **Done when:** `Phase::InferenceSecurity` variant added to enum, detection patterns implemented in `phases.rs`, at least 5 rules covering: hardcoded non-standard base_url in OpenAI/Anthropic clients, env vars interpolated into prompt strings, API key overrides in client config, model endpoint redirection, prompt exfiltration via custom endpoints. Self-scan of test fixtures validates detection.
- **Files:** `cli/src/scanner/mod.rs` (add phase variant), `cli/src/scanner/phases.rs` (add rules), `cli/src/scanner/scoring.rs` (add weight — 5x)
- **Notes:** Inspired by OpenShell's Privacy Router concept. This is static detection of the patterns that a runtime inference router would catch. Weight 5x (High) aligned with Code Patterns phase.

### STORY-004: Add Phases 7-8 to Rust CLI (Prompt Injection & Skill Security)
- **Status:** DONE ✅
- **Goal:** Port Phases 7 (Prompt Injection, 10x) and 8 (Skill Security, 5x) from the API/bash scanner into the Rust CLI
- **Done when:** `Phase::PromptInjection` and `Phase::SkillSecurity` variants exist, detection patterns from `api/services/scanner.py` and `api/services/prompt_scanner.py` are ported, scoring weights match (10x and 5x). Rust CLI `sigil scan` reports findings from all 8 phases.
- **Files:** `cli/src/scanner/mod.rs`, `cli/src/scanner/phases.rs`, `cli/src/scanner/scoring.rs`
- **Notes:** These phases already exist in the Python API but not in Rust. Port patterns, not the full Python logic. Prerequisite for complete policy generation (Phase 7 findings inform inference policy).

---

## Phase 2: Runtime Enforcement

### STORY-005: `sigil run` — Sandboxed Execution with Policy Enforcement
- **Status:** DONE ✅
- **Goal:** Add a `sigil run --policy <file> -- <command>` command that executes a command inside an isolated environment with policy enforcement
- **Done when:** Command launches a Docker/Podman container with: filesystem mounts restricted to policy read_only/read_write paths, network egress filtered to allowed endpoints (using container networking), only specified env vars passed through. Exit code of the inner command is propagated. Works with `sigil run --policy strict -- python agent.py`.
- **Files:** `cli/src/main.rs` (add Run subcommand), `cli/src/sandbox/mod.rs` (new), `cli/src/sandbox/container.rs` (new)
- **Notes:** Depends on STORY-001. Start with Docker as the runtime (most widely available). Use `std::process::Command` to invoke `docker run` with appropriate flags. Built-in policy presets: `strict` (no network, minimal fs), `standard` (allow listed endpoints), `permissive` (log-only).

### STORY-006: Credential Provider System
- **Status:** DONE ✅
- **Goal:** Implement named credential bundles that control which env vars are available inside `sigil run`
- **Done when:** `sigil provider create --name github --vars GITHUB_TOKEN,GH_TOKEN` saves a provider to `~/.sigil/providers/`. `sigil run --provider github -- cmd` only passes those env vars to the container. `sigil provider list` shows saved providers. Auto-discovery detects common agent credentials (ANTHROPIC_API_KEY, OPENAI_API_KEY, GITHUB_TOKEN) and suggests provider creation.
- **Files:** `cli/src/main.rs` (add Provider subcommand), `cli/src/provider/mod.rs` (new)
- **Notes:** Inspired by OpenShell's provider system. Credentials stored as JSON in `~/.sigil/providers/<name>.json`, never written to container filesystem — only injected as env vars via `docker run -e`.

### STORY-007: `sigil safe-run` — Scan + Sandbox in One Command
- **Status:** DONE ✅
- **Goal:** Combine scanning and sandboxed execution: scan first, auto-generate policy, run in sandbox
- **Done when:** `sigil safe-run <path> -- <command>` runs a scan, generates a policy from findings, and launches the command in a sandbox with that policy. If scan verdict is CRITICAL_RISK, execution is blocked. If HIGH_RISK, user is prompted for confirmation. LOW/MEDIUM proceed with generated policy.
- **Files:** `cli/src/main.rs` (add SafeRun subcommand), `cli/src/sandbox/safe_run.rs` (new)
- **Notes:** Depends on STORY-002 (policy generate) and STORY-005 (sandbox run). This is the flagship UX — "scan it, then safely run it" in one step.

---

## Phase 3: Skills & SBOM

### STORY-008: `sigil sbom` — Software Bill of Materials Generation
- **Status:** DONE ✅
- **Goal:** Add a CLI command that generates SBOM from project dependency files, cross-referenced against Sigil's known threat database
- **Done when:** `sigil sbom <path>` parses lockfiles (package-lock.json, poetry.lock, Cargo.lock, requirements.txt, go.sum) and outputs CycloneDX JSON. Each component is cross-referenced against `api/data/known_threats.json`. Flagged components are annotated with threat severity. `--format` flag supports `cyclonedx`, `spdx`, `table`.
- **Files:** `cli/src/main.rs` (add Sbom subcommand), `cli/src/sbom/mod.rs` (new), `cli/src/sbom/parsers.rs` (new), `cli/src/sbom/cyclonedx.rs` (new)
- **Notes:** `docs/SBOM.md` documents Sigil's own SBOM but there's no `sigil sbom` command for users. Leverages existing `known_threats.json` (172KB). Start with 3 parsers: package-lock.json, requirements.txt, Cargo.lock.

### STORY-009: Claude Code Skills — `/fix-finding` and `/generate-policy`
- **Status:** DONE ✅
- **Goal:** Add two new Claude Code skills that make scan results actionable
- **Done when:** `/fix-finding` skill accepts a finding (phase, rule, file, line) and proposes a code fix with explanation. `/generate-policy` skill runs `sigil policy generate` and explains the policy to the user. Both follow the existing skill format in `plugins/claude-code/skills/`.
- **Files:** `plugins/claude-code/skills/fix-finding/SKILL.md` (new), `plugins/claude-code/skills/generate-policy/SKILL.md` (new)
- **Notes:** Follows existing skill pattern from `scan-repo/SKILL.md`. `/fix-finding` maps common findings to remediation patterns (e.g., "replace `eval()` with `ast.literal_eval()`", "remove postinstall hook"). `/generate-policy` wraps STORY-002's CLI command.

---

## Feature: F-003 Pro Billing + Tier Gating Verification (EP-003)

> **PRD:** `tasks/prd-pro-billing-gating-verification.md`
> **Plan:** `.nomark/artifacts/plans/pro-billing-gating-verification-plan.md`
> **Started:** 2026-05-03
> **Mode:** verification (no new build, prove the existing path carries water)

### STORY-100: Capture Stripe key environment audit (Container Apps env)
- **Status:** PARTIAL (2026-05-03, autopilot — 2/4 Price IDs verified live; Container Apps env audit deferred to operator)
- **Goal:** Documented evidence that all six STRIPE_* env vars are present on the running `sigil-api` Container App and the four Price IDs resolve to live-mode Stripe Products.
- **Done when:** `evidence/F-003/US-100-stripe-env-audit.md` exists with raw `az containerapp show` env output, `livemode: true` per Price ID, secretRef names (NOT values) for secret keys, pass/fail verdict per var.
- **Files:** `evidence/F-003/US-100-stripe-env-audit.md` (new) ✓ (partial)
- **Dependencies:** none
- **TDD anchor:** Manual verification — verbatim `az` command logged in evidence is the reproducibility surface.
- **Scope:** moderate (manual verification)
- **Evidence (partial):** `evidence/F-003/US-100-stripe-env-audit.md` — Pro Price ID `price_1T2AOLFhPhxEz27fs0Z2nU4y` and Team `price_1T2AQCFhPhxEz27fOjCVsuwe`: both `livemode:true, active:true`, $29/$99 monthly, USD, recurring, **`trial_period_days: null`** (direct evidence supporting STORY-107 Branch A). FINDINGS: (1) `STRIPE_PRICE_PRO_ANNUAL` and `STRIPE_PRICE_TEAM_ANNUAL` MISSING from local api/.env — could be configured only on Container App OR could be stub annual pricing without backing Stripe Price (would fail at Checkout); operator audit required. (2) `az containerapp show` snapshot not captured (no Azure CLI access from this session).
- **Notes:** CHARTER II — if `az` access unavailable, escalate; do NOT mark DONE on partial evidence. `livemode: true` on the Price object is ground-truth; do not infer from key prefix alone.

### STORY-101: Capture Stripe Dashboard webhook subscription audit
- **Status:** FAIL (2026-05-03, autopilot — P0 SHIP-BLOCKING DEFECT FOUND)
- **Goal:** Documented evidence that the live-mode Stripe Dashboard has exactly one webhook endpoint at `https://api.sigilsec.ai/v1/billing/webhook` subscribed to all six required event types.
- **Done when:** `evidence/F-003/US-101-webhook-subscription-audit.md` exists with `stripe webhook_endpoints list --live` output, exact membership check vs `{customer.subscription.{created,updated,deleted}, invoice.{paid,payment_failed}, checkout.session.completed}`, endpoint `enabled: true`. Append findings to config audit doc.
- **Files:** `evidence/F-003/US-101-webhook-subscription-audit.md` (new) ✓
- **Dependencies:** none
- **TDD anchor:** Manual verification via `stripe` CLI live-mode access.
- **Scope:** moderate (manual verification)
- **Evidence:** `evidence/F-003/US-101-webhook-subscription-audit.md` — Sigil endpoint `we_1T2AXKFhPhxEz27fCYP53mKc` is `enabled:true, livemode:true` at correct URL. **BUT subscribed events MISSING: `checkout.session.completed` AND `customer.subscription.created`.** Handler dispatches on both (`api/routers/billing.py:782, 784`). Without these events, paid checkout completion will NOT trigger tier flip — F-003 round-trip is currently broken in live mode AND will fail STORY-105 in test mode unless test webhook has same fix. Naming-mismatch finding: PRD says `invoice.paid` but handler+Stripe use `invoice.payment_succeeded` (functionally OK; PRD wording should be amended). Side-finding: shared Stripe account also hosts `instaindex.ai/api/webhook` — config data point only.
- **Operator P0 fix:** Stripe Dashboard live-mode → Webhooks → endpoint `we_1T2AXKFhPhxEz27fCYP53mKc` → add `checkout.session.completed` and `customer.subscription.created`. Apply same fix to test-mode webhook. Then re-run audit.
- **Notes:** Split from PRD US-003. Missing events → owner-driven Dashboard fix, then re-verify. **STORY-105 is hard-blocked by this defect — round-trip cannot succeed until fixed.**

### STORY-102: Verify webhook signing-secret alignment via Dashboard test send
- **Status:** PARTIAL (2026-05-03, autopilot — negative control captured; positive control awaits operator)
- **Goal:** Prove `STRIPE_WEBHOOK_SECRET` matches the live endpoint signing secret WITHOUT logging either value.
- **Done when:** `evidence/F-003/US-102-webhook-signature-roundtrip.md` exists with: Dashboard test-send timestamp + event ID, container log line showing handler returned 200 for that event ID, NEGATIVE control curl with bogus signature returns 400.
- **Files:** `evidence/F-003/US-102-webhook-signature-roundtrip.md` (new) ✓ (partial)
- **Dependencies:** STORY-101
- **TDD anchor:** `curl -sS -X POST https://api.sigilsec.ai/v1/billing/webhook -H 'Stripe-Signature: t=1,v1=bad' -d '{}' -w '%{http_code}'` — expected `400`. **MET (got 400 + `Invalid webhook signature`).**
- **Scope:** moderate (manual verification)
- **Evidence (partial):** `evidence/F-003/US-102-webhook-signature-roundtrip.md` — negative control PASS (HTTP 400 for bogus signature; HTTP 400 for unsigned request). FR-4 satisfied. Positive control (Dashboard test send → handler 200) deferred to operator AND should run AFTER STORY-101 P0 fix lands.
- **Notes:** PRD US-003 forbids direct value comparison — round-trip 200 + negative 400 is the only acceptable evidence pair.

### STORY-103: Audit `require_plan(PlanTier.PRO)` route inventory
- **Status:** DONE (2026-05-03, autopilot)
- **Goal:** Reproducible list of all Pro-gated routes; canary route for STORY-105 named.
- **Done when:** `evidence/F-003/US-103-pro-gated-routes.md` exists with `grep -rn "require_plan(PlanTier.PRO)" api/routers/` output, HTTP method + path resolved per line, recommended canary `POST /v1/interactive/investigate` named at bottom with rationale.
- **Files:** `evidence/F-003/US-103-pro-gated-routes.md` (new) ✓
- **Dependencies:** none
- **TDD anchor:** Grep returns ≥18 hits per PRD intro. <18 = red flag, gate may have been removed.
- **Scope:** trivial
- **Evidence:** `evidence/F-003/US-103-pro-gated-routes.md` — 33 hits across 5 routers (15 interactive, 8 threat, 5 policies, 4 scan via dashboard_router, 1 billing). Floor of ≥18 met. Canary: `POST /v1/interactive/investigate`. Findings: PRD figure of "18 in interactive.py" is stale (actual 15 in interactive.py, 33 total); scan.py Pro routes live on dashboard_router (no `/v1` prefix).
- **Notes:** Locks in canary so STORY-105 evidence is comparable to a documented baseline.

### STORY-104: Free-mode 403 baseline probe
- **Status:** TODO
- **Goal:** Document that the canary Pro route returns 403 for an authenticated free-tier user.
- **Done when:** `evidence/F-003/US-104-free-403-baseline.md` exists with: real Auth0 free-tier JWT curl (token redacted), full response showing 403, MSSQL parameterised query confirming `subscription_tier='free'` for that user.
- **Files:** `evidence/F-003/US-104-free-403-baseline.md` (new)
- **Dependencies:** STORY-103
- **TDD anchor:** `curl -sS -X POST https://api.sigilsec.ai/<canary> -H "Authorization: Bearer <free-jwt>" -w '\n%{http_code}\n'` — expected 403.
- **Scope:** moderate (manual verification)
- **Notes:** Use `?` placeholder per aioodbc conventions. JWT must come from real Auth0 sign-in, not minted.

### STORY-105: Stripe TEST-mode end-to-end round-trip
- **Status:** HARD-BLOCKED (2026-05-03, autopilot — STORY-101 P0 defect must land first)
- **Goal:** Observed and recorded full PRD §3 loop in test mode: signup → 403 → checkout → webhook → tier=pro → 200 → portal cancel → tier=free → 403.
- **Done when:** `evidence/F-003/US-105-testmode-roundtrip.md` exists with 12 timestamped sections (Auth0 signup, MSSQL T0 free, 403, real `checkout.stripe.com` URL from `/v1/billing/subscribe`, Stripe test-card completion + `customer.subscription.created` event ID, container log 200 for that event, MSSQL T1 pro w/ stripe_customer_id + stripe_subscription_id populated, Pro route 200 with real LLM body, `/v1/billing/portal` returning `billing.stripe.com/…` URL, portal cancel `customer.subscription.deleted` event ID, MSSQL T2 free, Pro route 403).
- **Files:** `evidence/F-003/US-105-testmode-roundtrip.md` (new)
- **Dependencies:** STORY-100, STORY-101, STORY-102, STORY-103, STORY-104
- **TDD anchor:** 12-section evidence file IS the assertion. No automated substitute for an actual paid Checkout session.
- **Scope:** complex (manual verification)
- **Block reason (2026-05-03):** Per `evidence/F-003/US-101-webhook-subscription-audit.md`, the live Sigil webhook is NOT subscribed to `checkout.session.completed` or `customer.subscription.created`. Handler dispatches on both. Test-mode webhook likely has the same gap. STORY-105 round-trip CANNOT succeed in current state — webhook will not fire those events, tier flip will not happen, story §sections 5-7 will fail. Operator must fix subscription membership in BOTH live and test-mode Dashboard endpoints before STORY-105 is attempted.
- **Notes:** CHARTER II — do NOT fabricate any section. If section 4 returns `cs_test_<tier>_<cycle>_<ts>` (the dashboard stub), wrong path was taken; STORY-106 must run first. Webhook must fire within 30s or story stays TODO.

### STORY-106: Delete dead `dashboard/src/app/api/billing/create-checkout/route.ts`
- **Status:** TODO (precursor done — zero callers; trivial path confirmed)
- **Goal:** No production code path returns a fabricated `cs_test_…` URL after this story (FR-5).
- **Done when:** (1) `grep -rn "/api/billing/create-checkout" dashboard/src` returns zero matches; (2) the file does not exist; (3) dashboard build exits 0; (4) STORY-105 step 4 re-probe still returns a real `checkout.stripe.com` URL. Evidence at `evidence/F-003/US-106-dead-route-removed.md`.
- **Files:** `dashboard/src/app/api/billing/create-checkout/route.ts` (delete), `evidence/F-003/US-106-dead-route-removed.md` (new)
- **Dependencies:** STORY-105
- **TDD anchor:** Empty grep + zero exit code from build.
- **Scope:** trivial
- **Precursor finding (2026-05-03, autopilot):** `grep -rn "/api/billing/create-checkout" dashboard/src` returns ZERO matches (exit 1). No callers exist. Once STORY-105 confirms the real path returns `checkout.stripe.com`, STORY-106 is a clean delete + build verification — no caller migration needed.
- **Notes:** If STORY-105 returned the stub, this flips to moderate (callers must be re-pointed at `/v1/billing/subscribe` first). Precursor confirms trivial-path holds.

### STORY-107: Free-trial decision and pricing-page reconciliation
- **Status:** BLOCKED-pending-owner-decision (de-risked — see precursor)
- **Goal:** Pricing-page free-trial copy reflects an owner decision (enabled-and-working OR removed).
- **Done when:** Branch A (REMOVE) — owner ADR row added to SOLUTION.md, pricing page free-trial copy stripped, post-cache-fix production HTML grep `free trial` returns zero. Branch B (ENABLE) — owner ADR + Stripe Price `trial_period_days` set + STORY-105 re-run with `subscription.status='trialing'` captured + trial-end transition captured. Evidence at `evidence/F-003/US-107-free-trial-resolution.md`.
- **Files:** `evidence/F-003/US-107-free-trial-resolution.md` (new), `SOLUTION.md` (append ADR row), `dashboard/src/app/pricing/page.tsx` (modify if Branch A)
- **Dependencies:** STORY-105 (Branch B), STORY-112 (Branch A)
- **TDD anchor:** Branch A — `curl -sS https://www.sigilsec.ai/pricing | grep -i 'free trial'` returns empty. Branch B — `subscription.status='trialing'` row in MSSQL.
- **Scope:** moderate (manual verification + owner-gated)
- **Precursor finding (2026-05-03, autopilot — see `evidence/F-003/US-108-cdn-investigation.md` §"Side Finding" + `evidence/F-003/US-112-cdn-fix-verification.md` §"STORY-107 Implications"):** Free-trial copy is not in current `dashboard/` source (verified via aggressive grep across the full tree). HOWEVER, STORY-112's `vercel redeploy` rebuilt the 23-day-old source (which DID have the copy somewhere), so production HTML post-redeploy STILL shows "30-day free trial". Source-level removal: verified. Production-level removal: requires a fresh build from current main HEAD (operator's `git push` flow or `vercel deploy --prod --yes`). Owner ADR (Branch A) should follow a confirmed clean-source deploy.
- **Stripe-side evidence (2026-05-03, autopilot — see `evidence/F-003/US-100-stripe-env-audit.md` §F3):** Both live monthly Prices have `trial_period_days: null`. Stripe will not honor any trial — a user is charged at Checkout regardless of pricing-page copy. Branch A (REMOVE) is the correct choice unless Branch B also configures `trial_period_days` on Stripe Prices. **Decision is now low-stakes; default firmly toward Branch A.**
- **Notes:** PRD Q3. Default recommendation: Branch A (remove) — shipping advertised-but-unverified behavior violates CHARTER II. Precursor + Stripe-side evidence strengthen this default.

### STORY-108: Investigate CDN cache `age: ~1.8M` on www.sigilsec.ai/pricing
- **Status:** DONE (2026-05-03, autopilot)
- **Goal:** Root cause of 21-day-stale `age` header documented before any fix is applied.
- **Done when:** `evidence/F-003/US-108-cdn-investigation.md` exists with full curl headers, Vercel deploy list, second-region probe, named root cause from {stale Vercel build cache, origin header misconfig, CDN never invalidated, other}, recommended fix sized.
- **Files:** `evidence/F-003/US-108-cdn-investigation.md` (new) ✓
- **Dependencies:** none
- **TDD anchor:** Diagnostic — curl headers IS the data.
- **Scope:** moderate (manual verification)
- **Evidence:** `evidence/F-003/US-108-cdn-investigation.md` — root cause: pricing route is `"use client"` with no `export const revalidate`, so Next.js + Vercel only refresh edge artefact on redeploy. Last deploy was ~21 days ago. Tier-1 fix (recommended): redeploy dashboard to Vercel; expect age <60s post-deploy. Side findings: CSP retains foreign domains (`*.cakewalk.ai`, `cw-ai-prod.s3.us-west-1.amazonaws.com`) — separate hygiene cleanup; deployed HTML has "Free Trial" copy but source does not (de-risks STORY-107 Branch A).
- **Notes:** Split from PRD US-006 because fix differs by cause.

### STORY-109: Stripe LIVE-mode end-to-end round-trip with one real $29 charge
- **Status:** BLOCKED-pending-owner-action
- **Goal:** Observed full PRD §3 loop in live mode using a real card; refund issued; webhook reverses tier on refund.
- **Done when:** `evidence/F-003/US-109-livemode-roundtrip.md` exists with same 12 sections as STORY-105 PLUS section 13 (Stripe invoice `paid:true, amount:2900, currency:usd, livemode:true`), section 14 (refund event ID), section 15 (MSSQL T3 free post-refund). Refund within 24h.
- **Files:** `evidence/F-003/US-109-livemode-roundtrip.md` (new)
- **Dependencies:** STORY-105, STORY-100, STORY-101, STORY-102
- **TDD anchor:** 15-section evidence file IS the assertion.
- **Scope:** complex (manual verification, owner-only)
- **Notes:** PRD Q2 — owner has live-mode access. Auto-mode rule 6 forbids destructive financial actions without explicit owner go-ahead. Hard escalation gate.

### STORY-110: Probe `/v1/billing/plans` for live Pro pricing surface
- **Status:** DONE (2026-05-03, autopilot)
- **Goal:** Documented snapshot of `/v1/billing/plans` in production; API-side mirror to pricing-page audit.
- **Done when:** `evidence/F-003/US-110-billing-plans-snapshot.md` contains verbatim `curl ... | jq` output, per-tier row showing tier name + price ($29 for Pro) + interval support + feature count, discrepancies vs pricing page flagged.
- **Files:** `evidence/F-003/US-110-billing-plans-snapshot.md` (new) ✓
- **Dependencies:** none
- **TDD anchor:** `jq '.[] | select(.tier=="pro") | .price_monthly'` — expected `29`.
- **Scope:** trivial
- **Evidence:** `evidence/F-003/US-110-billing-plans-snapshot.md` — HTTP 200, Pro $29/mo $232/yr w/ 12 features matching PRD intro. Confirms API surface is current; pricing page is stale (STORY-108). API does NOT expose Stripe Price IDs (correct — those stay backend-only; STORY-100 covers env-var alignment).
- **Notes:** Useful diagnostic for STORY-108/STORY-112 (API current, page stale → CDN root cause confirmed).

### STORY-111: Pricing-page byte-equal probe (localhost vs production)
- **Status:** TODO
- **Goal:** Diff between localhost-built pricing page and production-fetched HTML; freshness assertion for STORY-112.
- **Done when:** `evidence/F-003/US-111-pricing-page-diff.md` contains localhost build curl, production curl, diff with every divergence explained (nonces/build hashes expected; copy text divergence is the signal).
- **Files:** `evidence/F-003/US-111-pricing-page-diff.md` (new)
- **Dependencies:** STORY-112
- **TDD anchor:** `diff <(curl localhost ... | sed nonces) <(curl prod ... | sed nonces)` — zero meaningful divergence.
- **Scope:** moderate
- **Notes:** Must run AFTER STORY-112 to be meaningful.

### STORY-112: CDN cache fix — apply remediation from STORY-108 root cause
- **Status:** PARTIAL (2026-05-03, autopilot — cache flushed; content currency open)
- **Goal:** Production www.sigilsec.ai/pricing serves `age` header < 3600 on a fresh probe.
- **Done when:** Fix applied (purge / redeploy / config change per STORY-108), evidence has pre-fix stale curl, exact remediation command + timestamp, post-fix curl (≥60s wait) showing `age` < 3600, second probe 5min later showing monotonically increasing age.
- **Files:** `evidence/F-003/US-112-cdn-fix-verification.md` (new) ✓
- **Dependencies:** STORY-108
- **TDD anchor:** `curl -sS -I https://www.sigilsec.ai/pricing | grep -i '^age:' | awk '{print $2}'` < 3600.
- **Scope:** moderate (could be trivial if pure purge)
- **Evidence:** `evidence/F-003/US-112-cdn-fix-verification.md` — cache freshness verified (`age: 0`, ETag changed `8f3abbb...` → `b08afad...`). BUT: `vercel redeploy <url>` rebuilds the prior deployment's source (frozen 23 days ago), so deployed HTML still shows old "30-day free trial" copy that has since been removed from current `dashboard/` source. To ship current content: operator pushes `7f874b6` to `origin/main` (Vercel auto-deploys from main per their flow) OR runs `vercel deploy --prod --yes` from `dashboard/`. Monotonic-age probe at +5min not captured (autopilot foreground-wait constraint).
- **Notes:** Sizing TBD by STORY-108 outcome. Cache-freshness AC met; full content-update AC pending operator-driven fresh deploy.

### STORY-113: Flip F-003 status in SOLUTION.md and progress.md
- **Status:** TODO
- **Goal:** F-003 marked DONE with evidence pointers; close-out gate.
- **Done when:** SOLUTION.md F-003 status = DONE w/ shipped date, all 7 ACs ticked with evidence file paths inline; progress.md STORY-100..STORY-112 all DONE pointing at evidence files; PRD Success Criteria items 1–8 each marked complete.
- **Files:** `SOLUTION.md`, `progress.md`, `tasks/prd-pro-billing-gating-verification.md`
- **Dependencies:** STORY-100..STORY-112
- **TDD anchor:** `grep -E '^\*\*Status:\*\* DONE' SOLUTION.md` after F-003; `grep -c "STORY-1[01][0-9]" progress.md` ≥ 13.
- **Scope:** trivial
- **Notes:** Does NOT get DONE if any prior story is TODO/BLOCKED — including STORY-109.

---

## Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-02 | Start with policy schema before runtime enforcement | Schema is the foundation — generation, validation, and sandbox all depend on it |
| 2026-04-02 | Use Docker/Podman for sandbox, not Landlock/seccomp directly | Broader platform support (macOS, Linux, WSL). OpenShell's Landlock approach is Linux-only |
| 2026-04-02 | Port Phases 7-8 before adding Phase 10 | Phases 7-8 already exist in Python API — port is lower risk than new phase design |
| 2026-04-02 | SBOM in Rust CLI, not Python API | Aligns with Rust CLI strategy; parsing lockfiles is well-suited to Rust |
| 2026-04-02 | 9 stories across 3 phases, not 10+ | Scoped to actionable deliverables; bypass monitoring and OCSF deferred to future phase |
| 2026-05-03 | Story IDs for F-003 use STORY-100+ prefix | Avoid collision with existing OpenShell STORY-001..STORY-009 in same progress.md |


## session-observations

### Session 2026-04-11

**Start:** 2026-04-11T11:40:25.011Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-04-11

**Start:** 2026-04-11T11:40:41.962Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-04-30

**Start:** 2026-04-30T07:51:57.016Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-04-30T07:52:49.979Z
**Outcome:** DONE
**Stories:** 9/9 (0 blocked)

- 4: react, hooks, frontend [confidence: 0.8]



### Session 2026-04-30

**Start:** 2026-04-30T08:00:45.538Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-04-30T08:01:14.695Z
**Outcome:** DONE
**Stories:** 9/9 (0 blocked)

- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-04-30

**Start:** 2026-04-30T09:13:25.238Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-04-30T09:14:00.677Z
**Outcome:** DONE
**Stories:** 9/9 (0 blocked)

- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-04-30

**Start:** 2026-04-30T22:32:20.308Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-04-30

**Start:** 2026-04-30T22:34:02.493Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-04-30T22:42:26.492Z
**Outcome:** DONE
**Stories:** 9/9 (0 blocked)

- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-04-30

**Start:** 2026-04-30T23:12:36.832Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-04-30T23:12:55.006Z
**Outcome:** DONE
**Stories:** 9/9 (0 blocked)

- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-05-02

**Start:** 2026-05-02T22:36:15.564Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-05-02T22:41:35.574Z
**Outcome:** DONE
**Stories:** 9/9 (0 blocked)

- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-05-02

**Start:** 2026-05-02T22:42:31.496Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-05-02T22:48:18.290Z
**Outcome:** DONE
**Stories:** 9/9 (0 blocked)

- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-05-03

**Start:** 2026-05-03T07:54:40.333Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** unknown — 9 stories (0/0/0)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-05-03T07:57:40.521Z
**Outcome:** BLOCKED
**Stories:** 9/23 (2 blocked)

- 4: react, hooks, frontend [confidence: 0.8]

## instinct-health

| ID | Pattern | Injections | Applied | Completions | Fallbacks | Applied Rate | Outcome Rate | Status |
|----|---------|------------|---------|-------------|-----------|-------------|-------------|--------|







