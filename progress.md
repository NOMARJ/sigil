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
- **Status:** DONE (2026-05-04, autopilot — all 4 Price IDs verified live via Stripe MCP, sigil-infra PR #3 wired them durably into TF, `az containerapp show` snapshot captured post-deploy)
- **Closure evidence:** `evidence/F-003/US-100-stripe-price-ids-live-confirmation.md` — all 4 prices (Pro mo/yr + Team mo/yr) `active=true`, `recurring`, `usd`, `trial_period_days=null`. sigil-infra PR #3 (`737891f`) declared all 4 in TF; rev `sigil-api--0000077` populated post-apply. Branch C trial decision (STORY-107) documented in ADR-0001.
- **Goal:** Documented evidence that all six STRIPE_* env vars are present on the running `sigil-api` Container App and the four Price IDs resolve to live-mode Stripe Products.
- **Done when:** `evidence/F-003/US-100-stripe-env-audit.md` exists with raw `az containerapp show` env output, `livemode: true` per Price ID, secretRef names (NOT values) for secret keys, pass/fail verdict per var.
- **Files:** `evidence/F-003/US-100-stripe-env-audit.md` (new) ✓ (partial)
- **Dependencies:** none
- **TDD anchor:** Manual verification — verbatim `az` command logged in evidence is the reproducibility surface.
- **Scope:** moderate (manual verification)
- **Evidence (partial):** `evidence/F-003/US-100-stripe-env-audit.md` — Pro Price ID `price_1T2AOLFhPhxEz27fs0Z2nU4y` and Team `price_1T2AQCFhPhxEz27fOjCVsuwe`: both `livemode:true, active:true`, $29/$99 monthly, USD, recurring, **`trial_period_days: null`** (direct evidence supporting STORY-107 Branch A). FINDINGS: (1) `STRIPE_PRICE_PRO_ANNUAL` and `STRIPE_PRICE_TEAM_ANNUAL` MISSING from local api/.env — could be configured only on Container App OR could be stub annual pricing without backing Stripe Price (would fail at Checkout); operator audit required. (2) `az containerapp show` snapshot not captured (no Azure CLI access from this session).
- **Notes:** CHARTER II — if `az` access unavailable, escalate; do NOT mark DONE on partial evidence. `livemode: true` on the Price object is ground-truth; do not infer from key prefix alone.

### STORY-101: Capture Stripe Dashboard webhook subscription audit
- **Status:** DONE (2026-05-03, autopilot — P0 fix applied + re-verified)
- **Goal:** Documented evidence that the live-mode Stripe Dashboard has exactly one webhook endpoint at `https://api.sigilsec.ai/v1/billing/webhook` subscribed to all six required event types.
- **Done when:** `evidence/F-003/US-101-webhook-subscription-audit.md` exists with `stripe webhook_endpoints list --live` output, exact membership check vs `{customer.subscription.{created,updated,deleted}, invoice.{paid,payment_failed}, checkout.session.completed}`, endpoint `enabled: true`. Append findings to config audit doc.
- **Files:** `evidence/F-003/US-101-webhook-subscription-audit.md` (audit) ✓ + `evidence/F-003/US-101-fix-applied.md` (fix evidence) ✓
- **Dependencies:** none
- **TDD anchor:** Manual verification via Stripe API. Pre-fix `enabled_events|length == 4`, post-fix `== 6` containing both `checkout.session.completed` and `customer.subscription.created`.
- **Scope:** moderate (manual verification + fix)
- **Audit evidence:** `evidence/F-003/US-101-webhook-subscription-audit.md` — Sigil endpoint `we_1T2AXKFhPhxEz27fCYP53mKc` is `enabled:true, livemode:true` at correct URL. Pre-fix subscribed events were `customer.subscription.{updated,deleted}, invoice.{payment_failed,payment_succeeded}` — MISSING `checkout.session.completed` and `customer.subscription.created`.
- **Fix evidence:** `evidence/F-003/US-101-fix-applied.md` — owner-authorized POST `/v1/webhook_endpoints/we_1T2AXKFhPhxEz27fCYP53mKc` replacing `enabled_events` with the full 6-event union. Stripe response: `count: 6`. Independent re-verify GET confirms `count: 6` containing all 6 PRD-required events. Live-mode only — test-mode webhook (separate ID, separate audit) still requires the same fix before STORY-105 can run in test mode.
- **Notes:** Split from PRD US-003. Naming-mismatch finding stands: PRD says `invoice.paid` but handler+Stripe use `invoice.payment_succeeded` (functionally OK for subscription billing; PRD wording amendment is non-blocking). Side-finding: shared Stripe account also hosts `instaindex.ai/api/webhook` — config data point only. **STORY-105 unblocked for live-mode; test-mode webhook subscription audit is the remaining gate before TEST-mode round-trip.**

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
- **Status:** DONE (2026-05-03, autopilot via agent-browser + curl — F1+F1.5+F1.6 fix cascade landed; real JWT → /v1/policies → 403 with structured GateError. See `evidence/F-003/STORY-104-DONE-closes-F1.5-F1.6.md`.)
- **Goal:** Document that the canary Pro route returns 403 for an authenticated free-tier user.
- **Done when:** `evidence/F-003/US-104-free-403-baseline.md` exists with: real Auth0 free-tier JWT curl (token redacted), full response showing 403, MSSQL parameterised query confirming `subscription_tier='free'` for that user.
- **Files:** `evidence/F-003/US-104-105-agent-browser-roundtrip.md` (covers US-104 + US-105) ✓
- **Dependencies:** STORY-103
- **TDD anchor:** `curl -sS -X POST https://api.sigilsec.ai/<canary> -H "Authorization: Bearer <free-jwt>" -w '\n%{http_code}\n'` — expected 403.
- **Scope:** moderate (manual verification)
- **Evidence:** `evidence/F-003/US-104-105-agent-browser-roundtrip.md` — Created Auth0 user `auth0|69f71abe8253a1122bb3acd9` (`reece+sigil-f003-1777801888@nomark.au`) via agent-browser. `/api/auth/me` returns user info; `/api/auth/token` returns a valid 776-byte RS256 JWT. **But the production API returns 503 `"Authentication service not configured"` for ALL protected endpoints — not the expected 403.** Same JWT, no JWT → API returns proper 401, so the 503 is post-Bearer-extraction in `api/routers/auth.py:557` (`if not settings.auth0_configured`).
- **F1 fix (2026-05-03, autopilot):** Container App env vars `SIGIL_AUTH0_DOMAIN=auth.sigilsec.ai` + `SIGIL_AUTH0_AUDIENCE=https://api.sigilsec.ai` set via `az containerapp update`. New revision `sigil-api--0000071` Running + Healthy + 100% traffic. Verified by 503→401 transition: pre-fix any Bearer → 503 "Authentication service not configured"; post-fix → 401 "Invalid or expired Auth0 token" (verify_auth0_token reached). See `evidence/F-003/F1-fix-applied.md`.
- **F1.5 FIXED (commit `69b9f13`, revision `sigil-api--0000072`):** /userinfo fallback added to `verify_auth0_token` at `api/routers/auth.py:425-446` — when JWT lacks email claim, fetches `https://{auth0_domain}/userinfo` with the access token. TDD via `api/tests/test_auth_userinfo_fallback.py` (2 tests, both pass).
- **F1.6 FIXED (commit `43f2165`, revision `sigil-api--0000073`):** T-SQL reserved-word column quoting. `MssqlClient._q()` helper added; applied at all 7 SQL-gen sites (insert/select/upsert/update/delete) so columns like `subscriptions.plan`, `scans.status` get bracket-quoted as `[plan]`, `[status]`. Pre-fix: 500 `pyodbc.ProgrammingError "Incorrect syntax near the keyword 'plan'"` blocked every authenticated /v1/billing/subscription call. TDD via `api/tests/test_database_reserved_word_columns.py` (5 tests, all pass).
- **F1.7 BLOCKED (2026-05-03, /bugfix all):** `interactive.router` registration requires fixing a chain of missing modules. (a) `api/exceptions.py` — FIXED in commit `9b13983` (re-exports `InsufficientCreditsError` + `CreditTransactionError` from `credit_service`, adds `UnauthorizedError`; six service files import from it). (b) `api/services/claude_service.py` — STILL MISSING; `bulk_analyzer.py:17` imports `claude_service`, `bulk_analyzer.py:147` calls `claude_service.analyze_with_claude(prompt, ...)` which doesn't match the existing `LLMService.analyze_threat()` signature. Fixing this is feature work (a Claude/Anthropic API wrapper service), not a bug fix. Out of `/bugfix` scope. Effect: paid Pro users will see 404s when they try to use what they paid for (AI Investigation, False Positive Verification, Interactive Chat, Attack Chain, Compliance Mapping). P0 for actual Pro feature delivery; does NOT block STORY-104 (other Pro routes work). Two regression tests added in `api/tests/test_interactive_router_registered.py`, marked `@pytest.mark.skip` until claude_service lands. See `evidence/F-003/F1.7-BLOCKED.md`.
- **CI Dashboard build (2026-05-03, /bugfix all):** FIXED in commit `9b13983`. `dashboard/package-lock.json` was out of sync with `package.json` (missing `posthog-js` + ~30 transitive deps). `npm ci` in CI failed every run since at least 2026-04. Regenerated lock via `npm install`. All 3 image build steps now succeed. Dashboard tests + tsc clean.
- **CI deploy dispatch (FIXED 2026-05-03):** Operator rotated `INFRA_REPO_PAT` (fine-grained PAT, `Contents: Read & write` on `NOMARJ/sigil-infra`). Re-ran `gh run rerun 25277397051 --failed` — deploy-azure went `failure` → `success`. Dispatch fired sigil-infra workflow run `25277809861`.
- **sigil-infra Terraform Apply skipped (NEW finding — exposed by the dispatch fix):** sigil-infra deploy.yml's Plan step does `EXITCODE=$?` after `terraform plan`, but `hashicorp/setup-terraform@v3` (default `terraform_wrapper: true`) wraps terraform and always exits 0 — so EXITCODE is always 0 regardless of real plan diff. Plan Summary echoes "✅ No changes detected" even when terraform itself logs `Plan: 5 to add, 20 to change`. Apply gate `if: needs.terraform-plan.outputs.plan-exists == '2'` then skips. **PR opened: https://github.com/NOMARJ/sigil-infra/pull/1** (branch `fix/terraform-wrapper-exitcode`, one-line fix: add `terraform_wrapper: false` to Setup Terraform). Awaits operator review + merge. Once merged, future repository_dispatch deploys auto-apply terraform changes (no more manual `az containerapp update`).
- **F2 dashboard fix DEPLOYED to production (2026-05-03 via parallel agent):** Manual `az containerapp update -n sigil-dashboard --image sigilacr46iy6y.azurecr.io/sigil-dashboard:9b13983` advanced sigil-dashboard from revision `0000016` (image `ff33824`, March) to revision `0000017` (image `9b13983`). Running + Healthy. Smoke: `/` → 200, `/api/auth/login` → 302 (Auth0). The SubscriptionManager rewrite (Stripe Portal canonical path) is live. F2 fix journey: code in `2a72827` → CI image build only landed at `9b13983` → manually deployed today.
- **Notes:** Cleanup required: operator deletes 2 test users from Auth0 Dashboard → Users (`reece+sigil-f003-1777801888@nomark.au`, `reece+sigil-f003-f1verify-1777803354@nomark.au`). Neither has an MSSQL row (auto-provision blocked at F1.5 email-claim check).

### STORY-105: Stripe TEST-mode end-to-end round-trip
- **Status:** BLOCKED (2026-05-03, autopilot — STORY-101 live-mode fix LANDED; test-mode webhook subscription audit + browser-driven Stripe Checkout still required)
- **Goal:** Observed and recorded full PRD §3 loop in test mode: signup → 403 → checkout → webhook → tier=pro → 200 → portal cancel → tier=free → 403.
- **Done when:** `evidence/F-003/US-105-testmode-roundtrip.md` exists with 12 timestamped sections (Auth0 signup, MSSQL T0 free, 403, real `checkout.stripe.com` URL from `/v1/billing/subscribe`, Stripe test-card completion + `customer.subscription.created` event ID, container log 200 for that event, MSSQL T1 pro w/ stripe_customer_id + stripe_subscription_id populated, Pro route 200 with real LLM body, `/v1/billing/portal` returning `billing.stripe.com/…` URL, portal cancel `customer.subscription.deleted` event ID, MSSQL T2 free, Pro route 403).
- **Files:** `evidence/F-003/US-105-testmode-roundtrip.md` (new)
- **Dependencies:** STORY-100, STORY-101, STORY-102, STORY-103, STORY-104
- **TDD anchor:** 12-section evidence file IS the assertion. No automated substitute for an actual paid Checkout session.
- **Scope:** complex (manual verification)
- **Block reason (2026-05-03, autopilot, updated post-F1+F2 fix):** Three stacked ship-blockers in priority order: (1) STORY-101 webhook events — DONE (`evidence/F-003/US-101-fix-applied.md`). (2) F1 production API Auth0 config drift — DONE (`evidence/F-003/F1-fix-applied.md`, revision `sigil-api--0000071`). (3) F2 dashboard `/api/v1/billing/*` proxy 404s — DONE (`evidence/F-003/F2-fix-applied.md`, commit `2a72827`). **NEW remaining blocker: F1.5 — Auth0 access token lacks email claim.** API at `auth.py:432-434` expects `https://api.sigilsec.ai/email` namespaced claim or plain `email`, neither present in default Auth0 access tokens. Operator must configure an Auth0 Post-Login Action OR maintainer must add a `/userinfo` fallback in `verify_auth0_token`. Once F1.5 resolved, STORY-104 progresses (signup → free user → 403 from canary Pro endpoint), then STORY-105 needs (a) test-mode webhook subscription audit + fix and (b) browser-driven Stripe Checkout with test card.
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
- **Sibling defect (F2) FIXED 2026-05-03 via /bugfix:** SubscriptionManager.tsx had four raw `fetch('/api/v1/billing/{portal,cancel,reactivate,invoices}')` calls — all 404 in production (none have FastAPI implementations except `/portal`, which was being called via a non-existent Next.js proxy path). Rewritten to call `api.createPortalSession()` (the working FastAPI wrapper); cancel/reactivate/invoice management delegated to Stripe Customer Portal (the canonical path). TDD red→green via `dashboard/src/__tests__/components/SubscriptionManager.routes.test.ts`. Full Jest suite 21/21 PASS. Evidence: `evidence/F-003/F2-fix-applied.md`.
- **Notes:** If STORY-105 returned the stub, this flips to moderate (callers must be re-pointed at `/v1/billing/subscribe` first). Precursor confirms trivial-path holds. F2 sibling fix above does NOT discharge STORY-106 — that file (`create-checkout/route.ts`) is a different dead-route from the F2 set and stays gated on STORY-105.

### STORY-107: Free-trial decision and pricing-page reconciliation
- **Status:** ADR DONE (2026-05-04, owner approved Branch C). Live trialing-state verification deferred to STORY-105 unblock.
- **Owner decision (2026-05-04):** Branch C — 14-day trial set on Stripe Checkout Session (`subscription_data.trial_period_days=14`), gated to first-time customers. Implementation: `api/routers/billing.py:207` `_TRIAL_PERIOD_DAYS = 14`, commit `7b60315`, live on `sigil-api--0000078`. ADR-0001 at `docs/adr/ADR-0001-stripe-free-trial.md`. SOLUTION.md ADR log updated.
- **Goal:** Pricing-page free-trial copy reflects an owner decision (enabled-and-working OR removed).
- **Done when:** Branch A (REMOVE) — owner ADR row added to SOLUTION.md, pricing page free-trial copy stripped, post-cache-fix production HTML grep `free trial` returns zero. Branch B (ENABLE on Stripe Price) — owner ADR + Stripe Price `trial_period_days` set + STORY-105 re-run with `subscription.status='trialing'` captured + trial-end transition captured. **Branch C (ENABLE on Checkout Session — chosen):** owner ADR ✓, code-level trial gate ✓, regression tests ✓, STORY-105 re-run with `subscription.status='trialing'` PENDING (blocked on F1.7 + test-mode webhook setup), trial→active transition PENDING. Evidence: `docs/adr/ADR-0001-stripe-free-trial.md` + `api/tests/test_billing_trial_period.py`.
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

## F-003 Closeout (PRD: tasks/prd-remaining-f-003-work.json)

> **Created:** 2026-05-04
> **Mode:** verification + one feature-work item (claude_service)
> Atomic stories that close out the open F-003 surface. Owner-gated items flagged inline.

### US-001: Decide claude_service shape (ADR-0003)
- **Status:** DONE (2026-05-04, owner approved Branch A) — ADR-0003 `status: accepted`. SOLUTION.md ADR log row marked owned. US-002 unblocked.
- **Linear:** [NOM-883](https://linear.app/nomark/issue/NOM-883)
- **Goal:** Documented decision on shim vs refactor vs drop-bulk, owner-approved.
- **Done when:** `docs/adr/ADR-0003-claude-service-strategy.md` exists with `status: accepted`; SOLUTION.md ADR log row added.
- **Files:** `docs/adr/ADR-0003-claude-service-strategy.md` ✓ (proposed), `SOLUTION.md` ✓
- **Dependencies:** none
- **TDD anchor:** `test -f docs/adr/ADR-0003-claude-service-strategy.md && grep -q '^status: accepted' docs/adr/ADR-0003-claude-service-strategy.md` — currently grep matches `status: proposed`, not `status: accepted`; flips when owner approves.
- **Scope:** trivial (writeup) — gate is owner approval
- **Notes:** Branches per `evidence/F-003/F1.7-BLOCKED.md`: (a) thin shim — RECOMMENDED, (b) bulk_analyzer refactor, (c) drop bulk routes. Implementation sketch + test surface included in the ADR for US-002 reviewer.

### US-002: Implement claude_service per ADR-0003 + register interactive.router
- **Status:** DONE (2026-05-04, autopilot, PR #111 squash-merged into `main` as `853b718`; deployed) — all 6 ACs verified. AC #6 confirmed against production: `curl -sS -X POST https://api.sigilsec.ai/v1/interactive/investigate -H 'Content-Type: application/json' -d '{}'` → **HTTP 401** (`{"detail":"Bad request: not authenticated"}`), not 404. F1.7 fully resolved. Evidence: `evidence/F-003/US-002-claude-service-implementation.md`.
- **Linear:** [NOM-892](https://linear.app/nomark/issue/NOM-892)
- **Goal:** 33 Pro-gated interactive routes load and respond 401/422 (not 404) in production.
- **Done when:** `python3 -c 'from api.routers import interactive'` exits 0 ✓; both `@pytest.mark.skip` decorators removed ✓; `pytest api/tests/test_interactive_router_registered.py` shows 2 PASSED ✓; `curl -X POST .../v1/interactive/investigate` returns 401 or 422 (post-deploy).
- **Files:** `api/services/llm_service.py` (rename + model param), `api/services/claude_service.py` (new), `api/main.py` (router registration), `api/tests/test_claude_service.py` (new, 4 tests), `api/tests/test_interactive_router_registered.py` (un-skipped), `api/tests/test_pro_performance.py` + `api/tests/test_phase9_llm.py` (rename pass-through).
- **Dependencies:** US-001 ✓
- **TDD anchor:** existing skip-marked tests in `test_interactive_router_registered.py` flip to PASS once skip is removed ✓ + 4 new claude_service tests, including a concurrent-calls regression that pins the wrapper's parameter-threading contract end-to-end (the no-global-mutation property is enforced by construction in `call_llm_api` and by ADR-0003 review, not directly by this single test — see test docstring for honest scope).
- **Scope:** complex (feature work)
- **Notes:** Highest-leverage remaining item — unblocks every Pro feature mentioned on the pricing page. Branch A implementation per ADR-0003: thin wrapper, model threaded as parameter (not via global mutation). Test sweep confirmed no regressions; failures in `test_scan.py`/`test_threat.py`/`test_auth_dependency_injection.py` are pre-existing event-loop fixture issues (verified by stashing my changes and reproducing the same errors on unmodified tree).

### US-003: Test-mode Stripe webhook subscription audit + fix
- **Status:** PARTIAL — operator-gated. Re-attempted 2026-05-04 post-merge against `main`: Stripe MCP confirmed connected to the correct NOMARK account (`acct_1RkD8NFhPhxEz27f`), but its surfaced operations (`fetch_stripe_resources`, `search_stripe_resources`, `stripe_api_execute`) do not include `webhook_endpoints` resource — `GetWebhookEndpoints` returns "Operation not available". Evidence file `evidence/F-003/US-105a-test-mode-webhook-audit.md` captures the runbook (Options A/B/C); verbatim `enabled_events` capture + any fix application require operator.
- **Linear:** [NOM-884](https://linear.app/nomark/issue/NOM-884)
- **Goal:** test-mode Stripe webhook endpoint subscribes to all 6 required events.
- **Done when:** `evidence/F-003/US-105a-test-mode-webhook-audit.md` with verbatim `enabled_events`; if missing events, fix applied + re-verify shows 6/6.
- **Files:** `evidence/F-003/US-105a-test-mode-webhook-audit.md` ✓ (runbook only — verbatim list pending)
- **Dependencies:** none
- **Scope:** moderate
- **Operator action:** Run Option A (`stripe webhook_endpoints list --project-name sigil` after `stripe login --project-name sigil`), Option B (Dashboard → toggle Test mode → Developers → Webhooks), or Option C (curl with test-mode `sk_test_…` against `https://api.stripe.com/v1/webhook_endpoints`). Append the result block at the bottom of the evidence file using the template provided.

### US-004: Stripe Dashboard test-send positive control (closes STORY-102)
- **Status:** TODO (operator-only)
- **Linear:** [NOM-885](https://linear.app/nomark/issue/NOM-885)
- **Goal:** prove signing-secret alignment with a real Dashboard test-send.
- **Done when:** `evidence/F-003/US-102-webhook-signature-roundtrip.md` gains a `## Positive Control` section with event ID + container log timestamp + 200.
- **Files:** `evidence/F-003/US-102-webhook-signature-roundtrip.md`
- **Dependencies:** STORY-101 (DONE)
- **Scope:** trivial

### US-005: Test-mode end-to-end round-trip (closes STORY-105)
- **Status:** PARTIAL (autopilot 2026-05-04 via agent-browser 0.26.0, owner-authorized) — Sections 1–3 PASS + Section 4 PASS-for-no-stub-regression / STOPPED-for-completion. Sections 5–12 BLOCKED on a structural finding: production sigil-api hardcodes `sk_live_*` (`api/.env:41`) and has no test-mode toggle on the billing path, so `/v1/billing/subscribe` returns a `cs_live_*` Checkout Session, not `cs_test_*`. Test card 4242 is rejected against live mode. Side-finding: dashboard `/api/auth/me` reports `plan: pro` for a free user (frontend defect — backend tier authoritative). Evidence: `evidence/F-003/US-105-testmode-roundtrip.md` + 6 screenshots in `US-105-roundtrip-trace/`. Cleanup: Auth0 user `auth0|69f843dba30893f65d3c543a` (`reece+sigil-f003-1777875215@nomark.au`) added to NOM-891 list.
- **Decision needed:** Path A (staging environment), B (local API run with test keys), C (re-scope to US-008 live-mode), or D (accept Section 4 as sufficient, cancel sections 5–12).
- **Linear:** [NOM-886](https://linear.app/nomark/issue/NOM-886)
- **Goal:** 12-section evidence file proving Free → Pro → cancel works in test mode.
- **Done when:** `evidence/F-003/US-105-testmode-roundtrip.md` has all 12 sections per existing STORY-105 spec; webhook events reach MSSQL within 30s; portal cancel flips tier back to free.
- **Files:** `evidence/F-003/US-105-testmode-roundtrip.md`
- **Dependencies:** US-002 ✓, US-003 (PARTIAL — operator-gated)
- **Scope:** complex (manual + browser-driven)
- **Notes:** Owner-supervised — uses Stripe TEST card `4242 4242 4242 4242`.

### US-006: Trialing-state verification (closes STORY-107 Branch C)
- **Status:** BLOCKED on US-005
- **Linear:** [NOM-887](https://linear.app/nomark/issue/NOM-887)
- **Goal:** Capture `subscription.status='trialing'` in MSSQL during US-005; flip ADR-0001 outcome to `success`.
- **Done when:** `evidence/F-003/US-107-trialing-state-verification.md` has the verbatim row + webhook payload; `docs/adr/ADR-0001-stripe-free-trial.md` frontmatter shows `outcome: success`.
- **Files:** `evidence/F-003/US-107-trialing-state-verification.md`, `docs/adr/ADR-0001-stripe-free-trial.md`
- **Dependencies:** US-005
- **Scope:** moderate

### US-007: Delete dead create-checkout route (closes STORY-106)
- **Status:** BLOCKED on US-005
- **Linear:** [NOM-888](https://linear.app/nomark/issue/NOM-888)
- **Done when:** file deleted, `grep` returns zero matches, dashboard build exits 0, evidence file captures pre/post.
- **Files:** `dashboard/src/app/api/billing/create-checkout/route.ts` (delete), `evidence/F-003/US-106-dead-route-removed.md`
- **Dependencies:** US-005
- **Scope:** trivial

### US-008: Live-mode round-trip with $29 charge + refund (closes STORY-109)
- **Status:** BLOCKED on US-005 + owner-only
- **Linear:** [NOM-889](https://linear.app/nomark/issue/NOM-889)
- **Goal:** prove live-mode operation end-to-end with one real charge, refunded within 24h.
- **Done when:** `evidence/F-003/US-109-livemode-roundtrip.md` has the 12 sections from US-005 PLUS section 13 (paid invoice $29), 14 (refund event), 15 (MSSQL T3 free post-refund).
- **Files:** `evidence/F-003/US-109-livemode-roundtrip.md`
- **Dependencies:** US-005
- **Scope:** complex
- **Notes:** Auto-Mode rule 5 — irreversible action, requires explicit owner go-ahead per charge AND per refund.

### US-009: Terraform-import 5 stale monitor_metric_alert resources
- **Status:** TODO (operator-only — sigil-infra terraform CLI access required)
- **Linear:** [NOM-890](https://linear.app/nomark/issue/NOM-890) (sigil-infra project)
- **Goal:** stop CI Apply step from erroring on the same 5 already-exist resources every run.
- **Done when:** `terraform import` succeeds for `api_response_time`, `api_replicas_down`, `api_high_cpu`, `dashboard_replicas_down`, `redis_down`; next CI Apply exits 0; evidence file captures import commands + plan diff.
- **Files:** `evidence/F-003/US-009-monitor-alert-imports.md`
- **Dependencies:** none
- **Scope:** moderate

### US-010: Auth0 test-user cleanup
- **Status:** BLOCKED on US-005 (need users intact for round-trip)
- **Linear:** [NOM-891](https://linear.app/nomark/issue/NOM-891)
- **Done when:** Auth0 dashboard search returns 0 test users; corresponding MSSQL rows deleted or tagged.
- **Files:** `evidence/F-003/US-010-auth0-cleanup.md`
- **Dependencies:** US-005
- **Scope:** trivial

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


### Session 2026-05-03

**Start:** 2026-05-03T09:07:46.542Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 23 stories (4/8/2)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-05-03T09:08:06.607Z
**Outcome:** BLOCKED
**Stories:** 12/18 (2 blocked)

- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-05-03

**Start:** 2026-05-03T10:06:54.865Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 23 stories (4/8/2)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-05-03T10:07:23.498Z
**Outcome:** BLOCKED
**Stories:** 13/19 (3 blocked)

- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-05-03

**Start:** 2026-05-03T10:08:26.650Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 23 stories (4/8/2)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-05-03T10:11:42.534Z
**Outcome:** BLOCKED
**Stories:** 13/19 (3 blocked)

- 4: react, hooks, frontend [confidence: 0.8]


### Session 2026-05-03

**Start:** 2026-05-03T11:44:46.340Z
**Available instincts:** 10 (proven: 5, pending: 5, promoted: 0, dormant: 0)
**Task scope:** F-003 — 23 stories (4/8/2)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
- 4: react, hooks, frontend [confidence: 0.8]
- 5: npm, sigil, scope [confidence: 0.3]
- 6: agents, verification, brief-compliance [confidence: 0.3]
- 7: secrets, release, ci-cd [confidence: 0.3]
- 8: github-actions, tags, ci-cd [confidence: 0.3]
- 9: npm, release, ci-cd [confidence: 0.3]


### Session 2026-05-03

**Start:** 2026-05-03T11:49:45.672Z
**Available instincts:** 10 (proven: 5, pending: 5, promoted: 0, dormant: 0)
**Task scope:** F-003 — 23 stories (4/8/2)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-05-03T11:52:25.816Z
**Outcome:** BLOCKED
**Stories:** 14/20 (3 blocked)

- 4: react, hooks, frontend [confidence: 0.8]
- 5: npm, sigil, scope [confidence: 0.3]
- 6: agents, verification, brief-compliance [confidence: 0.3]
- 7: secrets, release, ci-cd [confidence: 0.3]
- 8: github-actions, tags, ci-cd [confidence: 0.3]
- 9: npm, release, ci-cd [confidence: 0.3]


### Session 2026-05-04

**Start:** 2026-05-04T03:03:59.582Z
**Available instincts:** 10 (proven: 5, pending: 5, promoted: 0, dormant: 0)
**Task scope:** F-003 — 23 stories (4/8/2)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-05-04T03:04:59.352Z
**Outcome:** BLOCKED
**Stories:** 15/20 (2 blocked)

- 4: react, hooks, frontend [confidence: 0.8]
- 5: npm, sigil, scope [confidence: 0.3]
- 6: agents, verification, brief-compliance [confidence: 0.3]
- 7: secrets, release, ci-cd [confidence: 0.3]
- 8: github-actions, tags, ci-cd [confidence: 0.3]
- 9: npm, release, ci-cd [confidence: 0.3]


### Session 2026-05-04

**Start:** 2026-05-04T04:26:36.196Z
**Available instincts:** 10 (proven: 5, pending: 5, promoted: 0, dormant: 0)
**Task scope:** F-003 — 33 stories (8/11/5)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-05-04T04:30:47.435Z
**Outcome:** BLOCKED
**Stories:** 15/30 (8 blocked)

- 4: react, hooks, frontend [confidence: 0.8]
- 5: npm, sigil, scope [confidence: 0.3]
- 6: agents, verification, brief-compliance [confidence: 0.3]
- 7: secrets, release, ci-cd [confidence: 0.3]
- 8: github-actions, tags, ci-cd [confidence: 0.3]
- 9: npm, release, ci-cd [confidence: 0.3]


### Session 2026-05-04

**Start:** 2026-05-04T05:01:55.907Z
**Available instincts:** 10 (proven: 5, pending: 5, promoted: 0, dormant: 0)
**Task scope:** F-003 — 33 stories (8/11/5)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-05-04T05:03:52.164Z
**Outcome:** BLOCKED
**Stories:** 17/29 (7 blocked)

- 4: react, hooks, frontend [confidence: 0.8]
- 5: npm, sigil, scope [confidence: 0.3]
- 6: agents, verification, brief-compliance [confidence: 0.3]
- 7: secrets, release, ci-cd [confidence: 0.3]
- 8: github-actions, tags, ci-cd [confidence: 0.3]
- 9: npm, release, ci-cd [confidence: 0.3]


### Session 2026-05-04

**Start:** 2026-05-04T05:15:40.599Z
**Available instincts:** 10 (proven: 5, pending: 5, promoted: 0, dormant: 0)
**Task scope:** F-003 — 33 stories (8/11/5)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-05-04T05:18:45.892Z
**Outcome:** BLOCKED
**Stories:** 17/29 (7 blocked)

- 4: react, hooks, frontend [confidence: 0.8]
- 5: npm, sigil, scope [confidence: 0.3]
- 6: agents, verification, brief-compliance [confidence: 0.3]
- 7: secrets, release, ci-cd [confidence: 0.3]
- 8: github-actions, tags, ci-cd [confidence: 0.3]
- 9: npm, release, ci-cd [confidence: 0.3]

## instinct-health

| ID | Pattern | Injections | Applied | Completions | Fallbacks | Applied Rate | Outcome Rate | Status |
|----|---------|------------|---------|-------------|-----------|-------------|-------------|--------|















