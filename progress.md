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

## Feature: F-007 Launch Readiness Remediation (EP-003)

> **Linear:** NOM-1068 (Feature) · Epic EP-003 = NOM-1067
> **PRD:** `tasks/prd-launch-readiness.json`
> **Source:** `docs/launch-readiness-report.md` (2026-06-08, verdict: NOT READY)
> **Created:** 2026-06-08
> **Mode:** launch-gate tracker — cross-refs F-003/F-004 for pricing+installer, new stories for uncovered work
> **Governance:** trust 0 / probation — only `executor: agent` stories run without owner go-ahead

### US-001: Triage API test-suite failures into fix-categories
- **Linear:** NOM-1069
- **Status:** DONE (2026-06-08, autopilot) — baseline `25 failed/167 passed/31 errors` = 56 (matches report). All 56 categorized: 34 event-loop, 6 legacy-auth-410, 15 real-bug-protected, 1 test-only-mock. `grep -c 'category:'` = 57 (≥56). Evidence: `evidence/launch-readiness/US-001-pytest-triage.md`.
- **Executor:** agent (buildable) · **Blocker:** CRITICAL-004 · **Scope:** moderate
- **Goal:** Categorize the 25 failures + 31 errors into {test-only fixture, stale-expectation, real-bug-protected}.
- **Done when:** `evidence/launch-readiness/US-001-pytest-triage.md` with verbatim pytest tail; `grep -c 'category:'` >= 56.
- **Files:** `evidence/launch-readiness/US-001-pytest-triage.md`

### US-002: Fix event-loop fixture errors in API test suite
- **Linear:** NOM-1070
- **Status:** DONE (2026-06-08, autopilot) — root cause: local `SIGIL_DATABASE_URL` made lifespan build a real MSSQL pool vs the suite's intended in-memory store. Fix: session-autouse `_force_in_memory_db` in `conftest.py` (test-infra only, no `api/database.py` edit). Errors 31→0; passed 167→197; no regression. Evidence: `evidence/launch-readiness/US-002-event-loop-fix.md`.
- **Executor:** agent (buildable) · **Blocker:** CRITICAL-004 · **Scope:** moderate · **Deps:** US-001
- **Goal:** Resolve `got Future attached to a different loop` errors at the fixture layer (no production db edits).
- **Done when:** `pytest api/tests -q` reports 0 event-loop errors; count strictly decreases vs US-001 baseline.
- **Files:** `api/tests/conftest.py`, `evidence/launch-readiness/US-002-event-loop-fix.md`
- **Note:** Removing the loop error exposed 7 `test_scan` submission tests as `422` schema-drift failures (stale fixture, test-only, buildable but UNSCOPED by any F-007 story). Surfaced, not fixed (probation scope discipline).

### US-003: Update legacy auth test expectations to 410 post-Auth0
- **Linear:** NOM-1071
- **Status:** DONE (2026-06-08, autopilot) — 6 legacy register/login tests flipped 200/201/401/409 → 410 (test-only; production `api/routers/auth.py:605-640` already returns 410). `-k auth`: 38 passed/0 failed. Full suite 20 failed/203 passed/0 errors (203=197+6, no regression). Evidence: `evidence/launch-readiness/US-003-legacy-auth-410.md`.
- **Executor:** agent (buildable) · **Blocker:** CRITICAL-004 · **Scope:** trivial · **Deps:** US-001
- **Goal:** Flip stale 200-expecting legacy auth tests to assert 410 (test-only, no endpoint edits).
- **Done when:** `pytest api/tests -q -k auth` shows previously-failing legacy-auth tests pass.
- **Files:** `api/tests/`, `evidence/launch-readiness/US-003-legacy-auth-410.md`

### US-004: Diagnose /v1/report uniqueidentifier 500 (protected fix)
- **Linear:** NOM-1072
- **Status:** TODO
- **Executor:** owner-gated · **Blocker:** CRITICAL-004 · **Scope:** moderate · **Deps:** US-001
- **Goal:** Root-cause the SQL uniqueidentifier-conversion 500 + propose minimal patch (NOT applied) for owner approval.
- **Done when:** `evidence/launch-readiness/US-004-report-500-diagnosis.md` with conversion site, proposed diff, TDD anchor.
- **Files:** `evidence/launch-readiness/US-004-report-500-diagnosis.md`

### US-005: Repair public signup CTA (404 -> working signup)
- **Linear:** NOM-1073
- **Status:** TODO
- **Executor:** owner-gated · **Blocker:** CRITICAL-001 · **Scope:** moderate
- **Goal:** Owner-approved fix so `/signup` reaches a working flow (auth entry change).
- **Done when:** `curl -I https://app.sigilsec.ai/signup` returns 200 or intentional 302 to Auth0 signup, not 404.
- **Files:** `evidence/launch-readiness/US-005-signup-cta.md`

### US-006: Next.js upgrade assessment for high-severity advisory
- **Linear:** NOM-1074
- **Status:** DONE (2026-06-08, autopilot) — real `npm audit` (1 high next + 1 moderate postcss → next@16.2.7 breaking). Blast radius mapped to actual dashboard usage: React 18→19, 6 async-request-API files, caching defaults, eslint-config-next bump. Rollback + verify commands listed. `--force` NOT run. Evidence: `evidence/launch-readiness/US-006-nextjs-upgrade-assessment.md`.
- **Executor:** agent (buildable) · **Blocker:** HIGH-001 · **Scope:** moderate
- **Goal:** Written upgrade assessment for the breaking Next.js bump (-> 16.2.7), no forced fix run.
- **Done when:** `evidence/launch-readiness/US-006-nextjs-upgrade-assessment.md` with audit output, breaking surface, rollback plan.
- **Files:** `evidence/launch-readiness/US-006-nextjs-upgrade-assessment.md`

### US-007: Execute Next.js upgrade and clear audit
- **Linear:** NOM-1075
- **Status:** DONE (2026-06-09, owner-approved Auth0 v4 migration + agent team)
- **Executor:** operator-gated · **Blocker:** HIGH-001 · **Scope:** moderate · **Deps:** US-006
- **Goal:** Apply the planned upgrade; production audit clean.
- **Done when:** `npm audit --audit-level=high --omit=dev` exits 0; `npm test` + `npm run build` pass.
- **Files:** `dashboard/package.json`, `dashboard/package-lock.json`, `evidence/launch-readiness/US-007-nextjs-upgrade-applied.md`
- **Evidence:** `evidence/launch-readiness/US-007-nextjs-upgrade-applied.md` — `npm ci` exits 0; dependency graph resolves Next 16.2.7 / React 19.2.1 / Auth0 SDK 4.22.0; `npm run lint` exits 0 with 5 warnings; `npx tsc --noEmit` exits 0; Jest 4 suites / 43 tests pass; `npm run build` succeeds; `npm audit --audit-level=high --omit=dev` exits 0. Plain audit still reports 2 moderate PostCSS findings nested under Next.js.

### US-008: Draft Rust CLI verification CI job
- **Linear:** NOM-1076
- **Status:** DONE (2026-06-08, autopilot) — `.github/workflows/rust-cli.yml` drafted: ubuntu-latest, `rustup default 1.82.0` then `cargo build/test` with `working-directory: cli`. `actionlint 1.7.12` CLEAN (exit 0). checkout SHA-pinned to repo's existing v4 SHA. Enabling as required check = operator action. Evidence: `evidence/launch-readiness/US-008-rust-ci.md`.
- **Executor:** agent (buildable) · **Blocker:** HIGH-002 · **Scope:** moderate
- **Goal:** CI workflow installing a pinned Rust toolchain and running `cargo test` against `cli/`.
- **Done when:** Workflow YAML validates (actionlint clean), references `cli/Cargo.toml`; evidence explains local toolchain gap.
- **Files:** `.github/workflows/rust-cli.yml`, `evidence/launch-readiness/US-008-rust-ci.md`

### US-009: Verify Rust CLI builds and tests pass
- **Linear:** NOM-1077
- **Status:** DONE (2026-06-08, autopilot via CI, owner-approved) — `rust-cli.yml` ran on CI. First run (PR #115) failed: `clap_builder 4.6` needs `edition2024` (Cargo ≥1.85); bumped pin 1.82.0→1.90.0 (PR #116). Re-run green: `rustc 1.90.0`, `cargo build` + `cargo test` → `test result: ok. 6 passed; 0 failed`. Run 27110957847 success. **HIGH-002 closed.** Evidence: `evidence/launch-readiness/US-009-rust-verification.md`.
- **Executor:** environment-gated · **Blocker:** HIGH-002 · **Scope:** moderate · **Deps:** US-008
- **Goal:** `cargo test` passes for the CLI (CI or configured toolchain).
- **Done when:** `cargo test` exits 0 for `cli/`; evidence captures toolchain version + full test output.
- **Files:** `evidence/launch-readiness/US-009-rust-verification.md`

### US-010: [cross-ref] Pricing page reconciliation
- **Status:** TODO (tracked in F-003 STORY-107/111/112 — do not duplicate)
- **Executor:** operator-gated · **Blocker:** CRITICAL-002 · **Scope:** moderate
- **Goal:** Pricing page ($199/30-day-trial) reconciled with billing API (Team $99) per owner ADR-0001.
- **Done when:** Probe shows Team $99 + reconciled trial copy; F-003 STORY-112 fresh-deploy closed; evidence links F-003 files.
- **Files:** `evidence/launch-readiness/US-010-pricing-crossref.md`

### US-011: [cross-ref] Installer URL serves real installer
- **Status:** TODO (tracked in F-004 + F-003 STORY-108/112 — do not duplicate)
- **Executor:** operator-gated · **Blocker:** CRITICAL-003 · **Scope:** moderate
- **Goal:** `www.sigilsec.ai/install.sh` serves the GitHub-main installer, not the private-dev copy.
- **Done when:** `curl install.sh | head -5` matches real installer; root cause confirmed = STORY-108/112 stale deploy.
- **Files:** `evidence/launch-readiness/US-011-installer-crossref.md`

### US-012: Re-run launch-readiness report and flip verdict
- **Linear:** NOM-1078
- **Status:** BLOCKED (updated 2026-06-09) — cannot flip verdict to READY: hard deps US-004 (owner), US-005 (owner), US-009 (env), US-010 (operator), and US-011 (operator) remain gated and unmet. US-007 is now DONE. Verdict stays NOT READY. Run summary: `evidence/launch-readiness/F-007-autopilot-run.md`. Re-run once gated blockers clear.
- **Executor:** agent (buildable) · **Blocker:** ALL · **Scope:** moderate · **Deps:** US-001..US-011 (excl. cross-ref dupes)
- **Goal:** Re-run report once blockers clear; verdict NOT READY -> READY with refreshed evidence.
- **Done when:** Report verdict READY (or owner-acknowledged residual list); SOLUTION.md F-007 -> DONE; progress.md final.
- **Files:** `docs/launch-readiness-report.md`, `SOLUTION.md`, `progress.md`

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


### Session 2026-05-04

**Start:** 2026-05-04T07:24:31.367Z
**Available instincts:** 10 (proven: 5, pending: 5, promoted: 0, dormant: 0)
**Task scope:** F-003 — 33 stories (8/11/5)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.9]
- 1: scanner, false-positives, patterns [confidence: 0.9]
- 2: python, imports, packaging [confidence: 0.8]
- 3: python, fastapi, configuration [confidence: 0.8]
**End:** 2026-05-04T07:26:26.056Z
**Outcome:** BLOCKED
**Stories:** 17/28 (6 blocked)

- 4: react, hooks, frontend [confidence: 0.8]
- 5: npm, sigil, scope [confidence: 0.3]
- 6: agents, verification, brief-compliance [confidence: 0.3]
- 7: secrets, release, ci-cd [confidence: 0.3]
- 8: github-actions, tags, ci-cd [confidence: 0.3]
- 9: npm, release, ci-cd [confidence: 0.3]


### Session 2026-06-07

**Start:** 2026-06-07T23:55:25.640Z
**Available instincts:** 10 (proven: 5, pending: 5, promoted: 0, dormant: 0)
**Task scope:** F-003 — 33 stories (8/11/5)
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


### Session 2026-06-08

**Start:** 2026-06-08T00:15:35.250Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 33 stories (8/11/5)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
**End:** 2026-06-08T00:23:13.702Z
**Outcome:** BLOCKED
**Stories:** 18/45 (6 blocked)

- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-08

**Start:** 2026-06-08T00:42:41.303Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 45 stories (9/22/5)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
**End:** 2026-06-08T01:32:51.095Z
**Outcome:** BLOCKED
**Stories:** 24/45 (7 blocked)

- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-08

**Start:** 2026-06-08T02:00:00.463Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 45 stories (9/22/5)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-08

**Start:** 2026-06-08T02:00:31.961Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 45 stories (9/22/5)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
**End:** 2026-06-08T02:21:23.012Z
**Outcome:** BLOCKED
**Stories:** 25/46 (7 blocked)

- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-08

**Start:** 2026-06-08T03:49:30.960Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 45 stories (9/22/5)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
**End:** 2026-06-08T04:00:39.990Z
**Outcome:** BLOCKED
**Stories:** 25/46 (7 blocked)

- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-10

**Start:** 2026-06-10T09:17:08.210Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 45 stories (9/22/5)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
**End:** 2026-06-10T09:21:40.405Z
**Outcome:** BLOCKED
**Stories:** 27/46 (7 blocked)

- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-10

**Start:** 2026-06-10T09:23:30.503Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 45 stories (9/22/5)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
**End:** 2026-06-10T09:26:32.334Z
**Outcome:** BLOCKED
**Stories:** 27/46 (7 blocked)

- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-10

**Start:** 2026-06-10T09:27:11.937Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 45 stories (9/22/5)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
**End:** 2026-06-10T09:36:04.594Z
**Outcome:** BLOCKED
**Stories:** 27/46 (7 blocked)

- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-10

**Start:** 2026-06-10T23:01:00.817Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 45 stories (11/32/14)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-10

**Start:** 2026-06-10T23:01:20.024Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 45 stories (11/32/14)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
**End:** 2026-06-10T23:10:04.071Z
**Outcome:** BLOCKED
**Stories:** 35/67 (7 blocked)

- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-10

**Start:** 2026-06-10T23:19:43.109Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 45 stories (11/32/14)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
**End:** 2026-06-10T23:21:48.557Z
**Outcome:** BLOCKED
**Stories:** 35/67 (7 blocked)

- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-11

**Start:** 2026-06-11T04:05:06.213Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 45 stories (11/32/14)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
**End:** 2026-06-11T05:17:02.043Z
**Outcome:** BLOCKED
**Stories:** 45/67 (7 blocked)

- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-11

**Start:** 2026-06-11T07:31:31.389Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 45 stories (11/32/14)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-11

**Start:** 2026-06-11T07:31:55.171Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 45 stories (11/32/14)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
**End:** 2026-06-11T07:33:41.733Z
**Outcome:** BLOCKED
**Stories:** 48/67 (7 blocked)

- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-11

**Start:** 2026-06-11T09:53:23.072Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 57 stories (11/41/20)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
**End:** 2026-06-11T10:03:16.904Z
**Outcome:** BLOCKED
**Stories:** 58/82 (7 blocked)

- 4: react, hooks, frontend [confidence: 0.7]


### Session 2026-06-12

**Start:** 2026-06-12T06:31:01.620Z
**Available instincts:** 5 (proven: 5, pending: 0, promoted: 0, dormant: 0)
**Task scope:** F-003 — 57 stories (11/41/20)
**Instincts loaded:**
- 0: rust, safety, unicode [confidence: 0.8]
- 1: scanner, false-positives, patterns [confidence: 0.8]
- 2: python, imports, packaging [confidence: 0.7]
- 3: python, fastapi, configuration [confidence: 0.7]
**End:** 2026-06-12T06:39:16.618Z
**Outcome:** BLOCKED
**Stories:** 62/82 (7 blocked)

- 4: react, hooks, frontend [confidence: 0.7]

## instinct-health

| ID | Pattern | Injections | Applied | Completions | Fallbacks | Applied Rate | Outcome Rate | Status |
|----|---------|------------|---------|-------------|-----------|-------------|-------------|--------|

## Feature: Pre-Production Launch Readiness

> **Started:** 2026-06-08
> **Mode:** implementation with probation restrictions
> **Governance notes:** Trust score is 0/probation, so no autonomous subagent dispatch. CHARTER II.5 applies: auth, authorization, database schema, and CI/CD configuration changes require explicit owner approval before edits. First pass is evidence-driven discovery and non-protected fixes only.
> **Context:** FRESH (exchange 0), drift score 0/healthy.

### LAUNCH-001: Establish launch-readiness baseline
- **Status:** DONE (2026-06-08)
- **Goal:** Produce a fresh, reproducible baseline across package manager detection, build/test commands, live-route smoke checks, security dependency checks, and known owner-gated blockers.
- **Done when:** `docs/launch-readiness-report.md` contains command evidence and a launch verdict; every failed check is classified Critical/High/Medium/Low with next story routing.
- **Files:** `docs/launch-readiness-report.md`, `docs/pre-production-checklist.md`
- **Evidence:** `docs/launch-readiness-report.md` verdict `NOT READY`; `rg -n "NOT READY|CRITICAL-001|25 failed|has30DayTrial|HTTP/2 404|Sigil 1.1.2" docs/...` found all evidence anchors; `jq empty .nomark/resources.json tasks/instincts/index.json package-lock.json dashboard/package-lock.json && echo json-ok` returned `json-ok`; `ls -l evidence/launch-readiness` shows desktop/mobile pricing screenshots; `node scripts/drift-scorer.cjs 0` returned score `0`, bracket `FRESH`.
- **Notes:** Vercel Agent Browser is not available in this harness; Playwright Chromium was installed and used as substitute. Critical blockers found: `/signup` 404, stale public pricing, stale public install script, API suite failures. Non-protected fixes applied during baseline: `bin/sigil --version` now reports `1.1.2`; root `package-lock.json` version matches `1.1.2`; dashboard non-forced `npm audit fix` reduced audit from 3 vulnerabilities to 2 remaining Next/PostCSS advisories.
- **Reassessment (2026-06-08 03:33 UTC):** Verdict remains `NOT READY`. Live blockers unchanged: `https://app.sigilsec.ai/signup` -> `HTTP/2 404`; `https://www.sigilsec.ai/install.sh` still says private development/public beta coming soon; `https://www.sigilsec.ai/pricing` still has `30-day free trial`, `Start Free Trial`, and `$199` Team copy while `/v1/billing/plans` returns Team `$99`. Dashboard still passes (`41/41`, build OK) but audit still reports 2 vulnerabilities requiring breaking Next upgrade. API suite now passes: `223 passed, 339 skipped, 6 warnings`. Rust CLI local verification now passes: `cargo test --manifest-path cli/Cargo.toml` -> `6 passed`.
- **Reassessment (2026-06-09 00:27 UTC):** Verdict remains `NOT READY`, but public-route blockers are cleared. `https://app.sigilsec.ai/signup` -> `HTTP/2 200`; Playwright lands on `https://app.sigilsec.ai/login`. Pricing browser probe now has `has14DayTrial=true`, `hasTeam99=true`, `hasTeam199=false`, `has30DayTrial=false`. `https://www.sigilsec.ai/install.sh` -> `HTTP/2 307` to GitHub raw installer; `curl -sSL` returns the real `#!/usr/bin/env sh` installer. API suite passes: `223 passed, 339 skipped, 6 warnings`; Rust CLI passes: `6 passed`; dashboard tests pass: `43 passed`; dashboard build succeeds. Remaining blockers: dashboard dependency audit still exits 1 for Next/PostCSS requiring `next@16.2.7`; credentialed browser journey and Stripe test/live round trips remain owner/operator-gated.

### LAUNCH-002: Fix non-protected launch blockers from baseline
- **Status:** DONE (2026-06-09)
- **Goal:** Resolve launch-blocking issues that do not touch auth, authorization, database schema, or CI/CD configuration.
- **Done when:** LAUNCH-001 Critical/High issues outside protected areas are fixed and their original failing checks now pass.
- **Files:** `api/main.py`, `api/monitoring.py`, `api/services/scanner.py`, `api/services/scoring.py`, `dashboard/components/BulkInvestigator.tsx`, `docs/launch-readiness-report.md`, `docs/pre-production-checklist.md`, `docs/known-risks.md`, `docs/security-review.md`.
- **Evidence (2026-06-08 03:33 UTC):** Targeted scanner/monitoring/scoring slice passes: `61 passed, 3 warnings`; full API suite passes: `223 passed, 339 skipped, 6 warnings`; Rust CLI passes: `6 passed`; dashboard tests pass: `41 passed`; dashboard build succeeds. Remaining non-protected blocker is dependency audit: `npm audit --audit-level=high --omit=dev` still exits 1 because Next/PostCSS remediation requires `next@16.2.7` breaking upgrade.
- **Evidence (2026-06-09 00:27 UTC):** Public signup/pricing/installer checks now pass in live probes. Dashboard tests now include signup route coverage: `4 passed` suites, `43 passed` tests. Dashboard build succeeds with `33/33` static pages generated. Dependency audit still fails: `2 vulnerabilities (1 moderate, 1 high)`, fix requires breaking `next@16.2.7` upgrade.
- **Evidence (2026-06-09 00:49 UTC):** Activated two subagents. Next/Auth0 migration scan found `@auth0/nextjs-auth0@3.8.0` blocks `next@16.2.7` (`npm install` ERESOLVE on Auth0 peer range through Next 15.2.3). Required remediation touches protected auth files (`dashboard/src/app/api/auth/[auth0]/route.ts`, auth me/token handlers, onboarding route handlers, auth wrappers/tests, and proxy/middleware setup), so no source edits were made under probation. Aborted package-lock churn was reverted; `dashboard/package.json` and `dashboard/package-lock.json` have no diff. Fresh verification after revert: dashboard Jest passes (`4` suites, `43` tests) and `npm run build` succeeds; audit still exits 1 for Next/PostCSS.
- **Evidence (2026-06-09 01:05 UTC):** Owner approved Auth0 v4 migration. Agent team activated and HIGH-001 cleared: `npm ci` exits 0; `npm ls next react react-dom @auth0/nextjs-auth0 eslint eslint-config-next --depth=0` resolves `next@16.2.7`, `react@19.2.1`, `react-dom@19.2.1`, `@auth0/nextjs-auth0@4.22.0`, `eslint@9.39.4`, `eslint-config-next@16.2.7`; `npm run lint` exits 0 with 5 warnings; `npx tsc --noEmit` exits 0; `npm test -- --runInBand` -> 4 suites passed, 43 tests passed; `npm run build` succeeds on Next 16.2.7 and generates 32/32 static pages; `npm audit --audit-level=high --omit=dev` exits 0. Residual plain audit output still reports 2 moderate PostCSS findings nested under Next.js.
- **Notes:** Non-protected launch blockers and HIGH-001 are cleared. Protected/live areas still pending owner or operator action: credentialed browser journey and Stripe test/live round trips.

### LAUNCH-003: Security, auth, database, and CI/CD protected-change queue
- **Status:** TODO
- **Goal:** Convert protected launch blockers into owner-approval-ready change requests with exact files, risks, and verification commands.
- **Done when:** `docs/known-risks.md` lists each protected blocker, its severity, required approval, and evidence.
- **Files:** `docs/security-review.md`, `docs/known-risks.md`
- **Notes:** Auth0 v3 to v4 migration received current-session owner approval and was executed on June 9. Remaining protected/live queue: Stripe test-mode webhook audit/positive control, browser checkout completion, live $29 charge/refund, and deployment/operator evidence.

### LAUNCH-004: Browser and journey validation
- **Status:** TODO
- **Goal:** Validate core user journeys with browser evidence against the available local or deployed surface.
- **Done when:** `docs/browser-test-results.md` records personas, routes, console/network findings, screenshots where possible, and pass/fail status.
- **Files:** `docs/browser-test-results.md`
- **Notes:** Use Playwright if Vercel Agent Browser remains unavailable. June 9 Playwright probe: pricing copy and signup no-404 pass; full credentialed login/dashboard/billing journey not completed.

### LAUNCH-005: Deployment and rollback readiness docs
- **Status:** TODO
- **Goal:** Ensure launch operators have current deployment and rollback instructions grounded in verified resource graph entries.
- **Done when:** `docs/deployment-runbook.md` and `docs/rollback-runbook.md` exist and reference only `.nomark/resources.json`-verified resources or explicitly unresolved placeholders.
- **Files:** `docs/deployment-runbook.md`, `docs/rollback-runbook.md`
- **Notes:** Check `.nomark/resources.json` before writing any resource names, endpoints, or environment variables.















---

## Feature: F-008 Open-Source Core Hardening (Goal 1)

> **Created:** 2026-06-10
> **Inputs:** Ground-truth audit 2026-06-10 (session) · `docs/internal/THREAT-LANDSCAPE-2026-06.md` · `docs/internal/ARCHITECTURE-DECISIONS-2026-06.md` (D1–D7, PROPOSED)
> **Gate:** ACCEPTED by owner 2026-06-10 — BUILD unlocked. Decisions promoted to ADR-0004…ADR-0010. Goal 2 (Pro/Fable) also unlocked by the same acceptance (not yet started).
> **Standing constraints:** capability-minimal (D6 permission test on every story); no fabricated metrics; every AC is a command.

### Phase A — Hygiene & truth

### US-A1 [F-008]: Derive signature counts, never declare them
- **Status:** DONE (2026-06-10) — `threat_signatures.json` signature_count corrected 247 → 55 (derived); validator covers `threat_signatures.json` + `known_threats.json`. Demonstrated both ways: `python3 scripts/validate_corpus_counts.py` → exit 0 ("OK … 55 entries / 133 entries"); with deliberately falsified count 999 → exit 1 ("FAIL declares 999, contains 55"); restored, green. Wire into CI alongside US-D3.
- **Scope:** trivial
- **Goal:** `threat_signatures.json` metadata count is computed from entries; a validator fails CI when any corpus file's declared count ≠ actual.
- **Done when:** `python3 scripts/validate_corpus_counts.py` exits 0 after fix and exits 1 when a count is deliberately falsified in a temp copy (both demonstrated). Current state: declares 247, contains 55.
- **Files:** `api/data/threat_signatures.json`, `scripts/validate_corpus_counts.py`

### US-A2 [F-008]: Fix BadHost exposure in Sigil's own API (CVE-2026-48710)
- **Status:** DONE (2026-06-10, queue-jumped on owner approval) — `starlette==0.49.3 → 1.2.1`, `fastapi==0.128.8 → 0.136.3` (0.128.8 capped starlette <1.0.0). Verified in fresh python3.11 venv (production interpreter): lock installs exit 0; `pytest api/tests -q` → `223 passed, 340 skipped, 0 failed` (340th skip = asyncpg env artifact, diff in evidence). Middleware audit: no path-based auth existed; exposure was content-type-check skip (`security.py:290`) + rate-tier evasion (`rate_limit_enhanced.py:227`), both closed. **Prod deploy DONE 2026-06-10** (owner-approved): built `sigil-api:d4b74d3-badhost` from deployed SHA d4b74d3 + minimal patch; revision sigil-api--0000096 Running @100% traffic, old vulnerable revision deprovisioned; /health 200, investigate 401. Required a 3rd file (Dockerfile.api: dropped a fabricated 40-char base-image digest → floating tag, matching Dockerfile.bot). Evidence: `evidence/F-008/US-A2-badhost-fix.md`, `evidence/F-008/US-A2-deploy.md`.
- **Scope:** moderate
- **Goal:** `api/requirements.lock` moves starlette 0.49.3 → ≥1.0.1 (with whatever FastAPI bump that requires); middleware path checks audited for `request.url.path` auth decisions.
- **Done when:** `grep starlette== api/requirements.lock` shows ≥1.0.1; `python3 -m pytest api/tests -q` ≥ current baseline (223 passed/0 failed); `grep -rn "url.path" api/middleware/` output reviewed in evidence file.
- **Files:** `api/requirements.txt`, `api/requirements.lock`, `evidence/F-008/US-A2-badhost-fix.md`
- **Notes:** Sigil's threat-model anchor CVE must not be live in Sigil's own stack. Deploy via established `az acr build` + `containerapp update` flow (owner-gated for prod).

### Phase B — Scanner mechanics (D5)

### US-B1 [F-008]: Walker exclusions, ignore files, parallel traversal
- **Status:** DONE (2026-06-10) — ignore::WalkBuilder + rayon; self-scan `real 2.18s` (was >30min), 1170 files; hard-excludes + .sigilignore + tarball-safe .gitignore. Tests: 4 walker tests pass. Evidence: evidence/F-008/phase-B-scanner-mechanics.md
- **Scope:** moderate
- **Goal:** Rust scanner respects `.gitignore`/`.sigilignore` + hard default excludes (node_modules, .git, target, dist, .next); rayon-parallel file scan.
- **Done when:** `time ./cli/target/release/sigil scan .` on the Sigil repo completes in <60s (today: did not finish in 30min, debug build); `cargo test` passes with new walker tests.
- **Files:** `cli/src/scanner/mod.rs`, `cli/Cargo.toml`

### US-B2 [F-008]: Unicode normalization pass (PUA / bidi / zero-width)
- **Status:** DONE (2026-06-10) — scanner/normalize.rs; UNICODE-001/002/003 (PUA/bidi/zero-width), High in instruction files; normalize_for_matching de-cloaks before pattern phases; emoji ZWJ preserved. 6 unicode tests pass incl. clean-CJK negative control. Evidence: evidence/F-008/phase-B-scanner-mechanics.md
- **Scope:** moderate
- **Goal:** Pre-match normalization layer; invisible chars in instruction files (SKILL.md, CLAUDE.md, .cursorrules, tool descriptions) are themselves a High finding (GlassWorm / Rules-File-Backdoor tradecraft).
- **Done when:** `cargo test unicode` passes against fixtures containing PUA-encoded payloads, bidi-reversed strings, and zero-width-joiner injection (fixtures labeled SYNTHETIC per disclosure format); a clean file with legitimate CJK/emoji produces 0 findings.
- **Files:** `cli/src/scanner/normalize.rs` (new), `tests/fixtures/unicode/`

### US-B3 [F-008]: Context suppression — kill the .d.ts false-positive class
- **Status:** DONE (2026-06-10) — scanner/context.rs is_declaration_file; scan_code_patterns early-returns for .d.ts/.pyi. test-repo: 3 findings all malicious.js, types.d.ts now 0 (was 4 of 7). Evidence: evidence/F-008/phase-B-scanner-mechanics.md
- **Scope:** moderate
- **Goal:** Declaration files, type stubs, and Python's proven suppression contexts (UMD/polyfill/webpack preambles) stop producing code-execution findings.
- **Done when:** `./cli/target/release/sigil scan test-repo --format json` reports 0 CodePatterns findings for `types.d.ts` while `malicious.js` findings are unchanged (today: 4 of 7 findings are .d.ts declarations).
- **Files:** `cli/src/scanner/phases.rs`, `cli/src/scanner/context.rs` (new)

### US-B4 [F-008]: Honest fixture corpus
- **Status:** DONE (2026-06-10) — tests/fixtures/* + MANIFEST.json (Data Source/Sample Size/Limitations, all SYNTHETIC, traced to advisories); fixtures_tests::fixture_corpus_matches_manifest asserts phase+severity per case. Passes. Evidence: evidence/F-008/phase-B-scanner-mechanics.md
- **Scope:** moderate
- **Goal:** `tests/fixtures/` holds labeled samples per threat phase — synthetic ones marked SYNTHETIC in a manifest; real ones traced to source advisories (Shai-Hulud IOCs, postmark-mcp pattern, hermes-px pattern from published research).
- **Done when:** `cargo test fixtures` runs every fixture through the scanner and asserts expected phase + severity per manifest; manifest declares Data Source / Sample Size / Limitations for the corpus.
- **Files:** `tests/fixtures/`, `tests/fixtures/MANIFEST.json`

### Phase C — Corpus externalization (D2)

### US-C1 [F-008]: Signature-pack schema and loader
- **Status:** DONE (2026-06-11, agent+integration) — corpus/{schema,loader,mod}.rs; packs include_str!-embedded; counts derived. corpus_loader tests pass.
- **Scope:** complex
- **Goal:** Versioned pack format (id, phase, severity, weight, patterns, language scope, suppression predicates, provenance, dates); Rust loads packs at startup; counts derived.
- **Done when:** `cargo test corpus_loader` passes; `./cli/target/release/sigil scan test-repo` produces identical findings from pack-loaded rules as from a golden snapshot of today's hardcoded rules (parity test committed).
- **Files:** `cli/src/corpus/` (new), `packs/core/v1/`

### US-C2 [F-008]: Port Rust hardcoded patterns into the core pack
- **Status:** DONE (2026-06-11) — phases.rs is now thin pack dispatch (scan_file_with_packs); zero inline Regex::new in production code; 13 parity_rust tests. Integration fix: PROMPT-007 ported as bare `"""` (matched every docstring, 2467 FPs) → restored `"""\s*\n`; char-boundary panic in engine header slice fixed + regression test.
- **Scope:** complex
- **Goal:** All patterns in `phases.rs` (Phases 1–8, 10) move to `packs/core/`; `phases.rs` becomes engine logic only.
- **Done when:** Fixture-corpus parity: `cargo test parity_rust` shows identical (file, rule, severity) findings before/after on `tests/fixtures/`; `grep -c "Regex::new" cli/src/scanner/phases.rs` drops to ~0.
- **Files:** `cli/src/scanner/phases.rs`, `packs/core/v1/`

### US-C3 [F-008]: Port Python-only rules and FP filters into the pack
- **Status:** DONE (2026-06-11) — packs/core/v1/{obfuscation_chain.json (19 rules), supply_chain.json (19 rules)} ported from Python ENHANCED_OBFUSCATION_RULES + NOVEL_VECTOR_RULES; SUPPLY-003/005 lookaround rewritten for Rust regex via suppress predicates; 12 parity_python tests.
- **Scope:** complex
- **Goal:** Python's 13 supply-chain rules, 14 obfuscation-chain rules, 4 context filters, and 22-domain safe list become pack entries/predicates. Closes the cross-implementation drift found in the audit.
- **Done when:** `cargo test parity_python` — fixtures derived from each Python rule's intent produce the expected finding in Rust; suppression fixtures (UMD wrapper, polyfill, safe-domain HTTP) produce 0 findings.
- **Files:** `packs/core/v1/`, `tests/fixtures/`

### US-C4 [F-008]: Pack signing and verified updates
- **Status:** DONE (2026-06-11) — corpus/signing.rs: ed25519-dalek PackVerifier; verify() canonicalises + checks Ed25519; 5 pack_signature tests (valid/missing/tampered/wrong-key/bad-base64). Core packs are include_str!-embedded (not signature-gated); signing is for fetched packs.
- **Scope:** moderate
- **Goal:** Packs signed at publish; `sigil fetch` verifies signature before installing to `~/.sigil/`; tampered pack is rejected loudly.
- **Done when:** `cargo test pack_signature` passes including a tampered-pack rejection case; `sigil fetch --offline` uses cache without error.
- **Files:** `cli/src/corpus/verify.rs`, `cli/src/main.rs` (fetch path)

### Phase D — Output contract & self-audit CI (D7)

### US-D1 [F-008]: Exit-code contract
- **Status:** DONE (2026-06-10) — `--fail-on` (default high); exit 0/1/2 contract via pure exit_code_for(); 5 CLI cases + 5 unit tests pass. Evidence: evidence/F-008/phase-D-output-contract.md
- **Scope:** trivial
- **Goal:** 0 = below threshold, 1 = findings ≥ `--fail-on` (default high), 2 = scan error. Today bash exits 0 on CRITICAL; Rust must not repeat that.
- **Done when:** `./cli/target/release/sigil scan test-repo; echo $?` prints 1; scan of an empty dir prints 0; scan of a nonexistent path prints 2.
- **Files:** `cli/src/main.rs`, `cli/src/output.rs`

### US-D2 [F-008]: SARIF 2.1.0 output
- **Status:** DONE (2026-06-10) — SARIF 2.1.0 validates clean against official OASIS schema via check-jsonschema (exit 0). Evidence: evidence/F-008/phase-D-output-contract.md
- **Scope:** moderate
- **Goal:** `--format sarif` emits valid SARIF consumable by GitHub Code Scanning.
- **Done when:** `./cli/target/release/sigil scan test-repo --format sarif` output validates against the SARIF 2.1.0 schema (validator command recorded in evidence).
- **Files:** `cli/src/output.rs`

### US-D3 [F-008]: Self-scan as a required CI gate
- **Status:** DONE (2026-06-11) — Triaged 1073 high+crit self-findings: all category (a) self-reference-by-design (signature docs, vendored skill corpus, scanner test inputs, detection-engine source, bash scanner, synthetic fixtures) or documented scanner-FP. One category (b) genuine code smell fixed (`api/services/notifications.py` `__import__("time")` → `import time`). Rationale-backed `.sigilignore` written (scoped to specific files, NOT whole api/cli trees). After: `scan . --fail-on high` → exit 0 (0 crit, 0 high, 130 med, 36 low). Gate proven meaningful: canary `eval(__import__('os').environ)` at repo root → CODE-001+CODE-010 HIGH → exit 1; removed → exit 0. `.github/workflows/sigil-selfscan.yml` SHA-pinned, actionlint 1.7.12 clean (exit 0). Evidence: evidence/F-008/US-D3-selfscan-gate.md
- **Scope:** moderate
- **Goal:** CI job runs `sigil scan .` on the Sigil repo and fails on ≥high findings; suppressions live in `.sigilignore`/inline with written rationale (constraint: self-auditable, not a demo).
- **Done when:** `.github/workflows/sigil-selfscan.yml` exists, `actionlint` clean, and the job passes on a clean tree — meaning Phases B+C resolved or explicitly suppressed every current self-finding (bash audit verdict today: CRITICAL/250).
- **Files:** `.github/workflows/sigil-selfscan.yml`, `.sigilignore`

### Phase E — Feeds & provenance (D4)

### US-E1 [F-008]: OSV integration (CVEs + MAL- records)
- **Status:** DONE (2026-06-11)
- **Scope:** complex
- **Goal:** Lockfile/manifest dependency extraction → OSV batch query (offline-cached) → findings with OSV ids; covers npm, PyPI, crates, Go.
- **Done when:** `sigil scan tests/fixtures/osv-known-vuln/ --format json` flags a pinned known-CVE dependency and a known `MAL-` package (fixtures reference real OSV ids); network-off run uses cache and says so.
- **Files:** `cli/src/feeds/osv.rs`, `tests/fixtures/osv-known-vuln/`
- **Notes:** Two engine defects found + fixed (evidence/F-008/phase-E-feed-performance-and-suppression-reversal.md):
  (1) severity always graded High — `/v1/querybatch` returns IDs only and detail was never
  fetched; plus GitHub `MODERATE` was unmapped. Fixed with per-id `/v1/vulns/{id}` enrich +
  CVSS 3.x base-score calc + MODERATE→Medium. postcss GHSA-qx2v-qp2m-jg93 now Medium (was High).
  (2) detail fetches were sequential blocking (~0.75s each, fresh client each call) → dedup by
  id + shared keep-alive client + bounded rayon(8). osv feed now ~40-125ms warm. 104 tests pass.

### US-E2 [F-008]: KEV/EPSS prioritization overlay
- **Status:** DONE (2026-06-11)
- **Scope:** moderate
- **Goal:** Findings with CVE ids get `kev: true/false` and EPSS score; severity ordering uses KEV > EPSS > CVSS.
- **Done when:** `cargo test kev_epss` passes with recorded-fixture API responses; output JSON contains the fields for a KEV-listed fixture CVE.
- **Files:** `cli/src/feeds/`
- **Notes:** `Finding` carries `kev`/`epss` (serde default, skip-if-empty → backward-compatible JSON). Feed runs in <2µs on the self-scan (no matched KEV CVEs in our deps).

### US-E3 [F-008]: Provenance drift detection
- **Status:** DONE (2026-06-11)
- **Scope:** complex
- **Goal:** npm/PyPI attestation verification when present; findings ONLY for drift: provenance downgrade, publisher-identity change, repo mismatch. Absence is SBOM metadata, never a scored finding (<1% npm adoption = noise).
- **Done when:** `cargo test provenance_drift` passes on three fixture scenarios (downgrade, identity-change, mismatch) and asserts zero findings for an unattested-but-consistent package.
- **Files:** `cli/src/provenance/`
- **Notes:** THE infinite-hang culprit — one sequential blocking registry GET per pinned package.
  A 798-dep lockfile ran 3h40m without finishing (orphaned process found + killed). Fixed: bounded
  rayon(8) over independent per-component checks; ledger writes stay post-loop (no race). Full
  self-scan now 33s (was unbounded). `--verbose` now reports per-feed wall-clock.

### Phase E follow-ups (discovered, NOT yet done)
- **Suppression reversed:** `.sigilignore` lockfile entries (added by the Phase E build agent to
  force a green gate) are REMOVED and stay removed. They hid genuine high-severity advisories.
- **REMEDIATION-DEPS (DONE 2026-06-11):** relayed to a worktree agent; transitive-only bumps via
  `npm audit fix` (no overrides, no major direct-dep bumps, lockfiles only). mcp-server 25 High→0
  (build `npm run build` tsc clean), vscode 25 High→0 (`npm run compile` tsc clean). Independently
  re-verified with my own binary (anti-collusion): both lockfiles scan to 0 OSV high/critical; npm
  audit independently reports 0 vulns. Cherry-picked as 7600298. **Full self-scan now exit 0:
  172 findings (37 Low/135 Medium), 0 high/critical — the gate is green WITHOUT suppression.**
- **POLISH (TODO):** OSV finding-level dedup — same GHSA emits N findings when a package resolves
  at N lockfile paths. Detail-fetch is already deduped; the Finding list is not.

### Phase F — Stateful trust ledger (D3)

### US-F1 [F-008]: Approval ledger with content pinning
- **Status:** DONE (2026-06-11)
- **Scope:** complex
- **Goal:** `sigil approve` records hashes (package tarball+version, MCP tool definitions, instruction files) in a local ledger under `~/.sigil/`.
- **Done when:** `sigil approve <id> && sigil ledger show <id>` displays pinned hashes; `cargo test ledger` passes.
- **Files:** `cli/src/ledger.rs` (new), `cli/src/main.rs`
- **Notes:** `ledger::pin_directory` walks the artifact (excludes .git/node_modules/build dirs),
  sha256s each file → per-file map + aggregate `artifact_digest`, classifies instruction files
  (via `normalize::is_instruction_file`) and MCP tool-definition manifests (mcp.json/tools.json/
  package.json with mcp|mcpServers|tools key). `record_approval_in(dir,...)`/`get_in(dir,...)` take
  an explicit store dir → unit-testable without touching ~/.sigil. `cmd_approve` pins on approve
  (best-effort, warns on failure); `sigil ledger show <id>` prints digest + per-file hashes. The
  full `files` map is what US-F2 diffs. e2e demonstrated with isolated HOME (postmark-mcp@1.0.15
  fixture): approve → "pinned 3 files", ledger show → artifact + tool-def + instruction hashes.
  110 cargo tests pass (6 ledger).

### US-F2 [F-008]: Rug-pull detection on drift
- **Status:** DONE (2026-06-11)
- **Scope:** complex
- **Goal:** Re-scan of an approved artifact whose content/tool-definitions changed produces a Critical `RUGPULL-001` finding with a diff, and re-quarantines.
- **Done when:** `cargo test rugpull` passes a postmark-mcp-shaped fixture (benign at approve, BCC-exfil line added in "new version" — SYNTHETIC, modeled on the published Koi Security analysis); unchanged artifact re-scan produces 0 rug-pull findings.
- **Files:** `cli/src/ledger.rs`, `cli/src/quarantine.rs`, `cli/src/main.rs`, `tests/fixtures/rugpull/`
- **Notes:** `ledger::detect_rugpull(dir, baseline)` re-pins current content, compares the
  `artifact_digest`, and on drift emits one Critical RUGPULL-001 (weight 10) whose snippet lists
  modified/added/removed counts, a sample of changed files (always surfaces the real code change,
  e.g. index.js, not just the manifest), and flags watched tool-definition/instruction-file drift.
  Wired into the scan "all" block via `check_rugpull_for_path`: if the scanned path canonical-matches
  an Approved quarantine entry with a ledger pin, it diffs and — on drift — calls
  `quarantine::requarantine` (Approved→Pending, reason "content drift (RUGPULL-001)"). Fixtures are
  SYNTHETIC and labeled (tests/fixtures/rugpull/README.md). 3 rugpull tests + e2e (isolated HOME):
  unchanged re-scan 0 findings; v1.0.16 BCC swap → Critical RUGPULL-001 + re-quarantine. 113 tests pass.

### Phase F — COMPLETE (US-F1 + US-F2 DONE 2026-06-11). The quarantine approve/reject UX is now a
### stateful content-pinning trust ledger with rug-pull detection — ADR-0006's structural moat.

### Phase G — Unification & honest evaluation (D1)

### US-G1 [F-008]: API delegates scanning to the Rust engine
- **Status:** DONE (2026-06-11)
- **Scope:** complex
- **Goal:** `api/services/scanner.py` paths call the Rust binary (subprocess, `--format json`) behind a feature flag; Python rules frozen.
- **Done when:** `python3 -m pytest api/tests -q` ≥ baseline with flag on; a golden-file test shows API scan response schema unchanged.
- **Files:** `api/services/scanner.py`, `Dockerfile.api`, `api/tests/test_rust_engine_golden.py`
- **Notes:** Relayed to worktree agent, INDEPENDENTLY RE-VERIFIED by me (anti-collusion). Flag
  `SIGIL_RUST_ENGINE` (default OFF). Flag OFF = Python rules unchanged (224 passed ≥ baseline 223);
  flag ON routes scan_directory→Rust subprocess, maps findings into existing Finding objects (226
  passed); golden test asserts identical response schema in both modes (3 passed). Python Rule set
  frozen (untouched). Binary missing + flag ON = raise (no silent fallback). Dockerfile.api: documented
  TODO block only (binary not yet bundled; flag stays OFF in image). Merged as 20088ae.

### US-G2 [F-008]: bash CLI delegates to Rust
- **Status:** DONE (2026-06-11)
- **Scope:** moderate
- **Goal:** `bin/sigil scan|clone|pip|npm` exec the Rust binary when present (bootstrap-installs it when not); bash pattern phases removed from the scan path.
- **Done when:** `./bin/sigil scan test-repo; echo $?` returns the Rust exit contract (1) in <10s; `./bin/sigil clone <small-repo>` round-trips quarantine via Rust.
- **Files:** `bin/sigil`
- **Notes:** Relayed to worktree agent, INDEPENDENTLY RE-VERIFIED by me: `./bin/sigil scan test-repo`
  → exit 1 (<10s) emitting real Rust JSON (3 findings), not bash phases. `resolve_rust_bin`: SIGIL_BIN
  → PATH → cli/target/release → bootstrap-exit (no bash fallback, preserves single-engine ADR-0004).
  clone/pip/npm + approve/reject/list delegate to Rust → one quarantine store. The agents' exit-2
  observations were stale-base/homebrew-v1.0.4 binaries; my HEAD binary honors ADR-0010 exit-1 on
  both cache and fresh paths (verified). Merged as 114794c.

### US-G3 [F-008]: Honest evaluation harness (replaces the 97.96% lineage)
- **Status:** DONE (2026-06-11)
- **Scope:** complex
- **Goal:** Recall/precision measured against the Datadog malicious-packages dataset (27,813 human-triaged npm/PyPI samples) + clean-package control set; results published with Data Source / Sample Size / Limitations; **no `random` anywhere in evaluation code** (CI-greppable).
- **Done when:** `python3 scripts/run_eval.py --dataset datadog --out evaluation_results/` writes a report whose numbers are reproducible on a second run (same dataset hash); `grep -rn "import random" scripts/run_eval.py` returns nothing; report explicitly supersedes `production_d1_d4_scorecard_80k_scans.json`, which is moved to `archive/` with a provenance note.
- **Files:** `scripts/run_eval.py`, `evaluation_results/`, `archive/`
- **Notes:** REAL measurement, current engine (sigil 1.1.2), 351 real Datadog samples (110/bucket ×4,
  commit 605a7318), 20 popular real control packages. Deterministic (sorted per-bucket, no random —
  grep PASS), reproducible (identical fingerprint 5f7ebb09… + recall across two runs). Old scorecard
  moved to archive/ with provenance note. **Honest numbers (they ship): recall 96.87% @any, 93.73%
  @High, 61.54% @Critical. BUT FP-rate 95% @High — 19/20 popular legit packages (requests/flask/
  express/react/lodash) flagged High.** Report states this loudly + caveats that "precision 94.5%" is
  class-imbalance-distorted (351:20). Surfaced follow-up: FP-NARROWING needed before High can gate
  real installs. Engine resolution gotcha: harness picked homebrew sigil v1.0.4 off PATH first — must
  pin SIGIL_BIN. Samples NOT committed (live in /tmp; raw-CDN fetch, git promisor was unusable).
- **Follow-up (FP-NARROWING, DONE 2026-06-11):** eval-driven rule tuning, measured at every step.
  Clear rule BUGS fixed (near-zero recall cost): CODE-002 `\bexec\(` matched JS `regex.exec(` →
  now `(?m)(^|[^.\w])exec\(` (child_process.exec stays covered by CODE-007); SUPPLY-007's
  `module.exports=…require(` matched every re-export → now requires a DYNAMIC (non-literal) require
  arg. Redundant generics downgraded to their precise chain-rule equivalents (CODE-010→med [vs
  OBFUSC-CHAIN-017], OBFUSC-004→med [vs -CHAIN-014], OBFUSC-CHAIN-012→med [vs OBFUSC-008], pickle
  CODE-004 critical→high [obfuscated form stays critical via -CHAIN-004]). Benign-context suppressions
  (CRED-008 docs/examples, OBFUSC-006/007 test hex, NET-008 test sockets). **Result: FP@High 95%→70%,
  FP@Critical 30%→20%, for recall@High 93.7%→90.3% (recall@Medium held 96.6%).** 5 FP-regression
  tests lock the bug-fixes (118 cargo tests). **Honest limit reached:** the residual 70% FP is
  GENUINE dual-use patterns (eval/exec/pickle/child_process/private-keys) that popular legit packages
  (requests/flask/numpy/jinja2) really contain — pattern scanning alone cannot distinguish these from
  malice. The real discriminators are the precise chain rules + the Phase-F trust ledger (allowlist
  known-good). Logged as the next structural lever, not a rule-tuning problem.

### Phase G — COMPLETE (US-G1 + US-G2 + US-G3 DONE 2026-06-11). One Rust detection engine; API and
### bash both delegate to it; the fabricated scorecard is retired for a real, reproducible eval.
### F-008 Goal 1 (open-source core hardening) is COMPLETE across Phases A–G.

### F-008 carried-forward follow-ups (not blocking; logged honestly):
- FP-NARROWING (above) — highest-value next detection work; the honest eval quantified it (95% @High).
- OSV finding-level dedup (Phase E polish) — same GHSA emits N findings across N lockfile paths.
- Dockerfile.cli fabricated base digest — documented earlier; same defect class as the BadHost
  Dockerfile.api fix; not yet remediated.
- Dockerfile.api: bundle the Rust binary + flip SIGIL_RUST_ENGINE on in-image (US-G1 left a TODO).
- bin/sigil dead bash phase functions remain defined (only `fetch`/run_full_audit still references
  them); remove when `fetch` is migrated.

---

## Feature: F-009 Sigil Pro Tier + Fable Integration (F-008 Goal 2) — COMPLETE + DEPLOYED 2026-06-12

> **Status:** 12/12 DONE + verified. US-112 closed 2026-06-12 — live Fable-5 adjudication through prod (async, no 504) + metering usage row verified in `credit_transactions` (scan, -3, claude-fable-5, 318 tokens; user_credits balance 5000→4997). Prod rev `sigil-api--0000108` (image `2eff98f`). Evidence: `evidence/F-009/US-112-ops-verification.md`.
> **US-112 deploy/fix trail (2026-06-12):** five defects to land a usage row — (1) `except db.DatabaseError`→`pyodbc.Error`; (2) `initialize_user_credits` tier source; (3) prod-compatible credits migration `add_credits_system_prod.sql` (UNIQUEIDENTIFIER FK, applied); (4) async adjudication (`POST` 202 + `GET` poll, `LLM_TIMEOUT` 30→120s) to fix a Fable-5 edge-proxy 504; (5) **root cause** — `credit_service` data layer ported off asyncpg-style `fetch_one`/`execute`/`fetch_all` to the real `MssqlClient` API. Commits `84b7ce1`, `1121136`, `2eff98f`. CLI `sigil explain` now polls. Known follow-up: `purchase_credits`/`credit_packages` (Stripe top-ups) still on old API, out of scope.
> **Feature evidence:** `.nomark/evidence/sigil-pro-fable-complete.md` (AC table, final test runs, latent-bug list)
> **US-110 headline (2026-06-12):** FP@High 70%→30% (89/89 control verdicts benign), malicious retention 24/25 by verdict, 0 refusals in 168 live Fable 5 calls — SHIP recommendation in `evidence/F-009/fp-adjudication-eval.md`
> **Final integration run:** api 301 passed/0 failed (baseline 276) · cli 132+4 passed/0 failed (baseline 123)
> **Created:** 2026-06-11 (planned via /plan_feature; owner approved SOLUTION.md entry + scope same session)
> **PRD:** `tasks/prd-sigil-pro-fable.json` (status: approved)
> **Scope decisions (owner, 2026-06-11):** full capability scope (FP adjudication + triage/explanation + CLI + attack-chain) · Fable 5 with Opus 4.8 refusal-fallback, Haiku 4.5 for cheap paths · free-teaser + Pro-unlimited gating
> **Ground truth driving this feature:** `llm_config.py` defaults to `gpt-4-turbo`; `model_router.py` pins retired claude-3 models (claude-3-opus/sonnet-2024 retired; claude-3-haiku retires 2026-04-19); F-008 eval's residual 70% FP@High is dual-use patterns needing an LLM discriminator.
> **Standing constraints:** exact model IDs `claude-fable-5` / `claude-opus-4-8` / `claude-haiku-4-5` (no date suffixes); Fable 5 omits `thinking` param, no sampling params, no prefill, handle `stop_reason: "refusal"` before reading content; org needs 30-day retention; check `.nomark/resources.json` before any env/infra reference; no fabricated metrics (US-110 eval is real-data only).
> **Cross-feature note:** F-010 (trust-ledger allowlisting) attacks the same FP@High residual from the workflow side; US-110's eval should report adjudication's contribution separately from ledger suppression.

### US-101 [F-009]: Anthropic-first LLM config with current model registry
- **Status:** DONE (2026-06-11, autopilot) — 15/15 new tests pass; full suite 239 passed/0 failed (baseline 223, delta = new tests). ANTHROPIC_API_KEY fallback added (anthropic provider only). Evidence: `.nomark/evidence/US-101.md`
- **Scope:** moderate
- **Goal:** `llm_config.py` defaults to Anthropic with `claude-opus-4-8` default / `claude-fable-5` deep / `claude-haiku-4-5` fast (env-overridable); `gpt-4-turbo` default gone.
- **Done when:** `python3 -m pytest api/tests/test_llm_config.py -q` exits 0
- **Files:** `api/llm_config.py`, `api/tests/test_llm_config.py`
- **Dependencies:** none

### US-102 [F-009]: Model router registry refresh — retire claude-3 tiers
- **Status:** DONE (2026-06-11, autopilot) — registry = exactly 3 current IDs, multipliers 1/5/10; scorer now llm_config-driven (scope expansion to complexity_scorer.py owner-approved); legacy test_model_routing.py assertions updated (pre-authorized mechanical swap). 17/17 routing tests, full suite 251 passed/0 failed. Evidence: `.nomark/evidence/US-102.md`
- **Scope:** moderate
- **Goal:** `model_router.py` MODELS = exactly {claude-haiku-4-5 $1/$5, claude-opus-4-8 $5/$25, claude-fable-5 $10/$50}; downgrade path → haiku.
- **Done when:** `python3 -m pytest api/tests/test_model_router.py -q` exits 0; no `claude-3-` in file
- **Files:** `api/services/model_router.py`, `api/tests/test_model_router.py`
- **Dependencies:** US-101

### US-103 [F-009]: Refusal handling + Opus 4.8 fallback in llm_service
- **Status:** DONE (2026-06-11, autopilot) — LLMRefusalError typed+terminal (excluded from tenacity retries); deep-model refusal retries once on llm_config.model; partials discarded; anthropic payloads drop temperature/thinking. 5/5 mocked cases; full suite 256 passed/0 failed. Evidence: `.nomark/evidence/US-103.md`
- **Scope:** complex
- **Goal:** Fable 5 refusal (pre-output or mid-stream) retries once on `claude-opus-4-8`; fallback refusal → typed error. Fable calls omit `thinking` and sampling params.
- **Done when:** `python3 -m pytest api/tests/test_llm_refusal_fallback.py -q` exits 0 (4 mocked cases: pre-output refusal, mid-stream refusal, fallback success, fallback refusal)
- **Files:** `api/services/llm_service.py`, `api/tests/test_llm_refusal_fallback.py`
- **Dependencies:** US-101

### US-104 [F-009]: LLM usage metering — free teaser allowance + Pro fair-use
- **Status:** DONE (2026-06-11, autopilot) — check_llm_allowance (structured 402-able denial) + record_llm_usage (via existing sp_DeductCredits, NO schema change) + CREDIT_RATES refresh (1/5/10 per pricing) + LLM_FREE_MONTHLY_CREDITS env override. 11/11 tests; full suite 267 passed/0 failed. Evidence: `.nomark/evidence/US-104.md`
- **Scope:** complex
- **Goal:** `credit_service.check_llm_allowance` / `record_llm_usage`; free = 10 calls/month (config), Pro = metered fair-use; structured denial with reset date + upgrade URL. Reuse existing tables (CHARTER II.5 — no new schema without approval).
- **Done when:** `python3 -m pytest api/tests/test_llm_metering.py -q` exits 0
- **Files:** `api/services/credit_service.py`, `api/tests/test_llm_metering.py`
- **Dependencies:** US-101

### US-105 [F-009]: AI-analysis gate dependency — 402 on exhausted free tier
- **Status:** DONE (2026-06-11, autopilot, **with documented AC deviation**) — require_llm_access added (owner-approved CHARTER II.5): Pro+ unmetered-pass, free 402 on exhaustion with structured payload. New cases 5/5 green (`SIGIL_RUN_EXTENDED_TESTS=1 ... -k RequireLlmAccess`); default suite 267/0. DEVIATION: whole-file exit-0 unachievable — 8 pre-existing failures at HEAD (stash-verified) wedge the session-scoped event loop for subsequent async tests. Follow-up logged: repair extended tier-gating suite + conftest event_loop migration. Evidence: `.nomark/evidence/US-105.md`
- **Scope:** moderate
- **Goal:** `require_llm_access` in `api/gates.py`: Pro/Team pass; free passes while allowance remains; 402 + upgrade payload when exhausted; 401 unauthenticated.
- **Done when:** `python3 -m pytest api/tests/test_tier_gating.py -q` exits 0 incl. new free-teaser cases
- **Files:** `api/gates.py`, `api/tests/test_tier_gating.py`
- **Dependencies:** US-104

### US-106 [F-009]: FP adjudication service (Fable 5, structured verdict)
- **Status:** DONE (2026-06-11, autopilot) — fp_adjudicator service with enum-locked json_schema verdicts via deep model + US-103 fallback path; 8K context bound; AdjudicationError contract. Additive output_config passthrough on call_llm_api (preserved across fallback retry). 9/9 tests; full suite 276 passed/0 failed. Evidence: `.nomark/evidence/US-106.md`
- **Scope:** complex
- **Goal:** `fp_adjudicator` service: finding + bounded code context → structured `{classification: benign_dual_use|suspicious|malicious, confidence, rationale}` via json_schema output; deep_model through US-103 fallback path.
- **Done when:** `python3 -m pytest api/tests/test_fp_adjudicator.py -q` exits 0
- **Files:** `api/services/fp_adjudicator.py`, `api/tests/test_fp_adjudicator.py`
- **Dependencies:** US-103

### US-107 [F-009]: FP adjudication endpoint wired into scan results
- **Status:** DONE (2026-06-11, autopilot) — evidence: `.nomark/evidence/US-107.md`
- **Scope:** moderate
- **Goal:** `POST /v1/scans/{id}/findings/{finding_id}/adjudicate` behind `require_llm_access`; verdict persisted in `findings_json` (no schema change); idempotent.
- **Done when:** `python3 -m pytest api/tests/test_adjudicate_endpoint.py -q` exits 0 — VERIFIED: 7 passed; full suite 283 passed/0 failed
- **Files:** `api/routers/scan.py`, `api/tests/test_adjudicate_endpoint.py`, `api/services/fp_adjudicator.py` (`_usage` estimates), `api/main.py` (coupled: http_exception_handler stringified dict details, breaking the approved US-105 402 contract at the app boundary — dicts now pass through as JSON)
- **Dependencies:** US-105, US-106
- **Notes:** Refusal→422 `{reason: llm_refusal, category}`, unmetered. Metering best-effort (warn, never discard paid verdict). `_usage` token counts are estimates (~4 chars/token) — raw HTTP path has no usage object.

### US-108 [F-009]: Modernize finding investigator + explanations
- **Status:** DONE (2026-06-11, autopilot) — evidence: `.nomark/evidence/US-108.md`
- **Scope:** moderate
- **Goal:** Both services call through `llm_service` with config-driven models; no hardcoded/retired IDs; routes gated.
- **Done when:** `python3 -m pytest api/tests -q -k "investigator or explanations"` exits 0; `grep -rn "claude-3-" api/services/finding_investigator.py api/services/explanations.py` empty — VERIFIED: 9 passed; grep empty; full suite 292 passed/0 failed
- **Files:** `api/services/finding_investigator.py`, `api/llm_models.py` (+`model` field), `api/services/llm_service.py` (threads request.model), `api/routers/interactive.py` (mechanical: retired default + docstrings), `api/tests/test_finding_investigator.py`
- **Dependencies:** US-105
- **Notes:** explanations.py needed nothing (static registry, no LLM). Investigator was non-functional before: `SCAN_COSTS["investigate_finding"]` KeyError, `LLMAnalysisType.VULNERABILITY_ANALYSIS` AttributeError, and the hasattr-guarded config mutation never applied the depth model. Model override now travels with `LLMAnalysisRequest`. Route gating unchanged (require_plan PRO, pre-existing).

### US-109 [F-009]: Modernize remediation generator + attack-chain tracer
- **Status:** DONE (2026-06-11, autopilot) — evidence: `.nomark/evidence/US-109.md`
- **Scope:** moderate
- **Goal:** Both call through `llm_service` (attack-chain = deep_model); no retired IDs.
- **Done when:** `python3 -m pytest api/tests -q -k "remediation or attack_chain"` exits 0 — VERIFIED: 7 passed/1 skipped; full suite 298 passed/0 failed
- **Files:** `api/services/remediation_generator.py`, `api/services/attack_chain_tracer.py`, `api/llm_models.py` (+`custom_prompt`), `api/services/llm_service.py` (honours custom_prompt; reports request model), `api/tests/test_remediation_attack_chain.py`
- **Dependencies:** US-105
- **Notes:** Both paths were latently broken: remediation used nonexistent `LLMAnalysisType.VULNERABILITY_ANALYSIS`; tracer assigned `custom_prompt` post-construction (Pydantic v2 ValueError → every trace returned the fallback chain). Attack chain now deep_model end-to-end (deduction record + LLM request).

### US-110 [F-009]: Honest FP-adjudication eval on the F-008 corpus
- **Status:** DONE (2026-06-12, autopilot; owner unblocked Anthropic billing) — evidence: `evidence/F-009/fp-adjudication-eval.md` + `.json`
- **Scope:** complex
- **Goal:** Real before/after FP@High + recall@High with adjudication applied, on the F-008 eval set (real malicious samples + 20 popular-legit packages). Disclosure block mandatory. Report both directions even if unfavorable.
- **Done when:** `evidence/F-009/fp-adjudication-eval.md` exists with measurements + ship/no-ship recommendation; no `random`, no synthetic-as-production — VERIFIED: 168 real claude-fable-5 verdicts, deterministic sampling, disclosure block, both directions, SHIP recommendation
- **Files:** `scripts/eval_fp_adjudication.py`, `evidence/F-009/fp-adjudication-eval.{md,json}`
- **Dependencies:** US-106
- **Headline:** FP@High 70%→30% package-level (89/89 control findings benign, residual is purely the 10-findings/pkg cap); malicious sample retention 24/25 (96%), all 24 retained by verdict not cap; the 1 cleared sample's High findings were registry-metadata noise, not payload. 0 refusals/0 errors in 168 live calls. SHIP with conditions (explicit-benign-only clearing; per-finding triage not bulk suppression; US-112 before prod).
- **Notes:** Was BLOCKED 2026-06-11 on Anthropic credit (400 billing error); owner topped up 2026-06-12. First live Fable 5 call exposed the thinking-block bug (fixed in `e5b340c`). Malicious samples are encrypted zips (not extracted dirs) — script extracts with the dataset's documented unlock phrase, same as run_eval.py. Round 2 ran with `--reuse-control` to avoid re-paying the 89 control verdicts.

### US-111 [F-009]: sigil explain — Rust CLI surface for LLM analysis
- **Status:** DONE (2026-06-11, autopilot) — evidence: `evidence/F-009/US-111-cli-explain.md`
- **Scope:** complex
- **Goal:** `sigil explain <scan-json> [--finding N]` posts the finding to the API with the user's token, renders verdict + rationale; 402 → clear upgrade message; no client-side LLM call (D6).
- **Done when:** `cargo test --manifest-path cli/Cargo.toml explain` passes; transcript in `evidence/F-009/US-111-cli-explain.md` — VERIFIED: 3 unit + 4 integration passed; full CLI suite 132+4 passed/0 failed; transcript captured (real binary, real axios scan, mock API — live e2e blocked with US-110)
- **Files:** `cli/src/main.rs`, `cli/src/explain.rs`, `cli/tests/explain.rs`, `cli/src/api.rs` (load_token → pub(crate))
- **Dependencies:** US-107
- **Notes:** Normalizes CLI→API field mismatches (phase CamelCase→snake_case, severity→UPPER). No new deps (stdlib TcpListener mock). `--finding` long-only (`-f` collides with global `--format`). Follow-up logged: legacy `--submit` ScanResponse expects `id` but API returns `scan_id`.

### US-112 [F-009]: Ops verification — env, retention, live smoke
- **Status:** TODO (owner/operator-gated: live Azure + Anthropic org access)
- **Scope:** moderate
- **Goal:** Evidence that ANTHROPIC_API_KEY is on `sigil-api` (secretRef names only), org meets Fable 5's 30-day retention, one live Fable call (or its Opus fallback) succeeds, free-tier 402 / Pro 200 round-trip, usage row visible.
- **Done when:** `evidence/F-009/US-112-ops-verification.md` complete; new resource refs added to `.nomark/resources.json`
- **Files:** `evidence/F-009/US-112-ops-verification.md`
- **Dependencies:** US-107, US-108

---

## Feature: Trust-Ledger Allowlisting (F-010) — COMPLETE 2026-06-11 ✅

> **PRD:** `tasks/prd-trust-ledger-allowlisting.md` (approved 2026-06-11) — 3/3 stories DONE, 0 blocked
> **Feature evidence:** `.nomark/evidence/F-010-trust-ledger-allowlisting-complete.md`
> **Headline:** approved-content scans now suppress (warm FP 0%, exit 0); recall untouched
> (recall_delta 0 over 351 malicious samples); cold FP@High 70% unchanged — the honest
> detector metric. Rejection revokes pins; drift always wins; cache re-evaluates per scan.
> **Note:** pre-existing uncommitted changes (`sigil-skill/*`, `.nomark/*` telemetry, F-009
> session artifacts) are from other sessions and excluded from F-010 commits.

### US-H1: Digest-keyed ledger match API
- **Status:** DONE ✅ (2026-06-11 — `cargo test ledger::tests` 14/14 incl. 5 new, full suite 123/123; evidence `.nomark/evidence/US-H1.md`)
- **Design note (deviation from PRD sketch):** `match_approved` returns `Option<LedgerRecord>` (exact digest match only). Drifted content returns `None` — drift attribution/re-quarantine already lives in the path-bound `check_rugpull_for_path` (main.rs:1434); duplicating drift detection by content was redundant. Added `ledger::remove(id)` so US-H2 can revoke pins on `sigil reject` — without it, an approve-then-reject package would keep suppressing (violates PRD semantics #5).
- **Scope:** moderate
- **Goal:** `ledger::match_approved(path)` computes the ContentPin of a scan target and returns the approved LedgerRecord on exact `artifact_digest` match, distinguishing match vs drift vs none.
- **Done when:** `cd cli && cargo test ledger::tests` green incl. new tests (digest match; drift signal; rejected/pending never match).
- **Files:** `cli/src/ledger.rs`
- **Dependencies:** none

### US-H2: Scan-time suppression + `--ignore-ledger` flag
- **Status:** DONE ✅ (2026-06-11 — `cargo test` 129/129 incl. 6 new; 11-scenario e2e with hermetic HOME; evidence `.nomark/evidence/US-H2.md`)
- **Design note:** suppression attribution is result-level (`ScanResult.suppressed_findings` + `suppressed_by`), not per-Finding — all-or-nothing semantics make a per-finding field redundant and it would touch 22 construction sites. Scoring fns unchanged (recompute over active set). `output.rs` JSON summary stays array-free so `run_eval.py`'s first-array parser is unaffected. `cmd_reject` now revokes the ledger pin.
- **Scope:** complex
- **Goal:** `cmd_scan` suppresses findings (marked `suppressed_by`, excluded from score/verdict) when content digest-matches an approved ledger record; drift never suppresses; flag bypasses.
- **Done when:** `cd cli && cargo test` green incl. suppression, drift-no-suppress, flag-bypass, and serde tests.
- **Files:** `cli/src/scanner/mod.rs`, `cli/src/main.rs`, `cli/src/ledger.rs`, `cli/src/scanner/scoring.rs`
- **Dependencies:** US-H1

### US-H3: Eval ledger-warm mode + honest FP re-measure
- **Status:** DONE ✅ (2026-06-11 — full 351-sample + 20-control run, exit 0: warm FP 0% all thresholds, cold FP unchanged (70% @High), recall_delta 0; evidence `.nomark/evidence/US-H3.md`)
- **Note:** eval `resolve_binary` now prefers repo build over PATH — a stale Homebrew sigil 1.0.4 on PATH was silently measured in the first smoke run (measurement-integrity fix). Warm metrics nest under `ledger_warm` key in the report JSON.
- **Scope:** moderate
- **Goal:** `run_eval.py --ledger-warm` measures cold AND warm control FP (warm = control set approved into a hermetic `HOME` ledger); asserts recall delta is zero; report discloses warm FP is true-by-construction workflow suppression, not detector precision.
- **Done when:** Eval run vs `/tmp/evalset/samples` + `/tmp/control2` completes; JSON has `control_flagged_cold`/`control_flagged_warm`/`recall_delta: 0`; disclosure present.
- **Files:** `scripts/run_eval.py`, `evaluation_results/`
- **Dependencies:** US-H2

---

## Bugfix Log

### BUGFIX: Scanner announcement docs links 404 (2026-06-12)
- **Status:** DONE ✅ (2026-06-12, Codex)
- **Scope:** trivial
- **Goal:** `/docs/changelog` and `/docs/scanner-v2` from the enhanced scanner banner resolve to dashboard-owned pages instead of 404.
- **Done when:** Dashboard regression test proves the banner links point to existing app routes, `npm run build` includes both docs routes, and lint remains clean aside from known warnings.
- **Files:** `dashboard/src/app/docs/changelog/page.tsx`, `dashboard/src/app/docs/scanner-v2/page.tsx`, `dashboard/src/__tests__/components/SubscriptionManager.routes.test.ts`, `progress.md`
- **Evidence:** Live probes showed both `https://app.sigilsec.ai/docs/changelog` and `https://www.sigilsec.ai/docs/changelog` return 404, so redirecting to the public site would not fix the link. `npm test -- --runInBand SubscriptionManager.routes.test.ts` passed 5/5. `npm run build` exited 0 and generated 34/34 static pages, including `/docs/changelog` and `/docs/scanner-v2`. `npx tsc --noEmit` exited 0 after build refreshed Next route types. `npm run lint` exited 0 with the same 5 pre-existing warnings.
- **Notes:** Added dashboard-owned static docs pages for the scanner v2 improvement link and changelog link; no production deploy has been run yet.

### BUGFIX: Dashboard Auth0 session token and Pro credit API routing (2026-06-12)
- **Status:** DONE ✅ (2026-06-12, Codex)
- **Scope:** moderate
- **Goal:** Authenticated dashboard pages send a real Auth0 bearer token to the Sigil API and Pro credit widgets stop calling dead `/api/v1/billing/credits/*` routes.
- **Done when:** Dashboard tests covering API route usage pass, `npm run build` succeeds, and live/header probes confirm API CORS is not the remaining blocker.
- **Files:** `dashboard/src/lib/api.ts`, `dashboard/src/components/CreditUsageDashboard.tsx`, `dashboard/src/components/ProOnboardingFlow.tsx`, `dashboard/src/components/CreditPurchase.tsx`, dashboard regression tests.
- **Evidence:** Live probes with `Origin: https://app.sigilsec.ai` returned `access-control-allow-origin: https://app.sigilsec.ai` for `https://api.sigilsec.ai/dashboard/stats`, `https://api.sigilsec.ai/scans?page=1&per_page=5`, and the OPTIONS preflight, so backend CORS was not the remaining blocker. `npm test -- --runInBand SubscriptionManager.routes.test.ts` passed 4/4; `npx tsc --noEmit` exited 0; `npm run build` exited 0 on Next 16.2.7 and generated 32/32 static pages; `npm run lint` exited 0 with 5 pre-existing warnings.
- **Notes:** Root cause was missing dashboard bearer token retrieval after Auth0 v4 migration: `dashboard/src/lib/api.ts` called `/auth/access-token`, but the checked-in route is `/api/auth/token`. Pro credit widgets also called dead same-origin paths (`/api/v1/billing/credits/usage` and `/api/v1/billing/credits/purchase`); they now use shared API helpers backed by existing FastAPI routes `/v1/interactive/credits` and `/v1/billing/purchase-credits`. Credit package IDs were aligned to backend numeric IDs `1..4`.

### BUGFIX: POST /v1/scan 422 "Bad request" on valid bodies (2026-06-08)
- **Status:** DONE ✅
- **Symptom:** `POST /v1/scan` (and every other `Depends(RateLimiter(...))`-protected endpoint) returned `422 {"detail":"Bad request"}` on valid JSON bodies, on Python 3.11 (Docker/CI) and 3.9 (local).
- **Root cause:** `api/rate_limit.py` had `from __future__ import annotations`, stringising `RateLimiter.__call__`'s `request: Request` to `"Request"`. `RateLimiter` is used as a class-*instance* dependency; FastAPI resolves annotations via `getattr(call, "__globals__", {})`, and an instance has no `__globals__`, so the forward ref evaluated against an empty namespace and stayed `ForwardRef('Request')`. FastAPI then failed to recognise the special `Request` param and registered `request` as a **required query parameter** → 422 `Field required (query, request)`. The global `RequestValidationError` handler masked the real detail as `"Bad request"`.
- **Fix:** Removed `from __future__ import annotations` from `api/rate_limit.py` (so `request: Request` is a real class object) and converted `key_prefix: str | None` → `Optional[str]` for 3.9 compatibility. Added a regression-guard comment.
- **Blast radius:** `RateLimiter` is the only callable-class dependency in `api/`; one fix covers scan (×4), metrics, billing, email, rescan.
- **Evidence:** `api/tests/test_scan.py` 8/8 pass (were failing pre-fix). Initial full `api/` suite after this rate-limiter fix: 210 passed, 13 failed — all 13 pre-existing and unrelated to rate limiting. Superseded by launch-readiness reassessment fixes: full `api/` suite now passes with `223 passed, 339 skipped, 6 warnings`. Field-level check: `RateLimiter query=[] req_param=request`.
- **Follow-up (DONE, owner-approved 2026-06-08):** The `RequestValidationError` handler in `api/main.py` flattened every client validation error to `{"detail":"Bad request"}`, which made this near-undebuggable and gave API callers no actionable detail. Now returns `{"detail":"Validation error","errors":[{loc,msg,type},...]}` — actionable field locations while sanitising the raw Pydantic error (drops `input`/`ctx`/`url`, which echo the caller's submitted data and leak internals). Regression test in `api/tests/test_scan.py::test_submit_scan_validation_error` asserts both the actionable shape and that a submitted canary value is never echoed back.
