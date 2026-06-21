# Sigil — OpenShell-Inspired Features

## Feature: F-003/F-005 Production Hardening Sweep

### STORY-200: Dashboard auth CSRF/session gaps — DONE ✅ (2026-04-11)
- **Status:** DONE
- **Scope:** complex
- **Goal:** Address critical auth security issues identified in dashboard audit
- **Done when:** All critical auth vulnerabilities addressed with tests
- **Files:** `dashboard/src/**`
- **Notes:** Completed 2026-04-11. Covered CSRF protection, session validation, token refresh.

### STORY-201: API rate limiting + input validation hardening — DONE ✅ (2026-04-11)
- **Status:** DONE
- **Scope:** complex
- **Goal:** Add rate limiting and strengthen input validation across API endpoints
- **Done when:** Rate limiting active, validation tests pass
- **Files:** `api/**`
- **Notes:** Completed 2026-04-11.

### STORY-202: Stripe webhook signature verification — DONE ✅ (2026-04-12)
- **Status:** DONE
- **Scope:** moderate
- **Goal:** Verify Stripe webhook payloads with signature checking
- **Done when:** Webhook handler verifies Stripe-Signature header; test with invalid sig returns 400
- **Files:** `api/routers/billing.py`, `api/tests/test_billing.py`
- **Notes:** Completed 2026-04-12.

### STORY-203: Container App secrets audit — DONE ✅ (2026-04-13)
- **Status:** DONE
- **Scope:** moderate
- **Goal:** Audit and document all secrets in Container App environment
- **Done when:** All secrets documented in `.nomark/resources.json`
- **Files:** `.nomark/resources.json`
- **Notes:** Completed 2026-04-13.

### STORY-204: Dependency vulnerability sweep — DONE ✅ (2026-04-14)
- **Status:** DONE
- **Scope:** moderate
- **Goal:** Address high/critical CVEs in npm and Python dependencies
- **Done when:** `npm audit --audit-level=high` and `pip-audit` pass
- **Files:** `package.json`, `api/requirements.txt`
- **Notes:** Completed 2026-04-14.

---

## Phase 1 — Foundation (OpenShell parity)

### STORY-001: Rust scanner binary skeleton — DONE ✅
- **Status:** DONE
- **Scope:** complex
- **Goal:** Scaffold the Rust CLI with basic scan command
- **Done when:** `cargo build` succeeds; `./sigil scan --help` outputs usage
- **Files:** `cli/Cargo.toml`, `cli/src/main.rs`
- **Notes:** Completed early in project.

### STORY-002: Python API skeleton with health endpoint — DONE ✅
- **Status:** DONE
- **Scope:** moderate
- **Goal:** FastAPI app with `/health` returning `{status: ok}`
- **Done when:** `curl http://localhost:8000/health` returns 200
- **Files:** `api/main.py`
- **Notes:** Completed early in project.

### STORY-003: Docker + docker-compose dev stack — DONE ✅
- **Status:** DONE
- **Scope:** moderate
- **Goal:** `docker-compose up` starts API + dashboard
- **Done when:** All services start; health checks pass
- **Files:** `Dockerfile`, `docker-compose.yml`
- **Notes:** Completed early in project.

### STORY-004: Azure Container Apps Terraform — DONE ✅
- **Status:** DONE
- **Scope:** complex
- **Goal:** Terraform config deploys API and dashboard to Azure Container Apps
- **Done when:** `terraform apply` succeeds; services accessible
- **Files:** `sigil-infra/azure/**`
- **Notes:** Completed; lives in sigil-infra repo.

### STORY-005: GitHub Actions CI pipeline — DONE ✅
- **Status:** DONE
- **Scope:** moderate
- **Goal:** CI runs tests and build on every PR
- **Done when:** `.github/workflows/ci.yml` passes on PR
- **Files:** `.github/workflows/ci.yml`
- **Notes:** Completed.

### STORY-006: Auth0 integration — DONE ✅
- **Status:** DONE
- **Scope:** complex
- **Goal:** Auth0 JWT validation on API; login/logout on dashboard
- **Done when:** Protected endpoints return 401 without token; dashboard login works
- **Files:** `api/auth.py`, `dashboard/src/app/api/auth/**`
- **Notes:** Completed.

### STORY-007: Basic scan endpoint — DONE ✅
- **Status:** DONE
- **Scope:** complex
- **Goal:** `POST /v1/scan` accepts a repo URL and returns scan results
- **Done when:** Test scan returns findings JSON
- **Files:** `api/routers/scan.py`
- **Notes:** Completed.

### STORY-008: Dashboard scan UI — DONE ✅
- **Status:** DONE
- **Scope:** complex
- **Goal:** Dashboard scan form submits to API and displays results
- **Done when:** Scan form works end-to-end in browser
- **Files:** `dashboard/src/app/**`
- **Notes:** Completed.

### STORY-009: Rust CLI scan command — DONE ✅
- **Status:** DONE
- **Scope:** complex
- **Goal:** `sigil scan <path>` runs the full scan pipeline
- **Done when:** `./sigil scan .` exits 0 on clean repo
- **Files:** `cli/src/main.rs`, `cli/src/scanner/**`
- **Notes:** Completed.

---

## Feature: F-003 Pro Billing + Tier Gating

> **Status:** 12/12 DONE + PARTIAL (US-003 operator-gated) + 1 TODO (US-005 blocked on US-003)
> **PRD:** `tasks/prd-remaining-f-003-work.json`

### STORY-100 [F-003]: Stripe products + prices configured — DONE ✅
- **Status:** DONE (2026-04-15)
- **Scope:** moderate
- **Goal:** Pro and Team products exist in Stripe with correct price IDs
- **Done when:** Products/prices visible in Stripe dashboard; IDs in `.nomark/resources.json`
- **Files:** `.nomark/resources.json`
- **Notes:** Completed 2026-04-15. Price IDs captured in resource graph.

### STORY-101 [F-003]: Live-mode webhook subscription audit + fix — DONE ✅
- **Status:** DONE (2026-05-03, autopilot)
- **Scope:** moderate
- **Goal:** Live-mode endpoint `we_1T2AXKFhPhxEz27fCYP53mKc` subscribes to all 6 required events
- **Done when:** GET /v1/webhook_endpoints/we_1T2AXKFhPhxEz27fCYP53mKc shows count: 6 with all 6 events
- **Files:** `evidence/F-003/US-101-webhook-subscription-audit.md`, `evidence/F-003/US-101-fix-applied.md`
- **Evidence:** `evidence/F-003/US-101-fix-applied.md` — POST fix applied; GET re-verify shows `count: 6`.
- **Notes:** Live-mode endpoint fixed. Test-mode mirror tracked in US-003 / US-105a.

### STORY-102 [F-003]: Stripe Checkout session flow — DONE ✅
- **Status:** DONE (2026-04-20)
- **Scope:** complex
- **Goal:** `POST /v1/billing/checkout` creates a Stripe Checkout session and returns URL
- **Done when:** Test checkout creates session; redirect URL returned
- **Files:** `api/routers/billing.py`, `api/tests/test_billing.py`
- **Notes:** Completed 2026-04-20.

### STORY-103 [F-003]: Webhook handler — subscription lifecycle — DONE ✅
- **Status:** DONE (2026-04-21)
- **Scope:** complex
- **Goal:** Webhook handler processes checkout.session.completed, subscription.created/updated/deleted, invoice events
- **Done when:** All 6 event types handled; tier updated in DB; tests pass
- **Files:** `api/routers/billing.py`, `api/services/billing_service.py`
- **Notes:** Completed 2026-04-21.

### STORY-104 [F-003]: Tier gating middleware — DONE ✅
- **Status:** DONE (2026-04-22)
- **Scope:** complex
- **Goal:** `require_plan` dependency gates endpoints by subscription tier
- **Done when:** Free user gets 402 on Pro endpoints; Pro user passes
- **Files:** `api/gates.py`, `api/tests/test_tier_gating.py`
- **Notes:** Completed 2026-04-22.

### STORY-105 [F-003]: Dashboard billing UI — DONE ✅
- **Status:** DONE (2026-04-25)
- **Scope:** complex
- **Goal:** Billing page shows plan, upgrade/manage buttons, payment history
- **Done when:** Billing page renders for free and Pro users
- **Files:** `dashboard/src/app/billing/**`
- **Notes:** Completed 2026-04-25.

### STORY-106 [F-003]: Customer portal integration — DONE ✅
- **Status:** DONE (2026-04-26)
- **Scope:** moderate
- **Goal:** `POST /v1/billing/portal` creates Stripe Customer Portal session
- **Done when:** Portal URL returned; customer can manage subscription
- **Files:** `api/routers/billing.py`
- **Notes:** Completed 2026-04-26.

### STORY-107 [F-003]: Stripe environment audit — DONE ✅
- **Status:** DONE (2026-05-01, autopilot)
- **Scope:** moderate
- **Goal:** Verify all Stripe env vars set on Container App; document in evidence
- **Done when:** `evidence/F-003/US-100-stripe-env-audit.md` exists with all vars confirmed
- **Files:** `evidence/F-003/US-100-stripe-env-audit.md`
- **Notes:** Completed 2026-05-01. All Stripe env vars confirmed on sigil-api Container App.

### STORY-108 [F-003]: Stripe customer ID sync — DONE ✅
- **Status:** DONE (2026-04-28)
- **Scope:** moderate
- **Goal:** Auth0 user ID linked to Stripe customer ID in DB on first checkout
- **Done when:** `stripe_customer_id` populated in users table after checkout
- **Files:** `api/services/billing_service.py`
- **Notes:** Completed 2026-04-28.

### STORY-109 [F-003]: Subscription tier sync on webhook — DONE ✅
- **Status:** DONE (2026-04-29)
- **Scope:** moderate
- **Goal:** `subscription_tier` column updated from webhook events
- **Done when:** Tier updated in DB on subscription events; test verifies
- **Files:** `api/services/billing_service.py`, `api/tests/test_billing_webhooks.py`
- **Notes:** Completed 2026-04-29.

### STORY-110 [F-003]: Free tier scan limits — DONE ✅
- **Status:** DONE (2026-04-30)
- **Scope:** moderate
- **Goal:** Free users limited to N scans/month; 402 when exhausted
- **Done when:** Scan count tracked; limit enforced; test verifies
- **Files:** `api/gates.py`, `api/services/credit_service.py`
- **Notes:** Completed 2026-04-30.

### STORY-111 [F-003]: Trial period handling — DONE ✅
- **Status:** DONE (2026-05-01)
- **Scope:** moderate
- **Goal:** Trial subscriptions grant Pro access; expiry downgrades to free
- **Done when:** Trial detection in tier gate; test verifies expiry
- **Files:** `api/gates.py`, `api/services/billing_service.py`
- **Notes:** Completed 2026-05-01.

### STORY-112 [F-003]: Billing e2e smoke test — DONE ✅
- **Status:** DONE (2026-05-02)
- **Scope:** moderate
- **Goal:** End-to-end test: checkout → webhook → tier upgrade → gated endpoint passes
- **Done when:** `pytest api/tests/test_billing_e2e.py` passes
- **Files:** `api/tests/test_billing_e2e.py`
- **Notes:** Completed 2026-05-02.

---

## F-003 Closeout Stories

### US-001 [F-003 closeout]: Stripe env audit — DONE ✅
- **Status:** DONE (2026-05-01, autopilot)
- **Evidence:** `evidence/F-003/US-100-stripe-env-audit.md`

### US-002 [F-003 closeout]: Live-mode webhook subscription fix — DONE ✅
- **Status:** DONE (2026-05-03, autopilot)
- **Evidence:** `evidence/F-003/US-101-fix-applied.md` — count: 6 verified.

### US-003 [F-003 closeout]: Test-mode webhook subscription audit — PARTIAL ⚠️
- **Status:** PARTIAL (2026-05-04 first attempt; 2026-06-21 re-attempt NOM-884)
- **Scope:** moderate
- **Goal:** Test-mode endpoint subscribes to all 6 required events (mirrors STORY-101 for test mode)
- **Done when:** `evidence/F-003/US-105a-test-mode-webhook-audit.md` shows endpoint ID + verbatim 6-event list
- **Files:** `evidence/F-003/US-105a-test-mode-webhook-audit.md`
- **Notes:** OPERATOR-GATED. Three blocking conditions confirmed on both attempts: (1) Stripe MCP `GetWebhookEndpoints` unavailable in this environment, (2) local Stripe CLI configured to wrong account (`acct_1TNsZTFvlPr69lA2` exectables, not `acct_1RkD8NFhPhxEz27f` Sigil/NOMARK), (3) CHARTER II.5 forbids reading Azure Container App secrets. Runbook in evidence file (Options A/B/C). Option B (Stripe Dashboard test-mode toggle → Developers → Webhooks) is fastest. Blocks US-005.

### US-004 [F-003 closeout]: Checkout session smoke test — DONE ✅
- **Status:** DONE (2026-05-04, autopilot)
- **Evidence:** `evidence/F-003/US-104-checkout-smoke.md`

### US-005 [F-003 closeout]: Test-mode round-trip — TODO ⏳
- **Status:** TODO (blocked on US-003)
- **Scope:** moderate
- **Goal:** Full test-card checkout → webhook → tier upgrade round-trip in test mode
- **Done when:** Test card checkout completes; webhook received; tier updated
- **Files:** `evidence/F-003/US-005-test-roundtrip.md`
- **Notes:** Blocked on US-003 (test-mode webhook endpoint must be verified first).

### US-006 [F-003 closeout]: Tier gate verification — DONE ✅
- **Status:** DONE (2026-05-04, autopilot)
- **Evidence:** `evidence/F-003/US-106-tier-gate-verification.md`

### US-007 [F-003 closeout]: Customer portal smoke test — DONE ✅
- **Status:** DONE (2026-05-04, autopilot)
- **Evidence:** `evidence/F-003/US-107-portal-smoke.md`

### US-008 [F-003 closeout]: Billing UI acceptance — DONE ✅
- **Status:** DONE (2026-05-04, autopilot)
- **Evidence:** `evidence/F-003/US-108-billing-ui.md`

### US-009 [F-003 closeout]: Webhook event coverage — DONE ✅
- **Status:** DONE (2026-05-03, autopilot)
- **Evidence:** `evidence/F-003/US-109-webhook-coverage.md`

### US-010 [F-003 closeout]: PRD sign-off — DONE ✅
- **Status:** DONE (2026-05-04, autopilot)
- **Evidence:** `evidence/F-003/US-010-prd-signoff.md`

---

## Feature: F-007 Launch Readiness Remediation

> **Status:** 12/12 DONE
> **PRD:** `tasks/prd-launch-readiness.json`

### US-001 [F-007]: DNS + TLS verification — DONE ✅
- **Status:** DONE
- **Scope:** moderate

### US-002 [F-007]: API health endpoint hardening — DONE ✅
- **Status:** DONE
- **Scope:** moderate

### US-003 [F-007]: Dashboard error boundaries — DONE ✅
- **Status:** DONE
- **Scope:** moderate

### US-004 [F-007]: Log aggregation setup — DONE ✅
- **Status:** DONE
- **Scope:** moderate

### US-005 [F-007]: Alerting configuration — DONE ✅
- **Status:** DONE
- **Scope:** moderate

### US-006 [F-007]: Backup verification — DONE ✅
- **Status:** DONE
- **Scope:** moderate

### US-007 [F-007]: Load test baseline — DONE ✅
- **Status:** DONE
- **Scope:** moderate

### US-008 [F-007]: Security headers audit — DONE ✅
- **Status:** DONE
- **Scope:** moderate

### US-009 [F-007]: CORS policy lockdown — DONE ✅
- **Status:** DONE
- **Scope:** moderate

### US-010 [F-007]: Rate limit tuning — DONE ✅
- **Status:** DONE
- **Scope:** moderate

### US-011 [F-007]: Runbook documentation — DONE ✅
- **Status:** DONE
- **Scope:** moderate

### US-012 [F-007]: Launch go/no-go checklist — DONE ✅
- **Status:** DONE
- **Scope:** moderate

---

## Decisions Log

- 2026-04-11: Auth0 v4 SDK adopted for dashboard (breaking change from v3)
- 2026-04-15: Stripe price IDs captured in `.nomark/resources.json` (not hardcoded)
- 2026-04-20: Checkout uses `payment_mode: subscription` (not one-time)
- 2026-04-22: `require_plan` implemented as FastAPI Depends (not middleware) for per-route granularity
- 2026-05-01: Stripe env vars confirmed via Azure CLI (not assumed from Terraform)
- 2026-05-03: Live-mode webhook fix applied via operator-authorized Stripe API POST
- 2026-05-04: US-003 deferred to operator — credential boundary per CHARTER II.5
- 2026-06-11: F-008 Phase G complete; Rust engine is the detection engine for API and bash
- 2026-06-11: F-009 scope approved: Fable 5 + Opus 4.8 fallback; free teaser + Pro-unlimited
- 2026-06-12: F-009 US-112 deployed to prod; Fable-5 adjudication live
- 2026-06-21: US-003 re-attempted (NOM-884); all three blocking conditions unchanged

---

## Session observations

### Session start — 2026-04-11
- Instinct index loaded: 0 instincts
- Task scope: F-003/F-005 Production Hardening Sweep
- Context bracket: FRESH

### Session end — 2026-04-11
- Stories completed: STORY-200, STORY-201
- Outcome: partial (2/5 hardening stories)
- Next: STORY-202 (Stripe webhook sig verification)

### Session start — 2026-04-12
- Instinct index loaded: 2 instincts
- Task scope: STORY-202 (webhook sig), STORY-203 (secrets audit)
- Context bracket: FRESH

### Session end — 2026-04-12
- Stories completed: STORY-202
- Next: STORY-203

### Session start — 2026-04-13
- Task scope: STORY-203 (Container App secrets audit)

### Session end — 2026-04-13
- Stories completed: STORY-203
- Next: STORY-204 (dependency sweep)

### Session start — 2026-04-14
- Task scope: STORY-204

### Session end — 2026-04-14
- Stories completed: STORY-204
- F-003/F-005 sweep complete

### Session start — 2026-04-15
- Task scope: F-003 billing (STORY-100 through STORY-112)

### Session end — 2026-04-15
- Stories completed: STORY-100

### Session start — 2026-04-20
- Task scope: STORY-102 (Checkout)

### Session end — 2026-04-20
- Stories completed: STORY-102

### Session start — 2026-04-21
- Task scope: STORY-103 (webhook handler)

### Session end — 2026-04-21
- Stories completed: STORY-103

### Session start — 2026-04-22
- Task scope: STORY-104 (tier gating)

### Session end — 2026-04-22
- Stories completed: STORY-104

### Session start — 2026-04-25
- Task scope: STORY-105 (billing UI)

### Session end — 2026-04-25
- Stories completed: STORY-105

### Session start — 2026-04-26
- Task scope: STORY-106 (portal)

### Session end — 2026-04-26
- Stories completed: STORY-106

### Session start — 2026-04-28
- Task scope: STORY-108 (customer ID sync)

### Session end — 2026-04-28
- Stories completed: STORY-108

### Session start — 2026-04-29
- Task scope: STORY-109 (tier sync)

### Session end — 2026-04-29
- Stories completed: STORY-109

### Session start — 2026-04-30
- Task scope: STORY-110 (free tier limits)

### Session end — 2026-04-30
- Stories completed: STORY-110

### Session start — 2026-05-01
- Task scope: STORY-111 (trial), US-001 (Stripe env audit), STORY-107

### Session end — 2026-05-01
- Stories completed: STORY-111, US-001, STORY-107

### Session start — 2026-05-02
- Task scope: STORY-112 (billing e2e)

### Session end — 2026-05-02
- Stories completed: STORY-112

### Session start — 2026-05-03
- Task scope: US-002 (live webhook fix), US-009

### Session end — 2026-05-03
- Stories completed: US-002, US-009, STORY-101

### Session start — 2026-05-04
- Task scope: F-003 closeout (US-003 through US-010)

### Session end — 2026-05-04
- Stories completed: US-001, US-002, US-004, US-006, US-007, US-008, US-009, US-010
- Stories partial/blocked: US-003 (PARTIAL — operator-gated, credential boundary)
- Stories blocked: US-005 (TODO — blocked on US-003)
- Instincts captured: credential-boundary pattern (CHARTER II.5 applies to Azure secrets)

---

## instinct-index

| ID | Summary | Confidence |
|---|---|---|
| I-001 | CHARTER II.5: never read Azure secrets into agent context | 0.95 |
| I-002 | Stripe MCP does not expose GetWebhookEndpoints in this env | 0.90 |
| I-003 | Stripe CLI config points to exectables acct, not Sigil/NOMARK | 0.90 |
| I-004 | Operator runbook (Options A/B/C) is the correct escalation path for Stripe webhook audits | 0.85 |

---

## Session observations (continued)

### Session start — 2026-05-04 (F-008 Phase A)
- Task scope: F-008 Open-Source Core Hardening Phase A (pattern coverage)
- Instinct index: 4 instincts loaded
- Context bracket: FRESH

### Session end — 2026-05-04
- Stories completed: US-A1, US-A2, US-A3 (Phase A DONE)

### Session start — 2026-05-10 (F-008 Phase B)
- Task scope: F-008 Phase B (SBOM + OSV)

### Session end — 2026-05-10
- Stories completed: US-B1, US-B2, US-B3 (Phase B DONE)

### Session start — 2026-05-17 (F-008 Phase C)
- Task scope: F-008 Phase C (quarantine + sandbox)

### Session end — 2026-05-17
- Stories completed: US-C1, US-C2, US-C3, US-C4 (Phase C DONE)

### Session start — 2026-05-24 (F-008 Phase D)
- Task scope: F-008 Phase D (policy engine)

### Session end — 2026-05-24
- Stories completed: US-D1, US-D2, US-D3 (Phase D DONE)

### Session start — 2026-05-31 (F-008 Phase E)
- Task scope: F-008 Phase E (OSV enrichment + SBOM export)

### Session end — 2026-05-31
- Stories completed: US-E1, US-E2, US-E3, US-E4 (Phase E DONE)

### Session start — 2026-06-07 (F-008 Phase F)
- Task scope: F-008 Phase F (trust ledger + allowlist)

### Session end — 2026-06-07
- Stories completed: US-F1, US-F2, US-F3 (Phase F DONE)

### Session start — 2026-06-08 (BUGFIX: POST /v1/scan 422)
- Task scope: Debug 422 on POST /v1/scan
- Outcome: DONE — root cause: `from __future__ import annotations` in rate_limit.py

### Session start — 2026-06-11 (F-008 Phase G + F-009 planning)
- Task scope: F-008 Phase G (Rust engine integration) + F-009 scope approval

### Session end — 2026-06-11
- Stories completed: US-G1, US-G2, US-G3 (Phase G DONE); F-009 US-101 through US-111; F-010 US-H1, US-H2, US-H3
- F-008 Goal 1 COMPLETE across Phases A–G
- FP-NARROWING completed (FP@High 95%→70%, FP@Critical 30%→20%)

### Session start — 2026-06-12 (F-009 US-110 + US-112 + bugfixes)
- Task scope: F-009 US-110 (Anthropic billing unblocked), US-112 (ops verification), scanner docs bugfix, dashboard auth bugfix

### Session end — 2026-06-12
- Stories completed: F-009 US-110, US-112; BUGFIX scanner docs links; BUGFIX dashboard Auth0/Pro routing
- F-009 COMPLETE + DEPLOYED (prod rev sigil-api--0000108)

---

## instinct-health

| ID | Outcome count | Confirmed | Rejected | Health |
|---|---|---|---|---|
| I-001 | 3 | 3 | 0 | healthy |
| I-002 | 2 | 2 | 0 | healthy |
| I-003 | 2 | 2 | 0 | healthy |
| I-004 | 2 | 2 | 0 | healthy |

---

## Feature: Pre-Production Launch Readiness

### LAUNCH-001: Production infrastructure verified — DONE ✅
- **Status:** DONE (2026-06-13)
- **Scope:** moderate

### LAUNCH-002: Database migration verified — DONE ✅
- **Status:** DONE (2026-06-13)
- **Scope:** moderate

### LAUNCH-003: CI/CD pipeline verified — DONE ✅
- **Status:** DONE (2026-06-13)
- **Scope:** moderate

### LAUNCH-004: Security hardening sweep — DONE ✅ (see STORY-205, STORY-206, STORY-207)
- **Status:** DONE (2026-06-14)
- **Scope:** complex

### LAUNCH-005: Live smoke tests — DONE ✅
- **Status:** DONE (2026-06-14)
- **Scope:** moderate
- **Evidence:** Live API health `{status:ok, database_connected:true, redis_connected:true}`; live dashboard HTTP 200.

---

## Feature: F-008 Open-Source Core Hardening

> **Status:** COMPLETE across Phases A–G (2026-06-11)
> **Goal 1:** Production-quality open-source scanner engine ✅
> **Goal 2:** Sigil Pro tier with LLM adjudication → F-009

### Phase A — Pattern Coverage

#### US-A1 [F-008]: Extend install-hook patterns — DONE ✅
- **Status:** DONE (2026-05-04)
- **Scope:** moderate
- **Goal:** Cover npm lifecycle hooks, Makefile targets, cargo build scripts
- **Done when:** `cargo test install_hook` green; patterns match new test vectors
- **Files:** `cli/src/scanner/patterns.rs`, `cli/tests/patterns.rs`

#### US-A2 [F-008]: Code pattern expansion (eval/exec/pickle hardening) — DONE ✅
- **Status:** DONE (2026-05-04)
- **Scope:** moderate
- **Goal:** Distinguish benign vs malicious eval/exec/pickle patterns; add chain rules
- **Done when:** Chain rule tests pass; FP rate for stdlib usage reduced
- **Files:** `cli/src/scanner/patterns.rs`, `cli/src/scanner/chains.rs`

#### US-A3 [F-008]: Prompt injection pattern coverage — DONE ✅
- **Status:** DONE (2026-05-04)
- **Scope:** moderate
- **Goal:** Cover jailbreak, markdown RCE, social engineering patterns
- **Done when:** `cargo test prompt_injection` green
- **Files:** `cli/src/scanner/patterns.rs`

### Phase B — SBOM + OSV

#### US-B1 [F-008]: SPDX SBOM generation — DONE ✅
- **Status:** DONE (2026-05-10)
- **Scope:** moderate
- **Goal:** `sigil scan --sbom` outputs SPDX 2.3 JSON
- **Done when:** SBOM validates against SPDX schema; cargo test green
- **Files:** `cli/src/sbom.rs`, `cli/src/main.rs`

#### US-B2 [F-008]: OSV vulnerability lookup — DONE ✅
- **Status:** DONE (2026-05-10)
- **Scope:** moderate
- **Goal:** SBOM packages checked against OSV.dev; CVEs surfaced in scan output
- **Done when:** OSV findings appear in scan JSON; tests mock OSV API
- **Files:** `cli/src/osv.rs`, `cli/src/scanner/mod.rs`

#### US-B3 [F-008]: SBOM + OSV integration test — DONE ✅
- **Status:** DONE (2026-05-10)
- **Scope:** moderate
- **Goal:** End-to-end: scan → SBOM → OSV → findings in output
- **Done when:** Integration test passes
- **Files:** `cli/tests/sbom_osv.rs`

### Phase C — Quarantine + Sandbox

#### US-C1 [F-008]: Quarantine directory management — DONE ✅
- **Status:** DONE (2026-05-17)
- **Scope:** moderate

#### US-C2 [F-008]: `sigil clone` quarantine flow — DONE ✅
- **Status:** DONE (2026-05-17)
- **Scope:** moderate

#### US-C3 [F-008]: `sigil pip` / `sigil npm` quarantine — DONE ✅
- **Status:** DONE (2026-05-17)
- **Scope:** moderate

#### US-C4 [F-008]: Approve/reject workflow — DONE ✅
- **Status:** DONE (2026-05-17)
- **Scope:** moderate

### Phase D — Policy Engine

#### US-D1 [F-008]: Policy file format (YAML) — DONE ✅
- **Status:** DONE (2026-05-24)
- **Scope:** moderate

#### US-D2 [F-008]: Policy evaluation engine — DONE ✅
- **Status:** DONE (2026-05-24)
- **Scope:** moderate

#### US-D3 [F-008]: `--policy` CLI flag + CI integration — DONE ✅
- **Status:** DONE (2026-05-24)
- **Scope:** moderate

### Phase E — OSV Enrichment + SBOM Export

#### US-E1 [F-008]: OSV finding deduplication — DONE ✅
- **Status:** DONE (2026-05-31)
- **Scope:** moderate

#### US-E2 [F-008]: CVSS scoring integration — DONE ✅
- **Status:** DONE (2026-05-31)
- **Scope:** moderate

#### US-E3 [F-008]: CycloneDX SBOM format — DONE ✅
- **Status:** DONE (2026-05-31)
- **Scope:** moderate

#### US-E4 [F-008]: SBOM export CI action — DONE ✅
- **Status:** DONE (2026-05-31)
- **Scope:** moderate

### Phase F — Trust Ledger + Allowlist

#### US-F1 [F-008]: Trust ledger data model — DONE ✅
- **Status:** DONE (2026-06-07)
- **Scope:** moderate

#### US-F2 [F-008]: Allowlist policy integration — DONE ✅
- **Status:** DONE (2026-06-07)
- **Scope:** moderate

#### US-F3 [F-008]: Ledger CLI commands (approve/reject/list) — DONE ✅
- **Status:** DONE (2026-06-07)
- **Scope:** moderate

### Phase G — Rust Engine Integration

#### US-G1 [F-008]: API delegates scan to Rust binary — DONE ✅
- **Status:** DONE (2026-06-11, autopilot)
- **Scope:** complex
- **Goal:** `POST /v1/scan` shells out to the Rust binary (`SIGIL_BIN`); Python phase functions retired
- **Done when:** API tests pass with Rust engine; Python fallback documented
- **Files:** `api/scanner.py`, `api/tests/test_scanner_rust.py`
- **Notes:** SIGIL_BIN env var; Dockerfile.api TODO to bundle binary.

#### US-G2 [F-008]: bin/sigil bash delegates to Rust — DONE ✅
- **Status:** DONE (2026-06-11, autopilot)
- **Scope:** moderate
- **Goal:** Legacy bash wrapper calls Rust binary; output format preserved
- **Done when:** `./bin/sigil scan .` uses Rust engine; bash phase functions deprecated
- **Files:** `bin/sigil`

#### US-G3 [F-008]: Real reproducible eval (retire fabricated scorecard) — DONE ✅
- **Status:** DONE (2026-06-11, autopilot)
- **Scope:** complex
- **Goal:** `scripts/run_eval.py` measures detection against real malicious samples; fabricated 99.26% scorecard retired
- **Done when:** Eval report exists; no `random` in eval; disclosure block present; results reproducible
- **Files:** `scripts/run_eval.py`, `evaluation_results/`
- **Notes (FP-NARROWING, completed 2026-06-11):** Engine resolution gotcha: harness picked homebrew sigil v1.0.4 off PATH first — must
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

### STORY-205: Production hardening sweep (2026-06-13)
- **Status:** IN PROGRESS (two fresh subagent passes completed; high findings fixed; follow-up CI/migration patch ready to ship; local Docker build blocked by stopped daemon)
- **Scope:** complex
- **Goal:** Remove critical/high vibe-code defects across API security, dashboard auth/UX, CLI release packaging, cache, quarantine, and deployment readiness.
- **Done when:** API tests, dashboard audit/lint/type/test/build, CLI clippy/tests, package install, MCP audit, and two fresh post-fix subagent passes complete with no unresolved critical/high findings.
- **Files:** `.github/action-entrypoint.sh`, `.github/workflows/release.yml`, `.gitignore`, `api/**`, `cli/**`, `dashboard/**`, `install.sh`, `package.json`, `package-lock.json`, `scripts/install-binary.js`, `scripts/cleanup.js`, `pytest.ini`.
- **Evidence:** Post-pass validation: `PYTHONPATH=. /tmp/sigil-api-venv/bin/pytest api/tests -q` -> 364 passed, 348 skipped before first push; after CI/migration follow-up -> 365 passed, 348 skipped. `cd dashboard && npm run lint && npx tsc --noEmit && npm test -- --runInBand && npm run build` -> lint/type/build passed, 9 suites / 66 tests passed, 34 static pages generated. `cd cli && cargo clippy --all-targets --all-features -- -D warnings && cargo test --locked --quiet` -> clippy clean, 140 unit + 4 integration tests passed. Root `npm ci --ignore-scripts && npm audit --audit-level=moderate && npm pack --json` -> install/audit/pack passed. Real packed install in temp prefix -> `sigil 1.2.1`. `sh -n install.sh && node --check scripts/install-binary.js scripts/cleanup.js bin/sigil-wrapper.js` -> passed. `git diff --check` -> passed. `SIGIL_BIN="$PWD/cli/target/release/sigil" ./bin/sigil scan .` -> exit 0 with 0 critical / 0 high after documented `.sigilignore` suppressions. Live DB migration verification via `python -m api.migrations.apply_prod_migration api/migrations/add_auth0_subscription_columns_prod.sql api/migrations/add_credits_system_prod.sql` -> users auth/billing columns, indexes, credit tables/procs, interactive_sessions table/indexes all present. `docker build --build-arg NEXT_PUBLIC_API_URL=https://api.sigilsec.ai -t sigil-full-hardening-test .` blocked because Docker daemon socket was unavailable.
- **Notes:** Two fresh subagent passes completed (`019ebe55-3de8-7d43-9178-849a1b9e4d52`, `019ebe55-8fea-7171-b29b-d36d48b7c8b5`). Migration subagent (`019ebe85-52ea-7530-b59c-ffa4b46b6179`) found live DB drift: `users.auth0_sub`, `users.subscription_tier`, their indexes, and `interactive_sessions` were missing; fixed with idempotent prod migration and live apply. Findings fixed: dashboard stats cross-tenant leak; Stripe webhook side effects using nonexistent DB methods/swallowing entitlement failures; interactive sessions production DB/schema incompatibility; scan-detail rescan routed to missing local route and wrong response contract; Azure API deploy/CI bypassing locked dependencies; full Docker image missing build arg and Rust engine; CI self-scan missing Rust engine and stale Pro workflow dependency set. Regression tests added/updated for each. `.nomark/graph.json` and `.nomark/index.json` are generated telemetry and remain unstaged unless explicitly requested.

### STORY-206: Remaining release hardening pass (2026-06-14)
- **Status:** DONE ✅ (2026-06-14 — app `9f3de3c`, infra `50f7673`; local + GitHub + live deploy verification passed)
- **Scope:** complex
- **Goal:** Close the remaining production hardening risks from STORY-205: infra deploy collision/health gaps, GitHub Actions runtime warnings, migration drift automation, self-scan medium/low burn-down, and noisy API deprecation warnings.
- **Done when:** Relevant unit/integration tests pass, self-scan remains 0 critical/high, migration verifier can run read-only, CI/deploy workflows are updated with regression coverage, and the pushed `main` workflows/deploy complete green.
- **Audit map before edits:**
  - **P1 Infra deploy concurrency + health:** latest ship exposed overlapping `repository_dispatch` Terraform runs; health job could skip checks when URL vars were empty. Inspect `sigil-infra` workflow and dispatch contract; fix with concurrency and fail-closed health inputs.
  - **P1 GitHub Actions runtime:** recent runs emitted Node.js 20 action deprecation warnings. Upgrade or pin affected actions to Node 24-compatible versions where available, and add tests/guardrails.
  - **P1 Migration drift:** `api/migrations/apply_prod_migration.py` verifies after applying, but it needs a read-only verification mode for scheduled/operator drift checks that does not reapply SQL.
  - **P2 Self-scan findings:** root self-scan is clean for critical/high but still has medium/low findings. Triage and fix true positives without broad suppressions.
  - **P2 API warning cleanup:** pytest output contains `datetime.utcnow`, `HTTP_422_UNPROCESSABLE_ENTITY`, and Starlette/httpx deprecations. Clean the low-risk repo-owned warnings first.
- **Files:** `.github/workflows/**`, `api/migrations/**`, `api/**`, `dashboard/**`, `.sigilignore`, `progress.md`; `sigil-infra` workflow files if required for deploy hardening.
- **Evidence (local, pre-push):** Two initial subagent sweeps found release/deploy/migration gaps; two final independent passes found no remaining critical issues and the high findings were fixed before ship. `ruff check api/ && ruff format --check api/` -> passed, 188 files formatted. `PYTHONPATH=. /tmp/sigil-api-venv/bin/pytest api/tests -q` -> 373 passed, 348 skipped, 2 dependency warnings. `actionlint -shellcheck '' -color=false .github/workflows/*.yml /Users/reecefrazier/CascadeProjects/sigil-infra/.github/workflows/deploy.yml && actionlint -color=false .github/workflows/test-pro-tier.yml` -> passed. `PYTHONPATH=. /tmp/sigil-api-venv/bin/python -m api.migrations.apply_prod_migration --verify-only` -> all expected Auth0, credit, and interactive session schema objects present. `cd dashboard && npm test -- --runTestsByPath src/__tests__/app/auth-onboarding-hardening.test.ts && NEXT_PUBLIC_API_URL=https://api.sigilsec.ai npm run build` -> 4 tests passed and Next production build passed. `cd cli && cargo clippy --all-targets --all-features -- -D warnings && cargo test --locked --quiet` -> clippy clean, 140 unit + 4 integration tests passed. `./cli/target/release/sigil scan . --no-cache --fail-on high` -> exit 0, 0 critical / 0 high, 137 medium / 35 low. Root and dashboard `npm ci --ignore-scripts` -> zero vulnerabilities. `git diff --check` and infra workflow diff check -> passed.
- **Evidence (remote/live):** `NOMARJ/sigil` `9f3de3c` workflows: CI `27487410501` success, Sigil Self-Scan `27487410498` success, nomark-hygiene `27487410507` success, Deploy to Azure `27487410504` success. Manual Production Migration Drift `27487219054` success after the pseudo-TTY fix, proving read-only migration verification can run in GitHub Actions. `NOMARJ/sigil-infra` `50f7673`: push validation `27487408350` success and repository_dispatch deploy `27487506602` success with Terraform Plan, Terraform Apply, and Health Check all green. Live probes after deploy: `https://api.sigilsec.ai/health` returned `{"status":"ok","version":"0.1.0","database_connected":true,"redis_connected":true}` and `https://app.sigilsec.ai` returned HTTP 200.
- **Notes:** Trust score is 0/probation; use fresh verification before any DONE claim. Drift score 0/FRESH. `.nomark/lifecycles/manifests/code.yaml` missing and MEE ledger cold-start still fails because `.nomark/schemas/mee-event.schema.json` is missing. Remaining accepted risks after local validation: dependency-level pytest warnings (`starlette.testclient`/`httpx`, passlib `crypt`), dashboard install transitive deprecation warnings, and medium/low self-scan heuristics for documented MCP/curl/subprocess surfaces.

### STORY-207: Residual hardening burn-down (2026-06-14)
- **Status:** DONE ✅ (2026-06-14, Codex)
- **Scope:** complex
- **Goal:** Remove or explicitly close the residual risks left after STORY-206: unrelated infra worktree noise, dependency warnings, self-scan medium/low true positives, Node 20 action runtime gaps, Terraform `latest` defaults, and deploy image identity verification.
- **Done when:** Subagent passes cover infra/actions/self-scan/dependencies, material true positives are fixed with tests, app and infra validation pass locally and on GitHub, live API/dashboard health is verified, and any unavoidable residuals are recorded with evidence.
- **Audit map before edits:**
  - **P1 Infra immutability:** Terraform variables still default container image tags to `latest`; module-level validation should reject mutable/missing tags, not only workflow inputs.
  - **P1 Deploy provenance:** Infra health checks prove HTTP health, but not that deployed Container Apps are running the expected image tags from the app dispatch.
  - **P1 GitHub Actions runtime:** Workflows still rely on actions that currently declare Node 20; replace with Node 24-native versions where available or documented non-JS commands where feasible.
  - **P2 Dependency warnings:** API tests still warn from Starlette/httpx TestClient compatibility and passlib `crypt`; determine whether project-owned dependency updates remove them without breaking tests.
  - **P2 Self-scan medium/low:** Triage scanner findings and fix true positives; do not suppress legitimate product surfaces or documentation without evidence.
  - **P2 Infra worktree hygiene:** `sigil-infra` has untracked `chains/**`; classify as user/generator artifacts, ignored artifacts, or publishable work before touching them.
- **Files:** `progress.md`, `.github/workflows/**`, `api/**`, `cli/**`, `dashboard/**`, and `/Users/reecefrazier/CascadeProjects/sigil-infra/**` as required.
- **Evidence:** Parallel agent passes covered infra, GitHub Actions runtime, dependency warnings, and self-scan triage. Local validation: `actionlint -shellcheck '' -color=false .github/workflows/*.yml /Users/reecefrazier/CascadeProjects/sigil-infra/.github/workflows/*.yml` -> passed. `terraform -chdir=/Users/reecefrazier/CascadeProjects/sigil-infra/azure fmt -check -recursive` and `terraform validate` -> passed. Terraform negative plan with `api_image_tag=latest`, `dashboard_image_tag=latest`, and `bot_image_tag=latest` exits 1 with all three validation errors. `/tmp/sigil-api-venv/bin/python -m pytest api/tests -q` -> 388 passed, 348 skipped. Focused warning gate `pytest api/tests/test_release_hardening.py api/tests/test_git_analyzer_hardening.py api/tests/test_clawhub_crawler_hardening.py api/tests/test_auth.py -q -W error` -> 40 passed. `ruff check` on changed API files/tests -> passed. `/tmp/sigil-api-venv/bin/python -m pip install -r api/requirements.lock` and `pip check` -> passed. `cd dashboard && npm run lint && npx tsc --noEmit && npm test -- --runInBand --coverage=false && npm run build` -> passed, 9 suites / 66 tests, 34 static app pages. `npx prettier --check ...` -> passed. `sh -n install.sh` -> passed. `./cli/target/release/sigil scan . --no-cache --severity high --fail-on high` -> 449 files scanned, 0 findings. `git diff --check` and infra `git diff --check` -> passed.
- **Notes:** Trust score is 0/probation; resource references were checked against `.nomark/resources.json` and `https://www.sigilsec.ai/install.sh` was live-verified (`HTTP/2 307` to the GitHub raw installer). `sigil-infra/chains/**` was preserved and ignored as local NOMARK chain harness data rather than staged or deleted. No local critical/high self-scan findings remain. Remaining non-blocking work: internal historical docs still contain pipe-to-shell examples as examples or stale planning notes; scanner false-positive tuning for MCP/documentation heuristics remains a lower-priority quality pass.

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
