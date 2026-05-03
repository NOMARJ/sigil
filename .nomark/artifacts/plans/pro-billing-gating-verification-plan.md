# Autopilot Plan: Pro Billing + Tier Gating Verification (F-003)

**PRD:** tasks/prd-pro-billing-gating-verification.md
**Feature:** F-003 (EP-003)
**Date:** 2026-05-03
**Mode:** --dry-run (decompose only)

## Summary
- Stories: 14 (3 trivial / 9 moderate / 2 complex)
- Estimated exchanges: ~95–115
- Parallel-safe batches:
  - Batch A (config/audit, no DB writes): US-100, US-101, US-102, US-103, US-104, US-110
  - Batch B (after Batch A): US-105 (test-mode round-trip) — depends on config audit pass
  - Batch C (post-test-mode): US-106 (dead route deletion), US-107 (free-trial decision capture), US-108 (CDN investigation)
  - Batch D (sequential, owner-gated): US-109 (live-mode $29 round-trip)
  - Batch E (close-out): US-111 (pricing-page byte-equal probe), US-112 (CDN fix verification), US-113 (status flip in SOLUTION.md / progress.md)
- Blocked-pending:
  - US-109: BLOCKED-pending-owner-action — owner is the only person with Stripe live-mode access and ability to refund a real $29 charge (PRD Q2)
  - US-107: BLOCKED-pending-owner-decision — free-trial enable-vs-remove is an owner ADR call (PRD Q3)
- Risk flags:
  - CHARTER Article II: every "Done when" requires real evidence; do NOT fabricate Stripe event IDs, SQL rows, or webhook receipts. If a step is not run, story stays TODO. The lessons.md `synthetic data presented as real` insight (INS-003 in SOLUTION.md) applies directly here.
  - MSSQL queries in evidence packs must use parameterised queries (`WHERE email = ?`), never string concatenation, per existing aioodbc conventions. Capture the row by re-running the parameterised query verbatim with the captured email.
  - US-105 and US-109 require human-in-the-loop with Stripe Checkout; they are NOT unit-testable. Marked `(manual verification)` in scope; `TDD anchor` is the evidence-capture command sequence, not a pytest assertion.
  - Stripe Dashboard webhook signing-secret comparison must be verified by sending a Stripe Dashboard "test webhook" event and observing 200 from the production handler — NOT by direct comparison of secret values (per PRD US-003 AC).
  - `evidence/` directory does not yet exist in the repo; the first story to write evidence (US-100) will create it implicitly via the Write performed by the executor (planner is read-only — this is a note for the build phase, not a separate scaffolding story).
  - Auth0 production callback URL (PRD Q1) is an upstream assumption; if US-105 fails at signup, escalate as a blocker rather than logging a fake-success.

## Story Sequence

### US-100: Capture Stripe key environment audit (Container Apps env)
- **Status:** TODO
- **Goal:** Documented evidence that `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PRO`, `STRIPE_PRICE_TEAM`, `STRIPE_PRICE_PRO_ANNUAL`, `STRIPE_PRICE_TEAM_ANNUAL` are all present on the running `sigil-api` Container App, and the four Price IDs resolve to live-mode Stripe Products.
- **Done when:** `evidence/F-003/US-100-stripe-env-audit.md` exists containing: (1) raw `az containerapp show -n sigil-api -g sigil-rg --query 'properties.template.containers[0].env[?contains(name, \`STRIPE\`)]' -o json` output, (2) for each `price_*` value, a `stripe products retrieve` (or Dashboard URL) result showing `livemode: true`, (3) the secretRef name for `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` (NOT the values), (4) explicit pass/fail verdict per env var. No raw secret values logged.
- **Files:** `evidence/F-003/US-100-stripe-env-audit.md` (new), `docs/internal/2026-05-stripe-config-audit.md` (new — initial section "Env vars")
- **Dependencies:** none
- **TDD anchor:** Manual verification, no automated test — this is an external-state audit. Reproducibility comes from the verbatim `az` command logged in the evidence file.
- **Scope:** moderate (manual verification)
- **Notes:** Apply CHARTER Article II — if `az` access is unavailable in this session, story stays TODO and is escalated, NOT marked DONE with "would have shown live keys". `livemode: true` on a Price object is the single ground-truth check; do not infer live-mode from key prefix alone (a `sk_live_…` could still have test prices attached if misconfigured).

### US-101: Capture Stripe Dashboard webhook subscription audit
- **Status:** TODO
- **Goal:** Documented evidence that the live-mode Stripe Dashboard has exactly one webhook endpoint pointing at `https://api.sigilsec.ai/v1/billing/webhook` subscribed to all six required event types.
- **Done when:** `evidence/F-003/US-101-webhook-subscription-audit.md` exists containing: (1) screenshot or `stripe webhook_endpoints list --live` output showing the endpoint URL, (2) the `enabled_events` array with exact membership check vs `{customer.subscription.created, customer.subscription.updated, customer.subscription.deleted, invoice.paid, invoice.payment_failed, checkout.session.completed}` — flag any missing/extra, (3) endpoint status `enabled: true`. Append findings to `docs/internal/2026-05-stripe-config-audit.md` under heading "Webhook subscriptions".
- **Files:** `evidence/F-003/US-101-webhook-subscription-audit.md` (new), `docs/internal/2026-05-stripe-config-audit.md` (append)
- **Dependencies:** none
- **TDD anchor:** Manual verification — Stripe Dashboard / `stripe` CLI live-mode access. Reproducibility = the `stripe webhook_endpoints list --live` command and the live-mode account it ran against.
- **Scope:** moderate (manual verification)
- **Notes:** Split from PRD US-003 (env-vars vs webhooks have different surfaces — env-var audit can be done by a launch operator with `az`, but webhook-subscription audit needs Stripe Dashboard live-mode access). If events are missing, fix is owner-driven (add subscriptions in Dashboard) and re-verify.

### US-102: Verify webhook signing-secret alignment via Dashboard test send
- **Status:** TODO
- **Goal:** Prove `STRIPE_WEBHOOK_SECRET` injected into Container Apps matches the live-mode webhook endpoint's signing secret WITHOUT logging either value.
- **Done when:** `evidence/F-003/US-102-webhook-signature-roundtrip.md` exists with: (1) Stripe Dashboard "Send test webhook" action timestamp + event ID, (2) corresponding API log line from `az containerapp logs show -n sigil-api -g sigil-rg --tail 200 | grep <event_id>` showing the handler returned 200, (3) NEGATIVE control: a curl with a bogus `Stripe-Signature` header returns 400 (proves verification is on) — captured request/response. Append to config audit doc.
- **Files:** `evidence/F-003/US-102-webhook-signature-roundtrip.md` (new), `docs/internal/2026-05-stripe-config-audit.md` (append)
- **Dependencies:** US-101 (need the endpoint to exist before sending a test)
- **TDD anchor:** Manual verification + reproducible curl. The negative-control curl (`curl -sS -X POST https://api.sigilsec.ai/v1/billing/webhook -H 'Stripe-Signature: t=1,v1=bad' -d '{}' -w '%{http_code}'`) IS the assertion — expected 400.
- **Scope:** moderate (manual verification)
- **Notes:** PRD US-003 explicitly forbids comparing secret values directly — this story enforces that rule by using a round-trip 200 + a negative 400 as the only acceptable evidence pair.

### US-103: Audit `require_plan(PlanTier.PRO)` route inventory
- **Status:** TODO
- **Goal:** Reproducible list of all routes that gate on Pro tier, used as the source-of-truth for which endpoint US-105 calls in steps 2 and 6.
- **Done when:** `evidence/F-003/US-103-pro-gated-routes.md` exists with output of `grep -rn "require_plan(PlanTier.PRO)" api/routers/` (or equivalent ripgrep), one line per route, with the HTTP method + path resolved (e.g., `POST /v1/interactive/investigate`). The chosen "canary" route for US-105 (recommended: `POST /v1/interactive/investigate`) is named at the bottom with rationale.
- **Files:** `evidence/F-003/US-103-pro-gated-routes.md` (new)
- **Dependencies:** none
- **TDD anchor:** The grep command itself — `grep -rn "require_plan(PlanTier.PRO)" api/routers/` should return ≥18 hits per the PRD intro. If <18, that's a red flag (gate may have been removed); investigate before proceeding.
- **Scope:** trivial
- **Notes:** Locks in the canary endpoint so US-105 evidence is comparable to a documented baseline. Cheap insurance against scope drift.

### US-104: Free-mode 403 baseline probe (no auth needed for the deny path)
- **Status:** TODO
- **Goal:** Document that the canary Pro route returns 403 for an authenticated free-tier user (lower bound of the round-trip; not a sentinel of success but a sentinel that the gate is on).
- **Done when:** `evidence/F-003/US-104-free-403-baseline.md` exists with: (1) the curl command including a real Auth0 free-tier JWT (token redacted in evidence — only the `sub` claim and tier from MSSQL), (2) full response headers + body showing HTTP 403, (3) MSSQL query `SELECT id, email, subscription_tier FROM users WHERE email = ?` (parameterised) confirming `subscription_tier='free'` for that user.
- **Files:** `evidence/F-003/US-104-free-403-baseline.md` (new)
- **Dependencies:** US-103 (need to know which route to hit)
- **TDD anchor:** `curl -sS -X POST https://api.sigilsec.ai/<canary-route> -H "Authorization: Bearer <free-jwt>" -w '\n%{http_code}\n'` — expected `403`. The MSSQL row dump is the second assertion.
- **Scope:** moderate (manual verification)
- **Notes:** Uses `?` placeholder per aioodbc/MSSQL conventions and CLAUDE.md no-fake-data rules. JWT must come from a real Auth0 signup, not a hand-rolled token; the lessons.md "synthetic data presented as production data destroys trust" rule applies — capture the Auth0 sign-in flow's token, do not mint one.

### US-105: Stripe TEST-mode end-to-end round-trip
- **Status:** TODO
- **Goal:** Observed and recorded full PRD §3 loop in test mode: signup → 403 → checkout → webhook → tier=pro → 200 → portal cancel → tier=free → 403.
- **Done when:** `evidence/F-003/US-105-testmode-roundtrip.md` exists with sections (in order, each with timestamp + raw command/response):
  1. Auth0 signup confirmation (email + Auth0 user_id)
  2. MSSQL row T0: `SELECT id, email, subscription_tier, stripe_customer_id, stripe_subscription_id FROM users WHERE email = ?` showing `subscription_tier='free'`, customer/sub IDs NULL
  3. Canary Pro route 403 (curl + response)
  4. `POST /v1/billing/subscribe` request + response — response URL must start `https://checkout.stripe.com/` (NOT `cs_test_<tier>_…` stub)
  5. Stripe Checkout completion with `4242 4242 4242 4242` — Stripe event ID for `customer.subscription.created`
  6. Webhook handler log line (from container logs) showing 200 + the event ID
  7. MSSQL row T1 (within 30s of T0+5): `subscription_tier='pro'`, `stripe_customer_id=cus_…`, `stripe_subscription_id=sub_…` populated
  8. Canary Pro route 200 with truncated body confirming real LLM response (not a stub)
  9. `POST /v1/billing/portal` returns a `https://billing.stripe.com/…` URL
  10. Portal cancellation event ID for `customer.subscription.deleted`
  11. MSSQL row T2: `subscription_tier='free'`
  12. Canary Pro route 403 again
- **Files:** `evidence/F-003/US-105-testmode-roundtrip.md` (new)
- **Dependencies:** US-100, US-101, US-102, US-103, US-104
- **TDD anchor:** Manual end-to-end. The 12-section evidence file IS the assertion — each section must contain the literal command + literal response. No automated test substitutes for an actual paid Checkout session.
- **Scope:** complex (manual verification, owner or operator-driven)
- **Notes:** Lessons.md applies: do NOT fabricate any of the 12 sections. If the webhook does not fire within 30s, story stays TODO and the gap is filed as a F-003 sub-bug. The `cs_test_<tier>_<cycle>_<ts>` stub from `dashboard/src/app/api/billing/create-checkout/route.ts` is the canary for "wrong path was taken" — if section 4's URL matches that pattern, the dashboard is calling the dead route and US-106 must be done first.

### US-106: Delete dead `dashboard/src/app/api/billing/create-checkout/route.ts`
- **Status:** TODO
- **Goal:** No production code path returns a fabricated `cs_test_…` URL after this story (FR-5).
- **Done when:** (1) `grep -rn "/api/billing/create-checkout" /Users/reecefrazier/CascadeProjects/sigil/dashboard/src` returns zero matches, (2) `dashboard/src/app/api/billing/create-checkout/route.ts` does not exist, (3) `pnpm --filter dashboard build` (or repo-standard build command) exits 0, (4) the pricing-page upgrade CTA from US-105 step 4 still returns a real `checkout.stripe.com` URL on a re-probe (re-run just step 4 of US-105 evidence). Evidence at `evidence/F-003/US-106-dead-route-removed.md`.
- **Files:** `dashboard/src/app/api/billing/create-checkout/route.ts` (delete), `evidence/F-003/US-106-dead-route-removed.md` (new)
- **Dependencies:** US-105 (must have observed real path working before deleting the alternative)
- **TDD anchor:** The grep command — `grep -rn "/api/billing/create-checkout" dashboard/src` must return empty. The `pnpm build` exit code is the second assertion.
- **Scope:** trivial
- **Notes:** PRD US-004 has an "if callers exist, migrate them" branch — US-105 step 4 already proves no caller depends on it (since the real `checkout.stripe.com` URL came back). If US-105 returned a `cs_test_<tier>_…` stub, this story flips to "moderate" because callers must be re-pointed at `/v1/billing/subscribe` first.

### US-107: Free-trial decision and pricing-page reconciliation
- **Status:** BLOCKED-pending-owner-decision
- **Goal:** Pricing-page free-trial copy reflects an owner decision (enabled-and-working OR removed) — never an aspirational claim.
- **Done when:** EITHER (A) owner records "free-trial REMOVED" decision in `SOLUTION.md` ADR log AND `dashboard/src/app/pricing/page.tsx` has no "free trial" / "trial" string in any Pro CTA AND production-fetched `https://www.sigilsec.ai/pricing` HTML grep for `free trial` returns zero (after US-112 cache fix); OR (B) owner records "free-trial ENABLED" decision, the live Stripe Price for Pro has `trial_period_days` set, US-105 is re-run with the trialing flow showing `subscription.status='trialing'` + tier still gating correctly during trial, and the trial-end transition is captured. Evidence at `evidence/F-003/US-107-free-trial-resolution.md`.
- **Files:** `evidence/F-003/US-107-free-trial-resolution.md` (new), `SOLUTION.md` (append ADR row), `dashboard/src/app/pricing/page.tsx` (modify if Branch A)
- **Dependencies:** US-105 (Branch B requires re-running the round-trip), US-112 (Branch A requires CDN-current pricing page to grep)
- **TDD anchor:** Branch A — the production-HTML grep is the assertion: `curl -sS https://www.sigilsec.ai/pricing | grep -i 'free trial'` returns empty. Branch B — re-run of US-105 with `subscription.status='trialing'` captured in MSSQL evidence.
- **Scope:** moderate (manual verification + owner-gated)
- **Notes:** PRD Q3 — owner intent unknown. Planner cannot decide; flagging as BLOCKED. Default recommendation in absence of decision: Branch A (remove), because shipping advertised-but-unverified behaviour is a direct CHARTER Article II violation.

### US-108: Investigate CDN cache `age: ~1.8M` on www.sigilsec.ai/pricing
- **Status:** TODO
- **Goal:** Root cause of the 21-day-stale `age` header documented before any fix is applied.
- **Done when:** `evidence/F-003/US-108-cdn-investigation.md` exists with: (1) current `curl -sS -I https://www.sigilsec.ai/pricing` response (full headers including `age`, `cache-control`, `x-vercel-cache`, `x-vercel-id`, `etag`), (2) Vercel deployment list (`vercel ls` or dashboard screenshot) showing the latest production deploy timestamp, (3) probe from a second region (curl with a different network egress) to determine if it's a single-edge issue or global, (4) named root cause from {`stale Vercel build cache`, `origin cache header misconfig`, `CDN config never invalidated`, `other — describe`}, (5) recommended fix sized as trivial/moderate.
- **Files:** `evidence/F-003/US-108-cdn-investigation.md` (new)
- **Dependencies:** none
- **TDD anchor:** The curl headers IS the data. No automated assertion appropriate for the investigate phase — this is diagnostic.
- **Scope:** moderate (manual verification)
- **Notes:** PRD US-006 splits into investigate + fix because the brief at §4 lists three plausible causes (Vercel build hash, edge config, origin) and the fix is different per cause. If root cause is "needed redeploy", US-112 fix is trivial; if it's `cache-control` header coming from the framework rendering, US-112 may need a code change.

### US-109: Stripe LIVE-mode end-to-end round-trip with one real $29 charge
- **Status:** BLOCKED-pending-owner-action
- **Goal:** Observed and recorded full PRD §3 loop in live mode using a real card; charge refunded after; webhook reverses tier on refund.
- **Done when:** `evidence/F-003/US-109-livemode-roundtrip.md` exists with the same 12-section structure as US-105 PLUS: section 13 = Stripe Dashboard invoice URL/ID showing `paid: true, amount: 2900, currency: usd, livemode: true`, section 14 = refund event ID, section 15 = MSSQL row T3 showing `subscription_tier='free'` post-refund. Refund must be issued within 24h of charge per PRD AC.
- **Files:** `evidence/F-003/US-109-livemode-roundtrip.md` (new)
- **Dependencies:** US-105 (test-mode must pass first), US-100, US-101, US-102 (config audit must pass)
- **TDD anchor:** Manual end-to-end with real money. 15-section evidence file IS the assertion. No automated substitute exists.
- **Scope:** complex (manual verification, owner-only)
- **Notes:** PRD Q2 explicitly notes only the owner has live-mode Stripe access. This story does NOT proceed without owner explicit confirmation per CHARTER Article II + Auto-mode rule 6 ("Auto mode is not a license to destroy" — a real $29 charge is destructive financial action requiring owner go-ahead). Treat as a sequenced gate, not a build-phase task.

### US-110: Probe `/v1/billing/plans` for live Pro pricing surface
- **Status:** TODO
- **Goal:** Documented snapshot of what `/v1/billing/plans` returns in production, used as the API-side mirror to the pricing-page audit.
- **Done when:** `evidence/F-003/US-110-billing-plans-snapshot.md` contains the verbatim output of `curl -sS https://api.sigilsec.ai/v1/billing/plans | jq` and a per-tier row showing: tier name, price (must show $29 for Pro), interval support (monthly + annual), feature list count. Discrepancies vs pricing page (US-111) flagged.
- **Files:** `evidence/F-003/US-110-billing-plans-snapshot.md` (new)
- **Dependencies:** none
- **TDD anchor:** `curl -sS https://api.sigilsec.ai/v1/billing/plans | jq '.[] | select(.tier=="pro") | .price_monthly'` — expected `29` (or `2900` cents, document the unit). The exact assertion lives in the evidence file based on observed schema.
- **Scope:** trivial
- **Notes:** Cheap; runs against prod; gives a second data source if pricing-page diverges from API. Useful diagnostic for US-108/US-112 (if API is current but page is not, points clearly at CDN, not at code).

### US-111: Pricing-page byte-equal probe (localhost vs production)
- **Status:** TODO
- **Goal:** Documented diff between freshly built dashboard `pricing/page.tsx` rendered output and production-fetched HTML, used as the freshness-check assertion for US-112.
- **Done when:** `evidence/F-003/US-111-pricing-page-diff.md` contains: (1) `pnpm --filter dashboard build && pnpm --filter dashboard start` (or `next build && next start`) on localhost, captured `curl -sS http://localhost:3000/pricing`, (2) `curl -sS https://www.sigilsec.ai/pricing`, (3) a `diff` of the two with explanation of every divergence (CSP nonces, build hashes are expected; copy text divergences are the story's signal). Ideally byte-equal modulo nonces.
- **Files:** `evidence/F-003/US-111-pricing-page-diff.md` (new)
- **Dependencies:** US-112 (run AFTER cache fix — running before just confirms the staleness)
- **TDD anchor:** `diff <(curl -sS http://localhost:3000/pricing | sed 's/nonce="[^"]*"//g') <(curl -sS https://www.sigilsec.ai/pricing | sed 's/nonce="[^"]*"//g')` — the diff output IS the evidence. Zero meaningful divergence is the success condition.
- **Scope:** moderate
- **Notes:** PRD US-006 AC: "Pricing-page HTML byte-equal between localhost build and prod fetch (or diff explained)". This story is the explicit "or diff explained" mechanism. Must run AFTER US-112 to be meaningful.

### US-112: CDN cache fix — apply remediation from US-108 root cause
- **Status:** TODO
- **Goal:** Production www.sigilsec.ai/pricing serves an `age` header < 3600 seconds on a fresh probe.
- **Done when:** (1) Fix from US-108's recommendation applied (cache purge, redeploy, header config change — depending on cause), (2) `evidence/F-003/US-112-cdn-fix-verification.md` contains: pre-fix `curl -I` showing the stale `age`, the exact remediation command/action with timestamp, post-fix `curl -I` (waited ≥60s after fix to avoid catching mid-propagation) showing `age` < 3600, (3) a second probe 5 minutes later showing `age` increasing monotonically (proves cache is now serving fresh and aging normally, not stuck).
- **Files:** `evidence/F-003/US-112-cdn-fix-verification.md` (new); other files depend on US-108 root cause (e.g., `dashboard/next.config.js` if header config, none if pure cache purge)
- **Dependencies:** US-108
- **TDD anchor:** `curl -sS -I https://www.sigilsec.ai/pricing | grep -i '^age:' | awk '{print $2}'` — expected integer < 3600. Second probe asserts strictly increasing.
- **Scope:** moderate (could be trivial if pure purge)
- **Notes:** Split from US-108 because the fix may involve a code change (moderate) or a one-button purge (trivial). Sizing TBD by US-108 outcome.

### US-113: Flip F-003 status in SOLUTION.md and progress.md
- **Status:** TODO
- **Goal:** SOLUTION.md F-003 row shows `Status: DONE` with shipped date; progress.md shows DONE for US-100 through US-112.
- **Done when:** (1) `SOLUTION.md` F-003 section status changed from `BUILT — pending end-to-end verification` to `DONE` with `Shipped: 2026-05-XX`, all 7 acceptance-criteria checkboxes ticked with evidence file paths cited inline, (2) `progress.md` has DONE entries for US-100 through US-112 each pointing at their evidence file, (3) PRD `tasks/prd-pro-billing-gating-verification.md` Success Criteria items 1–8 each marked complete with evidence pointer.
- **Files:** `SOLUTION.md` (modify F-003 section), `progress.md` (append/modify), `tasks/prd-pro-billing-gating-verification.md` (modify Success Criteria section)
- **Dependencies:** US-100, US-101, US-102, US-103, US-104, US-105, US-106, US-107, US-108, US-109, US-110, US-111, US-112
- **TDD anchor:** `grep -E '^\*\*Status:\*\* DONE' SOLUTION.md` after F-003 heading returns the line. `grep -c "US-1[01][0-9]" progress.md` returns ≥13.
- **Scope:** trivial
- **Notes:** This story is the explicit close-out gate. Does not get DONE if any of US-100..US-112 are TODO/BLOCKED — including US-109, which means the story may sit pending until owner runs the live charge. That is correct: F-003 is genuinely not done until live mode is proven.

## Dependency DAG

```
US-100 ──┐
US-101 ──┼─→ US-105 ──┬─→ US-106 ──→ US-113
US-102 ──┤            │
US-103 ──┤            ├─→ US-109 ──→ US-113   (US-109 also gated on US-100/101/102)
US-104 ──┘            │
US-110 ───────────────┘   (independent, feeds into US-113 evidence)

US-108 ──→ US-112 ──→ US-111 ──→ US-107 (Branch A) ──→ US-113
                                    │
                                    └─→ US-105 (Branch B re-run) ──→ US-113
```

Parallel-safe wave 1 (no dependencies): US-100, US-101, US-103, US-108, US-110
Parallel-safe wave 2 (after wave 1): US-102 (needs US-101), US-104 (needs US-103), US-112 (needs US-108)
Sequential wave 3: US-105 (needs US-100, US-101, US-102, US-103, US-104)
Sequential wave 4: US-106 (needs US-105), US-111 (needs US-112), US-109 (needs US-105 + config audit)
Sequential wave 5: US-107 (needs US-105 or US-111 depending on branch)
Final: US-113 (needs everything)

## Escalation boundaries

- **US-109** — Real $29 live-mode charge. Auto-mode rule 6 forbids destructive financial actions without owner sign-off. Story does not move past BLOCKED until the owner explicitly says "charge the card now" in-session. Refund must be issued within 24h per PRD AC; this is a chained owner action.
- **US-107** — Free-trial enable/remove decision is an owner ADR call (PRD Q3). Default-to-remove is the safer bet under CHARTER Article II but requires owner ratification before US-113.
- **US-100, US-101, US-102** — These require Stripe Dashboard live-mode access and `az` CLI access scoped to `sigil-rg`. If the executing session lacks those, escalate; do NOT mark DONE on partial evidence.
- **Auth0 blocker (PRD Q1)** — If US-105 fails at signup because Auth0 production callback URL is misconfigured, that is an out-of-scope blocker per PRD "Dependencies and Constraints" — file a separate issue and pause F-003 rather than working around it.

## Suggested execution order

1. **Wave 1 (parallel, ~5–10 min each)**: US-100, US-101, US-103, US-108, US-110 — all read-only audits, can be batched. Surface any config drift before running the round-trip.
2. **Wave 2 (parallel)**: US-102 (after US-101), US-104 (after US-103), US-112 (after US-108). At this point all preconditions for the round-trip are verified; cache is current.
3. **Wave 3**: US-111 — confirm pricing page is byte-equal to localhost build. If divergent, debug before involving Stripe.
4. **Wave 4**: US-105 — the test-mode round-trip. Single most important story; failure here means the rest of F-003 is still BUILT, not DONE.
5. **Wave 5**: US-106 — delete dead route now that the real path is observed working.
6. **Wave 6**: US-107 — owner free-trial decision; if Branch A (remove), simple copy edit; if Branch B (keep), re-run US-105 with trialing flow.
7. **Wave 7 (owner-gated)**: US-109 — live $29 charge + refund. Only after every other story is DONE.
8. **Wave 8**: US-113 — flip statuses; the close-out.

Rationale for ordering: cheapest audits first (waves 1–2) so any config rot is found before burning a Stripe Checkout session. Round-trip in test mode (wave 4) before any code change (wave 5) so the dead-route deletion has a positive control. Live-mode charge last (wave 7) because every other story is a precondition for it being safe.

## Open questions

- **Q-A (carry-over from PRD Q3):** Free-trial intent — owner to decide before US-107 can leave BLOCKED. Recommended default: REMOVE.
- **Q-B (carry-over from PRD Q2):** US-109 — owner personally runs the live charge, or delegates? Determines scheduling, not scope.
- **Q-C (planner-introduced):** Does `/v1/billing/subscribe` accept the same JWT as `/v1/interactive/investigate` (i.e., is there a single bearer token that suffices for the entire US-105 round-trip), or does Checkout flow require a separate session cookie from the dashboard? PRD assumes single bearer; if not, US-105 evidence schema needs a "session handoff" sub-section. Cheap to confirm in wave 1 by reading `api/routers/billing.py:394` Auth dependency. Not a planning blocker — flagged for the build-phase agent to verify in the first 2 minutes of US-105.

### Critical Files for Implementation
- /Users/reecefrazier/CascadeProjects/sigil/api/routers/billing.py
- /Users/reecefrazier/CascadeProjects/sigil/api/routers/interactive.py
- /Users/reecefrazier/CascadeProjects/sigil/api/gates.py
- /Users/reecefrazier/CascadeProjects/sigil/dashboard/src/app/api/billing/create-checkout/route.ts
- /Users/reecefrazier/CascadeProjects/sigil/dashboard/src/app/pricing/page.tsx
