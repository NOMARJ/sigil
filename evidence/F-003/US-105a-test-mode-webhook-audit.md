# US-003 / US-105a — Test-mode Stripe Webhook Subscription Audit

**Feature:** F-003 Pro Billing + Tier Gating Verification (closeout PRD)
**Story:** US-003 — test-mode Stripe webhook endpoint must subscribe to all 6 required events before US-005 (test-mode round-trip) can execute.
**Status:** PARTIAL — autopilot blocked on Stripe credentials for `acct_1RkD8NFhPhxEz27f` (Sigil/NOMARK account); operator runbook below.
**Captured:** 2026-05-04 (autopilot, branch `feature/f-003-closeout`)
**Re-attempted:** 2026-06-21 (autopilot, branch `claude/admiring-hopper-0q4dj4`, NOM-884)

---

## Audit Target

Sigil's test-mode Stripe webhook endpoint must be subscribed to the full 6-event union enforced for live-mode in STORY-101:

```
checkout.session.completed
customer.subscription.created
customer.subscription.updated
customer.subscription.deleted
invoice.payment_succeeded
invoice.payment_failed
```

This is the same set of events the live-mode endpoint `we_1T2AXKFhPhxEz27fCYP53mKc` was reconfigured to subscribe to in `evidence/F-003/US-101-fix-applied.md` (verified `count: 6`). The test-mode endpoint sits in the same Stripe account (`acct_1RkD8NFhPhxEz27f`) and must match before US-005's test-card flow can be observed end-to-end.

## What Autopilot Tried

### 1. Stripe MCP

Available operations (from `mcp__claude_ai_Stripe__stripe_api_search`) cover Customers, Payment Intents, Charges, Invoices, Prices, Products, Subscriptions, Coupons, Payment Links, Promotion Codes — and **not** `WebhookEndpoints`. Direct execution attempts:

```
mcp__claude_ai_Stripe__stripe_api_execute(
  stripe_api_operation_id="GetWebhookEndpoints",
  parameters={"limit": 20}
)
→ Error: Operation 'GetWebhookEndpoints' is not available. Use stripe_api_search to find available operations.
```

Searches for `webhook_endpoints`, `webhook`, and `endpoints events subscription configuration` all returned no matching operations. The Stripe MCP in this environment does not surface webhook endpoint management.

### 2. Local Stripe CLI

`stripe` CLI is installed (`/opt/homebrew/bin/stripe`, version 1.29.0) but the active configuration in `~/.config/stripe/config.toml` is for account **`acct_1TNsZTFvlPr69lA2`** ("exectables"), not the Sigil/NOMARK account **`acct_1RkD8NFhPhxEz27f`**. Running `stripe webhook_endpoints list --live=false` against the local CLI would query the wrong account and is therefore not a valid audit.

### 3. Azure Container App env

The test-mode Stripe secret (the credential needed to authenticate `curl` against `https://api.stripe.com/v1/webhook_endpoints` in test mode) lives in Azure Key Vault and is mounted into `sigil-api` via `secretRef`. CHARTER II.5 forbids exfiltrating secrets into the agent context — autopilot does not read secrets out of Container App config. This path requires operator action.

## Operator Runbook (one of the following)

### Option A — Stripe CLI with the Sigil account (preferred)

```bash
# 1. Add the Sigil project to the Stripe CLI (one-time):
stripe login --project-name sigil

# 2. List test-mode webhook endpoints subscribed to the Sigil account:
stripe webhook_endpoints list --project-name sigil

# 3. For each endpoint pointing at https://api.sigilsec.ai/v1/billing/webhook (test-mode),
#    capture the verbatim enabled_events list and the endpoint ID (we_…).
```

### Option B — Stripe Dashboard (no CLI required)

1. Sign in to https://dashboard.stripe.com.
2. Toggle to **Test mode** (top-right toggle — confirm the URL becomes `dashboard.stripe.com/test/...`).
3. Developers → Webhooks. Find the endpoint with URL `https://api.sigilsec.ai/v1/billing/webhook`.
4. Capture the endpoint ID (`we_…`) and the listed events. If any of the six required events is missing, click "Update details" → "Listen to events" → tick the missing ones → "Update endpoint".

### Option C — Direct API call with the test-mode restricted key

```bash
# Replace TEST_KEY with a Sigil test-mode secret key (sk_test_…). Do NOT paste the
# value into git or chat; export it from a local secret manager:
export STRIPE_TEST_KEY="$(...your secret store...)"

# List test-mode webhook endpoints:
curl -sS https://api.stripe.com/v1/webhook_endpoints \
  -u "${STRIPE_TEST_KEY}:" | jq '.data[] | {id, url, enabled_events, status}'

# If the Sigil endpoint exists and is missing events, replace the enabled_events:
curl -sS -X POST "https://api.stripe.com/v1/webhook_endpoints/we_TESTMODEID" \
  -u "${STRIPE_TEST_KEY}:" \
  -d "enabled_events[]=checkout.session.completed" \
  -d "enabled_events[]=customer.subscription.created" \
  -d "enabled_events[]=customer.subscription.updated" \
  -d "enabled_events[]=customer.subscription.deleted" \
  -d "enabled_events[]=invoice.payment_succeeded" \
  -d "enabled_events[]=invoice.payment_failed" | jq

# Re-verify count:
curl -sS https://api.stripe.com/v1/webhook_endpoints/we_TESTMODEID \
  -u "${STRIPE_TEST_KEY}:" | jq '{id, enabled_events_count: (.enabled_events | length), enabled_events}'
# Expected: enabled_events_count: 6
```

If the test-mode endpoint **does not exist at all**, create it pointing at the API:

```bash
curl -sS -X POST https://api.stripe.com/v1/webhook_endpoints \
  -u "${STRIPE_TEST_KEY}:" \
  -d "url=https://api.sigilsec.ai/v1/billing/webhook" \
  -d "enabled_events[]=checkout.session.completed" \
  -d "enabled_events[]=customer.subscription.created" \
  -d "enabled_events[]=customer.subscription.updated" \
  -d "enabled_events[]=customer.subscription.deleted" \
  -d "enabled_events[]=invoice.payment_succeeded" \
  -d "enabled_events[]=invoice.payment_failed" | jq
```

After creating, the response includes a `secret` field (the signing secret for this new test-mode endpoint). That secret needs to be wired to the API as `STRIPE_TEST_WEBHOOK_SECRET` (or whichever env var the test-mode webhook handler reads). Per `evidence/F-003/US-100-stripe-env-audit.md`, the live `STRIPE_WEBHOOK_SECRET` is set on the Container App; verify whether a separate test-mode key is configured or whether test-mode is meant to share one webhook handler with mode detection at the Stripe-Signature header.

## Acceptance Criteria — Status

| AC from PRD US-003 | Status |
|---|---|
| Evidence file captures test-mode endpoint ID + verbatim `enabled_events` | **PARTIAL** — runbook captured; verbatim list pending operator |
| If list missing required events, POST same fix as STORY-101 + re-verify | **PENDING** — operator action required |
| Re-verify GET shows `count: 6` containing all 6 required events | **PENDING** |

## What Closes This Story

After running Option A, B, or C above, append to this file:

```markdown
## Audit Result (operator: <name>, <ISO timestamp>)

- Endpoint ID: `we_…`
- URL: `https://api.sigilsec.ai/v1/billing/webhook` (test mode)
- Pre-fix `enabled_events` count: <N>
- Pre-fix events: [verbatim list]
- Fix applied: yes / no — <commands run>
- Post-fix `enabled_events` count: 6
- Post-fix events: [verbatim list]
- Status: enabled / disabled

Verdict: PASS — STORY-101 parity achieved for test mode; US-005 unblocked.
```

## Cross-References

- `evidence/F-003/US-101-webhook-subscription-audit.md` — live-mode endpoint audit (pre-fix).
- `evidence/F-003/US-101-fix-applied.md` — live-mode fix evidence (post-fix `count: 6`).
- `tasks/prd-remaining-f-003-work.json` US-003 — this story's PRD entry.
- `progress.md` US-003 closeout block — this story's progress entry.

## Why This Is PARTIAL Not BLOCKED

This is not a model limitation — Stripe's API supports the operation, the operator has credentials, and the runbook above is unambiguous. The block is purely a credential-sharing boundary: autopilot does not read secrets out of Azure to run a curl that the operator can run in 30 seconds with a Dashboard click. STORY-101 followed the same pattern (operator-authorized POST against live-mode); this is the test-mode mirror.

## Re-attempt Log

### 2026-05-04 (autopilot, branch `feature/f-003-closeout`)

All three blocking conditions first confirmed on this date. Stripe MCP connected to `acct_1RkD8NFhPhxEz27f` but `GetWebhookEndpoints` unavailable. Stripe CLI on wrong account. CHARTER II.5 forbids Azure secret access. Runbook written; verbatim `enabled_events` capture deferred to operator.

### 2026-06-21 (autopilot, branch `claude/admiring-hopper-0q4dj4`, NOM-884)

All three blocking conditions confirmed unchanged:

1. **Stripe MCP `GetWebhookEndpoints` — still unavailable.** Returns "Operation not available" in this session. No webhook endpoint management operations are exposed by the Stripe MCP in this cloud environment.

2. **Stripe CLI wrong account — still misconfigured.** Active CLI project is `acct_1TNsZTFvlPr69lA2` (exectables), not Sigil/NOMARK `acct_1RkD8NFhPhxEz27f`. Any `stripe webhook_endpoints list` call would query the wrong account.

3. **CHARTER II.5 credential boundary — unchanged.** The `sk_test_*` key for the Sigil Stripe account lives in Azure Key Vault / Container App secrets. Autopilot does not read secrets out of Container App config.

**Conclusion:** Runbook above remains valid and complete. No new agent-executable path identified. Operator action still required. Options A, B, and C above are all viable paths — Option B (Stripe Dashboard toggle to test mode → Developers → Webhooks) requires no CLI setup and is the fastest path. Linear comment on NOM-884 contains the operator handoff summary.
