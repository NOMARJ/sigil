# US-100 Evidence: Stripe Env Audit (PARTIAL — Price IDs only; Container Apps env not accessible from this session)

**Feature:** F-003 Pro Billing + Tier Gating Verification
**Story:** STORY-100
**Status:** PARTIAL — 2/4 Price IDs verified live-mode; 2/4 missing locally; Container Apps env not accessible
**Captured:** 2026-05-03 (autopilot session, owner-authorized live-key API call)
**Verifier:** Claude Code (Opus 4.7) — `api.stripe.com` read-only

---

## Reproducibility

```bash
( set -a; . api/.env; set +a; \
  for id in "$SIGIL_STRIPE_PRICE_PRO" "$SIGIL_STRIPE_PRICE_TEAM"; do \
    curl -sS "https://api.stripe.com/v1/prices/$id" \
      -H "Authorization: Bearer $SIGIL_STRIPE_SECRET_KEY" \
      | jq '{id, livemode, active, unit_amount, currency, product, type, recurring}'; \
  done )
```

## Verbatim Stripe API Response — Pro

```json
{
  "id": "price_1T2AOLFhPhxEz27fs0Z2nU4y",
  "livemode": true,
  "active": true,
  "unit_amount": 2900,
  "currency": "usd",
  "type": "recurring",
  "product": "prod_U0AjyTY923R8J5",
  "recurring": {
    "interval": "month",
    "interval_count": 1,
    "meter": null,
    "trial_period_days": null,
    "usage_type": "licensed"
  }
}
```

## Verbatim Stripe API Response — Team

```json
{
  "id": "price_1T2AQCFhPhxEz27fOjCVsuwe",
  "livemode": true,
  "active": true,
  "unit_amount": 9900,
  "currency": "usd",
  "type": "recurring",
  "product": "prod_U0Al82KNwdy7iR",
  "recurring": {
    "interval": "month",
    "interval_count": 1,
    "meter": null,
    "trial_period_days": null,
    "usage_type": "licensed"
  }
}
```

## Per-Variable Verdict

| Variable (PRD AC) | Local `api/.env` | Stripe livemode | active | Amount | Verdict |
|-------------------|------------------|-----------------|--------|--------|---------|
| `STRIPE_SECRET_KEY` (handler) | present | (n/a — used to make these calls) | n/a | n/a | implicit PASS — only a live secret key would return `livemode: true` from these endpoints |
| `STRIPE_WEBHOOK_SECRET` (handler) | present | (verified indirectly via STORY-102 negative control) | n/a | n/a | implicit PASS at signature-verify level |
| `STRIPE_PRICE_PRO` (`price_1T2AOLFhPhxEz27fs0Z2nU4y`) | present | true | true | $29.00/month | **PASS** |
| `STRIPE_PRICE_TEAM` (`price_1T2AQCFhPhxEz27fOjCVsuwe`) | present | true | true | $99.00/month | **PASS** |
| `STRIPE_PRICE_PRO_ANNUAL` | **MISSING** | n/a | n/a | n/a | **FAIL — not configured in `api/.env`** |
| `STRIPE_PRICE_TEAM_ANNUAL` | **MISSING** | n/a | n/a | n/a | **FAIL — not configured in `api/.env`** |

## Findings

### F1 — Pro and Team monthly Price IDs are correctly configured (live-mode, active, $29/$99/month)

Both monthly Price IDs match the public `/v1/billing/plans` API surface (per STORY-110 evidence) and resolve to live-mode active recurring Stripe Prices. The `unit_amount: 2900` (Pro) and `9900` (Team) match the dashboard / API copy ($29 and $99). USD currency, monthly interval. `usage_type: licensed` (per-seat / fixed price).

### F2 — Annual Price IDs are NOT configured in `api/.env`

`SIGIL_STRIPE_PRICE_PRO_ANNUAL` and `SIGIL_STRIPE_PRICE_TEAM_ANNUAL` (or any `*_ANNUAL` / `*_YEARLY` variants) are absent from the local `api/.env` file.

But `/v1/billing/plans` exposes annual pricing (`price_yearly: 232.0` for Pro, `792.0` for Team — STORY-110). So either:
- (a) The annual prices are returned from a hardcoded value in the plans-listing code, not from a Stripe Price object — meaning a user attempting to subscribe annually would fail at the Stripe Checkout step.
- (b) The annual Price IDs ARE configured on the running Container App (via Azure Key Vault → env var injection) but were never copied to local `api/.env`.

**This requires `az containerapp show` to disambiguate** — out of reach from this session (no Azure CLI access).

If (a): annual subscription is a half-baked feature that ships a price but cannot accept payment. Defect, recommend disabling annual UI until configured.
If (b): local dev env diverges from production env. Recommend syncing `.env.example` / docs to ensure new contributors know annual price IDs exist.

### F3 — `trial_period_days: null` on both monthly Prices — direct evidence for STORY-107

Neither Price has `trial_period_days` configured at the Stripe level. So:
- A subscription created against either Price will NOT include a trial.
- Any pricing-page copy advertising a "free trial" or "30-day free trial" is **not delivered by Stripe** — the user would be charged immediately on Checkout.
- This is direct evidence supporting STORY-107 Branch A (REMOVE) — there is no working trial; the pricing copy is misleading.

This finding makes the STORY-107 owner decision low-stakes: Branch A is the only correct choice unless the operator wants to ALSO configure `trial_period_days` on the Stripe Price (Branch B). Recording for STORY-107 evidence.

### F4 — Stripe API version `2025-06-30.basil` (from STORY-101 endpoint metadata)

Both endpoints emit events at `api_version: 2025-06-30.basil`. Confirm the Sigil handler is compatible with this version. Out of scope here — flag for `docs/internal/2026-05-stripe-config-audit.md`.

## What This Story Does NOT Cover

PRD AC §1: `az containerapp show -n sigil-api -g sigil-rg --query 'properties.template.containers[0].env'` — verifies the **running** Container App's env-var resolution. **Not done** — requires Azure CLI access not available from this autopilot session.

PRD AC §1 specifically requires:
- `STRIPE_SECRET_KEY` value reference resolves to a `sk_live_...` key (verified by Stripe key fingerprint). This audit only proves that whatever key is in `api/.env` is live (because Stripe accepted it). It does NOT prove the production Container App is using the same / a live key. Production may have a different key configured.

To close STORY-100 fully, operator runs:

```bash
# Confirm STRIPE_* env vars are present on the production Container App.
az containerapp show -n sigil-api -g sigil-rg \
  --query 'properties.template.containers[0].env[?contains(name, `STRIPE`)].{name:name, secretRef:secretRef}' \
  -o tsv

# Expected output: 6 rows (STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_PRO,
# STRIPE_PRICE_TEAM, STRIPE_PRICE_PRO_ANNUAL, STRIPE_PRICE_TEAM_ANNUAL).
# secretRef points at Key Vault — values are NOT logged.

# Then for each *_PRICE_* env var, retrieve via Stripe API and confirm livemode:true, active:true.
# Annual Price IDs in particular need to come from there since they're missing from local api/.env.
```

## Verdict

PARTIAL PASS:
- [x] Monthly Pro Price ID: live-mode + active + correct amount.
- [x] Monthly Team Price ID: live-mode + active + correct amount.
- [x] Stripe SECRET_KEY in `api/.env` is live-mode (proven implicitly: API returned livemode:true objects).
- [x] Webhook secret signing is enforced (per STORY-102 negative control).
- [ ] Annual Pro Price ID — MISSING locally; Container App audit required.
- [ ] Annual Team Price ID — MISSING locally; Container App audit required.
- [ ] Container App `properties.template.containers[0].env` snapshot — not captured (no Azure CLI).

**Net:** The 2 monthly Price IDs are confirmed good. The 4-Price-ID requirement is not fully verifiable from this session. The story stays PARTIAL until the operator runs the `az containerapp show` audit and feeds annual Price IDs back through this same Stripe API check.
