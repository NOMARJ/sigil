# US-100 Update: Live Stripe Price IDs confirmed via MCP

**Captured:** 2026-05-04 (autopilot session, Stripe MCP)
**Account:** `acct_1RkD8NFhPhxEz27f` (NOMARK, live mode)
**Verifier:** Claude Code (Opus 4.7) via `mcp__claude_ai_Stripe__list_products` + `list_prices`

## Products

| Product | ID |
|---|---|
| Sigil Pro | `prod_U0AjyTY923R8J5` |
| Sigil Team | `prod_U0Al82KNwdy7iR` |

## Prices (all `active`, `livemode: true` implied by live-account connection)

| Tier | Interval | Price ID | Amount | Currency | Trial |
|---|---|---|---|---|---|
| Pro | month | `price_1T2AOLFhPhxEz27fs0Z2nU4y` | 2900 (=$29.00) | USD | none |
| Pro | year | `price_1T2AnKFhPhxEz27fNp6Kt7O3` | 23200 (=$232.00) | USD | none |
| Team | month | `price_1T2AQCFhPhxEz27fOjCVsuwe` | 9900 (=$99.00) | USD | none |
| Team | year | `price_1T2AlpFhPhxEz27f8tni554h` | 79200 (=$792.00) | USD | none |

All four prices: `type=recurring`, `interval_count=1`, `usage_type=licensed`, `trial_period_days=null`, `meter=null`.

## Annual discount sanity check

- Pro: $232 / ($29 × 12 = $348) → **33.3% saving** for annual
- Team: $792 / ($99 × 12 = $1188) → **33.3% saving** for annual

Identical 33% discount on both tiers — consistent annual promotion math.

## Verification of `trial_period_days: null`

Both products' annual + monthly prices return `trial_period_days: null`. This reaffirms STORY-107 Branch A evidence: there is no Stripe-side free trial configured. If pricing-page copy mentions "free trial", it's product/marketing copy, not an enforced Stripe trial.

## Operator action taken (autopilot, 2026-05-04 22:23Z)

Two GH Actions secrets set on `NOMARJ/sigil-infra`:
- `STRIPE_PRICE_PRO_ANNUAL` = `price_1T2AnKFhPhxEz27fNp6Kt7O3`
- `STRIPE_PRICE_TEAM_ANNUAL` = `price_1T2AlpFhPhxEz27f8tni554h`

Combined with sigil-infra PR #3 (open at https://github.com/NOMARJ/sigil-infra/pull/3), once merged the running `sigil-api` Container App will have all 4 Price ID env vars populated:
- `SIGIL_STRIPE_PRICE_PRO` = `price_1T2AOLFhPhxEz27fs0Z2nU4y` (literal in deploy.yml heredoc)
- `SIGIL_STRIPE_PRICE_TEAM` = `price_1T2AQCFhPhxEz27fOjCVsuwe` (literal)
- `SIGIL_STRIPE_PRICE_PRO_ANNUAL` = `price_1T2AnKFhPhxEz27fNp6Kt7O3` (from GH secret)
- `SIGIL_STRIPE_PRICE_TEAM_ANNUAL` = `price_1T2AlpFhPhxEz27f8tni554h` (from GH secret)

## Status

STORY-100 finding (1) — annual prices "could be stub annual pricing without backing Stripe Price (would fail at Checkout)" — **disproved**. All 4 backing Stripe Prices exist, are live, are active, and resolve to the expected dollar amounts. STORY-100 partial finding can now be closed once PR #3 lands.

## Reproducibility

```python
# In a session with claude.ai Stripe MCP connected to acct_1RkD8NFhPhxEz27f:
list_prices(product="prod_U0AjyTY923R8J5")  # Sigil Pro
list_prices(product="prod_U0Al82KNwdy7iR")  # Sigil Team
```
