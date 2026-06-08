# Rollback Runbook

Date: 2026-06-08

## Rollback Triggers

Rollback or halt launch if any of these occur after deployment:

- `https://app.sigilsec.ai/signup` returns 404.
- `https://www.sigilsec.ai/install.sh` serves private-development copy.
- `https://api.sigilsec.ai/health` does not return 200.
- `/v1/billing/plans` disagrees with visible public pricing.
- Protected API routes return 404/500 instead of 401/403 for unauthenticated requests.

## Verification Commands

```bash
curl -sS -I https://www.sigilsec.ai/pricing
curl -sS https://www.sigilsec.ai/install.sh | sed -n '1,40p'
curl -sS -I https://app.sigilsec.ai/signup
curl -sS -i https://api.sigilsec.ai/health
curl -sS -i https://api.sigilsec.ai/v1/billing/plans
```

## Rollback Notes

This session did not perform a deployment, so no concrete deployment ID was captured. Use the hosting provider's last known good deployment for `https://www.sigilsec.ai` and `https://app.sigilsec.ai`, and the previous healthy Azure Container App revision for `sigil-api`.

Do not roll back API changes without checking whether Stripe webhook, Auth0, and database schema state depend on the newer revision.
