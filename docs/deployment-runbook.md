# Deployment Runbook

Date: 2026-06-08

## Verified Resources

Resource names and URLs below are recorded in `.nomark/resources.json`.

- Public web: `https://www.sigilsec.ai`
- App web: `https://app.sigilsec.ai`
- API: `https://api.sigilsec.ai`
- Auth0 domain: `https://auth.sigilsec.ai`
- Azure resource group: `sigil-rg`
- Azure Container App: `sigil-api`
- Azure Container Registry: `sigilacr46iy6y.azurecr.io`

## Pre-Deploy Checks

```bash
npm ci --ignore-scripts
cd dashboard && npm test -- --runInBand
cd dashboard && npm run build
python3 -m pytest api/tests -q
./bin/sigil --version
```

Do not proceed to public launch while `python3 -m pytest api/tests -q` fails or while the public signup/pricing/install checks fail.

## Public Web Verification

```bash
curl -sS -I https://www.sigilsec.ai/
curl -sS -I https://www.sigilsec.ai/pricing
curl -sS https://www.sigilsec.ai/install.sh | sed -n '1,40p'
```

Expected before launch:

- `/pricing` must not show stale 30-day trial copy unless the 30-day trial is actually implemented.
- `/install.sh` must serve the real installer, not private-development copy.

## App Verification

```bash
curl -sS -I https://app.sigilsec.ai/login
curl -sS -I https://app.sigilsec.ai/signup
curl -sS -I 'https://app.sigilsec.ai/api/auth/login?screen_hint=signup'
```

Expected before launch:

- `/signup` must not return 404.
- Auth redirect must point at `https://auth.sigilsec.ai/authorize`.

## API Verification

```bash
curl -sS -i https://api.sigilsec.ai/health
curl -sS -i https://api.sigilsec.ai/v1/billing/plans
curl -sS -i -X POST https://api.sigilsec.ai/v1/interactive/investigate -H 'Content-Type: application/json' -d '{}'
```

Expected:

- `/health` returns 200 with database and Redis connected.
- `/v1/billing/plans` prices match the public pricing page.
- Unauthenticated protected routes return 401, not 404 or 500.
