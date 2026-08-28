# Deployment Runbook

Last updated: 2026-06-27

## Verified Resources

All names and URLs below come from `.nomark/resources.json`. Do not write infrastructure
references from memory — look them up there first.

| Resource | Name | Notes |
|---|---|---|
| Azure resource group | `sigil-rg` | eastus |
| Azure Container Registry | `sigilacr46iy6y.azurecr.io` | eastus |
| Azure Container App — API | `sigil-api` | image: `sigil-api:TAG` |
| Azure Container App — bot watchers | `sigil-bot-watchers` | image: `sigil-bot:TAG` |
| Azure Container App — bot workers | `sigil-bot-workers` | image: `sigil-bot:TAG` |
| Azure Container App — bot PR worker | `sigil-bot-pr-worker` | image: `sigil-bot:TAG` |
| Azure Redis Cache | `sigil-redis` | sigil-rg |
| Azure Key Vault | `sigil-kv-46iy6y` | sigil-rg, secrets mounted as secretRef |
| MSSQL server | `sigil-sql-w2-46iy6y.database.windows.net` | westus2, db: `sigil` |
| Public web | `https://www.sigilsec.ai` | Vercel |
| App web | `https://app.sigilsec.ai` | Vercel |
| API | `https://api.sigilsec.ai` | Azure Container Apps ingress |
| Auth0 domain | `https://auth.sigilsec.ai` | Auth0 custom domain |
| Egress IP (NAT) | `20.127.119.78` | sigil-nat, sigil-rg |

## Pre-Deploy Checks

```bash
npm ci --ignore-scripts
cd dashboard && npm test -- --runInBand
cd dashboard && npm run build
python3 -m pytest api/tests -q
./bin/sigil --version
```

Do not proceed while `python3 -m pytest api/tests -q` fails or while the public
signup/pricing/install checks below fail.

## Build Images

Set a tag before building. Use the short git SHA or a date-stamped label.

```bash
TAG=$(git rev-parse --short HEAD)
```

### sigil-api (API backend — Dockerfile)

```bash
az acr build \
  --registry sigilacr46iy6y \
  --image sigil-api:${TAG} \
  --file Dockerfile \
  .
```

### sigil-bot (bot workers — Dockerfile.bot)

```bash
az acr build \
  --registry sigilacr46iy6y \
  --image sigil-bot:${TAG} \
  --file Dockerfile.bot \
  .
```

## Database Migration Check

Before deploying a new API image, verify that any pending MSSQL migrations have been
reviewed. The migration tool runs inside the API container on startup. To run migrations
manually against the production database, exec into a running container or run a
one-off revision:

```bash
# Check current revision of sigil-api
az containerapp revision list \
  --name sigil-api \
  --resource-group sigil-rg \
  --query "[?properties.active==\`true\`].{name:name, replicas:properties.replicas}" \
  --output table
```

Do not deploy a new API image if the migration would be destructive (dropping columns
or tables) without first scheduling a maintenance window and notifying users.

## Deploy Container Apps

### sigil-api

```bash
az containerapp update \
  --name sigil-api \
  --resource-group sigil-rg \
  --image sigilacr46iy6y.azurecr.io/sigil-api:${TAG}
```

### Bot containers (watchers, workers, pr-worker)

```bash
az containerapp update \
  --name sigil-bot-watchers \
  --resource-group sigil-rg \
  --image sigilacr46iy6y.azurecr.io/sigil-bot:${TAG}

az containerapp update \
  --name sigil-bot-workers \
  --resource-group sigil-rg \
  --image sigilacr46iy6y.azurecr.io/sigil-bot:${TAG}

az containerapp update \
  --name sigil-bot-pr-worker \
  --resource-group sigil-rg \
  --image sigilacr46iy6y.azurecr.io/sigil-bot:${TAG}
```

## Deploy Web Frontends

`www.sigilsec.ai` and `app.sigilsec.ai` are deployed via Vercel. Deployments trigger
automatically on push to the production branch. To trigger a manual redeploy:

1. Open the Vercel dashboard and navigate to the project.
2. Click **Redeploy** on the latest successful build, or push a commit to the
   production branch.
3. Wait for the deployment to complete and run the Public Web Verification checks below.

## Post-Deploy Verification

### Public Web

```bash
curl -sS -I https://www.sigilsec.ai/
curl -sS -I https://www.sigilsec.ai/pricing
curl -sS https://www.sigilsec.ai/install.sh | sed -n '1,40p'
```

Expected:
- `/pricing` must not show stale 30-day trial copy unless the 30-day trial is actually
  implemented.
- `/install.sh` must serve the real installer, not private-development copy.

### App

```bash
curl -sS -I https://app.sigilsec.ai/login
curl -sS -I https://app.sigilsec.ai/signup
curl -sS -I 'https://app.sigilsec.ai/api/auth/login?screen_hint=signup'
```

Expected:
- `/signup` must not return 404.
- Auth redirect must point at `https://auth.sigilsec.ai/authorize`.

### API

```bash
curl -sS -i https://api.sigilsec.ai/health
curl -sS -i https://api.sigilsec.ai/v1/billing/plans
curl -sS -i -X POST https://api.sigilsec.ai/v1/interactive/investigate \
  -H 'Content-Type: application/json' -d '{}'
```

Expected:
- `/health` returns 200 with database and Redis connected.
- `/v1/billing/plans` prices match the public pricing page.
- Unauthenticated protected routes return 401, not 404 or 500.
