# Rollback Runbook

Last updated: 2026-06-27

## Verified Resources

All names below come from `.nomark/resources.json`. Do not write infrastructure
references from memory — look them up there first.

| Resource | Name | Notes |
|---|---|---|
| Azure resource group | `sigil-rg` | eastus |
| Azure Container App — API | `sigil-api` | image: `sigil-api:TAG` |
| Azure Container App — bot watchers | `sigil-bot-watchers` | image: `sigil-bot:TAG` |
| Azure Container App — bot workers | `sigil-bot-workers` | image: `sigil-bot:TAG` |
| Azure Container App — bot PR worker | `sigil-bot-pr-worker` | image: `sigil-bot:TAG` |
| Public web | `https://www.sigilsec.ai` | Vercel |
| App web | `https://app.sigilsec.ai` | Vercel |
| API | `https://api.sigilsec.ai` | Azure Container Apps ingress |

## Rollback Triggers

Roll back immediately if any of these occur after deployment:

- `https://api.sigilsec.ai/health` does not return 200 with database and Redis connected.
- `https://app.sigilsec.ai/signup` returns 404.
- `https://www.sigilsec.ai/install.sh` serves a private-development copy.
- `/v1/billing/plans` disagrees with visible public pricing page.
- Protected API routes return 404 or 500 instead of 401 for unauthenticated requests.

Do not roll back API changes without checking whether Stripe webhook, Auth0, and
database schema state depend on the newer revision.

## Roll Back Container Apps

### Step 1 — List revisions and identify the last healthy one

Run for each container app. The most recent active revision with replicas > 0 and
no error spikes is the target.

```bash
az containerapp revision list \
  --name sigil-api \
  --resource-group sigil-rg \
  --query "[].{name:name, active:properties.active, replicas:properties.replicas, created:properties.createdTime}" \
  --output table

az containerapp revision list \
  --name sigil-bot-watchers \
  --resource-group sigil-rg \
  --query "[].{name:name, active:properties.active, replicas:properties.replicas, created:properties.createdTime}" \
  --output table

az containerapp revision list \
  --name sigil-bot-workers \
  --resource-group sigil-rg \
  --query "[].{name:name, active:properties.active, replicas:properties.replicas, created:properties.createdTime}" \
  --output table

az containerapp revision list \
  --name sigil-bot-pr-worker \
  --resource-group sigil-rg \
  --query "[].{name:name, active:properties.active, replicas:properties.replicas, created:properties.createdTime}" \
  --output table
```

### Step 2 — Redirect traffic to the previous healthy revision

Replace `$PREV_REVISION` with the revision name from Step 1.

```bash
# sigil-api
PREV_REVISION=<revision-name-from-step-1>
az containerapp ingress traffic set \
  --name sigil-api \
  --resource-group sigil-rg \
  --revision-weight ${PREV_REVISION}=100

# sigil-bot-watchers
PREV_REVISION=<revision-name-from-step-1>
az containerapp ingress traffic set \
  --name sigil-bot-watchers \
  --resource-group sigil-rg \
  --revision-weight ${PREV_REVISION}=100

# sigil-bot-workers
PREV_REVISION=<revision-name-from-step-1>
az containerapp ingress traffic set \
  --name sigil-bot-workers \
  --resource-group sigil-rg \
  --revision-weight ${PREV_REVISION}=100

# sigil-bot-pr-worker
PREV_REVISION=<revision-name-from-step-1>
az containerapp ingress traffic set \
  --name sigil-bot-pr-worker \
  --resource-group sigil-rg \
  --revision-weight ${PREV_REVISION}=100
```

### Step 3 — Verify traffic has shifted

```bash
az containerapp revision list \
  --name sigil-api \
  --resource-group sigil-rg \
  --query "[?properties.active==\`true\`].{name:name, trafficWeight:properties.trafficWeight}" \
  --output table
```

Expected: 100% weight on the previous revision, 0% on the bad one.

## Roll Back Web Frontends

`www.sigilsec.ai` and `app.sigilsec.ai` deploy via Vercel. Rollback is done through
the Vercel dashboard:

1. Open the Vercel dashboard and navigate to the project (`www` or `app`).
2. Open **Deployments** and locate the last known-good deployment.
3. Click **...** → **Promote to Production** on that deployment.
4. Wait for the promotion to complete and run the verification checks below.

## Post-Rollback Verification

```bash
curl -sS -I https://www.sigilsec.ai/
curl -sS -I https://www.sigilsec.ai/pricing
curl -sS https://www.sigilsec.ai/install.sh | sed -n '1,40p'
curl -sS -I https://app.sigilsec.ai/login
curl -sS -I https://app.sigilsec.ai/signup
curl -sS -i https://api.sigilsec.ai/health
curl -sS -i https://api.sigilsec.ai/v1/billing/plans
curl -sS -i -X POST https://api.sigilsec.ai/v1/interactive/investigate \
  -H 'Content-Type: application/json' -d '{}'
```

Expected:
- `/health` returns 200 with database and Redis connected.
- `/signup` does not return 404.
- `/install.sh` serves the real installer.
- Unauthenticated protected routes return 401, not 404 or 500.

## Incident Logging

After any rollback, append an entry to `docs/internal/incidents.md` (create if absent):

```markdown
## Incident <YYYY-MM-DD>
- **Trigger:** [which check failed]
- **Bad revision:** [revision name]
- **Rolled back to:** [revision name]
- **Time to rollback:** [minutes]
- **Root cause:** [short description]
- **Follow-up:** [PR / issue link]
```
