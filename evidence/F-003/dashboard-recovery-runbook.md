# Dashboard Recovery Runbook — Post-Terraform Env Wipe

**Captured:** 2026-05-03 11:50Z
**Resolved:** 2026-05-03 12:17Z (sigil-infra PR #2 merged → rev 0019 created → pod restart)
**Status:** RESOLVED — dashboard auth restored, terraform now owns all env + secrets
**Cause:** sigil-infra terraform apply (rev 0018) wiped 9 env vars + 3 secrets that had been set imperatively via `az containerapp update` outside terraform's spec. Terraform-owned full env spec is authoritative.

## Resolution Trail

1. Operator rotated GitHub OAuth client secret at github.com/settings/developers
2. 5 GH Actions secrets set in NOMARJ/sigil-infra (AUTH0_SECRET, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, GH_OAUTH_CLIENT_ID, GH_OAUTH_CLIENT_SECRET)
3. PR #2 merged → workflow `25278780487` triggered
4. Container App modifications all completed at 12:11:48Z (api, dashboard, bot_watchers, bot_workers, bot_pr_worker — 5 monitor_metric_alert errors are unrelated out-of-band state drift, do not block container app applies)
5. Rev 0019 created with 14 env vars + 5 secret refs (dashboard-auth0-secret, dashboard-auth0-client-id, dashboard-auth0-client-secret, dashboard-github-oauth-client-id, dashboard-github-oauth-client-secret)
6. Initial pod served stale env from rev 0018 — `az containerapp revision restart` forced fresh env read
7. Smoke test: `GET /api/auth/login` → 302 with correct Auth0 redirect URL (client_id, audience, PKCE state all present)

## Final Smoke Evidence

```
HTTP/2 302
location: https://auth.sigilsec.ai/authorize?client_id=WzNmPGqml7IKSAcSCwz8lhwyv383CKfq
        &scope=openid%20profile%20email
        &response_type=code
        &redirect_uri=https%3A%2F%2Fapp.sigilsec.ai%2Fapi%2Fauth%2Fcallback
        &audience=https%3A%2F%2Fapi.sigilsec.ai
        &nonce=...&state=...&code_challenge_method=S256&code_challenge=...
set-cookie: auth_verification=...; Secure; HttpOnly; SameSite=lax
```

## Lessons Captured

- `feedback_no_imperative_secrets_in_terraform_infra.md` — when terraform owns the resource, recover via TF PR
- After a terraform apply that changes env vars, **restart the active revision** to force a fresh env read; new revisions inherit env at creation, but live pods may keep cached state until restart

## Outstanding (separate work)

- 5 `azurerm_monitor_metric_alert` resources need `terraform import` — they exist in Azure but not in TF state. Apply step will keep failing on those until imported. Operator-only state surgery.

## sigil-api Drift Status: Already Resolved by PR #2

PR #2 (`9821c44`) declared `SIGIL_AUTH0_DOMAIN` + `SIGIL_AUTH0_AUDIENCE` on `azurerm_container_app.api` at the same time as the dashboard fix. Verified 2026-05-04: TF declares 29 env vars, runtime has 29, diff is empty. No PR #3 needed.

## Current Live State

| Resource | State |
|---|---|
| `sigil-dashboard` rev 0017 | image `9b13983`, 15 env vars (good), **inactive** (replicas=0) |
| `sigil-dashboard` rev 0018 | image `:latest`, 5 env vars (no AUTH0), **active** (replicas=1) |
| Traffic split | rev 0017 = 100%, rev 0018 = 0% |
| Net effect | 100% of requests routed to a revision that has no replicas → 404 |
| `sigil-api` rev 0075 | hotfixed with manual `az containerapp update --set-env-vars` (working) |
| Container App secrets on dashboard | only `acr-password` remains; `auth0-secret`, `auth0-client-secret`, `github-client-secret` were stripped |

## Why Imperative `az containerapp secret set` Was Rejected

Operator decision (2026-05-03): no placeholder secrets in shared production infrastructure. The path forward is declarative — sigil-infra PR #2 declares all 3 secret blocks + 9 env vars in terraform. No band-aid fixes that bypass the terraform spec.

## Forward Path — sigil-infra PR #2

PR: https://github.com/NOMARJ/sigil-infra/pull/2
Branch: `fix/restore-auth0-env-vars-in-tf`
State: OPEN, MERGEABLE, no checks queued

### Operator Action Required (5 GitHub Actions secrets in NOMARJ/sigil-infra)

Before merging PR #2, set these in repo settings → Secrets and variables → Actions:

| Secret name | Value source | Notes |
|---|---|---|
| `AUTH0_SECRET` | `dashboard/.env.local` AUTH0_SECRET | 32-hex random |
| `AUTH0_CLIENT_ID` | rev 0017 env: `WzNmPGqml7IKSAcSCwz8lhwyv383CKfq` | non-secret but TF needs it |
| `AUTH0_CLIENT_SECRET` | `dashboard/.env.local` AUTH0_CLIENT_SECRET | Auth0 app client secret |
| `GH_OAUTH_CLIENT_ID` | rev 0017 env: `Ov23liKKJJXkHIVqOJnD` | non-secret but TF needs it |
| `GH_OAUTH_CLIENT_SECRET` | **Rotate at GitHub** — value was wiped, no copy on disk | See rotation steps below |

### GitHub OAuth Client Secret Rotation

1. https://github.com/settings/developers → find OAuth App with client ID `Ov23liKKJJXkHIVqOJnD`
2. Generate new client secret
3. Save the new value to `GH_OAUTH_CLIENT_SECRET` GH Actions secret in NOMARJ/sigil-infra
4. Also update `dashboard/.env.local` locally for dev parity

### Once Secrets Are Set

```bash
gh pr merge 2 --repo NOMARJ/sigil-infra --squash
gh run watch -R NOMARJ/sigil-infra
```

PR #2 includes the wrapper fix from PR #1 (already merged), so the Apply step will report real exit codes. Expected outcome: terraform apply rebuilds dashboard env spec with all 9 vars + 3 secrets, container apps creates a new revision, dashboard auth restored.

### Post-Merge Verification

```bash
curl -sI https://app.sigilsec.ai/api/auth/login | head -3
# Expected: HTTP/2 302 with Location: https://auth.sigilsec.ai/authorize?...
```

If still 404, check the new revision spec:
```bash
az containerapp revision list -n sigil-dashboard -g sigil-rg --query "[?properties.active].{name:name, env_count:length(properties.template.containers[0].env)}" -o table
```
Expect env_count >= 14.

## Why Not Activate Rev 0017

- Rev 0017 references 3 secrets that no longer exist on the Container App (terraform stripped them)
- Activation fails with `ContainerAppSecretNotFound: auth0-secret, auth0-client-secret, github-client-secret`
- Setting those secrets imperatively via `az containerapp secret set` would conflict with terraform's spec on the next apply (terraform would strip them again unless declared in TF)
- PR #2 declares them in TF — that's the correct fix-once path

## Why Not Hotfix Rev 0018

Same reason — any imperative `--set-env-vars` or `secret set` would be wiped on next terraform apply. The cycle of imperative fixes → terraform wipe → manual recovery is the root of this incident.

## Lessons (filed in tasks/lessons.md)

- **Secrets must be declared in IaC.** Setting Container App secrets via `az` imperatively, when terraform owns the full container_app spec, guarantees a wipe on the next apply.
- **Terraform owns full env spec.** When a resource block declares `env { ... }` blocks, terraform replaces the entire env array on apply. Partial overlay does not exist for this attribute.
- **No placeholder secrets in production.** Even time-boxed placeholders create real attack surface and inject silent failure modes (e.g. an OAuth flow that 500s instead of failing closed).
