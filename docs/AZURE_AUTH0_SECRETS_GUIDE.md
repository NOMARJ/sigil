# Azure Auth0 Secrets Setup Guide

## Overview

This guide shows how to configure Auth0 environment variables as Azure Container Apps secrets for the Sigil Dashboard at `app.sigilsec.ai`.

## Quick Start

### 1. Check Current Configuration

```bash
./scripts/get_azure_auth0_config.sh
```

This will show:
- Current Auth0 environment variables
- Secret configuration status
- Container app status
- What's missing (if anything)

### 2. Set Auth0 Secrets

```bash
./scripts/set_azure_auth0_secrets.sh
```

This interactive script will:
1. Prompt for `AUTH0_SECRET` (generate with `openssl rand -hex 32`)
2. Prompt for `AUTH0_CLIENT_SECRET` (from Auth0 Dashboard)
3. Update the Azure Container App with all Auth0 configuration
4. Store secrets securely in Azure

### 3. Verify

Visit: `https://app.sigilsec.ai/login`

Expected: Auth0 login page loads correctly

---

## Manual Configuration

If you prefer to set secrets manually via Azure CLI:

### Prerequisites

```bash
# Install Azure CLI
brew install azure-cli  # macOS
# or visit: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli

# Login to Azure
az login
```

### Generate Secrets

```bash
# Generate AUTH0_SECRET (64-character hex string)
openssl rand -hex 32
```

Get `AUTH0_CLIENT_SECRET` from:
1. Go to [Auth0 Dashboard](https://manage.auth0.com/dashboard)
2. Applications → **Sigil Dashboard** → Settings
3. Copy **Client Secret**

### Set Secrets in Azure

```bash
RESOURCE_GROUP="sigil-rg"
DASHBOARD_APP="sigil-dashboard"

# Update container app with Auth0 configuration
az containerapp update \
  --name "$DASHBOARD_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --set-env-vars \
    "AUTH0_SECRET=secretref:auth0-secret" \
    "AUTH0_BASE_URL=https://app.sigilsec.ai" \
    "AUTH0_ISSUER_BASE_URL=https://auth.sigilsec.ai" \
    "AUTH0_CLIENT_ID=WzNmPGqml7IKSAcSCwz8lhwyv383CKfq" \
    "AUTH0_CLIENT_SECRET=secretref:auth0-client-secret" \
    "AUTH0_AUDIENCE=https://api.sigilsec.ai" \
    "NEXT_PUBLIC_API_URL=https://api.sigilsec.ai" \
    "NEXT_TELEMETRY_DISABLED=1" \
  --secrets \
    "auth0-secret=<your-generated-secret>" \
    "auth0-client-secret=<your-auth0-client-secret>"
```

### Verify Deployment

```bash
# Check container app status
az containerapp show \
  --name "$DASHBOARD_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --query "properties.runningStatus" -o tsv

# View logs
az containerapp logs show \
  --name "$DASHBOARD_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --follow
```

---

## Environment Variables Reference

### Required Auth0 Variables

| Variable | Value | Type | Description |
|----------|-------|------|-------------|
| `AUTH0_SECRET` | `<64-char-hex>` | Secret | Session encryption key |
| `AUTH0_BASE_URL` | `https://app.sigilsec.ai` | Public | Dashboard base URL |
| `AUTH0_ISSUER_BASE_URL` | `https://auth.sigilsec.ai` | Public | Auth0 custom domain |
| `AUTH0_CLIENT_ID` | `<your-auth0-client-id>` | Public | Auth0 application client ID |
| `AUTH0_CLIENT_SECRET` | `<from-auth0-dashboard>` | Secret | Auth0 application client secret |
| `AUTH0_AUDIENCE` | `https://api.sigilsec.ai` | Public | Auth0 API audience |
| `NEXT_PUBLIC_API_URL` | `https://api.sigilsec.ai` | Public | Backend API URL |

### Secret Storage

Secrets are stored in Azure Container Apps using the `secretref:` pattern:

```bash
# Environment variable references a secret
AUTH0_SECRET=secretref:auth0-secret

# Actual secret value stored securely
--secrets "auth0-secret=<actual-value>"
```

This keeps sensitive values encrypted and separate from environment variables.

---

## Troubleshooting

### Check if secrets are set

```bash
./scripts/get_azure_auth0_config.sh
```

Look for:
- ✅ Green checkmarks = configured correctly
- ⚠️ Yellow warnings = missing configuration

### View container app logs

```bash
az containerapp logs show \
  --name sigil-dashboard \
  --resource-group sigil-rg \
  --follow
```

Look for Auth0-related errors like:
- `AUTH0_SECRET is required`
- `AUTH0_CLIENT_SECRET is required`
- `Invalid state parameter`

### Common Issues

**"AUTH0_SECRET is required"**
- Secret not set or empty
- Run: `./scripts/set_azure_auth0_secrets.sh`

**"Invalid state parameter"**
- `AUTH0_SECRET` changed after user started login
- Clear browser cookies and try again
- Ensure `AUTH0_SECRET` is at least 32 characters

**"Callback URL mismatch"**
- Auth0 application doesn't have correct callback URL
- Add to Auth0 Dashboard: `https://app.sigilsec.ai/api/auth/callback`

**Login redirects to localhost**
- `AUTH0_BASE_URL` not set correctly
- Should be: `https://app.sigilsec.ai`

### Verify Auth0 Application Settings

In [Auth0 Dashboard](https://manage.auth0.com/dashboard):

**Applications → Sigil Dashboard → Settings:**

```
Allowed Callback URLs:
https://app.sigilsec.ai/api/auth/callback
http://localhost:3000/api/auth/callback

Allowed Logout URLs:
https://app.sigilsec.ai
http://localhost:3000

Allowed Web Origins:
https://app.sigilsec.ai
http://localhost:3000
```

---

## Updating Secrets

To update existing secrets:

```bash
# Run the setup script again
./scripts/set_azure_auth0_secrets.sh

# Or update manually
az containerapp secret set \
  --name sigil-dashboard \
  --resource-group sigil-rg \
  --secrets "auth0-secret=<new-value>"
```

**Note:** Updating secrets will trigger a new deployment revision.

---

## Security Best Practices

1. **Never commit secrets to git**
   - Secrets are stored in Azure, not in code
   - `.env.production` contains placeholders only

2. **Rotate secrets regularly**
   - Generate new `AUTH0_SECRET` periodically
   - Update via `set_azure_auth0_secrets.sh`

3. **Use Azure Key Vault (optional)**
   - For enhanced security, integrate with Azure Key Vault
   - Secrets can reference Key Vault values

4. **Monitor access**
   - Review Azure Activity Logs for secret access
   - Enable Azure Monitor alerts for configuration changes

5. **Restrict access**
   - Use Azure RBAC to limit who can view/update secrets
   - Require MFA for Azure portal access

---

## CI/CD Integration

### GitHub Actions

The secrets are set manually via Azure CLI, not through GitHub Actions. This is intentional for security.

However, you can reference them in the deployment workflow:

```yaml
# .github/workflows/deploy-azure.yml
- name: Build and push Dashboard image
  uses: docker/build-push-action@v5
  with:
    context: ./dashboard
    file: ./dashboard/Dockerfile
    push: true
    tags: ${{ env.ACR_LOGIN_SERVER }}/sigil-dashboard:${{ steps.meta.outputs.dashboard-tag }}
    build-args: |
      NEXT_PUBLIC_API_URL=https://api.sigilsec.ai
    # Note: Auth0 secrets are set in Azure Container App, not at build time
```

### Terraform

If using Terraform (in `sigil-infra` repo), you can manage secrets there:

```hcl
# container_apps.tf
resource "azurerm_container_app" "dashboard" {
  # ... other configuration ...

  secret {
    name  = "auth0-secret"
    value = var.auth0_secret
  }

  secret {
    name  = "auth0-client-secret"
    value = var.auth0_client_secret
  }

  template {
    container {
      env {
        name        = "AUTH0_SECRET"
        secret_name = "auth0-secret"
      }
      env {
        name        = "AUTH0_CLIENT_SECRET"
        secret_name = "auth0-client-secret"
      }
      # ... other env vars ...
    }
  }
}
```

Then set via GitHub Secrets in the `sigil-infra` repository.

---

## Related Documentation

- `docs/AUTH0_PRODUCTION_SETUP.md` - Complete Auth0 setup guide
- `docs/QUICK_START_AUTH0_PRODUCTION.md` - 5-minute quick fix
- `dashboard/.env.production` - Production environment template
- `dashboard/.env.local` - Local development configuration

---

## Support

If you encounter issues:

1. **Check configuration:** `./scripts/get_azure_auth0_config.sh`
2. **View logs:** `az containerapp logs show --name sigil-dashboard --resource-group sigil-rg --follow`
3. **Verify Auth0 settings:** [Auth0 Dashboard](https://manage.auth0.com/dashboard)
4. **Contact:** support@sigilsec.ai
