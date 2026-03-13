# Deploy Auth0 Configuration to Azure

Your Auth0 credentials are now set in `dashboard/.env.production`. Here's how to deploy them to Azure Container Apps.

## ✅ Configuration Template

Set these values in `dashboard/.env.production`:

```bash
AUTH0_DOMAIN=<your-auth0-domain>
AUTH0_SECRET=<generate-with-openssl-rand-hex-32>
AUTH0_BASE_URL=https://app.sigilsec.ai
AUTH0_ISSUER_BASE_URL=https://auth.sigilsec.ai
AUTH0_CLIENT_ID=<your-auth0-client-id>
AUTH0_CLIENT_SECRET=<your-auth0-client-secret>
AUTH0_AUDIENCE=https://api.sigilsec.ai
GITHUB_CLIENT_ID=<your-github-oauth-client-id>
GITHUB_CLIENT_SECRET=<your-github-oauth-client-secret>
```

## 🚀 Deploy to Azure (One Command)

```bash
./scripts/deploy_env_to_azure.sh
```

This script will:
1. ✅ Load all variables from `dashboard/.env.production`
2. ✅ Validate required secrets are present
3. ✅ Show you what will be deployed (without exposing secrets)
4. ✅ Ask for confirmation
5. ✅ Deploy to Azure Container App `sigil-dashboard`
6. ✅ Store secrets securely in Azure
7. ✅ Verify deployment status

## 📋 What Gets Deployed

### Public Environment Variables
- `NEXT_PUBLIC_API_URL=https://api.sigilsec.ai`
- `AUTH0_BASE_URL=https://app.sigilsec.ai`
- `AUTH0_ISSUER_BASE_URL=https://auth.sigilsec.ai`
- `AUTH0_CLIENT_ID=<your-auth0-client-id>`
- `AUTH0_DOMAIN=<your-auth0-domain>`
- `GITHUB_CLIENT_ID=<your-github-oauth-client-id>`
- `NEXT_TELEMETRY_DISABLED=1`

### Secrets (Stored Securely)
- `auth0-secret` → `AUTH0_SECRET`
- `auth0-client-secret` → `AUTH0_CLIENT_SECRET`
- `github-client-secret` → `GITHUB_CLIENT_SECRET`

## ⚠️ Before Deploying

### 1. Verify Auth0 Application Settings

Go to [Auth0 Dashboard](https://manage.auth0.com/dashboard) → Applications → **Sigil Dashboard** → Settings

**Ensure these URLs are configured:**

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

### 2. Verify GitHub OAuth App

Go to [GitHub Settings](https://github.com/settings/developers) → OAuth Apps → Your App

**Authorization callback URL should be:**
```
https://auth.sigilsec.ai/login/callback
```

### 3. Login to Azure

```bash
az login
```

## 🎯 Deployment Steps

### Step 1: Deploy Secrets

```bash
./scripts/deploy_env_to_azure.sh
```

Expected output:
```
🚀 Deploying .env.production to Azure Container Apps

✅ Found dashboard/.env.production
✅ Azure CLI configured
✅ Found container app: sigil-dashboard

📋 Loading environment variables from dashboard/.env.production

Configuration to deploy:
  NEXT_PUBLIC_API_URL: https://api.sigilsec.ai
  AUTH0_BASE_URL: https://app.sigilsec.ai
  AUTH0_ISSUER_BASE_URL: https://auth.sigilsec.ai
  AUTH0_CLIENT_ID: <your-auth0-client-id>
  AUTH0_AUDIENCE: https://api.sigilsec.ai
  AUTH0_DOMAIN: <your-auth0-domain>
  AUTH0_SECRET: ******* (secret)
  AUTH0_CLIENT_SECRET: ******* (secret)
  GITHUB_CLIENT_ID: <your-github-oauth-client-id>
  GITHUB_CLIENT_SECRET: ******* (secret)
  NEXT_TELEMETRY_DISABLED: 1

✅ All required variables present

Deploy these secrets to Azure? (y/n)
```

Type `y` and press Enter.

### Step 2: Wait for Deployment

The script will:
- Update the container app
- Wait 15 seconds for deployment
- Show deployment status

Expected output:
```
🔄 Updating Azure Container App...

✅ Secrets deployed successfully

⏳ Waiting for deployment to complete...

Deployment Status:
  Status: Running
  Latest Revision: sigil-dashboard--xyz123

✅ Dashboard is running

🎉 Deployment complete!
```

### Step 3: Verify Configuration

```bash
./scripts/get_azure_auth0_config.sh
```

Expected output:
```
✅ AUTH0_SECRET: configured (secret: auth0-secret)
✅ AUTH0_CLIENT_SECRET: configured (secret: auth0-client-secret)
✅ All Auth0 configuration is set
```

### Step 4: Test Login

Visit: **https://app.sigilsec.ai/login**

Expected flow:
1. Click "Sign in with Sigil" → redirects to Auth0
2. Login with credentials, GitHub, or Google
3. Redirects back to dashboard
4. User is authenticated ✅

## 🔍 Troubleshooting

### Check Deployment Logs

```bash
az containerapp logs show \
  --name sigil-dashboard \
  --resource-group sigil-rg \
  --follow
```

### Verify Container App Status

```bash
az containerapp show \
  --name sigil-dashboard \
  --resource-group sigil-rg \
  --query "properties.runningStatus" -o tsv
```

### Common Issues

**"AUTH0_SECRET is required"**
- Secret not deployed correctly
- Re-run: `./scripts/deploy_env_to_azure.sh`

**"Callback URL mismatch"**
- Auth0 application missing callback URL
- Add: `https://app.sigilsec.ai/api/auth/callback`

**Login redirects to localhost**
- `AUTH0_BASE_URL` not set correctly
- Verify in Azure: `./scripts/get_azure_auth0_config.sh`

**"Invalid state parameter"**
- Clear browser cookies
- Try again in incognito mode

## 📚 Additional Resources

- **Azure Secrets Guide:** `docs/AZURE_AUTH0_SECRETS_GUIDE.md`
- **Full Auth0 Setup:** `docs/AUTH0_PRODUCTION_SETUP.md`
- **Quick Start:** `docs/QUICK_START_AUTH0_PRODUCTION.md`

## 🔐 Security Notes

1. **Never commit `.env.production` to git** - It contains real secrets
2. **Secrets are stored in Azure** - Not in environment variables
3. **Use `secretref:` pattern** - Keeps secrets encrypted
4. **Rotate secrets regularly** - Update via deployment script

## ✅ Success Checklist

- [ ] Auth0 Application URLs configured
- [ ] GitHub OAuth callback URL set
- [ ] Logged into Azure CLI
- [ ] Ran `./scripts/deploy_env_to_azure.sh`
- [ ] Deployment status shows "Running"
- [ ] Configuration verified with `get_azure_auth0_config.sh`
- [ ] Login tested at `https://app.sigilsec.ai/login`
- [ ] User can authenticate successfully

---

**Ready to deploy?** Run: `./scripts/deploy_env_to_azure.sh`
