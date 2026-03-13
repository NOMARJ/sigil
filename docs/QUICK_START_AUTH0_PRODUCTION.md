# Quick Start: Fix Auth0 Login at app.sigilsec.ai

## Problem

Visiting `https://app.sigilsec.ai/auth/login` shows error: `"Login handler failed. CAUSE: \"secret\" is required"`

## Root Cause

The production deployment is missing Auth0 environment variables. The dashboard code is correctly configured for Auth0, but the deployment platform doesn't have the required environment variables set.

## Solution (5 Minutes)

### Step 1: Get Auth0 Client Secret

1. Go to [Auth0 Dashboard](https://manage.auth0.com/dashboard)
2. Navigate to: **Applications** → **Sigil Dashboard**
3. Click **Settings** tab
4. Copy the **Client Secret** value

### Step 2: Generate AUTH0_SECRET

```bash
openssl rand -hex 32
```

Copy the output (64-character hex string)

### Step 3: Set Environment Variables

Set these in your deployment platform (Vercel/Netlify/Azure):

```bash
AUTH0_SECRET=<output-from-step-2>
AUTH0_BASE_URL=https://app.sigilsec.ai
AUTH0_ISSUER_BASE_URL=https://auth.sigilsec.ai
AUTH0_CLIENT_ID=<your-auth0-client-id>
AUTH0_CLIENT_SECRET=<from-step-1>
AUTH0_AUDIENCE=https://api.sigilsec.ai
NEXT_PUBLIC_API_URL=https://api.sigilsec.ai
```

### Step 4: Verify Auth0 Application Settings

In Auth0 Dashboard → Applications → Sigil Dashboard → Settings:

**Allowed Callback URLs** must include:
```
https://app.sigilsec.ai/api/auth/callback
```

**Allowed Logout URLs** must include:
```
https://app.sigilsec.ai
```

**Allowed Web Origins** must include:
```
https://app.sigilsec.ai
```

### Step 5: Redeploy

Trigger a new deployment with the environment variables set.

### Step 6: Test

Visit: `https://app.sigilsec.ai/login`

Expected behavior:
1. Click "Sign in with Sigil" → redirects to Auth0
2. Login with email/password, GitHub, or Google
3. Redirects back to dashboard
4. User is authenticated ✅

---

## Platform-Specific Commands

### Vercel

```bash
vercel env add AUTH0_SECRET production
vercel env add AUTH0_BASE_URL production
vercel env add AUTH0_ISSUER_BASE_URL production
vercel env add AUTH0_CLIENT_ID production
vercel env add AUTH0_CLIENT_SECRET production
vercel env add AUTH0_AUDIENCE production

vercel --prod
```

### Netlify

Add via UI: **Site settings** → **Environment variables** → **Add a variable**

Or via CLI:
```bash
netlify env:set AUTH0_SECRET "your-secret-here"
netlify env:set AUTH0_BASE_URL "https://app.sigilsec.ai"
netlify env:set AUTH0_ISSUER_BASE_URL "https://auth.sigilsec.ai"
netlify env:set AUTH0_CLIENT_ID "your-auth0-client-id"
netlify env:set AUTH0_CLIENT_SECRET "your-client-secret-here"
netlify env:set AUTH0_AUDIENCE "https://api.sigilsec.ai"

netlify deploy --prod
```

### Azure Container Apps

```bash
az containerapp update \
  --name sigil-dashboard \
  --resource-group sigil-rg \
  --set-env-vars \
    "AUTH0_SECRET=<your-secret>" \
    "AUTH0_BASE_URL=https://app.sigilsec.ai" \
    "AUTH0_ISSUER_BASE_URL=https://auth.sigilsec.ai" \
    "AUTH0_CLIENT_ID=<your-auth0-client-id>" \
    "AUTH0_CLIENT_SECRET=<your-client-secret>" \
    "AUTH0_AUDIENCE=https://api.sigilsec.ai"
```

---

## What's Already Working

✅ Dashboard code has Auth0 integration (`@auth0/nextjs-auth0`)  
✅ Auth0 routes configured at `/api/auth/[auth0]/route.ts`  
✅ Login page uses `loginWithOAuth()` correctly  
✅ API backend verifies Auth0 RS256 JWT tokens  
✅ Auth0 custom domain `auth.sigilsec.ai` configured  

**Only missing:** Production environment variables

---

## Full Documentation

See `docs/AUTH0_PRODUCTION_SETUP.md` for complete setup guide including troubleshooting.
