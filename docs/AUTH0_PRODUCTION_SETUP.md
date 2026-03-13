# Auth0 Production Setup for app.sigilsec.ai

## Overview

This guide configures Auth0 Universal Login for the production dashboard at `https://app.sigilsec.ai`.

## Current Status

✅ **Dashboard Code:** Auth0 integration complete (`@auth0/nextjs-auth0` v3.8.0)  
✅ **Auth0 Domain:** `auth.sigilsec.ai` (custom domain configured)  
✅ **API Backend:** Auth0 RS256 JWT verification implemented  
⚠️ **Production Env:** Needs environment variables configured in deployment platform

---

## Auth0 Application Configuration

### Step 1: Verify Application Settings

Go to [Auth0 Dashboard](https://manage.auth0.com/dashboard) → Applications → **Sigil Dashboard**

**Application Type:** Regular Web Application

**Application URIs:**

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

**Credentials:**
- **Domain:** `auth.sigilsec.ai`
- **Client ID:** `<your-auth0-client-id>`
- **Client Secret:** (stored securely in Auth0 dashboard)
- **Audience:** `https://api.sigilsec.ai`

---

## Step 2: Configure Social Connections

### GitHub OAuth

1. Go to **Authentication** → **Social** → **GitHub**
2. Verify **Authorization callback URL:**
   ```
   https://auth.sigilsec.ai/login/callback
   ```
3. Ensure connection is enabled for **Sigil Dashboard** application

### Google OAuth

1. Go to **Authentication** → **Social** → **Google**
2. Verify **Authorized redirect URI:**
   ```
   https://auth.sigilsec.ai/login/callback
   ```
3. Ensure connection is enabled for **Sigil Dashboard** application

---

## Step 3: Deployment Platform Configuration

### Environment Variables

Set these in your deployment platform (Vercel, Netlify, Azure, etc.):

```bash
# Auth0 Configuration
AUTH0_SECRET=<generate-with-openssl-rand-hex-32>
AUTH0_BASE_URL=https://app.sigilsec.ai
AUTH0_ISSUER_BASE_URL=https://auth.sigilsec.ai
AUTH0_CLIENT_ID=<your-auth0-client-id>
AUTH0_CLIENT_SECRET=<from-auth0-dashboard>
AUTH0_AUDIENCE=https://api.sigilsec.ai

# API Backend
NEXT_PUBLIC_API_URL=https://api.sigilsec.ai

# Telemetry
NEXT_TELEMETRY_DISABLED=1
```

**Generate AUTH0_SECRET:**
```bash
openssl rand -hex 32
```

**Get AUTH0_CLIENT_SECRET:**
1. Go to Auth0 Dashboard → Applications → Sigil Dashboard
2. Settings tab → Basic Information
3. Copy the Client Secret value

### Platform-Specific Instructions

#### Vercel

```bash
# Install Vercel CLI
npm i -g vercel

# Set environment variables
vercel env add AUTH0_SECRET production
vercel env add AUTH0_BASE_URL production
vercel env add AUTH0_ISSUER_BASE_URL production
vercel env add AUTH0_CLIENT_ID production
vercel env add AUTH0_CLIENT_SECRET production
vercel env add AUTH0_AUDIENCE production
vercel env add NEXT_PUBLIC_API_URL production

# Deploy
vercel --prod
```

#### Netlify

Add to `netlify.toml`:

```toml
[build.environment]
  NEXT_PUBLIC_API_URL = "https://api.sigilsec.ai"

[context.production.environment]
  AUTH0_BASE_URL = "https://app.sigilsec.ai"
  AUTH0_ISSUER_BASE_URL = "https://auth.sigilsec.ai"
  AUTH0_CLIENT_ID = "WzNmPGqml7IKSAcSCwz8lhwyv383CKfq"
  AUTH0_AUDIENCE = "https://api.sigilsec.ai"
```

Then set secrets via Netlify UI:
- `AUTH0_SECRET`
- `AUTH0_CLIENT_SECRET`

#### Azure Container Apps

```bash
az containerapp update \
  --name sigil-dashboard \
  --resource-group sigil-rg \
  --set-env-vars \
    "AUTH0_SECRET=secretref:auth0-secret" \
    "AUTH0_BASE_URL=https://app.sigilsec.ai" \
    "AUTH0_ISSUER_BASE_URL=https://auth.sigilsec.ai" \
    "AUTH0_CLIENT_ID=<your-auth0-client-id>" \
    "AUTH0_CLIENT_SECRET=secretref:auth0-client-secret" \
    "AUTH0_AUDIENCE=https://api.sigilsec.ai" \
    "NEXT_PUBLIC_API_URL=https://api.sigilsec.ai"
```

---

## Step 4: Test the Login Flow

### 1. Test Direct Login

Visit: `https://app.sigilsec.ai/login`

Expected flow:
1. Click "Sign in with Sigil" → redirects to `https://auth.sigilsec.ai`
2. Auth0 Universal Login page loads
3. Enter credentials or choose social login
4. Redirects to `https://app.sigilsec.ai/api/auth/callback`
5. Callback handler exchanges code for tokens
6. Redirects to `https://app.sigilsec.ai/` (dashboard home)

### 2. Test GitHub OAuth

1. Click "Continue with GitHub"
2. Redirects to `https://auth.sigilsec.ai/authorize?connection=github`
3. GitHub authorization page
4. Approve → redirects back to Auth0
5. Auth0 redirects to `https://app.sigilsec.ai/api/auth/callback`
6. Dashboard home page loads with user authenticated

### 3. Test Google OAuth

Same flow as GitHub, but with `connection=google-oauth2`

### 4. Verify API Integration

Once logged in, check browser console:

```javascript
// Should see successful API calls
fetch('https://api.sigilsec.ai/v1/auth/me', {
  headers: {
    'Authorization': 'Bearer <auth0-jwt-token>'
  }
})
```

---

## Troubleshooting

### "Callback URL mismatch"

**Cause:** Auth0 application doesn't have `https://app.sigilsec.ai/api/auth/callback` in Allowed Callback URLs

**Fix:**
1. Go to Auth0 Dashboard → Applications → Sigil Dashboard → Settings
2. Add to Allowed Callback URLs: `https://app.sigilsec.ai/api/auth/callback`
3. Save Changes

### "Invalid state parameter"

**Cause:** `AUTH0_SECRET` not set or changed between requests

**Fix:**
1. Generate new secret: `openssl rand -hex 32`
2. Set in deployment platform environment variables
3. Redeploy application
4. Clear browser cookies and try again

### "Audience validation failed"

**Cause:** API not configured to accept Auth0 audience

**Fix:**
Verify API environment variables:
```bash
SIGIL_AUTH0_DOMAIN=auth.sigilsec.ai
SIGIL_AUTH0_AUDIENCE=https://api.sigilsec.ai
SIGIL_AUTH0_CLIENT_ID=WzNmPGqml7IKSAcSCwz8lhwyv383CKfq
```

### Login redirects to localhost

**Cause:** `AUTH0_BASE_URL` not set in production

**Fix:**
Set `AUTH0_BASE_URL=https://app.sigilsec.ai` in deployment platform

### "Failed to fetch user profile"

**Cause:** API can't verify Auth0 JWT tokens

**Fix:**
1. Verify API has Auth0 configuration
2. Check API logs for JWT verification errors
3. Ensure Auth0 JWKS endpoint is accessible: `https://auth.sigilsec.ai/.well-known/jwks.json`

---

## Security Checklist

- [ ] `AUTH0_SECRET` is at least 32 characters (use `openssl rand -hex 32`)
- [ ] `AUTH0_CLIENT_SECRET` stored as secret/encrypted environment variable
- [ ] Never commit `.env.local` or `.env.production` with real secrets to git
- [ ] HTTPS enforced for all callback URLs (no HTTP in production)
- [ ] CORS configured in API to allow `https://app.sigilsec.ai`
- [ ] Auth0 custom domain SSL certificate valid
- [ ] Rate limiting enabled on Auth0 login endpoints
- [ ] MFA available for admin accounts

---

## Login Flow Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  User visits: https://app.sigilsec.ai/login                 │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Click "Sign in with Sigil" or social provider              │
│  → window.location.href = "/api/auth/login?connection=..."  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Next.js API Route: /api/auth/[auth0]/route.ts              │
│  → handleLogin() from @auth0/nextjs-auth0                   │
│  → Redirects to: https://auth.sigilsec.ai/authorize         │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Auth0 Universal Login Page                                 │
│  → User authenticates (email/password, GitHub, Google)      │
│  → Auth0 generates authorization code                       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Auth0 redirects to:                                        │
│  https://app.sigilsec.ai/api/auth/callback?code=...&state=..│
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Next.js API Route: /api/auth/[auth0]/route.ts              │
│  → handleCallback() from @auth0/nextjs-auth0                │
│  → Exchanges code for tokens (access_token, id_token)       │
│  → Creates encrypted session cookie                         │
│  → Redirects to: https://app.sigilsec.ai/                   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Dashboard Home Page                                        │
│  → Reads session cookie                                     │
│  → Calls /api/auth/token to get access_token                │
│  → Makes API calls with: Authorization: Bearer <token>      │
└─────────────────────────────────────────────────────────────┘
```

---

## API Token Verification

The API verifies Auth0 tokens using RS256 public key verification:

```python
# api/routers/auth.py
async def verify_auth0_token(token: str) -> dict[str, Any]:
    """Verify Auth0 RS256 JWT token using JWKS."""
    
    # Fetch JWKS from Auth0
    jwks_url = f"https://{settings.auth0_domain}/.well-known/jwks.json"
    
    # Decode and verify token
    payload = jwt.decode(
        token,
        key=jwks_client.get_signing_key_from_jwt(token).key,
        algorithms=["RS256"],
        audience=settings.auth0_audience,
        issuer=f"https://{settings.auth0_domain}/",
    )
    
    return payload
```

---

## Next Steps

After deployment:

1. **Test all login flows** (email/password, GitHub, Google)
2. **Monitor Auth0 logs** for authentication errors
3. **Set up monitoring** for failed login attempts
4. **Configure MFA** for admin accounts
5. **Review security settings** in Auth0 dashboard

---

## Support

If you encounter issues:

1. **Check Auth0 Logs:** [Dashboard → Monitoring → Logs](https://manage.auth0.com/dashboard/us/dev-xekq8s5o2x8o84p5/logs)
2. **Check API Logs:** `docker compose logs api` or deployment platform logs
3. **Verify Environment Variables:** Ensure all required vars are set in production
4. **Test Locally First:** Use `.env.local` to test before deploying

**Contact:** support@sigilsec.ai
