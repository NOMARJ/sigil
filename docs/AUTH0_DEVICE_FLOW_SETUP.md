# Auth0 Device Flow Setup for CLI Authentication

This guide explains how to configure Auth0 Device Authorization Flow for the Sigil CLI.

## Overview

The Sigil CLI uses OAuth 2.0 Device Authorization Flow (RFC 8628) for authentication. This is the industry-standard approach for CLI tools and provides:

- ✅ Secure authentication without passwords in CLI
- ✅ Works in SSH/remote environments
- ✅ Supports MFA and all Auth0 features
- ✅ No localhost server required
- ✅ Better UX than browser-based flows

## How It Works

```
┌─────────┐                                    ┌──────────┐
│   CLI   │                                    │  Auth0   │
└────┬────┘                                    └────┬─────┘
     │                                              │
     │  1. POST /oauth/device/code                 │
     ├─────────────────────────────────────────────>│
     │                                              │
     │  2. device_code + user_code                 │
     │<─────────────────────────────────────────────┤
     │                                              │
     │  3. Display: "Visit URL, enter code"        │
     │                                              │
     │                                              │
     │  4. Poll POST /oauth/token                  │
     ├─────────────────────────────────────────────>│
     │                                              │
     │  5. authorization_pending                   │
     │<─────────────────────────────────────────────┤
     │                                              │
     │  (User completes auth in browser)           │
     │                                              │
     │  6. Poll POST /oauth/token                  │
     ├─────────────────────────────────────────────>│
     │                                              │
     │  7. access_token + refresh_token            │
     │<─────────────────────────────────────────────┤
     │                                              │
```

## Auth0 Configuration

### Step 1: Enable Device Flow in Auth0 Application

1. Go to [Auth0 Dashboard](https://manage.auth0.com/dashboard/us/dev-xekq8s5o2x8o84p5/applications)
2. Select your application: **Sigil Dashboard**
3. Go to **Settings** tab
4. Scroll to **Advanced Settings** → **Grant Types**
5. Enable: ✅ **Device Code**
6. Click **Save Changes**

### Step 2: Configure Device Flow Settings

1. Still in **Advanced Settings**
2. Go to **Device Settings** tab
3. Configure:
   - **Device Code Lifetime**: 900 seconds (15 minutes)
   - **Polling Interval**: 5 seconds
4. Click **Save Changes**

### Step 3: Update Application Settings

Ensure your application has the correct settings:

```yaml
Application Type: Single Page Application
Token Endpoint Authentication Method: None
Allowed Callback URLs: http://localhost:3000/api/auth/callback
Allowed Logout URLs: http://localhost:3000
Allowed Web Origins: http://localhost:3000
```

### Step 4: Configure Universal Login

1. Go to **Branding** → **Universal Login**
2. Ensure **New Universal Login Experience** is enabled
3. Customize the device activation page (optional):
   - Go to **Advanced Options** → **Custom Text**
   - Select **Device Flow** → **device-flow-user-code-prompt**
   - Customize messaging for your brand

## API Implementation

The Sigil API provides two endpoints for device flow:

### 1. Request Device Code

```http
POST /v1/auth/device/code
Content-Type: application/json
```

**Response:**
```json
{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://auth.sigilsec.ai/activate",
  "verification_uri_complete": "https://auth.sigilsec.ai/activate?user_code=WDJB-MJHT",
  "expires_in": 900,
  "interval": 5
}
```

### 2. Poll for Token

```http
POST /v1/auth/device/token?device_code={device_code}
```

**Responses:**

**Success (200):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "refresh_token": "v1.MRrT...",
  "scope": "openid profile email offline_access"
}
```

**Pending (400):**
```json
{
  "error": "authorization_pending",
  "error_description": "User has not yet authorized"
}
```

**Slow Down (400):**
```json
{
  "error": "slow_down",
  "error_description": "Polling too frequently"
}
```

**Expired (400):**
```json
{
  "error": "expired_token",
  "error_description": "Device code expired"
}
```

**Denied (400):**
```json
{
  "error": "access_denied",
  "error_description": "User denied authorization"
}
```

## CLI Usage

### Login Flow

```bash
$ sigil login

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Sigil CLI Authentication
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Visit: https://auth.sigilsec.ai/activate
2. Enter code: WDJB-MJHT

Waiting for authentication...

✓ Authentication successful!
[info] Token stored in /Users/alice/.sigil/token
```

### User Experience

1. User runs `sigil login`
2. CLI displays verification URL and user code
3. User visits URL in browser
4. User enters code (or clicks pre-filled link)
5. User completes Auth0 login (email/password, GitHub, Google)
6. User authorizes the CLI application
7. CLI receives token and stores it
8. User can now use Pro features

### Token Storage

Tokens are stored in `~/.sigil/token` with 600 permissions:

```bash
$ cat ~/.sigil/token
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

$ ls -la ~/.sigil/token
-rw------- 1 alice staff 1234 Mar 13 07:30 /Users/alice/.sigil/token
```

## Testing

### Test Device Flow Locally

```bash
# 1. Start API
cd api
uvicorn api.main:app --reload

# 2. Request device code
curl -X POST http://localhost:8000/v1/auth/device/code

# 3. Visit verification URL and enter code

# 4. Poll for token
curl -X POST "http://localhost:8000/v1/auth/device/token?device_code={device_code}"
```

### Test CLI Login

```bash
# Run login
sigil login

# Verify token stored
cat ~/.sigil/token

# Test authenticated request
sigil scan . --pro
```

## Security Considerations

### Token Security

- ✅ Tokens stored with 600 permissions (user-only read/write)
- ✅ Tokens are Auth0 JWTs with RS256 signature
- ✅ Tokens expire after 24 hours
- ✅ Refresh tokens allow silent renewal
- ✅ Tokens can be revoked in Auth0 dashboard

### Device Code Security

- Device codes expire after 15 minutes
- User codes are short (8 chars) for easy entry
- Verification URI uses HTTPS
- Polling rate limited to prevent abuse
- Failed authorization attempts logged

### Best Practices

1. **Never commit tokens to git**
   - Add `~/.sigil/token` to global gitignore
   - Use environment variables in CI/CD

2. **Rotate tokens regularly**
   - Tokens expire automatically
   - Use `sigil logout && sigil login` to refresh

3. **Monitor token usage**
   - Check Auth0 logs for suspicious activity
   - Revoke tokens if compromised

4. **Use refresh tokens**
   - CLI automatically refreshes expired tokens
   - No need to re-authenticate frequently

## Troubleshooting

### "Failed to connect to Sigil API"

**Cause:** Network connectivity issue or API not running

**Solution:**
```bash
# Check API is running
curl http://localhost:8000/status

# Check Auth0 domain is accessible
curl https://auth.sigilsec.ai/.well-known/openid-configuration
```

### "Device code expired"

**Cause:** User took longer than 15 minutes to complete auth

**Solution:**
```bash
# Simply run login again
sigil login
```

### "Authentication denied"

**Cause:** User clicked "Deny" on authorization screen

**Solution:**
```bash
# Run login again and click "Authorize"
sigil login
```

### "Authentication timed out"

**Cause:** CLI polled for 5 minutes without user completing auth

**Solution:**
```bash
# Complete auth faster or increase timeout in CLI
sigil login
```

## Migration from Custom JWT

### For Existing Users

Users with old custom JWT tokens need to re-authenticate:

```bash
# Old tokens no longer work
$ sigil scan .
[FAIL] Authentication required. Please sign in again.

# Re-authenticate with new flow
$ sigil login
# Follow device flow instructions

# Now works
$ sigil scan . --pro
```

### For CI/CD

**Before (Custom JWT):**
```yaml
- name: Login to Sigil
  run: sigil login --email ${{ secrets.SIGIL_EMAIL }} --password ${{ secrets.SIGIL_PASSWORD }}
```

**After (Device Flow):**
```yaml
- name: Login to Sigil
  run: |
    # Generate token in dashboard and store as secret
    echo "${{ secrets.SIGIL_TOKEN }}" > ~/.sigil/token
    chmod 600 ~/.sigil/token
```

**Recommended (Personal Access Tokens):**

For CI/CD, we recommend using Personal Access Tokens instead of device flow:

1. Generate token in dashboard: **Settings** → **API Tokens** → **Generate Token**
2. Store as repository secret: `SIGIL_TOKEN`
3. Use in workflow:
   ```yaml
   - name: Configure Sigil
     run: |
       mkdir -p ~/.sigil
       echo "${{ secrets.SIGIL_TOKEN }}" > ~/.sigil/token
       chmod 600 ~/.sigil/token
   ```

## References

- [RFC 8628: OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [Auth0 Device Flow Documentation](https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow)
- [Auth0 Device Flow API Reference](https://auth0.com/docs/api/authentication#device-authorization-flow)

## Support

If you encounter issues:

1. Check Auth0 logs: [Dashboard → Monitoring → Logs](https://manage.auth0.com/dashboard/us/dev-xekq8s5o2x8o84p5/logs)
2. Check API logs: `docker compose logs api`
3. Contact support: support@sigilsec.ai
