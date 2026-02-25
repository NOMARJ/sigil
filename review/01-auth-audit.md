# Phase 1: Authentication Audit

**Severity: P0 — Fix First**

---

## Auth Architecture Map

```
┌─────────────────────────────────────────────────────────────────┐
│                     AUTHENTICATION FLOWS                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  CLI Flow (WORKING):                                            │
│  sigil login --email --password                                 │
│    → POST /auth/login                                           │
│    → API validates password (bcrypt/PBKDF2)                     │
│    → Returns JWT (HS256, 60min expiry)                          │
│    → Token stored in ~/.sigil/token (mode 0600)                 │
│    → Subsequent requests: Authorization: Bearer <jwt>           │
│                                                                  │
│  Dashboard OAuth Flow (BROKEN):                                  │
│  Login button → supabase.auth.signInWithOAuth({provider:'github'})│
│    → Supabase client is NULL (no env vars configured)           │
│    → Crash on supabase.auth.signInWithOAuth()                   │
│    → Even if configured: callback URL mismatch                  │
│    → Even if callback worked: API can't verify Supabase JWTs    │
│      (supabase_jwt_secret is None)                              │
│                                                                  │
│  Dashboard Email/Password Flow (PARTIALLY WORKING):              │
│  Login form → POST /auth/login                                  │
│    → Returns JWT + stores in localStorage                       │
│    → API validates custom JWT correctly                          │
│    → BUT: dashboard tries Supabase token first, fails silently  │
│                                                                  │
│  API Token Validation (get_current_user_unified):               │
│  1. Try Supabase JWT → FAILS (no jwt_secret configured)         │
│  2. Fall back to custom JWT → WORKS                             │
│  Result: Only custom JWT auth works                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Bugs Found (Severity-Ranked)

### CRITICAL

**1. Hardcoded Default JWT Secret**
- **File:** `api/config.py:49`
- **Code:** `jwt_secret: str = "changeme-generate-a-real-secret"`
- **Impact:** If `SIGIL_JWT_SECRET` env var not set, anyone can forge valid JWTs
- **Fix:** Fail fast on startup if not set (see fixes/)

**2. Supabase OAuth Flow Completely Broken**
- **Files:** `dashboard/.env.production`, `dashboard/src/lib/supabase.ts`
- **Issue:** No `NEXT_PUBLIC_SUPABASE_URL` or `NEXT_PUBLIC_SUPABASE_ANON_KEY` configured
- **Result:** `supabase = null`, all OAuth calls crash
- **Fix:** Add env vars to `.env.production` and `.env.example`

**3. OAuth Callback URL Mismatch**
- **Dashboard:** `${window.location.origin}/auth/callback` → `app.sigilsec.ai/auth/callback`
- **GitHub OAuth App:** Configured for `pjjelfyuplqjgljvuybr.supabase.co/auth/v1/callback`
- **Fix:** These are actually correct for Supabase flow — Supabase handles the GitHub redirect internally, then redirects to app. But the Supabase URL/key must be configured.

**4. Supabase JWT Verification Impossible**
- **File:** `api/config.py:57`
- **Code:** `supabase_jwt_secret: str | None = None  # Deprecated: use JWKS for verification`
- **Impact:** API cannot verify Supabase-issued tokens; falls back to custom JWT
- **Fix:** Either set `SIGIL_SUPABASE_JWT_SECRET` or implement JWKS

### HIGH

**5. No Token Revocation**
- **File:** `api/routers/auth.py` — logout endpoint
- **Issue:** Logout doesn't invalidate tokens; logged-out JWTs remain valid for up to 60 minutes
- **Fix:** Implement Redis-backed token blocklist

**6. No Rate Limiting on Login**
- **File:** `api/routers/auth.py`
- **Issue:** No rate limiting on POST /auth/login — brute force possible
- **Fix:** Add rate limiter middleware (e.g., `slowapi`)

**7. Refresh Token Is Just Another Access Token**
- **File:** `api/routers/auth.py:707-747`
- **Issue:** POST /auth/refresh takes a "refresh_token" but it's the same JWT with same 60min expiry
- **Fix:** Issue refresh tokens with 7-day expiry, separate from access tokens

**8. CORS Too Permissive**
- **File:** `api/main.py:79-85`
- **Code:** `allow_methods=["*"]`, `allow_headers=["*"]`
- **Fix:** Whitelist: `["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]` and specific headers

### MEDIUM

**9. Password Reset Email Not Implemented**
- Token generation works, but `send_email_notification()` service doesn't actually send
- **Impact:** Users cannot reset forgotten passwords
- **Fix:** Implement SMTP sending or use Supabase Auth's built-in password reset

**10. Reset Link Uses First CORS Origin**
- **File:** `api/routers/auth.py:813`
- **Code:** `reset_link = f"{settings.cors_origins[0]}/reset-password?token={raw_token}"`
- **Impact:** If CORS origins misconfigured, link goes to wrong domain
- **Fix:** Add dedicated `SIGIL_FRONTEND_URL` config

**11. No JWT Claims Validation**
- Missing: `iat` (issued-at), `jti` (JWT ID), `nbf` (not-before)
- Missing: Token scope/permissions
- **Impact:** Tokens cannot be individually tracked or revoked

**12. API URL Inconsistency**
- CLI default: `https://api.sigil.nomark.dev`
- Dashboard config: `https://api.sigilsec.ai`
- **Fix:** Standardize on `api.sigilsec.ai`

---

## Required Environment Variables for Auth

```bash
# REQUIRED — API will refuse to start without these
SIGIL_JWT_SECRET=<64-char-hex-secret>  # Generate: python3 -c "import secrets; print(secrets.token_hex(32))"

# REQUIRED for Dashboard OAuth
NEXT_PUBLIC_SUPABASE_URL=https://<project>.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=<supabase-anon-key>

# REQUIRED for API to verify Supabase tokens
SIGIL_SUPABASE_URL=https://<project>.supabase.co
SIGIL_SUPABASE_KEY=<supabase-service-role-key>
SIGIL_SUPABASE_JWT_SECRET=<supabase-jwt-secret>  # From Supabase → Settings → API → JWT Secret

# REQUIRED for production CORS
SIGIL_CORS_ORIGINS=["https://app.sigilsec.ai","https://sigilsec.ai"]
```

---

## Corrected Auth Happy Path

```
User clicks "Sign in with GitHub" on dashboard
  → Supabase OAuth redirect to GitHub
  → User authorizes on GitHub
  → GitHub redirects to Supabase callback URL
  → Supabase creates session, redirects to app.sigilsec.ai/auth/callback
  → Dashboard auth callback page detects session
  → supabase.auth.getSession() returns valid session with access_token
  → Dashboard API calls include Authorization: Bearer <supabase-jwt>
  → API get_current_user_unified() verifies Supabase JWT
  → User authenticated, dashboard loads data

User runs `sigil login` in CLI
  → POST /auth/login with email/password
  → API verifies password hash
  → API returns custom JWT
  → Token saved to ~/.sigil/token
  → Subsequent CLI requests include Bearer token
  → API get_current_user_unified() verifies custom JWT
```
