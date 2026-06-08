---
description: Migrate to Auth0-only authentication (remove custom JWT)
---

# Auth0 Unified Authentication Migration - Team Build

**Goal:** Consolidate all authentication through Auth0, remove custom JWT system
**Estimated Time:** 2-3 hours
**Team Size:** 2-3 developers

---

## Team Roles

### 🔧 Backend Developer
- Deprecate custom JWT endpoints in API
- Update `get_current_user_unified()` to Auth0-only
- Remove custom JWT validation logic
- Update environment variables

### 🎨 Frontend Developer  
- Simplify dashboard login page to Auth0 Universal Login
- Remove custom email/password form
- Update auth context to remove localStorage token logic
- Test all auth flows

### ✅ QA/Tester
- Test Auth0 Database connection setup
- Verify all login methods work (email/password, GitHub, Google)
- Test password reset flow
- Verify session persistence
- Check logout functionality

---

## Phase 1: Auth0 Configuration (15 minutes)

**Owner:** Backend Developer

// turbo
1. Enable Auth0 Database Connection
```bash
# Go to Auth0 Dashboard
open "https://manage.auth0.com/dashboard/us/dev-xekq8s5o2x8o84p5/connections/database"
```

**Steps:**
- Click **+ Create DB Connection**
- Name: `Username-Password-Authentication`
- Requires Username: **No** (email only)
- Disable Sign Ups: **No** (allow registration)
- Click **Create**
- Go to **Applications** tab → Enable **Sigil Dashboard**
- Go to **Password Policy** → Set to **Fair** (min 8 chars)
- Click **Save**

**Verification:**
```bash
# Test Auth0 Universal Login shows email/password form
open "https://auth.sigilsec.ai/authorize?client_id=WzNmPGqml7IKSAcSCwz8lhwyv383CKfq&response_type=code&redirect_uri=http://localhost:3000/api/auth/callback&scope=openid%20profile%20email"
```

---

## Phase 2: Dashboard Updates (45 minutes)

**Owner:** Frontend Developer

### 2.1 Simplify Login Page

**File:** `dashboard/src/app/login/page.tsx`

**Remove:**
- Email/password form inputs (lines 127-199)
- Mode switching (login/register/forgot)
- `handleSubmit` function
- `api.register()` and `api.login()` calls

**Replace with:**
```typescript
export default function LoginPage() {
  const { loginWithOAuth } = useAuth();

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950 -m-8">
      <div className="w-full max-w-md px-6">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-brand-600 text-white font-bold text-2xl mb-4 glow-brand">
            S
          </div>
          <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
            Sign in to Sigil
          </h1>
          <p className="text-sm text-gray-500 mt-2">
            Automated security auditing for AI agent code.
          </p>
        </div>

        <div className="card">
          <div className="card-body">
            <button
              onClick={() => loginWithOAuth()}
              className="btn-primary w-full"
            >
              Sign in with Sigil
            </button>
            
            <div className="relative mt-6">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-800" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-gray-900 text-gray-500">Or continue with</span>
              </div>
            </div>

            <div className="mt-6 flex flex-col gap-3">
              <button
                onClick={() => loginWithOAuth("github")}
                className="flex items-center justify-center gap-3 w-full px-4 py-2.5 border border-gray-800 rounded-lg text-sm font-medium text-gray-300 bg-gray-900 hover:bg-gray-800 transition-colors"
              >
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 0C4.477 0 0 4.484 0 10.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0110 4.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.203 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.942.359.31.678.921.678 1.856 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0020 10.017C20 4.484 15.522 0 10 0z" clipRule="evenodd" />
                </svg>
                Continue with GitHub
              </button>

              <button
                onClick={() => loginWithOAuth("google-oauth2")}
                className="flex items-center justify-center gap-3 w-full px-4 py-2.5 border border-gray-800 rounded-lg text-sm font-medium text-gray-300 bg-gray-900 hover:bg-gray-800 transition-colors"
              >
                <svg className="w-5 h-5" viewBox="0 0 24 24">
                  <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 01-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/>
                  <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                  <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                  <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                </svg>
                Continue with Google
              </button>
            </div>
          </div>
        </div>

        <p className="text-center text-xs text-gray-600 mt-6">
          By signing in, you agree to our Terms of Service and Privacy Policy.
        </p>
      </div>
    </div>
  );
}
```

### 2.2 Simplify Auth Context

**File:** `dashboard/src/lib/auth.ts`

**Remove:**
- `loginWithEmail` function (lines 97-115)
- localStorage token logic in `restoreSession` (lines 64-82)
- `sigil_access_token` and `sigil_refresh_token` references

**Update `restoreSession`:**
```typescript
async function restoreSession() {
  // Only try Auth0 session
  try {
    const res = await fetch("/api/auth/token", {
      credentials: 'include',
      cache: 'no-store',
    });
    if (res.ok) {
      const { accessToken } = await res.json();
      if (accessToken) {
        try {
          const appUser = await api.getCurrentUser();
          if (!cancelled) {
            const userWithPlan = { ...appUser, plan: appUser.plan || "pro" as const };
            setUser(userWithPlan);
            setLoading(false);
            return;
          }
        } catch {
          // Token invalid, user not authenticated
        }
      }
    }
  } catch {
    // Auth0 unavailable
  }

  if (!cancelled) {
    setUser(null);
    setLoading(false);
  }
}
```

**Update interface:**
```typescript
interface AuthContextType {
  user: User | null;
  loading: boolean;
  isAuthenticated: boolean;
  loginWithOAuth: (connection?: string) => void;
  logout: () => Promise<void>;
}
```

### 2.3 Remove API Client Methods

**File:** `dashboard/src/lib/api.ts`

**Deprecate (comment out, don't delete yet):**
```typescript
// DEPRECATED: Auth0 handles registration now
// export async function register(payload: RegisterRequest): Promise<AuthTokens> { ... }

// DEPRECATED: Auth0 handles login now  
// export async function login(payload: LoginRequest): Promise<AuthTokens> { ... }

// DEPRECATED: Auth0 handles token refresh
// export async function refreshToken(refresh: string): Promise<AuthTokens> { ... }
```

**Update `getToken`:**
```typescript
async function getToken(): Promise<string | null> {
  if (typeof window === "undefined") return null;

  // Only Auth0 tokens now
  try {
    const res = await fetch("/api/auth/token", {
      credentials: 'include',
      cache: 'no-store',
    });
    if (res.ok) {
      const { accessToken } = await res.json();
      return accessToken || null;
    }
  } catch {
    // Not authenticated
  }

  return null;
}
```

---

## Phase 3: API Updates (30 minutes)

**Owner:** Backend Developer

### 3.1 Update Auth Router

**File:** `api/routers/auth.py`

**Deprecate endpoints (add decorator):**
```python
@router.post(
    "/register",
    deprecated=True,
    summary="DEPRECATED: Use Auth0 Database Connection",
    ...
)
async def register(body: UserCreate) -> TokenResponse:
    raise HTTPException(
        status_code=410,
        detail="This endpoint is deprecated. Please use Auth0 authentication at /api/auth/login"
    )

@router.post(
    "/login",
    deprecated=True,
    summary="DEPRECATED: Use Auth0 Database Connection",
    ...
)
async def login(body: UserLogin, request: Request) -> TokenResponse:
    raise HTTPException(
        status_code=410,
        detail="This endpoint is deprecated. Please use Auth0 authentication at /api/auth/login"
    )
```

**Simplify `get_current_user_unified`:**
```python
async def get_current_user_unified(request: Request) -> UserResponse:
    """Auth0-only authentication (RS256 JWT)."""
    
    # Extract token
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bad request: not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header[7:]

    # Verify Auth0 token
    if not settings.auth0_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service not configured",
        )

    try:
        user_info = await verify_auth0_token(token)
        user = await _auto_provision_auth0_user(user_info)
        logger.debug("Authentication successful via Auth0")
        return UserResponse(
            id=str(user["id"]),
            email=user["email"],
            name=user.get("name", ""),
            created_at=user.get("created_at", datetime.utcnow()),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Auth0 authentication failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
```

### 3.2 Update Config

**File:** `api/config.py`

**Mark as deprecated:**
```python
# DEPRECATED: Custom JWT no longer used
jwt_secret: str = Field(
    default="changeme-generate-a-real-secret",
    description="DEPRECATED: Use Auth0 instead"
)
jwt_expire_minutes: int = Field(
    default=60,
    description="DEPRECATED: Use Auth0 instead"
)
```

---

## Phase 4: Testing (30 minutes)

**Owner:** QA/Tester

### 4.1 Local Testing Checklist

// turbo
```bash
# Start services
cd /Users/reecefrazier/CascadeProjects/sigil
docker compose up -d
```

**Test Cases:**

- [ ] **Auth0 Universal Login loads**
  ```bash
  open http://localhost:3000/login
  # Click "Sign in with Sigil"
  # Should redirect to auth.sigilsec.ai
  # Should show email/password form + GitHub + Google buttons
  ```

- [ ] **Email/Password Registration**
  - Click "Sign up" on Auth0 page
  - Enter email + password
  - Should create account and redirect back to app
  - Should be logged in

- [ ] **Email/Password Login**
  - Enter existing credentials
  - Should log in successfully
  - Should redirect to dashboard

- [ ] **GitHub OAuth**
  - Click "Continue with GitHub"
  - Should authorize on GitHub
  - Should redirect back logged in

- [ ] **Google OAuth**
  - Click "Continue with Google"
  - Should authorize on Google
  - Should redirect back logged in

- [ ] **Password Reset**
  - Click "Forgot password?"
  - Enter email
  - Should receive reset email
  - Should be able to reset password

- [ ] **Session Persistence**
  - Log in
  - Refresh page
  - Should stay logged in

- [ ] **Logout**
  - Click logout
  - Should redirect to login
  - Should clear Auth0 session

- [ ] **API Token Validation**
  ```bash
  # Get token from browser console
  TOKEN=$(node -e "fetch('/api/auth/token').then(r=>r.json()).then(d=>console.log(d.accessToken))")
  
  # Test API
  curl http://localhost:8000/auth/me \
    -H "Authorization: Bearer $TOKEN"
  
  # Should return user profile
  ```

- [ ] **Deprecated Endpoints Return 410**
  ```bash
  curl -X POST http://localhost:8000/v1/auth/register \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"test123","name":"Test"}'
  
  # Should return 410 Gone
  ```

### 4.2 Error Cases

- [ ] Invalid token returns 401
- [ ] Expired token returns 401
- [ ] No token returns 401
- [ ] Logout clears session completely

---

## Phase 5: Deployment (15 minutes)

**Owner:** Backend Developer

### 5.1 Update Environment Variables

**Azure Container Apps:**
```bash
RESOURCE_GROUP="sigil-rg"

# Dashboard - remove JWT secrets
az containerapp update \
  --name sigil-dashboard \
  --resource-group "$RESOURCE_GROUP" \
  --remove-env-vars SIGIL_JWT_SECRET SIGIL_JWT_EXPIRE_MINUTES

# API - remove JWT secrets
az containerapp update \
  --name sigil-api \
  --resource-group "$RESOURCE_GROUP" \
  --remove-env-vars SIGIL_JWT_SECRET SIGIL_JWT_EXPIRE_MINUTES
```

### 5.2 Deploy

// turbo
```bash
# Commit changes
git add dashboard/src/app/login/page.tsx
git add dashboard/src/lib/auth.ts
git add dashboard/src/lib/api.ts
git add api/routers/auth.py
git add api/config.py

git commit -m "feat: Migrate to Auth0-only authentication

- Remove custom JWT email/password auth
- Simplify login page to Auth0 Universal Login
- Enable Auth0 Database Connection for email/password
- Deprecate /v1/auth/register and /v1/auth/login endpoints
- Remove localStorage token management
- Simplify get_current_user_unified to Auth0-only

BREAKING CHANGE: Custom JWT tokens no longer accepted.
Users must re-authenticate via Auth0."

git push origin main
```

---

## Rollback Plan

If issues occur:

1. **Revert commit:**
   ```bash
   git revert HEAD
   git push origin main
   ```

2. **Re-enable custom JWT in API:**
   - Restore `get_current_user_unified` fallback logic
   - Un-deprecate `/v1/auth/register` and `/v1/auth/login`

3. **Restore dashboard form:**
   - Restore email/password inputs
   - Restore `loginWithEmail` function

---

## Success Criteria

✅ All authentication goes through Auth0
✅ Email/password works via Auth0 Database Connection
✅ GitHub OAuth works
✅ Google OAuth works
✅ No localStorage tokens created
✅ No custom JWT validation in API
✅ All tests pass
✅ Zero downtime deployment

---

## Timeline

- **Phase 1:** 15 min (Auth0 config)
- **Phase 2:** 45 min (Dashboard updates)
- **Phase 3:** 30 min (API updates)
- **Phase 4:** 30 min (Testing)
- **Phase 5:** 15 min (Deployment)

**Total:** ~2.5 hours

---

## Post-Migration Cleanup (After 30 Days)

Once Auth0-only auth is stable:

1. Delete deprecated endpoints from `api/routers/auth.py`
2. Remove `verify_custom_jwt()` function
3. Remove `jwt_secret` from config
4. Remove `_verify_token()` helper
5. Update documentation to remove custom JWT references
