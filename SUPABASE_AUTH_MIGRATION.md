# Supabase Auth Migration Guide

## Overview
This guide migrates Sigil from custom JWT authentication to Supabase Auth for better security, built-in features, and reduced maintenance.

## Prerequisites
- Supabase project: `pjjelfyuplqjgljvuybr`
- Project URL: `https://pjjelfyuplqjgljvuybr.supabase.co`
- Database password: `IXRZVYbPhlqZeKN4`

## Environment Variables

### Dashboard (.env.local - already created)
```bash
NEXT_PUBLIC_SUPABASE_URL=https://pjjelfyuplqjgljvuybr.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBqamVsZnl1cGxxamdsanZ1eWJyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzE0NDYyMzUsImV4cCI6MjA4NzAyMjIzNX0.BNjx-iRbvRnHZWaNTNe9F_RqBmtNbSntFGA0Wpb7d3o
```

### API (.env)
Add these to `api/.env`:
```bash
SIGIL_SUPABASE_URL=https://pjjelfyuplqjgljvuybr.supabase.co
SIGIL_SUPABASE_SERVICE_KEY=<get from Supabase dashboard - Settings > API > service_role key>
SIGIL_SUPABASE_JWT_SECRET=<get from Supabase dashboard - Settings > API > JWT Settings > JWT Secret>
```

## Step 1: Install Dependencies

### Dashboard
```bash
cd dashboard
npm install @supabase/supabase-js
```

### API (optional - for admin operations)
```bash
cd api
# Add to requirements.txt if needed
echo "supabase>=2.3.0" >> requirements.txt
pip install supabase
```

## Step 2: Update Dashboard Auth

### Create Supabase Client (`dashboard/src/lib/supabase.ts`)
```typescript
import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!

export const supabase = createClient(supabaseUrl, supabaseAnonKey)
```

### Update Auth Context (`dashboard/src/lib/auth.ts`)
Replace the entire file with Supabase Auth implementation:

```typescript
"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { supabase } from "./supabase";
import type { User, Session } from "@supabase/supabase-js";

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, name: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Get initial session
    supabase.auth.getSession().then(({ data: { session } }) => {
      setUser(session?.user ?? null);
      setLoading(false);
    });

    // Listen for auth changes
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user ?? null);
    });

    return () => subscription.unsubscribe();
  }, []);

  const register = useCallback(async (email: string, password: string, name: string) => {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          name, // Store name in user metadata
        },
      },
    });

    if (error) throw error;

    // User will be automatically logged in after signup
    setUser(data.user);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) throw error;
    setUser(data.user);
  }, []);

  const logout = useCallback(async () => {
    const { error } = await supabase.auth.signOut();
    if (error) throw error;
    setUser(null);
  }, []);

  return React.createElement(
    AuthContext.Provider,
    { value: { user, loading, login, register, logout } },
    children
  );
}
```

### Update Dashboard Pages

No changes needed! The `useAuth` hook API remains the same, so your existing pages will work.

## Step 3: Update API to Validate Supabase JWTs

### Update API Config (`api/config.py`)
Add Supabase configuration:

```python
# --- Supabase Auth (new) ---------------------------------------------------
supabase_url: str | None = None
supabase_service_key: str | None = None
supabase_jwt_secret: str | None = None

@property
def supabase_auth_configured(self) -> bool:
    """Return True when Supabase Auth is configured."""
    return bool(self.supabase_jwt_secret)
```

### Create Supabase Auth Dependency (`api/routers/auth.py`)
Add this function to validate Supabase JWTs:

```python
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def get_current_user_supabase(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Validate Supabase JWT and return user info."""
    token = credentials.credentials

    try:
        # Decode and verify Supabase JWT
        payload = jwt.decode(
            token,
            settings.supabase_jwt_secret,
            algorithms=["HS256"],
            audience="authenticated",
        )

        # Extract user ID from Supabase token
        user_id = payload.get("sub")
        email = payload.get("email")

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing user ID",
            )

        return {
            "id": user_id,
            "email": email,
            "metadata": payload.get("user_metadata", {}),
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
        )
```

### Update Protected Endpoints
Replace `get_current_user` with `get_current_user_supabase`:

```python
@router.get("/me")
async def get_me(user: dict = Depends(get_current_user_supabase)) -> UserResponse:
    """Get current user info from Supabase token."""
    return UserResponse(
        id=user["id"],
        email=user["email"],
        name=user["metadata"].get("name", ""),
        created_at=datetime.utcnow(),  # You can fetch from DB if needed
    )
```

### Remove Old Auth Endpoints
You can remove or deprecate:
- `/auth/register` (handled by Supabase)
- `/auth/login` (handled by Supabase)
- Custom JWT generation functions

## Step 4: Migrate Existing Users (Optional)

If you have existing users in your custom `users` table that you want to migrate to Supabase Auth:

### Migration Script (`scripts/migrate_users_to_supabase.py`)
```python
import asyncio
import asyncpg
from supabase import create_client

async def migrate_users():
    # Connect to database
    conn = await asyncpg.connect(
        'postgresql://postgres:IXRZVYbPhlqZeKN4@db.pjjelfyuplqjgljvuybr.supabase.co:5432/postgres',
        ssl='require'
    )

    # Get existing users from custom table
    users = await conn.fetch("SELECT id, email, name FROM public.users")

    # Create Supabase admin client
    supabase = create_client(
        "https://pjjelfyuplqjgljvuybr.supabase.co",
        "<service_role_key>"  # Use service_role key for admin operations
    )

    for user in users:
        try:
            # Create user in Supabase Auth
            # Note: Users will need to reset their password
            result = supabase.auth.admin.create_user({
                "email": user["email"],
                "email_confirm": True,  # Auto-confirm email
                "user_metadata": {
                    "name": user["name"],
                    "migrated_from_custom_auth": True,
                }
            })
            print(f"✓ Migrated {user['email']}")
        except Exception as e:
            print(f"✗ Failed to migrate {user['email']}: {e}")

    await conn.close()

asyncio.run(migrate_users())
```

**Note:** Since you can't migrate password hashes, users will need to:
1. Use "Forgot Password" to reset their password, OR
2. You send them a password reset link via Supabase

## Step 5: Rebuild and Deploy

### Dashboard
```bash
cd dashboard

# Build with Supabase env vars
az acr build \
  --registry sigilacrhoqms2 \
  --image sigil-dashboard:supabase-auth \
  --file Dockerfile \
  --build-arg NEXT_PUBLIC_API_URL=https://api.sigilsec.ai \
  --build-arg NEXT_PUBLIC_SUPABASE_URL=https://pjjelfyuplqjgljvuybr.supabase.co \
  --build-arg NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBqamVsZnl1cGxxamdsanZ1eWJyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzE0NDYyMzUsImV4cCI6MjA4NzAyMjIzNX0.BNjx-iRbvRnHZWaNTNe9F_RqBmtNbSntFGA0Wpb7d3o \
  .

# Deploy
az containerapp update \
  --name sigil-dashboard-v2 \
  --resource-group sigil-rg \
  --image sigilacrhoqms2.azurecr.io/sigil-dashboard:supabase-auth
```

### Update Dashboard Dockerfile
Add build args for Supabase:

```dockerfile
# In dashboard/Dockerfile, add these ARGs:
ARG NEXT_PUBLIC_SUPABASE_URL
ARG NEXT_PUBLIC_SUPABASE_ANON_KEY

ENV NEXT_PUBLIC_SUPABASE_URL=${NEXT_PUBLIC_SUPABASE_URL}
ENV NEXT_PUBLIC_SUPABASE_ANON_KEY=${NEXT_PUBLIC_SUPABASE_ANON_KEY}
```

### API
```bash
cd api

# Update secrets in Azure
az containerapp secret set \
  --name sigil-api-v2 \
  --resource-group sigil-rg \
  --secrets \
    "sigil-supabase-url=https://pjjelfyuplqjgljvuybr.supabase.co" \
    "sigil-supabase-jwt-secret=<JWT_SECRET_FROM_DASHBOARD>"

# Update environment variables
az containerapp update \
  --name sigil-api-v2 \
  --resource-group sigil-rg \
  --set-env-vars \
    "SIGIL_SUPABASE_URL=secretref:sigil-supabase-url" \
    "SIGIL_SUPABASE_JWT_SECRET=secretref:sigil-supabase-jwt-secret"

# Build and deploy
az acr build --registry sigilacrhoqms2 --image sigil-api:supabase-auth --file Dockerfile .
az containerapp update --name sigil-api-v2 --resource-group sigil-rg --image sigilacrhoqms2.azurecr.io/sigil-api:supabase-auth
```

## Step 6: Testing

### Test Registration
```bash
# Should create user in Supabase Auth
curl -X POST https://app.sigilsec.ai/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123","name":"Test User"}'
```

### Test Login
```bash
# Should return Supabase JWT
curl -X POST https://app.sigilsec.ai/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

### Test Protected Endpoint
```bash
# Should validate Supabase JWT
curl https://api.sigilsec.ai/auth/me \
  -H "Authorization: Bearer <supabase_jwt_token>"
```

## Benefits of Supabase Auth

✅ **No more serialization issues** - Supabase handles all UUID/datetime conversions
✅ **Built-in email verification** - Automatic email confirmation flow
✅ **Password reset** - Forgot password functionality out of the box
✅ **Social OAuth** - Add Google, GitHub, etc. with 1-click
✅ **Row Level Security** - Integrate auth with database policies
✅ **Session management** - Automatic token refresh
✅ **Rate limiting** - Built-in protection against brute force
✅ **Audit logs** - Track all auth events in Supabase dashboard

## Rollback Plan

If you need to rollback:

1. **Dashboard**: Deploy previous image
   ```bash
   az containerapp update --name sigil-dashboard-v2 --resource-group sigil-rg --image sigilacrhoqms2.azurecr.io/sigil-dashboard:prod
   ```

2. **API**: Deploy previous image
   ```bash
   az containerapp update --name sigil-api-v2 --resource-group sigil-rg --image sigilacrhoqms2.azurecr.io/sigil-api:a675c5c
   ```

## Troubleshooting

### CORS Issues
Add your dashboard URL to Supabase Auth settings:
1. Go to https://supabase.com/dashboard/project/pjjelfyuplqjgljvuybr/auth/url-configuration
2. Add `https://app.sigilsec.ai` to Site URL and Redirect URLs

### Email Not Sending
1. Configure SMTP in Supabase: Settings > Auth > SMTP Settings
2. Or use Supabase's built-in email service (limited on free tier)

### JWT Validation Failing
1. Verify JWT secret matches: Settings > API > JWT Settings
2. Check token audience is "authenticated"
3. Ensure token hasn't expired (default: 1 hour)

## Next Steps

After migration:
1. **Enable Email Verification** in Supabase Auth settings
2. **Set up Social OAuth** (Google, GitHub) for better UX
3. **Configure RLS** on your `users` table to use `auth.uid()`
4. **Remove old auth code** from `api/routers/auth.py`
5. **Update API dependencies** - remove `python-jose` and `passlib`

## Resources

- [Supabase Auth Docs](https://supabase.com/docs/guides/auth)
- [Supabase JS Client](https://supabase.com/docs/reference/javascript/auth-signup)
- [JWT Validation](https://supabase.com/docs/guides/auth/server-side/validating-jwts)
- [Row Level Security](https://supabase.com/docs/guides/auth/row-level-security)
