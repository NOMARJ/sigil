# GitHub OAuth Quick Start Guide

## ✅ Code Already Added!

I've already added GitHub and Google OAuth support to your dashboard code:

**Updated Files:**
- ✅ `dashboard/src/lib/auth.ts` - Added `loginWithGitHub()` and `loginWithGoogle()` methods
- ✅ `dashboard/src/app/auth/callback/page.tsx` - Created OAuth callback handler

## 🚀 Setup Steps (5 minutes)

### Step 1: Create GitHub OAuth App

1. Visit: https://github.com/settings/developers
2. Click "OAuth Apps" → "New OAuth App"
3. Fill in:
   ```
   Application name: Sigil
   Homepage URL: https://sigilsec.ai
   Authorization callback URL: https://pjjelfyuplqjgljvuybr.supabase.co/auth/v1/callback
   ```
4. Click "Register application"
5. **Save the Client ID**
6. Click "Generate a new client secret" and **save the Client Secret**

### Step 2: Configure Supabase

1. Go to: https://supabase.com/dashboard/project/pjjelfyuplqjgljvuybr/auth/providers
2. Find "GitHub" and click to expand
3. Toggle "Enable GitHub" ON
4. Paste:
   - GitHub Client ID
   - GitHub Client Secret
5. Click "Save"

### Step 3: Add GitHub Button to Login Page

Update your login page to add the GitHub button. Here's example code:

```tsx
'use client'

import { useAuth } from '@/lib/auth'

export default function LoginPage() {
  const { login, loginWithGitHub } = useAuth()

  return (
    <div>
      {/* Your existing email/password form */}

      {/* Add divider */}
      <div className="mt-6">
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-300" />
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-2 bg-white text-gray-500">Or continue with</span>
          </div>
        </div>

        {/* GitHub button */}
        <div className="mt-6">
          <button
            onClick={() => loginWithGitHub()}
            className="flex items-center justify-center gap-2 w-full px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
          >
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 0C4.477 0 0 4.484 0 10.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0110 4.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.203 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.942.359.31.678.921.678 1.856 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0020 10.017C20 4.484 15.522 0 10 0z" clipRule="evenodd" />
            </svg>
            Continue with GitHub
          </button>
        </div>
      </div>
    </div>
  )
}
```

### Step 4: Deploy

After adding the button to your login page:

```bash
./scripts/deploy-dashboard-supabase.sh
```

## 🎉 That's It!

Users can now:
1. Click "Continue with GitHub"
2. Authorize your app on GitHub
3. Get redirected back and signed in automatically

## 📊 User Data

GitHub users will have:
- Email from GitHub
- Avatar URL: `user.user_metadata.avatar_url`
- Name: `user.user_metadata.full_name`
- Username: `user.user_metadata.user_name`

## 🔐 Adding Google OAuth (Optional)

Same process:

1. **Create Google OAuth App:**
   - Go to: https://console.cloud.google.com/apis/credentials
   - Create OAuth 2.0 Client ID
   - Authorized redirect URI: `https://pjjelfyuplqjgljvuybr.supabase.co/auth/v1/callback`

2. **Configure Supabase:**
   - Enable Google provider
   - Add Client ID and Secret

3. **Add Button:**
   ```tsx
   <button onClick={() => loginWithGoogle()}>
     Continue with Google
   </button>
   ```

## 📚 More Info

Full setup guide: `docs/internal/GITHUB_OAUTH_SETUP.md`

---

**Status:** Ready to implement
**Time Required:** 5 minutes
