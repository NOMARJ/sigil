---
id: ADR-0002
title: "Password reset is delegated to Auth0 Universal Login; the legacy MSSQL-token reset flow is removed"
status: accepted
date: 2026-05-04
venture: sigil
tags: [auth, auth0, security, password-reset]
outcome: pending
---

## Context

The Auth0 migration moved identity ownership to Auth0. The MSSQL `users` table still exists but its `password_hash` column is permanently `""` for Auth0-provisioned users (`api/routers/auth.py:543`) — Auth0 is the only authority for credentials.

The dashboard, however, still carried a legacy "reset password" flow that pre-dated the Auth0 migration:

1. Dashboard `/reset-password` page (custom React form) → POST `/v1/auth/forgot-password`
2. API generated a token, stored it in MSSQL `password_reset_tokens`, sent an email
3. User clicked email link → Dashboard `/reset-password?token=…` → POST `/v1/auth/reset-password`
4. API updated `users.password_hash` in MSSQL — **and Auth0 was never notified**

End result: the user's "new" password lived only in MSSQL. Login still went through Auth0, where the old password was unchanged. Reset flow was structurally non-functional. A separate bug (ADR adjacent: 2026-05-04 commit `a09aaec`) had also wired email through Resend after a regression where SMTP was the only configured provider — both bugs surfaced together.

## Decision

**Remove the dashboard's custom reset flow entirely. Delegate password reset to Auth0 Universal Login.**

Specifically:

1. `dashboard/src/app/reset-password/page.tsx` — replaced with a redirect to `/api/auth/login` (Auth0 hosted login) plus an explanatory message. Stale email links from inboxes now bounce to Auth0's hosted reset entry point.
2. `dashboard/src/lib/api.ts` — `forgotPassword()` and `resetPassword()` client helpers removed.
3. `api/routers/auth.py` — `/v1/auth/forgot-password` and `/v1/auth/reset-password` endpoints removed; `_send_reset_email` helper removed.
4. `api/models.py` — `ForgotPasswordRequest`, `ForgotPasswordResponse`, `ResetPasswordRequest`, `ResetPasswordResponse` removed.

Deferred (intentional non-changes):

- `api/database.py` retains `create_password_reset_token` / `get_password_reset_token` / `delete_password_reset_token` / `update_user_password` methods — unused by the API now, but kept to avoid coupling this ADR to a database refactor.
- MSSQL `password_reset_tokens` table and `users.password_hash` column stay in `api/schema.sql` — schema cleanup is a separate migration concern.

Future user reset flow (canonical):

1. User visits `app.sigilsec.ai/login` → clicks "Sign in" → redirected to Auth0 (`auth.sigilsec.ai/u/login`)
2. User clicks "Don't remember your password?" on Auth0's hosted login page
3. Auth0 sends the reset email via the tenant's configured email provider
4. User clicks email link → Auth0's hosted reset page → enters new password → Auth0 stores it
5. User logs in normally — Auth0 owns the credential end-to-end

## Consequences

**Positive**

- One source of truth for credentials (Auth0). No more split-brain between MSSQL `password_hash` and Auth0's password store.
- ~110 lines of legacy code removed (4 endpoints, 4 models, 1 helper, 1 dashboard form, 2 client functions).
- Reset flow now works as users expect — typing a new password actually changes the password.
- Email deliverability becomes Auth0's problem, not ours. Auth0 tenant email config (provider + templates) is the single lever; no API redeploy needed to change reset behaviour.

**Negative / trade-offs**

- Reset email content + branding is constrained by Auth0's templating rather than our Resend templates. Acceptable given Auth0 supports custom HTML and from-address per tenant.
- Users who somehow have stale `/reset-password?token=…` links in their inbox will hit a redirect rather than a form. The page does explain what happened.
- Auth0 tenant must have an Email Provider configured (Tenant Settings → Email → Email Provider). The default Auth0 SMTP has poor deliverability and tight quotas — **operator action required** to confirm/configure.

**Operator follow-up (CHARTER II — flagged, not auto-actioned)**

- Verify Auth0 tenant has a custom Email Provider (SendGrid / Mailgun / Resend SMTP / SES). If on default Auth0 SMTP, switch before relying on production reset flow.
- Verify "Change Password" email template in Auth0 dashboard renders with Sigil branding and the correct `from` address.

## Reversibility

Reverting requires restoring the four removed endpoints, the four models, the helper, and the dashboard form — and **does not re-establish a working reset flow** unless paired with Auth0 Management API integration to actually update the Auth0 password (Branch B in the original triage). So a "revert" without that addition would re-create the structural bug. Preferred direction is forward only.

## Evidence

- Commit `a09aaec` — wired reset email through Resend (the proximate fix that surfaced the deeper structural break).
- This commit — Branch A implementation (delegation to Auth0).
- `api/routers/auth.py:543` — Auth0-provisioned users have `password_hash=""`, the empirical proof that the legacy flow was non-functional after the Auth0 migration.
