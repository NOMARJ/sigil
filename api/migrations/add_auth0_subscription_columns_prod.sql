-- Migration: Auth0 identity + billing tier columns for production users table
-- Date: 2026-06-13
-- Scope:
--   Auth0 auto-provisioning requires users.auth0_sub.
--   Billing webhooks require users.subscription_tier.
--
-- Idempotent: guarded with IF NOT EXISTS. Safe to re-run.

IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('users') AND name = 'auth0_sub')
    ALTER TABLE users ADD auth0_sub NVARCHAR(255) NULL;
GO

IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('users') AND name = 'subscription_tier')
    ALTER TABLE users ADD subscription_tier NVARCHAR(50) NOT NULL DEFAULT 'free';
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE object_id = OBJECT_ID('users') AND name = 'idx_users_auth0_sub')
    CREATE UNIQUE INDEX idx_users_auth0_sub ON users (auth0_sub) WHERE auth0_sub IS NOT NULL;
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE object_id = OBJECT_ID('users') AND name = 'idx_users_subscription_tier')
    CREATE INDEX idx_users_subscription_tier ON users (subscription_tier);
GO
