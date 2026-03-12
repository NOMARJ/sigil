-- Add session sharing support to interactive_sessions table
-- Migration: add_session_sharing.sql

-- Add share_token column for unique sharing URLs
ALTER TABLE interactive_sessions
ADD COLUMN share_token NVARCHAR(36) NULL;

-- Add expires_at column for session expiry (30 days)
ALTER TABLE interactive_sessions
ADD COLUMN expires_at DATETIME2 NULL;

-- Create index on share_token for fast lookups
CREATE INDEX idx_sessions_share_token 
ON interactive_sessions (share_token)
WHERE share_token IS NOT NULL;

-- Create index on expires_at for cleanup queries
CREATE INDEX idx_sessions_expires_at
ON interactive_sessions (expires_at)
WHERE expires_at IS NOT NULL;

-- Update existing sessions with share tokens and expiry
UPDATE interactive_sessions
SET 
    share_token = CAST(NEWID() AS NVARCHAR(36)),
    expires_at = DATEADD(DAY, 30, started_at)
WHERE share_token IS NULL;

-- Make share_token unique
ALTER TABLE interactive_sessions
ADD CONSTRAINT uq_sessions_share_token UNIQUE (share_token);