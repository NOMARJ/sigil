-- Sigil API — Forge Premium Features Migration
--
-- Creates tables for Forge premium features:
-- - User tool tracking and preferences
-- - Custom tool stacks 
-- - Alert subscriptions
-- - Analytics events
--
-- Run with:
--   sqlcmd -S <server>.database.windows.net -d sigil -U <user> -i api/migrations/008_forge_premium_features.sql

-- =====================================================================
-- Forge User Tools (tracking, starred tools, personal preferences)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_user_tools')
BEGIN
    CREATE TABLE forge_user_tools (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id         UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        tool_id         NVARCHAR(255) NOT NULL,         -- Package name (e.g., "requests")
        ecosystem       NVARCHAR(50) NOT NULL,          -- pip, npm, mcp, etc.
        tracked_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        is_starred      BIT NOT NULL DEFAULT 0,
        custom_tags     NVARCHAR(MAX),                  -- JSON array of user-defined tags
        notes           NVARCHAR(MAX),                  -- User notes about this tool
        
        UNIQUE(user_id, tool_id, ecosystem)            -- Prevent duplicate tracking
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_user_tools_user')
    CREATE INDEX idx_forge_user_tools_user ON forge_user_tools (user_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_user_tools_tool')
    CREATE INDEX idx_forge_user_tools_tool ON forge_user_tools (tool_id, ecosystem);
GO

-- =====================================================================
-- Forge Custom Stacks (user-created tool combinations)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_stacks')
BEGIN
    CREATE TABLE forge_stacks (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id         UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        team_id         UNIQUEIDENTIFIER NULL REFERENCES teams(id) ON DELETE SET NULL,
        name            NVARCHAR(255) NOT NULL,
        description     NVARCHAR(MAX),
        tools           NVARCHAR(MAX) NOT NULL DEFAULT '[]', -- JSON array of tools
        is_public       BIT NOT NULL DEFAULT 0,
        created_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_stacks_user')
    CREATE INDEX idx_forge_stacks_user ON forge_stacks (user_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_stacks_team')
    CREATE INDEX idx_forge_stacks_team ON forge_stacks (team_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_stacks_public')
    CREATE INDEX idx_forge_stacks_public ON forge_stacks (is_public);
GO

-- =====================================================================
-- Forge Alert Subscriptions (notifications for tracked tools)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_alert_subscriptions')
BEGIN
    CREATE TABLE forge_alert_subscriptions (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id         UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        tool_id         NVARCHAR(255),                  -- Specific tool or NULL for all tools
        ecosystem       NVARCHAR(50),                   -- Specific ecosystem or NULL for all
        alert_types     NVARCHAR(MAX) NOT NULL,         -- JSON array: ["security", "updates", "vulnerabilities"]
        channels        NVARCHAR(MAX) NOT NULL DEFAULT '{}', -- JSON object: {"email": true, "slack": false}
        is_active       BIT NOT NULL DEFAULT 1,
        created_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_alert_subscriptions_user')
    CREATE INDEX idx_forge_alert_subscriptions_user ON forge_alert_subscriptions (user_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_alert_subscriptions_tool')
    CREATE INDEX idx_forge_alert_subscriptions_tool ON forge_alert_subscriptions (tool_id, ecosystem);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_alert_subscriptions_active')
    CREATE INDEX idx_forge_alert_subscriptions_active ON forge_alert_subscriptions (is_active);
GO

-- =====================================================================
-- Forge Analytics Events (usage tracking for premium analytics)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_analytics_events')
BEGIN
    CREATE TABLE forge_analytics_events (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id         UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        event_type      NVARCHAR(100) NOT NULL,         -- "tool_tracked", "stack_created", "search_performed"
        event_data      NVARCHAR(MAX) NOT NULL DEFAULT '{}', -- JSON with context-specific data
        timestamp       DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_analytics_user_time')
    CREATE INDEX idx_forge_analytics_user_time ON forge_analytics_events (user_id, timestamp);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_analytics_type_time')
    CREATE INDEX idx_forge_analytics_type_time ON forge_analytics_events (event_type, timestamp);
GO

-- =====================================================================
-- Forge User Settings (preferences for notifications, UI, etc.)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_user_settings')
BEGIN
    CREATE TABLE forge_user_settings (
        user_id                 UNIQUEIDENTIFIER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        alert_frequency         NVARCHAR(50) NOT NULL DEFAULT 'daily',    -- daily, weekly, instant
        alert_types             NVARCHAR(MAX) NOT NULL DEFAULT '["security", "updates"]', -- JSON array
        delivery_channels       NVARCHAR(MAX) NOT NULL DEFAULT '["email"]', -- JSON array
        quiet_hours             NVARCHAR(MAX),                              -- JSON: {"start": "22:00", "end": "08:00"}
        email_notifications     BIT NOT NULL DEFAULT 1,
        slack_notifications     BIT NOT NULL DEFAULT 0,
        weekly_digest           BIT NOT NULL DEFAULT 1,
        created_at             DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at             DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

-- =====================================================================
-- Forge Analytics Summaries (pre-computed metrics for performance)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_analytics_summaries')
BEGIN
    CREATE TABLE forge_analytics_summaries (
        id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id             UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        team_id             UNIQUEIDENTIFIER NULL REFERENCES teams(id) ON DELETE CASCADE,
        summary_type        NVARCHAR(50) NOT NULL,              -- "daily", "weekly", "monthly"
        period_start        DATE NOT NULL,
        period_end          DATE NOT NULL,
        metrics             NVARCHAR(MAX) NOT NULL DEFAULT '{}', -- JSON with computed metrics
        computed_at         DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        
        UNIQUE(user_id, team_id, summary_type, period_start)    -- Prevent duplicates
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_analytics_summaries_user_period')
    CREATE INDEX idx_forge_analytics_summaries_user_period ON forge_analytics_summaries (user_id, period_start, period_end);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_analytics_summaries_team_period')
    CREATE INDEX idx_forge_analytics_summaries_team_period ON forge_analytics_summaries (team_id, period_start, period_end);
GO

PRINT 'Forge premium features tables created successfully';
GO