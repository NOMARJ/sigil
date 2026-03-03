-- Forge Analytics Database Schema
-- Adds comprehensive event tracking and analytics to existing Sigil database
-- Run with: sqlcmd -S <server>.database.windows.net -d sigil -U <user> -i api/migrations/add_forge_analytics.sql

-- =====================================================================
-- Forge Analytics Events (primary event tracking table)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_analytics_events')
BEGIN
    CREATE TABLE forge_analytics_events (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id         UNIQUEIDENTIFIER REFERENCES users(id) ON DELETE CASCADE,
        event_type      NVARCHAR(50) NOT NULL,
        event_data      NVARCHAR(MAX) NOT NULL DEFAULT '{}',
        session_id      NVARCHAR(255),
        ip_address      NVARCHAR(45),
        user_agent      NVARCHAR(1000),
        timestamp       DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT CK_forge_analytics_events_data CHECK (event_data IS NULL OR ISJSON(event_data) = 1)
    );
END
GO

-- Indexes for efficient analytics queries
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_analytics_user_type')
    CREATE INDEX idx_analytics_user_type ON forge_analytics_events (user_id, event_type);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_analytics_timestamp')
    CREATE INDEX idx_analytics_timestamp ON forge_analytics_events (timestamp DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_analytics_event_type')
    CREATE INDEX idx_analytics_event_type ON forge_analytics_events (event_type, timestamp DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_analytics_session')
    CREATE INDEX idx_analytics_session ON forge_analytics_events (session_id, timestamp);
GO

-- =====================================================================
-- User Tool Tracking (for personal analytics)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_user_tools')
BEGIN
    CREATE TABLE forge_user_tools (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id         UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        tool_id         NVARCHAR(255) NOT NULL,
        ecosystem       NVARCHAR(50) NOT NULL,
        tool_name       NVARCHAR(255) NOT NULL,
        category        NVARCHAR(100),
        tracked_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        last_viewed     DATETIMEOFFSET,
        view_count      INT NOT NULL DEFAULT 1,
        is_starred      BIT NOT NULL DEFAULT 0,
        custom_tags     NVARCHAR(MAX) DEFAULT '[]',
        notes           NVARCHAR(MAX),
        UNIQUE(user_id, tool_id, ecosystem),
        CONSTRAINT CK_forge_user_tools_tags CHECK (custom_tags IS NULL OR ISJSON(custom_tags) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_user_tools_user')
    CREATE INDEX idx_user_tools_user ON forge_user_tools (user_id, tracked_at DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_user_tools_ecosystem')
    CREATE INDEX idx_user_tools_ecosystem ON forge_user_tools (ecosystem, user_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_user_tools_starred')
    CREATE INDEX idx_user_tools_starred ON forge_user_tools (user_id, is_starred) WHERE is_starred = 1;
GO

-- =====================================================================
-- User Stacks (for stack management analytics)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_user_stacks')
BEGIN
    CREATE TABLE forge_user_stacks (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id         UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        team_id         UNIQUEIDENTIFIER REFERENCES teams(id) ON DELETE SET NULL,
        name            NVARCHAR(255) NOT NULL,
        description     NVARCHAR(MAX),
        tools           NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        use_case        NVARCHAR(500),
        is_public       BIT NOT NULL DEFAULT 0,
        is_featured     BIT NOT NULL DEFAULT 0,
        view_count      INT NOT NULL DEFAULT 0,
        like_count      INT NOT NULL DEFAULT 0,
        created_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT CK_forge_user_stacks_tools CHECK (tools IS NULL OR ISJSON(tools) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_user_stacks_user')
    CREATE INDEX idx_user_stacks_user ON forge_user_stacks (user_id, created_at DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_user_stacks_team')
    CREATE INDEX idx_user_stacks_team ON forge_user_stacks (team_id, is_public);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_user_stacks_public')
    CREATE INDEX idx_user_stacks_public ON forge_user_stacks (is_public, view_count DESC) WHERE is_public = 1;
GO

-- =====================================================================
-- Trust Score History (for security trend analytics)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_trust_score_history')
BEGIN
    CREATE TABLE forge_trust_score_history (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        tool_id         NVARCHAR(255) NOT NULL,
        ecosystem       NVARCHAR(50) NOT NULL,
        tool_name       NVARCHAR(255) NOT NULL,
        trust_score     FLOAT NOT NULL,
        previous_score  FLOAT,
        scan_id         UNIQUEIDENTIFIER REFERENCES public_scans(id) ON DELETE SET NULL,
        change_reason   NVARCHAR(500),
        recorded_at     DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_trust_history_tool')
    CREATE INDEX idx_trust_history_tool ON forge_trust_score_history (tool_id, ecosystem, recorded_at DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_trust_history_date')
    CREATE INDEX idx_trust_history_date ON forge_trust_score_history (recorded_at DESC);
GO

-- =====================================================================
-- Analytics Aggregation Views (for performance)
-- =====================================================================

-- Daily user activity summary
IF NOT EXISTS (SELECT * FROM sys.views WHERE name = 'forge_daily_user_activity')
BEGIN
    EXEC('CREATE VIEW forge_daily_user_activity AS
    SELECT 
        user_id,
        CAST(timestamp AS DATE) as activity_date,
        event_type,
        COUNT(*) as event_count
    FROM forge_analytics_events 
    WHERE timestamp >= DATEADD(day, -90, GETDATE())
    GROUP BY user_id, CAST(timestamp AS DATE), event_type');
END
GO

-- Tool popularity metrics
IF NOT EXISTS (SELECT * FROM sys.views WHERE name = 'forge_tool_popularity')
BEGIN
    EXEC('CREATE VIEW forge_tool_popularity AS
    SELECT 
        JSON_VALUE(event_data, ''$.tool_id'') as tool_id,
        JSON_VALUE(event_data, ''$.ecosystem'') as ecosystem,
        COUNT(CASE WHEN event_type = ''tool_viewed'' THEN 1 END) as view_count,
        COUNT(CASE WHEN event_type = ''tool_tracked'' THEN 1 END) as track_count,
        COUNT(CASE WHEN event_type = ''tool_detail_viewed'' THEN 1 END) as detail_view_count,
        COUNT(DISTINCT user_id) as unique_users,
        MAX(timestamp) as last_activity
    FROM forge_analytics_events 
    WHERE event_type IN (''tool_viewed'', ''tool_tracked'', ''tool_detail_viewed'')
      AND JSON_VALUE(event_data, ''$.tool_id'') IS NOT NULL
      AND timestamp >= DATEADD(day, -30, GETDATE())
    GROUP BY JSON_VALUE(event_data, ''$.tool_id''), JSON_VALUE(event_data, ''$.ecosystem'')');
END
GO

-- Search pattern analysis
IF NOT EXISTS (SELECT * FROM sys.views WHERE name = 'forge_search_patterns')
BEGIN
    EXEC('CREATE VIEW forge_search_patterns AS
    SELECT 
        JSON_VALUE(event_data, ''$.query'') as search_query,
        JSON_VALUE(event_data, ''$.category'') as category_filter,
        JSON_VALUE(event_data, ''$.ecosystem'') as ecosystem_filter,
        COUNT(*) as search_count,
        COUNT(DISTINCT user_id) as unique_searchers,
        MAX(timestamp) as last_search
    FROM forge_analytics_events 
    WHERE event_type = ''search_performed''
      AND JSON_VALUE(event_data, ''$.query'') IS NOT NULL
      AND timestamp >= DATEADD(day, -30, GETDATE())
    GROUP BY 
        JSON_VALUE(event_data, ''$.query''),
        JSON_VALUE(event_data, ''$.category''),
        JSON_VALUE(event_data, ''$.ecosystem'')');
END
GO

-- =====================================================================
-- Analytics Functions for Common Queries
-- =====================================================================

-- Function to get user tool usage analytics
IF OBJECT_ID('fn_get_user_tool_usage', 'TF') IS NOT NULL
    DROP FUNCTION fn_get_user_tool_usage;
GO

CREATE FUNCTION fn_get_user_tool_usage(@user_id UNIQUEIDENTIFIER, @days_back INT)
RETURNS TABLE
AS
RETURN (
    SELECT 
        JSON_VALUE(event_data, '$.tool_id') as tool_id,
        JSON_VALUE(event_data, '$.ecosystem') as ecosystem,
        JSON_VALUE(event_data, '$.tool_name') as tool_name,
        JSON_VALUE(event_data, '$.category') as category,
        COUNT(*) as interaction_count,
        COUNT(CASE WHEN event_type = 'tool_viewed' THEN 1 END) as view_count,
        COUNT(CASE WHEN event_type = 'tool_tracked' THEN 1 END) as track_count,
        MAX(timestamp) as last_interaction
    FROM forge_analytics_events
    WHERE user_id = @user_id
      AND timestamp >= DATEADD(day, -@days_back, GETDATE())
      AND event_type IN ('tool_viewed', 'tool_tracked', 'tool_detail_viewed')
      AND JSON_VALUE(event_data, '$.tool_id') IS NOT NULL
    GROUP BY 
        JSON_VALUE(event_data, '$.tool_id'),
        JSON_VALUE(event_data, '$.ecosystem'),
        JSON_VALUE(event_data, '$.tool_name'),
        JSON_VALUE(event_data, '$.category')
);
GO

-- Function to get team collaboration metrics
IF OBJECT_ID('fn_get_team_collaboration_metrics', 'TF') IS NOT NULL
    DROP FUNCTION fn_get_team_collaboration_metrics;
GO

CREATE FUNCTION fn_get_team_collaboration_metrics(@team_id UNIQUEIDENTIFIER)
RETURNS TABLE
AS
RETURN (
    SELECT 
        COUNT(DISTINCT e.user_id) as active_members,
        COUNT(DISTINCT JSON_VALUE(e.event_data, '$.tool_id')) as unique_tools_viewed,
        COUNT(CASE WHEN e.event_type = 'stack_shared' THEN 1 END) as stacks_shared,
        COUNT(CASE WHEN e.event_type = 'tool_tracked' THEN 1 END) as tools_tracked,
        AVG(CAST(fut.view_count AS FLOAT)) as avg_tool_interactions
    FROM forge_analytics_events e
    JOIN users u ON e.user_id = u.id
    LEFT JOIN forge_user_tools fut ON fut.user_id = u.id
    WHERE u.team_id = @team_id
      AND e.timestamp >= DATEADD(day, -30, GETDATE())
);
GO

-- Function to get security compliance score
IF OBJECT_ID('fn_get_security_compliance_score', 'IF') IS NOT NULL
    DROP FUNCTION fn_get_security_compliance_score;
GO

CREATE FUNCTION fn_get_security_compliance_score(@team_id UNIQUEIDENTIFIER)
RETURNS FLOAT
AS
BEGIN
    DECLARE @compliance_score FLOAT;
    
    SELECT @compliance_score = (
        SELECT 
            CASE 
                WHEN COUNT(*) = 0 THEN 100.0
                ELSE (COUNT(CASE WHEN ps.risk_score < 20 THEN 1 END) * 100.0) / COUNT(*)
            END
        FROM forge_user_tools fut
        JOIN users u ON fut.user_id = u.id
        LEFT JOIN public_scans ps ON ps.package_name = fut.tool_name 
                                   AND ps.ecosystem = fut.ecosystem
        WHERE u.team_id = @team_id
    );
    
    RETURN ISNULL(@compliance_score, 100.0);
END
GO

-- =====================================================================
-- Analytics Cleanup Procedures (data retention)
-- =====================================================================

-- Procedure to clean old analytics events (retain 1 year)
IF OBJECT_ID('sp_cleanup_analytics_events', 'P') IS NOT NULL
    DROP PROCEDURE sp_cleanup_analytics_events;
GO

CREATE PROCEDURE sp_cleanup_analytics_events
AS
BEGIN
    DECLARE @cutoff_date DATETIMEOFFSET = DATEADD(year, -1, GETDATE());
    
    DELETE FROM forge_analytics_events
    WHERE timestamp < @cutoff_date;
    
    PRINT 'Cleaned up analytics events older than ' + CAST(@cutoff_date AS NVARCHAR(50));
END
GO

-- =====================================================================
-- Initial Data and Triggers
-- =====================================================================

-- Trigger to update trust score history when public_scans are updated
IF OBJECT_ID('tr_public_scans_trust_score_update', 'TR') IS NOT NULL
    DROP TRIGGER tr_public_scans_trust_score_update;
GO

CREATE TRIGGER tr_public_scans_trust_score_update
ON public_scans
AFTER INSERT, UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    
    -- Insert trust score history for new or updated scans
    INSERT INTO forge_trust_score_history (
        tool_id, ecosystem, tool_name, trust_score, 
        previous_score, scan_id, change_reason, recorded_at
    )
    SELECT 
        i.package_name,
        i.ecosystem,
        i.package_name,
        -- Calculate trust score from risk score
        CASE 
            WHEN i.risk_score <= 10 THEN 90 + (10 - i.risk_score)
            WHEN i.risk_score <= 30 THEN 70 + (30 - i.risk_score) * 0.67
            WHEN i.risk_score <= 60 THEN 40 + (60 - i.risk_score) * 0.5
            ELSE GREATEST(0, 40 - (i.risk_score - 60) * 0.67)
        END,
        -- Previous score from last history record
        (SELECT TOP 1 trust_score 
         FROM forge_trust_score_history h 
         WHERE h.tool_id = i.package_name 
           AND h.ecosystem = i.ecosystem 
         ORDER BY recorded_at DESC),
        i.id,
        CASE 
            WHEN EXISTS (SELECT 1 FROM deleted d WHERE d.id = i.id) 
            THEN 'Updated scan results'
            ELSE 'Initial scan'
        END,
        i.scanned_at
    FROM inserted i;
END
GO

-- =====================================================================
-- Grant permissions for analytics access
-- =====================================================================

-- Grant SELECT permissions on analytics views to application role
-- GRANT SELECT ON forge_daily_user_activity TO [sigil_app_role];
-- GRANT SELECT ON forge_tool_popularity TO [sigil_app_role];
-- GRANT SELECT ON forge_search_patterns TO [sigil_app_role];

PRINT 'Forge Analytics schema created successfully.';