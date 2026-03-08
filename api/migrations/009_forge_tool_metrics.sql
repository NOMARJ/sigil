-- Migration: 009_forge_tool_metrics.sql
-- Description: Create database schema for forge tool metrics and trending calculations
-- Date: 2026-03-08

-- Create forge_tool_metrics table to track tool usage and engagement over time
CREATE TABLE forge_tool_metrics (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    tool_id NVARCHAR(255) NOT NULL,
    date DATE NOT NULL,
    downloads BIGINT DEFAULT 0,
    stars BIGINT DEFAULT 0,
    version NVARCHAR(50) NULL,
    forks BIGINT DEFAULT 0,
    issues_open BIGINT DEFAULT 0,
    issues_closed BIGINT DEFAULT 0,
    trust_score DECIMAL(5,2) DEFAULT 0,
    created_at DATETIME2 DEFAULT GETUTCDATE(),
    updated_at DATETIME2 DEFAULT GETUTCDATE(),
    
    -- Constraints
    CONSTRAINT UK_forge_tool_metrics_tool_date UNIQUE (tool_id, date),
    CONSTRAINT CK_forge_tool_metrics_downloads CHECK (downloads >= 0),
    CONSTRAINT CK_forge_tool_metrics_stars CHECK (stars >= 0),
    CONSTRAINT CK_forge_tool_metrics_trust_score CHECK (trust_score >= 0 AND trust_score <= 100)
);

-- Create indexes for performance on common queries
CREATE INDEX IX_forge_tool_metrics_tool_id_date ON forge_tool_metrics (tool_id, date DESC);
CREATE INDEX IX_forge_tool_metrics_date ON forge_tool_metrics (date DESC);
CREATE INDEX IX_forge_tool_metrics_downloads ON forge_tool_metrics (downloads DESC);
CREATE INDEX IX_forge_tool_metrics_stars ON forge_tool_metrics (stars DESC);

-- Create forge_trending_cache table for pre-calculated trending data
CREATE TABLE forge_trending_cache (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    tool_id NVARCHAR(255) NOT NULL,
    timeframe NVARCHAR(10) NOT NULL, -- '24h', '7d', '30d'
    ecosystem NVARCHAR(50) DEFAULT 'all',
    category NVARCHAR(100) DEFAULT 'all',
    rank_position INT NOT NULL,
    previous_rank INT NULL,
    rank_change INT DEFAULT 0,
    growth_percentage DECIMAL(10,4) DEFAULT 0,
    direction NVARCHAR(10) DEFAULT 'stable', -- 'up', 'down', 'stable', 'new'
    composite_score DECIMAL(10,4) DEFAULT 0,
    
    -- Metric components
    downloads_current BIGINT DEFAULT 0,
    downloads_previous BIGINT DEFAULT 0,
    downloads_growth DECIMAL(10,4) DEFAULT 0,
    stars_current BIGINT DEFAULT 0,
    stars_previous BIGINT DEFAULT 0,
    stars_growth DECIMAL(10,4) DEFAULT 0,
    trust_score_current DECIMAL(5,2) DEFAULT 0,
    
    cache_key NVARCHAR(255) NOT NULL,
    expires_at DATETIME2 NOT NULL,
    created_at DATETIME2 DEFAULT GETUTCDATE(),
    updated_at DATETIME2 DEFAULT GETUTCDATE(),
    
    -- Constraints
    CONSTRAINT UK_forge_trending_cache_key UNIQUE (cache_key),
    CONSTRAINT CK_forge_trending_cache_timeframe CHECK (timeframe IN ('24h', '7d', '30d')),
    CONSTRAINT CK_forge_trending_cache_direction CHECK (direction IN ('up', 'down', 'stable', 'new')),
    CONSTRAINT CK_forge_trending_cache_rank CHECK (rank_position > 0)
);

-- Create indexes for trending cache
CREATE INDEX IX_forge_trending_cache_timeframe_ecosystem ON forge_trending_cache (timeframe, ecosystem, category, rank_position);
CREATE INDEX IX_forge_trending_cache_expires_at ON forge_trending_cache (expires_at);
CREATE INDEX IX_forge_trending_cache_composite_score ON forge_trending_cache (composite_score DESC);

-- Create a view for latest tool metrics (performance optimization)
GO
CREATE VIEW forge_tool_metrics_latest AS
WITH RankedMetrics AS (
    SELECT 
        tool_id,
        date,
        downloads,
        stars,
        version,
        forks,
        issues_open,
        issues_closed,
        trust_score,
        created_at,
        updated_at,
        ROW_NUMBER() OVER (PARTITION BY tool_id ORDER BY date DESC) as rn
    FROM forge_tool_metrics
)
SELECT 
    tool_id,
    date,
    downloads,
    stars,
    version,
    forks,
    issues_open,
    issues_closed,
    trust_score,
    created_at,
    updated_at
FROM RankedMetrics 
WHERE rn = 1;

-- Create stored procedure to clean up expired trending cache entries
GO
CREATE PROCEDURE sp_cleanup_trending_cache
AS
BEGIN
    SET NOCOUNT ON;
    
    DELETE FROM forge_trending_cache 
    WHERE expires_at < GETUTCDATE();
    
    -- Log cleanup activity
    DECLARE @deleted_rows INT = @@ROWCOUNT;
    IF @deleted_rows > 0
    BEGIN
        PRINT 'Cleaned up ' + CAST(@deleted_rows AS NVARCHAR(10)) + ' expired trending cache entries';
    END
END;

-- Create update trigger for updated_at timestamps
GO
CREATE TRIGGER tr_forge_tool_metrics_updated_at
    ON forge_tool_metrics
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE forge_tool_metrics 
    SET updated_at = GETUTCDATE()
    FROM inserted 
    WHERE forge_tool_metrics.id = inserted.id;
END;

GO
CREATE TRIGGER tr_forge_trending_cache_updated_at
    ON forge_trending_cache
    AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE forge_trending_cache 
    SET updated_at = GETUTCDATE()
    FROM inserted 
    WHERE forge_trending_cache.id = inserted.id;
END;