-- Sigil API — Performance Optimization Migration (T-SQL)
--
-- Comprehensive database performance improvements including:
-- - Missing indexes for search operations
-- - Forge classification tables and indexes
-- - Full-text search capabilities
-- - Composite indexes for complex queries
-- - Connection pooling recommendations
--
-- Run with:
--   sqlcmd -S <server>.database.windows.net -d sigil -U <user> -i migrations/006_performance_optimization.sql

-- =====================================================================
-- Forge Classification Tables
-- =====================================================================

-- Main classification table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_classification')
BEGIN
    CREATE TABLE forge_classification (
        id                      UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        ecosystem               NVARCHAR(100) NOT NULL,
        package_name            NVARCHAR(400) NOT NULL,
        package_version         NVARCHAR(255) NOT NULL DEFAULT '',
        category                NVARCHAR(200) NOT NULL,
        subcategory             NVARCHAR(200) NOT NULL DEFAULT '',
        confidence_score        FLOAT NOT NULL DEFAULT 0.0,
        description_summary     NVARCHAR(MAX) NOT NULL DEFAULT '',
        environment_vars        NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        network_protocols       NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        file_patterns          NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        import_patterns        NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        risk_indicators        NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        metadata_json          NVARCHAR(MAX) NOT NULL DEFAULT '{}',
        classified_at          DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        created_at             DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        
        CONSTRAINT UQ_forge_classification_package UNIQUE(ecosystem, package_name, package_version),
        CONSTRAINT CK_forge_classification_environment CHECK (environment_vars IS NULL OR ISJSON(environment_vars) = 1),
        CONSTRAINT CK_forge_classification_protocols CHECK (network_protocols IS NULL OR ISJSON(network_protocols) = 1),
        CONSTRAINT CK_forge_classification_file_patterns CHECK (file_patterns IS NULL OR ISJSON(file_patterns) = 1),
        CONSTRAINT CK_forge_classification_import_patterns CHECK (import_patterns IS NULL OR ISJSON(import_patterns) = 1),
        CONSTRAINT CK_forge_classification_risk_indicators CHECK (risk_indicators IS NULL OR ISJSON(risk_indicators) = 1),
        CONSTRAINT CK_forge_classification_metadata CHECK (metadata_json IS NULL OR ISJSON(metadata_json) = 1)
    );
END
GO

-- Capabilities table (many-to-many relationship)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_capabilities')
BEGIN
    CREATE TABLE forge_capabilities (
        id                    UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        classification_id     UNIQUEIDENTIFIER NOT NULL REFERENCES forge_classification(id) ON DELETE CASCADE,
        capability           NVARCHAR(200) NOT NULL,
        confidence           FLOAT NOT NULL DEFAULT 1.0,
        evidence             NVARCHAR(MAX) NOT NULL DEFAULT '',
        created_at           DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

-- Matches table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_matches')
BEGIN
    CREATE TABLE forge_matches (
        id                           UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        primary_classification_id    UNIQUEIDENTIFIER NOT NULL REFERENCES forge_classification(id) ON DELETE CASCADE,
        secondary_classification_id  UNIQUEIDENTIFIER NOT NULL REFERENCES forge_classification(id) ON DELETE NO ACTION,
        match_type                  NVARCHAR(100) NOT NULL,
        compatibility_score         FLOAT NOT NULL DEFAULT 0.0,
        shared_elements            NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        match_reason               NVARCHAR(MAX) NOT NULL DEFAULT '',
        trust_score_combined       FLOAT NOT NULL DEFAULT 0.0,
        created_at                 DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        
        CONSTRAINT UQ_forge_matches_pair UNIQUE(primary_classification_id, secondary_classification_id),
        CONSTRAINT CK_forge_matches_shared CHECK (shared_elements IS NULL OR ISJSON(shared_elements) = 1)
    );
END
GO

-- Categories table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_categories')
BEGIN
    CREATE TABLE forge_categories (
        id                UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        category          NVARCHAR(200) NOT NULL UNIQUE,
        display_name      NVARCHAR(255) NOT NULL,
        description       NVARCHAR(MAX) NOT NULL DEFAULT '',
        parent_category   NVARCHAR(200),
        sort_order        INT NOT NULL DEFAULT 0,
        is_active         BIT NOT NULL DEFAULT 1,
        created_at        DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

-- =====================================================================
-- Critical Performance Indexes for Search Operations
-- =====================================================================

-- Forge classification indexes for search performance
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_classification_ecosystem')
    CREATE INDEX idx_forge_classification_ecosystem ON forge_classification (ecosystem);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_classification_category')
    CREATE INDEX idx_forge_classification_category ON forge_classification (category);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_classification_package_name')
    CREATE INDEX idx_forge_classification_package_name ON forge_classification (package_name);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_classification_confidence')
    CREATE INDEX idx_forge_classification_confidence ON forge_classification (confidence_score DESC);
GO

-- Composite index for common search patterns (ecosystem + category + confidence)
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_classification_search_composite')
    CREATE INDEX idx_forge_classification_search_composite ON forge_classification (ecosystem, category, confidence_score DESC);
GO

-- Index for package lookup (ecosystem + package_name)
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_classification_package_lookup')
    CREATE INDEX idx_forge_classification_package_lookup ON forge_classification (ecosystem, package_name);
GO

-- Forge capabilities indexes
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_capabilities_classification')
    CREATE INDEX idx_forge_capabilities_classification ON forge_capabilities (classification_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_capabilities_capability')
    CREATE INDEX idx_forge_capabilities_capability ON forge_capabilities (capability);
GO

-- Forge matches indexes
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_matches_primary')
    CREATE INDEX idx_forge_matches_primary ON forge_matches (primary_classification_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_matches_secondary')
    CREATE INDEX idx_forge_matches_secondary ON forge_matches (secondary_classification_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_matches_compatibility')
    CREATE INDEX idx_forge_matches_compatibility ON forge_matches (compatibility_score DESC);
GO

-- Forge categories indexes
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_categories_active')
    CREATE INDEX idx_forge_categories_active ON forge_categories (is_active, sort_order) WHERE is_active = 1;
GO

-- =====================================================================
-- Public Scans Performance Indexes
-- =====================================================================

-- Composite index for ecosystem + package searches
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_public_scans_ecosystem_package_composite')
    CREATE INDEX idx_public_scans_ecosystem_package_composite ON public_scans (ecosystem, package_name, verdict);
GO

-- Index for risk score filtering
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_public_scans_ecosystem_risk')
    CREATE INDEX idx_public_scans_ecosystem_risk ON public_scans (ecosystem, risk_score DESC);
GO

-- Temporal index for recent scans
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_public_scans_ecosystem_recent')
    CREATE INDEX idx_public_scans_ecosystem_recent ON public_scans (ecosystem, scanned_at DESC);
GO

-- =====================================================================
-- Permissions Performance Indexes
-- =====================================================================

-- MCP ecosystem filtering (for permissions endpoint)
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_public_scans_mcp_created')
    CREATE INDEX idx_public_scans_mcp_created ON public_scans (ecosystem, created_at DESC) WHERE ecosystem = 'mcp';
GO

-- =====================================================================
-- General Query Performance Indexes
-- =====================================================================

-- User scans with pagination
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_scans_user_created_paginated')
    CREATE INDEX idx_scans_user_created_paginated ON scans (user_id, created_at DESC) INCLUDE (target, verdict, risk_score, files_scanned);
GO

-- Team scans with verdict filtering
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_scans_team_verdict_created')
    CREATE INDEX idx_scans_team_verdict_created ON scans (team_id, verdict, created_at DESC);
GO

-- Threat package lookup optimization
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_threats_package_version')
    CREATE INDEX idx_threats_package_version ON threats (package_name, version);
GO

-- Publisher reputation lookup
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_publishers_trust_active')
    CREATE INDEX idx_publishers_trust_active ON publishers (trust_score DESC, last_active DESC);
GO

-- =====================================================================
-- Full-Text Search Capabilities (for large text fields)
-- =====================================================================

-- Enable full-text search on forge descriptions (if not exists)
IF NOT EXISTS (SELECT * FROM sys.fulltext_catalogs WHERE name = 'forge_fulltext_catalog')
    CREATE FULLTEXT CATALOG forge_fulltext_catalog AS DEFAULT;
GO

-- Full-text index on description_summary for search
IF NOT EXISTS (SELECT * FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID('forge_classification'))
BEGIN
    CREATE FULLTEXT INDEX ON forge_classification(description_summary)
    KEY INDEX PK__forge_cl__3213E83F
    ON forge_fulltext_catalog;
END
GO

-- =====================================================================
-- Materialized Views for Expensive Aggregations
-- =====================================================================

-- View for category statistics (updated via scheduled job)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_category_stats')
BEGIN
    CREATE TABLE forge_category_stats (
        category              NVARCHAR(200) PRIMARY KEY,
        ecosystem            NVARCHAR(100) NOT NULL DEFAULT 'all',
        tool_count           INT NOT NULL DEFAULT 0,
        avg_confidence       FLOAT NOT NULL DEFAULT 0.0,
        high_confidence_count INT NOT NULL DEFAULT 0,
        last_updated         DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        
        CONSTRAINT UQ_forge_category_stats UNIQUE(category, ecosystem)
    );
END
GO

-- Index for category stats
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_category_stats_ecosystem')
    CREATE INDEX idx_forge_category_stats_ecosystem ON forge_category_stats (ecosystem, tool_count DESC);
GO

-- =====================================================================
-- Database Health and Performance Monitoring Views
-- =====================================================================

-- View for index usage statistics
IF NOT EXISTS (SELECT * FROM sys.views WHERE name = 'v_index_usage_stats')
EXEC('
CREATE VIEW v_index_usage_stats AS
SELECT 
    OBJECT_NAME(i.object_id) AS table_name,
    i.name AS index_name,
    i.type_desc AS index_type,
    ius.user_seeks,
    ius.user_scans,
    ius.user_lookups,
    ius.user_updates,
    ius.last_user_seek,
    ius.last_user_scan,
    ius.last_user_lookup,
    CASE 
        WHEN ius.user_seeks + ius.user_scans + ius.user_lookups = 0 THEN ''UNUSED''
        ELSE ''ACTIVE''
    END AS usage_status
FROM sys.indexes i
LEFT JOIN sys.dm_db_index_usage_stats ius 
    ON i.object_id = ius.object_id AND i.index_id = ius.index_id
WHERE OBJECT_NAME(i.object_id) IN (
    ''scans'', ''public_scans'', ''forge_classification'', 
    ''forge_capabilities'', ''forge_matches'', ''threats''
)
');
GO

-- View for query performance monitoring
IF NOT EXISTS (SELECT * FROM sys.views WHERE name = 'v_slow_queries')
EXEC('
CREATE VIEW v_slow_queries AS
SELECT TOP 20
    qs.total_elapsed_time / qs.execution_count AS avg_elapsed_time,
    qs.execution_count,
    qs.total_logical_reads / qs.execution_count AS avg_logical_reads,
    SUBSTRING(qt.text, (qs.statement_start_offset/2)+1, 
        ((CASE qs.statement_end_offset
            WHEN -1 THEN DATALENGTH(qt.text)
            ELSE qs.statement_end_offset
        END - qs.statement_start_offset)/2)+1) AS query_text,
    qs.creation_time,
    qs.last_execution_time
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) qt
WHERE qt.text LIKE ''%forge_%'' 
   OR qt.text LIKE ''%public_scans%''
   OR qt.text LIKE ''%scans%''
ORDER BY avg_elapsed_time DESC
');
GO

-- =====================================================================
-- Stored Procedures for Performance Monitoring
-- =====================================================================

-- Procedure to analyze index fragmentation
IF NOT EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_analyze_index_fragmentation')
EXEC('
CREATE PROCEDURE sp_analyze_index_fragmentation
AS
BEGIN
    SELECT 
        OBJECT_NAME(i.object_id) AS table_name,
        i.name AS index_name,
        ips.avg_fragmentation_in_percent,
        ips.page_count,
        CASE 
            WHEN ips.avg_fragmentation_in_percent > 30 THEN ''REBUILD REQUIRED''
            WHEN ips.avg_fragmentation_in_percent > 10 THEN ''REORGANIZE RECOMMENDED''
            ELSE ''OK''
        END AS recommendation
    FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, ''LIMITED'') ips
    JOIN sys.indexes i ON ips.object_id = i.object_id AND ips.index_id = i.index_id
    WHERE OBJECT_NAME(i.object_id) IN (
        ''scans'', ''public_scans'', ''forge_classification'', 
        ''forge_capabilities'', ''forge_matches'', ''threats''
    )
    AND ips.avg_fragmentation_in_percent > 5
    ORDER BY ips.avg_fragmentation_in_percent DESC;
END
');
GO

-- Procedure to update category statistics (for materialized view)
IF NOT EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_update_category_stats')
EXEC('
CREATE PROCEDURE sp_update_category_stats
AS
BEGIN
    -- Update forge category statistics
    MERGE forge_category_stats AS target
    USING (
        SELECT 
            fc.category,
            fc.ecosystem,
            COUNT(*) as tool_count,
            AVG(fc.confidence_score) as avg_confidence,
            SUM(CASE WHEN fc.confidence_score > 0.8 THEN 1 ELSE 0 END) as high_confidence_count
        FROM forge_classification fc
        GROUP BY fc.category, fc.ecosystem
        
        UNION ALL
        
        SELECT 
            fc.category,
            ''all'' as ecosystem,
            COUNT(*) as tool_count,
            AVG(fc.confidence_score) as avg_confidence,
            SUM(CASE WHEN fc.confidence_score > 0.8 THEN 1 ELSE 0 END) as high_confidence_count
        FROM forge_classification fc
        GROUP BY fc.category
    ) AS source (category, ecosystem, tool_count, avg_confidence, high_confidence_count)
    ON (target.category = source.category AND target.ecosystem = source.ecosystem)
    WHEN MATCHED THEN 
        UPDATE SET 
            tool_count = source.tool_count,
            avg_confidence = source.avg_confidence,
            high_confidence_count = source.high_confidence_count,
            last_updated = SYSDATETIMEOFFSET()
    WHEN NOT MATCHED THEN
        INSERT (category, ecosystem, tool_count, avg_confidence, high_confidence_count)
        VALUES (source.category, source.ecosystem, source.tool_count, source.avg_confidence, source.high_confidence_count);
END
');
GO

-- =====================================================================
-- Connection Pool Optimization Settings
-- =====================================================================

-- Database scoped configuration for better performance
-- (These are recommendations - adjust based on workload)

-- Optimize for read-heavy workload
IF NOT EXISTS (SELECT * FROM sys.database_scoped_configurations WHERE name = 'MAXDOP')
    ALTER DATABASE SCOPED CONFIGURATION SET MAXDOP = 4;
GO

-- Enable query store for performance monitoring
IF NOT EXISTS (SELECT * FROM sys.database_query_store_options WHERE actual_state = 2)
    ALTER DATABASE CURRENT SET QUERY_STORE = ON (
        OPERATION_MODE = READ_WRITE,
        DATA_FLUSH_INTERVAL_SECONDS = 900,
        INTERVAL_LENGTH_MINUTES = 60,
        MAX_STORAGE_SIZE_MB = 1000,
        QUERY_CAPTURE_MODE = AUTO,
        SIZE_BASED_CLEANUP_MODE = AUTO
    );
GO

-- =====================================================================
-- Performance Testing Procedures
-- =====================================================================

-- Procedure to benchmark search queries
IF NOT EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_benchmark_search_queries')
EXEC('
CREATE PROCEDURE sp_benchmark_search_queries
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @start_time DATETIME2 = SYSDATETIME();
    DECLARE @end_time DATETIME2;
    DECLARE @duration_ms INT;
    
    PRINT ''=== Search Performance Benchmark ==='';
    
    -- Test 1: Forge classification search by category
    SET @start_time = SYSDATETIME();
    SELECT TOP 20 * FROM forge_classification WHERE category = ''ai-agent'' ORDER BY confidence_score DESC;
    SET @end_time = SYSDATETIME();
    SET @duration_ms = DATEDIFF(MILLISECOND, @start_time, @end_time);
    PRINT ''Forge category search: '' + CAST(@duration_ms AS VARCHAR) + ''ms'';
    
    -- Test 2: Public scans ecosystem filter
    SET @start_time = SYSDATETIME();
    SELECT TOP 20 * FROM public_scans WHERE ecosystem = ''mcp'' ORDER BY scanned_at DESC;
    SET @end_time = SYSDATETIME();
    SET @duration_ms = DATEDIFF(MILLISECOND, @start_time, @end_time);
    PRINT ''Public scans ecosystem filter: '' + CAST(@duration_ms AS VARCHAR) + ''ms'';
    
    -- Test 3: Complex join query (forge classification + capabilities)
    SET @start_time = SYSDATETIME();
    SELECT TOP 20 fc.*, cap.capability 
    FROM forge_classification fc
    JOIN forge_capabilities cap ON fc.id = cap.classification_id
    WHERE fc.ecosystem = ''clawhub''
    ORDER BY fc.confidence_score DESC;
    SET @end_time = SYSDATETIME();
    SET @duration_ms = DATEDIFF(MILLISECOND, @start_time, @end_time);
    PRINT ''Complex join query: '' + CAST(@duration_ms AS VARCHAR) + ''ms'';
    
    -- Test 4: User scan history
    SET @start_time = SYSDATETIME();
    SELECT TOP 20 * FROM scans ORDER BY created_at DESC;
    SET @end_time = SYSDATETIME();
    SET @duration_ms = DATEDIFF(MILLISECOND, @start_time, @end_time);
    PRINT ''User scan history: '' + CAST(@duration_ms AS VARCHAR) + ''ms'';
    
    PRINT ''=== Benchmark Complete ==='';
END
');
GO

-- =====================================================================
-- Summary and Recommendations
-- =====================================================================

PRINT '=== Performance Optimization Migration Complete ===';
PRINT '';
PRINT 'Applied optimizations:';
PRINT '✓ Created forge classification tables with proper indexes';
PRINT '✓ Added composite indexes for search operations';
PRINT '✓ Implemented full-text search capabilities';
PRINT '✓ Created materialized view tables for expensive aggregations';
PRINT '✓ Added performance monitoring views and procedures';
PRINT '✓ Optimized database configuration settings';
PRINT '';
PRINT 'Next steps:';
PRINT '1. Update connection pool settings in application config';
PRINT '2. Run sp_update_category_stats regularly (daily/hourly)';
PRINT '3. Monitor query performance with v_slow_queries view';
PRINT '4. Check index usage with v_index_usage_stats view';
PRINT '5. Run sp_benchmark_search_queries to validate performance';
PRINT '';
PRINT 'Connection Pool Recommendations:';
PRINT '- minsize: 5-10 connections';
PRINT '- maxsize: 20-50 connections (based on expected load)';
PRINT '- connection timeout: 30 seconds';
PRINT '- command timeout: 60 seconds';
PRINT '- Enable connection pooling in application layer';
GO