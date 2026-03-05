-- =====================================================================
-- MSSQL Forge Tables - Complete Setup and Foreign Key Fix
-- =====================================================================
-- 
-- Purpose: Fix foreign key constraints and ensure all forge tables exist
-- with proper relationships to public_scans table
--
-- Issue: Foreign key constraint errors with forge tables referencing
-- incorrect scan_id column instead of public_scans.id
--
-- Solution: 
-- 1. Drop problematic constraints if they exist
-- 2. Create missing tables if needed
-- 3. Add proper foreign key relationships
-- 4. Create indexes for performance
--
-- Usage:
--   sqlcmd -S <server> -d <database> -i scripts/fix_forge_tables_mssql.sql
-- =====================================================================

PRINT 'Starting Forge Tables Fix...';
GO

-- =====================================================================
-- 1. Clean up any broken foreign key constraints
-- =====================================================================

-- Drop the problematic constraint if it exists
IF EXISTS (SELECT * FROM sys.foreign_keys WHERE name = 'FK__forge_tru__scan___5708E33C')
BEGIN
    ALTER TABLE forge_trust_score_history DROP CONSTRAINT FK__forge_tru__scan___5708E33C;
    PRINT 'Dropped problematic foreign key constraint FK__forge_tru__scan___5708E33C';
END
GO

-- =====================================================================
-- 2. Create forge_trust_score_history table (missing from migration)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_trust_score_history')
BEGIN
    CREATE TABLE forge_trust_score_history (
        id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        public_scan_id      UNIQUEIDENTIFIER NOT NULL,  -- References public_scans.id
        ecosystem           NVARCHAR(100) NOT NULL,
        package_name        NVARCHAR(400) NOT NULL,
        package_version     NVARCHAR(255) NOT NULL DEFAULT '',
        trust_score         FLOAT NOT NULL DEFAULT 0.0,
        risk_score          FLOAT NOT NULL DEFAULT 0.0,
        verdict             NVARCHAR(50) NOT NULL DEFAULT 'UNKNOWN',
        calculated_at       DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        calculation_method  NVARCHAR(100) NOT NULL DEFAULT 'standard',
        metadata_json       NVARCHAR(MAX) NOT NULL DEFAULT '{}',
        CONSTRAINT FK_forge_trust_score_history_public_scan 
            FOREIGN KEY (public_scan_id) REFERENCES public_scans(id) ON DELETE CASCADE,
        CONSTRAINT CK_forge_trust_score_history_metadata 
            CHECK (metadata_json IS NULL OR ISJSON(metadata_json) = 1)
    );
    PRINT 'Created table: forge_trust_score_history';
END
ELSE
BEGIN
    PRINT 'Table forge_trust_score_history already exists';
END
GO

-- =====================================================================
-- 3. Create forge_analytics table (for tracking analytics data)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_analytics')
BEGIN
    CREATE TABLE forge_analytics (
        id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        public_scan_id      UNIQUEIDENTIFIER NOT NULL,
        ecosystem           NVARCHAR(100) NOT NULL,
        package_name        NVARCHAR(400) NOT NULL,
        event_type          NVARCHAR(100) NOT NULL,        -- 'download', 'view', 'classification'
        event_data          NVARCHAR(MAX) NOT NULL DEFAULT '{}',
        user_agent          NVARCHAR(MAX),
        ip_address          NVARCHAR(45),                 -- IPv4 or IPv6
        created_at          DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT FK_forge_analytics_public_scan 
            FOREIGN KEY (public_scan_id) REFERENCES public_scans(id) ON DELETE CASCADE,
        CONSTRAINT CK_forge_analytics_event_data 
            CHECK (event_data IS NULL OR ISJSON(event_data) = 1)
    );
    PRINT 'Created table: forge_analytics';
END
ELSE
BEGIN
    PRINT 'Table forge_analytics already exists';
END
GO

-- =====================================================================
-- 4. Create forge_security_reports table
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_security_reports')
BEGIN
    CREATE TABLE forge_security_reports (
        id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        public_scan_id      UNIQUEIDENTIFIER NOT NULL,
        classification_id   UNIQUEIDENTIFIER,              -- Optional reference to forge_classification
        security_level      NVARCHAR(50) NOT NULL DEFAULT 'UNKNOWN',
        vulnerability_count INT NOT NULL DEFAULT 0,
        critical_issues     NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        recommendations     NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        scan_engine_version NVARCHAR(50) NOT NULL DEFAULT 'v1.0',
        generated_at        DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        expires_at          DATETIMEOFFSET,
        metadata_json       NVARCHAR(MAX) NOT NULL DEFAULT '{}',
        CONSTRAINT FK_forge_security_reports_public_scan 
            FOREIGN KEY (public_scan_id) REFERENCES public_scans(id) ON DELETE CASCADE,
        CONSTRAINT FK_forge_security_reports_classification 
            FOREIGN KEY (classification_id) REFERENCES forge_classification(id) ON DELETE SET NULL,
        CONSTRAINT CK_forge_security_reports_critical_issues 
            CHECK (critical_issues IS NULL OR ISJSON(critical_issues) = 1),
        CONSTRAINT CK_forge_security_reports_recommendations 
            CHECK (recommendations IS NULL OR ISJSON(recommendations) = 1),
        CONSTRAINT CK_forge_security_reports_metadata 
            CHECK (metadata_json IS NULL OR ISJSON(metadata_json) = 1)
    );
    PRINT 'Created table: forge_security_reports';
END
ELSE
BEGIN
    PRINT 'Table forge_security_reports already exists';
END
GO

-- =====================================================================
-- 5. Create forge_package_metrics table
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_package_metrics')
BEGIN
    CREATE TABLE forge_package_metrics (
        id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        public_scan_id      UNIQUEIDENTIFIER NOT NULL,
        ecosystem           NVARCHAR(100) NOT NULL,
        package_name        NVARCHAR(400) NOT NULL,
        package_version     NVARCHAR(255) NOT NULL DEFAULT '',
        download_count      BIGINT NOT NULL DEFAULT 0,
        github_stars        INT NOT NULL DEFAULT 0,
        github_forks        INT NOT NULL DEFAULT 0,
        github_issues       INT NOT NULL DEFAULT 0,
        last_commit_date    DATETIMEOFFSET,
        maintainer_count    INT NOT NULL DEFAULT 0,
        dependency_count    INT NOT NULL DEFAULT 0,
        vulnerability_count INT NOT NULL DEFAULT 0,
        collected_at        DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        source_urls         NVARCHAR(MAX) NOT NULL DEFAULT '{}',
        metadata_json       NVARCHAR(MAX) NOT NULL DEFAULT '{}',
        CONSTRAINT FK_forge_package_metrics_public_scan 
            FOREIGN KEY (public_scan_id) REFERENCES public_scans(id) ON DELETE CASCADE,
        CONSTRAINT CK_forge_package_metrics_source_urls 
            CHECK (source_urls IS NULL OR ISJSON(source_urls) = 1),
        CONSTRAINT CK_forge_package_metrics_metadata 
            CHECK (metadata_json IS NULL OR ISJSON(metadata_json) = 1)
    );
    PRINT 'Created table: forge_package_metrics';
END
ELSE
BEGIN
    PRINT 'Table forge_package_metrics already exists';
END
GO

-- =====================================================================
-- 6. Verify and fix existing forge tables constraints
-- =====================================================================

-- Check if forge_classification exists (should exist from migration)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_classification')
BEGIN
    PRINT 'ERROR: forge_classification table missing! Run migration 004_create_forge_classification.sql first';
END
ELSE
BEGIN
    PRINT 'Verified: forge_classification table exists';
END
GO

-- Check if forge_capabilities exists
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_capabilities')
BEGIN
    PRINT 'ERROR: forge_capabilities table missing! Run migration 004_create_forge_classification.sql first';
END
ELSE
BEGIN
    PRINT 'Verified: forge_capabilities table exists';
END
GO

-- Check if forge_matches exists
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_matches')
BEGIN
    PRINT 'ERROR: forge_matches table missing! Run migration 004_create_forge_classification.sql first';
END
ELSE
BEGIN
    PRINT 'Verified: forge_matches table exists';
END
GO

-- Check if forge_categories exists
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_categories')
BEGIN
    PRINT 'ERROR: forge_categories table missing! Run migration 004_create_forge_classification.sql first';
END
ELSE
BEGIN
    PRINT 'Verified: forge_categories table exists';
END
GO

-- =====================================================================
-- 7. Create performance indexes for new tables
-- =====================================================================

-- Indexes for forge_trust_score_history
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_trust_score_history_public_scan')
    CREATE INDEX idx_forge_trust_score_history_public_scan ON forge_trust_score_history (public_scan_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_trust_score_history_package')
    CREATE INDEX idx_forge_trust_score_history_package ON forge_trust_score_history (ecosystem, package_name);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_trust_score_history_calculated_at')
    CREATE INDEX idx_forge_trust_score_history_calculated_at ON forge_trust_score_history (calculated_at DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_trust_score_history_trust_score')
    CREATE INDEX idx_forge_trust_score_history_trust_score ON forge_trust_score_history (trust_score DESC);
GO

-- Indexes for forge_analytics
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_analytics_public_scan')
    CREATE INDEX idx_forge_analytics_public_scan ON forge_analytics (public_scan_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_analytics_package')
    CREATE INDEX idx_forge_analytics_package ON forge_analytics (ecosystem, package_name);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_analytics_event_type')
    CREATE INDEX idx_forge_analytics_event_type ON forge_analytics (event_type);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_analytics_created_at')
    CREATE INDEX idx_forge_analytics_created_at ON forge_analytics (created_at DESC);
GO

-- Indexes for forge_security_reports
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_security_reports_public_scan')
    CREATE INDEX idx_forge_security_reports_public_scan ON forge_security_reports (public_scan_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_security_reports_classification')
    CREATE INDEX idx_forge_security_reports_classification ON forge_security_reports (classification_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_security_reports_security_level')
    CREATE INDEX idx_forge_security_reports_security_level ON forge_security_reports (security_level);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_security_reports_generated_at')
    CREATE INDEX idx_forge_security_reports_generated_at ON forge_security_reports (generated_at DESC);
GO

-- Indexes for forge_package_metrics
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_package_metrics_public_scan')
    CREATE INDEX idx_forge_package_metrics_public_scan ON forge_package_metrics (public_scan_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_package_metrics_package')
    CREATE INDEX idx_forge_package_metrics_package ON forge_package_metrics (ecosystem, package_name);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_package_metrics_download_count')
    CREATE INDEX idx_forge_package_metrics_download_count ON forge_package_metrics (download_count DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_package_metrics_github_stars')
    CREATE INDEX idx_forge_package_metrics_github_stars ON forge_package_metrics (github_stars DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_package_metrics_collected_at')
    CREATE INDEX idx_forge_package_metrics_collected_at ON forge_package_metrics (collected_at DESC);
GO

-- =====================================================================
-- 8. Add optional linkage between forge_classification and public_scans
-- =====================================================================

-- Check if we need to add a public_scan_id column to forge_classification
-- for direct linking to scan data
IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('forge_classification') AND name = 'public_scan_id')
BEGIN
    ALTER TABLE forge_classification 
    ADD public_scan_id UNIQUEIDENTIFIER NULL;
    
    -- Add foreign key constraint
    ALTER TABLE forge_classification
    ADD CONSTRAINT FK_forge_classification_public_scan 
        FOREIGN KEY (public_scan_id) REFERENCES public_scans(id) ON DELETE SET NULL;
    
    -- Add index for performance
    CREATE INDEX idx_forge_classification_public_scan ON forge_classification (public_scan_id);
    
    PRINT 'Added public_scan_id column to forge_classification with foreign key';
END
ELSE
BEGIN
    PRINT 'forge_classification.public_scan_id column already exists';
END
GO

-- =====================================================================
-- 9. Create composite indexes for common query patterns
-- =====================================================================

-- Trust score history by package and time
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_trust_score_history_package_time')
    CREATE INDEX idx_forge_trust_score_history_package_time 
    ON forge_trust_score_history (ecosystem, package_name, calculated_at DESC);
GO

-- Analytics by package and event type
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_analytics_package_event')
    CREATE INDEX idx_forge_analytics_package_event 
    ON forge_analytics (ecosystem, package_name, event_type);
GO

-- Security reports by security level and generation time
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_security_reports_level_time')
    CREATE INDEX idx_forge_security_reports_level_time 
    ON forge_security_reports (security_level, generated_at DESC);
GO

-- Package metrics for popular packages
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_package_metrics_popularity')
    CREATE INDEX idx_forge_package_metrics_popularity 
    ON forge_package_metrics (ecosystem, download_count DESC, github_stars DESC);
GO

-- =====================================================================
-- 10. Verification queries
-- =====================================================================

PRINT 'Running verification checks...';

-- Check table counts
DECLARE @forge_classification_count INT, @forge_capabilities_count INT, 
        @forge_matches_count INT, @forge_categories_count INT,
        @public_scans_count INT;

SELECT @forge_classification_count = COUNT(*) FROM forge_classification;
SELECT @forge_capabilities_count = COUNT(*) FROM forge_capabilities;
SELECT @forge_matches_count = COUNT(*) FROM forge_matches;
SELECT @forge_categories_count = COUNT(*) FROM forge_categories;
SELECT @public_scans_count = COUNT(*) FROM public_scans;

PRINT 'Table counts:';
PRINT '  forge_classification: ' + CAST(@forge_classification_count AS VARCHAR(10));
PRINT '  forge_capabilities: ' + CAST(@forge_capabilities_count AS VARCHAR(10));
PRINT '  forge_matches: ' + CAST(@forge_matches_count AS VARCHAR(10));
PRINT '  forge_categories: ' + CAST(@forge_categories_count AS VARCHAR(10));
PRINT '  public_scans: ' + CAST(@public_scans_count AS VARCHAR(10));

-- Check foreign key constraints
SELECT 
    fk.name AS constraint_name,
    OBJECT_NAME(fk.parent_object_id) AS table_name,
    COL_NAME(fkc.parent_object_id, fkc.parent_column_id) AS column_name,
    OBJECT_NAME(fk.referenced_object_id) AS referenced_table,
    COL_NAME(fkc.referenced_object_id, fkc.referenced_column_id) AS referenced_column
FROM sys.foreign_keys fk
INNER JOIN sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
WHERE OBJECT_NAME(fk.parent_object_id) LIKE 'forge_%'
ORDER BY table_name, constraint_name;

PRINT '';
PRINT 'Forge Tables Fix completed successfully!';
PRINT 'All tables created with proper foreign key relationships to public_scans.id';
PRINT '';
GO