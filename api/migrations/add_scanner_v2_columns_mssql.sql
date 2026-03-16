-- Migration: Add Scanner v2 columns for progressive migration (SQL Server version)
-- Purpose: Track scanner versions, confidence levels, and rescan metadata

-- Add scanner versioning columns to scans table
IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('scans') AND name = 'scanner_version')
    ALTER TABLE scans ADD scanner_version VARCHAR(20) DEFAULT '1.0.0';

IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('scans') AND name = 'confidence_level')
    ALTER TABLE scans ADD confidence_level VARCHAR(20);

IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('scans') AND name = 'original_score')
    ALTER TABLE scans ADD original_score INT;

IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('scans') AND name = 'rescanned_at')
    ALTER TABLE scans ADD rescanned_at DATETIME;

IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('scans') AND name = 'context_weight')
    ALTER TABLE scans ADD context_weight DECIMAL(3,2) DEFAULT 1.0;

-- Add confidence summary JSON column for detailed tracking
IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('scans') AND name = 'confidence_summary')
    ALTER TABLE scans ADD confidence_summary NVARCHAR(MAX);

-- Create index on scanner_version for filtering
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE object_id = OBJECT_ID('scans') AND name = 'idx_scans_scanner_version')
    CREATE INDEX idx_scans_scanner_version ON scans(scanner_version);

-- Create index for finding packages needing rescan (without filtered index for compatibility)
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE object_id = OBJECT_ID('scans') AND name = 'idx_scans_rescan_candidates')
    CREATE INDEX idx_scans_rescan_candidates 
    ON scans(scanner_version, risk_score);

-- Add scanner metadata to findings table
IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('findings') AND name = 'confidence')
    ALTER TABLE findings ADD confidence VARCHAR(20);

IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('findings') AND name = 'context_adjusted')
    ALTER TABLE findings ADD context_adjusted BIT DEFAULT 0;

-- Create migration tracking table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'scanner_migration_progress')
CREATE TABLE scanner_migration_progress (
    id INT IDENTITY(1,1) PRIMARY KEY,
    migration_date DATE DEFAULT GETDATE(),
    total_scans INT,
    v1_scans INT,
    v2_scans INT,
    avg_score_reduction DECIMAL(5,2),
    false_positive_rate DECIMAL(5,2),
    created_at DATETIME DEFAULT GETDATE()
);

-- Create index for migration progress tracking
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE object_id = OBJECT_ID('scanner_migration_progress') AND name = 'idx_migration_progress_date')
    CREATE INDEX idx_migration_progress_date ON scanner_migration_progress(migration_date);

-- Verification query to confirm migration
SELECT 
    'Scanner v2 columns added successfully' as status,
    COUNT(*) as columns_added
FROM sys.columns
WHERE object_id = OBJECT_ID('scans')
AND name IN ('scanner_version', 'confidence_level', 'original_score', 'rescanned_at', 'context_weight');