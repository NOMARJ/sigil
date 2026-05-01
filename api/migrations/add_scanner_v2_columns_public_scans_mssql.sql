-- Migration: Add Scanner v2 columns to public_scans (SQL Server)
-- Mirror of add_scanner_v2_columns_mssql.sql but targeting public_scans,
-- which is the table the bot writes to via bot/store/store_scan_result().
-- Required by commit 99c46af which expanded the bot row dict to include
-- scanner_version / confidence_level / context_weight.

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('public_scans') AND name = 'scanner_version')
    ALTER TABLE public_scans ADD scanner_version VARCHAR(20) NULL;

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('public_scans') AND name = 'confidence_level')
    ALTER TABLE public_scans ADD confidence_level VARCHAR(20) NULL;

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('public_scans') AND name = 'context_weight')
    ALTER TABLE public_scans ADD context_weight DECIMAL(3,2) NULL;

-- Index on scanner_version supports api/services/scanner_metrics.py grouping
-- queries (GROUP BY scanner_version, confidence_level, verdict).
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('public_scans') AND name = 'idx_public_scans_scanner_version')
    CREATE INDEX idx_public_scans_scanner_version ON public_scans(scanner_version);

-- Verification: confirm all three columns exist
SELECT
    'public_scans Scanner v2 columns' AS status,
    COUNT(*) AS columns_added
FROM sys.columns
WHERE object_id = OBJECT_ID('public_scans')
AND name IN ('scanner_version', 'confidence_level', 'context_weight');
