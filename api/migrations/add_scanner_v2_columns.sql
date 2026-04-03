-- Migration: Add Scanner v2 columns for progressive migration
-- Purpose: Track scanner versions, confidence levels, and rescan metadata

-- Add scanner versioning columns to scans table
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scanner_version VARCHAR(20) DEFAULT '1.0.0';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS confidence_level VARCHAR(20);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS original_score INTEGER;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS rescanned_at TIMESTAMP;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS context_weight DECIMAL(3,2) DEFAULT 1.0;

-- Add confidence summary JSON column for detailed tracking
ALTER TABLE scans ADD COLUMN IF NOT EXISTS confidence_summary JSONB;

-- Create index on scanner_version for filtering
CREATE INDEX IF NOT EXISTS idx_scans_scanner_version ON scans(scanner_version);

-- Create index for finding packages needing rescan
CREATE INDEX IF NOT EXISTS idx_scans_rescan_candidates 
ON scans(scanner_version, risk_score) 
WHERE scanner_version = '1.0.0' AND risk_score >= 30;

-- Add scanner metadata to findings table
ALTER TABLE findings ADD COLUMN IF NOT EXISTS confidence VARCHAR(20);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS context_adjusted BOOLEAN DEFAULT FALSE;

-- Create migration tracking table
CREATE TABLE IF NOT EXISTS scanner_migration_progress (
    id SERIAL PRIMARY KEY,
    migration_date DATE DEFAULT CURRENT_DATE,
    total_scans INTEGER,
    v1_scans INTEGER,
    v2_scans INTEGER,
    avg_score_reduction DECIMAL(5,2),
    false_positive_rate DECIMAL(5,2),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create index for migration progress tracking
CREATE INDEX IF NOT EXISTS idx_migration_progress_date ON scanner_migration_progress(migration_date);

-- Add comment documentation
COMMENT ON COLUMN scans.scanner_version IS 'Version of scanner used (1.0.0 for legacy, 2.0.0 for enhanced)';
COMMENT ON COLUMN scans.confidence_level IS 'Overall confidence level of scan results (HIGH/MEDIUM/LOW)';
COMMENT ON COLUMN scans.original_score IS 'Original risk score before rescan (preserved for comparison)';
COMMENT ON COLUMN scans.rescanned_at IS 'Timestamp of when package was rescanned with v2';
COMMENT ON COLUMN scans.context_weight IS 'Weight adjustment based on file context (1.0 = normal, 0.5 = reduced)';
COMMENT ON COLUMN scans.confidence_summary IS 'JSON object with detailed confidence metrics';
COMMENT ON COLUMN findings.confidence IS 'Confidence level for individual finding (HIGH/MEDIUM/LOW)';
COMMENT ON COLUMN findings.context_adjusted IS 'Whether finding severity was adjusted based on context';

-- Verification query to confirm migration
SELECT 
    'Scanner v2 columns added successfully' as status,
    COUNT(*) FILTER (WHERE column_name IN ('scanner_version', 'confidence_level', 'original_score', 'rescanned_at', 'context_weight')) as columns_added
FROM information_schema.columns
WHERE table_name = 'scans'
AND column_name IN ('scanner_version', 'confidence_level', 'original_score', 'rescanned_at', 'context_weight');