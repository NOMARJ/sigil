-- Migration: Create registry statistics cache
-- Purpose: Pre-compute registry statistics to avoid expensive table scans
-- The stats are updated periodically by a background task

CREATE TABLE registry_stats_cache (
    id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),

    -- Aggregated statistics
    total_packages INT NOT NULL DEFAULT 0,
    total_scans INT NOT NULL DEFAULT 0,
    threats_found INT NOT NULL DEFAULT 0,

    -- JSON columns for flexible statistics
    ecosystems_json NVARCHAR(MAX) NOT NULL DEFAULT '{}',
    verdicts_json NVARCHAR(MAX) NOT NULL DEFAULT '{}',

    -- Metadata
    computed_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
    computation_duration_ms INT NOT NULL DEFAULT 0,

    -- Ensure only one row exists
    CONSTRAINT chk_single_row CHECK (id = CAST('00000000-0000-0000-0000-000000000001' AS UNIQUEIDENTIFIER))
);

-- Insert initial stats row (will be updated by background task)
INSERT INTO registry_stats_cache (
    id,
    total_packages,
    total_scans,
    threats_found,
    ecosystems_json,
    verdicts_json,
    computed_at,
    computation_duration_ms
) VALUES (
    CAST('00000000-0000-0000-0000-000000000001' AS UNIQUEIDENTIFIER),
    0,
    0,
    0,
    '{}',
    '{}',
    SYSDATETIMEOFFSET(),
    0
);

-- Create indexes for efficient reads
CREATE INDEX idx_registry_stats_cache_computed_at
ON registry_stats_cache(computed_at);
