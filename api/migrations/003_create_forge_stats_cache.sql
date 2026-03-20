-- Migration: Create Forge statistics cache
-- Purpose: Pre-compute Forge stats to avoid expensive table scans on /forge/stats
-- Updated periodically by a background task (same pattern as registry_stats_cache)

CREATE TABLE forge_stats_cache (
    id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),

    -- Aggregated statistics
    total_tools INT NOT NULL DEFAULT 0,
    total_categories INT NOT NULL DEFAULT 0,
    total_matches INT NOT NULL DEFAULT 0,
    mcp_servers INT NOT NULL DEFAULT 0,
    skills_count INT NOT NULL DEFAULT 0,
    npm_packages INT NOT NULL DEFAULT 0,
    pypi_packages INT NOT NULL DEFAULT 0,

    -- JSON columns for flexible breakdowns
    ecosystems_json NVARCHAR(MAX) NOT NULL DEFAULT '{}',
    categories_json NVARCHAR(MAX) NOT NULL DEFAULT '{}',
    trust_distribution_json NVARCHAR(MAX) NOT NULL DEFAULT '{}',
    top_categories_json NVARCHAR(MAX) NOT NULL DEFAULT '[]',

    -- Metadata
    computed_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
    computation_duration_ms INT NOT NULL DEFAULT 0,

    -- Ensure only one row exists
    CONSTRAINT chk_forge_single_row CHECK (id = CAST('00000000-0000-0000-0000-000000000002' AS UNIQUEIDENTIFIER))
);

-- Insert initial row
INSERT INTO forge_stats_cache (
    id, total_tools, total_categories, total_matches,
    mcp_servers, skills_count, npm_packages, pypi_packages,
    ecosystems_json, categories_json, trust_distribution_json, top_categories_json,
    computed_at, computation_duration_ms
) VALUES (
    CAST('00000000-0000-0000-0000-000000000002' AS UNIQUEIDENTIFIER),
    0, 0, 0, 0, 0, 0, 0,
    '{}', '{}', '{}', '[]',
    SYSDATETIMEOFFSET(), 0
);
