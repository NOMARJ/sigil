# Forge Tool Metrics Database Schema

## Overview

This document describes the database schema for tracking tool metrics and calculating trending data for the Sigil Forge platform. The schema consists of two main tables and supporting views/procedures for optimal performance.

## Tables

### forge_tool_metrics

Primary table for storing daily tool metrics collected from various registries (npm, PyPI, GitHub, etc.).

| Column | Type | Description | Constraints |
|--------|------|-------------|-------------|
| `id` | BIGINT IDENTITY | Primary key | NOT NULL, AUTO INCREMENT |
| `tool_id` | NVARCHAR(255) | Unique identifier for the tool | NOT NULL |
| `date` | DATE | Date of metrics collection | NOT NULL |
| `downloads` | BIGINT | Total downloads/installs | DEFAULT 0, >= 0 |
| `stars` | BIGINT | GitHub stars or equivalent | DEFAULT 0, >= 0 |
| `version` | NVARCHAR(50) | Latest version number | NULLABLE |
| `forks` | BIGINT | Repository forks | DEFAULT 0 |
| `issues_open` | BIGINT | Open issues count | DEFAULT 0 |
| `issues_closed` | BIGINT | Closed issues count | DEFAULT 0 |
| `trust_score` | DECIMAL(5,2) | Calculated trust score 0-100 | DEFAULT 0, 0-100 |
| `created_at` | DATETIME2 | Record creation timestamp | DEFAULT GETUTCDATE() |
| `updated_at` | DATETIME2 | Last update timestamp | DEFAULT GETUTCDATE() |

**Unique Constraint:** `UK_forge_tool_metrics_tool_date` on (tool_id, date)

**Indexes:**
- `IX_forge_tool_metrics_tool_id_date` - Primary query optimization
- `IX_forge_tool_metrics_date` - Date range queries
- `IX_forge_tool_metrics_downloads` - Sorting by downloads
- `IX_forge_tool_metrics_stars` - Sorting by stars

### forge_trending_cache

Pre-calculated trending data cache to optimize API response times.

| Column | Type | Description | Constraints |
|--------|------|-------------|-------------|
| `id` | BIGINT IDENTITY | Primary key | NOT NULL, AUTO INCREMENT |
| `tool_id` | NVARCHAR(255) | Tool identifier | NOT NULL |
| `timeframe` | NVARCHAR(10) | Trending timeframe | NOT NULL, IN ('24h', '7d', '30d') |
| `ecosystem` | NVARCHAR(50) | Tool ecosystem filter | DEFAULT 'all' |
| `category` | NVARCHAR(100) | Tool category filter | DEFAULT 'all' |
| `rank_position` | INT | Current ranking position | NOT NULL, > 0 |
| `previous_rank` | INT | Previous period rank | NULLABLE |
| `rank_change` | INT | Change in rank (+/-) | DEFAULT 0 |
| `growth_percentage` | DECIMAL(10,4) | Overall growth percentage | DEFAULT 0 |
| `direction` | NVARCHAR(10) | Trend direction | DEFAULT 'stable', IN ('up', 'down', 'stable', 'new') |
| `composite_score` | DECIMAL(10,4) | Calculated trending score | DEFAULT 0 |
| `downloads_current` | BIGINT | Current period downloads | DEFAULT 0 |
| `downloads_previous` | BIGINT | Previous period downloads | DEFAULT 0 |
| `downloads_growth` | DECIMAL(10,4) | Downloads growth rate | DEFAULT 0 |
| `stars_current` | BIGINT | Current stars count | DEFAULT 0 |
| `stars_previous` | BIGINT | Previous stars count | DEFAULT 0 |
| `stars_growth` | DECIMAL(10,4) | Stars growth rate | DEFAULT 0 |
| `trust_score_current` | DECIMAL(5,2) | Current trust score | DEFAULT 0 |
| `cache_key` | NVARCHAR(255) | Redis cache key reference | NOT NULL, UNIQUE |
| `expires_at` | DATETIME2 | Cache expiration time | NOT NULL |
| `created_at` | DATETIME2 | Record creation timestamp | DEFAULT GETUTCDATE() |
| `updated_at` | DATETIME2 | Last update timestamp | DEFAULT GETUTCDATE() |

**Indexes:**
- `IX_forge_trending_cache_timeframe_ecosystem` - Primary query optimization
- `IX_forge_trending_cache_expires_at` - Cache cleanup
- `IX_forge_trending_cache_composite_score` - Score-based sorting

## Views

### forge_tool_metrics_latest

Optimized view returning the most recent metrics for each tool.

```sql
CREATE VIEW forge_tool_metrics_latest AS
WITH RankedMetrics AS (
    SELECT 
        tool_id, date, downloads, stars, version, forks,
        issues_open, issues_closed, trust_score,
        created_at, updated_at,
        ROW_NUMBER() OVER (PARTITION BY tool_id ORDER BY date DESC) as rn
    FROM forge_tool_metrics
)
SELECT * FROM RankedMetrics WHERE rn = 1;
```

## Stored Procedures

### sp_cleanup_trending_cache

Removes expired cache entries to maintain performance.

```sql
CREATE PROCEDURE sp_cleanup_trending_cache
AS
BEGIN
    DELETE FROM forge_trending_cache WHERE expires_at < GETUTCDATE();
END;
```

## Triggers

### Updated At Triggers

Automatically updates `updated_at` timestamps on record modifications:
- `tr_forge_tool_metrics_updated_at`
- `tr_forge_trending_cache_updated_at`

## Usage Patterns

### Daily Metrics Collection

```sql
-- Insert or update daily metrics
MERGE forge_tool_metrics AS target
USING (VALUES (@tool_id, @date, @downloads, @stars, @version, @trust_score)) 
    AS source (tool_id, date, downloads, stars, version, trust_score)
ON target.tool_id = source.tool_id AND target.date = source.date
WHEN MATCHED THEN 
    UPDATE SET downloads = source.downloads, stars = source.stars, 
               version = source.version, trust_score = source.trust_score
WHEN NOT MATCHED THEN
    INSERT (tool_id, date, downloads, stars, version, trust_score)
    VALUES (source.tool_id, source.date, source.downloads, source.stars, 
            source.version, source.trust_score);
```

### Trending Calculation Query

```sql
-- Get growth metrics for trending calculation
WITH current_metrics AS (
    SELECT tool_id, downloads, stars, trust_score
    FROM forge_tool_metrics 
    WHERE date >= DATEADD(day, -7, GETUTCDATE())
),
previous_metrics AS (
    SELECT tool_id, downloads, stars, trust_score
    FROM forge_tool_metrics 
    WHERE date >= DATEADD(day, -14, GETUTCDATE()) 
      AND date < DATEADD(day, -7, GETUTCDATE())
)
SELECT 
    c.tool_id,
    c.downloads as current_downloads,
    p.downloads as previous_downloads,
    CASE WHEN p.downloads > 0 
         THEN ((c.downloads - p.downloads) * 100.0 / p.downloads)
         ELSE 0 END as growth_percentage
FROM current_metrics c
LEFT JOIN previous_metrics p ON c.tool_id = p.tool_id;
```

## Performance Considerations

1. **Partitioning**: Consider partitioning `forge_tool_metrics` by date for large datasets
2. **Index Maintenance**: Monitor index fragmentation on high-volume tables
3. **Cache TTL**: Set appropriate TTL values based on data freshness requirements
4. **Cleanup Jobs**: Schedule regular cleanup of expired cache entries

## Migration Notes

- Migration file: `009_forge_tool_metrics.sql`
- Dependencies: Requires existing forge tools tables
- Rollback: Drop tables and views in reverse order
- Performance: Initial index creation may take time on large datasets

## Security

- No sensitive data stored in metrics tables
- Access controlled through application-level permissions
- Audit triggers could be added for compliance requirements