# Sigil Forge Tables - Database Administration Guide

## Executive Summary

The Sigil bot workers are experiencing foreign key constraint errors when attempting to insert data into the `forge_trust_score_history` table. The root cause is a mismatch between the expected database schema and the actual table structure, specifically with foreign key references to the `public_scans` table.

## Problem Analysis

### Issue
- **Error**: `FK__forge_tru__scan___5708E33C` foreign key constraint failure
- **Root Cause**: The constraint references `scan_id` but the `public_scans` table uses `id` as its primary key
- **Impact**: Bot workers cannot insert forge classification data, blocking the Sigil Forge functionality

### Missing Tables
The following tables are referenced by the application but missing from the database schema:
- `forge_trust_score_history` - Track trust score changes over time
- `forge_analytics` - Track usage analytics for packages
- `forge_security_reports` - Security analysis reports
- `forge_package_metrics` - Package popularity and maintenance metrics

## Solution Overview

This fix includes:

1. **Create Missing Tables**: Add all missing forge tables with proper structure
2. **Fix Foreign Key References**: Ensure all foreign keys properly reference `public_scans.id`
3. **Add Performance Indexes**: Create indexes for optimal query performance
4. **Backup & Recovery Plan**: Provide rollback procedures if needed

## Implementation Files

### Core Files
- `fix_forge_tables_mssql.sql` - Main SQL script with all fixes
- `fix_forge_tables.ps1` - PowerShell execution script (Windows/Azure)
- `fix_forge_tables.sh` - Bash execution script (Linux/Unix)

### Database Schema Files
- `migrations/004_create_forge_classification.sql` - Original forge tables migration
- `api/schema.sql` - Main database schema including `public_scans` table

## Pre-Execution Checklist

### Prerequisites
- [ ] SQL Server Management Studio or `sqlcmd` access
- [ ] Database admin permissions (CREATE TABLE, ALTER TABLE, CREATE INDEX)
- [ ] `DATABASE_URL` environment variable configured
- [ ] Backup of current database (recommended)

### Environment Variables
```bash
# Required
export DATABASE_URL='Driver={ODBC Driver 18 for SQL Server};Server=yourserver.database.windows.net;Database=sigil;Uid=yourusername;Pwd=yourpassword;'
```

### Verify Current State
```sql
-- Check which forge tables exist
SELECT TABLE_NAME 
FROM INFORMATION_SCHEMA.TABLES 
WHERE TABLE_NAME LIKE 'forge_%'
ORDER BY TABLE_NAME;

-- Check for broken foreign keys
SELECT 
    fk.name AS constraint_name,
    OBJECT_NAME(fk.parent_object_id) AS table_name
FROM sys.foreign_keys fk
WHERE OBJECT_NAME(fk.parent_object_id) LIKE 'forge_%';
```

## Execution Instructions

### Option 1: PowerShell (Recommended for Windows/Azure)
```powershell
# Test first with dry run
.\scripts\fix_forge_tables.ps1 -DryRun

# Execute the fix
.\scripts\fix_forge_tables.ps1 -Verbose
```

### Option 2: Bash (Linux/Unix)
```bash
# Test first with dry run
./scripts/fix_forge_tables.sh --dry-run

# Execute the fix
./scripts/fix_forge_tables.sh --verbose
```

### Option 3: Direct SQL Execution
```sql
-- Execute the SQL script directly
sqlcmd -S yourserver.database.windows.net -d sigil -U username -P password -i scripts/fix_forge_tables_mssql.sql
```

## Database Schema Changes

### New Tables Created

#### `forge_trust_score_history`
Tracks trust score evolution for packages over time.
```sql
CREATE TABLE forge_trust_score_history (
    id                  UNIQUEIDENTIFIER PRIMARY KEY,
    public_scan_id      UNIQUEIDENTIFIER NOT NULL,  -- FK to public_scans.id
    ecosystem           NVARCHAR(100) NOT NULL,
    package_name        NVARCHAR(400) NOT NULL,
    trust_score         FLOAT NOT NULL DEFAULT 0.0,
    calculated_at       DATETIMEOFFSET NOT NULL,
    -- Additional columns...
);
```

#### `forge_analytics`
Tracks package usage analytics and events.
```sql
CREATE TABLE forge_analytics (
    id                  UNIQUEIDENTIFIER PRIMARY KEY,
    public_scan_id      UNIQUEIDENTIFIER NOT NULL,  -- FK to public_scans.id
    event_type          NVARCHAR(100) NOT NULL,
    event_data          NVARCHAR(MAX) NOT NULL,
    created_at          DATETIMEOFFSET NOT NULL,
    -- Additional columns...
);
```

#### `forge_security_reports`
Security analysis and vulnerability reports.
```sql
CREATE TABLE forge_security_reports (
    id                  UNIQUEIDENTIFIER PRIMARY KEY,
    public_scan_id      UNIQUEIDENTIFIER NOT NULL,  -- FK to public_scans.id
    classification_id   UNIQUEIDENTIFIER,           -- FK to forge_classification.id
    security_level      NVARCHAR(50) NOT NULL,
    vulnerability_count INT NOT NULL DEFAULT 0,
    -- Additional columns...
);
```

#### `forge_package_metrics`
Package popularity and maintenance metrics.
```sql
CREATE TABLE forge_package_metrics (
    id                  UNIQUEIDENTIFIER PRIMARY KEY,
    public_scan_id      UNIQUEIDENTIFIER NOT NULL,  -- FK to public_scans.id
    download_count      BIGINT NOT NULL DEFAULT 0,
    github_stars        INT NOT NULL DEFAULT 0,
    maintainer_count    INT NOT NULL DEFAULT 0,
    -- Additional columns...
);
```

### Schema Modifications

#### `forge_classification` Enhancement
Added optional link to public_scans:
```sql
ALTER TABLE forge_classification 
ADD public_scan_id UNIQUEIDENTIFIER NULL;

ALTER TABLE forge_classification
ADD CONSTRAINT FK_forge_classification_public_scan 
    FOREIGN KEY (public_scan_id) REFERENCES public_scans(id) ON DELETE SET NULL;
```

## Performance Optimizations

### New Indexes Created
- **Trust Score History**: Package lookup, time-based queries, score ranking
- **Analytics**: Event type filtering, package analytics, time-based aggregation  
- **Security Reports**: Security level filtering, classification lookup
- **Package Metrics**: Popularity ranking, GitHub stats, collection time

### Composite Indexes
- `forge_trust_score_history_package_time` - For package history queries
- `forge_analytics_package_event` - For package event analytics
- `forge_security_reports_level_time` - For security trend analysis
- `forge_package_metrics_popularity` - For package popularity ranking

## Monitoring & Maintenance

### Health Check Queries

#### Table Status Check
```sql
SELECT 
    t.TABLE_NAME,
    CASE WHEN t.TABLE_NAME IS NOT NULL THEN 'EXISTS' ELSE 'MISSING' END as STATUS,
    ISNULL(p.rows, 0) as ROW_COUNT
FROM INFORMATION_SCHEMA.TABLES t
LEFT JOIN sys.partitions p ON OBJECT_ID(t.TABLE_NAME) = p.object_id AND p.index_id IN (0,1)
WHERE t.TABLE_NAME LIKE 'forge_%'
ORDER BY t.TABLE_NAME;
```

#### Foreign Key Constraint Check
```sql
SELECT 
    fk.name AS constraint_name,
    OBJECT_NAME(fk.parent_object_id) AS table_name,
    COL_NAME(fkc.parent_object_id, fkc.parent_column_id) AS column_name,
    OBJECT_NAME(fk.referenced_object_id) AS referenced_table,
    COL_NAME(fkc.referenced_object_id, fkc.referenced_column_id) AS referenced_column,
    fk.is_disabled
FROM sys.foreign_keys fk
INNER JOIN sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
WHERE OBJECT_NAME(fk.parent_object_id) LIKE 'forge_%'
ORDER BY table_name, constraint_name;
```

#### Performance Monitoring
```sql
-- Check index usage
SELECT 
    OBJECT_NAME(i.object_id) AS table_name,
    i.name AS index_name,
    ius.user_seeks + ius.user_scans + ius.user_lookups AS total_reads,
    ius.user_updates AS total_writes,
    ius.last_user_seek,
    ius.last_user_scan
FROM sys.indexes i
LEFT JOIN sys.dm_db_index_usage_stats ius ON i.object_id = ius.object_id AND i.index_id = ius.index_id
WHERE OBJECT_NAME(i.object_id) LIKE 'forge_%'
ORDER BY table_name, index_name;
```

### Automated Maintenance

#### Weekly Health Check Script
```sql
-- Weekly forge tables health check
DECLARE @report NVARCHAR(MAX) = '';

-- Check row counts
SELECT @report = @report + 'Table: ' + TABLE_NAME + ' - Rows: ' + CAST(ISNULL(p.rows, 0) AS VARCHAR(10)) + CHAR(13)
FROM INFORMATION_SCHEMA.TABLES t
LEFT JOIN sys.partitions p ON OBJECT_ID(t.TABLE_NAME) = p.object_id AND p.index_id IN (0,1)
WHERE t.TABLE_NAME LIKE 'forge_%';

-- Check for constraint violations
IF EXISTS (SELECT 1 FROM sys.foreign_keys WHERE is_disabled = 1 AND OBJECT_NAME(parent_object_id) LIKE 'forge_%')
    SELECT @report = @report + 'WARNING: Disabled foreign key constraints found!' + CHAR(13);

PRINT @report;
```

#### Index Maintenance
```sql
-- Monthly index maintenance for forge tables
DECLARE @sql NVARCHAR(MAX);
DECLARE index_cursor CURSOR FOR
    SELECT 'ALTER INDEX ' + i.name + ' ON ' + OBJECT_NAME(i.object_id) + ' REBUILD;'
    FROM sys.indexes i
    WHERE OBJECT_NAME(i.object_id) LIKE 'forge_%' 
    AND i.name IS NOT NULL
    AND i.type > 0;

OPEN index_cursor;
FETCH NEXT FROM index_cursor INTO @sql;

WHILE @@FETCH_STATUS = 0
BEGIN
    EXEC sp_executesql @sql;
    FETCH NEXT FROM index_cursor INTO @sql;
END;

CLOSE index_cursor;
DEALLOCATE index_cursor;
```

## Backup & Recovery

### Pre-Fix Backup
```sql
-- Backup existing forge tables before applying fix
BACKUP DATABASE [sigil] 
TO DISK = 'C:\Backups\sigil_before_forge_fix_' + REPLACE(CONVERT(VARCHAR, GETDATE(), 120), ':', '') + '.bak'
WITH FORMAT, INIT, COMPRESSION;
```

### Rollback Procedure
If the fix causes issues, use this rollback procedure:

1. **Restore from backup**:
```sql
RESTORE DATABASE [sigil] 
FROM DISK = 'C:\Backups\sigil_before_forge_fix_YYYYMMDDHHMMSS.bak'
WITH REPLACE;
```

2. **Selective table removal** (if backup not available):
```sql
-- Drop new tables created by the fix
DROP TABLE IF EXISTS forge_trust_score_history;
DROP TABLE IF EXISTS forge_analytics;
DROP TABLE IF EXISTS forge_security_reports;
DROP TABLE IF EXISTS forge_package_metrics;

-- Remove added column from existing table
ALTER TABLE forge_classification DROP CONSTRAINT FK_forge_classification_public_scan;
ALTER TABLE forge_classification DROP COLUMN public_scan_id;
```

## Troubleshooting

### Common Issues

#### Issue: "Cannot alter table because foreign key constraint exists"
**Solution**: The fix script handles this by dropping problematic constraints first.

#### Issue: "Invalid object reference"
**Cause**: Missing `public_scans` table
**Solution**: Ensure main schema migration has been run first (`api/schema.sql`).

#### Issue: "Insufficient permissions"
**Cause**: Database user lacks DDL permissions
**Solution**: Grant necessary permissions or use admin account:
```sql
GRANT CREATE TABLE, ALTER ANY SCHEMA TO [your_user];
```

#### Issue: "Timeout during index creation"
**Cause**: Large datasets causing long index creation times
**Solution**: Run index creation during maintenance window or use `ONLINE = ON` option.

### Log Analysis
Monitor these logs for forge-related issues:
- Application logs: Look for "foreign key constraint" errors
- Database error logs: Check for constraint violation patterns
- Performance logs: Monitor query execution times for forge tables

## Testing & Validation

### Post-Fix Validation Script
```sql
-- Comprehensive validation of forge tables fix
DECLARE @errors INT = 0;

-- Test 1: Check all expected tables exist
IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'forge_trust_score_history')
BEGIN
    PRINT 'ERROR: forge_trust_score_history table missing';
    SET @errors = @errors + 1;
END;

-- Test 2: Check foreign key constraints
IF NOT EXISTS (
    SELECT 1 FROM sys.foreign_keys fk
    JOIN sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
    WHERE OBJECT_NAME(fk.parent_object_id) = 'forge_trust_score_history'
    AND OBJECT_NAME(fk.referenced_object_id) = 'public_scans'
)
BEGIN
    PRINT 'ERROR: forge_trust_score_history foreign key to public_scans missing';
    SET @errors = @errors + 1;
END;

-- Test 3: Test insert capability
BEGIN TRY
    INSERT INTO forge_trust_score_history (public_scan_id, ecosystem, package_name, trust_score)
    SELECT TOP 1 id, 'test', 'validation-test', 100.0 
    FROM public_scans;
    
    DELETE FROM forge_trust_score_history WHERE package_name = 'validation-test';
    PRINT 'SUCCESS: Insert test passed';
END TRY
BEGIN CATCH
    PRINT 'ERROR: Insert test failed - ' + ERROR_MESSAGE();
    SET @errors = @errors + 1;
END CATCH;

-- Test 4: Check indexes exist
DECLARE @missing_indexes INT;
SELECT @missing_indexes = COUNT(*)
FROM (VALUES 
    ('forge_trust_score_history', 'idx_forge_trust_score_history_public_scan'),
    ('forge_analytics', 'idx_forge_analytics_public_scan'),
    ('forge_security_reports', 'idx_forge_security_reports_public_scan')
) AS expected(table_name, index_name)
WHERE NOT EXISTS (
    SELECT 1 FROM sys.indexes i
    WHERE OBJECT_NAME(i.object_id) = expected.table_name
    AND i.name = expected.index_name
);

IF @missing_indexes > 0
BEGIN
    PRINT 'ERROR: ' + CAST(@missing_indexes AS VARCHAR(10)) + ' expected indexes missing';
    SET @errors = @errors + 1;
END;

-- Final result
IF @errors = 0
    PRINT 'VALIDATION PASSED: All forge tables fix tests successful';
ELSE
    PRINT 'VALIDATION FAILED: ' + CAST(@errors AS VARCHAR(10)) + ' errors found';
```

## Support & Documentation

### Related Files
- `/api/routers/forge.py` - Application code using these tables
- `/api/services/forge_classifier.py` - Classification logic
- `/migrations/004_create_forge_classification.sql` - Original migration
- `/api/schema.sql` - Main database schema

### Additional Resources
- [Azure SQL Database Documentation](https://docs.microsoft.com/en-us/azure/azure-sql/)
- [SQL Server Foreign Key Constraints](https://docs.microsoft.com/en-us/sql/relational-databases/tables/create-foreign-key-relationships)
- [Performance Tuning Guide](https://docs.microsoft.com/en-us/sql/relational-databases/performance/performance-monitoring-and-tuning-tools)

### Emergency Contacts
- **Database Team**: [Your DBA team contact info]
- **Application Team**: [Development team contact info]
- **Infrastructure Team**: [DevOps team contact info]

---

**Last Updated**: March 5, 2026
**Version**: 1.0
**Author**: Database Administration Team