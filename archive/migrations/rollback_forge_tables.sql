-- Rollback Script: Drop All Forge Database Tables
-- WARNING: This script will permanently delete all Forge data
-- 
-- Use this script to completely remove Forge functionality from the database
-- Run in order shown to handle foreign key dependencies correctly
--
-- Before running this script:
-- 1. Backup all Forge data if needed for restoration
-- 2. Ensure no applications are actively using Forge tables
-- 3. Test on a development environment first
--
-- Usage:
--   sqlcmd -S <server>.database.windows.net -d sigil -U <user> -i rollback_forge_tables.sql

SET NOCOUNT ON;
PRINT 'Starting Forge database cleanup...';

-- ==========================================================================
-- Drop views first (no data loss)
-- ==========================================================================

IF OBJECT_ID('forge_tool_metrics_latest', 'V') IS NOT NULL
BEGIN
    DROP VIEW forge_tool_metrics_latest;
    PRINT 'Dropped view: forge_tool_metrics_latest';
END

-- ==========================================================================
-- Drop stored procedures (no data loss)
-- ==========================================================================

IF OBJECT_ID('sp_cleanup_trending_cache', 'P') IS NOT NULL
BEGIN
    DROP PROCEDURE sp_cleanup_trending_cache;
    PRINT 'Dropped procedure: sp_cleanup_trending_cache';
END

-- ==========================================================================
-- Drop triggers (no data loss)
-- ==========================================================================

IF OBJECT_ID('tr_forge_tool_metrics_updated_at', 'TR') IS NOT NULL
BEGIN
    DROP TRIGGER tr_forge_tool_metrics_updated_at;
    PRINT 'Dropped trigger: tr_forge_tool_metrics_updated_at';
END

IF OBJECT_ID('tr_forge_trending_cache_updated_at', 'TR') IS NOT NULL
BEGIN
    DROP TRIGGER tr_forge_trending_cache_updated_at;
    PRINT 'Dropped trigger: tr_forge_trending_cache_updated_at';
END

-- ==========================================================================
-- Drop tables in dependency order (DATA WILL BE LOST)
-- ==========================================================================

-- Drop dependent tables first (those with foreign keys)

IF OBJECT_ID('forge_capabilities', 'U') IS NOT NULL
BEGIN
    DROP TABLE forge_capabilities;
    PRINT 'Dropped table: forge_capabilities';
END

IF OBJECT_ID('forge_matches', 'U') IS NOT NULL
BEGIN
    DROP TABLE forge_matches;
    PRINT 'Dropped table: forge_matches';
END

IF OBJECT_ID('forge_analytics_events', 'U') IS NOT NULL
BEGIN
    DROP TABLE forge_analytics_events;
    PRINT 'Dropped table: forge_analytics_events';
END

IF OBJECT_ID('forge_analytics_summaries', 'U') IS NOT NULL
BEGIN
    DROP TABLE forge_analytics_summaries;
    PRINT 'Dropped table: forge_analytics_summaries';
END

IF OBJECT_ID('forge_alert_subscriptions', 'U') IS NOT NULL
BEGIN
    DROP TABLE forge_alert_subscriptions;
    PRINT 'Dropped table: forge_alert_subscriptions';
END

IF OBJECT_ID('forge_user_tools', 'U') IS NOT NULL
BEGIN
    DROP TABLE forge_user_tools;
    PRINT 'Dropped table: forge_user_tools';
END

IF OBJECT_ID('forge_stacks', 'U') IS NOT NULL
BEGIN
    DROP TABLE forge_stacks;
    PRINT 'Dropped table: forge_stacks';
END

IF OBJECT_ID('forge_user_settings', 'U') IS NOT NULL
BEGIN
    DROP TABLE forge_user_settings;
    PRINT 'Dropped table: forge_user_settings';
END

-- Drop cache and metrics tables

IF OBJECT_ID('forge_trending_cache', 'U') IS NOT NULL
BEGIN
    DROP TABLE forge_trending_cache;
    PRINT 'Dropped table: forge_trending_cache';
END

IF OBJECT_ID('forge_tool_metrics', 'U') IS NOT NULL
BEGIN
    DROP TABLE forge_tool_metrics;
    PRINT 'Dropped table: forge_tool_metrics';
END

-- Drop main classification tables last

IF OBJECT_ID('forge_classification', 'U') IS NOT NULL
BEGIN
    DROP TABLE forge_classification;
    PRINT 'Dropped table: forge_classification';
END

IF OBJECT_ID('forge_categories', 'U') IS NOT NULL
BEGIN
    DROP TABLE forge_categories;
    PRINT 'Dropped table: forge_categories';
END

PRINT '';
PRINT 'Forge database cleanup completed successfully.';
PRINT '';
PRINT 'WARNING: All Forge data has been permanently deleted.';
PRINT 'To restore Forge functionality, you must:';
PRINT '1. Re-run the original migration scripts';
PRINT '2. Restore data from backups if needed';
PRINT '3. Update application configuration';