-- Archive Forge Database Script
-- This script safely archives Forge tables by renaming them instead of dropping
-- Data is preserved for potential restoration while removing from active use
--
-- Usage:
--   sqlcmd -S <server>.database.windows.net -d sigil -U <user> -i archive_forge_database.sql

SET NOCOUNT ON;
PRINT 'Starting Forge database archival process...';

-- Create archive timestamp for unique table names
DECLARE @archive_suffix NVARCHAR(20) = '_archived_' + FORMAT(GETUTCDATE(), 'yyyyMMdd_HHmmss');
PRINT 'Archive suffix: ' + @archive_suffix;

-- ==========================================================================
-- Archive Strategy: Rename tables to preserve data
-- ==========================================================================

-- Archive forge_capabilities (dependent table)
IF OBJECT_ID('forge_capabilities', 'U') IS NOT NULL AND OBJECT_ID('forge_capabilities' + @archive_suffix, 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_capabilities', 'forge_capabilities_archived_20260313_120000';
    PRINT 'Archived table: forge_capabilities -> forge_capabilities_archived_20260313_120000';
END

-- Archive forge_matches (dependent table)
IF OBJECT_ID('forge_matches', 'U') IS NOT NULL AND OBJECT_ID('forge_matches' + @archive_suffix, 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_matches', 'forge_matches_archived_20260313_120000';
    PRINT 'Archived table: forge_matches -> forge_matches_archived_20260313_120000';
END

-- Archive forge_analytics_events
IF OBJECT_ID('forge_analytics_events', 'U') IS NOT NULL AND OBJECT_ID('forge_analytics_events' + @archive_suffix, 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_analytics_events', 'forge_analytics_events_archived_20260313_120000';
    PRINT 'Archived table: forge_analytics_events -> forge_analytics_events_archived_20260313_120000';
END

-- Archive forge_analytics_summaries
IF OBJECT_ID('forge_analytics_summaries', 'U') IS NOT NULL AND OBJECT_ID('forge_analytics_summaries' + @archive_suffix, 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_analytics_summaries', 'forge_analytics_summaries_archived_20260313_120000';
    PRINT 'Archived table: forge_analytics_summaries -> forge_analytics_summaries_archived_20260313_120000';
END

-- Archive forge_alert_subscriptions
IF OBJECT_ID('forge_alert_subscriptions', 'U') IS NOT NULL AND OBJECT_ID('forge_alert_subscriptions' + @archive_suffix, 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_alert_subscriptions', 'forge_alert_subscriptions_archived_20260313_120000';
    PRINT 'Archived table: forge_alert_subscriptions -> forge_alert_subscriptions_archived_20260313_120000';
END

-- Archive forge_user_tools
IF OBJECT_ID('forge_user_tools', 'U') IS NOT NULL AND OBJECT_ID('forge_user_tools' + @archive_suffix, 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_user_tools', 'forge_user_tools_archived_20260313_120000';
    PRINT 'Archived table: forge_user_tools -> forge_user_tools_archived_20260313_120000';
END

-- Archive forge_stacks
IF OBJECT_ID('forge_stacks', 'U') IS NOT NULL AND OBJECT_ID('forge_stacks' + @archive_suffix, 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_stacks', 'forge_stacks_archived_20260313_120000';
    PRINT 'Archived table: forge_stacks -> forge_stacks_archived_20260313_120000';
END

-- Archive forge_user_settings
IF OBJECT_ID('forge_user_settings', 'U') IS NOT NULL AND OBJECT_ID('forge_user_settings' + @archive_suffix, 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_user_settings', 'forge_user_settings_archived_20260313_120000';
    PRINT 'Archived table: forge_user_settings -> forge_user_settings_archived_20260313_120000';
END

-- Archive forge_trending_cache
IF OBJECT_ID('forge_trending_cache', 'U') IS NOT NULL AND OBJECT_ID('forge_trending_cache' + @archive_suffix, 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_trending_cache', 'forge_trending_cache_archived_20260313_120000';
    PRINT 'Archived table: forge_trending_cache -> forge_trending_cache_archived_20260313_120000';
END

-- Archive forge_tool_metrics
IF OBJECT_ID('forge_tool_metrics', 'U') IS NOT NULL AND OBJECT_ID('forge_tool_metrics' + @archive_suffix, 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_tool_metrics', 'forge_tool_metrics_archived_20260313_120000';
    PRINT 'Archived table: forge_tool_metrics -> forge_tool_metrics_archived_20260313_120000';
END

-- Archive forge_classification (main table)
IF OBJECT_ID('forge_classification', 'U') IS NOT NULL AND OBJECT_ID('forge_classification' + @archive_suffix, 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_classification', 'forge_classification_archived_20260313_120000';
    PRINT 'Archived table: forge_classification -> forge_classification_archived_20260313_120000';
END

-- Archive forge_categories
IF OBJECT_ID('forge_categories', 'U') IS NOT NULL AND OBJECT_ID('forge_categories' + @archive_suffix, 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_categories', 'forge_categories_archived_20260313_120000';
    PRINT 'Archived table: forge_categories -> forge_categories_archived_20260313_120000';
END

-- ==========================================================================
-- Drop views and procedures (can be recreated easily)
-- ==========================================================================

IF OBJECT_ID('forge_tool_metrics_latest', 'V') IS NOT NULL
BEGIN
    DROP VIEW forge_tool_metrics_latest;
    PRINT 'Dropped view: forge_tool_metrics_latest';
END

IF OBJECT_ID('sp_cleanup_trending_cache', 'P') IS NOT NULL
BEGIN
    DROP PROCEDURE sp_cleanup_trending_cache;
    PRINT 'Dropped procedure: sp_cleanup_trending_cache';
END

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

PRINT '';
PRINT 'Forge database archival completed successfully.';
PRINT '';
PRINT 'All Forge tables have been renamed with timestamp suffix.';
PRINT 'Data is preserved but no longer accessible to the application.';
PRINT '';
PRINT 'To restore Forge functionality:';
PRINT '1. Use restore_forge_database.sql to rename tables back';
PRINT '2. Recreate views, procedures, and triggers from original migrations';
PRINT '3. Update application configuration';