-- Restore Forge Database Script
-- This script restores archived Forge tables to their original names
--
-- Usage:
--   sqlcmd -S <server>.database.windows.net -d sigil -U <user> -i restore_forge_database.sql

SET NOCOUNT ON;
PRINT 'Starting Forge database restoration process...';

-- ==========================================================================
-- Restore Strategy: Rename archived tables back to original names
-- ==========================================================================

-- Restore forge_categories first (base table)
IF OBJECT_ID('forge_categories_archived_20260313_120000', 'U') IS NOT NULL AND OBJECT_ID('forge_categories', 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_categories_archived_20260313_120000', 'forge_categories';
    PRINT 'Restored table: forge_categories_archived_20260313_120000 -> forge_categories';
END

-- Restore forge_classification (main table)
IF OBJECT_ID('forge_classification_archived_20260313_120000', 'U') IS NOT NULL AND OBJECT_ID('forge_classification', 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_classification_archived_20260313_120000', 'forge_classification';
    PRINT 'Restored table: forge_classification_archived_20260313_120000 -> forge_classification';
END

-- Restore forge_tool_metrics
IF OBJECT_ID('forge_tool_metrics_archived_20260313_120000', 'U') IS NOT NULL AND OBJECT_ID('forge_tool_metrics', 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_tool_metrics_archived_20260313_120000', 'forge_tool_metrics';
    PRINT 'Restored table: forge_tool_metrics_archived_20260313_120000 -> forge_tool_metrics';
END

-- Restore forge_trending_cache
IF OBJECT_ID('forge_trending_cache_archived_20260313_120000', 'U') IS NOT NULL AND OBJECT_ID('forge_trending_cache', 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_trending_cache_archived_20260313_120000', 'forge_trending_cache';
    PRINT 'Restored table: forge_trending_cache_archived_20260313_120000 -> forge_trending_cache';
END

-- Restore forge_user_settings
IF OBJECT_ID('forge_user_settings_archived_20260313_120000', 'U') IS NOT NULL AND OBJECT_ID('forge_user_settings', 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_user_settings_archived_20260313_120000', 'forge_user_settings';
    PRINT 'Restored table: forge_user_settings_archived_20260313_120000 -> forge_user_settings';
END

-- Restore forge_stacks
IF OBJECT_ID('forge_stacks_archived_20260313_120000', 'U') IS NOT NULL AND OBJECT_ID('forge_stacks', 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_stacks_archived_20260313_120000', 'forge_stacks';
    PRINT 'Restored table: forge_stacks_archived_20260313_120000 -> forge_stacks';
END

-- Restore forge_user_tools
IF OBJECT_ID('forge_user_tools_archived_20260313_120000', 'U') IS NOT NULL AND OBJECT_ID('forge_user_tools', 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_user_tools_archived_20260313_120000', 'forge_user_tools';
    PRINT 'Restored table: forge_user_tools_archived_20260313_120000 -> forge_user_tools';
END

-- Restore forge_alert_subscriptions
IF OBJECT_ID('forge_alert_subscriptions_archived_20260313_120000', 'U') IS NOT NULL AND OBJECT_ID('forge_alert_subscriptions', 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_alert_subscriptions_archived_20260313_120000', 'forge_alert_subscriptions';
    PRINT 'Restored table: forge_alert_subscriptions_archived_20260313_120000 -> forge_alert_subscriptions';
END

-- Restore forge_analytics_summaries
IF OBJECT_ID('forge_analytics_summaries_archived_20260313_120000', 'U') IS NOT NULL AND OBJECT_ID('forge_analytics_summaries', 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_analytics_summaries_archived_20260313_120000', 'forge_analytics_summaries';
    PRINT 'Restored table: forge_analytics_summaries_archived_20260313_120000 -> forge_analytics_summaries';
END

-- Restore forge_analytics_events
IF OBJECT_ID('forge_analytics_events_archived_20260313_120000', 'U') IS NOT NULL AND OBJECT_ID('forge_analytics_events', 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_analytics_events_archived_20260313_120000', 'forge_analytics_events';
    PRINT 'Restored table: forge_analytics_events_archived_20260313_120000 -> forge_analytics_events';
END

-- Restore forge_matches (dependent table)
IF OBJECT_ID('forge_matches_archived_20260313_120000', 'U') IS NOT NULL AND OBJECT_ID('forge_matches', 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_matches_archived_20260313_120000', 'forge_matches';
    PRINT 'Restored table: forge_matches_archived_20260313_120000 -> forge_matches';
END

-- Restore forge_capabilities (dependent table)
IF OBJECT_ID('forge_capabilities_archived_20260313_120000', 'U') IS NOT NULL AND OBJECT_ID('forge_capabilities', 'U') IS NULL
BEGIN
    EXEC sp_rename 'forge_capabilities_archived_20260313_120000', 'forge_capabilities';
    PRINT 'Restored table: forge_capabilities_archived_20260313_120000 -> forge_capabilities';
END

PRINT '';
PRINT 'Forge database restoration completed successfully.';
PRINT '';
PRINT 'Next steps to complete Forge restoration:';
PRINT '1. Re-run migration scripts to recreate views, procedures, and triggers:';
PRINT '   - 009_forge_tool_metrics.sql (for views and procedures)';
PRINT '2. Restart the API service to reconnect to restored tables';
PRINT '3. Verify Forge endpoints are functioning correctly';