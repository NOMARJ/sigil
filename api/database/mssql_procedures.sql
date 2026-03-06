-- =====================================================================
-- Sigil Pro Tier - MSSQL Stored Procedures
-- Pro tier subscription management and usage tracking procedures
-- =====================================================================

-- =====================================================================
-- Procedure: sp_GetUserSubscription
-- Get user subscription details for tier checking
-- =====================================================================
CREATE OR ALTER PROCEDURE sp_GetUserSubscription
    @user_id UNIQUEIDENTIFIER
AS
BEGIN
    SET NOCOUNT ON;
    
    SELECT 
        s.id,
        s.user_id,
        s.[plan],
        s.[status],
        s.billing_interval,
        s.stripe_customer_id,
        s.stripe_subscription_id,
        s.current_period_end,
        s.created_at,
        s.updated_at,
        CASE 
            WHEN s.[status] = 'active' AND (s.current_period_end IS NULL OR s.current_period_end > SYSDATETIMEOFFSET()) THEN 1
            ELSE 0
        END as is_active,
        CASE 
            WHEN s.[plan] IN ('pro', 'team', 'enterprise') AND s.[status] = 'active' 
                 AND (s.current_period_end IS NULL OR s.current_period_end > SYSDATETIMEOFFSET()) THEN 1
            ELSE 0
        END as has_pro_features
    FROM subscriptions s
    WHERE s.user_id = @user_id;
    
    IF @@ROWCOUNT = 0
    BEGIN
        -- Return default free tier if no subscription exists
        SELECT 
            NULL as id,
            @user_id as user_id,
            'free' as [plan],
            'active' as [status],
            'monthly' as billing_interval,
            NULL as stripe_customer_id,
            NULL as stripe_subscription_id,
            NULL as current_period_end,
            SYSDATETIMEOFFSET() as created_at,
            SYSDATETIMEOFFSET() as updated_at,
            1 as is_active,
            0 as has_pro_features;
    END
END
GO

-- =====================================================================
-- Procedure: sp_CreateProSubscription
-- Create or upgrade user to Pro subscription
-- =====================================================================
CREATE OR ALTER PROCEDURE sp_CreateProSubscription
    @user_id UNIQUEIDENTIFIER,
    @stripe_customer_id NVARCHAR(255),
    @stripe_subscription_id NVARCHAR(255),
    @billing_interval NVARCHAR(50) = 'monthly',
    @current_period_end DATETIMEOFFSET = NULL
AS
BEGIN
    SET NOCOUNT ON;
    BEGIN TRY
        BEGIN TRANSACTION;
        
        -- Upsert subscription record
        MERGE subscriptions AS target
        USING (SELECT @user_id as user_id) AS source
        ON target.user_id = source.user_id
        WHEN MATCHED THEN
            UPDATE SET
                [plan] = 'pro',
                [status] = 'active',
                billing_interval = @billing_interval,
                stripe_customer_id = @stripe_customer_id,
                stripe_subscription_id = @stripe_subscription_id,
                current_period_end = @current_period_end,
                updated_at = SYSDATETIMEOFFSET()
        WHEN NOT MATCHED THEN
            INSERT (user_id, [plan], [status], billing_interval, stripe_customer_id, stripe_subscription_id, current_period_end)
            VALUES (@user_id, 'pro', 'active', @billing_interval, @stripe_customer_id, @stripe_subscription_id, @current_period_end);
        
        -- Log the subscription change
        INSERT INTO subscription_audit_log (
            user_id, 
            action, 
            old_plan, 
            new_plan, 
            stripe_customer_id,
            created_at
        )
        SELECT 
            @user_id,
            'upgrade_to_pro',
            ISNULL(old_sub.[plan], 'free'),
            'pro',
            @stripe_customer_id,
            SYSDATETIMEOFFSET()
        FROM (SELECT [plan] FROM subscriptions WHERE user_id = @user_id) old_sub;
        
        COMMIT TRANSACTION;
        
        -- Return updated subscription
        EXEC sp_GetUserSubscription @user_id;
        
    END TRY
    BEGIN CATCH
        ROLLBACK TRANSACTION;
        THROW;
    END CATCH
END
GO

-- =====================================================================
-- Procedure: sp_CancelProSubscription
-- Cancel or downgrade Pro subscription to free tier
-- =====================================================================
CREATE OR ALTER PROCEDURE sp_CancelProSubscription
    @user_id UNIQUEIDENTIFIER,
    @cancellation_reason NVARCHAR(255) = 'user_cancelled'
AS
BEGIN
    SET NOCOUNT ON;
    BEGIN TRY
        BEGIN TRANSACTION;
        
        DECLARE @old_plan NVARCHAR(50);
        SELECT @old_plan = [plan] FROM subscriptions WHERE user_id = @user_id;
        
        -- Update subscription to free tier
        UPDATE subscriptions 
        SET 
            [plan] = 'free',
            [status] = 'cancelled',
            stripe_subscription_id = NULL,
            current_period_end = NULL,
            updated_at = SYSDATETIMEOFFSET()
        WHERE user_id = @user_id;
        
        -- Log the cancellation
        INSERT INTO subscription_audit_log (
            user_id, 
            action, 
            old_plan, 
            new_plan,
            metadata_json,
            created_at
        )
        VALUES (
            @user_id,
            'downgrade_to_free',
            ISNULL(@old_plan, 'pro'),
            'free',
            JSON_OBJECT('cancellation_reason', @cancellation_reason),
            SYSDATETIMEOFFSET()
        );
        
        COMMIT TRANSACTION;
        
        -- Return updated subscription
        EXEC sp_GetUserSubscription @user_id;
        
    END TRY
    BEGIN CATCH
        ROLLBACK TRANSACTION;
        THROW;
    END CATCH
END
GO

-- =====================================================================
-- Procedure: sp_TrackProFeatureUsage
-- Track usage of Pro features for analytics and billing
-- =====================================================================
CREATE OR ALTER PROCEDURE sp_TrackProFeatureUsage
    @user_id UNIQUEIDENTIFIER,
    @feature_type NVARCHAR(100), -- 'llm_analysis', 'advanced_scan', etc.
    @usage_data NVARCHAR(MAX) = NULL -- JSON with usage details
AS
BEGIN
    SET NOCOUNT ON;
    
    -- Check if user has Pro features
    DECLARE @has_pro_features BIT = 0;
    SELECT @has_pro_features = 1
    FROM subscriptions 
    WHERE user_id = @user_id 
          AND [plan] IN ('pro', 'team', 'enterprise')
          AND [status] = 'active'
          AND (current_period_end IS NULL OR current_period_end > SYSDATETIMEOFFSET());
    
    IF @has_pro_features = 0
    BEGIN
        RAISERROR('User does not have active Pro subscription', 16, 1);
        RETURN;
    END
    
    -- Insert usage record
    INSERT INTO pro_feature_usage (
        user_id,
        feature_type,
        usage_data,
        created_at
    )
    VALUES (
        @user_id,
        @feature_type,
        @usage_data,
        SYSDATETIMEOFFSET()
    );
    
    SELECT @@ROWCOUNT as records_inserted;
END
GO

-- =====================================================================
-- Procedure: sp_GetProFeatureUsage
-- Get Pro feature usage statistics for a user
-- =====================================================================
CREATE OR ALTER PROCEDURE sp_GetProFeatureUsage
    @user_id UNIQUEIDENTIFIER,
    @start_date DATETIMEOFFSET = NULL,
    @end_date DATETIMEOFFSET = NULL,
    @feature_type NVARCHAR(100) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    
    -- Default to last 30 days if no date range provided
    IF @start_date IS NULL
        SET @start_date = DATEADD(day, -30, SYSDATETIMEOFFSET());
    
    IF @end_date IS NULL
        SET @end_date = SYSDATETIMEOFFSET();
    
    SELECT 
        pfu.feature_type,
        COUNT(*) as usage_count,
        MIN(pfu.created_at) as first_usage,
        MAX(pfu.created_at) as last_usage,
        CASE 
            WHEN pfu.feature_type = 'llm_analysis' THEN
                JSON_VALUE(pfu.usage_data, '$.tokens_used')
            ELSE NULL
        END as total_tokens_used
    FROM pro_feature_usage pfu
    WHERE pfu.user_id = @user_id
          AND pfu.created_at >= @start_date
          AND pfu.created_at <= @end_date
          AND (@feature_type IS NULL OR pfu.feature_type = @feature_type)
    GROUP BY pfu.feature_type
    ORDER BY usage_count DESC;
END
GO

-- =====================================================================
-- Supporting Tables for Pro Features
-- =====================================================================

-- Pro feature usage tracking
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'pro_feature_usage')
BEGIN
    CREATE TABLE pro_feature_usage (
        id                UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id           UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        feature_type      NVARCHAR(100) NOT NULL, -- 'llm_analysis', 'advanced_scan', etc.
        usage_data        NVARCHAR(MAX), -- JSON with feature-specific data
        created_at        DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT CK_pro_feature_usage_data_json CHECK (usage_data IS NULL OR ISJSON(usage_data) = 1)
    );
END
GO

-- Indexes for pro feature usage
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_pro_feature_usage_user_id')
    CREATE INDEX idx_pro_feature_usage_user_id ON pro_feature_usage(user_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_pro_feature_usage_type_date')
    CREATE INDEX idx_pro_feature_usage_type_date ON pro_feature_usage(feature_type, created_at);
GO

-- Subscription audit log
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'subscription_audit_log')
BEGIN
    CREATE TABLE subscription_audit_log (
        id                UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id           UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        action            NVARCHAR(100) NOT NULL, -- 'upgrade_to_pro', 'downgrade_to_free', etc.
        old_plan          NVARCHAR(50),
        new_plan          NVARCHAR(50),
        stripe_customer_id NVARCHAR(255),
        metadata_json     NVARCHAR(MAX), -- Additional context
        created_at        DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT CK_subscription_audit_metadata_json CHECK (metadata_json IS NULL OR ISJSON(metadata_json) = 1)
    );
END
GO

-- Indexes for audit log
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_subscription_audit_user_id')
    CREATE INDEX idx_subscription_audit_user_id ON subscription_audit_log(user_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_subscription_audit_action_date')
    CREATE INDEX idx_subscription_audit_action_date ON subscription_audit_log(action, created_at);
GO