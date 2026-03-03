-- Sigil Forge Security and Access Control Schema Updates
-- Adds subscription, team, and audit logging tables for Forge premium features

-- ============================================================================
-- UPDATE USERS TABLE - Add subscription fields
-- ============================================================================

-- Add subscription fields to users table
IF NOT EXISTS (SELECT * FROM sys.columns WHERE name = 'subscription_plan' AND object_id = OBJECT_ID('users'))
BEGIN
    ALTER TABLE users ADD subscription_plan NVARCHAR(50) NOT NULL DEFAULT 'free';
END
GO

IF NOT EXISTS (SELECT * FROM sys.columns WHERE name = 'subscription_status' AND object_id = OBJECT_ID('users'))
BEGIN
    ALTER TABLE users ADD subscription_status NVARCHAR(50) NOT NULL DEFAULT 'active';
END
GO

IF NOT EXISTS (SELECT * FROM sys.columns WHERE name = 'subscription_expires' AND object_id = OBJECT_ID('users'))
BEGIN
    ALTER TABLE users ADD subscription_expires DATETIME2 NULL;
END
GO

IF NOT EXISTS (SELECT * FROM sys.columns WHERE name = 'stripe_customer_id' AND object_id = OBJECT_ID('users'))
BEGIN
    ALTER TABLE users ADD stripe_customer_id NVARCHAR(255) NULL;
END
GO

IF NOT EXISTS (SELECT * FROM sys.columns WHERE name = 'organization_id' AND object_id = OBJECT_ID('users'))
BEGIN
    ALTER TABLE users ADD organization_id UNIQUEIDENTIFIER NULL;
END
GO

IF NOT EXISTS (SELECT * FROM sys.columns WHERE name = 'org_role' AND object_id = OBJECT_ID('users'))
BEGIN
    ALTER TABLE users ADD org_role NVARCHAR(50) NULL;
END
GO

-- Add indexes for subscription queries
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_users_subscription_plan')
    CREATE INDEX idx_users_subscription_plan ON users (subscription_plan);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_users_organization')
    CREATE INDEX idx_users_organization ON users (organization_id);
GO

-- ============================================================================
-- ORGANIZATIONS TABLE - For Enterprise customers
-- ============================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'organizations')
BEGIN
    CREATE TABLE organizations (
        id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        name NVARCHAR(255) NOT NULL,
        domain NVARCHAR(255) NULL, -- Company domain for SSO
        subscription_plan NVARCHAR(50) NOT NULL DEFAULT 'enterprise',
        subscription_status NVARCHAR(50) NOT NULL DEFAULT 'active',
        subscription_expires DATETIME2 NULL,
        
        -- Billing information
        stripe_customer_id NVARCHAR(255) NULL,
        billing_email NVARCHAR(255) NULL,
        
        -- Settings
        sso_enabled BIT DEFAULT 0,
        enforce_2fa BIT DEFAULT 0,
        ip_whitelist NVARCHAR(MAX) NULL, -- JSON array of allowed IPs
        
        -- Limits
        max_users INT DEFAULT 100,
        max_api_calls_per_hour INT DEFAULT 25000,
        
        created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
        updated_at DATETIME2 NOT NULL DEFAULT GETDATE()
    );
END
GO

-- Add foreign key from users to organizations
IF NOT EXISTS (SELECT * FROM sys.foreign_keys WHERE name = 'fk_users_organization')
BEGIN
    ALTER TABLE users
        ADD CONSTRAINT fk_users_organization 
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL;
END
GO

-- ============================================================================
-- FORGE USER TOOLS - Track which tools users are monitoring
-- ============================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_user_tools')
BEGIN
    CREATE TABLE forge_user_tools (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        user_id UNIQUEIDENTIFIER NOT NULL,
        team_id UNIQUEIDENTIFIER NULL,
        
        -- Tool identification
        package_name NVARCHAR(255) NOT NULL,
        ecosystem NVARCHAR(50) NOT NULL,
        package_version NVARCHAR(100) NULL,
        
        -- Tracking metadata
        tracking_reason NVARCHAR(500) NULL,
        tags NVARCHAR(MAX) NULL, -- JSON array of user tags
        notes NVARCHAR(MAX) NULL,
        
        -- Alerts configuration
        alert_on_update BIT DEFAULT 1,
        alert_on_vulnerability BIT DEFAULT 1,
        alert_on_removal BIT DEFAULT 1,
        
        -- Timestamps
        tracked_at DATETIME2 NOT NULL DEFAULT GETDATE(),
        last_checked DATETIME2 NULL,
        
        -- Constraints
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE SET NULL,
        INDEX IX_forge_user_tools_user (user_id, tracked_at DESC),
        INDEX IX_forge_user_tools_package (package_name, ecosystem),
        UNIQUE (user_id, package_name, ecosystem)
    );
END
GO

-- ============================================================================
-- FORGE USER STACKS - Custom tool combinations
-- ============================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_user_stacks')
BEGIN
    CREATE TABLE forge_user_stacks (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        user_id UNIQUEIDENTIFIER NOT NULL,
        team_id UNIQUEIDENTIFIER NULL,
        
        -- Stack details
        stack_name NVARCHAR(255) NOT NULL,
        description NVARCHAR(1000) NULL,
        use_case NVARCHAR(500) NULL,
        
        -- Stack components (JSON arrays)
        skills NVARCHAR(MAX) NOT NULL,
        mcps NVARCHAR(MAX) NOT NULL,
        
        -- Sharing settings
        is_public BIT DEFAULT 0,
        is_team_shared BIT DEFAULT 0,
        share_token NVARCHAR(255) NULL, -- For public sharing
        
        -- Analytics
        view_count INT DEFAULT 0,
        fork_count INT DEFAULT 0,
        
        created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
        updated_at DATETIME2 NOT NULL DEFAULT GETDATE(),
        
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE SET NULL,
        INDEX IX_forge_user_stacks_user (user_id),
        INDEX IX_forge_user_stacks_public (is_public, view_count DESC),
        UNIQUE (user_id, stack_name)
    );
END
GO

-- ============================================================================
-- AUDIT LOGS - For Enterprise customers
-- ============================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'audit_logs')
BEGIN
    CREATE TABLE audit_logs (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        user_id UNIQUEIDENTIFIER NOT NULL,
        organization_id UNIQUEIDENTIFIER NULL,
        team_id UNIQUEIDENTIFIER NULL,
        
        -- Action details
        action NVARCHAR(100) NOT NULL,
        resource_type NVARCHAR(100) NOT NULL,
        resource_id NVARCHAR(255) NOT NULL,
        
        -- Additional context
        metadata NVARCHAR(MAX) NULL, -- JSON object
        ip_address NVARCHAR(45) NULL,
        user_agent NVARCHAR(500) NULL,
        
        -- Response
        success BIT DEFAULT 1,
        error_message NVARCHAR(500) NULL,
        
        timestamp DATETIME2 NOT NULL DEFAULT GETDATE(),
        
        -- Indexes for querying
        INDEX IX_audit_logs_user_time (user_id, timestamp DESC),
        INDEX IX_audit_logs_org_time (organization_id, timestamp DESC),
        INDEX IX_audit_logs_action_time (action, timestamp DESC),
        INDEX IX_audit_logs_resource (resource_type, resource_id),
        
        -- Foreign keys
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL,
        FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE SET NULL
    );
END
GO

-- ============================================================================
-- API KEYS - For programmatic access
-- ============================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'api_keys')
BEGIN
    CREATE TABLE api_keys (
        id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id UNIQUEIDENTIFIER NOT NULL,
        team_id UNIQUEIDENTIFIER NULL,
        
        -- Key details
        key_hash NVARCHAR(128) NOT NULL, -- SHA-256 hash of the actual key
        key_prefix NVARCHAR(20) NOT NULL, -- First few chars for identification
        name NVARCHAR(255) NOT NULL,
        description NVARCHAR(500) NULL,
        
        -- Permissions
        scopes NVARCHAR(MAX) NULL, -- JSON array of allowed scopes
        rate_limit_override INT NULL, -- Custom rate limit for this key
        
        -- Usage tracking
        last_used DATETIME2 NULL,
        usage_count INT DEFAULT 0,
        
        -- Lifecycle
        expires_at DATETIME2 NULL,
        revoked_at DATETIME2 NULL,
        created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
        
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE SET NULL,
        INDEX IX_api_keys_hash (key_hash),
        INDEX IX_api_keys_user (user_id),
        UNIQUE (key_hash)
    );
END
GO

-- ============================================================================
-- FEATURE FLAGS - For gradual rollout and custom access
-- ============================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'feature_flags')
BEGIN
    CREATE TABLE feature_flags (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        user_id UNIQUEIDENTIFIER NULL,
        team_id UNIQUEIDENTIFIER NULL,
        organization_id UNIQUEIDENTIFIER NULL,
        
        -- Feature details
        feature_name NVARCHAR(100) NOT NULL,
        enabled BIT NOT NULL DEFAULT 1,
        
        -- Override metadata
        reason NVARCHAR(500) NULL,
        expires_at DATETIME2 NULL,
        
        created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
        created_by UNIQUEIDENTIFIER NULL,
        
        -- Ensure only one flag per feature per entity
        INDEX IX_feature_flags_user (user_id, feature_name),
        INDEX IX_feature_flags_team (team_id, feature_name),
        INDEX IX_feature_flags_org (organization_id, feature_name),
        
        -- Foreign keys
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE,
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
        
        -- Constraint to ensure at least one entity is specified
        CONSTRAINT CK_feature_flags_entity CHECK (
            (user_id IS NOT NULL AND team_id IS NULL AND organization_id IS NULL) OR
            (user_id IS NULL AND team_id IS NOT NULL AND organization_id IS NULL) OR
            (user_id IS NULL AND team_id IS NULL AND organization_id IS NOT NULL)
        )
    );
END
GO

-- ============================================================================
-- USAGE ANALYTICS - Track feature usage for insights
-- ============================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_usage_analytics')
BEGIN
    CREATE TABLE forge_usage_analytics (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        user_id UNIQUEIDENTIFIER NOT NULL,
        team_id UNIQUEIDENTIFIER NULL,
        
        -- Feature usage
        feature_name NVARCHAR(100) NOT NULL,
        action_type NVARCHAR(100) NOT NULL,
        
        -- Context
        metadata NVARCHAR(MAX) NULL, -- JSON object with additional data
        session_id NVARCHAR(255) NULL,
        
        -- Performance
        duration_ms INT NULL,
        
        timestamp DATETIME2 NOT NULL DEFAULT GETDATE(),
        
        -- Indexes for analytics queries
        INDEX IX_forge_usage_analytics_user_time (user_id, timestamp DESC),
        INDEX IX_forge_usage_analytics_feature_time (feature_name, timestamp DESC),
        INDEX IX_forge_usage_analytics_daily NONCLUSTERED (
            CAST(timestamp AS DATE),
            feature_name,
            user_id
        ),
        
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE SET NULL
    );
END
GO

-- ============================================================================
-- COMPLIANCE REPORTS - For Enterprise regulatory compliance
-- ============================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'compliance_reports')
BEGIN
    CREATE TABLE compliance_reports (
        id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        organization_id UNIQUEIDENTIFIER NOT NULL,
        
        -- Report details
        report_type NVARCHAR(100) NOT NULL, -- 'GDPR', 'SOC2', 'ISO27001', etc.
        report_period_start DATE NOT NULL,
        report_period_end DATE NOT NULL,
        
        -- Report content
        summary NVARCHAR(MAX) NULL,
        findings NVARCHAR(MAX) NULL, -- JSON array
        recommendations NVARCHAR(MAX) NULL, -- JSON array
        
        -- Status
        status NVARCHAR(50) NOT NULL DEFAULT 'draft', -- draft, final, archived
        
        -- Audit trail
        generated_by UNIQUEIDENTIFIER NOT NULL,
        reviewed_by UNIQUEIDENTIFIER NULL,
        approved_by UNIQUEIDENTIFIER NULL,
        
        generated_at DATETIME2 NOT NULL DEFAULT GETDATE(),
        reviewed_at DATETIME2 NULL,
        approved_at DATETIME2 NULL,
        
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
        FOREIGN KEY (generated_by) REFERENCES users(id),
        FOREIGN KEY (reviewed_by) REFERENCES users(id),
        FOREIGN KEY (approved_by) REFERENCES users(id),
        
        INDEX IX_compliance_reports_org (organization_id, report_period_end DESC)
    );
END
GO

-- ============================================================================
-- RATE LIMIT TRACKING - For API rate limiting
-- ============================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'rate_limit_tracking')
BEGIN
    CREATE TABLE rate_limit_tracking (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        user_id UNIQUEIDENTIFIER NOT NULL,
        api_key_id UNIQUEIDENTIFIER NULL,
        
        -- Window tracking
        window_start DATETIME2 NOT NULL,
        window_end DATETIME2 NOT NULL,
        
        -- Counters
        request_count INT NOT NULL DEFAULT 0,
        limit_exceeded_count INT NOT NULL DEFAULT 0,
        
        -- Last request
        last_request_at DATETIME2 NULL,
        last_endpoint NVARCHAR(255) NULL,
        
        INDEX IX_rate_limit_tracking_user_window (user_id, window_end DESC),
        INDEX IX_rate_limit_tracking_key_window (api_key_id, window_end DESC),
        
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
    );
END
GO

-- ============================================================================
-- GRANT PERMISSIONS (if using specific database user for API)
-- ============================================================================

-- Example: Grant permissions to API user
-- GRANT SELECT, INSERT, UPDATE, DELETE ON forge_user_tools TO [api_user];
-- GRANT SELECT, INSERT, UPDATE, DELETE ON forge_user_stacks TO [api_user];
-- GRANT SELECT, INSERT ON audit_logs TO [api_user];
-- etc...