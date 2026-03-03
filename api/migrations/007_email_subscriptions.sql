-- Email subscription and newsletter management tables
-- Migration 007: Email subscriptions and weekly digest automation
-- Azure SQL Database (T-SQL)

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'email_subscriptions')
BEGIN
    CREATE TABLE email_subscriptions (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        email NVARCHAR(255) NOT NULL,
        preferences NVARCHAR(MAX) NOT NULL DEFAULT '{"security_alerts": true, "tool_discoveries": true, "weekly_digest": true, "product_updates": true}',
        unsubscribe_token NVARCHAR(64) NOT NULL DEFAULT LOWER(REPLACE(CONVERT(NVARCHAR(36), NEWID()), '-', '')),
        source NVARCHAR(50) NOT NULL DEFAULT 'forge',
        is_active BIT NOT NULL DEFAULT 1,
        confirmed_at DATETIMEOFFSET NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT UQ_email_subscriptions_email UNIQUE (email),
        CONSTRAINT UQ_email_subscriptions_token UNIQUE (unsubscribe_token),
        CONSTRAINT CK_email_subscriptions_preferences_json CHECK (preferences IS NULL OR ISJSON(preferences) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'email_campaigns')
BEGIN
    CREATE TABLE email_campaigns (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        campaign_id NVARCHAR(64) NOT NULL,
        subject NVARCHAR(255) NOT NULL,
        content_json NVARCHAR(MAX) NOT NULL,
        recipient_count INT NOT NULL DEFAULT 0,
        sent_count INT NOT NULL DEFAULT 0,
        bounced_count INT NOT NULL DEFAULT 0,
        opened_count INT NOT NULL DEFAULT 0,
        clicked_count INT NOT NULL DEFAULT 0,
        status NVARCHAR(50) NOT NULL DEFAULT 'scheduled',
        scheduled_for DATETIMEOFFSET NOT NULL,
        sent_at DATETIMEOFFSET NULL,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT UQ_email_campaigns_campaign_id UNIQUE (campaign_id),
        CONSTRAINT CK_email_campaigns_content_json CHECK (content_json IS NULL OR ISJSON(content_json) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'email_sends')
BEGIN
    CREATE TABLE email_sends (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        campaign_id NVARCHAR(64) NOT NULL,
        email NVARCHAR(255) NOT NULL,
        status NVARCHAR(50) NOT NULL DEFAULT 'sent',
        sent_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        opened_at DATETIMEOFFSET NULL,
        clicked_at DATETIMEOFFSET NULL,
        bounced_at DATETIMEOFFSET NULL,
        unsubscribed_at DATETIMEOFFSET NULL,
        external_id NVARCHAR(255) NULL,
        CONSTRAINT FK_email_sends_campaign_id FOREIGN KEY (campaign_id) REFERENCES email_campaigns(campaign_id) ON DELETE CASCADE
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'weekly_digest_cache')
BEGIN
    CREATE TABLE weekly_digest_cache (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        week_ending DATE NOT NULL,
        content_json NVARCHAR(MAX) NOT NULL,
        generated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        is_current BIT NOT NULL DEFAULT 0,
        CONSTRAINT UQ_weekly_digest_cache_week_ending UNIQUE (week_ending),
        CONSTRAINT CK_weekly_digest_cache_content_json CHECK (content_json IS NULL OR ISJSON(content_json) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'unsubscribe_log')
BEGIN
    CREATE TABLE unsubscribe_log (
        id BIGINT IDENTITY(1,1) PRIMARY KEY,
        email NVARCHAR(255) NOT NULL,
        unsubscribe_token NVARCHAR(64) NOT NULL,
        reason NVARCHAR(MAX) NULL,
        campaign_id NVARCHAR(64) NULL,
        unsubscribed_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

-- Indexes for performance
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_email_subscriptions_email')
    CREATE INDEX idx_email_subscriptions_email ON email_subscriptions(email);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_email_subscriptions_active')
    CREATE INDEX idx_email_subscriptions_active ON email_subscriptions(is_active) WHERE is_active = 1;
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_email_subscriptions_token')
    CREATE INDEX idx_email_subscriptions_token ON email_subscriptions(unsubscribe_token);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_email_campaigns_status')
    CREATE INDEX idx_email_campaigns_status ON email_campaigns(status);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_email_campaigns_scheduled')
    CREATE INDEX idx_email_campaigns_scheduled ON email_campaigns(scheduled_for) WHERE status = 'scheduled';
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_email_campaigns_sent')
    CREATE INDEX idx_email_campaigns_sent ON email_campaigns(sent_at) WHERE status = 'sent';
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_email_sends_campaign')
    CREATE INDEX idx_email_sends_campaign ON email_sends(campaign_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_email_sends_email')
    CREATE INDEX idx_email_sends_email ON email_sends(email);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_email_sends_status')
    CREATE INDEX idx_email_sends_status ON email_sends(status);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_weekly_digest_week')
    CREATE INDEX idx_weekly_digest_week ON weekly_digest_cache(week_ending);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_weekly_digest_current')
    CREATE INDEX idx_weekly_digest_current ON weekly_digest_cache(is_current) WHERE is_current = 1;
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_unsubscribe_log_email')
    CREATE INDEX idx_unsubscribe_log_email ON unsubscribe_log(email);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_unsubscribe_log_token')
    CREATE INDEX idx_unsubscribe_log_token ON unsubscribe_log(unsubscribe_token);
GO

-- Keep updated_at current on profile updates
IF OBJECT_ID('tr_email_subscriptions_updated_at', 'TR') IS NOT NULL
    DROP TRIGGER tr_email_subscriptions_updated_at;
GO

CREATE TRIGGER tr_email_subscriptions_updated_at
ON email_subscriptions
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF TRIGGER_NESTLEVEL() > 1
        RETURN;

    UPDATE es
    SET updated_at = SYSDATETIMEOFFSET()
    FROM email_subscriptions es
    INNER JOIN inserted i ON i.id = es.id;
END
GO

-- Insert test data for development (idempotent)
IF NOT EXISTS (SELECT 1 FROM email_subscriptions WHERE email = 'test@example.com')
BEGIN
    INSERT INTO email_subscriptions (email, source)
    VALUES ('test@example.com', 'forge');
END
GO

PRINT 'Migration 007_email_subscriptions applied successfully.';
GO