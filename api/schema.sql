-- Sigil API — Azure SQL Database Schema (T-SQL)
--
-- Tables for users, teams, scans, threat intelligence, policies,
-- alerts, audit logging, and billing-related metadata.
--
-- Run with:
--   sqlcmd -S <server>.database.windows.net -d sigil -U <user> -i api/schema.sql

-- =====================================================================
-- Teams
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'teams')
BEGIN
    CREATE TABLE teams (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        name            NVARCHAR(255) NOT NULL,
        owner_id        UNIQUEIDENTIFIER,                       -- FK to users, set after user creation
        [plan]          NVARCHAR(50)  NOT NULL DEFAULT 'free',
        created_at      DATETIMEOFFSET  NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_teams_owner')
    CREATE INDEX idx_teams_owner ON teams (owner_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_teams_plan')
    CREATE INDEX idx_teams_plan ON teams ([plan]);
GO

-- =====================================================================
-- Users
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'users')
BEGIN
    CREATE TABLE users (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        email           NVARCHAR(255) NOT NULL UNIQUE,
        password_hash   NVARCHAR(MAX) NOT NULL,
        name            NVARCHAR(255) NOT NULL DEFAULT '',
        team_id         UNIQUEIDENTIFIER REFERENCES teams(id) ON DELETE SET NULL,
        role            NVARCHAR(50)  NOT NULL DEFAULT 'member',
        created_at      DATETIMEOFFSET  NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_users_email')
    CREATE UNIQUE INDEX idx_users_email ON users (email);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_users_team')
    CREATE INDEX idx_users_team ON users (team_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_users_role')
    CREATE INDEX idx_users_role ON users (role);
GO

-- Now add the FK from teams.owner_id -> users.id
IF NOT EXISTS (SELECT * FROM sys.foreign_keys WHERE name = 'fk_teams_owner')
    ALTER TABLE teams
        ADD CONSTRAINT fk_teams_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE SET NULL;
GO

-- =====================================================================
-- Scans
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'scans')
BEGIN
    CREATE TABLE scans (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id         UNIQUEIDENTIFIER REFERENCES users(id) ON DELETE SET NULL,
        team_id         UNIQUEIDENTIFIER REFERENCES teams(id) ON DELETE SET NULL,
        target          NVARCHAR(MAX) NOT NULL,
        target_type     NVARCHAR(50)  NOT NULL DEFAULT 'directory',
        files_scanned   INT      NOT NULL DEFAULT 0,
        risk_score      FLOAT NOT NULL DEFAULT 0.0,
        verdict         NVARCHAR(50)  NOT NULL DEFAULT 'LOW_RISK',
        findings_json   NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        metadata_json   NVARCHAR(MAX) NOT NULL DEFAULT '{}',
        created_at      DATETIMEOFFSET  NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT CK_scans_findings_json CHECK (findings_json IS NULL OR ISJSON(findings_json) = 1),
        CONSTRAINT CK_scans_metadata_json CHECK (metadata_json IS NULL OR ISJSON(metadata_json) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_scans_user')
    CREATE INDEX idx_scans_user ON scans (user_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_scans_team')
    CREATE INDEX idx_scans_team ON scans (team_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_scans_verdict')
    CREATE INDEX idx_scans_verdict ON scans (verdict);
GO

-- Index removed: target is NVARCHAR(MAX) and can exceed 450 chars (URLs/paths)
-- Use full-text search if target lookup is needed
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_scans_created')
    CREATE INDEX idx_scans_created ON scans (created_at DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_scans_risk_score')
    CREATE INDEX idx_scans_risk_score ON scans (risk_score DESC);
GO

-- =====================================================================
-- Threats (known-malicious package registry)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'threats')
BEGIN
    CREATE TABLE threats (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        hash            NVARCHAR(128) NOT NULL UNIQUE,
        package_name    NVARCHAR(255) NOT NULL,
        version         NVARCHAR(128) NOT NULL DEFAULT '',
        severity        NVARCHAR(50)  NOT NULL DEFAULT 'HIGH',
        source          NVARCHAR(100) NOT NULL DEFAULT 'community',
        confirmed_at    DATETIMEOFFSET,
        description     NVARCHAR(MAX) NOT NULL DEFAULT '',
        created_at      DATETIMEOFFSET  NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_threats_hash')
    CREATE UNIQUE INDEX idx_threats_hash ON threats (hash);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_threats_package')
    CREATE INDEX idx_threats_package ON threats (package_name);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_threats_severity')
    CREATE INDEX idx_threats_severity ON threats (severity);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_threats_source')
    CREATE INDEX idx_threats_source ON threats (source);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_threats_confirmed')
    CREATE INDEX idx_threats_confirmed ON threats (confirmed_at);
GO

-- =====================================================================
-- Signatures: see api/scripts/create_signature_tables.sql (extended version with category, weight, etc.)
-- =====================================================================

-- =====================================================================
-- Publishers (reputation tracking)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'publishers')
BEGIN
    CREATE TABLE publishers (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        publisher_id    NVARCHAR(255) NOT NULL UNIQUE,
        trust_score     FLOAT NOT NULL DEFAULT 100.0,
        total_packages  INT      NOT NULL DEFAULT 0,
        flagged_count   INT      NOT NULL DEFAULT 0,
        first_seen      DATETIMEOFFSET,
        last_active     DATETIMEOFFSET,
        notes           NVARCHAR(MAX) NOT NULL DEFAULT ''
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_publishers_pid')
    CREATE UNIQUE INDEX idx_publishers_pid ON publishers (publisher_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_publishers_trust_score')
    CREATE INDEX idx_publishers_trust_score ON publishers (trust_score);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_publishers_flagged')
    CREATE INDEX idx_publishers_flagged ON publishers (flagged_count DESC);
GO

-- =====================================================================
-- Threat Reports (community submissions)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'threat_reports')
BEGIN
    CREATE TABLE threat_reports (
        id                UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        package_name      NVARCHAR(255) NOT NULL,
        package_version   NVARCHAR(128) NOT NULL DEFAULT '',
        ecosystem         NVARCHAR(50)  NOT NULL DEFAULT 'unknown',
        reason            NVARCHAR(MAX) NOT NULL,
        evidence          NVARCHAR(MAX) NOT NULL DEFAULT '',
        reporter_email    NVARCHAR(255),
        reporter_user_id  UNIQUEIDENTIFIER REFERENCES users(id) ON DELETE SET NULL,
        [status]          NVARCHAR(50)  NOT NULL DEFAULT 'received',
        reviewer_id       UNIQUEIDENTIFIER REFERENCES users(id) ON DELETE NO ACTION,
        review_notes      NVARCHAR(MAX) NOT NULL DEFAULT '',
        reviewed_at       DATETIMEOFFSET,
        created_at        DATETIMEOFFSET  NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_reports_package')
    CREATE INDEX idx_reports_package ON threat_reports (package_name);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_reports_status')
    CREATE INDEX idx_reports_status ON threat_reports (status);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_reports_reporter')
    CREATE INDEX idx_reports_reporter ON threat_reports (reporter_user_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_reports_created')
    CREATE INDEX idx_reports_created ON threat_reports (created_at DESC);
GO

-- =====================================================================
-- Verifications (marketplace package verification records)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'verifications')
BEGIN
    CREATE TABLE verifications (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        package_name    NVARCHAR(255) NOT NULL,
        version         NVARCHAR(128) NOT NULL DEFAULT '',
        ecosystem       NVARCHAR(50)  NOT NULL DEFAULT 'unknown',
        publisher_id    NVARCHAR(255),
        artifact_hash   NVARCHAR(128),
        verdict         NVARCHAR(50)  NOT NULL DEFAULT 'PENDING',
        risk_score      FLOAT NOT NULL DEFAULT 0.0,
        badge_url       NVARCHAR(MAX),
        verified_at     DATETIMEOFFSET,
        created_at      DATETIMEOFFSET  NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_verifications_package')
    CREATE INDEX idx_verifications_package ON verifications (package_name, ecosystem);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_verifications_publisher')
    CREATE INDEX idx_verifications_publisher ON verifications (publisher_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_verifications_verdict')
    CREATE INDEX idx_verifications_verdict ON verifications (verdict);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_verifications_created')
    CREATE INDEX idx_verifications_created ON verifications (created_at DESC);
GO

-- =====================================================================
-- Policies (team scan policies)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'policies')
BEGIN
    CREATE TABLE policies (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        team_id         UNIQUEIDENTIFIER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
        name            NVARCHAR(255) NOT NULL,
        type            NVARCHAR(50)  NOT NULL,
        config_json     NVARCHAR(MAX) NOT NULL DEFAULT '{}',
        enabled         BIT      NOT NULL DEFAULT 1,
        created_at      DATETIMEOFFSET  NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at      DATETIMEOFFSET  NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT CK_policies_config_json CHECK (config_json IS NULL OR ISJSON(config_json) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_policies_team')
    CREATE INDEX idx_policies_team ON policies (team_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_policies_type')
    CREATE INDEX idx_policies_type ON policies (type);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_policies_enabled')
    CREATE INDEX idx_policies_enabled ON policies (team_id, enabled);
GO

-- =====================================================================
-- Alerts (notification channels)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'alerts')
BEGIN
    CREATE TABLE alerts (
        id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        team_id             UNIQUEIDENTIFIER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
        channel_type        NVARCHAR(50)  NOT NULL,
        channel_config_json NVARCHAR(MAX) NOT NULL DEFAULT '{}',
        enabled             BIT      NOT NULL DEFAULT 1,
        created_at          DATETIMEOFFSET  NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT CK_alerts_channel_config_json CHECK (channel_config_json IS NULL OR ISJSON(channel_config_json) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_alerts_team')
    CREATE INDEX idx_alerts_team ON alerts (team_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_alerts_type')
    CREATE INDEX idx_alerts_type ON alerts (channel_type);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_alerts_enabled')
    CREATE INDEX idx_alerts_enabled ON alerts (team_id, enabled);
GO

-- =====================================================================
-- Audit Log
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'audit_log')
BEGIN
    CREATE TABLE audit_log (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id         UNIQUEIDENTIFIER REFERENCES users(id) ON DELETE SET NULL,
        team_id         UNIQUEIDENTIFIER REFERENCES teams(id) ON DELETE SET NULL,
        action          NVARCHAR(255) NOT NULL,
        details_json    NVARCHAR(MAX) NOT NULL DEFAULT '{}',
        created_at      DATETIMEOFFSET  NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT CK_audit_log_details_json CHECK (details_json IS NULL OR ISJSON(details_json) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_audit_user')
    CREATE INDEX idx_audit_user ON audit_log (user_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_audit_team')
    CREATE INDEX idx_audit_team ON audit_log (team_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_audit_action')
    CREATE INDEX idx_audit_action ON audit_log (action);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_audit_created')
    CREATE INDEX idx_audit_created ON audit_log (created_at DESC);
GO

-- =====================================================================
-- Useful composite indexes for common query patterns
-- =====================================================================

-- Recent scans by team with high risk
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_scans_team_risk')
    CREATE INDEX idx_scans_team_risk ON scans (team_id, risk_score DESC, created_at DESC);
GO

-- Active policies for a team
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_policies_team_active')
    CREATE INDEX idx_policies_team_active ON policies (team_id, enabled) WHERE enabled = 1;
GO

-- Recent audit actions by team
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_audit_team_recent')
    CREATE INDEX idx_audit_team_recent ON audit_log (team_id, created_at DESC);
GO

-- =====================================================================
-- Password Reset Tokens
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'password_reset_tokens')
BEGIN
    CREATE TABLE password_reset_tokens (
        id          UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id     UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash  NVARCHAR(450) NOT NULL UNIQUE,
        expires_at  DATETIMEOFFSET NOT NULL,
        created_at  DATETIMEOFFSET DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_password_reset_tokens_token_hash')
    CREATE INDEX idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_password_reset_tokens_user_id')
    CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
GO

-- =====================================================================
-- Subscriptions (billing plan records per user)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'subscriptions')
BEGIN
    CREATE TABLE subscriptions (
        id                      UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        user_id                 UNIQUEIDENTIFIER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        [plan]                  NVARCHAR(50) NOT NULL DEFAULT 'free',
        [status]                NVARCHAR(50) NOT NULL DEFAULT 'active',
        billing_interval        NVARCHAR(50) NOT NULL DEFAULT 'monthly',
        stripe_customer_id      NVARCHAR(255),
        stripe_subscription_id  NVARCHAR(255),
        current_period_end      DATETIMEOFFSET,
        created_at              DATETIMEOFFSET DEFAULT SYSDATETIMEOFFSET(),
        updated_at              DATETIMEOFFSET DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_subscriptions_user_id')
    CREATE INDEX idx_subscriptions_user_id ON subscriptions(user_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_subscriptions_stripe_customer_id')
    CREATE INDEX idx_subscriptions_stripe_customer_id ON subscriptions(stripe_customer_id);
GO

-- Migration: add billing_interval to existing deployments
IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('subscriptions') AND name = 'billing_interval')
    ALTER TABLE subscriptions ADD billing_interval NVARCHAR(50) NOT NULL DEFAULT 'monthly';
GO

-- =====================================================================
-- Scan Usage (monthly quota tracking per user)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'scan_usage')
BEGIN
    CREATE TABLE scan_usage (
        user_id     UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        year_month  CHAR(7) NOT NULL,  -- e.g. '2026-02'
        count       INT NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, year_month)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_scan_usage_user')
    CREATE INDEX idx_scan_usage_user ON scan_usage (user_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_scan_usage_month')
    CREATE INDEX idx_scan_usage_month ON scan_usage (year_month);
GO

-- =====================================================================
-- Public Scan Database (distribution layer)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'public_scans')
BEGIN
    CREATE TABLE public_scans (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        ecosystem       NVARCHAR(100) NOT NULL,        -- 'clawhub', 'pypi', 'npm', 'github', 'mcp'
        package_name    NVARCHAR(400) NOT NULL,
        package_version NVARCHAR(255) NOT NULL DEFAULT '',
        risk_score      FLOAT NOT NULL DEFAULT 0.0,
        verdict         NVARCHAR(50) NOT NULL DEFAULT 'LOW_RISK',
        findings_count  INT NOT NULL DEFAULT 0,
        files_scanned   INT NOT NULL DEFAULT 0,
        findings_json   NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        metadata_json   NVARCHAR(MAX) NOT NULL DEFAULT '{}',
        scanned_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        created_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT UQ_public_scans_ecosystem_package UNIQUE(ecosystem, package_name, package_version),
        CONSTRAINT CK_public_scans_findings_json CHECK (findings_json IS NULL OR ISJSON(findings_json) = 1),
        CONSTRAINT CK_public_scans_metadata_json CHECK (metadata_json IS NULL OR ISJSON(metadata_json) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_public_scans_ecosystem')
    CREATE INDEX idx_public_scans_ecosystem ON public_scans (ecosystem);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_public_scans_package')
    CREATE INDEX idx_public_scans_package ON public_scans (ecosystem, package_name);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_public_scans_verdict')
    CREATE INDEX idx_public_scans_verdict ON public_scans (verdict);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_public_scans_risk_score')
    CREATE INDEX idx_public_scans_risk_score ON public_scans (risk_score DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_public_scans_scanned_at')
    CREATE INDEX idx_public_scans_scanned_at ON public_scans (scanned_at DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_public_scans_ecosystem_verdict')
    CREATE INDEX idx_public_scans_ecosystem_verdict ON public_scans (ecosystem, verdict);
GO

-- =====================================================================
-- Badge Cache (avoid regenerating SVG on every request)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'badge_cache')
BEGIN
    CREATE TABLE badge_cache (
        ecosystem       NVARCHAR(100) NOT NULL,
        slug            NVARCHAR(400) NOT NULL,
        svg_content     NVARCHAR(MAX) NOT NULL,
        verdict         NVARCHAR(50) NOT NULL,
        cached_at       DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        PRIMARY KEY(ecosystem, slug)
    );
END
GO

-- =====================================================================
-- GitHub App — Installation tracking
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'github_installations')
BEGIN
    CREATE TABLE github_installations (
        id                    NVARCHAR(255) PRIMARY KEY,
        installation_id       INT NOT NULL UNIQUE,
        account_login         NVARCHAR(255) NOT NULL DEFAULT '',
        account_type          NVARCHAR(50) NOT NULL DEFAULT 'User',
        repository_selection  NVARCHAR(50) NOT NULL DEFAULT 'all',
        created_at            DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_gh_install_account')
    CREATE INDEX idx_gh_install_account ON github_installations (account_login);
GO

-- =====================================================================
-- GitHub App — PR scan events (queued for async processing)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'github_pr_events')
BEGIN
    CREATE TABLE github_pr_events (
        id              NVARCHAR(255) PRIMARY KEY,
        repo            NVARCHAR(400) NOT NULL,
        pr_number       INT NOT NULL,
        action          NVARCHAR(100) NOT NULL DEFAULT '',
        pr_title        NVARCHAR(MAX) NOT NULL DEFAULT '',
        pr_head_sha     NVARCHAR(64) NOT NULL DEFAULT '',
        installation_id INT NOT NULL DEFAULT 0,
        status          NVARCHAR(50) NOT NULL DEFAULT 'pending',
        comment_id      NVARCHAR(100),
        scan_results    NVARCHAR(MAX) DEFAULT '{}',
        created_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        processed_at    DATETIMEOFFSET,
        CONSTRAINT CK_github_pr_events_scan_results CHECK (scan_results IS NULL OR ISJSON(scan_results) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_gh_pr_repo')
    CREATE INDEX idx_gh_pr_repo ON github_pr_events (repo, pr_number);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_gh_pr_status')
    CREATE INDEX idx_gh_pr_status ON github_pr_events (status);
GO
