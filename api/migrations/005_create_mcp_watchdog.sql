-- Migration 005: MCP Watchdog Tables
-- Creates tables for typosquat alerts and MCP server tracking

-- Table for storing typosquat detection alerts
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'typosquat_alerts')
BEGIN
    CREATE TABLE typosquat_alerts (
        id NVARCHAR(16) PRIMARY KEY,
        alert_type NVARCHAR(50) NOT NULL DEFAULT 'typosquat',
        ecosystem NVARCHAR(50) NOT NULL,
        suspicious_package NVARCHAR(200) NOT NULL,
        target_package NVARCHAR(200) NOT NULL,
        risk_level NVARCHAR(20) NOT NULL, -- LOW, MEDIUM, HIGH
        metadata_json NVARCHAR(MAX) NULL, -- JSON blob with edit_distance, similarity_score, etc.
        resolved BIT NOT NULL DEFAULT 0,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        resolved_at DATETIMEOFFSET NULL,
        resolved_by NVARCHAR(100) NULL,
        CONSTRAINT CK_typosquat_alerts_metadata_json CHECK (metadata_json IS NULL OR ISJSON(metadata_json) = 1)
    );
END
GO

-- Index for efficient querying
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_typosquat_alerts_ecosystem')
    CREATE INDEX idx_typosquat_alerts_ecosystem ON typosquat_alerts(ecosystem);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_typosquat_alerts_risk')
    CREATE INDEX idx_typosquat_alerts_risk ON typosquat_alerts(risk_level);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_typosquat_alerts_created')
    CREATE INDEX idx_typosquat_alerts_created ON typosquat_alerts(created_at DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_typosquat_alerts_unresolved')
    CREATE INDEX idx_typosquat_alerts_unresolved ON typosquat_alerts(resolved) WHERE resolved = 0;
GO

-- Table for tracking MCP server metadata and monitoring status
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'mcp_servers')
BEGIN
    CREATE TABLE mcp_servers (
        id NVARCHAR(16) PRIMARY KEY,
        repo_name NVARCHAR(200) NOT NULL, -- e.g. "user/mcp-postgres"
        author NVARCHAR(100) NOT NULL,
        description NVARCHAR(MAX) NULL,
        stars INT NOT NULL DEFAULT 0,
        forks INT NOT NULL DEFAULT 0,
        language NVARCHAR(50) NULL,
        topics NVARCHAR(MAX) NULL, -- JSON array of topic strings
        homepage NVARCHAR(500) NULL,
        clone_url NVARCHAR(500) NULL,
        mcp_config NVARCHAR(MAX) NULL, -- JSON blob of .mcp.json contents
        first_seen DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        last_updated DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        last_scanned DATETIMEOFFSET NULL,
        scan_status NVARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, scanning, scanned, error
        monitoring_enabled BIT NOT NULL DEFAULT 1,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT UQ_mcp_servers_repo_name UNIQUE (repo_name),
        CONSTRAINT CK_mcp_servers_topics_json CHECK (topics IS NULL OR ISJSON(topics) = 1),
        CONSTRAINT CK_mcp_servers_mcp_config_json CHECK (mcp_config IS NULL OR ISJSON(mcp_config) = 1)
    );
END
GO

-- Indexes for MCP server tracking
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_mcp_servers_author')
    CREATE INDEX idx_mcp_servers_author ON mcp_servers(author);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_mcp_servers_last_updated')
    CREATE INDEX idx_mcp_servers_last_updated ON mcp_servers(last_updated DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_mcp_servers_scan_status')
    CREATE INDEX idx_mcp_servers_scan_status ON mcp_servers(scan_status);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_mcp_servers_monitoring')
    CREATE INDEX idx_mcp_servers_monitoring ON mcp_servers(monitoring_enabled) WHERE monitoring_enabled = 1;
GO

-- Table for tracking popular MCP server names (for typosquat detection)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'popular_mcp_names')
BEGIN
    CREATE TABLE popular_mcp_names (
        id NVARCHAR(32) PRIMARY KEY,
        name NVARCHAR(100) NOT NULL,
        category NVARCHAR(50) NULL, -- database, api, devops, etc.
        official_repo NVARCHAR(200) NULL, -- canonical repository if known
        download_count INT NOT NULL DEFAULT 0,
        added_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        last_verified DATETIMEOFFSET NULL,
        CONSTRAINT UQ_popular_mcp_names_name UNIQUE (name)
    );
END
GO

-- Insert initial popular MCP server names
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-postgres')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_postgres', 'mcp-postgres', 'database', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-mongodb')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_mongodb', 'mcp-mongodb', 'database', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-redis')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_redis', 'mcp-redis', 'database', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-mysql')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_mysql', 'mcp-mysql', 'database', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-sqlite')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_sqlite', 'mcp-sqlite', 'database', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-github')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_github', 'mcp-github', 'api', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-gitlab')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_gitlab', 'mcp-gitlab', 'api', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-jira')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_jira', 'mcp-jira', 'api', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-slack')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_slack', 'mcp-slack', 'communication', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-discord')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_discord', 'mcp-discord', 'communication', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-stripe')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_stripe', 'mcp-stripe', 'payment', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-shopify')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_shopify', 'mcp-shopify', 'ecommerce', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-aws')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_aws', 'mcp-aws', 'cloud', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-gcp')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_gcp', 'mcp-gcp', 'cloud', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-azure')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_azure', 'mcp-azure', 'cloud', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-docker')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_docker', 'mcp-docker', 'devops', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-kubernetes')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_kubernetes', 'mcp-kubernetes', 'devops', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-terraform')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_terraform', 'mcp-terraform', 'devops', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-ansible')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_ansible', 'mcp-ansible', 'devops', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-jupyter')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_jupyter', 'mcp-jupyter', 'development', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-vscode')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_vscode', 'mcp-vscode', 'development', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-obsidian')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_obsidian', 'mcp-obsidian', 'productivity', SYSDATETIMEOFFSET());
IF NOT EXISTS (SELECT 1 FROM popular_mcp_names WHERE name = 'mcp-notion')
    INSERT INTO popular_mcp_names (id, name, category, added_at) VALUES ('pop_mcp_notion', 'mcp-notion', 'productivity', SYSDATETIMEOFFSET());
GO

-- Table for MCP watchdog configuration and statistics
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'mcp_watchdog_config')
BEGIN
    CREATE TABLE mcp_watchdog_config (
        id NVARCHAR(32) PRIMARY KEY,
        enabled BIT NOT NULL DEFAULT 1,
        scan_interval_hours INT NOT NULL DEFAULT 12, -- How often to scan for new MCPs
        typosquat_threshold FLOAT NOT NULL DEFAULT 0.7, -- Similarity threshold for alerts
        max_alerts_per_hour INT NOT NULL DEFAULT 10, -- Rate limiting for alerts
        last_discovery_run DATETIMEOFFSET NULL,
        last_typosquat_check DATETIMEOFFSET NULL,
        total_servers_discovered INT NOT NULL DEFAULT 0,
        total_alerts_sent INT NOT NULL DEFAULT 0,
        created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

-- Insert default configuration
IF NOT EXISTS (SELECT 1 FROM mcp_watchdog_config WHERE id = 'default_config')
BEGIN
    INSERT INTO mcp_watchdog_config (
        id, enabled, scan_interval_hours, typosquat_threshold,
        max_alerts_per_hour, created_at, updated_at
    ) VALUES (
        'default_config', 1, 12, 0.7, 10,
        SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET()
    );
END
GO

PRINT 'Migration 005_create_mcp_watchdog applied successfully.';
GO