-- Migration 005: MCP Watchdog Tables
-- Creates tables for typosquat alerts and MCP server tracking

-- Table for storing typosquat detection alerts
CREATE TABLE IF NOT EXISTS typosquat_alerts (
    id VARCHAR(16) PRIMARY KEY,
    alert_type VARCHAR(50) NOT NULL DEFAULT 'typosquat',
    ecosystem VARCHAR(50) NOT NULL,
    suspicious_package VARCHAR(200) NOT NULL,
    target_package VARCHAR(200) NOT NULL,
    risk_level VARCHAR(20) NOT NULL, -- LOW, MEDIUM, HIGH
    metadata_json TEXT, -- JSON blob with edit_distance, similarity_score, etc.
    resolved BOOLEAN DEFAULT FALSE,
    created_at DATETIME NOT NULL,
    resolved_at DATETIME NULL,
    resolved_by VARCHAR(100) NULL
);

-- Index for efficient querying
CREATE INDEX idx_typosquat_alerts_ecosystem ON typosquat_alerts(ecosystem);
CREATE INDEX idx_typosquat_alerts_risk ON typosquat_alerts(risk_level);
CREATE INDEX idx_typosquat_alerts_created ON typosquat_alerts(created_at DESC);
CREATE INDEX idx_typosquat_alerts_unresolved ON typosquat_alerts(resolved) WHERE resolved = FALSE;

-- Table for tracking MCP server metadata and monitoring status
CREATE TABLE IF NOT EXISTS mcp_servers (
    id VARCHAR(16) PRIMARY KEY,
    repo_name VARCHAR(200) UNIQUE NOT NULL, -- e.g. "user/mcp-postgres"
    author VARCHAR(100) NOT NULL,
    description TEXT,
    stars INTEGER DEFAULT 0,
    forks INTEGER DEFAULT 0,
    language VARCHAR(50),
    topics TEXT, -- JSON array of topic strings
    homepage VARCHAR(500),
    clone_url VARCHAR(500),
    mcp_config TEXT, -- JSON blob of .mcp.json contents
    first_seen DATETIME NOT NULL,
    last_updated DATETIME NOT NULL,
    last_scanned DATETIME NULL,
    scan_status VARCHAR(50) DEFAULT 'pending', -- pending, scanning, scanned, error
    monitoring_enabled BOOLEAN DEFAULT TRUE,
    created_at DATETIME NOT NULL
);

-- Indexes for MCP server tracking
CREATE INDEX idx_mcp_servers_author ON mcp_servers(author);
CREATE INDEX idx_mcp_servers_last_updated ON mcp_servers(last_updated DESC);
CREATE INDEX idx_mcp_servers_scan_status ON mcp_servers(scan_status);
CREATE INDEX idx_mcp_servers_monitoring ON mcp_servers(monitoring_enabled) WHERE monitoring_enabled = TRUE;

-- Table for tracking popular MCP server names (for typosquat detection)
CREATE TABLE IF NOT EXISTS popular_mcp_names (
    id VARCHAR(16) PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    category VARCHAR(50), -- database, api, devops, etc.
    official_repo VARCHAR(200), -- canonical repository if known
    download_count INTEGER DEFAULT 0,
    added_at DATETIME NOT NULL,
    last_verified DATETIME
);

-- Insert initial popular MCP server names
INSERT OR IGNORE INTO popular_mcp_names (id, name, category, added_at) VALUES
    ('pop_mcp_postgres', 'mcp-postgres', 'database', datetime('now')),
    ('pop_mcp_mongodb', 'mcp-mongodb', 'database', datetime('now')),
    ('pop_mcp_redis', 'mcp-redis', 'database', datetime('now')),
    ('pop_mcp_mysql', 'mcp-mysql', 'database', datetime('now')),
    ('pop_mcp_sqlite', 'mcp-sqlite', 'database', datetime('now')),
    ('pop_mcp_github', 'mcp-github', 'api', datetime('now')),
    ('pop_mcp_gitlab', 'mcp-gitlab', 'api', datetime('now')),
    ('pop_mcp_jira', 'mcp-jira', 'api', datetime('now')),
    ('pop_mcp_slack', 'mcp-slack', 'communication', datetime('now')),
    ('pop_mcp_discord', 'mcp-discord', 'communication', datetime('now')),
    ('pop_mcp_stripe', 'mcp-stripe', 'payment', datetime('now')),
    ('pop_mcp_shopify', 'mcp-shopify', 'ecommerce', datetime('now')),
    ('pop_mcp_aws', 'mcp-aws', 'cloud', datetime('now')),
    ('pop_mcp_gcp', 'mcp-gcp', 'cloud', datetime('now')),
    ('pop_mcp_azure', 'mcp-azure', 'cloud', datetime('now')),
    ('pop_mcp_docker', 'mcp-docker', 'devops', datetime('now')),
    ('pop_mcp_kubernetes', 'mcp-kubernetes', 'devops', datetime('now')),
    ('pop_mcp_terraform', 'mcp-terraform', 'devops', datetime('now')),
    ('pop_mcp_ansible', 'mcp-ansible', 'devops', datetime('now')),
    ('pop_mcp_jupyter', 'mcp-jupyter', 'development', datetime('now')),
    ('pop_mcp_vscode', 'mcp-vscode', 'development', datetime('now')),
    ('pop_mcp_obsidian', 'mcp-obsidian', 'productivity', datetime('now')),
    ('pop_mcp_notion', 'mcp-notion', 'productivity', datetime('now'));

-- Table for MCP watchdog configuration and statistics
CREATE TABLE IF NOT EXISTS mcp_watchdog_config (
    id VARCHAR(16) PRIMARY KEY,
    enabled BOOLEAN DEFAULT TRUE,
    scan_interval_hours INTEGER DEFAULT 12, -- How often to scan for new MCPs
    typosquat_threshold REAL DEFAULT 0.7, -- Similarity threshold for alerts
    max_alerts_per_hour INTEGER DEFAULT 10, -- Rate limiting for alerts
    last_discovery_run DATETIME,
    last_typosquat_check DATETIME,
    total_servers_discovered INTEGER DEFAULT 0,
    total_alerts_sent INTEGER DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

-- Insert default configuration
INSERT OR IGNORE INTO mcp_watchdog_config (
    id, enabled, scan_interval_hours, typosquat_threshold, 
    max_alerts_per_hour, created_at, updated_at
) VALUES (
    'default_config', TRUE, 12, 0.7, 10, 
    datetime('now'), datetime('now')
);