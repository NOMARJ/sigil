-- Sigil Forge Database Schema
-- Adds classification and curation tables to existing Sigil database

-- ============================================================================
-- FORGE CLASSIFICATION TABLES
-- ============================================================================

-- Core classification of skills and MCP servers
CREATE TABLE forge_classification (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    package_name NVARCHAR(255) NOT NULL,
    ecosystem NVARCHAR(50) NOT NULL, -- 'skills', 'mcp', 'npm', 'pypi'
    package_hash NVARCHAR(64), -- Link to existing scan data
    
    -- Classification results
    primary_category NVARCHAR(100) NOT NULL,
    secondary_categories NVARCHAR(MAX), -- JSON array
    capability_tags NVARCHAR(MAX), -- JSON array: ["reads_files", "network_calls"]
    
    -- Compatibility signals
    env_vars_required NVARCHAR(MAX), -- JSON array: ["DATABASE_URL", "API_KEY"]
    protocols_supported NVARCHAR(MAX), -- JSON array: ["http", "postgres", "redis"]
    runtime_requirements NVARCHAR(MAX), -- JSON array: ["python", "node", "docker"]
    
    -- Classification metadata
    classified_at DATETIME2 DEFAULT GETDATE(),
    classifier_version NVARCHAR(50) DEFAULT '1.0',
    confidence_score DECIMAL(3,2), -- 0.00 to 1.00
    manual_override BIT DEFAULT 0,
    
    -- Indexing
    INDEX IX_forge_classification_ecosystem_category (ecosystem, primary_category),
    INDEX IX_forge_classification_package (package_name, ecosystem),
    INDEX IX_forge_classification_hash (package_hash),
    UNIQUE (package_name, ecosystem)
);

-- Pre-computed compatible stacks (skill + MCP combinations)
CREATE TABLE forge_stacks (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    stack_name NVARCHAR(255) NOT NULL,
    use_case_description NVARCHAR(500) NOT NULL,
    
    -- Stack components
    skills NVARCHAR(MAX) NOT NULL, -- JSON array of skill names
    mcps NVARCHAR(MAX) NOT NULL, -- JSON array of MCP server names
    
    -- Compatibility metadata
    shared_env_vars NVARCHAR(MAX), -- JSON array of common env vars
    shared_protocols NVARCHAR(MAX), -- JSON array of common protocols
    trust_score_avg DECIMAL(5,2), -- Average Sigil trust score
    
    -- Curation metadata
    curated BIT DEFAULT 0, -- Hand-picked by team
    featured BIT DEFAULT 0, -- Promoted on homepage
    popularity_score INTEGER DEFAULT 0, -- Usage/download tracking
    
    created_at DATETIME2 DEFAULT GETDATE(),
    updated_at DATETIME2 DEFAULT GETDATE(),
    
    INDEX IX_forge_stacks_use_case (use_case_description),
    INDEX IX_forge_stacks_featured (featured, trust_score_avg),
    UNIQUE (stack_name)
);

-- Track which packages are used together (for recommendation engine)
CREATE TABLE forge_usage_patterns (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    package_a NVARCHAR(255) NOT NULL,
    package_b NVARCHAR(255) NOT NULL,
    ecosystem_a NVARCHAR(50) NOT NULL,
    ecosystem_b NVARCHAR(50) NOT NULL,
    
    co_occurrence_count INTEGER DEFAULT 1,
    last_seen DATETIME2 DEFAULT GETDATE(),
    
    INDEX IX_forge_usage_patterns_package_a (package_a, ecosystem_a),
    UNIQUE (package_a, package_b, ecosystem_a, ecosystem_b)
);

-- ============================================================================
-- FORGE CURATION TABLES  
-- ============================================================================

-- Categories and their definitions
CREATE TABLE forge_categories (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    category_name NVARCHAR(100) NOT NULL UNIQUE,
    category_slug NVARCHAR(100) NOT NULL UNIQUE,
    description NVARCHAR(500),
    icon NVARCHAR(50), -- Icon identifier for UI
    
    -- Ordering and visibility
    display_order INTEGER DEFAULT 0,
    visible BIT DEFAULT 1,
    
    created_at DATETIME2 DEFAULT GETDATE()
);

-- Featured/promoted packages by category
CREATE TABLE forge_featured (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    package_name NVARCHAR(255) NOT NULL,
    ecosystem NVARCHAR(50) NOT NULL,
    category_id BIGINT NOT NULL,
    
    -- Feature details
    feature_type NVARCHAR(50) NOT NULL, -- 'homepage', 'category', 'weekly'
    featured_until DATETIME2, -- NULL = permanent
    sort_order INTEGER DEFAULT 0,
    
    created_at DATETIME2 DEFAULT GETDATE(),
    
    FOREIGN KEY (category_id) REFERENCES forge_categories(id),
    INDEX IX_forge_featured_type_category (feature_type, category_id),
    UNIQUE (package_name, ecosystem, feature_type, category_id)
);

-- Publisher engagement tracking (for badge/featured listing revenue)
CREATE TABLE forge_publisher_subscriptions (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    publisher_name NVARCHAR(255) NOT NULL,
    ecosystem NVARCHAR(50) NOT NULL,
    
    -- Subscription details
    subscription_type NVARCHAR(50) NOT NULL, -- 'featured', 'badge', 'verified'
    monthly_fee DECIMAL(10,2) NOT NULL,
    active BIT DEFAULT 1,
    
    -- Billing
    stripe_subscription_id NVARCHAR(255),
    billing_cycle_start DATE,
    billing_cycle_end DATE,
    
    created_at DATETIME2 DEFAULT GETDATE(),
    
    INDEX IX_forge_publisher_subscriptions_active (active, subscription_type),
    UNIQUE (publisher_name, ecosystem, subscription_type)
);

-- ============================================================================
-- FORGE ANALYTICS TABLES
-- ============================================================================

-- Track API usage for agent consumption patterns
CREATE TABLE forge_api_usage (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    endpoint NVARCHAR(255) NOT NULL, -- '/api/search', '/api/stacks', etc.
    user_agent NVARCHAR(500), -- Track agent vs human usage
    ip_address NVARCHAR(45), -- IPv4/IPv6 support
    
    -- Request details
    query_params NVARCHAR(MAX), -- JSON of query parameters
    response_time_ms INTEGER,
    status_code INTEGER,
    
    -- Classification
    request_type NVARCHAR(50), -- 'human', 'agent', 'bot', 'unknown'
    
    created_at DATETIME2 DEFAULT GETDATE(),
    
    INDEX IX_forge_api_usage_endpoint_date (endpoint, created_at),
    INDEX IX_forge_api_usage_request_type (request_type, created_at)
);

-- Track package discovery patterns (for recommendation improvements)
CREATE TABLE forge_discovery_events (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    session_id NVARCHAR(255), -- Track user session
    
    -- Discovery details
    search_query NVARCHAR(500),
    package_viewed NVARCHAR(255),
    ecosystem NVARCHAR(50),
    action_taken NVARCHAR(50), -- 'viewed', 'copied', 'installed', 'shared'
    
    -- Context
    referrer NVARCHAR(500),
    user_agent NVARCHAR(500),
    
    created_at DATETIME2 DEFAULT GETDATE(),
    
    INDEX IX_forge_discovery_events_session (session_id, created_at),
    INDEX IX_forge_discovery_events_package (package_viewed, ecosystem)
);

-- ============================================================================
-- INITIAL DATA SEEDS
-- ============================================================================

-- Pre-populate core categories
INSERT INTO forge_categories (category_name, category_slug, description, display_order) VALUES
('Database Connectors', 'database', 'Connect to SQL and NoSQL databases', 1),
('API Integrations', 'api', 'Third-party service integrations', 2),
('Code Tools', 'code', 'Linting, testing, formatting utilities', 3),
('File/System Tools', 'filesystem', 'File operations and system access', 4),
('AI/LLM Tools', 'ai-llm', 'LLM orchestration and prompt engineering', 5),
('Security Tools', 'security', 'Scanning, secrets management, auth', 6),
('DevOps Tools', 'devops', 'CI/CD, deployment, infrastructure', 7),
('Search Tools', 'search', 'Web search, document indexing', 8),
('Communication', 'communication', 'Email, Slack, messaging platforms', 9),
('Data Pipeline', 'data', 'ETL, data processing, analytics', 10),
('Testing Tools', 'testing', 'Unit tests, integration tests, mocks', 11),
('Monitoring', 'monitoring', 'Logging, metrics, alerting', 12);

-- Add constraints and indexes after data population
ALTER TABLE forge_classification 
    ADD CONSTRAINT FK_forge_classification_scan 
    FOREIGN KEY (package_hash) REFERENCES scan_results(id);