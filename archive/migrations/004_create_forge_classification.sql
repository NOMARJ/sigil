-- Migration: Create Forge Classification Tables
-- Database: Azure SQL Database (T-SQL)
-- Date: 2026-03-03
--
-- Purpose: Enable Sigil Forge classification system for skills and MCPs
--
-- Tables:
--   - forge_classification: Classification data for each package
--   - forge_capabilities: Capability tags for packages
--   - forge_matches: Compatible tool pairings
--
-- This migration supports the Sigil Forge product as defined in
-- docs/internal/skills-x-mcps-product-opportunities.md

-- =====================================================================
-- Forge Classification — Main classification data for each package
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_classification')
BEGIN
    CREATE TABLE forge_classification (
        id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        ecosystem           NVARCHAR(100) NOT NULL,        -- 'clawhub', 'mcp', 'npm', 'pypi'
        package_name        NVARCHAR(400) NOT NULL,
        package_version     NVARCHAR(255) NOT NULL DEFAULT '',
        category            NVARCHAR(100) NOT NULL,        -- Primary category (Database, API Integration, etc.)
        subcategory         NVARCHAR(100) NOT NULL DEFAULT '', -- Secondary category
        confidence_score    FLOAT NOT NULL DEFAULT 0.0,    -- Classification confidence 0.0-1.0
        description_summary NVARCHAR(MAX) NOT NULL DEFAULT '', -- Cleaned/summarized description
        environment_vars    NVARCHAR(MAX) NOT NULL DEFAULT '[]', -- JSON array of env var patterns
        network_protocols   NVARCHAR(MAX) NOT NULL DEFAULT '[]', -- JSON array of protocols (HTTP, WebSocket, etc.)
        file_patterns       NVARCHAR(MAX) NOT NULL DEFAULT '[]', -- JSON array of file types accessed
        import_patterns     NVARCHAR(MAX) NOT NULL DEFAULT '[]', -- JSON array of key imports/dependencies
        risk_indicators     NVARCHAR(MAX) NOT NULL DEFAULT '[]', -- JSON array of risk patterns from scan
        classified_at       DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at          DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        classifier_version  NVARCHAR(50) NOT NULL DEFAULT 'v1.0',
        metadata_json       NVARCHAR(MAX) NOT NULL DEFAULT '{}', -- Additional classification metadata
        CONSTRAINT UQ_forge_classification_package UNIQUE(ecosystem, package_name, package_version),
        CONSTRAINT CK_forge_classification_environment_vars CHECK (environment_vars IS NULL OR ISJSON(environment_vars) = 1),
        CONSTRAINT CK_forge_classification_network_protocols CHECK (network_protocols IS NULL OR ISJSON(network_protocols) = 1),
        CONSTRAINT CK_forge_classification_file_patterns CHECK (file_patterns IS NULL OR ISJSON(file_patterns) = 1),
        CONSTRAINT CK_forge_classification_import_patterns CHECK (import_patterns IS NULL OR ISJSON(import_patterns) = 1),
        CONSTRAINT CK_forge_classification_risk_indicators CHECK (risk_indicators IS NULL OR ISJSON(risk_indicators) = 1),
        CONSTRAINT CK_forge_classification_metadata_json CHECK (metadata_json IS NULL OR ISJSON(metadata_json) = 1)
    );
    PRINT 'Created table: forge_classification';
END
ELSE
BEGIN
    PRINT 'Table forge_classification already exists, skipping.';
END;
GO

-- Indexes for forge_classification
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_classification_ecosystem')
    CREATE INDEX idx_forge_classification_ecosystem ON forge_classification (ecosystem);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_classification_package')
    CREATE INDEX idx_forge_classification_package ON forge_classification (ecosystem, package_name);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_classification_category')
    CREATE INDEX idx_forge_classification_category ON forge_classification (category);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_classification_subcategory')
    CREATE INDEX idx_forge_classification_subcategory ON forge_classification (category, subcategory);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_classification_confidence')
    CREATE INDEX idx_forge_classification_confidence ON forge_classification (confidence_score DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_classification_updated')
    CREATE INDEX idx_forge_classification_updated ON forge_classification (updated_at DESC);
GO

-- =====================================================================
-- Forge Capabilities — Capability tags for packages
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_capabilities')
BEGIN
    CREATE TABLE forge_capabilities (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        classification_id UNIQUEIDENTIFIER NOT NULL REFERENCES forge_classification(id) ON DELETE CASCADE,
        capability      NVARCHAR(100) NOT NULL,        -- 'reads_files', 'makes_network_calls', etc.
        confidence      FLOAT NOT NULL DEFAULT 1.0,    -- Confidence in this capability detection
        evidence        NVARCHAR(MAX) NOT NULL DEFAULT '', -- Evidence from scan that supports this capability
        created_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
    PRINT 'Created table: forge_capabilities';
END
ELSE
BEGIN
    PRINT 'Table forge_capabilities already exists, skipping.';
END;
GO

-- Indexes for forge_capabilities
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_capabilities_classification')
    CREATE INDEX idx_forge_capabilities_classification ON forge_capabilities (classification_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_capabilities_capability')
    CREATE INDEX idx_forge_capabilities_capability ON forge_capabilities (capability);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_capabilities_confidence')
    CREATE INDEX idx_forge_capabilities_confidence ON forge_capabilities (capability, confidence DESC);
GO

-- =====================================================================
-- Forge Matches — Compatible tool pairings
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_matches')
BEGIN
    CREATE TABLE forge_matches (
        id                      UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        primary_classification_id UNIQUEIDENTIFIER NOT NULL REFERENCES forge_classification(id) ON DELETE CASCADE,
        secondary_classification_id UNIQUEIDENTIFIER NOT NULL REFERENCES forge_classification(id) ON DELETE NO ACTION,
        match_type              NVARCHAR(50) NOT NULL,      -- 'env_vars', 'protocols', 'complementary', 'category'
        compatibility_score     FLOAT NOT NULL DEFAULT 0.0, -- How well they work together (0.0-1.0)
        shared_elements         NVARCHAR(MAX) NOT NULL DEFAULT '[]', -- JSON array of shared env vars, protocols, etc.
        match_reason            NVARCHAR(MAX) NOT NULL DEFAULT '', -- Human-readable explanation
        trust_score_combined    FLOAT NOT NULL DEFAULT 0.0, -- Combined trust score from Sigil scans
        created_at              DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at              DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT CK_forge_matches_shared_elements CHECK (shared_elements IS NULL OR ISJSON(shared_elements) = 1),
        CONSTRAINT CK_forge_matches_different_packages CHECK (primary_classification_id != secondary_classification_id)
    );
    PRINT 'Created table: forge_matches';
END
ELSE
BEGIN
    PRINT 'Table forge_matches already exists, skipping.';
END;
GO

-- Indexes for forge_matches
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_matches_primary')
    CREATE INDEX idx_forge_matches_primary ON forge_matches (primary_classification_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_matches_secondary')
    CREATE INDEX idx_forge_matches_secondary ON forge_matches (secondary_classification_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_matches_type')
    CREATE INDEX idx_forge_matches_type ON forge_matches (match_type);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_matches_compatibility')
    CREATE INDEX idx_forge_matches_compatibility ON forge_matches (compatibility_score DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_matches_trust')
    CREATE INDEX idx_forge_matches_trust ON forge_matches (trust_score_combined DESC);
GO

-- Composite index for finding matches for a specific package
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_matches_primary_compatibility')
    CREATE INDEX idx_forge_matches_primary_compatibility ON forge_matches (primary_classification_id, compatibility_score DESC);
GO

-- =====================================================================
-- Forge Categories — Predefined category taxonomy
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_categories')
BEGIN
    CREATE TABLE forge_categories (
        id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        category        NVARCHAR(100) NOT NULL UNIQUE,
        display_name    NVARCHAR(200) NOT NULL,
        description     NVARCHAR(MAX) NOT NULL DEFAULT '',
        parent_category NVARCHAR(100),                 -- For hierarchical categories
        sort_order      INT NOT NULL DEFAULT 0,
        is_active       BIT NOT NULL DEFAULT 1,
        created_at      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
    );
    PRINT 'Created table: forge_categories';
END
ELSE
BEGIN
    PRINT 'Table forge_categories already exists, skipping.';
END;
GO

-- Indexes for forge_categories
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_categories_category')
    CREATE UNIQUE INDEX idx_forge_categories_category ON forge_categories (category);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_categories_parent')
    CREATE INDEX idx_forge_categories_parent ON forge_categories (parent_category);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_categories_active')
    CREATE INDEX idx_forge_categories_active ON forge_categories (is_active, sort_order);
GO

-- =====================================================================
-- Insert predefined categories based on the specification
-- =====================================================================

-- Insert main categories if not exists
INSERT INTO forge_categories (category, display_name, description, sort_order) 
SELECT 'Database', 'Database', 'Database connectors and management tools (Postgres, MongoDB, Redis, MySQL)', 10
WHERE NOT EXISTS (SELECT 1 FROM forge_categories WHERE category = 'Database');

INSERT INTO forge_categories (category, display_name, description, sort_order) 
SELECT 'API Integration', 'API Integration', 'Third-party API integrations (Stripe, GitHub, Slack, REST APIs)', 20
WHERE NOT EXISTS (SELECT 1 FROM forge_categories WHERE category = 'API Integration');

INSERT INTO forge_categories (category, display_name, description, sort_order) 
SELECT 'Code Tools', 'Code Tools', 'Development tools (linting, testing, formatting, compilation)', 30
WHERE NOT EXISTS (SELECT 1 FROM forge_categories WHERE category = 'Code Tools');

INSERT INTO forge_categories (category, display_name, description, sort_order) 
SELECT 'File System', 'File & System', 'File system operations, search, git, file processing', 40
WHERE NOT EXISTS (SELECT 1 FROM forge_categories WHERE category = 'File System');

INSERT INTO forge_categories (category, display_name, description, sort_order) 
SELECT 'AI/LLM', 'AI & LLM', 'AI tools (prompt engineering, RAG, embeddings, model operations)', 50
WHERE NOT EXISTS (SELECT 1 FROM forge_categories WHERE category = 'AI/LLM');

INSERT INTO forge_categories (category, display_name, description, sort_order) 
SELECT 'Security', 'Security', 'Security tools (scanning, secrets management, authentication)', 60
WHERE NOT EXISTS (SELECT 1 FROM forge_categories WHERE category = 'Security');

INSERT INTO forge_categories (category, display_name, description, sort_order) 
SELECT 'DevOps', 'DevOps', 'CI/CD, monitoring, deployment, infrastructure tools', 70
WHERE NOT EXISTS (SELECT 1 FROM forge_categories WHERE category = 'DevOps');

INSERT INTO forge_categories (category, display_name, description, sort_order) 
SELECT 'Communication', 'Communication', 'Email, chat, notifications, messaging', 80
WHERE NOT EXISTS (SELECT 1 FROM forge_categories WHERE category = 'Communication');

INSERT INTO forge_categories (category, display_name, description, sort_order) 
SELECT 'Data Pipeline', 'Data Pipeline', 'ETL, data transformation, analytics', 90
WHERE NOT EXISTS (SELECT 1 FROM forge_categories WHERE category = 'Data Pipeline');

INSERT INTO forge_categories (category, display_name, description, sort_order) 
SELECT 'Testing', 'Testing', 'Unit tests, integration tests, QA automation', 100
WHERE NOT EXISTS (SELECT 1 FROM forge_categories WHERE category = 'Testing');

INSERT INTO forge_categories (category, display_name, description, sort_order) 
SELECT 'Search', 'Search', 'Web search, document search, indexing', 110
WHERE NOT EXISTS (SELECT 1 FROM forge_categories WHERE category = 'Search');

INSERT INTO forge_categories (category, display_name, description, sort_order) 
SELECT 'Monitoring', 'Monitoring', 'Application monitoring, logging, metrics', 120
WHERE NOT EXISTS (SELECT 1 FROM forge_categories WHERE category = 'Monitoring');

INSERT INTO forge_categories (category, display_name, description, sort_order) 
SELECT 'Uncategorized', 'Uncategorized', 'Tools that do not fit other categories', 999
WHERE NOT EXISTS (SELECT 1 FROM forge_categories WHERE category = 'Uncategorized');

GO

-- Migration complete
PRINT 'Migration 004_create_forge_classification.sql completed successfully.';
GO