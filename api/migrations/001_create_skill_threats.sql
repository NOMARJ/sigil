-- Migration: Add skill_threats table for AI skill security (T-SQL)
-- Description: VirusTotal-style hash-based threat intelligence for AI skills/agents
-- Created: 2026-02-20
-- Related: OpenClaw attack lessons, Phase 7-8 detection

-- =====================================================================
-- Skill Threats (AI skill threat intelligence database)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'skill_threats')
BEGIN
    CREATE TABLE skill_threats (
        id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        hash                NVARCHAR(64) NOT NULL UNIQUE,
        skill_name          NVARCHAR(255) NOT NULL,
        skill_author        NVARCHAR(255),
        skill_type          NVARCHAR(50) NOT NULL DEFAULT 'unknown',  -- 'claude-skill', 'mcp-server', 'langchain-tool', 'openclaw-skill'
        skill_version       NVARCHAR(128) NOT NULL DEFAULT '',

        -- Threat classification
        threat_level        NVARCHAR(20) NOT NULL DEFAULT 'unknown',  -- 'benign', 'suspicious', 'malicious'
        detection_count     INT NOT NULL DEFAULT 1,
        classifications     NVARCHAR(MAX) NOT NULL DEFAULT '[]',      -- ["prompt-injection", "tool-abuse", "credential-theft"]

        -- Evidence and analysis
        evidence            NVARCHAR(MAX) NOT NULL DEFAULT '',
        attack_patterns     NVARCHAR(MAX) NOT NULL DEFAULT '[]',      -- JSON array of pattern IDs
        risk_score          FLOAT NOT NULL DEFAULT 0.0,

        -- Community feedback
        community_votes     NVARCHAR(MAX) NOT NULL DEFAULT '{"malicious": 0, "suspicious": 0, "benign": 0}',

        -- Related threats
        similar_hashes      NVARCHAR(MAX) NOT NULL DEFAULT '[]',      -- JSON array of hashes
        campaign_id         NVARCHAR(128),                            -- Group related attacks (e.g., "openclaw-hightower6eu")

        -- Metadata
        first_seen          DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        last_seen           DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        created_at          DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at          DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),

        CONSTRAINT CK_skill_threats_classifications CHECK (classifications IS NULL OR ISJSON(classifications) = 1),
        CONSTRAINT CK_skill_threats_attack_patterns CHECK (attack_patterns IS NULL OR ISJSON(attack_patterns) = 1),
        CONSTRAINT CK_skill_threats_community_votes CHECK (community_votes IS NULL OR ISJSON(community_votes) = 1),
        CONSTRAINT CK_skill_threats_similar_hashes CHECK (similar_hashes IS NULL OR ISJSON(similar_hashes) = 1)
    );
END
GO

-- Indexes for fast lookups
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_threats_hash')
    CREATE UNIQUE INDEX idx_skill_threats_hash ON skill_threats(hash);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_threats_name')
    CREATE INDEX idx_skill_threats_name ON skill_threats(skill_name);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_threats_author')
    CREATE INDEX idx_skill_threats_author ON skill_threats(skill_author);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_threats_type')
    CREATE INDEX idx_skill_threats_type ON skill_threats(skill_type);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_threats_level')
    CREATE INDEX idx_skill_threats_level ON skill_threats(threat_level);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_threats_campaign')
    CREATE INDEX idx_skill_threats_campaign ON skill_threats(campaign_id) WHERE campaign_id IS NOT NULL;
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_threats_risk')
    CREATE INDEX idx_skill_threats_risk ON skill_threats(risk_score DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_threats_detections')
    CREATE INDEX idx_skill_threats_detections ON skill_threats(detection_count DESC);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_threats_first_seen')
    CREATE INDEX idx_skill_threats_first_seen ON skill_threats(first_seen DESC);
GO

-- Composite index for dashboard queries (threat level + detection count)
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_threats_level_detections')
    CREATE INDEX idx_skill_threats_level_detections ON skill_threats(threat_level, detection_count DESC);
GO

-- =====================================================================
-- Skill Scan History (track individual scans for analytics)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'skill_scans')
BEGIN
    CREATE TABLE skill_scans (
        id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        skill_threat_id     UNIQUEIDENTIFIER REFERENCES skill_threats(id) ON DELETE CASCADE,
        hash                NVARCHAR(64) NOT NULL,
        user_id             UNIQUEIDENTIFIER REFERENCES users(id) ON DELETE SET NULL,
        team_id             UNIQUEIDENTIFIER REFERENCES teams(id) ON DELETE SET NULL,

        -- Scan results
        verdict             NVARCHAR(50) NOT NULL DEFAULT 'LOW_RISK',
        risk_score          FLOAT NOT NULL DEFAULT 0.0,
        findings_count      INT NOT NULL DEFAULT 0,
        findings_json       NVARCHAR(MAX) NOT NULL DEFAULT '[]',

        -- Context
        source              NVARCHAR(100) NOT NULL DEFAULT 'cli',    -- 'cli', 'api', 'github-action', 'vscode'
        metadata_json       NVARCHAR(MAX) NOT NULL DEFAULT '{}',

        -- Timestamps
        scanned_at          DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),

        CONSTRAINT CK_skill_scans_findings_json CHECK (findings_json IS NULL OR ISJSON(findings_json) = 1),
        CONSTRAINT CK_skill_scans_metadata_json CHECK (metadata_json IS NULL OR ISJSON(metadata_json) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_scans_threat')
    CREATE INDEX idx_skill_scans_threat ON skill_scans(skill_threat_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_scans_hash')
    CREATE INDEX idx_skill_scans_hash ON skill_scans(hash);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_scans_user')
    CREATE INDEX idx_skill_scans_user ON skill_scans(user_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_scans_team')
    CREATE INDEX idx_skill_scans_team ON skill_scans(team_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_scans_verdict')
    CREATE INDEX idx_skill_scans_verdict ON skill_scans(verdict);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_skill_scans_date')
    CREATE INDEX idx_skill_scans_date ON skill_scans(scanned_at DESC);
GO

-- =====================================================================
-- Publisher Campaigns (track coordinated attack campaigns)
-- =====================================================================

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'publisher_campaigns')
BEGIN
    CREATE TABLE publisher_campaigns (
        id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        campaign_id         NVARCHAR(128) NOT NULL UNIQUE,
        name                NVARCHAR(255) NOT NULL,                   -- 'OpenClaw hightower6eu Campaign'

        -- Campaign details
        publisher_ids       NVARCHAR(MAX) NOT NULL DEFAULT '[]',      -- JSON array: ['hightower6eu', 'related-actor']
        skill_count         INT NOT NULL DEFAULT 0,
        infected_count      INT NOT NULL DEFAULT 0,              -- Estimated infections

        -- Timeline
        first_detected      DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        last_activity       DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        [status]            NVARCHAR(50) NOT NULL DEFAULT 'active',   -- 'active', 'contained', 'resolved'

        -- Attack characteristics
        attack_patterns     NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        payload_types       NVARCHAR(MAX) NOT NULL DEFAULT '[]',      -- JSON array: ['atomic-stealer', 'packed-trojan']

        -- Metadata
        description         NVARCHAR(MAX) NOT NULL DEFAULT '',
        remediation         NVARCHAR(MAX) NOT NULL DEFAULT '',
        [references]        NVARCHAR(MAX) NOT NULL DEFAULT '[]',      -- JSON array of URLs

        created_at          DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
        updated_at          DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),

        CONSTRAINT CK_publisher_campaigns_publisher_ids CHECK (publisher_ids IS NULL OR ISJSON(publisher_ids) = 1),
        CONSTRAINT CK_publisher_campaigns_attack_patterns CHECK (attack_patterns IS NULL OR ISJSON(attack_patterns) = 1),
        CONSTRAINT CK_publisher_campaigns_payload_types CHECK (payload_types IS NULL OR ISJSON(payload_types) = 1),
        CONSTRAINT CK_publisher_campaigns_references CHECK ([references] IS NULL OR ISJSON([references]) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_campaigns_campaign_id')
    CREATE UNIQUE INDEX idx_campaigns_campaign_id ON publisher_campaigns(campaign_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_campaigns_status')
    CREATE INDEX idx_campaigns_status ON publisher_campaigns([status]);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_campaigns_first_detected')
    CREATE INDEX idx_campaigns_first_detected ON publisher_campaigns(first_detected DESC);
GO

-- =====================================================================
-- Triggers for automatic updates
-- =====================================================================

-- Update skill_threats.updated_at on row modification
IF OBJECT_ID('trigger_skill_threats_updated', 'TR') IS NOT NULL
    DROP TRIGGER trigger_skill_threats_updated;
GO

CREATE TRIGGER trigger_skill_threats_updated
ON skill_threats
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE skill_threats
    SET updated_at = SYSDATETIMEOFFSET()
    FROM inserted
    WHERE skill_threats.id = inserted.id;
END;
GO

-- Update publisher_campaigns.updated_at on row modification
IF OBJECT_ID('trigger_campaigns_updated', 'TR') IS NOT NULL
    DROP TRIGGER trigger_campaigns_updated;
GO

CREATE TRIGGER trigger_campaigns_updated
ON publisher_campaigns
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE publisher_campaigns
    SET updated_at = SYSDATETIMEOFFSET()
    FROM inserted
    WHERE publisher_campaigns.id = inserted.id;
END;
GO

-- =====================================================================
-- Views for dashboard queries
-- =====================================================================

-- Recent malicious skills (last 30 days)
IF OBJECT_ID('recent_malicious_skills', 'V') IS NOT NULL
    DROP VIEW recent_malicious_skills;
GO

CREATE VIEW recent_malicious_skills AS
SELECT
    st.hash,
    st.skill_name,
    st.skill_author,
    st.threat_level,
    st.detection_count,
    st.risk_score,
    st.classifications,
    st.first_seen,
    st.campaign_id,
    pc.name as campaign_name
FROM skill_threats st
LEFT JOIN publisher_campaigns pc ON st.campaign_id = pc.campaign_id
WHERE st.threat_level = 'malicious'
  AND st.first_seen >= DATEADD(DAY, -30, SYSDATETIMEOFFSET());
GO

-- Threat statistics by type
IF OBJECT_ID('threat_stats_by_type', 'V') IS NOT NULL
    DROP VIEW threat_stats_by_type;
GO

CREATE VIEW threat_stats_by_type AS
SELECT
    skill_type,
    threat_level,
    COUNT(*) as count,
    SUM(detection_count) as total_detections,
    AVG(risk_score) as avg_risk_score
FROM skill_threats
GROUP BY skill_type, threat_level;
GO

-- Top malicious authors
IF OBJECT_ID('top_malicious_authors', 'V') IS NOT NULL
    DROP VIEW top_malicious_authors;
GO

CREATE VIEW top_malicious_authors AS
SELECT
    skill_author,
    COUNT(*) as malicious_skills,
    SUM(detection_count) as total_detections,
    MAX(first_seen) as latest_activity,
    STRING_AGG(campaign_id, ',') as campaigns
FROM skill_threats
WHERE threat_level = 'malicious'
  AND skill_author IS NOT NULL
GROUP BY skill_author;
GO
