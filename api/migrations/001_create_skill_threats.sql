-- Migration: Add skill_threats table for AI skill security
-- Description: VirusTotal-style hash-based threat intelligence for AI skills/agents
-- Created: 2026-02-20
-- Related: OpenClaw attack lessons, Phase 7-8 detection

-- =====================================================================
-- Skill Threats (AI skill threat intelligence database)
-- =====================================================================

CREATE TABLE IF NOT EXISTS skill_threats (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hash                VARCHAR(64) NOT NULL UNIQUE,
    skill_name          VARCHAR(255) NOT NULL,
    skill_author        VARCHAR(255),
    skill_type          VARCHAR(50) NOT NULL DEFAULT 'unknown',  -- 'claude-skill', 'mcp-server', 'langchain-tool', 'openclaw-skill'
    skill_version       VARCHAR(128) NOT NULL DEFAULT '',

    -- Threat classification
    threat_level        VARCHAR(20) NOT NULL DEFAULT 'unknown',  -- 'benign', 'suspicious', 'malicious'
    detection_count     INTEGER NOT NULL DEFAULT 1,
    classifications     JSONB NOT NULL DEFAULT '[]'::jsonb,      -- ["prompt-injection", "tool-abuse", "credential-theft"]

    -- Evidence and analysis
    evidence            TEXT NOT NULL DEFAULT '',
    attack_patterns     TEXT[] NOT NULL DEFAULT '{}',            -- Array of pattern IDs that matched
    risk_score          DOUBLE PRECISION NOT NULL DEFAULT 0.0,

    -- Community feedback
    community_votes     JSONB NOT NULL DEFAULT '{"malicious": 0, "suspicious": 0, "benign": 0}'::jsonb,

    -- Related threats
    similar_hashes      TEXT[] NOT NULL DEFAULT '{}',            -- Related threat hashes
    campaign_id         VARCHAR(128),                            -- Group related attacks (e.g., "openclaw-hightower6eu")

    -- Metadata
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for fast lookups
CREATE UNIQUE INDEX idx_skill_threats_hash ON skill_threats(hash);
CREATE INDEX idx_skill_threats_name ON skill_threats(skill_name);
CREATE INDEX idx_skill_threats_author ON skill_threats(skill_author);
CREATE INDEX idx_skill_threats_type ON skill_threats(skill_type);
CREATE INDEX idx_skill_threats_level ON skill_threats(threat_level);
CREATE INDEX idx_skill_threats_campaign ON skill_threats(campaign_id) WHERE campaign_id IS NOT NULL;
CREATE INDEX idx_skill_threats_risk ON skill_threats(risk_score DESC);
CREATE INDEX idx_skill_threats_detections ON skill_threats(detection_count DESC);
CREATE INDEX idx_skill_threats_first_seen ON skill_threats(first_seen DESC);
CREATE INDEX idx_skill_threats_classifications ON skill_threats USING GIN (classifications);

-- Composite index for dashboard queries (threat level + detection count)
CREATE INDEX idx_skill_threats_level_detections ON skill_threats(threat_level, detection_count DESC);

-- =====================================================================
-- Skill Scan History (track individual scans for analytics)
-- =====================================================================

CREATE TABLE IF NOT EXISTS skill_scans (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    skill_threat_id     UUID REFERENCES skill_threats(id) ON DELETE CASCADE,
    hash                VARCHAR(64) NOT NULL,
    user_id             UUID REFERENCES users(id) ON DELETE SET NULL,
    team_id             UUID REFERENCES teams(id) ON DELETE SET NULL,

    -- Scan results
    verdict             VARCHAR(50) NOT NULL DEFAULT 'CLEAN',
    risk_score          DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    findings_count      INTEGER NOT NULL DEFAULT 0,
    findings_json       JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- Context
    source              VARCHAR(100) NOT NULL DEFAULT 'cli',    -- 'cli', 'api', 'github-action', 'vscode'
    metadata_json       JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Timestamps
    scanned_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_skill_scans_threat ON skill_scans(skill_threat_id);
CREATE INDEX idx_skill_scans_hash ON skill_scans(hash);
CREATE INDEX idx_skill_scans_user ON skill_scans(user_id);
CREATE INDEX idx_skill_scans_team ON skill_scans(team_id);
CREATE INDEX idx_skill_scans_verdict ON skill_scans(verdict);
CREATE INDEX idx_skill_scans_date ON skill_scans(scanned_at DESC);

-- =====================================================================
-- Publisher Campaigns (track coordinated attack campaigns)
-- =====================================================================

CREATE TABLE IF NOT EXISTS publisher_campaigns (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    campaign_id         VARCHAR(128) NOT NULL UNIQUE,
    name                VARCHAR(255) NOT NULL,                   -- 'OpenClaw hightower6eu Campaign'

    -- Campaign details
    publisher_ids       TEXT[] NOT NULL DEFAULT '{}',            -- ['hightower6eu', 'related-actor']
    skill_count         INTEGER NOT NULL DEFAULT 0,
    infected_count      INTEGER NOT NULL DEFAULT 0,              -- Estimated infections

    -- Timeline
    first_detected      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status              VARCHAR(50) NOT NULL DEFAULT 'active',   -- 'active', 'contained', 'resolved'

    -- Attack characteristics
    attack_patterns     TEXT[] NOT NULL DEFAULT '{}',
    payload_types       TEXT[] NOT NULL DEFAULT '{}',            -- ['atomic-stealer', 'packed-trojan']

    -- Metadata
    description         TEXT NOT NULL DEFAULT '',
    remediation         TEXT NOT NULL DEFAULT '',
    references          TEXT[] NOT NULL DEFAULT '{}',            -- URLs to blog posts, reports

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_campaigns_campaign_id ON publisher_campaigns(campaign_id);
CREATE INDEX idx_campaigns_status ON publisher_campaigns(status);
CREATE INDEX idx_campaigns_first_detected ON publisher_campaigns(first_detected DESC);
CREATE INDEX idx_campaigns_publishers ON publisher_campaigns USING GIN (publisher_ids);

-- =====================================================================
-- Functions for automatic updates
-- =====================================================================

-- Update skill_threats.updated_at on row modification
CREATE OR REPLACE FUNCTION update_skill_threat_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_skill_threats_updated
    BEFORE UPDATE ON skill_threats
    FOR EACH ROW
    EXECUTE FUNCTION update_skill_threat_timestamp();

-- Update publisher_campaigns.updated_at on row modification
CREATE OR REPLACE FUNCTION update_campaign_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_campaigns_updated
    BEFORE UPDATE ON publisher_campaigns
    FOR EACH ROW
    EXECUTE FUNCTION update_campaign_timestamp();

-- =====================================================================
-- Views for dashboard queries
-- =====================================================================

-- Recent malicious skills (last 30 days)
CREATE OR REPLACE VIEW recent_malicious_skills AS
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
  AND st.first_seen >= NOW() - INTERVAL '30 days'
ORDER BY st.first_seen DESC;

-- Threat statistics by type
CREATE OR REPLACE VIEW threat_stats_by_type AS
SELECT
    skill_type,
    threat_level,
    COUNT(*) as count,
    SUM(detection_count) as total_detections,
    AVG(risk_score) as avg_risk_score
FROM skill_threats
GROUP BY skill_type, threat_level
ORDER BY count DESC;

-- Top malicious authors
CREATE OR REPLACE VIEW top_malicious_authors AS
SELECT
    skill_author,
    COUNT(*) as malicious_skills,
    SUM(detection_count) as total_detections,
    MAX(first_seen) as latest_activity,
    ARRAY_AGG(DISTINCT campaign_id) FILTER (WHERE campaign_id IS NOT NULL) as campaigns
FROM skill_threats
WHERE threat_level = 'malicious'
  AND skill_author IS NOT NULL
GROUP BY skill_author
ORDER BY malicious_skills DESC;

-- =====================================================================
-- Initial data / seed examples (for testing)
-- =====================================================================

-- Commented out - uncomment to seed test data
-- INSERT INTO skill_threats (hash, skill_name, skill_author, skill_type, threat_level, classifications, evidence, attack_patterns, risk_score, campaign_id, community_votes)
-- VALUES
-- (
--     'sha256:abc123def456789...',
--     'crypto-analytics',
--     'hightower6eu',
--     'openclaw-skill',
--     'malicious',
--     '["prompt-injection", "tool-abuse", "credential-theft"]'::jsonb,
--     'Instructs user to download and execute openclaw-agent.exe from unencrypted HTTP',
--     ARRAY['prompt-execute-binary', 'net-http-exe-download', 'prompt-password-archive'],
--     95.0,
--     'openclaw-hightower6eu-2026-02',
--     '{"malicious": 142, "suspicious": 8, "benign": 6}'::jsonb
-- );

COMMENT ON TABLE skill_threats IS 'Hash-based threat intelligence for AI skills, MCP servers, and agent tools';
COMMENT ON TABLE skill_scans IS 'Individual scan history for skills (analytics and user audit trail)';
COMMENT ON TABLE publisher_campaigns IS 'Coordinated attack campaigns across multiple publishers/skills';
COMMENT ON COLUMN skill_threats.hash IS 'SHA-256 hash of skill bundle (deterministic)';
COMMENT ON COLUMN skill_threats.threat_level IS 'benign | suspicious | malicious';
COMMENT ON COLUMN skill_threats.campaign_id IS 'Groups related threats (e.g., openclaw-hightower6eu-2026-02)';
COMMENT ON COLUMN skill_threats.community_votes IS 'JSON object with vote counts from community';
