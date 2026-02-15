-- Sigil API — PostgreSQL Database Schema
--
-- Tables for users, teams, scans, threat intelligence, policies,
-- alerts, audit logging, and billing-related metadata.
--
-- Run with:
--   psql -d sigil -f api/schema.sql

-- =====================================================================
-- Extensions
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =====================================================================
-- Teams
-- =====================================================================

CREATE TABLE IF NOT EXISTS teams (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    owner_id        UUID,                       -- FK to users, set after user creation
    plan            VARCHAR(50)  NOT NULL DEFAULT 'free',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_teams_owner ON teams (owner_id);
CREATE INDEX idx_teams_plan  ON teams (plan);

-- =====================================================================
-- Users
-- =====================================================================

CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   TEXT         NOT NULL,
    name            VARCHAR(255) NOT NULL DEFAULT '',
    team_id         UUID         REFERENCES teams(id) ON DELETE SET NULL,
    role            VARCHAR(50)  NOT NULL DEFAULT 'member',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_users_email   ON users (email);
CREATE INDEX idx_users_team           ON users (team_id);
CREATE INDEX idx_users_role           ON users (role);

-- Now add the FK from teams.owner_id -> users.id
ALTER TABLE teams
    ADD CONSTRAINT fk_teams_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE SET NULL;

-- =====================================================================
-- Scans
-- =====================================================================

CREATE TABLE IF NOT EXISTS scans (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID         REFERENCES users(id) ON DELETE SET NULL,
    team_id         UUID         REFERENCES teams(id) ON DELETE SET NULL,
    target          TEXT         NOT NULL,
    target_type     VARCHAR(50)  NOT NULL DEFAULT 'directory',
    files_scanned   INTEGER      NOT NULL DEFAULT 0,
    risk_score      DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    verdict         VARCHAR(50)  NOT NULL DEFAULT 'CLEAN',
    findings_json   JSONB        NOT NULL DEFAULT '[]'::jsonb,
    metadata_json   JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scans_user       ON scans (user_id);
CREATE INDEX idx_scans_team       ON scans (team_id);
CREATE INDEX idx_scans_verdict    ON scans (verdict);
CREATE INDEX idx_scans_target     ON scans (target);
CREATE INDEX idx_scans_created    ON scans (created_at DESC);
CREATE INDEX idx_scans_risk_score ON scans (risk_score DESC);

-- =====================================================================
-- Threats (known-malicious package registry)
-- =====================================================================

CREATE TABLE IF NOT EXISTS threats (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hash            VARCHAR(128) NOT NULL UNIQUE,
    package_name    VARCHAR(255) NOT NULL,
    version         VARCHAR(128) NOT NULL DEFAULT '',
    severity        VARCHAR(50)  NOT NULL DEFAULT 'HIGH',
    source          VARCHAR(100) NOT NULL DEFAULT 'community',
    confirmed_at    TIMESTAMPTZ,
    description     TEXT         NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_threats_hash     ON threats (hash);
CREATE INDEX idx_threats_package         ON threats (package_name);
CREATE INDEX idx_threats_severity        ON threats (severity);
CREATE INDEX idx_threats_source          ON threats (source);
CREATE INDEX idx_threats_confirmed       ON threats (confirmed_at);

-- =====================================================================
-- Signatures (scanner pattern rules)
-- =====================================================================

CREATE TABLE IF NOT EXISTS signatures (
    id              VARCHAR(128) PRIMARY KEY,
    phase           VARCHAR(50)  NOT NULL,
    pattern         TEXT         NOT NULL,
    severity        VARCHAR(50)  NOT NULL DEFAULT 'MEDIUM',
    description     TEXT         NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_signatures_phase    ON signatures (phase);
CREATE INDEX idx_signatures_severity ON signatures (severity);
CREATE INDEX idx_signatures_updated  ON signatures (updated_at DESC);

-- =====================================================================
-- Publishers (reputation tracking)
-- =====================================================================

CREATE TABLE IF NOT EXISTS publishers (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    publisher_id    VARCHAR(255) NOT NULL UNIQUE,
    trust_score     DOUBLE PRECISION NOT NULL DEFAULT 100.0,
    total_packages  INTEGER      NOT NULL DEFAULT 0,
    flagged_count   INTEGER      NOT NULL DEFAULT 0,
    first_seen      TIMESTAMPTZ,
    last_active     TIMESTAMPTZ,
    notes           TEXT         NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX idx_publishers_pid     ON publishers (publisher_id);
CREATE INDEX idx_publishers_trust_score    ON publishers (trust_score);
CREATE INDEX idx_publishers_flagged        ON publishers (flagged_count DESC);

-- =====================================================================
-- Threat Reports (community submissions)
-- =====================================================================

CREATE TABLE IF NOT EXISTS threat_reports (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    package_name      VARCHAR(255) NOT NULL,
    package_version   VARCHAR(128) NOT NULL DEFAULT '',
    ecosystem         VARCHAR(50)  NOT NULL DEFAULT 'unknown',
    reason            TEXT         NOT NULL,
    evidence          TEXT         NOT NULL DEFAULT '',
    reporter_email    VARCHAR(255),
    reporter_user_id  UUID         REFERENCES users(id) ON DELETE SET NULL,
    status            VARCHAR(50)  NOT NULL DEFAULT 'received',
    reviewer_id       UUID         REFERENCES users(id) ON DELETE SET NULL,
    review_notes      TEXT         NOT NULL DEFAULT '',
    reviewed_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reports_package  ON threat_reports (package_name);
CREATE INDEX idx_reports_status   ON threat_reports (status);
CREATE INDEX idx_reports_reporter ON threat_reports (reporter_user_id);
CREATE INDEX idx_reports_created  ON threat_reports (created_at DESC);

-- =====================================================================
-- Verifications (marketplace package verification records)
-- =====================================================================

CREATE TABLE IF NOT EXISTS verifications (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    package_name    VARCHAR(255) NOT NULL,
    version         VARCHAR(128) NOT NULL DEFAULT '',
    ecosystem       VARCHAR(50)  NOT NULL DEFAULT 'unknown',
    publisher_id    VARCHAR(255),
    artifact_hash   VARCHAR(128),
    verdict         VARCHAR(50)  NOT NULL DEFAULT 'PENDING',
    risk_score      DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    badge_url       TEXT,
    verified_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_verifications_package   ON verifications (package_name, ecosystem);
CREATE INDEX idx_verifications_publisher ON verifications (publisher_id);
CREATE INDEX idx_verifications_verdict   ON verifications (verdict);
CREATE INDEX idx_verifications_created   ON verifications (created_at DESC);

-- =====================================================================
-- Policies (team scan policies)
-- =====================================================================

CREATE TABLE IF NOT EXISTS policies (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id         UUID         NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    type            VARCHAR(50)  NOT NULL,
    config_json     JSONB        NOT NULL DEFAULT '{}'::jsonb,
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policies_team    ON policies (team_id);
CREATE INDEX idx_policies_type    ON policies (type);
CREATE INDEX idx_policies_enabled ON policies (team_id, enabled);

-- =====================================================================
-- Alerts (notification channels)
-- =====================================================================

CREATE TABLE IF NOT EXISTS alerts (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id             UUID         NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    channel_type        VARCHAR(50)  NOT NULL,
    channel_config_json JSONB        NOT NULL DEFAULT '{}'::jsonb,
    enabled             BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_team    ON alerts (team_id);
CREATE INDEX idx_alerts_type    ON alerts (channel_type);
CREATE INDEX idx_alerts_enabled ON alerts (team_id, enabled);

-- =====================================================================
-- Audit Log
-- =====================================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID         REFERENCES users(id) ON DELETE SET NULL,
    team_id         UUID         REFERENCES teams(id) ON DELETE SET NULL,
    action          VARCHAR(255) NOT NULL,
    details_json    JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_user    ON audit_log (user_id);
CREATE INDEX idx_audit_team    ON audit_log (team_id);
CREATE INDEX idx_audit_action  ON audit_log (action);
CREATE INDEX idx_audit_created ON audit_log (created_at DESC);

-- =====================================================================
-- Useful composite indexes for common query patterns
-- =====================================================================

-- Recent scans by team with high risk
CREATE INDEX idx_scans_team_risk ON scans (team_id, risk_score DESC, created_at DESC);

-- Active policies for a team
CREATE INDEX idx_policies_team_active ON policies (team_id, enabled) WHERE enabled = TRUE;

-- Recent audit actions by team
CREATE INDEX idx_audit_team_recent ON audit_log (team_id, created_at DESC);
