-- Analytics Database Schema for Sigil Pro Usage Tracking
-- Created for US-009: Implement Usage Tracking for Pro Features

-- User Analytics Events Table
-- Tracks general analytics events for business intelligence
CREATE TABLE user_analytics (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    user_id NVARCHAR(255) NOT NULL,
    event_type NVARCHAR(100) NOT NULL, -- 'llm_scan', 'threat_detected', 'zero_day_found', 'upgrade_prompt'
    event_data NVARCHAR(MAX), -- JSON data with event-specific details
    tier NVARCHAR(50) NOT NULL, -- 'free', 'pro', 'team', 'enterprise'
    created_at DATETIME2 DEFAULT GETUTCDATE(),
    
    INDEX IX_user_analytics_user_id (user_id),
    INDEX IX_user_analytics_event_type (event_type),
    INDEX IX_user_analytics_created_at (created_at),
    INDEX IX_user_analytics_tier (tier)
);

-- LLM Usage Metrics Table  
-- Tracks detailed LLM API usage for cost analysis and performance optimization
CREATE TABLE llm_usage_metrics (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    user_id NVARCHAR(255) NOT NULL,
    scan_id NVARCHAR(100) NOT NULL,
    model_used NVARCHAR(100) NOT NULL, -- 'gpt-4', 'claude-3-sonnet', etc.
    tokens_used INT DEFAULT 0,
    processing_time_ms INT DEFAULT 0,
    cost_cents DECIMAL(10,2) DEFAULT 0.00, -- Cost in cents for precise tracking
    insights_generated INT DEFAULT 0, -- Number of AI insights produced
    threats_found INT DEFAULT 0, -- Number of threats detected with confidence > 0.7
    confidence_avg DECIMAL(3,2) DEFAULT 0.00, -- Average confidence score (0-1)
    cache_hit BIT DEFAULT 0, -- Whether result came from cache
    fallback_used BIT DEFAULT 0, -- Whether fallback was used due to errors
    created_at DATETIME2 DEFAULT GETUTCDATE(),
    
    INDEX IX_llm_usage_user_id (user_id),
    INDEX IX_llm_usage_created_at (created_at),
    INDEX IX_llm_usage_model_used (model_used),
    INDEX IX_llm_usage_scan_id (scan_id)
);

-- Threat Discoveries Table
-- Tracks individual threat discoveries for trend analysis and zero-day detection
CREATE TABLE threat_discoveries (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    user_id NVARCHAR(255) NOT NULL,
    scan_id NVARCHAR(100), -- Links to specific scan
    threat_type NVARCHAR(100) NOT NULL, -- 'code_injection', 'credential_theft', etc.
    severity NVARCHAR(20) NOT NULL, -- 'info', 'low', 'medium', 'high', 'critical'
    confidence DECIMAL(3,2) NOT NULL, -- Confidence score 0-1
    is_zero_day BIT DEFAULT 0, -- Flag for zero-day discoveries
    file_path NVARCHAR(500), -- Path to affected file
    threat_hash NVARCHAR(64), -- SHA-256 hash for deduplication
    analysis_type NVARCHAR(50), -- 'static', 'llm_analysis', 'zero_day_detection'
    evidence_snippet NVARCHAR(MAX), -- Code snippet showing the threat
    remediation_suggested NVARCHAR(MAX), -- JSON array of remediation steps
    created_at DATETIME2 DEFAULT GETUTCDATE(),
    
    INDEX IX_threat_discoveries_user_id (user_id),
    INDEX IX_threat_discoveries_threat_type (threat_type),
    INDEX IX_threat_discoveries_is_zero_day (is_zero_day),
    INDEX IX_threat_discoveries_created_at (created_at),
    INDEX IX_threat_discoveries_threat_hash (threat_hash),
    INDEX IX_threat_discoveries_severity (severity)
);

-- User Engagement Metrics Table
-- Tracks user engagement patterns for churn prediction
CREATE TABLE user_engagement_metrics (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    user_id NVARCHAR(255) NOT NULL,
    date_tracked DATE NOT NULL, -- Daily aggregation
    scans_performed INT DEFAULT 0,
    threats_discovered INT DEFAULT 0,
    zero_days_found INT DEFAULT 0,
    llm_tokens_used INT DEFAULT 0,
    session_duration_minutes INT DEFAULT 0,
    features_used NVARCHAR(MAX), -- JSON array of features accessed
    upgrade_prompts_shown INT DEFAULT 0, -- For free users
    upgrade_prompts_dismissed INT DEFAULT 0,
    created_at DATETIME2 DEFAULT GETUTCDATE(),
    
    UNIQUE INDEX IX_user_engagement_user_date (user_id, date_tracked),
    INDEX IX_user_engagement_date_tracked (date_tracked)
);

-- Billing Usage Summary Table
-- Daily aggregation for billing calculations and limits
CREATE TABLE billing_usage_summary (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    user_id NVARCHAR(255) NOT NULL,
    billing_period_start DATE NOT NULL, -- Start of billing period
    billing_period_end DATE NOT NULL, -- End of billing period
    tier NVARCHAR(50) NOT NULL,
    total_scans INT DEFAULT 0,
    total_llm_tokens INT DEFAULT 0,
    total_cost_cents DECIMAL(10,2) DEFAULT 0.00,
    total_threats_found INT DEFAULT 0,
    zero_days_discovered INT DEFAULT 0,
    overage_charges_cents DECIMAL(10,2) DEFAULT 0.00, -- For usage beyond plan limits
    last_updated DATETIME2 DEFAULT GETUTCDATE(),
    created_at DATETIME2 DEFAULT GETUTCDATE(),
    
    UNIQUE INDEX IX_billing_usage_user_period (user_id, billing_period_start),
    INDEX IX_billing_usage_period_start (billing_period_start)
);

-- Analytics Aggregation Views
-- Pre-computed views for common analytics queries

-- Daily Usage Rollup View
CREATE VIEW daily_usage_rollup AS
SELECT 
    CAST(created_at AS DATE) as usage_date,
    COUNT(DISTINCT user_id) as active_users,
    COUNT(*) as total_scans,
    SUM(tokens_used) as total_tokens,
    SUM(cost_cents) as total_cost_cents,
    SUM(insights_generated) as total_insights,
    SUM(threats_found) as total_threats,
    AVG(CAST(processing_time_ms AS FLOAT)) as avg_processing_time_ms,
    COUNT(CASE WHEN cache_hit = 1 THEN 1 END) as cache_hits,
    COUNT(CASE WHEN fallback_used = 1 THEN 1 END) as fallbacks_used
FROM llm_usage_metrics
WHERE created_at >= DATEADD(month, -3, GETDATE()) -- Last 3 months
GROUP BY CAST(created_at AS DATE);

-- User Churn Risk View
CREATE VIEW user_churn_risk AS
SELECT 
    user_id,
    MAX(created_at) as last_activity,
    COUNT(*) as total_scans_30d,
    AVG(CAST(threats_found AS FLOAT)) as avg_threats_per_scan,
    CASE 
        WHEN MAX(created_at) < DATEADD(day, -14, GETDATE()) THEN 'HIGH_RISK'
        WHEN COUNT(*) < 5 AND MAX(created_at) < DATEADD(day, -7, GETDATE()) THEN 'MEDIUM_RISK'
        WHEN AVG(CAST(threats_found AS FLOAT)) < 0.1 THEN 'LOW_ENGAGEMENT'
        ELSE 'HEALTHY'
    END as risk_category
FROM llm_usage_metrics
WHERE created_at >= DATEADD(day, -30, GETDATE())
GROUP BY user_id;

-- Threat Discovery Trends View
CREATE VIEW threat_discovery_trends AS
SELECT 
    CAST(created_at AS DATE) as discovery_date,
    threat_type,
    severity,
    COUNT(*) as discoveries,
    COUNT(CASE WHEN is_zero_day = 1 THEN 1 END) as zero_day_count,
    AVG(confidence) as avg_confidence
FROM threat_discoveries
WHERE created_at >= DATEADD(month, -6, GETDATE()) -- Last 6 months
GROUP BY CAST(created_at AS DATE), threat_type, severity;