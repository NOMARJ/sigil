-- Email subscription and newsletter management tables
-- Migration 007: Email subscriptions and weekly digest automation

-- Email subscriptions table
CREATE TABLE IF NOT EXISTS email_subscriptions (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    preferences JSONB DEFAULT '{"security_alerts": true, "tool_discoveries": true, "weekly_digest": true, "product_updates": true}'::jsonb,
    unsubscribe_token VARCHAR(64) UNIQUE NOT NULL,
    source VARCHAR(50) DEFAULT 'forge',
    is_active BOOLEAN DEFAULT true,
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Email campaigns table
CREATE TABLE IF NOT EXISTS email_campaigns (
    id SERIAL PRIMARY KEY,
    campaign_id VARCHAR(64) UNIQUE NOT NULL,
    subject VARCHAR(255) NOT NULL,
    content_json JSONB NOT NULL,
    recipient_count INTEGER DEFAULT 0,
    sent_count INTEGER DEFAULT 0,
    bounced_count INTEGER DEFAULT 0,
    opened_count INTEGER DEFAULT 0,
    clicked_count INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'scheduled',
    scheduled_for TIMESTAMPTZ NOT NULL,
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Email sends tracking table
CREATE TABLE IF NOT EXISTS email_sends (
    id SERIAL PRIMARY KEY,
    campaign_id VARCHAR(64) NOT NULL,
    email VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'sent',
    sent_at TIMESTAMPTZ DEFAULT NOW(),
    opened_at TIMESTAMPTZ,
    clicked_at TIMESTAMPTZ,
    bounced_at TIMESTAMPTZ,
    unsubscribed_at TIMESTAMPTZ,
    external_id VARCHAR(255),
    FOREIGN KEY (campaign_id) REFERENCES email_campaigns(campaign_id) ON DELETE CASCADE
);

-- Weekly digest content cache table
CREATE TABLE IF NOT EXISTS weekly_digest_cache (
    id SERIAL PRIMARY KEY,
    week_ending DATE UNIQUE NOT NULL,
    content_json JSONB NOT NULL,
    generated_at TIMESTAMPTZ DEFAULT NOW(),
    is_current BOOLEAN DEFAULT false
);

-- Unsubscribe log table
CREATE TABLE IF NOT EXISTS unsubscribe_log (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    unsubscribe_token VARCHAR(64) NOT NULL,
    reason TEXT,
    campaign_id VARCHAR(64),
    unsubscribed_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_email_subscriptions_email ON email_subscriptions(email);
CREATE INDEX IF NOT EXISTS idx_email_subscriptions_active ON email_subscriptions(is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_email_subscriptions_token ON email_subscriptions(unsubscribe_token);

CREATE INDEX IF NOT EXISTS idx_email_campaigns_status ON email_campaigns(status);
CREATE INDEX IF NOT EXISTS idx_email_campaigns_scheduled ON email_campaigns(scheduled_for) WHERE status = 'scheduled';
CREATE INDEX IF NOT EXISTS idx_email_campaigns_sent ON email_campaigns(sent_at) WHERE status = 'sent';

CREATE INDEX IF NOT EXISTS idx_email_sends_campaign ON email_sends(campaign_id);
CREATE INDEX IF NOT EXISTS idx_email_sends_email ON email_sends(email);
CREATE INDEX IF NOT EXISTS idx_email_sends_status ON email_sends(status);

CREATE INDEX IF NOT EXISTS idx_weekly_digest_week ON weekly_digest_cache(week_ending);
CREATE INDEX IF NOT EXISTS idx_weekly_digest_current ON weekly_digest_cache(is_current) WHERE is_current = true;

CREATE INDEX IF NOT EXISTS idx_unsubscribe_log_email ON unsubscribe_log(email);
CREATE INDEX IF NOT EXISTS idx_unsubscribe_log_token ON unsubscribe_log(unsubscribe_token);

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_email_subscription_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER email_subscriptions_updated_at
    BEFORE UPDATE ON email_subscriptions
    FOR EACH ROW
    EXECUTE FUNCTION update_email_subscription_timestamp();

-- Function to generate secure unsubscribe tokens
CREATE OR REPLACE FUNCTION generate_unsubscribe_token()
RETURNS VARCHAR(64) AS $$
BEGIN
    RETURN encode(gen_random_bytes(32), 'hex');
END;
$$ LANGUAGE plpgsql;

-- Function to automatically set unsubscribe token
CREATE OR REPLACE FUNCTION set_unsubscribe_token()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.unsubscribe_token IS NULL OR NEW.unsubscribe_token = '' THEN
        NEW.unsubscribe_token = generate_unsubscribe_token();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER email_subscriptions_set_token
    BEFORE INSERT ON email_subscriptions
    FOR EACH ROW
    EXECUTE FUNCTION set_unsubscribe_token();

-- Insert test data for development
INSERT INTO email_subscriptions (email, source) VALUES 
('test@example.com', 'forge')
ON CONFLICT (email) DO NOTHING;

COMMENT ON TABLE email_subscriptions IS 'Stores email subscription data for Forge Weekly newsletter';
COMMENT ON TABLE email_campaigns IS 'Email campaign management and tracking';
COMMENT ON TABLE email_sends IS 'Individual email send tracking and analytics';
COMMENT ON TABLE weekly_digest_cache IS 'Cached weekly digest content for performance';
COMMENT ON TABLE unsubscribe_log IS 'Audit trail for email unsubscriptions';