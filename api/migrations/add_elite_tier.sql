-- Migration: Add Elite subscription tier
-- Date: 2026-03-12
-- Description: Adds Elite tier between Pro and Team for power users

-- 1. Update subscription_tiers enum if using lookup table
-- Note: If subscription_tier is stored as VARCHAR, no schema change needed

-- 2. Add Elite tier to any tier-based views or functions
-- Update the view to handle Elite tier
DROP VIEW IF EXISTS vw_subscription_capabilities;
GO

CREATE VIEW vw_subscription_capabilities AS
SELECT 
    u.id as user_id,
    u.subscription_tier,
    CASE u.subscription_tier
        WHEN 'ANONYMOUS' THEN 'No Access'
        WHEN 'FREE' THEN 'Basic (50 credits/mo)'
        WHEN 'PRO' THEN 'Professional (5,000 credits/mo)'
        WHEN 'ELITE' THEN 'Elite (15,000 credits/mo)'
        WHEN 'TEAM' THEN 'Team (50,000 shared credits/mo)'
        WHEN 'ENTERPRISE' THEN 'Enterprise (Unlimited)'
        ELSE 'Unknown'
    END as tier_description,
    CASE u.subscription_tier
        WHEN 'ANONYMOUS' THEN 0
        WHEN 'FREE' THEN 50
        WHEN 'PRO' THEN 5000
        WHEN 'ELITE' THEN 15000
        WHEN 'TEAM' THEN 50000
        WHEN 'ENTERPRISE' THEN 999999
        ELSE 0
    END as monthly_credits,
    CASE 
        WHEN u.subscription_tier IN ('PRO', 'ELITE', 'TEAM', 'ENTERPRISE') THEN 1
        ELSE 0
    END as has_llm_access,
    CASE 
        WHEN u.subscription_tier IN ('ELITE', 'TEAM', 'ENTERPRISE') THEN 1
        ELSE 0
    END as has_priority_support,
    CASE 
        WHEN u.subscription_tier IN ('TEAM', 'ENTERPRISE') THEN 1
        ELSE 0
    END as has_team_features
FROM users u;
GO

-- 3. Update stored procedure for user registration to handle anonymous vs free
CREATE OR ALTER PROCEDURE sp_RegisterUser
    @UserId NVARCHAR(128),
    @Email NVARCHAR(255) = NULL,
    @Name NVARCHAR(255) = NULL
AS
BEGIN
    DECLARE @Tier NVARCHAR(20);
    DECLARE @InitialCredits INT;
    
    -- Determine tier based on email presence
    IF @Email IS NULL
    BEGIN
        SET @Tier = 'ANONYMOUS';
        SET @InitialCredits = 0;
    END
    ELSE
    BEGIN
        SET @Tier = 'FREE';
        SET @InitialCredits = 50;
    END
    
    -- Insert user
    INSERT INTO users (id, email, name, subscription_tier, subscription_status)
    VALUES (@UserId, @Email, @Name, @Tier, 'active');
    
    -- Initialize credits
    INSERT INTO user_credits (
        user_id, 
        credits_balance, 
        subscription_credits, 
        reset_date
    )
    VALUES (
        @UserId, 
        @InitialCredits, 
        @InitialCredits, 
        DATEADD(MONTH, 1, GETDATE())
    );
    
    SELECT @Tier as assigned_tier, @InitialCredits as initial_credits;
END;
GO

-- 4. Add Stripe product mapping for Elite tier
INSERT INTO stripe_products (
    product_id,
    price_id,
    subscription_tier,
    price_monthly,
    price_yearly,
    is_active,
    created_at
)
VALUES (
    'prod_elite_tier',
    'price_elite_monthly',
    'ELITE',
    79.00,
    790.00,  -- ~17% discount for annual
    1,
    GETDATE()
);

-- 5. Create upgrade path tracking
CREATE TABLE IF NOT EXISTS upgrade_paths (
    id INT IDENTITY(1,1) PRIMARY KEY,
    from_tier NVARCHAR(20),
    to_tier NVARCHAR(20),
    upgrade_prompt NVARCHAR(500),
    benefits_description NVARCHAR(MAX),
    created_at DATETIME2 DEFAULT GETDATE()
);

INSERT INTO upgrade_paths (from_tier, to_tier, upgrade_prompt, benefits_description) VALUES
('ANONYMOUS', 'FREE', 'Sign up for free to get 50 monthly credits', '{"benefits": ["50 free credits monthly", "Basic threat scanning", "Save scan history"]}'),
('FREE', 'PRO', 'Upgrade to Pro for advanced AI analysis', '{"benefits": ["5,000 credits monthly", "Claude Haiku analysis", "Priority scanning", "Export reports"]}'),
('FREE', 'ELITE', 'Go Elite for power users', '{"benefits": ["15,000 credits monthly", "All Pro features", "Claude Sonnet access", "API access", "Custom integrations"]}'),
('PRO', 'ELITE', 'Unlock Elite features', '{"benefits": ["3x more credits", "Claude Sonnet for complex analysis", "API access", "Priority support"]}'),
('ELITE', 'TEAM', 'Scale with your team', '{"benefits": ["50,000 shared credits", "5 team seats", "Admin dashboard", "Usage analytics", "SSO"]}');

-- 6. Analytics query for tier distribution
CREATE OR ALTER PROCEDURE sp_GetTierAnalytics
AS
BEGIN
    SELECT 
        subscription_tier,
        COUNT(*) as user_count,
        AVG(CAST(uc.credits_used_month as FLOAT)) as avg_credits_used,
        SUM(uc.credits_used_month) as total_credits_used,
        COUNT(CASE WHEN uc.credits_balance < 100 THEN 1 END) as low_balance_users,
        COUNT(CASE WHEN u.last_login_at > DATEADD(DAY, -30, GETDATE()) THEN 1 END) as active_users
    FROM users u
    LEFT JOIN user_credits uc ON u.id = uc.user_id
    WHERE u.subscription_status = 'active'
    GROUP BY subscription_tier
    ORDER BY 
        CASE subscription_tier
            WHEN 'ANONYMOUS' THEN 1
            WHEN 'FREE' THEN 2
            WHEN 'PRO' THEN 3
            WHEN 'ELITE' THEN 4
            WHEN 'TEAM' THEN 5
            WHEN 'ENTERPRISE' THEN 6
        END;
END;
GO

-- Migration complete
PRINT 'Elite tier migration completed successfully';