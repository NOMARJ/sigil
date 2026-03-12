-- Migration: Add credit-based token management system for LLM features
-- Date: 2026-03-12
-- Description: Implements Windsurf-style credit system for Pro tier LLM usage

-- 1. Create user credits table
CREATE TABLE user_credits (
    user_id NVARCHAR(128) PRIMARY KEY,
    credits_balance INT NOT NULL DEFAULT 0,
    credits_used_month INT NOT NULL DEFAULT 0,
    bonus_credits INT NOT NULL DEFAULT 0,
    subscription_credits INT NOT NULL DEFAULT 0, -- Monthly allocation based on tier
    reset_date DATETIME2 NOT NULL,
    last_updated DATETIME2 NOT NULL DEFAULT GETDATE(),
    created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    CONSTRAINT FK_user_credits_users FOREIGN KEY (user_id) 
        REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT CK_credits_positive CHECK (credits_balance >= 0)
);

-- 2. Create credit transactions log
CREATE TABLE credit_transactions (
    transaction_id UNIQUEIDENTIFIER DEFAULT NEWID() PRIMARY KEY,
    user_id NVARCHAR(128) NOT NULL,
    credits_amount INT NOT NULL, -- Negative for deductions, positive for additions
    credits_balance_after INT NOT NULL,
    transaction_type NVARCHAR(50) NOT NULL, -- 'scan', 'interactive', 'refund', 'bonus', 'subscription', 'purchase'
    transaction_status NVARCHAR(20) NOT NULL DEFAULT 'completed', -- 'pending', 'completed', 'failed', 'refunded'
    scan_id NVARCHAR(64),
    session_id NVARCHAR(64),
    model_used NVARCHAR(50),
    tokens_used INT,
    metadata NVARCHAR(MAX), -- JSON for additional data
    created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    CONSTRAINT FK_transactions_user FOREIGN KEY (user_id) 
        REFERENCES users(id) ON DELETE CASCADE,
    INDEX IX_transactions_user_date (user_id, created_at DESC),
    INDEX IX_transactions_scan (scan_id)
);

-- 3. Create interactive sessions table
CREATE TABLE interactive_sessions (
    session_id NVARCHAR(64) PRIMARY KEY,
    user_id NVARCHAR(128) NOT NULL,
    scan_id NVARCHAR(64) NOT NULL,
    status NVARCHAR(20) NOT NULL DEFAULT 'active', -- 'active', 'completed', 'expired'
    findings_context NVARCHAR(MAX), -- JSON with findings and context
    conversation_history NVARCHAR(MAX), -- JSON array of messages
    total_credits_used INT NOT NULL DEFAULT 0,
    model_preference NVARCHAR(50) DEFAULT 'claude-3-haiku',
    started_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    last_activity DATETIME2 NOT NULL DEFAULT GETDATE(),
    completed_at DATETIME2,
    CONSTRAINT FK_sessions_user FOREIGN KEY (user_id) 
        REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT FK_sessions_scan FOREIGN KEY (scan_id) 
        REFERENCES scans(scan_id) ON DELETE CASCADE,
    INDEX IX_sessions_user_active (user_id, status),
    INDEX IX_sessions_scan (scan_id)
);

-- 4. Create credit packages for purchase
CREATE TABLE credit_packages (
    package_id INT IDENTITY(1,1) PRIMARY KEY,
    package_name NVARCHAR(100) NOT NULL,
    credits_amount INT NOT NULL,
    price_usd DECIMAL(10,2) NOT NULL,
    stripe_price_id NVARCHAR(255),
    is_active BIT NOT NULL DEFAULT 1,
    created_at DATETIME2 NOT NULL DEFAULT GETDATE()
);

-- 5. Insert default credit packages
INSERT INTO credit_packages (package_name, credits_amount, price_usd, stripe_price_id) VALUES
('Starter Pack', 1000, 5.00, NULL),
('Pro Pack', 5000, 20.00, NULL),
('Team Pack', 20000, 70.00, NULL);

-- 6. Create stored procedure to deduct credits
GO
CREATE OR ALTER PROCEDURE sp_DeductCredits
    @UserId NVARCHAR(128),
    @Amount INT,
    @TransactionType NVARCHAR(50),
    @ScanId NVARCHAR(64) = NULL,
    @SessionId NVARCHAR(64) = NULL,
    @ModelUsed NVARCHAR(50) = NULL,
    @TokensUsed INT = NULL,
    @Metadata NVARCHAR(MAX) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @CurrentBalance INT;
    DECLARE @NewBalance INT;
    
    BEGIN TRANSACTION;
    
    -- Get current balance with lock
    SELECT @CurrentBalance = credits_balance 
    FROM user_credits WITH (UPDLOCK)
    WHERE user_id = @UserId;
    
    -- Check if user exists
    IF @CurrentBalance IS NULL
    BEGIN
        ROLLBACK TRANSACTION;
        THROW 50001, 'User credits not found', 1;
    END
    
    -- Check sufficient balance
    IF @CurrentBalance < @Amount
    BEGIN
        ROLLBACK TRANSACTION;
        THROW 50002, 'Insufficient credits', 1;
    END
    
    -- Calculate new balance
    SET @NewBalance = @CurrentBalance - @Amount;
    
    -- Update balance
    UPDATE user_credits 
    SET credits_balance = @NewBalance,
        credits_used_month = credits_used_month + @Amount,
        last_updated = GETDATE()
    WHERE user_id = @UserId;
    
    -- Log transaction
    INSERT INTO credit_transactions (
        user_id, credits_amount, credits_balance_after, 
        transaction_type, scan_id, session_id, 
        model_used, tokens_used, metadata
    )
    VALUES (
        @UserId, -@Amount, @NewBalance, 
        @TransactionType, @ScanId, @SessionId,
        @ModelUsed, @TokensUsed, @Metadata
    );
    
    COMMIT TRANSACTION;
    
    -- Return new balance
    SELECT @NewBalance AS new_balance;
END;
GO

-- 7. Create stored procedure to add credits
CREATE OR ALTER PROCEDURE sp_AddCredits
    @UserId NVARCHAR(128),
    @Amount INT,
    @TransactionType NVARCHAR(50), -- 'subscription', 'purchase', 'bonus', 'refund'
    @Metadata NVARCHAR(MAX) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @CurrentBalance INT;
    DECLARE @NewBalance INT;
    
    BEGIN TRANSACTION;
    
    -- Get current balance or create new record
    SELECT @CurrentBalance = credits_balance 
    FROM user_credits WITH (UPDLOCK)
    WHERE user_id = @UserId;
    
    IF @CurrentBalance IS NULL
    BEGIN
        -- Create new credit record
        INSERT INTO user_credits (user_id, credits_balance, reset_date)
        VALUES (@UserId, 0, DATEADD(MONTH, 1, GETDATE()));
        SET @CurrentBalance = 0;
    END
    
    -- Calculate new balance
    SET @NewBalance = @CurrentBalance + @Amount;
    
    -- Update balance
    UPDATE user_credits 
    SET credits_balance = @NewBalance,
        last_updated = GETDATE(),
        subscription_credits = CASE 
            WHEN @TransactionType = 'subscription' THEN @Amount 
            ELSE subscription_credits 
        END,
        bonus_credits = CASE 
            WHEN @TransactionType = 'bonus' THEN bonus_credits + @Amount 
            ELSE bonus_credits 
        END
    WHERE user_id = @UserId;
    
    -- Log transaction
    INSERT INTO credit_transactions (
        user_id, credits_amount, credits_balance_after, 
        transaction_type, metadata
    )
    VALUES (
        @UserId, @Amount, @NewBalance, 
        @TransactionType, @Metadata
    );
    
    COMMIT TRANSACTION;
    
    -- Return new balance
    SELECT @NewBalance AS new_balance;
END;
GO

-- 8. Create stored procedure to reset monthly credits
CREATE OR ALTER PROCEDURE sp_ResetMonthlyCredits
AS
BEGIN
    SET NOCOUNT ON;
    
    -- Reset credits for users whose reset date has passed
    UPDATE uc
    SET uc.credits_balance = 
            CASE 
                WHEN u.subscription_tier = 'PRO' THEN 5000
                WHEN u.subscription_tier = 'ELITE' THEN 15000
                WHEN u.subscription_tier = 'TEAM' THEN 50000
                WHEN u.subscription_tier = 'ENTERPRISE' THEN 999999
                WHEN u.subscription_tier = 'FREE' AND u.email IS NOT NULL THEN 50
                ELSE 0 -- Anonymous users get no credits
            END + uc.bonus_credits, -- Keep bonus credits
        uc.credits_used_month = 0,
        uc.reset_date = DATEADD(MONTH, 1, uc.reset_date),
        uc.subscription_credits = 
            CASE 
                WHEN u.subscription_tier = 'PRO' THEN 5000
                WHEN u.subscription_tier = 'ELITE' THEN 15000
                WHEN u.subscription_tier = 'TEAM' THEN 50000
                WHEN u.subscription_tier = 'ENTERPRISE' THEN 999999
                WHEN u.subscription_tier = 'FREE' AND u.email IS NOT NULL THEN 50
                ELSE 0
            END
    FROM user_credits uc
    INNER JOIN users u ON uc.user_id = u.id
    WHERE uc.reset_date <= GETDATE()
        AND u.subscription_status = 'active';
    
    -- Log reset transactions
    INSERT INTO credit_transactions (
        user_id, credits_amount, credits_balance_after, 
        transaction_type, metadata
    )
    SELECT 
        uc.user_id,
        uc.subscription_credits,
        uc.credits_balance,
        'subscription',
        '{"reason": "monthly_reset"}'
    FROM user_credits uc
    INNER JOIN users u ON uc.user_id = u.id
    WHERE uc.reset_date <= GETDATE()
        AND u.subscription_status = 'active';
    
    -- Return number of users reset
    SELECT @@ROWCOUNT AS users_reset;
END;
GO

-- 9. Create view for credit analytics
CREATE VIEW vw_credit_analytics AS
SELECT 
    u.id AS user_id,
    u.email,
    u.subscription_tier,
    uc.credits_balance,
    uc.credits_used_month,
    uc.subscription_credits,
    uc.bonus_credits,
    uc.reset_date,
    (
        SELECT COUNT(*) 
        FROM credit_transactions ct 
        WHERE ct.user_id = u.id 
            AND ct.transaction_type = 'scan'
            AND ct.created_at >= DATEADD(DAY, -30, GETDATE())
    ) AS scans_last_30_days,
    (
        SELECT COUNT(*) 
        FROM interactive_sessions s
        WHERE s.user_id = u.id 
            AND s.started_at >= DATEADD(DAY, -30, GETDATE())
    ) AS interactive_sessions_last_30_days,
    (
        SELECT SUM(ABS(credits_amount))
        FROM credit_transactions ct
        WHERE ct.user_id = u.id
            AND ct.transaction_type IN ('scan', 'interactive')
            AND ct.created_at >= DATEADD(MONTH, -1, GETDATE())
    ) AS total_credits_consumed_month
FROM users u
LEFT JOIN user_credits uc ON u.id = uc.user_id;
GO

-- 10. Add indexes for performance
CREATE INDEX IX_user_credits_reset ON user_credits(reset_date) WHERE reset_date <= GETDATE();
CREATE INDEX IX_sessions_expiry ON interactive_sessions(last_activity) WHERE status = 'active';

-- 11. Create trigger to auto-expire sessions
GO
CREATE OR ALTER TRIGGER trg_ExpireSessions
ON interactive_sessions
AFTER UPDATE
AS
BEGIN
    -- Auto-expire sessions inactive for 1 hour
    UPDATE interactive_sessions
    SET status = 'expired',
        completed_at = GETDATE()
    WHERE status = 'active'
        AND DATEDIFF(MINUTE, last_activity, GETDATE()) > 60;
END;
GO

-- Migration complete
PRINT 'Credit system migration completed successfully';