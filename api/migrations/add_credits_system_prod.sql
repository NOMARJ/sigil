-- Migration: Credit/metering tables + procs — PROD-COMPATIBLE rewrite
-- Date: 2026-06-12
-- Feature: F-009 (Sigil Pro + Fable 5) — US-104/US-112 metering backing store
--
-- Why this exists (do NOT apply add_credits_system.sql to prod):
--   The original api/migrations/add_credits_system.sql was written for an
--   earlier schema where user IDs were NVARCHAR. The current prod `users`
--   table has `id UNIQUEIDENTIFIER`. The original FK
--     user_credits.user_id NVARCHAR(128) -> users(id) UNIQUEIDENTIFIER
--   is a type mismatch and fails to create — which is why metering has no
--   backing tables and sp_DeductCredits is absent in prod.
--
-- Scope: what the F-009 metering path and paid interactive routes need.
--   The legacy migration's interactive_sessions FK references scans(scan_id),
--   a column that does not exist on the prod scans table. This prod table keeps
--   scan_id as a string without a hard FK so existing API session IDs continue
--   to work across old and new scan rows.
--
-- Idempotent: guarded with IF NOT EXISTS / CREATE OR ALTER. Safe to re-run.

-- 1. user_credits ------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'user_credits')
BEGIN
    CREATE TABLE user_credits (
        user_id              UNIQUEIDENTIFIER PRIMARY KEY,
        credits_balance      INT NOT NULL DEFAULT 0,
        credits_used_month   INT NOT NULL DEFAULT 0,
        bonus_credits        INT NOT NULL DEFAULT 0,
        subscription_credits INT NOT NULL DEFAULT 0,
        reset_date           DATETIME2 NOT NULL,
        last_updated         DATETIME2 NOT NULL DEFAULT GETDATE(),
        created_at           DATETIME2 NOT NULL DEFAULT GETDATE(),
        CONSTRAINT FK_user_credits_users FOREIGN KEY (user_id)
            REFERENCES users(id) ON DELETE CASCADE,
        CONSTRAINT CK_credits_positive CHECK (credits_balance >= 0)
    );
END
GO

-- 2. credit_transactions -----------------------------------------------------
--    scan_id stays NVARCHAR (no FK): scan IDs are GUID strings (str(uuid4()))
--    written by the API path; a hard FK to scans is intentionally avoided.
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'credit_transactions')
BEGIN
    CREATE TABLE credit_transactions (
        transaction_id        UNIQUEIDENTIFIER DEFAULT NEWID() PRIMARY KEY,
        user_id               UNIQUEIDENTIFIER NOT NULL,
        credits_amount        INT NOT NULL,
        credits_balance_after INT NOT NULL,
        transaction_type      NVARCHAR(50) NOT NULL,
        transaction_status    NVARCHAR(20) NOT NULL DEFAULT 'completed',
        scan_id               NVARCHAR(64),
        session_id            NVARCHAR(64),
        model_used            NVARCHAR(50),
        tokens_used           INT,
        metadata              NVARCHAR(MAX),
        created_at            DATETIME2 NOT NULL DEFAULT GETDATE(),
        CONSTRAINT FK_credit_tx_user FOREIGN KEY (user_id)
            REFERENCES users(id) ON DELETE CASCADE,
        INDEX IX_credit_tx_user_date (user_id, created_at DESC),
        INDEX IX_credit_tx_scan (scan_id)
    );
END
GO

-- 3. interactive_sessions ----------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'interactive_sessions')
BEGIN
    CREATE TABLE interactive_sessions (
        session_id            NVARCHAR(64) PRIMARY KEY,
        user_id               UNIQUEIDENTIFIER NOT NULL,
        scan_id               NVARCHAR(64) NOT NULL,
        [status]              NVARCHAR(20) NOT NULL DEFAULT 'active',
        findings_context      NVARCHAR(MAX) NOT NULL DEFAULT '{}',
        conversation_history  NVARCHAR(MAX) NOT NULL DEFAULT '[]',
        total_credits_used    INT NOT NULL DEFAULT 0,
        model_preference      NVARCHAR(50) DEFAULT 'claude-3-haiku',
        share_token           NVARCHAR(128),
        expires_at            DATETIME2,
        started_at            DATETIME2 NOT NULL DEFAULT GETDATE(),
        last_activity         DATETIME2 NOT NULL DEFAULT GETDATE(),
        completed_at          DATETIME2,
        CONSTRAINT FK_interactive_sessions_user FOREIGN KEY (user_id)
            REFERENCES users(id) ON DELETE CASCADE,
        CONSTRAINT CK_interactive_findings_json CHECK (ISJSON(findings_context) = 1),
        CONSTRAINT CK_interactive_history_json CHECK (ISJSON(conversation_history) = 1)
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_sessions_user_active')
    CREATE INDEX IX_sessions_user_active ON interactive_sessions (user_id, [status]);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_sessions_scan')
    CREATE INDEX IX_sessions_scan ON interactive_sessions (scan_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_sessions_share_token')
    CREATE UNIQUE INDEX IX_sessions_share_token ON interactive_sessions (share_token)
    WHERE share_token IS NOT NULL;
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_sessions_expiry')
    CREATE INDEX IX_sessions_expiry ON interactive_sessions (expires_at)
    WHERE expires_at IS NOT NULL;
GO

-- 4. sp_DeductCredits --------------------------------------------------------
--    @UserId is UNIQUEIDENTIFIER; the service passes the GUID as a string and
--    SQL Server implicitly converts it.
CREATE OR ALTER PROCEDURE sp_DeductCredits
    @UserId UNIQUEIDENTIFIER,
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

    SELECT @CurrentBalance = credits_balance
    FROM user_credits WITH (UPDLOCK)
    WHERE user_id = @UserId;

    IF @CurrentBalance IS NULL
    BEGIN
        ROLLBACK TRANSACTION;
        THROW 50001, 'User credits not found', 1;
    END

    IF @CurrentBalance < @Amount
    BEGIN
        ROLLBACK TRANSACTION;
        THROW 50002, 'Insufficient credits', 1;
    END

    SET @NewBalance = @CurrentBalance - @Amount;

    UPDATE user_credits
    SET credits_balance = @NewBalance,
        credits_used_month = credits_used_month + @Amount,
        last_updated = GETDATE()
    WHERE user_id = @UserId;

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

    SELECT @NewBalance AS new_balance;
END;
GO

-- 5. sp_AddCredits -----------------------------------------------------------
CREATE OR ALTER PROCEDURE sp_AddCredits
    @UserId UNIQUEIDENTIFIER,
    @Amount INT,
    @TransactionType NVARCHAR(50),
    @Metadata NVARCHAR(MAX) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @CurrentBalance INT;
    DECLARE @NewBalance INT;

    BEGIN TRANSACTION;

    SELECT @CurrentBalance = credits_balance
    FROM user_credits WITH (UPDLOCK)
    WHERE user_id = @UserId;

    IF @CurrentBalance IS NULL
    BEGIN
        INSERT INTO user_credits (user_id, credits_balance, reset_date)
        VALUES (@UserId, 0, DATEADD(MONTH, 1, GETDATE()));
        SET @CurrentBalance = 0;
    END

    SET @NewBalance = @CurrentBalance + @Amount;

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

    INSERT INTO credit_transactions (
        user_id, credits_amount, credits_balance_after,
        transaction_type, metadata
    )
    VALUES (
        @UserId, @Amount, @NewBalance,
        @TransactionType, @Metadata
    );

    COMMIT TRANSACTION;

    SELECT @NewBalance AS new_balance;
END;
GO
