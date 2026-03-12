-- Add model routing log table for analytics
-- Migration: add_model_routing.sql

CREATE TABLE model_routing_log (
    id INT IDENTITY(1,1) PRIMARY KEY,
    user_id NVARCHAR(255) NOT NULL,
    task_type NVARCHAR(50) NOT NULL,
    model_selected NVARCHAR(50) NOT NULL,
    complexity NVARCHAR(20) NOT NULL,
    confidence FLOAT NOT NULL,
    credits_required INT NOT NULL,
    credits_used INT NULL,
    reason NVARCHAR(50) NOT NULL,
    downgraded BIT DEFAULT 0,
    original_model NVARCHAR(50) NULL,
    execution_time_ms INT NULL,
    timestamp DATETIME2 DEFAULT GETDATE(),
    
    INDEX idx_routing_user_time (user_id, timestamp DESC),
    INDEX idx_routing_model (model_selected),
    INDEX idx_routing_task (task_type)
);