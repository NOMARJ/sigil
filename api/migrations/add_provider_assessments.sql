-- Migration: add provider assessment verdict columns to public_scans
-- Initiative 2 — State of Agent Skill Security Report
-- These columns store structured third-party security verdicts for skills ecosystem scans.

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('public_scans') AND name = 'gen_verdict')
    ALTER TABLE public_scans ADD gen_verdict NVARCHAR(50) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('public_scans') AND name = 'socket_verdict')
    ALTER TABLE public_scans ADD socket_verdict NVARCHAR(50) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('public_scans') AND name = 'snyk_verdict')
    ALTER TABLE public_scans ADD snyk_verdict NVARCHAR(50) NULL;
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('public_scans') AND name = 'provider_assessments_json')
    ALTER TABLE public_scans ADD provider_assessments_json NVARCHAR(MAX) NULL;
