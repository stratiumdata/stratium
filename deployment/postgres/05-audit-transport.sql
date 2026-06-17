-- Migration: Add transport column to audit_logs
-- Purpose: Distinguish how agent actions were submitted (MCP stdio, MCP check mode, direct gRPC)
-- PRD: PRD_OPENAI_AGENT_AUTHORIZATION.md

-- Add transport column to audit_logs if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_logs' AND column_name = 'transport'
    ) THEN
        ALTER TABLE audit_logs ADD COLUMN transport VARCHAR(20) DEFAULT 'mcp';
        COMMENT ON COLUMN audit_logs.transport IS 'Integration transport: mcp (stdio), mcp-check (single-shot from hooks), grpc (direct)';
    END IF;
END $$;

-- Create index for transport-based filtering
CREATE INDEX IF NOT EXISTS idx_audit_logs_transport ON audit_logs(transport);
