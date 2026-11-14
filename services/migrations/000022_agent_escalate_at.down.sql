-- 000022_agent_escalate_at.down.sql
ALTER TABLE agents DROP COLUMN IF EXISTS escalate_at;
