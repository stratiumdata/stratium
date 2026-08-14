-- Reverses 000015_tenant_epoch_trigger.up.sql: the grant first (so no writer
-- can invoke the function while it is being removed), then the triggers,
-- then the function they all depended on.
REVOKE SELECT, INSERT, UPDATE ON tenant_epoch FROM stratium_app;
DROP TRIGGER IF EXISTS tenant_epoch_bump ON delegations;
DROP TRIGGER IF EXISTS tenant_epoch_bump ON tier_overrides;
DROP TRIGGER IF EXISTS tenant_epoch_bump ON tool_catalog;
DROP TRIGGER IF EXISTS tenant_epoch_bump ON agents;
DROP TRIGGER IF EXISTS tenant_epoch_bump ON policies;
DROP FUNCTION IF EXISTS bump_tenant_epoch();
