DROP TRIGGER IF EXISTS tenant_epoch_bump_update ON delegations;
DROP TRIGGER IF EXISTS tenant_epoch_bump ON delegations;
CREATE TRIGGER tenant_epoch_bump AFTER UPDATE OR DELETE ON delegations
    FOR EACH ROW EXECUTE FUNCTION bump_tenant_epoch();

REVOKE UPDATE (bound_jkt) ON delegations FROM stratium_app;
ALTER TABLE delegations DROP COLUMN IF EXISTS bound_jkt;
