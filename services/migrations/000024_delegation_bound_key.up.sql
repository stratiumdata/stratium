-- A delegation is bound to at most one key for its whole life. bound_jkt is
-- that key's RFC 7638 thumbprint; NULL means never bound. The PDP records it
-- the first time a key-bound token is issued for the delegation (at creation
-- or at a later IssueToken) and from then on refuses every token for the
-- delegation that is not bound to it.
ALTER TABLE delegations ADD COLUMN bound_jkt TEXT;

-- The PDP's serving role writes this one column and nothing else on the
-- table: revocation stays with stratium_pap.
GRANT UPDATE (bound_jkt) ON delegations TO stratium_app;

-- Recording a key must not bump the tenant epoch: it changes no decision an
-- existing cache entry could hold (a cached ALLOW belongs to the PEP that
-- holds the key), and the serving role has no business writing tenant_epoch.
-- 000015's single "AFTER UPDATE OR DELETE" trigger becomes two, because a
-- WHEN clause that reads NEW cannot sit on a DELETE trigger. The update one
-- fires whenever any column other than bound_jkt changed, so a column added
-- later is covered without being listed here.
DROP TRIGGER tenant_epoch_bump ON delegations;

CREATE TRIGGER tenant_epoch_bump AFTER DELETE ON delegations
    FOR EACH ROW EXECUTE FUNCTION bump_tenant_epoch();

CREATE TRIGGER tenant_epoch_bump_update AFTER UPDATE ON delegations
    FOR EACH ROW
    WHEN ((to_jsonb(OLD) - 'bound_jkt') IS DISTINCT FROM (to_jsonb(NEW) - 'bound_jkt'))
    EXECUTE FUNCTION bump_tenant_epoch();
