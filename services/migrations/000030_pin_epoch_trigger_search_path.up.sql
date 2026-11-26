-- bump_tenant_epoch() names the tenant_epoch table without a schema. A
-- temporary table is found before a permanent one of the same name, so a
-- session that first made a temporary table called tenant_epoch had its
-- writes bump that instead, and the tenant's real epoch stayed where it was:
-- a write the PEPs' caches were never told about.
--
-- Pinning the function's search path, with pg_temp named last, makes it find
-- the real table whatever the session has made. The schema is the one these
-- migrations run in, read here and not written down, since no migration
-- names it. pg_catalog is always searched first.
--
-- No other function in this schema needed it. audit_chain_deny_truncate()
-- reads nothing. current_tenant() calls current_setting(), and a function is
-- never looked up in pg_temp; no serving role can create one anywhere else.
-- forbid_serving_delete_of_live_delegation() (000028) is already pinned.
DO $$
BEGIN
    EXECUTE format('ALTER FUNCTION bump_tenant_epoch() SET search_path = %I, pg_temp', current_schema());
END $$;
