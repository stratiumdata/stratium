-- Row-level security. The application sets app.tenant_id per transaction and
-- the database enforces isolation, so a query missing its WHERE clause returns
-- nothing instead of another tenant's data (C18).
--
-- FORCE closes the table-OWNER bypass: by default the owner of a table is
-- exempt from its own RLS policies even without BYPASSRLS. It does nothing
-- against a superuser, which bypasses RLS unconditionally regardless of
-- FORCE — and these tables are owned by whichever role runs the migrations,
-- which is a superuser in most setups (including local/CI Postgres). FORCE
-- is therefore dormant defense-in-depth here; it becomes the live guarantee
-- only where the owning role is not a superuser, e.g. some managed-Postgres
-- providers. The actual guarantee in every setup is that the role the
-- application authenticates as holds no ownership of these tables, is not a
-- superuser, and does not have BYPASSRLS.

CREATE OR REPLACE FUNCTION current_tenant() RETURNS TEXT AS $$
    SELECT current_setting('app.tenant_id', true);
$$ LANGUAGE SQL STABLE;

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'agents','delegations','policies','entitlements','tier_overrides','tenant_epoch'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) '
            'WITH CHECK (tenant_id = current_tenant())', t);
    END LOOP;
END $$;
