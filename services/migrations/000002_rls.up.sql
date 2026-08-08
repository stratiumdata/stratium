-- Row-level security. The application sets app.tenant_id per transaction and
-- the database enforces isolation, so a query missing its WHERE clause returns
-- nothing instead of another tenant's data (C18).
--
-- FORCE is required because a table owner otherwise bypasses RLS. The
-- application role must not hold BYPASSRLS.

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
