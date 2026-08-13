-- Per-tenant tool catalog (spec §4.4.2, T1-T2). Replaces the hardcoded map
-- internal/authz.DefaultCatalog has served since Phase 3c -- that function's
-- own doc comment named a database-backed, per-tenant catalog as this map's
-- eventual home from the day it was written. One row per tool per tenant:
-- the action tier and verb that slot into §4.4's existing resolution order
-- (override, then catalog, then built-in -- DeriveTier is unchanged by this
-- migration; internal/authz stays pure and untouched by this task), plus
-- which raw_input field names carry the tool call's resource identity and
-- its command, so a later task can extract both server-side instead of
-- trusting a PEP-side table that only ever knew Claude Code's own tool
-- names.
--
-- resource_field and command_field are independently nullable. Most tools
-- have no command field at all -- only a shell-shaped tool (Bash, and an
-- MCP equivalent) carries one -- and plenty have no resource field either.
-- NULL means "this tool has no such field," the ordinary case, not an error
-- and not "unknown": the same reading DefaultCatalog's own doc comment
-- gives Bash's deliberately absent catalog entry one level up, now
-- expressed as a column that can be absent instead of a whole row.
--
-- No created_at/created_by columns: unlike tier_overrides, an
-- operator-authored audit log of raise-only overrides, this table has no
-- writer at all yet -- see the GRANT below -- and a timestamp nothing
-- populates is exactly the plumbed-but-never-populated field this project's
-- house style rules out. Add them alongside whatever future migration gives
-- this table its first writer.
CREATE TABLE tool_catalog (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      TEXT NOT NULL,

    -- Matched exactly and case-sensitively, both here and in
    -- internal/store.LoadToolCatalog: no lower() anywhere in this table's
    -- write or read path. A case-insensitive match must decide what two
    -- rows differing only in case mean when they disagree, and
    -- pkg/classification.lookupCap already shows that decision going wrong
    -- by default -- its own doc comment records a caps map keyed "NATO"
    -- silently invisible to a resource declaring "nato" under a naive fold,
    -- falling through to an ALLOW: a fail-open on this platform's core
    -- authorization primitive, from ambiguity alone, not from any value
    -- either row actually held. lookupCap was fixed to deny on that
    -- ambiguity. UNIQUE below goes one step further and refuses to store it
    -- at all: two rows differing only in case cannot exist here for a
    -- reader to resolve one way or the other, which is a stronger guarantee
    -- than resolving the collision correctly every time.
    tool_name      TEXT NOT NULL,

    action_tier    SMALLINT NOT NULL CHECK (action_tier BETWEEN 0 AND 4),
    verb           TEXT NOT NULL,

    -- The raw_input field name (e.g. "file_path") whose value is this tool
    -- call's resource identity. Nullable: see the table comment above.
    resource_field TEXT,
    -- The raw_input field name (e.g. "command") whose value is the command
    -- being run. Nullable, and usually null: see the table comment above.
    command_field  TEXT,

    UNIQUE (tenant_id, tool_name)
);
CREATE INDEX idx_tool_catalog_tenant ON tool_catalog(tenant_id);

ALTER TABLE tool_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_catalog FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tool_catalog
    USING (tenant_id = current_tenant())
    WITH CHECK (tenant_id = current_tenant());

-- Spec §4.4.2 T1, following E7 (§4.6.1): the PDP authenticates no callers --
-- the tenant comes from startup configuration, never a verified caller
-- identity (internal/store's own package doc) -- so an endpoint on this
-- service that wrote authorization configuration could not know who was
-- really asking for the write. Writing the catalog is the control plane's
-- job, which does authenticate its operators; the PDP only ever reads what
-- the control plane put here. INSERT, UPDATE, and DELETE are all absent
-- below, completely rather than partially: unlike 000012_approvals.up.sql,
-- whose serving role legitimately keeps INSERT for CreateApproval, this
-- table has no legitimate PDP writer at all, so nothing but SELECT belongs
-- on this line, ever.
--
-- The absent grants ARE the enforcement, the same claim
-- 000012_approvals.up.sql makes for UPDATE and backs with a real
-- integration test rather than leaving it as a comment. See
-- TestIntegration_ToolCatalog_ServingRoleCannotWrite
-- (internal/store/catalog_integration_test.go) for this table's own proof,
-- against a live database, that a comment cannot rot the way a GRANT line
-- someone widens without reading it can.
GRANT SELECT ON tool_catalog TO stratium_app;
