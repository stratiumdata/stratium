-- tool_catalog seed data for Claude Code's own built-in tools
-- (migrations/000013_tool_catalog, migrations/000014_tool_catalog_nullable_tier).
--
-- Data, not code, by design (Phase 8 Task 4): the PDP already ships a
-- built-in fallback for these same eleven tool names
-- (internal/authz.DefaultCatalog) with the identical tier values below, so
-- a tenant that never runs this file is not unprotected -- Read is still
-- READ_ONLY, Write is still INTERNAL_MODIFY, and so on. What this file adds
-- that the built-in fallback structurally cannot:
--
--   - Bash's row. DefaultCatalog deliberately omits Bash (see that
--     function's own doc comment): a single fixed tier can never describe a
--     shell command, so Bash needs the OTHER shape this table can express --
--     NULL action_tier, command_field naming where the command lives -- and
--     that shape only exists as a database row, never as a Go map entry.
--     Without this row, Bash's raw_input arrives as Claude Code's JSON
--     envelope ({"command":"ls -la"}), never gets its command extracted, and
--     a harmless "ls -la" derives INTERNAL_MODIFY instead of READ_ONLY --
--     Phase 3b's fix, silently regressed (see
--     .superpowers/sdd/2026-08-12-phase-8-tool-catalog/bash-gap-report.md).
--     Run this file to close that gap; it is not closed by code alone.
--   - resource_field, for the tools where one exact-path argument makes it
--     safe and useful (Read/Write/Edit/NotebookRead/NotebookEdit/LS). Before
--     Phase 8 Task 3, cmd/stratium-pep/resource.go extracted these fields on
--     the PEP's own side; that file is deleted now, so a delegation's
--     ResourceConstraints can only scope Claude Code's own tools again once
--     a tenant catalogs them here.
--
-- Glob, Grep, WebFetch, and WebSearch intentionally get NO resource_field
-- (NULL): each takes a pattern, URL, or query -- not one exact resource
-- identity -- and extracting one anyway would risk quietly changing the
-- observable shape of a known, deliberately-unfixed gap (Phase 7 Task 4's
-- Finding A: "a resource constraint silently disables Glob because a
-- pattern has no path" -- .superpowers/sdd/2026-08-12-phase-7-resource-identity/task-4-report.md).
-- Leaving these four NULL keeps that gap exactly as it was: any
-- ResourceConstraints entry still denies these four tools unconditionally
-- (the constrained key is simply absent from an empty resource map), the
-- same practical failure mode as before, for the same reason -- a caller who
-- wants that changed should make the choice deliberately, not inherit it
-- from this seed file.
--
-- Run as the stratium_migrate role (the table owner -- see
-- migrations/000013_tool_catalog's own GRANT comment: the serving role
-- stratium_app has SELECT only, by design, so writing this table is always
-- a control-plane action, never something the PDP does to itself):
--
--     psql "$STRATIUM_MIGRATION_DATABASE_URL" -v tenant_id='your-tenant-id' \
--         -f deploy/seed/tool-catalog-claude-code.sql
--
-- tool_catalog has FORCE ROW LEVEL SECURITY (migrations/000013_tool_catalog),
-- which applies even to stratium_migrate as the table's owner: the
-- set_config below MUST run, in the same session, before the INSERT -- an
-- INSERT with app.tenant_id unset does not silently write nothing (that
-- failure mode is DELETE/UPDATE's -- see 000014's own migration comment);
-- it fails loudly instead, because tenant_id = current_tenant() (NULL)
-- never satisfies the tenant_isolation policy's WITH CHECK. Loud is the
-- point: this line staying first is what makes that failure mode
-- structural rather than a discipline every future edit has to remember.
SELECT set_config('app.tenant_id', :'tenant_id', false);

-- action_tier: 0 REASONING, 1 READ_ONLY, 2 INTERNAL_MODIFY, 3 EXTERNAL_COMMS,
-- 4 DESTRUCTIVE (pkg/models.ActionTier) -- NULL means "classify by
-- command_field instead," Bash's own row below.
--
-- Safe to re-run: ON CONFLICT re-asserts these exact values rather than
-- erroring on a row this file (or an earlier run of it) already wrote.
-- An operator's own later override still wins if applied after this file --
-- this is a starting point, not a lock.
INSERT INTO tool_catalog (tenant_id, tool_name, action_tier, verb, resource_field, command_field) VALUES
    (:'tenant_id', 'Read',         1, 'read',  'file_path',     NULL),
    (:'tenant_id', 'Write',        2, 'write', 'file_path',     NULL),
    (:'tenant_id', 'Edit',         2, 'edit',  'file_path',     NULL),
    (:'tenant_id', 'Glob',         1, 'search', NULL,           NULL),
    (:'tenant_id', 'Grep',         1, 'search', NULL,           NULL),
    (:'tenant_id', 'NotebookRead', 1, 'read',  'notebook_path', NULL),
    (:'tenant_id', 'NotebookEdit', 2, 'edit',  'notebook_path', NULL),
    (:'tenant_id', 'LS',           1, 'list',  'path',          NULL),
    (:'tenant_id', 'WebFetch',     1, 'read',  NULL,            NULL),
    (:'tenant_id', 'WebSearch',    1, 'search', NULL,           NULL),
    (:'tenant_id', 'TodoWrite',    2, 'write', NULL,            NULL),
    -- Bash: no fixed tier -- command_field names the raw_input field
    -- carrying the shell command, so internal/authz.BuiltinTier's own
    -- command classifier decides per call (rm -rf / still DESTRUCTIVE,
    -- ls -la still READ_ONLY), exactly as Phase 3b intended.
    (:'tenant_id', 'Bash',         NULL, 'execute', NULL,       'command')
ON CONFLICT (tenant_id, tool_name) DO UPDATE SET
    action_tier    = EXCLUDED.action_tier,
    verb           = EXCLUDED.verb,
    resource_field = EXCLUDED.resource_field,
    command_field  = EXCLUDED.command_field;
