-- tool_catalog seed data for @modelcontextprotocol/server-filesystem
-- (migrations/000013_tool_catalog, migrations/000014_tool_catalog_nullable_tier),
-- the third-party MCP server this project has actually run `stratium-pep
-- mcp` against (see .superpowers/sdd/2026-08-12-phase-6-mcp-surface/task-4-report.md
-- and .superpowers/sdd/2026-08-12-phase-7-resource-identity/task-4-report.md).
--
-- Unlike Claude Code's own tools (tool-catalog-claude-code.sql, alongside
-- this file), NONE of these tool names exist in
-- internal/authz.DefaultCatalog -- that map only ever knew Claude Code's own
-- built-in vocabulary. Without a row here, every one of these derives
-- INTERNAL_MODIFY by default (BuiltinTier's "unrecognized -> assume it
-- modifies" fallback), reads included, which is exactly Phase 6 Task 4's
-- negative 1: a READ_ONLY delegation denied every third-party MCP read,
-- because read_file had no catalog entry anywhere. Running this file is
-- what closes that gap for this server; nothing in the PDP's code does it
-- for you.
--
-- Tool names and argument shapes below were captured empirically from a
-- live `tools/list` call against the real server (v0.2.0, fetched via
-- `npx -y @modelcontextprotocol/server-filesystem`), not guessed or taken
-- from documentation -- the same discipline Phase 6 Task 4's own report
-- describes for its own policy setup. Tier assignments follow this
-- project's OWN sensitivity model (pkg/models.ActionTier: what a call does
-- to state), not the server's own MCP `annotations.destructiveHint`
-- (a different axis -- see DefaultCatalog's own doc comment distinguishing
-- WebFetch/WebSearch's "reaches outside the trust boundary" axis from tier
-- the same way): the server marks write_file, edit_file, and move_file
-- destructiveHint:true (roughly, "may overwrite silently"), but none of the
-- three is irreversible or financially binding in this project's sense, so
-- each is cataloged INTERNAL_MODIFY here, matching Write/Edit's own
-- treatment in tool-catalog-claude-code.sql -- a deliberate judgment call,
-- not an oversight, worth an operator's own review before relying on it.
--
-- resource_field is "path" for every tool with exactly one path argument.
-- Three tools deliberately get NULL instead, each for its own stated
-- reason:
--   - read_multiple_files takes "paths" (a JSON array) -- ExtractFromCatalog
--     (internal/authz/extract.go) only ever reads a field as a single JSON
--     string; an array field would just extract nothing, so NULL here is
--     the honest value, not a workaround.
--   - list_allowed_directories takes no arguments at all.
--   - move_file has TWO path-shaped arguments (source, destination) and
--     this table has room for one resource_field. This file names "source"
--     -- the object being acted on, the same role Read/Write/Edit's own
--     single path argument plays -- which means a ResourceConstraints entry
--     scoped to this tool can see what is being moved but is blind to
--     where it lands. That is a real limitation of a one-resource-field
--     design applied to a two-path tool, not a bug in this file; pick
--     "destination" instead if your own use of move_file needs to
--     constrain the landing spot rather than the source.
--
-- Run as the stratium_migrate role (the table owner; the serving role
-- stratium_app has SELECT only by design -- migrations/000013_tool_catalog's
-- own GRANT comment):
--
--     psql "$STRATIUM_MIGRATION_DATABASE_URL" -v tenant_id='your-tenant-id' \
--         -f deploy/seed/tool-catalog-mcp-filesystem.sql
--
-- Same FORCE ROW LEVEL SECURITY requirement as the Claude Code seed file
-- (see that file's own comment for the full reasoning): set_config MUST run
-- first, in the same session, or the INSERT fails loudly rather than
-- silently writing nothing.
SELECT set_config('app.tenant_id', :'tenant_id', false);

-- action_tier: 0 REASONING, 1 READ_ONLY, 2 INTERNAL_MODIFY, 3 EXTERNAL_COMMS,
-- 4 DESTRUCTIVE (pkg/models.ActionTier). Every row here fixes an action_tier
-- (no NULL/command_field row in this file: none of this server's tools is
-- shell-shaped the way Bash is).
--
-- Safe to re-run: ON CONFLICT re-asserts these exact values rather than
-- erroring on a row this file (or an earlier run of it) already wrote.
INSERT INTO tool_catalog (tenant_id, tool_name, action_tier, verb, resource_field, command_field) VALUES
    (:'tenant_id', 'read_file',                 1, 'read',   'path',   NULL), -- Phase 6's negative 1's own tool
    (:'tenant_id', 'read_text_file',             1, 'read',   'path',   NULL),
    (:'tenant_id', 'read_media_file',            1, 'read',   'path',   NULL),
    (:'tenant_id', 'read_multiple_files',        1, 'read',   NULL,     NULL), -- "paths" is an array; see header
    (:'tenant_id', 'write_file',                 2, 'write',  'path',   NULL),
    (:'tenant_id', 'edit_file',                  2, 'edit',   'path',   NULL),
    (:'tenant_id', 'create_directory',           2, 'create', 'path',   NULL),
    (:'tenant_id', 'list_directory',             1, 'list',   'path',   NULL),
    (:'tenant_id', 'list_directory_with_sizes',  1, 'list',   'path',   NULL),
    (:'tenant_id', 'directory_tree',             1, 'list',   'path',   NULL),
    (:'tenant_id', 'move_file',                  2, 'move',   'source', NULL), -- blind to destination; see header
    (:'tenant_id', 'search_files',               1, 'search', 'path',   NULL),
    (:'tenant_id', 'get_file_info',              1, 'read',   'path',   NULL),
    (:'tenant_id', 'list_allowed_directories',   1, 'list',   NULL,     NULL)  -- takes no arguments
ON CONFLICT (tenant_id, tool_name) DO UPDATE SET
    action_tier    = EXCLUDED.action_tier,
    verb           = EXCLUDED.verb,
    resource_field = EXCLUDED.resource_field,
    command_field  = EXCLUDED.command_field;
