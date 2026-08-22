-- Seeds the ONE agent row example/proxy needs that the PAP's own admin API
-- cannot create: docker-compose.yml's pep-proxy is configured with a literal
-- STRATIUM_PEP_AGENT_ID, read once at startup and never from anything a
-- caller's session names (cmd/stratium-pep/proxy.go's package doc, NO
-- SESSION FILE) -- so the only agent row its principal leg will ever resolve
-- is the one whose id matches that exact literal. POST /v1/agents cannot
-- produce it: store.CreateAgent's own doc comment states plainly that id
-- (with tenant_id/created_at/updated_at) is ignored on input, and the row's
-- id always comes from the agents table's own uuid_generate_v4() default --
-- deliberate control-plane hygiene, not a gap (a caller choosing its own
-- primary key is exactly the write a real admin API should refuse).
--
-- The same literal id is independently hardcoded as proxyAgentID in
-- services/internal/store/proxy_integration_test.go, so this file, that test
-- suite, and docker-compose.yml's pep-proxy must all agree on it -- none of
-- the three may invent a different value.
--
-- Tenant and id are both fixed here, unlike deploy/seed's other two files:
-- this fixture only ever applies to pdp-proxy's own tenant
-- (tenant-proxy-integration), and there is exactly one agent id pep-proxy
-- will ever ask about, so a -v tenant_id= parameter would be configuration
-- for a value that never changes.
--
-- Run as the stratium_migrate role (the table owner -- see
-- migrations/000005_serving_app_grants.up.sql's own GRANT comment: the
-- serving role stratium_app has SELECT only on agents, by design, so
-- writing this table is always a control-plane action, never something the
-- PDP does to itself):
--
--     dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }
--     dc exec -T -e PGPASSWORD=stratium_migrate_local_dev_only postgres \
--       psql -h 127.0.0.1 -U stratium_migrate -d stratium -q \
--       -f /dev/stdin < deploy/seed/proxy-example-agent.sql
--
-- agents has FORCE ROW LEVEL SECURITY (migrations/000001_baseline), which
-- applies even to stratium_migrate as the table's owner: the set_config
-- below MUST run, in the same session, before the INSERT, or the INSERT
-- fails loudly against tenant_id = current_tenant() (NULL) rather than
-- silently writing nothing.
SELECT set_config('app.tenant_id', 'tenant-proxy-integration', false);

-- classification_caps: NOT NULL, no default (migrations/000020_agent_
-- classification_caps) -- '{}' matches CreateAgent's own "every created
-- agent starts capless" default. Safe to re-run: ON CONFLICT (id) DO
-- NOTHING leaves an already-seeded row untouched.
INSERT INTO agents (id, tenant_id, name, provider, model_id, trust_tier, enabled, suspended, allowed_tools, classification_caps)
VALUES ('04ef809a-849f-404a-9a5c-015b7f73a014', 'tenant-proxy-integration', 'proxy-example-agent', 'example', 'llama3.2', 3, true, false, '[]', '{}')
ON CONFLICT (id) DO NOTHING;
