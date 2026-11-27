#!/bin/sh
# Fills the demo tenant: the tool catalog, then seed.sql. Run after every
# reset, once the stack is up. Safe to run again.
#
#   ./seed.sh                                         the deployed stack
#   ./seed.sh -f docker-compose.yml -f docker-compose.local.yml   the local one
set -eu
cd "$(dirname "$0")"

for seed in ../seed/tool-catalog-claude-code.sql ../seed/tool-catalog-mcp-filesystem.sql seed.sql; do
	# Over the container's local socket as the migration role: the same
	# identity that owns the schema, and no password leaves the host.
	docker compose "$@" exec -T postgres psql -q -U stratium_migrate -d stratium \
		-v ON_ERROR_STOP=1 -v tenant_id=demo -f /dev/stdin < "$seed" > /dev/null
done
docker compose "$@" exec -T postgres psql -U stratium_migrate -d stratium -Atc "
	SELECT set_config('app.tenant_id', 'demo', false);
	SELECT 'seed: ' || (SELECT count(*) FROM tool_catalog) || ' catalog rows, '
		|| (SELECT count(*) FROM agents) || ' agent(s), '
		|| (SELECT count(*) FROM policies) || ' policy(ies), '
		|| (SELECT count(*) FROM resource_label_rules) || ' label rule(s)';" | tail -1
