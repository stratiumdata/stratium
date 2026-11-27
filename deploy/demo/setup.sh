#!/bin/sh
# Generates this demo's secrets: ./.env and ./secrets/signing.pem. Both are
# git-ignored and never leave the host. Refuses to overwrite either, because
# the database is initialised with these passwords once and a new .env
# against an existing volume would lock every service out.
#
#   ./setup.sh demo.example.com
set -eu
cd "$(dirname "$0")"

host="${1:?usage: ./setup.sh <public hostname>}"
[ ! -e .env ] || { echo "setup: .env already exists; delete it and the volumes to start over" >&2; exit 1; }

rand() { openssl rand -hex 24; }

umask 077
cat > .env <<EOF
DEMO_HOST=$host
POSTGRES_PASSWORD=$(rand)
STRATIUM_MIGRATE_DB_PASSWORD=$(rand)
STRATIUM_DB_PASSWORD=$(rand)
STRATIUM_PAP_DB_PASSWORD=$(rand)
KEYCLOAK_DB_PASSWORD=$(rand)
DEMO_ADMIN_PASSWORD=$(rand)
# Shared by every visitor and meant to be published; editor role only.
DEMO_USER_PASSWORD=$(openssl rand -hex 8)
EOF

mkdir -p secrets
openssl ecparam -name prime256v1 -genkey -noout -out secrets/signing.pem
chmod 0400 secrets/signing.pem
# The PDP image runs as uid 65532 and must be the only reader. Docker Desktop
# maps bind-mount ownership itself, so only a Linux host needs the chown.
if [ "$(uname)" = Linux ]; then
	sudo chown 65532:65532 secrets/signing.pem
fi

echo "setup: wrote .env and secrets/signing.pem for $host"
