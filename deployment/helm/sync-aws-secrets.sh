#!/usr/bin/env bash
#
# Sync secrets from AWS Secrets Manager into Kubernetes Secret objects that the
# Stratium Helm chart consumes.
#
# Requirements:
#   - aws CLI (configured for the target account)
#   - jq
#   - kubectl access to the destination cluster/namespace
#
# Environment variables (override as needed):
#   AWS_REGION                 : AWS region (default: us-east-2)
#   NAMESPACE                  : Kubernetes namespace (default: stratium)
#   STRATIUM_SECRET_ID         : AWS Secret name/ARN for app secrets
#   STRATIUM_SECRET_NAME       : Resulting K8s secret name (default: stratium-aws-sm)
#   KEYCLOAK_SECRET_ID         : AWS Secret for Keycloak admin creds
#   KEYCLOAK_SECRET_NAME       : K8s secret name (default: keycloak-aws-sm)
#   POSTGRESQL_SECRET_ID       : AWS Secret for PostgreSQL creds
#   POSTGRESQL_SECRET_NAME     : K8s secret name (default: postgresql-aws-sm)
#
# Example:
#   STRATIUM_SECRET_ID=prod/stratium \
#   KEYCLOAK_SECRET_ID=prod/keycloak \
#   POSTGRESQL_SECRET_ID=prod/postgresql \
#   ./sync-aws-secrets.sh
#
set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-2}"
NAMESPACE="${NAMESPACE:-stratium}"

STRATIUM_SECRET_ID="${STRATIUM_SECRET_ID:-stratium-aws-sm}"
STRATIUM_SECRET_NAME="${STRATIUM_SECRET_NAME:-stratium-aws-sm}"
KEYCLOAK_SECRET_ID="${KEYCLOAK_SECRET_ID:-keycloak-aws-sm}"
KEYCLOAK_SECRET_NAME="${KEYCLOAK_SECRET_NAME:-keycloak-aws-sm}"
POSTGRESQL_SECRET_ID="${POSTGRESQL_SECRET_ID:-postgresql-aws-sm}"
POSTGRESQL_SECRET_NAME="${POSTGRESQL_SECRET_NAME:-postgresql-aws-sm}"

command -v aws >/dev/null 2>&1 || { echo "aws CLI is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "kubectl is required" >&2; exit 1; }

fetch_secret() {
  local secret_id="$1"
  aws secretsmanager get-secret-value \
    --region "${AWS_REGION}" \
    --secret-id "${secret_id}" \
    --query SecretString \
    --output text
}

apply_secret() {
  kubectl apply -n "${NAMESPACE}" -f -
}

ensure_namespace() {
  if ! kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
    echo "Creating namespace ${NAMESPACE}"
    kubectl create namespace "${NAMESPACE}"
  fi
}

ensure_namespace

echo "Syncing Stratium application secret from ${STRATIUM_SECRET_ID}"
stratium_json="$(fetch_secret "${STRATIUM_SECRET_ID}")"
db_password="$(jq -r '."database-password"' <<<"${stratium_json}")"
km_secret="$(jq -r '."key-manager-oidc-secret"' <<<"${stratium_json}")"
ka_secret="$(jq -r '."key-access-oidc-secret"' <<<"${stratium_json}")"
pap_secret="$(jq -r '."pap-oidc-secret"' <<<"${stratium_json}")"

apply_secret <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${STRATIUM_SECRET_NAME}
type: Opaque
stringData:
  database-password: "${db_password}"
  key-manager-oidc-secret: "${km_secret}"
  key-access-oidc-secret: "${ka_secret}"
  pap-oidc-secret: "${pap_secret}"
EOF

echo "Syncing Keycloak admin secret from ${KEYCLOAK_SECRET_ID}"
keycloak_json="$(fetch_secret "${KEYCLOAK_SECRET_ID}")"
keycloak_user="$(jq -r '."admin-user"' <<<"${keycloak_json}")"
keycloak_pass="$(jq -r '."admin-password"' <<<"${keycloak_json}")"

apply_secret <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${KEYCLOAK_SECRET_NAME}
type: Opaque
stringData:
  admin-user: "${keycloak_user}"
  admin-password: "${keycloak_pass}"
EOF

echo "Syncing PostgreSQL secret from ${POSTGRESQL_SECRET_ID}"
postgres_json="$(fetch_secret "${POSTGRESQL_SECRET_ID}")"
pg_super_pass="$(jq -r '."postgres-password"' <<<"${postgres_json}")"
pg_user="$(jq -r '."username"' <<<"${postgres_json}")"
pg_pass="$(jq -r '."password"' <<<"${postgres_json}")"
stratium_user="$(jq -r '."stratium-user"' <<<"${postgres_json}")"
stratium_pass="$(jq -r '."stratium-password"' <<<"${postgres_json}")"

apply_secret <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${POSTGRESQL_SECRET_NAME}
type: Opaque
stringData:
  postgres-password: "${pg_super_pass}"
  username: "${pg_user}"
  password: "${pg_pass}"
  stratium-user: "${stratium_user}"
  stratium-password: "${stratium_pass}"
EOF

echo "Secrets synced to namespace ${NAMESPACE}"
