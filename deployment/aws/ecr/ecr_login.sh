#!/usr/bin/env bash
set -euo pipefail
REGION=${AWS_REGION:-us-east-1}
if [[ -z "${AWS_ACCOUNT_ID:-}" ]]; then
  ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
else
  ACCOUNT_ID=${AWS_ACCOUNT_ID}
fi
REGISTRY="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${REGISTRY}" >/dev/null
printf '%s' "${REGISTRY}"
