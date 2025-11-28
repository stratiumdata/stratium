#!/bin/bash
set -e

# AWS ECR Configuration
ECR_REGISTRY="536176198371.dkr.ecr.us-east-2.amazonaws.com"
AWS_REGION="us-east-2"

# Public images to mirror (format: "source_image|ecr_repo_name")
IMAGES=(
    "postgres:15.8-alpine|postgres"
    "redis:7.4.1-alpine|redis"
    "quay.io/keycloak/keycloak:26.0.7|keycloak"
    "envoyproxy/envoy:v1.31.2|envoy"
    "busybox:1.36|busybox"
)

echo "======================================================================"
echo "Mirroring Public Images to AWS ECR (ARM64 Architecture)"
echo "======================================================================"
echo "Registry: ${ECR_REGISTRY}"
echo "Region: ${AWS_REGION}"
echo "Platform: linux/arm64"
echo "======================================================================"
echo ""

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "ERROR: Docker is not running"
    exit 1
fi

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "ERROR: AWS CLI is not installed"
    exit 1
fi

# Authenticate with ECR
echo "→ Authenticating with AWS ECR..."
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_REGISTRY}

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to authenticate with ECR"
    exit 1
fi

echo "✓ Successfully authenticated with ECR"
echo ""

# Process each image
for IMAGE_PAIR in "${IMAGES[@]}"; do
    PUBLIC_IMAGE=$(echo "$IMAGE_PAIR" | cut -d'|' -f1)
    ECR_REPO_NAME=$(echo "$IMAGE_PAIR" | cut -d'|' -f2)
    SRC_TAG="${PUBLIC_IMAGE##*:}"
    ECR_IMAGE="${ECR_REGISTRY}/${ECR_REPO_NAME}:${SRC_TAG}"

    echo "======================================================================"
    echo "Processing: ${PUBLIC_IMAGE} → ${ECR_IMAGE} (linux/arm64)"
    echo "======================================================================"

    # Remove any cached versions
    echo "→ Removing cached images..."
    docker rmi ${PUBLIC_IMAGE} ${ECR_IMAGE} 2>/dev/null || true

    # Pull from public registry with ARM64 platform
    echo "→ Pulling public image (linux/arm64): ${PUBLIC_IMAGE}"
    docker pull --platform linux/arm64 ${PUBLIC_IMAGE}

    # Verify architecture
    ARCH=$(docker inspect ${PUBLIC_IMAGE} | jq -r '.[0].Architecture')
    echo "→ Verified architecture: ${ARCH}"
    if [ "$ARCH" != "arm64" ]; then
        echo "ERROR: Expected arm64 but got ${ARCH}"
        exit 1
    fi

    # Ensure repository exists
    if ! aws ecr describe-repositories --repository-names "${ECR_REPO_NAME}" --region "${AWS_REGION}" >/dev/null 2>&1; then
        echo "→ ECR repo ${ECR_REPO_NAME} missing; creating..."
        aws ecr create-repository --repository-name "${ECR_REPO_NAME}" --region "${AWS_REGION}" >/dev/null
    fi

    # Tag for ECR
    echo "→ Tagging image for ECR..."
    docker tag ${PUBLIC_IMAGE} ${ECR_IMAGE}

    # Push to ECR
    echo "→ Pushing to ECR: ${ECR_IMAGE}"
    docker push ${ECR_IMAGE}

    echo "✓ Successfully pushed ${PUBLIC_IMAGE} (arm64) as ${SRC_TAG}"
    echo ""
done

echo "======================================================================"
echo "✓ All ARM64 images mirrored successfully!"
echo "======================================================================"
