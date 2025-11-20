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
)

echo "======================================================================"
echo "Mirroring Public Images to AWS ECR (AMD64 Architecture)"
echo "======================================================================"
echo "Registry: ${ECR_REGISTRY}"
echo "Region: ${AWS_REGION}"
echo "Platform: linux/amd64"
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
    ECR_IMAGE="${ECR_REGISTRY}/${ECR_REPO_NAME}:latest"

    echo "======================================================================"
    echo "Processing: ${PUBLIC_IMAGE} → ${ECR_REPO_NAME} (linux/amd64)"
    echo "======================================================================"

    # Pull from public registry with AMD64 platform
    echo "→ Pulling public image (linux/amd64): ${PUBLIC_IMAGE}"
    docker pull --platform linux/amd64 ${PUBLIC_IMAGE}

    # Tag for ECR
    echo "→ Tagging image for ECR..."
    docker tag ${PUBLIC_IMAGE} ${ECR_IMAGE}

    # Push to ECR
    echo "→ Pushing to ECR: ${ECR_IMAGE}"
    docker push ${ECR_IMAGE}

    echo "✓ Successfully pushed ${PUBLIC_IMAGE}"
    echo ""
done

echo "======================================================================"
echo "✓ All AMD64 images mirrored successfully!"
echo "======================================================================"
echo ""
echo "Images are now available at:"
echo "  - ${ECR_REGISTRY}/postgres:latest (AMD64)"
echo "  - ${ECR_REGISTRY}/redis:latest (AMD64)"
echo "  - ${ECR_REGISTRY}/keycloak:latest (AMD64)"
echo "  - ${ECR_REGISTRY}/envoy:latest (AMD64)"
echo ""
