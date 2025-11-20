#!/bin/bash
set -e

# AWS ECR Configuration
ECR_REGISTRY="536176198371.dkr.ecr.us-east-2.amazonaws.com"
ECR_REPOSITORY_PREFIX="stratiumdata"
AWS_REGION="us-east-2"

# Image list and versions
IMAGES=(
  "platform"
  "key-manager"
  "key-access"
  "pap"
  "pap-ui"
)

# Default version tag
VERSION="${1:-latest}"

echo "======================================================================"
echo "Pushing Stratium Images to AWS ECR"
echo "======================================================================"
echo "Registry: ${ECR_REGISTRY}"
echo "Repository Prefix: ${ECR_REPOSITORY_PREFIX}"
echo "Region: ${AWS_REGION}"
echo "Version: ${VERSION}"
echo "======================================================================"
echo ""

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "ERROR: AWS CLI is not installed"
    echo "Install it with: pip install awscli"
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "ERROR: Docker is not running"
    exit 1
fi

# Authenticate with ECR
echo "→ Authenticating with AWS ECR..."
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_REGISTRY}

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to authenticate with ECR"
    echo "Make sure you have valid AWS credentials configured (aws configure)"
    exit 1
fi

echo "✓ Successfully authenticated with ECR"
echo ""

# Process each image
for IMAGE in "${IMAGES[@]}"; do
    LOCAL_IMAGE="stratiumdata/${IMAGE}:latest"
    ECR_REPOSITORY_NAME="${ECR_REPOSITORY_PREFIX}-${IMAGE}"
    ECR_IMAGE="${ECR_REGISTRY}/${ECR_REPOSITORY_NAME}:${VERSION}"
    ECR_IMAGE_LATEST="${ECR_REGISTRY}/${ECR_REPOSITORY_NAME}:latest"

    echo "======================================================================"
    echo "Processing: ${IMAGE}"
    echo "======================================================================"

    # Check if local image exists
    if ! docker image inspect ${LOCAL_IMAGE} &> /dev/null; then
        echo "WARNING: Local image ${LOCAL_IMAGE} not found, skipping..."
        echo ""
        continue
    fi

    # Create ECR repository if it doesn't exist
    echo "→ Checking if ECR repository exists: ${ECR_REPOSITORY_NAME}"
    if ! aws ecr describe-repositories --repository-names ${ECR_REPOSITORY_NAME} --region ${AWS_REGION} &> /dev/null; then
        echo "→ Creating ECR repository: ${ECR_REPOSITORY_NAME}"
        aws ecr create-repository \
            --repository-name ${ECR_REPOSITORY_NAME} \
            --region ${AWS_REGION} \
            --image-scanning-configuration scanOnPush=true \
            --encryption-configuration encryptionType=AES256 > /dev/null
        echo "✓ Repository created"
    else
        echo "✓ Repository already exists"
    fi

    echo "→ Tagging image with version: ${VERSION}"
    docker tag ${LOCAL_IMAGE} ${ECR_IMAGE}

    if [ "${VERSION}" != "latest" ]; then
        echo "→ Tagging image with: latest"
        docker tag ${LOCAL_IMAGE} ${ECR_IMAGE_LATEST}
    fi

    echo "→ Pushing ${ECR_IMAGE}..."
    docker push ${ECR_IMAGE}

    if [ "${VERSION}" != "latest" ]; then
        echo "→ Pushing ${ECR_IMAGE_LATEST}..."
        docker push ${ECR_IMAGE_LATEST}
    fi

    echo "✓ Successfully pushed ${IMAGE}"
    echo ""
done

echo "======================================================================"
echo "✓ All images pushed successfully!"
echo "======================================================================"
echo ""
echo "Images are now available at:"
for IMAGE in "${IMAGES[@]}"; do
    ECR_REPOSITORY_NAME="${ECR_REPOSITORY_PREFIX}-${IMAGE}"
    echo "  - ${ECR_REGISTRY}/${ECR_REPOSITORY_NAME}:${VERSION}"
done
echo ""
echo "To use these images in Kubernetes, update your values.yaml:"
echo ""
echo "global:"
echo "  imageRegistry: \"${ECR_REGISTRY}\""
echo ""
echo "platform:"
echo "  image:"
echo "    repository: ${ECR_REPOSITORY_PREFIX}-platform"
echo "    tag: \"${VERSION}\""
echo ""
echo "keyManager:"
echo "  image:"
echo "    repository: ${ECR_REPOSITORY_PREFIX}-key-manager"
echo "    tag: \"${VERSION}\""
echo ""
echo "# etc. for other services..."
echo ""