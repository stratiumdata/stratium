#!/bin/bash
set -e

# AWS ECR Configuration
ECR_REGISTRY="536176198371.dkr.ecr.us-east-2.amazonaws.com"
AWS_REGION="us-east-2"
SECRET_NAME="ecr-registry-secret"
NAMESPACE="${1:-stratium}"

echo "======================================================================"
echo "Creating ECR Pull Secret for Kubernetes"
echo "======================================================================"
echo "Registry: ${ECR_REGISTRY}"
echo "Region: ${AWS_REGION}"
echo "Namespace: ${NAMESPACE}"
echo "Secret Name: ${SECRET_NAME}"
echo "======================================================================"
echo ""

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "ERROR: AWS CLI is not installed"
    echo "Install it with: pip install awscli"
    exit 1
fi

# Check if kubectl is installed
if ! command -v kubectl &> /dev/null; then
    echo "ERROR: kubectl is not installed"
    exit 1
fi

# Check if namespace exists
if ! kubectl get namespace ${NAMESPACE} &> /dev/null; then
    echo "→ Creating namespace: ${NAMESPACE}"
    kubectl create namespace ${NAMESPACE}
else
    echo "✓ Namespace ${NAMESPACE} already exists"
fi

# Delete existing secret if it exists
if kubectl get secret ${SECRET_NAME} -n ${NAMESPACE} &> /dev/null; then
    echo "→ Deleting existing secret: ${SECRET_NAME}"
    kubectl delete secret ${SECRET_NAME} -n ${NAMESPACE}
fi

# Get ECR login password
echo "→ Getting ECR login token..."
ECR_TOKEN=$(aws ecr get-login-password --region ${AWS_REGION})

if [ -z "$ECR_TOKEN" ]; then
    echo "ERROR: Failed to get ECR token"
    echo "Make sure you have valid AWS credentials configured (aws configure)"
    exit 1
fi

# Create the secret
echo "→ Creating Kubernetes secret..."
kubectl create secret docker-registry ${SECRET_NAME} \
  --docker-server=${ECR_REGISTRY} \
  --docker-username=AWS \
  --docker-password="${ECR_TOKEN}" \
  --namespace=${NAMESPACE}

if [ $? -eq 0 ]; then
    echo "✓ Successfully created secret: ${SECRET_NAME}"
    echo ""
    echo "======================================================================"
    echo "✓ ECR Pull Secret Created Successfully!"
    echo "======================================================================"
    echo ""
    echo "The secret is valid for 12 hours. To refresh it, run this script again."
    echo ""
    echo "To use it in your Helm deployment:"
    echo ""
    echo "  helm install stratium ./stratium -n ${NAMESPACE} -f values-ecr.yaml"
    echo ""
    echo "Or add to your values.yaml:"
    echo ""
    echo "  global:"
    echo "    imagePullSecrets:"
    echo "      - name: ${SECRET_NAME}"
    echo ""
else
    echo "ERROR: Failed to create secret"
    exit 1
fi