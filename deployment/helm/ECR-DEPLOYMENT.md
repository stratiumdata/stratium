# AWS ECR Deployment Guide

This guide explains how to push Stratium Docker images to AWS ECR and deploy them to Kubernetes.

## Prerequisites

- AWS CLI installed and configured (`aws configure`)
- Docker installed and running
- kubectl configured for your Kubernetes cluster
- Helm 3.8+
- AWS account with ECR access

## ECR Repository Details

- **Registry**: `536176198371.dkr.ecr.us-east-2.amazonaws.com`
- **Repository**: `stratiumdata`
- **Region**: `us-east-2`

## Step 1: Build Docker Images

First, build all the Stratium Docker images locally:

```bash
cd deployment/helm
./build-images.sh
```

This creates the following images:
- `stratiumdata/platform:latest`
- `stratiumdata/key-manager:latest`
- `stratiumdata/key-access:latest`
- `stratiumdata/pap:latest`
- `stratiumdata/pap-ui:latest`

**Note**: Infrastructure services are not built locally - they use official public images:
- PostgreSQL: `docker.io/postgres:15.8-alpine`
- Redis: `docker.io/redis:7.4.1-alpine`
- Keycloak: `quay.io/keycloak/keycloak:26.0.7`
- Envoy: `docker.io/envoyproxy/envoy:v1.31.2`

## Step 2: Push Images to ECR

### Option A: Push with default 'latest' tag

```bash
./push-to-ecr.sh
```

### Option B: Push with a specific version tag

```bash
./push-to-ecr.sh v1.0.0
```

This will push both `v1.0.0` and `latest` tags.

### What the script does:

1. Authenticates with AWS ECR
2. Tags each local image with the ECR registry path
3. Pushes images to ECR
4. Creates both versioned and `latest` tags (if version specified)

## Step 3: Create ECR Pull Secret in Kubernetes

ECR requires authentication. Create a Kubernetes secret to allow image pulls:

```bash
./create-ecr-secret.sh stratium
```

**Important**: ECR tokens expire after 12 hours. You'll need to refresh the secret periodically.

### Manual Secret Creation (Alternative)

If you prefer to create the secret manually:

```bash
# Get ECR token
aws ecr get-login-password --region us-east-2 > /tmp/ecr-token.txt

# Create secret
kubectl create secret docker-registry ecr-registry-secret \
  --docker-server=536176198371.dkr.ecr.us-east-2.amazonaws.com \
  --docker-username=AWS \
  --docker-password=$(cat /tmp/ecr-token.txt) \
  --namespace=stratium

# Clean up
rm /tmp/ecr-token.txt
```

## Step 4: Deploy with ECR Images

### Option A: Use provided ECR values file

```bash
helm install stratium ./stratium \
  -n stratium \
  --create-namespace \
  -f stratium/values-ecr.yaml
```

### Option B: Customize your values

Create a custom values file or modify `values-ecr.yaml`:

```yaml
global:
  imageRegistry: "536176198371.dkr.ecr.us-east-2.amazonaws.com"
  imagePullSecrets:
    - name: ecr-registry-secret

platform:
  image:
    repository: stratiumdata/platform
    tag: "v1.0.0"

keyManager:
  image:
    repository: stratiumdata/key-manager
    tag: "v1.0.0"

# ... etc
```

Then deploy:

```bash
helm install stratium ./stratium \
  -n stratium \
  --create-namespace \
  -f my-custom-values.yaml
```

## Step 5: Verify Deployment

Check that all pods are running with ECR images:

```bash
kubectl get pods -n stratium

kubectl describe pod <pod-name> -n stratium | grep Image:
```

You should see image paths like:
```
# Stratium services (from ECR)
536176198371.dkr.ecr.us-east-2.amazonaws.com/stratiumdata-platform:latest
536176198371.dkr.ecr.us-east-2.amazonaws.com/stratiumdata-key-manager:latest
536176198371.dkr.ecr.us-east-2.amazonaws.com/stratiumdata-key-access:latest
536176198371.dkr.ecr.us-east-2.amazonaws.com/stratiumdata-pap:latest
536176198371.dkr.ecr.us-east-2.amazonaws.com/stratiumdata-pap-ui:latest

# Infrastructure services (from public registries)
docker.io/postgres:15.8-alpine
docker.io/redis:7.4.1-alpine
quay.io/keycloak/keycloak:26.0.7
docker.io/envoyproxy/envoy:v1.31.2
```

**Note**: Infrastructure services (PostgreSQL, Redis, Keycloak, Envoy) pull from public registries and do not use ECR credentials.

## Production Considerations

### 1. ECR Token Expiration

ECR authentication tokens expire after 12 hours. For production:

**Option A: Use IRSA (Recommended for EKS)**

Configure IAM Roles for Service Accounts to automatically refresh tokens:

```bash
# Associate IAM OIDC provider with your cluster
eksctl utils associate-iam-oidc-provider --cluster=my-cluster --approve

# Create IAM role with ECR policy
eksctl create iamserviceaccount \
  --name stratium-ecr-sa \
  --namespace stratium \
  --cluster my-cluster \
  --attach-policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly \
  --approve
```

Then update your deployment to use the service account:

```yaml
serviceAccount:
  create: true
  name: stratium-ecr-sa
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::536176198371:role/stratium-ecr-role
```

**Option B: Use a CronJob to refresh the secret**

Create a CronJob that runs every 6 hours:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ecr-token-refresh
  namespace: stratium
spec:
  schedule: "0 */6 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: ecr-refresh-sa
          containers:
          - name: refresh
            image: amazon/aws-cli:latest
            command:
            - /bin/sh
            - -c
            - |
              TOKEN=$(aws ecr get-login-password --region us-east-2)
              kubectl delete secret ecr-registry-secret -n stratium --ignore-not-found
              kubectl create secret docker-registry ecr-registry-secret \
                --docker-server=536176198371.dkr.ecr.us-east-2.amazonaws.com \
                --docker-username=AWS \
                --docker-password="$TOKEN" \
                --namespace=stratium
          restartPolicy: OnFailure
```

### 2. Image Versioning

Always use semantic versioning for production:

```bash
# Tag with version
./push-to-ecr.sh v1.0.0

# Deploy with specific version
helm install stratium ./stratium -n stratium -f values.yaml \
  --set platform.image.tag=v1.0.0 \
  --set keyManager.image.tag=v1.0.0 \
  --set keyAccess.image.tag=v1.0.0 \
  --set pap.image.tag=v1.0.0 \
  --set papUI.image.tag=v1.0.0
```

### 3. ECR Lifecycle Policies

Configure lifecycle policies to manage old images and reduce costs:

```json
{
  "rules": [
    {
      "rulePriority": 1,
      "description": "Keep last 10 images",
      "selection": {
        "tagStatus": "any",
        "countType": "imageCountMoreThan",
        "countNumber": 10
      },
      "action": {
        "type": "expire"
      }
    }
  ]
}
```

Apply to your repository:

```bash
aws ecr put-lifecycle-policy \
  --repository-name stratiumdata/platform \
  --lifecycle-policy-text file://lifecycle-policy.json \
  --region us-east-2
```

## Troubleshooting

### Image Pull Errors

**Error**: `ImagePullBackOff` or `ErrImagePull`

**Solutions**:
1. Verify secret exists: `kubectl get secret ecr-registry-secret -n stratium`
2. Check if token expired (>12 hours old): Recreate with `./create-ecr-secret.sh`
3. Verify image exists in ECR: `aws ecr describe-images --repository-name stratiumdata/platform --region us-east-2`
4. Check pod events: `kubectl describe pod <pod-name> -n stratium`

### Authentication Errors

**Error**: `no basic auth credentials`

**Solution**: Make sure you've configured AWS credentials:

```bash
aws configure
# Enter your AWS Access Key ID
# Enter your AWS Secret Access Key
# Enter region: us-east-2
```

### Image Not Found

**Error**: `repository does not exist`

**Solution**: Ensure the ECR repository exists:

```bash
# List repositories
aws ecr describe-repositories --region us-east-2

# Create repository if needed
aws ecr create-repository --repository-name stratiumdata/platform --region us-east-2
```

## Scripts Reference

| Script | Purpose |
|--------|---------|
| `build-images.sh` | Build all Stratium Docker images locally |
| `push-to-ecr.sh [version]` | Push images to AWS ECR |
| `create-ecr-secret.sh [namespace]` | Create Kubernetes pull secret for ECR |

## Additional Resources

- [AWS ECR Documentation](https://docs.aws.amazon.com/ecr/)
- [Kubernetes Private Registry Documentation](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/)
- [EKS IRSA Documentation](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)