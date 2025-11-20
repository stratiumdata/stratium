# Secrets Manager Integration Guide

Learn how to integrate Stratium with secrets management systems to securely store and manage sensitive credentials, encryption keys, and configuration data.

## Table of Contents
- [Overview](#overview)
- [Supported Providers](#supported-providers)
- [HashiCorp Vault](#hashicorp-vault)
- [AWS Secrets Manager](#aws-secrets-manager)
- [Azure Key Vault](#azure-key-vault)
- [Google Secret Manager](#google-secret-manager)
- [Kubernetes Secrets](#kubernetes-secrets)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

Secrets management is critical for securing sensitive information used by Stratium, including:

- **Database Credentials**: PostgreSQL passwords
- **OIDC Client Secrets**: OAuth/OIDC provider credentials
- **Encryption Keys**: Keys for ZTDF file encryption/decryption
- **API Keys**: External service credentials
- **TLS Certificates**: SSL/TLS private keys
- **Admin Keys**: Administrative encryption keys

**Benefits of Secrets Manager Integration:**
- Centralized secret storage
- Automatic secret rotation
- Audit logging of secret access
- Encryption at rest and in transit
- Fine-grained access controls
- Compliance with security standards

## HashiCorp Vault

### Overview

HashiCorp Vault is a popular secrets management solution supporting multiple authentication methods and secret engines.

### Prerequisites

- Vault server deployed and accessible
- Vault initialized and unsealed
- Authentication credentials (token, AppRole, Kubernetes, etc.)

### Configuration

Configure Vault in your Stratium configuration file:

```yaml
# config.yaml
secrets:
  provider: "vault"

  vault:
    # Vault server address
    address: "https://vault.example.com:8200"

    # Authentication method
    auth_method: "approle"  # or "token", "kubernetes", "aws", "azure"

    # AppRole authentication
    approle:
      role_id: "${VAULT_ROLE_ID}"
      secret_id: "${VAULT_SECRET_ID}"
      mount_path: "approle"  # Default mount path

    # Or token authentication
    # token: "${VAULT_TOKEN}"

    # Or Kubernetes authentication
    # kubernetes:
    #   role: "stratium"
    #   mount_path: "kubernetes"
    #   token_path: "/var/run/secrets/kubernetes.io/serviceaccount/token"

    # TLS settings
    tls:
      ca_cert: "/path/to/ca.crt"
      skip_verify: false  # Never true in production!

    # Secret paths
    paths:
      database_password: "secret/data/stratium/db/password"
      oidc_client_secret: "secret/data/stratium/oidc/client_secret"
      encryption_keys: "secret/data/stratium/keys"
      admin_key: "secret/data/stratium/admin/key"

    # Renewal settings
    renew_token: true
    renewal_interval: 3600  # Renew token every hour
```

### Vault Setup

#### 1. Enable KV Secrets Engine

```bash
# Enable KV v2 secrets engine
vault secrets enable -version=2 -path=secret kv

# Or if using different path
vault secrets enable -version=2 -path=stratium kv
```

#### 2. Create AppRole

```bash
# Enable AppRole auth method
vault auth enable approle

# Create policy for Stratium
vault policy write stratium-policy - <<EOF
# Read database credentials
path "secret/data/stratium/db/*" {
  capabilities = ["read"]
}

# Read OIDC secrets
path "secret/data/stratium/oidc/*" {
  capabilities = ["read"]
}

# Read and write encryption keys
path "secret/data/stratium/keys/*" {
  capabilities = ["read", "create", "update"]
}

# Read admin keys
path "secret/data/stratium/admin/*" {
  capabilities = ["read"]
}
EOF

# Create AppRole
vault write auth/approle/role/stratium \
    token_policies="stratium-policy" \
    token_ttl=1h \
    token_max_ttl=4h

# Get Role ID
vault read auth/approle/role/stratium/role-id

# Generate Secret ID
vault write -f auth/approle/role/stratium/secret-id
```

#### 3. Store Secrets

```bash
# Store database password
vault kv put secret/stratium/db/password \
    password="your_secure_database_password"

# Store OIDC client secret
vault kv put secret/stratium/oidc/client_secret \
    client_id="stratium-app" \
    client_secret="your_oidc_client_secret"

# Store encryption keys
vault kv put secret/stratium/keys/master \
    key="base64_encoded_encryption_key"

# Store admin key
vault kv put secret/stratium/admin/key \
    private_key=@/path/to/admin_private_key.pem \
    public_key=@/path/to/admin_public_key.pem
```

### Kubernetes Authentication

For Kubernetes deployments:

```yaml
# config.yaml
secrets:
  provider: "vault"

  vault:
    address: "https://vault.example.com:8200"
    auth_method: "kubernetes"

    kubernetes:
      role: "stratium"
      mount_path: "kubernetes"
      token_path: "/var/run/secrets/kubernetes.io/serviceaccount/token"

    paths:
      database_password: "secret/data/stratium/db/password"
      oidc_client_secret: "secret/data/stratium/oidc/client_secret"
```

Vault Kubernetes auth configuration:

```bash
# Enable Kubernetes auth
vault auth enable kubernetes

# Configure Kubernetes auth
vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc:443" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    token_reviewer_jwt=@/var/run/secrets/kubernetes.io/serviceaccount/token

# Create role for Stratium
vault write auth/kubernetes/role/stratium \
    bound_service_account_names=stratium \
    bound_service_account_namespaces=default \
    policies=stratium-policy \
    ttl=1h
```

### Usage in Application

Reference secrets using the configured paths:

```yaml
# config.yaml
database:
  host: "db.example.com"
  port: 5432
  database: "stratium"
  username: "stratium"
  # Password retrieved from Vault
  password: "vault:secret/data/stratium/db/password#password"

oidc:
  issuer: "https://auth.example.com"
  client_id: "stratium-app"
  # Client secret retrieved from Vault
  client_secret: "vault:secret/data/stratium/oidc/client_secret#client_secret"
```

## AWS Secrets Manager

### Overview

AWS Secrets Manager is a fully managed service for storing and rotating secrets on AWS.

### Prerequisites

- AWS account with Secrets Manager enabled
- IAM permissions to access secrets
- AWS credentials configured (IAM role, access keys, or instance profile)

### Configuration

```yaml
# config.yaml
secrets:
  provider: "awsSecretsManager"

  aws:
    # AWS region
    region: "us-east-1"

    # Authentication (uses AWS SDK default credential chain)
    # - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    # - IAM instance profile (EC2)
    # - IAM role (ECS, EKS)

    # Secret ARNs or names
    secrets:
      database_password: "stratium/db/password"
      oidc_client_secret: "stratium/oidc/client_secret"
      encryption_keys: "stratium/encryption/keys"
      admin_key: "stratium/admin/key"

    # Cache settings
    cache_ttl: 300  # Cache secrets for 5 minutes
```

### AWS Secrets Manager Setup

#### 1. Create Secrets

```bash
# Create database password secret
aws secretsmanager create-secret \
    --name stratium/db/password \
    --description "Stratium database password" \
    --secret-string '{"password":"your_secure_password"}'

# Create OIDC client secret
aws secretsmanager create-secret \
    --name stratium/oidc/client_secret \
    --description "Stratium OIDC client credentials" \
    --secret-string '{"client_id":"stratium-app","client_secret":"your_client_secret"}'

# Create encryption keys
aws secretsmanager create-secret \
    --name stratium/encryption/keys \
    --description "Stratium encryption keys" \
    --secret-string '{"master_key":"base64_encoded_key"}'
```

#### 2. Create IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:stratium/*"
      ]
    }
  ]
}
```

#### 3. Attach Policy to IAM Role

```bash
# Create policy
aws iam create-policy \
    --policy-name StratiumSecretsAccess \
    --policy-document file://stratium-secrets-policy.json

# Attach to IAM role (for EC2/ECS)
aws iam attach-role-policy \
    --role-name StratiumAppRole \
    --policy-arn arn:aws:iam::123456789012:policy/StratiumSecretsAccess
```

### Automatic Secret Rotation

Enable automatic rotation for database passwords:

```bash
# Enable rotation
aws secretsmanager rotate-secret \
    --secret-id stratium/db/password \
    --rotation-lambda-arn arn:aws:lambda:us-east-1:123456789012:function:SecretsManagerRotation \
    --rotation-rules AutomaticallyAfterDays=30
```

### Usage in Application

```yaml
# config.yaml
database:
  host: "db.example.com"
  username: "stratium"
  # Password from AWS Secrets Manager
  password: "awssm:stratium/db/password#password"

oidc:
  issuer: "https://auth.example.com"
  # Client secret from AWS Secrets Manager
  client_id: "awssm:stratium/oidc/client_secret#client_id"
  client_secret: "awssm:stratium/oidc/client_secret#client_secret"
```

## Azure Key Vault

### Overview

Azure Key Vault is Microsoft Azure's managed service for secrets, keys, and certificates.

### Prerequisites

- Azure subscription with Key Vault enabled
- Service Principal or Managed Identity with access to Key Vault
- Azure credentials configured

### Configuration

```yaml
# config.yaml
secrets:
  provider: "azure_key_vault"

  azure:
    # Key Vault URL
    vault_url: "https://stratium-kv.vault.azure.net/"

    # Authentication
    # Uses DefaultAzureCredential chain:
    # 1. Environment variables
    # 2. Managed Identity
    # 3. Azure CLI
    # 4. Service Principal

    # Optional: Explicit Service Principal
    tenant_id: "${AZURE_TENANT_ID}"
    client_id: "${AZURE_CLIENT_ID}"
    client_secret: "${AZURE_CLIENT_SECRET}"

    # Secret names
    secrets:
      database_password: "stratium-db-password"
      oidc_client_secret: "stratium-oidc-client-secret"
      encryption_keys: "stratium-encryption-keys"
      admin_key: "stratium-admin-key"

    # Cache settings
    cache_ttl: 300
```

### Azure Key Vault Setup

#### 1. Create Key Vault

```bash
# Create resource group
az group create --name stratium-rg --location eastus

# Create Key Vault
az keyvault create \
    --name stratium-kv \
    --resource-group stratium-rg \
    --location eastus
```

#### 2. Create Secrets

```bash
# Create database password secret
az keyvault secret set \
    --vault-name stratium-kv \
    --name stratium-db-password \
    --value "your_secure_password"

# Create OIDC client secret
az keyvault secret set \
    --vault-name stratium-kv \
    --name stratium-oidc-client-secret \
    --value '{"client_id":"stratium-app","client_secret":"your_client_secret"}'

# Create encryption keys
az keyvault secret set \
    --vault-name stratium-kv \
    --name stratium-encryption-keys \
    --value "base64_encoded_key"
```

#### 3. Grant Access

```bash
# Using Managed Identity (recommended for Azure VMs/AKS)
az keyvault set-policy \
    --name stratium-kv \
    --object-id <managed-identity-object-id> \
    --secret-permissions get list

# Or using Service Principal
az keyvault set-policy \
    --name stratium-kv \
    --spn <service-principal-app-id> \
    --secret-permissions get list
```

### Usage in Application

```yaml
# config.yaml
database:
  password: "azurekv:stratium-db-password"

oidc:
  client_secret: "azurekv:stratium-oidc-client-secret#client_secret"
```

## Google Secret Manager

### Overview

Google Secret Manager is GCP's managed service for storing API keys, passwords, and other sensitive data.

### Prerequisites

- GCP project with Secret Manager API enabled
- Service Account with Secret Manager permissions
- GCP credentials configured

### Configuration

```yaml
# config.yaml
secrets:
  provider: "gcp_secret_manager"

  gcp:
    # GCP project ID
    project_id: "stratium-prod"

    # Authentication (uses Application Default Credentials)
    # Service Account JSON key can be provided via GOOGLE_APPLICATION_CREDENTIALS env var

    # Secret names (format: projects/PROJECT_ID/secrets/SECRET_NAME/versions/VERSION)
    secrets:
      database_password: "projects/stratium-prod/secrets/stratium-db-password/versions/latest"
      oidc_client_secret: "projects/stratium-prod/secrets/stratium-oidc-client-secret/versions/latest"
      encryption_keys: "projects/stratium-prod/secrets/stratium-encryption-keys/versions/latest"

    # Cache settings
    cache_ttl: 300
```

### Google Secret Manager Setup

#### 1. Enable API

```bash
# Enable Secret Manager API
gcloud services enable secretmanager.googleapis.com
```

#### 2. Create Secrets

```bash
# Create database password secret
echo -n "your_secure_password" | \
    gcloud secrets create stratium-db-password \
    --data-file=- \
    --replication-policy="automatic"

# Create OIDC client secret
echo -n '{"client_id":"stratium-app","client_secret":"your_client_secret"}' | \
    gcloud secrets create stratium-oidc-client-secret \
    --data-file=- \
    --replication-policy="automatic"

# Create encryption keys
echo -n "base64_encoded_key" | \
    gcloud secrets create stratium-encryption-keys \
    --data-file=- \
    --replication-policy="automatic"
```

#### 3. Grant Access

```bash
# Grant Service Account access to secrets
gcloud secrets add-iam-policy-binding stratium-db-password \
    --member="serviceAccount:stratium@stratium-prod.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding stratium-oidc-client-secret \
    --member="serviceAccount:stratium@stratium-prod.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
```

### Usage in Application

```yaml
# config.yaml
database:
  password: "gcpsm:projects/stratium-prod/secrets/stratium-db-password/versions/latest"

oidc:
  client_secret: "gcpsm:projects/stratium-prod/secrets/stratium-oidc-client-secret/versions/latest#client_secret"
```

## Kubernetes Secrets

### Overview

Kubernetes Secrets provide a native way to store sensitive data in Kubernetes clusters.

### Prerequisites

- Kubernetes cluster
- kubectl access with appropriate permissions

### Configuration

```yaml
# config.yaml
secrets:
  provider: "kubernetes"

  kubernetes:
    # Namespace where secrets are stored
    namespace: "default"

    # Secret names and keys
    secrets:
      database:
        secret_name: "stratium-db-credentials"
        keys:
          password: "password"
          username: "username"

      oidc:
        secret_name: "stratium-oidc-credentials"
        keys:
          client_id: "client_id"
          client_secret: "client_secret"

      encryption:
        secret_name: "stratium-encryption-keys"
        keys:
          master_key: "master_key"
```

### Kubernetes Secrets Setup

#### 1. Create Secrets

```bash
# Create database credentials secret
kubectl create secret generic stratium-db-credentials \
    --from-literal=username=stratium \
    --from-literal=password=your_secure_password

# Create OIDC credentials secret
kubectl create secret generic stratium-oidc-credentials \
    --from-literal=client_id=stratium-app \
    --from-literal=client_secret=your_oidc_client_secret

# Create encryption keys secret
kubectl create secret generic stratium-encryption-keys \
    --from-literal=master_key=base64_encoded_key
```

#### 2. Create from File

```bash
# Create secret from files
kubectl create secret generic stratium-admin-key \
    --from-file=private_key=./admin_private_key.pem \
    --from-file=public_key=./admin_public_key.pem
```

#### 3. Create from YAML

```yaml
# stratium-secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: stratium-db-credentials
  namespace: default
type: Opaque
stringData:
  username: stratium
  password: your_secure_password
---
apiVersion: v1
kind: Secret
metadata:
  name: stratium-oidc-credentials
  namespace: default
type: Opaque
stringData:
  client_id: stratium-app
  client_secret: your_oidc_client_secret
```

Apply:

```bash
kubectl apply -f stratium-secrets.yaml
```

### Mount Secrets in Pods

#### Environment Variables

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: stratium
spec:
  template:
    spec:
      containers:
      - name: stratium
        image: stratium:latest
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: stratium-db-credentials
              key: password
        - name: OIDC_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: stratium-oidc-credentials
              key: client_secret
```

#### Volume Mounts

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: stratium
spec:
  template:
    spec:
      containers:
      - name: stratium
        image: stratium:latest
        volumeMounts:
        - name: admin-key
          mountPath: "/etc/stratium/keys"
          readOnly: true
      volumes:
      - name: admin-key
        secret:
          secretName: stratium-admin-key
```

### Sealed Secrets (Recommended)

For GitOps workflows, use Sealed Secrets to encrypt secrets before committing to Git:

```bash
# Install Sealed Secrets controller
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.18.0/controller.yaml

# Install kubeseal CLI
brew install kubeseal

# Create sealed secret
kubectl create secret generic stratium-db-credentials \
    --from-literal=password=your_secure_password \
    --dry-run=client -o yaml | \
    kubeseal -o yaml > stratium-db-sealed-secret.yaml

# Commit sealed secret to Git (safe!)
git add stratium-db-sealed-secret.yaml
git commit -m "Add database credentials"
```

## Best Practices

### 1. Use Managed Identities

Avoid storing credentials for accessing secrets managers:

**AWS**: Use IAM Roles for EC2/ECS/EKS
**Azure**: Use Managed Identities
**GCP**: Use Workload Identity
**Vault**: Use Kubernetes auth or AppRole

### 2. Implement Secret Rotation

Regularly rotate secrets:

```yaml
# Rotation schedule
secrets:
  rotation:
    enabled: true
    schedule:
      database_password: 90d  # Every 90 days
      oidc_client_secret: 180d  # Every 180 days
      encryption_keys: 365d  # Annually
```

### 3. Limit Secret Access

Grant minimal permissions:

- Read-only access for application
- Write access only for administrators
- Separate secrets by environment (dev, staging, prod)

### 4. Audit Secret Access

Enable audit logging:

```yaml
secrets:
  audit:
    enabled: true
    log_access: true
    log_failures: true
```

### 5. Cache Secrets Appropriately

Balance security and performance:

```yaml
secrets:
  cache:
    enabled: true
    ttl: 300  # 5 minutes
    max_size: 100
```

### 6. Use Secret Versioning

Maintain secret versions for rollback:

```bash
# AWS Secrets Manager - versions automatic
# Azure Key Vault - enable versioning
# GCP Secret Manager - versions automatic
# Vault KV v2 - versions automatic
```

### 7. Encrypt Secrets at Rest

Ensure secrets manager encrypts data:

- **Vault**: Enable encryption at rest
- **AWS**: Uses AWS KMS automatically
- **Azure**: Uses Azure Storage encryption
- **GCP**: Uses Google-managed encryption keys

### 8. Monitor Secret Expiration

Set up alerts for expiring secrets:

```yaml
monitoring:
  alerts:
    - name: "Secret Expiring Soon"
      condition: "secret_expiry_days < 30"
      severity: "warning"
```

## Troubleshooting

### Authentication Failures

**Error**: `permission denied` or `access denied`

**Solutions:**

1. **Verify credentials**:
   ```bash
   # Vault
   vault token lookup

   # AWS
   aws sts get-caller-identity

   # Azure
   az account show

   # GCP
   gcloud auth list
   ```

2. **Check permissions**:
   - Vault: Verify policy allows reading secret paths
   - AWS: Check IAM policy grants `secretsmanager:GetSecretValue`
   - Azure: Verify Key Vault access policy includes "Get" and "List"
   - GCP: Check service account has `secretmanager.secretAccessor` role

### Secret Not Found

**Error**: `secret not found` or `404`

**Solutions:**

1. **Verify secret path**:
   ```bash
   # Vault
   vault kv list secret/stratium

   # AWS
   aws secretsmanager list-secrets

   # Azure
   az keyvault secret list --vault-name stratium-kv

   # GCP
   gcloud secrets list
   ```

2. **Check secret name matches configuration**

### Connection Timeout

**Error**: `timeout connecting to secrets manager`

**Solutions:**

1. **Check network connectivity**:
   ```bash
   # Test connectivity
   curl https://vault.example.com:8200/v1/sys/health
   ```

2. **Verify firewall rules allow outbound connections**

3. **Check TLS/SSL certificates**

### Slow Secret Retrieval

**Problem**: Secrets taking too long to fetch

**Solutions:**

1. **Enable caching**:
   ```yaml
   secrets:
     cache:
       enabled: true
       ttl: 300
   ```

2. **Use connection pooling**

3. **Check network latency to secrets manager**

## API Reference

### Secrets Management Commands

```bash
# Test secrets connection
stratium secrets test

# List available secrets
stratium secrets list

# Get secret value (for debugging)
stratium secrets get database_password

# Rotate secret
stratium secrets rotate database_password

# Cache statistics
stratium secrets cache-stats
```

## Next Steps

- [Key Manager Integration](./KEY_MANAGER.md)
- [Database Integration](./DATABASE_INTEGRATION.md)
- [OIDC Integration](./OIDC_INTEGRATION.md)
- [Security Best Practices](../security/BEST_PRACTICES.md)

## License

Copyright © 2025 Stratium Data
